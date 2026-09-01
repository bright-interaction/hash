#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Copyright (c) Bright Interaction
#
# sqlc intentionally owns its generated prelude and does not offer a file-header
# option. Keep generation reproducible while restoring the repository license
# header that applies to every published Go file.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
generated_dir="$repo_root/internal/db/generated"
license_line='// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License'
tmp=''

cleanup() {
  if [ -n "$tmp" ]; then
    rm -f "$tmp"
  fi
}
trap cleanup EXIT

(
  cd "$repo_root/internal/db"
  sqlc generate
)

while IFS= read -r -d '' file; do
  if head -n 5 "$file" | grep -Fqx "$license_line"; then
    continue
  fi
  tmp="$(mktemp "${file}.license.XXXXXX")"
  {
    printf '%s\n' "$license_line"
    printf '%s\n\n' '// Copyright (c) Bright Interaction'
    cat "$file"
  } >"$tmp"
  chmod 0644 "$tmp"
  mv "$tmp" "$file"
  tmp=''
done < <(find "$generated_dir" -maxdepth 1 -type f -name '*.go' -print0)
