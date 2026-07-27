#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Copyright (c) Bright Interaction
#
# Every check CI runs, in one script you can also run yourself:
#
#   bash scripts/ci.sh
#
# Run it before opening a pull request and CI will not tell you anything new.
#
# WHY THE LOGIC LIVES HERE AND NOT IN .github/workflows/ci.yml
#
# Two reasons, and the second is not obvious.
#
# 1. A contributor can run it. Checks that only exist inside a workflow file are
#    checks you cannot reproduce locally, so you discover them after pushing.
#
# 2. It keeps .github/workflows/ci.yml STABLE, which is what makes automated
#    publishing possible at all. This repository is a filtered mirror of a private
#    monorepo, published by scripts/split-public-repo.sh over a repository deploy
#    key. GitHub does not allow a deploy key (or an OAuth token without the
#    `workflow` scope) to create or update anything under .github/workflows/. So a
#    check that lived in the workflow file would break the publish at the FINAL
#    push, after every gate had already passed, with a raw git error that reads
#    like a mystery. With the steps in this script, changing a check touches
#    scripts/ci.sh (an ordinary file the deploy key may write) and the workflow
#    file stays untouched, so the publish goes through.
#
# The consequence to remember: editing .github/workflows/ci.yml is now a rare,
# deliberate act (an action version bump, a trigger change) that needs a push from a
# credential with the `workflow` scope. Editing THIS file needs nothing special.
#
# Knobs:
#   HASH_CI_SKIP_SCANNERS=1   skip gitleaks + govulncheck (they may need network)
set -uo pipefail

# The same file lives at the repo root in the published mirror and under hash/ in the
# monorepo it is cut from, so find the module root instead of assuming either. If git
# is not there at all (someone unpacked a tarball), the current directory has to be it.
cd "$(git rev-parse --show-toplevel 2>/dev/null)" 2>/dev/null || true
[ -f go.mod ] || cd hash 2>/dev/null || true
[ -f go.mod ] || { echo "error: run this from the Hash module root (the directory holding go.mod)" >&2; exit 1; }

HAVE_GIT=0
git rev-parse --is-inside-work-tree >/dev/null 2>&1 && HAVE_GIT=1

FAILED=()
SKIPPED=()
# Exit code 99 means "this check did not run". It is distinct from pass and from fail
# on purpose: a skipped security scan that prints ok is worse than no scan at all,
# because it looks like evidence.
step() {
  local name="$1" rc; shift
  printf '\n=== %s ===\n' "$name"
  "$@"; rc=$?
  case "$rc" in
    0)  printf 'ok: %s\n' "$name" ;;
    99) printf 'SKIPPED: %s\n' "$name"; SKIPPED+=("$name") ;;
    *)  printf 'FAIL: %s\n' "$name" >&2; FAILED+=("$name") ;;
  esac
}

# Are we in the published mirror, or in the private monorepo the mirror is cut from?
# scripts/split-public-repo.sh strips a fixed list of internal-ops files (STRIP_PATHS)
# from every published commit, so any one of them existing means we are upstream.
# Hash has no pro code to strip (the commercial layer is hosting and eIDAS agreements,
# not source), so these runbooks and the estate compose file are the only marker there
# is. Two checks below have to mean different things in the two places, and getting
# that wrong makes the script either useless upstream or toothless downstream.
IN_MIRROR=1
for internal_only in PLAN.md docker-compose.prod.yml PRODUCTION-CUTOVER.md; do
  [ -e "$internal_only" ] && IN_MIRROR=0
done

# gofmt is not a style preference here, it is the diff-noise floor: an unformatted file
# makes every later change to it look bigger than it is. `gofmt -l` prints the files it
# would rewrite and says nothing when there is nothing to do, so the output IS the
# verdict. Note it exits 0 either way, which is why this reads the output and not $?.
gofmt_check() {
  local dirs unformatted
  # Ask the toolchain which directories hold packages rather than hardcoding cmd/ and
  # internal/. A new top-level Go directory is then covered without anyone remembering
  # to add it here, and frontend/node_modules is never walked. NUL-separated because
  # the monorepo path this is cut from contains a space.
  dirs="$(go list -f '{{.Dir}}' ./... 2>/dev/null)"
  [ -n "$dirs" ] || { echo "could not enumerate Go packages" >&2; return 1; }
  unformatted="$(printf '%s\n' "$dirs" | tr '\n' '\0' | xargs -0 gofmt -l)"
  if [ -n "$unformatted" ]; then
    echo "These files are not gofmt-clean:" >&2
    echo "$unformatted" >&2
    echo "Fix with: gofmt -w cmd internal" >&2
    return 1
  fi
  echo "every Go file in the module is gofmt-clean"
}

# vet twice. The default build misses internal/e2e entirely, because that package is
# behind `//go:build e2e` (it drives a real Postgres + MinIO, so it cannot run here).
# Tag-gated code that nothing type-checks rots quietly and you find out during a
# release. vet with the tag compiles it without running it, which is the honest half
# of the check we can do without services.
vet_all() {
  go vet ./... || return 1
  go vet -tags e2e ./... || return 1
  echo "vet clean for the default build and for -tags e2e (the tagged suite is type-checked, not run)"
}

# Every file the mirror publishes is under the Hash Sustainable Use License, and the
# header is how a reader (and a downstream packager) knows it. A .go file without one is
# an unlicensed contribution in a fair-code repo.
#
# Go only, deliberately. The .sql, .ts and .svelte files here do not carry headers yet,
# and a gate that is red on the day it lands teaches everyone to ignore it. Widen the
# list when those files are backfilled, not before.
#
# This also catches a regeneration papercut: `make sqlc` rewrites internal/db/generated/
# from scratch and does NOT re-emit the SPDX prelude, so a regenerate-and-commit drops
# the header from 31 files. This gate is what tells you.
license_headers() {
  local missing
  if [ "$HAVE_GIT" != "1" ]; then
    echo "not run: needs a git checkout to enumerate tracked files"
    return 99
  fi
  missing=$(git ls-files '*.go' | while read -r f; do
    awk 'NR<=5 && /SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License/ { found=1; exit } END { exit !found }' "$f" \
      || printf '%s\n' "$f"
  done)
  if [ -n "$missing" ]; then
    echo "These Go files lack the Hash SPDX header in their first 5 lines:" >&2
    echo "$missing" >&2
    echo "Add these two lines at the top of the file:" >&2
    echo "  // SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License" >&2
    echo "  // Copyright (c) Bright Interaction" >&2
    return 1
  fi
  echo "every tracked Go file carries the Hash SPDX header"
}

# No hand-written SQL in this project: queries live in internal/db/queries/*.sql and
# internal/db/generated/ is produced from them by sqlc (see CLAUDE.md). Generated code
# that drifts from its source is the whole failure mode, because it compiles fine and
# is wrong only against the database.
#
# `sqlc diff` regenerates in memory and prints what differs, but it can NEVER be clean
# here: the committed files carry a two-line SPDX prelude plus a blank line that sqlc
# does not emit (see license_headers above), so the diff always shows those three lines
# removed and sqlc always exits non-zero. Judging this on the exit status would make the
# gate permanently red; judging it on "did it print anything" would make it permanently
# red too. So read the CONTENT: filter out exactly the known prelude lines, and treat
# anything else that survives as real drift. Any staleness shows up as an added line
# (a query the generated code does not have yet) or as a removed line that is not part
# of the prelude, so nothing real can hide behind the filter.
sqlc_fresh() {
  local out real
  command -v sqlc >/dev/null 2>&1 || {
    echo "not run: sqlc is not installed (brew install sqlc)"
    return 99
  }
  out="$(cd internal/db && sqlc diff 2>&1)"
  real="$(printf '%s\n' "$out" \
    | grep -E '^[+-]' \
    | grep -vE '^(--- |\+\+\+ )' \
    | grep -vxF -e '-' \
        -e '-// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License' \
        -e '-// Copyright (c) Bright Interaction')"
  if [ -n "$real" ]; then
    echo "internal/db/generated/ is stale: it does not match internal/db/queries/*.sql." >&2
    echo "Regenerate with: make sqlc   (then re-add the SPDX header, see license headers)" >&2
    echo "$real" | head -40 >&2
    return 1
  fi
  echo "internal/db/generated/ matches internal/db/queries/*.sql (modulo the SPDX prelude sqlc does not emit)"
}

# Both scanners run from a binary on PATH when there is one (the estate installs
# gitleaks with brew, and split-public-repo.sh uses that same binary for the publish
# gate) and are otherwise installed on demand, which needs network. Set
# HASH_CI_SKIP_SCANNERS=1 to skip them when offline, and say SKIPPED rather than
# passing quietly, because a security scan that reports ok without running is worse
# than no scan.
scan() {
  local name="$1" mod="$2"; shift 2
  if [ "${HASH_CI_SKIP_SCANNERS:-0}" = "1" ]; then
    echo "not run: HASH_CI_SKIP_SCANNERS=1"
    return 99
  fi
  if command -v "$name" >/dev/null 2>&1; then
    "$name" "$@"
    return $?
  fi
  go install "$mod" >/dev/null 2>&1 || { echo "could not install $name (offline?)" >&2; return 1; }
  "$(go env GOPATH)/bin/$name" "$@"
}

# gitleaks exits non-zero when it finds something, so the exit status is the verdict
# here and the wrapper passes it straight through. .gitleaks.toml allowlists the
# change-me markers in .env.example; a real credential would not carry them.
secret_scan() {
  if [ "$IN_MIRROR" = "1" ] && [ "$HAVE_GIT" = "1" ]; then
    # Every commit in the mirror is this project's, so scanning the full history is
    # exactly right, and it is the last gate before a credential becomes world-readable.
    scan gitleaks github.com/zricethezav/gitleaks/v8@latest \
      detect --source . --config .gitleaks.toml --no-banner --redact
  else
    # Upstream the history belongs to a whole monorepo of unrelated projects, so a full
    # scan reports hundreds of findings that have nothing to do with Hash and trains
    # everyone to ignore the check. Here the working tree is what matters, and
    # split-public-repo.sh scans the real filtered payload's full history before it
    # pushes anything.
    scan gitleaks github.com/zricethezav/gitleaks/v8@latest \
      detect --source . --config .gitleaks.toml --no-git --no-banner --redact
  fi
}

step "build"                                   go build ./...
step "vet"                                     vet_all
step "tests (executed, not merely compiled)"   go test ./... -count=1
step "gofmt"                                   gofmt_check
step "sqlc generated code up to date"          sqlc_fresh
step "license headers"                         license_headers
if [ "$IN_MIRROR" = "1" ] && [ "$HAVE_GIT" = "1" ]; then
  step "secret scan (full history)" secret_scan
else
  step "secret scan (working tree; split-public-repo.sh scans the filtered history)" secret_scan
fi
step "vulnerability scan" scan govulncheck golang.org/x/vuln/cmd/govulncheck@latest ./...

printf '\n'
if [ ${#SKIPPED[@]} -ne 0 ]; then
  printf 'ci: %d check(s) DID NOT RUN: %s\n' "${#SKIPPED[@]}" "${SKIPPED[*]}" >&2
fi
if [ ${#FAILED[@]} -ne 0 ]; then
  # Report EVERY failure, not just the first. A run that stops at the first problem
  # costs a full round trip per issue.
  printf 'ci: %d check(s) failed: %s\n' "${#FAILED[@]}" "${FAILED[*]}" >&2
  exit 1
fi
if [ ${#SKIPPED[@]} -ne 0 ]; then
  echo "ci: every check that RAN passed, but some did not run (see above)"
  exit 0
fi
echo "ci: all checks passed"
