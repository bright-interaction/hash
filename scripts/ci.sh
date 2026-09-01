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
#   HASH_CI_REQUIRE_ALL=1     fail if any prerequisite makes a check skip;
#                             release publication sets this fail-closed mode
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

# The Go binary embeds frontend/build, so a backend-only green build can still
# ship a blank or type-invalid signer UI. Install from the frozen Bun lockfile,
# run Svelte's type/diagnostic pass, then produce the exact static artifact the
# Docker build embeds. Missing Bun is a failed CI prerequisite, not a skipped
# check: the public workflow installs the pinned version below.
frontend_checks() {
  local keepfile keepcopy rc hadkeep=0
  command -v bun >/dev/null 2>&1 || {
    echo "bun is required to typecheck and build the embedded frontend" >&2
    return 1
  }
  # adapter-static recreates build/ and can rewrite the tracked sentinel.
  # Preserve its exact contents so running CI never dirties a clean checkout.
  keepfile="frontend/build/.gitkeep"
  keepcopy="$(mktemp)" || return 1
  if [ -f "$keepfile" ]; then
    cp "$keepfile" "$keepcopy" || return 1
    hadkeep=1
  fi
  (
    cd frontend || return 1
    bun install --frozen-lockfile || return 1
    bun run test || return 1
    bun run check || return 1
    bun run build
  )
  rc=$?
  if [ "$hadkeep" = "1" ]; then
    mkdir -p "$(dirname "$keepfile")"
    cp "$keepcopy" "$keepfile"
  fi
  rm -f "$keepcopy"
  return "$rc"
}

frontend_dependency_audit() {
  command -v bun >/dev/null 2>&1 || {
    echo "bun is required to audit the frontend dependency lockfile" >&2
    return 1
  }
  (cd frontend && bun audit)
}

# Gotenberg uploads HTML into its own /tmp directory and opens that staged
# entrypoint with file://. Blocking file:// in Chromium therefore blocks every
# completed document, even though the application never supplied a remote URL.
# Keep that local scheme available while preserving both resolution-based
# private-IP blocking and the explicit internal HTTP(S) deny-list.
renderer_network_policy() {
  local file deny required
  for file in docker-compose.yml docker-compose.prod.yml; do
    [ -f "$file" ] || continue
    grep -Fq -- '--chromium-deny-private-ips=true' "$file" || {
      echo "$file must enable Gotenberg's Chromium private-IP denial" >&2
      return 1
    }
    deny="$(grep -F -- '--chromium-deny-list=' "$file")"
    [ -n "$deny" ] || {
      echo "$file must configure a Chromium URL deny-list" >&2
      return 1
    }
    case "$deny" in
      *file://*)
        echo "$file must allow Gotenberg's staged file:///tmp HTML entrypoint" >&2
        return 1
        ;;
    esac
    for required in 'https?://' '10\.' '127\.' '169\.254\.' '172\.' '192\.168\.' '0\.0\.0\.0' 'localhost' '::1' '[a-zA-Z0-9_-]+'; do
      case "$deny" in
        *"$required"*) ;;
        *)
          echo "$file Chromium deny-list no longer blocks required internal target pattern: $required" >&2
          return 1
          ;;
      esac
    done
  done
  echo "Gotenberg permits its local staged HTML and blocks private/internal HTTP(S) targets"
}

# Release-critical test services execute code on CI and deployment runners.
# Pinning only the application/toolchain still permits an upstream service tag
# to move between two runs of the same commit, so keep every canonical
# Postgres/MinIO dependency (and the browser suite's auxiliary services) bound
# to a registry digest. The human-readable tag remains for upgrade clarity.
dependency_image_policy() {
  local compose="docker-compose.yml" drill="scripts/backup-restore-drill.sh"
  local root_workflow="../.github/workflows/hash-ci.yml" ref
  local postgres_ref="postgres:16.15-alpine3.24@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"
  local minio_ref="minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
  local mailhog_ref="mailhog/mailhog:v1.0.1@sha256:8d76a3d4ffa32a3661311944007a415332c4bb855657f4f6c57996405c009bea"
  local webhook_ref="mendhak/http-https-echo:31@sha256:0fefe04350131d7bb28355e3bf037062643e45f4a8a32f23679529e1b09d8ce4"

  for ref in "$postgres_ref" "$minio_ref" "$mailhog_ref" "$webhook_ref"; do
    grep -Fq "image: $ref" "$compose" || {
      echo "$compose must pin dependency image $ref" >&2
      return 1
    }
  done
  for ref in "$postgres_ref" "$minio_ref"; do
    grep -Fq "$ref" "$drill" || {
      echo "$drill must default to dependency image $ref" >&2
      return 1
    }
    if [ -f "$root_workflow" ] && ! grep -Fq "$ref" "$root_workflow"; then
      echo "$root_workflow must pin release E2E dependency image $ref" >&2
      return 1
    fi
  done
  echo "canonical Hash service dependencies are pinned by registry digest"
}

# The internal production manifest is stripped from the public mirror, but in
# the monorepo it must fail closed when release plumbing forgets the selected
# Hash artifact. Both the web process and worker must share the required
# reference and release identity; a mutable fallback would bypass CI's
# commit-tag/content-ID guarantee.
production_image_policy() {
  local file="docker-compose.prod.yml" service block
  [ -f "$file" ] || {
    echo "production manifest is not part of the public mirror"
    return 0
  }
  [ "$(grep -Fc 'image: ${HASH_IMAGE:?' "$file")" -eq 2 ] || {
    echo "$file must require HASH_IMAGE for both the server and worker" >&2
    return 1
  }
  [ "$(grep -Fc 'HASH_RELEASE: ${HASH_RELEASE:?' "$file")" -eq 2 ] || {
    echo "$file must require HASH_RELEASE for both the server and worker" >&2
    return 1
  }
  [ "$(grep -Fc 'image: ${HASH_GOTENBERG_IMAGE:?' "$file")" -eq 1 ] || {
    echo "$file must require the staging-tested Gotenberg image ID" >&2
    return 1
  }
  if grep -Fq 'HASH_GOTENBERG_IMAGE:-' "$file"; then
    echo "$file contains a Gotenberg image fallback" >&2
    return 1
  fi
  if grep -Eq 'hash-hash:(latest|dev|main)([^[:alnum:]_.-]|$)' "$file"; then
    echo "$file contains a mutable Hash image fallback" >&2
    return 1
  fi
  if [ "$(grep -Fc 'HASH_ENVIRONMENT: production' "$file")" -ne 2 ] || grep -Fq '${HASH_ENVIRONMENT' "$file"; then
    echo "$file must pin literal HASH_ENVIRONMENT: production for both server and worker" >&2
    return 1
  fi
  for service in hash hash-worker; do
    block="$(awk -v service="$service" '
      $0 == "  " service ":" { in_service=1; next }
      in_service && /^  [[:alnum:]_-]+:$/ { exit }
      in_service { print }
    ' "$file")"
    for required in 'read_only: true' 'cap_drop:' '- ALL' 'no-new-privileges:true' '/tmp:rw,noexec,nosuid,nodev'; do
      printf '%s\n' "$block" | grep -Fq -- "$required" || {
        echo "$file service $service is missing runtime hardening: $required" >&2
        return 1
      }
    done
  done
  echo "production Compose requires explicit staged Hash and Gotenberg image IDs"
  echo "production Hash processes are read-only, capability-free, no-new-privileges containers with bounded /tmp"
}

# Hash intentionally has one production HTTP-server process until its
# rate-limit buckets, collaboration rooms, and BrightCRM resolver-cache
# invalidation all use shared backends. The runtime database lease is covered by
# cmd/server tests; this policy keeps the public deployment guide and the
# internal Compose topology from advertising or permitting a conflicting scale
# model.
single_server_topology_policy() {
  local deploy="DEPLOY.md" prod="docker-compose.prod.yml" cutover="PRODUCTION-CUTOVER.md" block
  grep -Fq 'Production supports exactly one `hash` HTTP-server replica.' "$deploy" || {
    echo "$deploy must state the one-server production topology" >&2
    return 1
  }
  if ! grep -Fq 'BrightCRM webhook cache invalidation' "$deploy" || ! grep -Fq 'process-local' "$deploy"; then
    echo "$deploy must explain that BrightCRM invalidation is process-local" >&2
    return 1
  fi

  # Internal production artifacts are intentionally absent from the public
  # mirror. When present, preserve both Compose's structural no-scale guard and
  # the operator-facing cutover warning.
  if [ -f "$prod" ]; then
    block="$(awk '
      $0 == "  hash:" { in_service=1; next }
      in_service && /^  [[:alnum:]_-]+:$/ { exit }
      in_service { print }
    ' "$prod")"
    printf '%s\n' "$block" | grep -Fxq '    container_name: hash' || {
      echo "$prod service hash must retain its exact singleton container name" >&2
      return 1
    }
    if printf '%s\n' "$block" | grep -Eq '^[[:space:]]+replicas:'; then
      echo "$prod service hash must not declare a replica count" >&2
      return 1
    fi
    if ! grep -Fq 'BrightCRM webhook cache invalidation' "$prod" || ! grep -Fq 'process-local' "$prod"; then
      echo "$prod must document the process-local BrightCRM invalidation constraint" >&2
      return 1
    fi
  fi
  if [ -f "$cutover" ]; then
    if ! grep -Fq 'BrightCRM webhook cache invalidation' "$cutover" || ! grep -Fq 'process-local' "$cutover"; then
      echo "$cutover must preserve the one-server BrightCRM invalidation warning" >&2
      return 1
    fi
  fi
  echo "production topology is documented and structurally pinned to one Hash HTTP server"
}

# HASH_AUDIT_PRIVATE_KEY accepts the raw 32-byte Ed25519 seed, not the complete
# PKCS#8 DER object emitted by `openssl genpkey -outform DER`. The environment
# template is the authoritative operator checklist, so a command which omits the
# extraction step creates a production config that passes documentation review
# but fails when the server and worker parse the signer key. Keep every shipped
# setup guide explicit about extracting exactly the seed bytes.
audit_key_documentation_policy() {
  local file
  for file in .env.example DEPLOY.md; do
    [ -f "$file" ] || {
      echo "$file is required for audit-key provisioning guidance" >&2
      return 1
    }
    grep -Fq 'tail -c 32 | base64' "$file" || {
      echo "$file must generate HASH_AUDIT_PRIVATE_KEY as a base64 raw 32-byte Ed25519 seed" >&2
      return 1
    }
  done
  if [ -f PRODUCTION-CUTOVER.md ] && ! grep -Fq 'tail -c 32 | base64' PRODUCTION-CUTOVER.md; then
    echo "PRODUCTION-CUTOVER.md must generate HASH_AUDIT_PRIVATE_KEY as a base64 raw 32-byte Ed25519 seed" >&2
    return 1
  fi
  echo "audit-key provisioning guides emit the exact raw 32-byte Ed25519 seed"
}

# Modern evidence rows bind the provider's VersionId into PostgreSQL. A logical
# S3 sync re-uploads bytes under new IDs and therefore cannot be advertised as a
# portable recovery path for those rows. Keep the operator guide fail-closed,
# keep the local synthetic drill honest about its legacy-only fixture, and make
# the production gate require an exact-version provider restore.
recovery_version_identity_policy() {
  local doc="ops/BACKUP-RESTORE.md" drill="scripts/backup-restore-drill.sh" required
  [ -f "$doc" ] || {
    echo "$doc is required for recovery guidance" >&2
    return 1
  }
  [ -f "$drill" ] || {
    echo "$drill is required for the local recovery preflight" >&2
    return 1
  }
  for required in \
    's3 sync` does not preserve provider VersionIds or' \
    'preserve every exact VersionId stored in PostgreSQL' \
    '$10 != "-" { pinned=1 }' \
    'portable logical restore refused: inventory contains exact VersionId pins' \
    'current exact-VersionId records' \
    'newly assigned VersionId does not satisfy this gate'; do
    grep -Fq "$required" "$doc" || {
      echo "$doc no longer states the fail-closed VersionId recovery contract: missing $required" >&2
      return 1
    }
  done
  if grep -Fq 'portable snapshot is the independent recovery copy' "$doc" \
      || grep -Fq 'validate the portable PostgreSQL + S3 path' "$doc"; then
    echo "$doc still advertises the logical latest-byte copy as a current portable restore" >&2
    return 1
  fi
  grep -Fq '[[ "$expected_version" == "-" && "$legacy_lookup" == "t" ]]' "$drill" || {
    echo "$drill must fail unless its digest-bearing fixture remains explicitly legacy/unpinned" >&2
    return 1
  }
  echo "recovery guidance rejects logical-sync restore for exact-VersionId records"
}

# A public 200 is not enough to prove a production cutover: ingress may still
# route to the previous healthy Hash container. Keep the internal acceptance
# script syntactically valid and bound to the manifest-selected release plus
# production runtime identity. The script is deliberately stripped from the
# public source mirror, where this estate-specific policy is not applicable.
cutover_smoke_identity_policy() {
  local file="scripts/cutover-smoke.sh" required
  if [ ! -f "$file" ]; then
    if [ "$IN_MIRROR" = "1" ]; then
      echo "estate cutover smoke is intentionally absent from the public mirror"
      return 0
    fi
    echo "$file is required in the internal release source" >&2
    return 1
  fi
  bash -n "$file" || return 1
  for required in \
    'EXPECTED_RELEASE=' \
    'X-Hash-Release' \
    'X-Hash-Environment' \
    'actual_environment" == "production"'; do
    grep -Fq "$required" "$file" || {
      echo "$file no longer fails closed on deployment identity: missing $required" >&2
      return 1
    }
  done
  echo "production cutover smoke requires the exact release and production runtime identity"
}

# Every file the mirror publishes is under the Hash Sustainable Use License, and the
# header is how a reader (and a downstream packager) knows it. A .go file without one is
# an unlicensed contribution in a fair-code repo.
#
# Go only, deliberately. The .sql, .ts and .svelte files here do not carry headers yet,
# and a gate that is red on the day it lands teaches everyone to ignore it. Widen the
# list when those files are backfilled, not before.
#
# This also catches a regeneration papercut: invoking sqlc directly rewrites
# internal/db/generated/ without the SPDX prelude. `make sqlc` uses the canonical
# wrapper that restores it; this gate catches bypasses and stale generated trees.
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
# here: the committed files carry a two-line SPDX prelude plus a blank line that the
# canonical generation wrapper adds after sqlc runs, so the diff shows those three lines
# removed and sqlc always exits non-zero. A newer compatible sqlc also changes only its
# generated `//   sqlc vX.Y.Z` comment. Judging this on the exit status would make the
# gate permanently red; judging it on "did it print anything" would make it permanently
# red too. So read the CONTENT: filter exactly the known prelude and generator-version
# comment, and treat anything else as real drift. Query/model staleness still produces
# added or removed Go lines and cannot hide behind either metadata filter.
sqlc_diff_is_comparison() {
	local rc="$1" out="$2"
	[ "$rc" -eq 0 ] && return 0
	[ "$rc" -eq 1 ] || return 1
	grep -E '^--- (a/)?generated/' <<<"$out" >/dev/null || return 1
	grep -E '^\+\+\+ (b/)?generated/' <<<"$out" >/dev/null
}

sqlc_diff_guard_self_test() {
	local comparison
	if sqlc_diff_is_comparison 1 'error parsing configuration files'; then
		echo "sqlc diff failure classifier accepted an execution error" >&2
		return 1
	fi
	comparison=$'--- a/generated/db.go\n+++ b/generated/db.go\n@@ -1 +1 @@\n-old\n+new'
	if ! sqlc_diff_is_comparison 1 "$comparison"; then
		echo "sqlc diff failure classifier rejected an ordinary comparison" >&2
		return 1
	fi
}

sqlc_generation_entrypoint() {
  local wrapper="scripts/generate-sqlc.sh"
  [ -f "$wrapper" ] || {
    echo "$wrapper is required so regenerated Go files retain their license header" >&2
    return 1
  }
  grep -Fq 'bash scripts/generate-sqlc.sh' Makefile || {
    echo "Makefile must route make sqlc through $wrapper" >&2
    return 1
  }
  grep -Fq 'sqlc generate' "$wrapper" || {
    echo "$wrapper must invoke sqlc generate" >&2
    return 1
  }
  grep -Fq '// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License' "$wrapper" || {
    echo "$wrapper must restore the Hash SPDX header after sqlc generation" >&2
    return 1
  }
  echo "make sqlc uses the license-preserving generation wrapper"
}

sqlc_fresh() {
	local out real rc
	command -v sqlc >/dev/null 2>&1 || {
		echo "not run: sqlc is not installed (brew install sqlc)"
		return 99
	}
	sqlc_diff_guard_self_test || return 1
	# Validate configuration, schema, and query parsing independently. sqlc diff
	# uses exit 1 both for an ordinary generated-code difference and for some
	# execution failures, so treating its filtered text alone as the verdict can
	# turn a parser/config error into a false green result.
	(cd internal/db && sqlc vet) || {
		echo "sqlc could not validate its configuration, schema, and queries" >&2
		return 1
	}
	out="$(cd internal/db && sqlc diff 2>&1)"
	rc=$?
	if ! sqlc_diff_is_comparison "$rc" "$out"; then
		echo "sqlc diff failed before producing a generated-code comparison:" >&2
		printf '%s\n' "$out" >&2
		return 1
	fi
	real="$(printf '%s\n' "$out" \
    | grep -E '^[+-]' \
    | grep -vE '^(--- |\+\+\+ )' \
    | grep -vE '^[+-]//   sqlc v[0-9]+\.[0-9]+\.[0-9]+$' \
    | grep -vxF -e '-' \
        -e '-// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License' \
        -e '-// Copyright (c) Bright Interaction')"
  if [ -n "$real" ]; then
    echo "internal/db/generated/ is stale: it does not match internal/db/queries/*.sql." >&2
    echo "Regenerate with: make sqlc" >&2
    echo "$real" | head -40 >&2
    return 1
  fi
  echo "internal/db/generated/ matches internal/db/queries/*.sql (modulo the SPDX prelude sqlc does not emit)"
}

# The canonical public workflow must install the same sqlc version that
# generated this tree and must make every skipped prerequisite fatal. Without
# both checks, sqlc_fresh can honestly report "SKIPPED" while GitHub still
# publishes a green status for stale generated database code.
public_workflow_fail_closed() {
  local workflow=".github/workflows/ci.yml"
  [ -f "$workflow" ] || {
    echo "$workflow is required in the public Hash source" >&2
    return 1
  }
  grep -Fq 'github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1' "$workflow" || {
    echo "$workflow must install pinned sqlc v1.31.1" >&2
    return 1
  }
  grep -Fq "HASH_CI_REQUIRE_ALL: '1'" "$workflow" || {
    echo "$workflow must set HASH_CI_REQUIRE_ALL to 1 for the canonical checks" >&2
    return 1
  }
  echo "public CI installs pinned sqlc and treats skipped checks as failures"
}

# Both scanners run from a binary on PATH when there is one (the estate installs
# gitleaks with brew, and split-public-repo.sh uses that same binary for the publish
# gate) and are otherwise installed on demand, which needs network. Set
# HASH_CI_SKIP_SCANNERS=1 to skip them when offline, and say SKIPPED rather than
# passing quietly, because a security scan that reports ok without running is worse
# than no scan.
resolve_scanner() {
  local name="$1" mod="$2"
  if [ "${HASH_CI_SKIP_SCANNERS:-0}" = "1" ]; then
    echo "not run: HASH_CI_SKIP_SCANNERS=1"
    return 99
  fi
  if command -v "$name" >/dev/null 2>&1; then
    SCANNER_BIN="$(command -v "$name")"
    return 0
  fi
  go install "$mod" >/dev/null 2>&1 || { echo "could not install $name (offline?)" >&2; return 1; }
  SCANNER_BIN="$(go env GOPATH)/bin/$name"
}

scan() {
  local name="$1" mod="$2"; shift 2
  resolve_scanner "$name" "$mod" || return $?
  "$SCANNER_BIN" "$@"
}

# gitleaks exits non-zero when it finds something, so the exit status is the verdict
# here and the wrapper passes it straight through. .gitleaks.toml allowlists the
# change-me markers in .env.example; a real credential would not carry them.
secret_scan() {
  local fixture_dir fixture_file self_test_rc
  resolve_scanner gitleaks github.com/zricethezav/gitleaks/v8@v8.30.1 || return $?

  # A scanner that starts but has no usable default rules is more dangerous
  # than a missing scanner: it reports green on every tree. Exercise one
  # realistic, synthetic GitHub-token shape before trusting the real result.
  fixture_dir="$(mktemp -d)" || return 1
  fixture_file="$fixture_dir/synthetic-leak.txt"
  # Keep the two halves separate in this source file so the scanner does not
  # quite correctly report its own test fixture as a repository credential.
  printf '%s%s%s\n' \
    'to' \
    'ken = "ghp_A1b2C3d4E5f6G7h8I9j0' \
    'K1l2M3n4O5p6Q7r8"' > "$fixture_file"
  "$SCANNER_BIN" detect --source "$fixture_dir" --config .gitleaks.toml \
    --no-git --no-banner --redact >/dev/null 2>&1
  self_test_rc=$?
  rm -f "$fixture_file"
  rmdir "$fixture_dir"
  if [ "$self_test_rc" -ne 1 ]; then
    echo "gitleaks self-test failed: synthetic credential was not detected (exit $self_test_rc)" >&2
    return 1
  fi

  if [ "$IN_MIRROR" = "1" ] && [ "$HAVE_GIT" = "1" ]; then
    # Every commit in the mirror is this project's, so scanning the full history is
    # exactly right, and it is the last gate before a credential becomes world-readable.
    "$SCANNER_BIN" detect --source . --config .gitleaks.toml --no-banner --redact
  else
    # Upstream the history belongs to a whole monorepo of unrelated projects, so a full
    # scan reports hundreds of findings that have nothing to do with Hash and trains
    # everyone to ignore the check. Here the working tree is what matters, and
    # split-public-repo.sh scans the real filtered payload's full history before it
    # pushes anything.
    "$SCANNER_BIN" detect --source . --config .gitleaks.toml --no-git --no-banner --redact
  fi
}

step "build"                                   go build ./...
step "vet"                                     vet_all
step "tests (executed, not merely compiled)"   go test -race ./... -count=1 -timeout=120s
step "frontend typecheck + production build"   frontend_checks
step "frontend dependency audit"               frontend_dependency_audit
step "Gotenberg renderer network policy"       renderer_network_policy
step "dependency image identity policy"        dependency_image_policy
step "production image identity policy"        production_image_policy
step "single-server production topology policy" single_server_topology_policy
step "audit-key provisioning documentation"   audit_key_documentation_policy
step "recovery VersionId documentation policy" recovery_version_identity_policy
step "production cutover smoke identity policy" cutover_smoke_identity_policy
step "gofmt"                                   gofmt_check
step "public workflow fail-closed prerequisites" public_workflow_fail_closed
step "sqlc generation entrypoint"               sqlc_generation_entrypoint
step "sqlc generated code up to date"          sqlc_fresh
step "license headers"                         license_headers
if [ "$IN_MIRROR" = "1" ] && [ "$HAVE_GIT" = "1" ]; then
  step "secret scan (full history)" secret_scan
else
  step "secret scan (working tree; split-public-repo.sh scans the filtered history)" secret_scan
fi
step "vulnerability scan" scan govulncheck golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

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
if [ ${#SKIPPED[@]} -ne 0 ] && [ "${HASH_CI_REQUIRE_ALL:-0}" = "1" ]; then
  echo "ci: release mode requires every check; skipped checks are a failure" >&2
  exit 1
fi
if [ ${#SKIPPED[@]} -ne 0 ]; then
  echo "ci: every check that RAN passed, but some did not run (see above)"
  exit 0
fi
echo "ci: all checks passed"
