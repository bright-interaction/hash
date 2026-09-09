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
SCANNER_TEMP_DIR=""

cleanup_scanner_temp() {
  [ -n "$SCANNER_TEMP_DIR" ] || return 0
  # GOBIN writes only these two reviewed tools. Remove exact filenames and use
  # rmdir so an unexpected file can never broaden cleanup scope.
  rm -f -- "$SCANNER_TEMP_DIR/gitleaks" "$SCANNER_TEMP_DIR/govulncheck"
  rmdir -- "$SCANNER_TEMP_DIR" 2>/dev/null || true
}
trap cleanup_scanner_temp EXIT

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

# Vet twice. The default build misses the E2E-only files spread across internal/e2e,
# auth, handler, and sign (they drive real Postgres + MinIO, so they cannot run here).
# Tag-gated code that nothing type-checks rots quietly and you find out during a
# release. Vet with the tag compiles it without running it, which is the honest half
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

# The renderer is an intentionally separate Go module so the application does
# not inherit Gotenberg's dependency graph. Root-module `go build ./...` and
# `go test ./...` stop at that module boundary, so exercise it explicitly or a
# broken/vulnerable renderer can pass an otherwise green Hash build.
renderer_module_checks() {
  [ -f gotenberg/go.mod ] && [ -f gotenberg/go.sum ] || {
    echo "gotenberg/go.mod and gotenberg/go.sum are required" >&2
    return 1
  }
  (
    cd gotenberg || return 1
    GOWORK=off go mod verify || return 1
    unformatted="$(find . -type f -name '*.go' -print0 | xargs -0 gofmt -l)"
    if [ -n "$unformatted" ]; then
      echo "These renderer Go files are not gofmt-clean:" >&2
      echo "$unformatted" >&2
      return 1
    fi
    GOWORK=off go vet ./... || return 1
    GOWORK=off go test -race -count=1 -timeout=120s ./...
  )
}

# Lock the renderer source boundary as tightly as the final image. `go mod
# verify` proves the downloaded bytes against go.sum; these assertions ensure
# a routine dependency tidy cannot silently change the audited upstream or add
# back the LibreOffice/pdfcpu module surfaces removed from Hash's binary.
renderer_source_policy() {
  local expected_imports actual_imports banned_deps file
  if grep -Eq '^[[:space:]]*(replace|exclude)([[:space:](]|$)' gotenberg/go.mod; then
    echo "renderer go.mod must not replace or exclude checksum-pinned dependencies" >&2
    return 1
  fi
  grep -Eq '^[[:space:]]*github\.com/gotenberg/gotenberg/v8 v8\.36\.0[[:space:]]*$' gotenberg/go.mod || {
    echo "renderer must pin github.com/gotenberg/gotenberg/v8 exactly at v8.36.0" >&2
    return 1
  }
  grep -Fxq 'github.com/gotenberg/gotenberg/v8 v8.36.0 h1:K4VDxqHRBIh/yKJbEStzQlaWOl286AnNjFwRFDtoKYc=' gotenberg/go.sum || {
    echo "renderer upstream v8.36.0 content checksum changed" >&2
    return 1
  }
  grep -Fxq 'github.com/gotenberg/gotenberg/v8 v8.36.0/go.mod h1:QuAMRjC9/VRIU6Yy2gfGZms0ISjieC+vtSYjdLIOzig=' gotenberg/go.sum || {
    echo "renderer upstream v8.36.0 module checksum changed" >&2
    return 1
  }
  expected_imports="$(printf '%s\n' \
    github.com/gotenberg/gotenberg/v8/pkg/modules/api \
    github.com/gotenberg/gotenberg/v8/pkg/modules/chromium)"
  actual_imports="$(grep -Eo 'github.com/gotenberg/gotenberg/v8/pkg/modules/[[:alnum:]_-]+' gotenberg/main.go | LC_ALL=C sort -u)"
  [ "$actual_imports" = "$expected_imports" ] || {
    echo "renderer must link exactly the Gotenberg API and Chromium modules" >&2
    printf 'actual module imports:\n%s\n' "$actual_imports" >&2
    return 1
  }
  for file in gotenberg/go.mod gotenberg/go.sum gotenberg/main.go; do
    if grep -Eqi '(pdfcpu|libreoffice|unoconv)' "$file"; then
      echo "$file reintroduces a banned renderer/document-engine dependency" >&2
      return 1
    fi
  done
  banned_deps="$(cd gotenberg && GOWORK=off go list -deps ./... \
    | grep -E '/pkg/modules/(libreoffice|pdfcpu|qpdf|pdftk|exiftool)(/|$)' || true)"
  if [ -n "$banned_deps" ]; then
    echo "renderer production dependency graph includes banned converter/engine modules:" >&2
    echo "$banned_deps" >&2
    return 1
  fi
  grep -Fq 'io.brightinteraction.hash.gotenberg.upstream.version="8.36.0"' gotenberg/Dockerfile \
    && grep -Fq 'io.brightinteraction.hash.gotenberg.upstream.module-h1="h1:K4VDxqHRBIh/yKJbEStzQlaWOl286AnNjFwRFDtoKYc="' gotenberg/Dockerfile || {
      echo "renderer image must carry the audited upstream version and module checksum" >&2
      return 1
    }
  grep -Fq 'CHROMIUM_DENY_LIST=^https?://.*' gotenberg/Dockerfile || {
    echo "renderer image must deny every HTTP(S) request before DNS resolution by default" >&2
    return 1
  }
  echo "renderer source/image provenance is checksum-pinned to Gotenberg v8.36.0; banned converter modules are absent"
}

# Gotenberg uploads HTML into its own /tmp directory and opens that staged
# entrypoint with file://. Blocking file:// in Chromium therefore blocks every
# completed document, even though the application never supplied a remote URL.
# Keep that local scheme available while preserving both resolution-based
# private-IP blocking and the explicit internal HTTP(S) deny-list.
renderer_network_policy() {
  local file service block deny required
  for file in docker-compose.yml docker-compose.prod.yml; do
    [ -f "$file" ] || continue
    if [ "$file" = "docker-compose.yml" ]; then
      service="gotenberg"
      grep -Fq 'dockerfile: gotenberg/Dockerfile' "$file" || {
        echo "$file must build the Hash renderer with gotenberg/Dockerfile" >&2
        return 1
      }
      grep -Fq 'image: ${HASH_GOTENBERG_IMAGE:-hash-gotenberg:dev}' "$file" || {
        echo "$file must default to the locally built Hash renderer" >&2
        return 1
      }
    else
      service="hash-gotenberg"
    fi
    block="$(awk -v service="$service" '
      $0 == "  " service ":" { in_service=1; next }
      in_service && /^  [[:alnum:]_-]+:$/ { exit }
      in_service { print }
    ' "$file")"
    [ -n "$block" ] || {
      echo "$file is missing renderer service $service" >&2
      return 1
    }
    for required in \
      'read_only: true' 'cap_drop:' '- ALL' 'no-new-privileges:true' \
      '/tmp:rw,noexec,nosuid,nodev,size=' '--api-disable-download-from=true' \
      '--pdfengines-disable-routes=true' '- hash-renderer' 'CMD-SHELL' \
      'command -v wget' 'command -v curl'; do
      printf '%s\n' "$block" | grep -Fq -- "$required" || {
        echo "$file renderer is missing required isolation control: $required" >&2
        return 1
      }
    done
    printf '%s\n' "$block" | grep -Fq -- '--chromium-deny-public-ips=true' || {
      echo "$file renderer must explicitly deny public-IP fetches" >&2
      return 1
    }
    for forbidden in '- default' '- app_default' '- web-proxy'; do
      if printf '%s\n' "$block" | grep -Fq -- "$forbidden"; then
        echo "$file renderer must not join shared network $forbidden" >&2
        return 1
      fi
    done
    [ "$(grep -Fc '      - hash-renderer' "$file")" -eq 3 ] || {
      echo "$file must connect only Hash, its worker, and the renderer to hash-renderer" >&2
      return 1
    }
    grep -A1 '^  hash-renderer:$' "$file" | grep -Fq 'internal: true' || {
      echo "$file hash-renderer network must be internal" >&2
      return 1
    }
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
    printf '%s\n' "$deny" | grep -Fq -- '--chromium-deny-list=^https?://.*' || {
      echo "$file must deny every HTTP(S) render request before DNS resolution" >&2
      return 1
    }
  done
  if [ -f docker-compose.prod.yml ]; then
    block="$(awk '
      $0 == "  hash-gotenberg:" { in_service=1; next }
      in_service && /^  [[:alnum:]_-]+:$/ { exit }
      in_service { print }
    ' docker-compose.prod.yml)"
    if printf '%s\n' "$block" | grep -Fq 'build:'; then
      echo "production renderer must remain image-only for exact-ID --no-build deployment" >&2
      return 1
    fi
  fi
  echo "Hash builds its minimal renderer; both Compose paths isolate and harden Chromium while preserving staged file:// input"
}

# The direct-Docker path is the vendor-neutral fallback when an operator does
# not use Compose. Keep it as complete as the Compose topology: an exact
# renderer image, isolated network, confined processes, internal renderer URL,
# and loopback-only application port. Candidate build instructions must not
# publish either half of the release before exact-artifact tests and scans.
standalone_renderer_documentation_policy() {
  local doc="DEPLOY.md" build_section run_section required
  build_section="$(awk '
    $0 == "## 2. Build the image" { in_section=1 }
    $0 == "## 3. Run" { exit }
    in_section { print }
  ' "$doc")"
  run_section="$(awk '
    $0 == "## 3. Run" { in_section=1 }
    $0 == "## 4. Reverse proxy, TLS, health" { exit }
    in_section { print }
  ' "$doc")"
  [ -n "$build_section" ] && [ -n "$run_section" ] || {
    echo "$doc is missing its standalone build/run sections" >&2
    return 1
  }
  if printf '%s\n' "$build_section" | grep -Fq 'docker push'; then
    echo "$doc must not push candidates before exact-image tests and scans" >&2
    return 1
  fi
  for required in \
    "export HASH_GOTENBERG_IMAGE=" \
    'docker network create --internal hash-renderer' \
    '--read-only --cap-drop ALL --security-opt no-new-privileges:true' \
    '--chromium-deny-list=^https?://.*' \
    'HASH_GOTENBERG_URL=http://hash-gotenberg:3000' \
    'docker network connect hash-renderer hash' \
    'docker network connect hash-renderer hash-worker' \
    '-p 127.0.0.1:8080:8080'; do
    printf '%s\n' "$run_section" | grep -Fq -- "$required" || {
      echo "$doc standalone renderer topology is incomplete: missing $required" >&2
      return 1
    }
  done
  echo "standalone Docker guidance builds/tests before push and isolates the exact renderer"
}

# Release-critical test services execute code on CI and deployment runners.
# Pinning only the application/toolchain still permits an upstream service tag
# to move between two runs of the same commit, so keep every canonical
# Postgres/MinIO dependency (and the browser suite's auxiliary services) bound
# to a registry digest. The human-readable tag remains for upgrade clarity.
dependency_image_policy() {
  local compose="docker-compose.yml" minio_compose="docker-compose.local-minio.yml"
  local drill="scripts/backup-restore-drill.sh"
  local root_workflow="../.github/workflows/hash-ci.yml" ref
  local postgres_ref="postgres:16.15-alpine3.24@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"
  local minio_ref="minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
  local mailhog_ref="mailhog/mailhog:v1.0.1@sha256:8d76a3d4ffa32a3661311944007a415332c4bb855657f4f6c57996405c009bea"
  local webhook_ref="mendhak/http-https-echo:31@sha256:0fefe04350131d7bb28355e3bf037062643e45f4a8a32f23679529e1b09d8ce4"

  for ref in "$postgres_ref" "$mailhog_ref" "$webhook_ref"; do
    grep -Fq "image: $ref" "$compose" || {
      echo "$compose must pin dependency image $ref" >&2
      return 1
    }
  done
  grep -Fq "image: $minio_ref" "$minio_compose" || {
    echo "$minio_compose must pin dependency image $minio_ref" >&2
    return 1
  }
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
  if [ -f "$root_workflow" ]; then
    for required in \
      'docker compose ps -q hash' \
      'docker compose ps -q worker' \
      'docker compose ps -q gotenberg' \
      "aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969" \
      '--severity HIGH,CRITICAL' \
      '--pkg-types os,library' \
      '--exit-code 1' \
      '^sha256:[0-9a-f]{64}$'; do
      grep -Fq -- "$required" "$root_workflow" || {
        echo "$root_workflow must scan both exact built image IDs with the pinned release policy: missing $required" >&2
        return 1
      }
    done
  fi
  echo "canonical Hash service dependencies are pinned by registry digest"
  echo "canonical browser CI scans the exact app and renderer image IDs"
}

# The external-S3 Compose path must not quietly inherit the bundled MinIO
# process or its startup dependency. Conversely, local development needs an
# explicit overlay that pins MinIO, waits for its health check, and forces both
# Hash processes back to the local endpoint. Render the merged models rather
# than trusting comments or filenames: Compose merge behavior is the contract.
standalone_storage_topology_policy() {
  local key_file fixture_access_key fixture_secret_key fixture_sha256
  local local_json external_json external_sse_s3_json
  command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 || {
    echo "not run: Docker Compose is required to validate storage topology"
    return 99
  }
  command -v jq >/dev/null 2>&1 || {
    echo "not run: jq is required to validate rendered Compose topology"
    return 99
  }

  key_file="$(mktemp)" || return 1
  # Generate a syntactically valid fingerprint without embedding a
  # credential-shaped 64-hex literal that secret scanners must flag.
  fixture_access_key="$(printf 'compose-policy-%s' access)"
  fixture_secret_key="$(printf 'compose-policy-%s' secret)"
  fixture_sha256="$(printf '%064d' 0)"
  local_json="$(docker compose --env-file /dev/null \
    -f docker-compose.yml -f docker-compose.local-minio.yml \
    config --format json)" || {
      rm -f "$key_file"
      echo "the bundled local-MinIO Compose topology does not render" >&2
      return 1
    }
  external_json="$(
    HASH_S3_ENDPOINT=fsn1.your-objectstorage.com \
    HASH_S3_REGION=fsn1 \
    HASH_S3_BUCKET=hash-compose-policy-fixture \
    HASH_S3_ACCESS_KEY="$fixture_access_key" \
    HASH_S3_SECRET_KEY="$fixture_secret_key" \
    HASH_S3_BUCKET_LOOKUP=path \
    HASH_S3_SSE_C_KEY_HOST_FILE="$key_file" \
    HASH_S3_SSE_C_KEY_SHA256="$fixture_sha256" \
      docker compose --env-file /dev/null \
        -f docker-compose.yml -f docker-compose.sse-c.yml \
        config --format json
  )" || {
      rm -f "$key_file"
      echo "the external-S3/SSE-C Compose topology does not render" >&2
      return 1
    }
  external_sse_s3_json="$(
    HASH_S3_ENDPOINT=s3.example.test \
    HASH_S3_REGION=eu-test-1 \
    HASH_S3_BUCKET=hash-compose-policy-fixture \
    HASH_S3_ACCESS_KEY="$fixture_access_key" \
    HASH_S3_SECRET_KEY="$fixture_secret_key" \
    HASH_S3_USE_SSL=true \
    HASH_S3_SSE_MODE=sse-s3 \
    HASH_S3_BUCKET_LOOKUP=dns \
      docker compose --env-file /dev/null -f docker-compose.yml \
        config --format json
  )" || {
      rm -f "$key_file"
      echo "the external-S3/SSE-S3 base Compose topology does not render" >&2
      return 1
    }
  rm -f "$key_file"

  printf '%s\n' "$external_json" | jq -e \
    --arg access "$fixture_access_key" --arg secret "$fixture_secret_key" '
    (.services | has("minio") | not) and
    (.volumes | has("hash_minio") | not) and
    (.services.hash.depends_on.minio == null) and
    (.services.worker.depends_on.minio == null) and
    (.services.hash.environment.HASH_S3_ENDPOINT == "fsn1.your-objectstorage.com") and
    (.services.worker.environment.HASH_S3_ENDPOINT == "fsn1.your-objectstorage.com") and
    (.services.hash.environment.HASH_S3_ACCESS_KEY == $access) and
    (.services.worker.environment.HASH_S3_ACCESS_KEY == $access) and
    (.services.hash.environment.HASH_S3_SECRET_KEY == $secret) and
    (.services.worker.environment.HASH_S3_SECRET_KEY == $secret) and
    (.services.hash.environment.HASH_S3_USE_SSL == "true") and
    (.services.worker.environment.HASH_S3_USE_SSL == "true") and
    (.services.hash.environment.HASH_S3_SSE_MODE == "sse-c") and
    (.services.worker.environment.HASH_S3_SSE_MODE == "sse-c") and
    ([.services.hash.secrets[].source] | index("hash-s3-sse-c") != null) and
    ([.services.worker.secrets[].source] | index("hash-s3-sse-c") != null)
  ' >/dev/null || {
    echo "external-S3/SSE-C Compose unexpectedly contains or depends on MinIO, or lost its TLS/SSE-C secret contract" >&2
    return 1
  }

  printf '%s\n' "$external_sse_s3_json" | jq -e \
    --arg access "$fixture_access_key" --arg secret "$fixture_secret_key" '
    (.services | has("minio") | not) and
    (.services.hash.depends_on.minio == null) and
    (.services.worker.depends_on.minio == null) and
    (.services.hash.environment.HASH_S3_ENDPOINT == "s3.example.test") and
    (.services.worker.environment.HASH_S3_ENDPOINT == "s3.example.test") and
    (.services.hash.environment.HASH_S3_ACCESS_KEY == $access) and
    (.services.worker.environment.HASH_S3_ACCESS_KEY == $access) and
    (.services.hash.environment.HASH_S3_SECRET_KEY == $secret) and
    (.services.worker.environment.HASH_S3_SECRET_KEY == $secret) and
    (.services.hash.environment.HASH_S3_USE_SSL == "true") and
    (.services.worker.environment.HASH_S3_USE_SSL == "true") and
    (.services.hash.environment.HASH_S3_SSE_MODE == "sse-s3") and
    (.services.worker.environment.HASH_S3_SSE_MODE == "sse-s3")
  ' >/dev/null || {
    echo "external-S3/SSE-S3 Compose unexpectedly contains or depends on MinIO, or lost its provider environment" >&2
    return 1
  }

  printf '%s\n' "$local_json" | jq -e '
    (.services | has("minio")) and
    (.volumes | has("hash_minio")) and
    (.services.hash.depends_on.minio.condition == "service_healthy") and
    (.services.worker.depends_on.minio.condition == "service_healthy") and
    (.services.hash.environment.HASH_S3_ENDPOINT == "hash-minio:9000") and
    (.services.worker.environment.HASH_S3_ENDPOINT == "hash-minio:9000") and
    (.services.hash.environment.HASH_S3_USE_SSL == "false") and
    (.services.worker.environment.HASH_S3_USE_SSL == "false") and
    (.services.hash.environment.HASH_S3_SSE_MODE == "sse-s3") and
    (.services.worker.environment.HASH_S3_SSE_MODE == "sse-s3")
  ' >/dev/null || {
    echo "bundled local-MinIO Compose lost its service, readiness dependency, or forced local storage policy" >&2
    return 1
  }

  grep -Fq 'docker-compose.local-minio.yml' DEPLOY.md || {
    echo "DEPLOY.md must document the opt-in local-MinIO overlay" >&2
    return 1
  }
  echo "standalone external-S3/SSE-C runs without MinIO; bundled MinIO remains an explicit local overlay"
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
  for service in hash hash-worker hash-gotenberg; do
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
  echo "production Hash processes and renderer are read-only, capability-free, no-new-privileges containers with bounded /tmp"
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

# A filesystem-style Hetzner Storage Box cannot replace Hash's S3 provider, but
# it can hold a cold whole-MinIO-volume recovery snapshot. Keep that workflow
# explicitly operator-started and prove its failure/restart behavior with only
# hermetic fake Docker/Restic commands; CI must never contact a live host.
storagebox_cold_backup_policy() {
  local workflow="scripts/storagebox-cold-backup.sh"
  local test_script="scripts/test-storagebox-cold-backup.sh"
  local doc="ops/BACKUP-RESTORE.md"
  local required
  for required in "$workflow" "$test_script" \
      ops/storagebox-cold-backup.config.example.json \
      ops/storagebox-maintenance-receipt.example.json \
      ops/storagebox-key-escrow-receipt.example.json; do
    [ -f "$required" ] || {
      echo "$required is required for the Storage Box cold-backup contract" >&2
      return 1
    }
  done
  bash -n "$workflow" || return 1
  bash -n "$test_script" || return 1
  for required in \
    'Storage Box is backup/DR only, never Hash' \
    'including `.minio.sys`' \
    'It offers no exclude flag' \
    'shared_minio_consumers_quiesced' \
    'gotenberg_container' \
    'restic-repository-decryption' \
    'minio-object-decryption' \
    'covers_all_versions_at_snapshot' \
    'bootstrap-storage-estate/intent.json' \
    'bootstrap-storage-estate/receipt/receipt.json' \
    'hash-storagebox-cold-backup-v2' \
    'material_in_snapshot:false'; do
    grep -Fq "$required" "$workflow" || {
      echo "$workflow lost a fail-closed cold-backup invariant: $required" >&2
      return 1
    }
  done
  for required in \
    'Storage Box is a valid encrypted **cold backup destination**' \
    'The ordinary Dockyard nightly backup intentionally continues to exclude' \
    'It does not back up or restore a Hetzner' \
    'Require exit `0`, not review exit `2`'; do
    grep -Fq "$required" "$doc" || {
      echo "$doc lost required Storage Box recovery guidance: $required" >&2
      return 1
    }
  done
  "$test_script"
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

# Install both scanners into a fresh private GOBIN instead of trusting PATH. The
# exact module version and checksum are then read from the binary's embedded Go
# build metadata, so a renamed or version-spoofing executable cannot satisfy the
# release gate. Set HASH_CI_SKIP_SCANNERS=1 to skip them when offline, and say
# SKIPPED rather than passing quietly, because a security scan that reports ok
# without running is worse than no scan.
resolve_scanner() {
  local name="$1" mod="$2" expected expected_command expected_module expected_h1
  local metadata actual_command installed
  if [ "${HASH_CI_SKIP_SCANNERS:-0}" = "1" ]; then
    echo "not run: HASH_CI_SKIP_SCANNERS=1"
    return 99
  fi
  case "$name" in
    gitleaks)
      expected_command="github.com/zricethezav/gitleaks/v8"
      expected_module="github.com/zricethezav/gitleaks/v8"
      expected_h1="h1:PmEvCfVI7ti9dV3s5aMZUY7sS2GxRvG3yzih7E+cS3w="
      ;;
    govulncheck)
      expected_command="golang.org/x/vuln/cmd/govulncheck"
      expected_module="golang.org/x/vuln"
      expected_h1="h1:Ju8QsuyhX3Hk8ma3CesTbO8vfJD9EvUBgHvkxHBzj0I="
      ;;
    *) echo "unsupported security scanner $name" >&2; return 1 ;;
  esac
  expected="${mod##*@}"
  [[ "$expected" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "security scanner $name must use an exact semantic version, got $mod" >&2
    return 1
  }
  if [ -z "$SCANNER_TEMP_DIR" ]; then
    SCANNER_TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hash-ci-scanners.XXXXXX")" || return 1
  fi
  SCANNER_BIN="$SCANNER_TEMP_DIR/$name"
  if [ ! -x "$SCANNER_BIN" ]; then
    GOBIN="$SCANNER_TEMP_DIR" go install "$mod" >/dev/null || {
      echo "could not install exact $name $expected (offline?)" >&2
      return 1
    }
  fi
  metadata="$(go version -m "$SCANNER_BIN")" || {
    echo "could not read embedded Go build metadata from $name" >&2
    return 1
  }
  actual_command="$(printf '%s\n' "$metadata" | awk -F '\t' '
    { for (i = 1; i <= NF; i++) if ($i == "path" && i < NF) { print $(i + 1); exit } }
  ')"
  installed="$(printf '%s\n' "$metadata" | awk -F '\t' '
    { for (i = 1; i <= NF; i++) if ($i == "mod" && i + 3 <= NF) {
        print $(i + 1) "|" $(i + 2) "|" $(i + 3); exit
      }
    }
  ')"
  [ "$actual_command" = "$expected_command" ] || {
    echo "installed $name command is $actual_command, want $expected_command" >&2
    return 1
  }
  [ "$installed" = "$expected_module|$expected|$expected_h1" ] || {
    echo "installed $name module metadata is $installed" >&2
    echo "want $expected_module|$expected|$expected_h1" >&2
    return 1
  }
}

scan() {
  local name="$1" mod="$2"; shift 2
  resolve_scanner "$name" "$mod" || return $?
  "$SCANNER_BIN" "$@"
}

renderer_vulnerability_scan() {
  local review="gotenberg/vulnerability-review.json" report rc
  local actual_version actual_h1 actual_revision expires reviewed today
  local detected approved unknown expected_review actual_review
  resolve_scanner govulncheck golang.org/x/vuln/cmd/govulncheck@v1.1.4 || return $?
  command -v jq >/dev/null 2>&1 || {
    echo "jq is required to reconcile renderer vulnerability results" >&2
    return 1
  }
  [ -f "$review" ] || {
    echo "$review is required for audited renderer vulnerability reconciliation" >&2
    return 1
  }

  actual_version="$(cd gotenberg && GOWORK=off go list -m -f '{{.Version}}' github.com/gotenberg/gotenberg/v8)" || return 1
  actual_h1="$(awk '$1 == "github.com/gotenberg/gotenberg/v8" && $2 == "v8.36.0" { print $3 }' gotenberg/go.sum)"
  actual_revision="$(sed -n 's/.*io.brightinteraction.hash.gotenberg.upstream.revision="\([0-9a-f]*\)".*/\1/p' gotenberg/Dockerfile)"
  jq -e \
    --arg module 'github.com/gotenberg/gotenberg/v8' \
    --arg version "$actual_version" \
    --arg h1 "$actual_h1" \
    --arg revision "$actual_revision" '
      .schema == 1 and .module == $module and .version == $version and
      .module_h1 == $h1 and .upstream_revision == $revision and
      .reviewed_on == "2026-09-09" and
      .review_expires_on == "2026-10-09" and
      (.basis | type == "string" and length > 0) and
      (.reviewed_on | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and
      (.review_expires_on | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and
      (.advisories | length == 7) and
      ([.advisories[].go_id] | length == (unique | length)) and
      all(.advisories[];
        (.go_id | test("^GO-[0-9]{4}-[0-9]{4}$")) and
        (.ghsa_id | test("^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")) and
        .reviewed_url == ("https://github.com/advisories/" + .ghsa_id) and
        .status == "not_affected" and
        (.official_affected_range | length > 0) and
        (.official_updated_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T")) and
        (.justification | type == "string" and length > 0))
    ' "$review" >/dev/null || {
      echo "$review does not match the exact audited renderer or has malformed statements" >&2
      return 1
    }
  expected_review="$(printf '%s\n' \
    'GO-2026-4990|GHSA-2pmr-289p-44r3|<= 8.31.0|2026-05-14T20:52:22Z' \
    'GO-2026-5080|GHSA-3cv5-q585-h563|<= 8.31.0|2026-05-14T20:52:33Z' \
    'GO-2026-5162|GHSA-62p3-hvxx-fxg4|<= 8.30.1|2026-05-14T20:51:33Z' \
    'GO-2026-5234|GHSA-7v3r-m9c8-r855|<= 8.29.1|2026-05-14T20:52:17Z' \
    'GO-2026-5244|GHSA-86m8-88fq-xfxp|<= 8.32.0|2026-05-29T16:50:38Z' \
    'GO-2026-5627|GHSA-rm4c-xj6x-49mw|<= 8.31.0|2026-05-14T20:52:18Z' \
    'GO-2026-5636|GHSA-rqgh-gxv4-6657|= 8.29.1|2026-05-14T20:52:08Z' \
    | LC_ALL=C sort)"
  actual_review="$(jq -r '.advisories[] | [.go_id, .ghsa_id, .official_affected_range, .official_updated_at] | join("|")' "$review" | LC_ALL=C sort)"
  [ "$actual_review" = "$expected_review" ] || {
    echo "$review no longer contains the exact reviewed GitHub advisory identities, ranges, and update timestamps" >&2
    return 1
  }
  expires="$(jq -r '.review_expires_on' "$review")"
  reviewed="$(jq -r '.reviewed_on' "$review")"
  today="$(date -u +%Y-%m-%d)"
  if [[ "$reviewed" > "$today" ]]; then
    echo "renderer vulnerability review date $reviewed is in the future" >&2
    return 1
  fi
  if [[ "$today" > "$expires" ]]; then
    echo "renderer vulnerability review expired on $expires; re-check every linked reviewed advisory" >&2
    return 1
  fi

  report="$(mktemp)" || return 1
  # Match the production Docker build and avoid auditing platform-only CGO
  # branches that cannot be linked into the renderer image. OpenVEX makes the
  # scanner verdict machine-readable: exit 3 means findings, while any other
  # nonzero code is an operational failure and can never be reconciled away.
  (cd gotenberg && GOWORK=off CGO_ENABLED=0 "$SCANNER_BIN" -format=openvex ./...) >"$report"
  rc=$?
  # OpenVEX output may exit zero even when it contains `affected` statements;
  # the document, not the status alone, is the verdict. Text mode normally uses
  # exit 3 for findings, so accept either result only long enough to parse it.
  case "$rc" in
    0|3) ;;
    *)
      rm -f "$report"
      echo "renderer govulncheck failed operationally with exit $rc" >&2
      return 1
      ;;
  esac
  jq -e --arg product 'pkg:golang/github.com%2Fgotenberg%2Fgotenberg%2Fv8@v8.36.0' '
    .["@context"] == "https://openvex.dev/ns/v0.2.0" and
    (.["@id"] | startswith("govulncheck/vex:")) and
    .version == 1 and
    .tooling == "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck" and
    (.statements | type == "array") and
    all(.statements[];
      (.status == "affected" or .status == "not_affected") and
      (.vulnerability.name | test("^GO-[0-9]{4}-[0-9]{4}$"))) and
    all(.statements[] | select(.status == "affected");
      any(.products[]?.subcomponents[]?; .["@id"] == $product))
  ' "$report" >/dev/null || {
    rm -f "$report"
    echo "renderer govulncheck did not emit valid OpenVEX" >&2
    return 1
  }
  detected="$(jq -r '.statements[] | select(.status == "affected") | .vulnerability.name' "$report" | LC_ALL=C sort -u)"
  approved="$(jq -r '.advisories[].go_id' "$review" | LC_ALL=C sort -u)"
  unknown="$(comm -23 <(printf '%s\n' "$detected") <(printf '%s\n' "$approved"))"
  rm -f "$report"
  if [ -z "$detected" ]; then
    if [ "$rc" -eq 3 ]; then
      echo "renderer govulncheck exit 3 contained no affected advisory" >&2
      return 1
    fi
    echo "renderer govulncheck found no affected vulnerabilities"
    return 0
  fi
  if [ -n "$unknown" ]; then
    echo "renderer govulncheck found unreviewed affected advisories:" >&2
    echo "$unknown" >&2
    return 1
  fi
  printf 'renderer govulncheck findings are covered by the unexpired exact-version review (%s):\n%s\n' "$expires" "$detected"
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
step "nested renderer module verify + test"    renderer_module_checks
step "renderer pinned-source/module policy"    renderer_source_policy
step "frontend typecheck + production build"   frontend_checks
step "frontend dependency audit"               frontend_dependency_audit
step "Gotenberg renderer network policy"       renderer_network_policy
step "standalone renderer documentation policy" standalone_renderer_documentation_policy
step "dependency image identity policy"        dependency_image_policy
step "standalone storage topology policy"      standalone_storage_topology_policy
step "production image identity policy"        production_image_policy
step "single-server production topology policy" single_server_topology_policy
step "audit-key provisioning documentation"   audit_key_documentation_policy
step "recovery VersionId documentation policy" recovery_version_identity_policy
step "Storage Box cold-backup contract"         storagebox_cold_backup_policy
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
step "renderer vulnerability scan"             renderer_vulnerability_scan

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
