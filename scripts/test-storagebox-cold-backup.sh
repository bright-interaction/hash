#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Copyright (c) Bright Interaction
#
# Hermetic contract tests for storagebox-cold-backup.sh. All Docker and Restic
# calls are intercepted by fixtures; this script never opens a network
# connection or touches a real container/repository.

set -euo pipefail
umask 077

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
subject="$script_dir/storagebox-cold-backup.sh"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/hash-storagebox-cold-test.XXXXXX")"
fixture_root="$(cd "$fixture_root" && pwd -P)"
cleanup() {
  case "$fixture_root" in
    "${TMPDIR:-/tmp}"/hash-storagebox-cold-test.*) rm -rf -- "$fixture_root" ;;
  esac
}
trap cleanup EXIT INT TERM

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

sha256_text() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

stat_identity() {
  stat -c '%d:%i' "$1" 2>/dev/null || stat -f '%d:%i' "$1"
}

fail() {
  printf 'test failure: %s\n' "$*" >&2
  exit 1
}

fixture_release_dir() {
  printf '%s/opt/hash/releases/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' "$1"
}

fixture_lock_file() {
  printf '%s/opt/hash-lock/maintenance.lock' "$1"
}

fixture_recovery_sentinel() {
  printf '%s/opt/hash/.cold-backup-recovery-required' "$1"
}

write_fake_docker() {
  local target="$1/bin/docker"
  cat > "$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root="${FAKE_ROOT:?}"
app_id="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
minio_id="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
postgres_id="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
state() { cat "$root/state/$1.running"; }
container_id() { cat "$root/state/$1.id"; }
resolve_name() {
  local selector="$1" name
  case "$selector" in
    hash-app|hash-worker|hash-gotenberg|pg-fixture|minio-fixture) printf '%s' "$selector"; return 0 ;;
  esac
  for name in hash-app hash-worker hash-gotenberg pg-fixture minio-fixture; do
    if [[ "$selector" == "$(container_id "$name")" || "$selector" == "$(cat "$root/state/$name.original-id")" ]]; then
      printf '%s' "$name"
      return 0
    fi
  done
  return 1
}
emit_container() {
  local selector="$1" name running health image ref project service exit_code mounts cmd id
  local env networks exposed restart_count inspect_count
  name="$(resolve_name "$selector")" || exit 1
  if [[ "$name" == hash-worker && -f "$root/state/hash-worker.unstable-armed" ]]; then
    inspect_count="$(cat "$root/state/hash-worker.inspect-count")"
    inspect_count=$((inspect_count + 1))
    printf '%s\n' "$inspect_count" > "$root/state/hash-worker.inspect-count"
    if ((inspect_count >= 3)); then
      restart_count="$(cat "$root/state/hash-worker.restart-count")"
      printf '%s\n' "$((restart_count + 1))" > "$root/state/hash-worker.restart-count"
      rm -f "$root/state/hash-worker.unstable-armed"
    fi
  fi
  id="$(container_id "$name")"
  running="$(state "$name")"
  restart_count="$(cat "$root/state/$name.restart-count")"
  exit_code=0
  mounts='[]'
  cmd='[]'
  env='[]'
  networks='{}'
  exposed='{}'
  case "$name" in
    hash-app|hash-worker)
      image="$app_id"; ref='hash-fixture:release'; project='hash-fixture'; health='healthy'
      [[ "$name" == hash-app ]] && service='app' || { service='worker'; health='none'; }
      env="$(jq -n --arg release 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' \
        --arg db 'postgres://hash:fixture-db-password@postgres:5432/hash_fixture?sslmode=disable' \
        '["HASH_RELEASE="+$release,"HASH_DB_URL="+$db,"HASH_S3_ENDPOINT=minio:9000",
          "HASH_S3_REGION=eu-central-1","HASH_S3_BUCKET=hash-bucket","HASH_S3_USE_SSL=false",
          "HASH_S3_BUCKET_LOOKUP=path","HASH_S3_SSE_MODE=sse-s3","HASH_S3_SSE_C_KEY_FILE="]')"
      if [[ -n "${FAKE_DOCKER_DB_URL_OVERRIDE:-}" ]]; then
        env="$(jq -c --arg value "$FAKE_DOCKER_DB_URL_OVERRIDE" \
          'map(if startswith("HASH_DB_URL=") then "HASH_DB_URL="+$value else . end)' <<<"$env")"
      fi
      if [[ "$name" == hash-app && -n "${FAKE_DOCKER_APP_S3_ENDPOINT:-}" ]]; then
        env="$(jq -c --arg value "$FAKE_DOCKER_APP_S3_ENDPOINT" \
          'map(if startswith("HASH_S3_ENDPOINT=") then "HASH_S3_ENDPOINT="+$value else . end)' <<<"$env")"
      fi
      if [[ "$name" == hash-worker && -n "${FAKE_DOCKER_WORKER_DB_URL:-}" ]]; then
        env="$(jq -c --arg value "$FAKE_DOCKER_WORKER_DB_URL" \
          'map(if startswith("HASH_DB_URL=") then "HASH_DB_URL="+$value else . end)' <<<"$env")"
      fi
      if [[ -n "${FAKE_DOCKER_PG_ENV:-}" \
          && ( "${FAKE_DOCKER_PG_ENV_TARGET:-all}" == all \
            || "${FAKE_DOCKER_PG_ENV_TARGET:-all}" == "$name" ) ]]; then
        env="$(jq -c --arg value "$FAKE_DOCKER_PG_ENV" '. + [$value]' <<<"$env")"
      fi
      networks='{"minio-network":{"NetworkID":"network-minio","IPAddress":"172.20.0.10","Aliases":[],"DNSNames":[]},"postgres-network":{"NetworkID":"network-postgres","IPAddress":"172.21.0.10","Aliases":[],"DNSNames":[]}}'
      ;;
    hash-gotenberg)
      image="sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"; ref='gotenberg:fixture'; project='hash-fixture'; service='gotenberg'; health='healthy'
      if [[ "${FAKE_DUPLICATE_MINIO_ALIAS:-0}" == 1 ]]; then
        networks='{"minio-network":{"NetworkID":"network-minio","IPAddress":"172.20.0.11","Aliases":["minio"],"DNSNames":["minio"]},"postgres-network":{"NetworkID":"network-postgres","IPAddress":"172.21.0.11","Aliases":[],"DNSNames":[]}}'
      elif [[ "${FAKE_DUPLICATE_POSTGRES_ALIAS:-0}" == 1 ]]; then
        networks='{"minio-network":{"NetworkID":"network-minio","IPAddress":"172.20.0.11","Aliases":[],"DNSNames":[]},"postgres-network":{"NetworkID":"network-postgres","IPAddress":"172.21.0.11","Aliases":["postgres"],"DNSNames":["postgres"]}}'
      else
        networks='{"minio-network":{"NetworkID":"network-minio","IPAddress":"172.20.0.11","Aliases":[],"DNSNames":[]},"postgres-network":{"NetworkID":"network-postgres","IPAddress":"172.21.0.11","Aliases":[],"DNSNames":[]}}'
      fi
      ;;
    pg-fixture)
      image="$postgres_id"; ref='postgres:fixture'; project='database-fixture'; service='postgres'; health='healthy'
      networks='{"postgres-network":{"NetworkID":"network-postgres","IPAddress":"172.21.0.2","Aliases":["postgres"],"DNSNames":["postgres"]}}'
      exposed='{"5432/tcp":{}}'
      ;;
    minio-fixture)
      image="$minio_id"; ref='minio/minio:fixture'; project='minio-fixture'; service='minio'; health='healthy'
      mounts="$(jq -n --arg source "$root/volume" '[{Type:"volume",Name:"minio-fixture-data",Source:$source,Destination:"/data"}]')"
      cmd='["server","/data","--console-address",":9001"]'
      networks='{"minio-network":{"NetworkID":"network-minio","IPAddress":"172.20.0.2","Aliases":["minio"],"DNSNames":["minio"]}}'
      exposed='{"9000/tcp":{},"9001/tcp":{}}'
      ;;
    *) exit 1 ;;
  esac
  [[ "$running" == 1 ]] || health='none'
  jq -n --arg name "$name" --arg id "$id" --arg image "$image" --arg ref "$ref" \
    --arg project "$project" --arg service "$service" --arg health "$health" \
    --argjson running "$( [[ "$running" == 1 ]] && printf true || printf false )" \
    --argjson exit_code "$exit_code" --argjson restart_count "$restart_count" \
    --argjson mounts "$mounts" --argjson cmd "$cmd" --argjson env "$env" \
    --argjson networks "$networks" --argjson exposed "$exposed" \
    '[{Id:$id,Name:$name,Image:$image,RestartCount:$restart_count,Config:{Image:$ref,Cmd:$cmd,Env:$env,ExposedPorts:$exposed,
      Labels:{"com.docker.compose.project":$project,"com.docker.compose.service":$service}},
      State:{Running:$running,ExitCode:$exit_code,Health:{Status:$health}},Mounts:$mounts,
      NetworkSettings:{Networks:$networks}}]'
}
printf '%s\n' "$*" >> "$root/docker.log"
case "${1:-}" in
  inspect)
    emit_container "$2"
    ;;
  volume)
    [[ "${2:-}" == inspect && "${3:-}" == --format && "${5:-}" == minio-fixture-data ]] || exit 2
    printf '%s\n' "$root/volume"
    ;;
  network)
    [[ "${2:-}" == inspect && -n "${3:-}" ]] || exit 2
    network="$3"
    case "$network" in
      minio-network)
        jq -n --arg app "$(container_id hash-app)" --arg worker "$(container_id hash-worker)" \
          --arg gotenberg "$(container_id hash-gotenberg)" --arg minio "$(container_id minio-fixture)" \
          '[{Name:"minio-network",Id:"network-minio",Containers:{
            ($app):{Name:"hash-app"},($worker):{Name:"hash-worker"},
            ($gotenberg):{Name:"hash-gotenberg"},($minio):{Name:"minio-fixture"}}}]'
        ;;
      postgres-network)
        jq -n --arg app "$(container_id hash-app)" --arg worker "$(container_id hash-worker)" \
          --arg gotenberg "$(container_id hash-gotenberg)" --arg postgres "$(container_id pg-fixture)" \
          '[{Name:"postgres-network",Id:"network-postgres",Containers:{
            ($app):{Name:"hash-app"},($worker):{Name:"hash-worker"},
            ($gotenberg):{Name:"hash-gotenberg"},($postgres):{Name:"pg-fixture"}}}]'
        ;;
      *) exit 2 ;;
    esac
    ;;
  ps)
    if [[ "$(state minio-fixture)" == 1 ]]; then printf '%s\n' minio-fixture; fi
    ;;
  stop)
    name="$(resolve_name "${@: -1}")" || exit 2
    if [[ "${FAKE_DOCKER_FAIL_STOP:-0}" == 1 ]]; then exit 41; fi
    printf '0\n' > "$root/state/$name.running"
    if [[ "${FAKE_DOCKER_REPLACE_AFTER_MINIO_STOP:-0}" == 1 && "$name" == minio-fixture ]]; then
      printf '%064d\n' 9 > "$root/state/minio-fixture.id"
    fi
    if [[ "${FAKE_DOCKER_LINK_SECRET_AFTER_MINIO_STOP:-0}" == 1 && "$name" == minio-fixture ]]; then
      ln "$root/opt/hash/.env" "$root/volume/hash-runtime-secret-hardlink"
    fi
    ;;
  start)
    name="$(resolve_name "$2")" || exit 2
    if [[ "${FAKE_DOCKER_FAIL_START:-}" == "$name" ]]; then exit 42; fi
    printf '1\n' > "$root/state/$name.running"
    if [[ "$name" == hash-worker && "${FAKE_DOCKER_WORKER_UNSTABLE:-0}" == 1 ]]; then
      : > "$root/state/hash-worker.unstable-armed"
      printf '0\n' > "$root/state/hash-worker.inspect-count"
    fi
    printf '%s\n' "$name"
    ;;
  image)
    if [[ "${2:-}" == inspect && "${3:-}" == --format ]]; then
      printf '%s\n' 1048576
    elif [[ "${2:-}" == save && "${3:-}" == --output ]]; then
      if [[ "${FAKE_DOCKER_BLOCK_IMAGE_SAVE:-0}" == 1 ]]; then
        : > "$root/image-save.blocked"
        while [[ ! -e "$root/image-save.release" ]]; do sleep 0.05; done
      fi
      printf 'fixture image archive for %s\n' "$5" > "$4"
      if [[ "${FAKE_DOCKER_REPLACE_DURING_STAGE:-0}" == 1 && "$5" == "$postgres_id" ]]; then
        printf '%064d\n' 8 > "$root/state/hash-app.id"
      fi
      if [[ "${FAKE_DOCKER_REPLACE_CURRENT_DURING_STAGE:-0}" == 1 && "$5" == "$postgres_id" ]]; then
        mv "$root/opt/hash/current" "$root/opt/hash/current.replaced-old"
        ln -s releases/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee "$root/opt/hash/current"
      fi
      if [[ "${FAKE_DOCKER_REPLACE_BOOTSTRAP_ESTATE_DURING_STAGE:-0}" == 1 && "$5" == "$postgres_id" ]]; then
        cp "$root/opt/hash/bootstrap-storage-estate/intent.json" \
          "$root/opt/hash/bootstrap-storage-estate/intent.replacement.json"
        mv "$root/opt/hash/bootstrap-storage-estate/intent.replacement.json" \
          "$root/opt/hash/bootstrap-storage-estate/intent.json"
      fi
    else
      exit 2
    fi
    ;;
  exec)
    shift
    [[ "${1:-}" == -i ]] && shift
    container="$(resolve_name "$1")" || exit 2; shift
    case "${1:-}" in
      psql)
        if [[ " $* " == *' --command '* ]]; then
          if [[ " $* " == *pg_control_system* ]]; then
            printf '%s\t%s\t%s\n' hash_fixture \
              "${FAKE_POSTGRES_SYSTEM_IDENTIFIER:-1234567890123456789}" \
              "${FAKE_POSTGRES_DATABASE_OID:-16384}"
          else
            printf '%s\n' 1048576
          fi
        else
          cat >/dev/null
          printf '%s\n' 'YQ==\t"a"\tdocument_final_pdf\tdocument:1\torg\t-\tf\tt\t1\tversion-fixture\tf\tf'
        fi
        ;;
      pg_dump)
        printf 'fixture custom PostgreSQL dump\n'
        ;;
      /usr/local/bin/hash-rollback-check)
        if [[ "${FAKE_DB_IDENTITY_UNSAFE:-0}" == 1 ]]; then
          printf '%s\n' '{"safe":false,"complete":true}'
          exit 1
        fi
        printf '%s\n' '{"safe":true,"complete":true}'
        ;;
      *) exit 2 ;;
    esac
    ;;
  *) exit 2 ;;
esac
EOF
  chmod +x "$target"
}

write_fake_restic() {
  local target="$1/bin/restic"
  cat > "$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root="${FAKE_ROOT:?}"
snapshot="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
case "${1:-}" in
  backup)
    if [[ "${2:-}" == --help ]]; then printf '%s\n' '  --json'; exit 0; fi
    printf '%s\n' "$*" >> "$root/restic.log"
    [[ "$*" != *--exclude* ]] || exit 61
    stage=''
    for arg in "$@"; do
      case "$arg" in "$root/state/staging/"*) stage="$arg" ;; esac
    done
    [[ -n "$stage" && -f "$stage/bootstrap-storage-estate/intent.json" \
        && -f "$stage/bootstrap-storage-estate/receipt/receipt.json" ]] || exit 63
    jq -e '
      .schema_version == 2 and .workflow == "hash-storagebox-cold-backup-v2" and
      .bootstrap_storage_estate.intent.snapshot_path == "bootstrap-storage-estate/intent.json" and
      .bootstrap_storage_estate.receipt.snapshot_path == "bootstrap-storage-estate/receipt/receipt.json" and
      .bootstrap_storage_estate.marker_key == "_hash/bootstrap-estate/v1" and
      (.bootstrap_storage_estate.marker_version_id | length > 0) and
      (.bootstrap_storage_estate.intent.source_identity | test("^[0-9]+:[0-9]+$")) and
      (.bootstrap_storage_estate.receipt.source_identity | test("^[0-9]+:[0-9]+$")) and
      (.bootstrap_storage_estate.intent.sha256 | test("^[0-9a-f]{64}$")) and
      (.bootstrap_storage_estate.receipt.sha256 | test("^[0-9a-f]{64}$"))
    ' "$stage/metadata/backup-manifest.json" >/dev/null || exit 64
    if [[ "${FAKE_RESTIC_FAIL_BACKUP:-0}" == 1 ]]; then
      printf '%s\n' 'fixture backup failure' >&2
      exit 62
    fi
    printf '{"message_type":"summary","snapshot_id":"%s"}\n' "$snapshot"
    ;;
  ls)
    if [[ "${2:-}" == --help ]]; then printf '%s\n' '  --recursive'; exit 0; fi
    path="${@: -1}"
    printf '%s\n' "$*" >> "$root/restic.log"
    jq -n --arg path "$path" '{struct_type:"node",path:$path,type:"file"}'
    ;;
  check)
    if [[ "${2:-}" == --help ]]; then printf '%s\n' '  --read-data-subset'; exit 0; fi
    printf '%s\n' "$*" >> "$root/restic.log"
    ;;
  cat)
    [[ "${2:-}" == config ]] || exit 2
    printf '%s\n' '{"version":2,"id":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}'
    ;;
  snapshots)
    printf '%s\n' '[]'
    ;;
  *) exit 2 ;;
esac
EOF
  chmod +x "$target"
}

write_fake_flock() {
  local target="$1/bin/flock"
  cat > "$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root="${FAKE_ROOT:?}"
printf '%s\n' "$*" >> "$root/flock.log"
[[ "${FAKE_FLOCK_FAIL:-0}" == 0 ]] || exit 75
[[ "${1:-}" == --exclusive && "${2:-}" == --nonblock && "${3:-}" =~ ^[0-9]+$ ]] || exit 2
EOF
  chmod +x "$target"
}

setup_fixture() {
  local root="$1" repo repo_sha archive_sha archive_bytes compose_sha sse_c_compose_sha inventory_sha verifier_sha now name id
  local commit hash_root release_store release fixture_uid bootstrap_root bootstrap_receipt_dir
  local bootstrap_root_identity bootstrap_receipt_dir_identity bootstrap_intent_identity bootstrap_receipt_identity
  local bootstrap_intent_sha bootstrap_receipt_sha
  commit='eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
  hash_root="$root/opt/hash"
  bootstrap_root="$hash_root/bootstrap-storage-estate"
  bootstrap_receipt_dir="$bootstrap_root/receipt"
  release_store="$hash_root/releases"
  release="$release_store/$commit"
  fixture_uid="$(id -u)"
  mkdir -p "$root/bin" "$root/state" "$release" "$hash_root/runtime-secrets" \
    "$bootstrap_receipt_dir" "$root/opt/hash-lock" "$root/minio-secrets" \
    "$root/volume/.minio.sys" "$root/volume/hash-bucket"
  chmod 0700 "$root/state"
  chmod 0755 "$root/opt/hash-lock"
  chmod 0700 "$hash_root/runtime-secrets" "$bootstrap_root" "$bootstrap_receipt_dir" "$root/minio-secrets"
  ln -s "releases/$commit" "$hash_root/current"
  printf 'fixture minio metadata\n' > "$root/volume/.minio.sys/config"
  printf 'fixture retained object\n' > "$root/volume/hash-bucket/object"
  printf 'fixture release image archive\n' > "$release/images.tar"
  printf 'services: {}\n' > "$release/docker-compose.yml"
  printf 'services: {}\n' > "$release/docker-compose.sse-c.yml"
  printf '%s\n' \
    'HASH_IMAGE=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    'HASH_GOTENBERG_IMAGE=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' \
    'HASH_RELEASE=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' \
    'HASH_ENVIRONMENT=production' > "$release/release.env"
  cp "$script_dir/../ops/recovery-object-inventory.sql" "$release/recovery-object-inventory.sql"
  cp "$script_dir/verify-recovery-objects.sh" "$release/verify-recovery-objects.sh"
  archive_sha="$(sha256_file "$release/images.tar")"
  archive_bytes="$(wc -c < "$release/images.tar" | tr -d ' ')"
  compose_sha="$(sha256_file "$release/docker-compose.yml")"
  sse_c_compose_sha="$(sha256_file "$release/docker-compose.sse-c.yml")"
  inventory_sha="$(sha256_file "$release/recovery-object-inventory.sql")"
  verifier_sha="$(sha256_file "$release/verify-recovery-objects.sh")"
  jq -n --arg archive_sha "$archive_sha" --argjson archive_bytes "$archive_bytes" \
    --arg compose_sha "$compose_sha" --arg sse_c_compose_sha "$sse_c_compose_sha" \
    --arg inventory_sha "$inventory_sha" --arg verifier_sha "$verifier_sha" \
    '{schema_version:4,commit_sha:"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      app_image_id:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      gotenberg_image_id:"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      image_archive_sha256:$archive_sha,image_archive_bytes:$archive_bytes,
      compose_sha256:$compose_sha,sse_c_compose:"docker-compose.sse-c.yml",
      sse_c_compose_sha256:$sse_c_compose_sha,
      recovery_inventory:"recovery-object-inventory.sql",recovery_inventory_sha256:$inventory_sha,
      recovery_verifier:"verify-recovery-objects.sh",recovery_verifier_sha256:$verifier_sha}' \
    > "$release/manifest.json"

  jq -n '{schema_version:1,endpoint:"minio:9000",region:"eu-central-1",
    bucket:"hash-bucket",use_ssl:false,bucket_lookup:"path",mode:"sse-s3",
    sse_c_key_sha256:""}' > "$hash_root/storage-contract.json"
  jq -n '{schema_version:1,host:"postgres",port:5432,
    database:"hash_fixture",username:"hash",ssl_mode:"disable",
    system_identifier:"1234567890123456789",database_oid:16384}' \
    > "$hash_root/database-contract.json"
  jq -n --slurpfile storage "$hash_root/storage-contract.json" \
    '{schema_version:1,
      candidate:{schema_version:2,phase:"foundation-empty-database",
        commit_sha:"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        app_image_id:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        migrations_sha256:"abababababababababababababababababababababababababababababababab",
        lifecycle_contract_version:1},
      storage:$storage[0],marker_key:"_hash/bootstrap-estate/v1",
      marker_nonce_hex:"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      marker_sha256:"efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
      created_at:"2026-01-01T00:00:00Z",retention_years:7,
      marker_retain_until:"2033-01-01T00:00:00Z"}' \
    > "$bootstrap_root/intent.json"
  jq -n '{schema_version:1,marker_key:"_hash/bootstrap-estate/v1",
    marker_version_id:"fixture-bootstrap-marker-version",
    marker_sha256:"efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
    marker_retain_until:"2033-01-01T00:00:00Z"}' \
    > "$bootstrap_receipt_dir/receipt.json"
  printf '%s\n' 'fixture Hash runtime secrets' > "$hash_root/.env"
  printf '%s\n' \
    'HASH_DB_URL=postgres://hash:fixture-db-password@postgres:5432/hash_fixture?sslmode=disable' \
    > "$hash_root/runtime-secrets/hash-db.env"
  printf '%s\n' 'fixture MinIO runtime secrets' > "$root/minio-secrets/minio.env"
  chmod 0600 "$hash_root/storage-contract.json" "$hash_root/database-contract.json" \
    "$bootstrap_root/intent.json" "$bootstrap_receipt_dir/receipt.json" \
    "$hash_root/.env" "$hash_root/runtime-secrets/hash-db.env" "$root/minio-secrets/minio.env"

  bootstrap_root_identity="$(stat_identity "$bootstrap_root")"
  bootstrap_receipt_dir_identity="$(stat_identity "$bootstrap_receipt_dir")"
  bootstrap_intent_identity="$(stat_identity "$bootstrap_root/intent.json")"
  bootstrap_receipt_identity="$(stat_identity "$bootstrap_receipt_dir/receipt.json")"
  bootstrap_intent_sha="$(sha256_file "$bootstrap_root/intent.json")"
  bootstrap_receipt_sha="$(sha256_file "$bootstrap_receipt_dir/receipt.json")"

  repo='sftp:u00000@u00000.your-storagebox.de:/home/hash-cold-fixture'
  repo_sha="$(printf '%s' "$repo" | sha256_text)"
  {
    printf 'RESTIC_REPOSITORY=%s\n' "$repo"
    printf '%s' 'RESTIC_PASS'
    printf '%s\n' 'WORD=fixture-only-not-a-secret'
  } > "$root/restic.env"
  chmod 0600 "$root/restic.env"

  jq -n --arg root "$root" --arg hash_root "$hash_root" --arg release_store "$release_store" \
    --arg release "$release" --arg repo_sha "$repo_sha" --arg inventory_sha "$inventory_sha" \
    --arg verifier_sha "$verifier_sha" --argjson fixture_uid "$fixture_uid" \
    --arg bootstrap_root "$bootstrap_root" --arg bootstrap_root_identity "$bootstrap_root_identity" \
    --arg bootstrap_receipt_dir "$bootstrap_receipt_dir" --arg bootstrap_receipt_dir_identity "$bootstrap_receipt_dir_identity" \
    --arg bootstrap_intent_identity "$bootstrap_intent_identity" --arg bootstrap_receipt_identity "$bootstrap_receipt_identity" \
    --arg bootstrap_intent_sha "$bootstrap_intent_sha" --arg bootstrap_receipt_sha "$bootstrap_receipt_sha" \
    '{schema_version:3,
      compose:{project:"hash-fixture",app_service:"app",worker_service:"worker",gotenberg_service:"gotenberg"},
      containers:{app:"hash-app",worker:"hash-worker",gotenberg:"hash-gotenberg",postgres:"pg-fixture",minio:"minio-fixture"},
      postgres:{database:"hash_fixture",user:"hash_dump",application_user:"hash",
        host:"postgres",port:5432,network:"postgres-network",
        ssl_mode:"disable",system_identifier:"1234567890123456789",database_oid:16384},
      minio:{volume:"minio-fixture-data",data_path:($root+"/volume"),mount_destination:"/data",
        expected_image_id:"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        endpoint_host:"minio",endpoint_port:9000,network:"minio-network",bucket:"hash-bucket"},
      release:{store:$release_store,dir:$release,current_symlink:($hash_root+"/current"),owner_uid:$fixture_uid},
      contracts:{storage:($hash_root+"/storage-contract.json"),database:($hash_root+"/database-contract.json"),owner_uid:$fixture_uid},
      bootstrap_storage_estate:{root:$bootstrap_root,root_identity:$bootstrap_root_identity,
        intent:($bootstrap_root+"/intent.json"),intent_identity:$bootstrap_intent_identity,
        intent_sha256:$bootstrap_intent_sha,receipt_dir:$bootstrap_receipt_dir,
        receipt_dir_identity:$bootstrap_receipt_dir_identity,
        receipt:($bootstrap_receipt_dir+"/receipt.json"),receipt_identity:$bootstrap_receipt_identity,
        receipt_sha256:$bootstrap_receipt_sha,owner_uid:$fixture_uid},
      inventory_sql:($release+"/recovery-object-inventory.sql"),
      inventory_sql_sha256:$inventory_sha,
      verifier_script:($release+"/verify-recovery-objects.sh"),
      verifier_script_sha256:$verifier_sha,
      secret_sources:[
        {purpose:"hash-runtime-env",path:($hash_root+"/.env"),owner_uid:$fixture_uid},
        {purpose:"hash-database-env",path:($hash_root+"/runtime-secrets/hash-db.env"),owner_uid:$fixture_uid},
        {purpose:"minio-runtime-env:primary",path:($root+"/minio-secrets/minio.env"),owner_uid:$fixture_uid}],
      state_dir:($root+"/state"),
      restic:{env_file:($root+"/restic.env"),repository_variable:"RESTIC_REPOSITORY",
        password_variable:"RESTIC_PASSWORD",repository_sha256:$repo_sha,host:"hash-fixture",
        config_id:"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        stop_timeout_seconds:5,health_timeout_seconds:5,worker_settle_seconds:1,integrity_subset:"1%"}}' \
    > "$root/config.json"
  chmod 0600 "$root/config.json"

  now="$(date -u +%FT%TZ)"
  jq -n --arg now "$now" \
    '{schema_version:1,scope:"hash-storagebox-cold-backup",maintenance_window_id:"fixture-window-1",
      approved_by:"Fixture Operator",approved_at:$now,ingress_drained:true,
      hash_writers_authorized_to_stop:true,shared_minio_consumers_quiesced:true}' \
    > "$root/maintenance.json"
  chmod 0600 "$root/maintenance.json"
  jq -n --arg repo_sha "$repo_sha" --arg now "$now" \
    '{schema_version:1,scope:"hash-storagebox-cold-backup-key-escrow",
      data_repository_sha256:$repo_sha,
      escrow_system_identity_sha256:"9999999999999999999999999999999999999999999999999999999999999999",
      escrow_reference:"fixture-break-glass-record",separate_failure_domain:true,
      rotation_state_reviewed:true,data_decryption_keysets_complete:true,
      verified_by:"Fixture Operator",verified_at:$now,
      key_sets:[
        {purpose:"restic-repository-decryption",manifest_reference:"fixture-restic-keyset-v1",covers_all_versions_at_snapshot:true},
        {purpose:"minio-object-decryption",manifest_reference:"fixture-minio-keyset-v1",covers_all_versions_at_snapshot:true},
        {purpose:"hash-audit-signing",manifest_reference:"fixture-audit-keyset-v1",covers_all_versions_at_snapshot:true},
        {purpose:"hash-signer-token",manifest_reference:"fixture-token-keyset-v1",covers_all_versions_at_snapshot:true},
        {purpose:"hash-session",manifest_reference:"fixture-session-keyset-v1",covers_all_versions_at_snapshot:true},
        {purpose:"hash-webhook-encryption",manifest_reference:"fixture-webhook-keyset-v1",covers_all_versions_at_snapshot:true},
        {purpose:"hash-ai-shield",manifest_reference:"fixture-not-configured-review-v1",covers_all_versions_at_snapshot:true}]}' \
    > "$root/key-escrow.json"
  chmod 0600 "$root/key-escrow.json"

  printf '1\n' > "$root/state/hash-app.running"
  printf '1\n' > "$root/state/hash-worker.running"
  printf '1\n' > "$root/state/hash-gotenberg.running"
  printf '1\n' > "$root/state/pg-fixture.running"
  printf '1\n' > "$root/state/minio-fixture.running"
  id=1
  for name in hash-app hash-worker hash-gotenberg pg-fixture minio-fixture; do
    printf '%064d\n' "$id" > "$root/state/$name.id"
    cp "$root/state/$name.id" "$root/state/$name.original-id"
    printf '0\n' > "$root/state/$name.restart-count"
    ((id += 1))
  done
  : > "$root/docker.log"
  : > "$root/restic.log"
  : > "$root/flock.log"
  : > "$root/opt/hash-lock/maintenance.lock"
  chmod 0600 "$root/opt/hash-lock/maintenance.lock"
  write_fake_docker "$root"
  write_fake_restic "$root"
  write_fake_flock "$root"
}

run_subject() {
  local root="$1"; shift
  FAKE_ROOT="$root" HASH_COLD_BACKUP_HERMETIC_ROOT="$root" \
    PATH="$root/bin:$PATH" "$subject" "$@"
}

bash -n "$subject"

missing="$fixture_root/missing-receipt"
setup_fixture "$missing"
if run_subject "$missing" backup --dry-run --config "$missing/config.json" \
    --maintenance-receipt "$missing/maintenance.json" >/dev/null 2>&1; then
  fail 'backup dry-run accepted a missing key-escrow receipt'
fi
[[ ! -s "$missing/docker.log" || "$(grep -c '^stop ' "$missing/docker.log" || true)" == 0 ]] \
  || fail 'receipt failure mutated a container'

extra_config_key="$fixture_root/extra-schema-v3-config-key"
setup_fixture "$extra_config_key"
jq '.bootstrap_storage_estate.unreviewed = true' \
  "$extra_config_key/config.json" > "$extra_config_key/config.tmp"
mv "$extra_config_key/config.tmp" "$extra_config_key/config.json"
chmod 0600 "$extra_config_key/config.json"
if run_subject "$extra_config_key" preflight --config "$extra_config_key/config.json" \
    --maintenance-receipt "$extra_config_key/maintenance.json" \
    --key-escrow-receipt "$extra_config_key/key-escrow.json" >/dev/null 2>&1; then
  fail 'schema-v3 config accepted an unknown bootstrap storage-estate key'
fi
[[ ! -s "$extra_config_key/docker.log" && ! -s "$extra_config_key/restic.log" ]] \
  || fail 'unknown schema-v3 config key reached a runtime or repository'

no_metadata="$fixture_root/no-minio-metadata"
setup_fixture "$no_metadata"
rm -rf -- "$no_metadata/volume/.minio.sys"
if run_subject "$no_metadata" preflight --config "$no_metadata/config.json" \
    --maintenance-receipt "$no_metadata/maintenance.json" \
    --key-escrow-receipt "$no_metadata/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a MinIO volume without .minio.sys'
fi
[[ "$(grep -c '^stop ' "$no_metadata/docker.log" || true)" == 0 ]] \
  || fail 'failed preflight mutated a container'

missing_estate_receipt="$fixture_root/missing-bootstrap-estate-receipt"
setup_fixture "$missing_estate_receipt"
rm "$missing_estate_receipt/opt/hash/bootstrap-storage-estate/receipt/receipt.json"
if run_subject "$missing_estate_receipt" preflight --config "$missing_estate_receipt/config.json" \
    --maintenance-receipt "$missing_estate_receipt/maintenance.json" \
    --key-escrow-receipt "$missing_estate_receipt/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a partial bootstrap storage-estate artifact set'
fi
[[ ! -s "$missing_estate_receipt/docker.log" && ! -s "$missing_estate_receipt/restic.log" ]] \
  || fail 'partial bootstrap storage-estate failure reached a runtime or repository'

symlinked_estate_intent="$fixture_root/symlinked-bootstrap-estate-intent"
setup_fixture "$symlinked_estate_intent"
mv "$symlinked_estate_intent/opt/hash/bootstrap-storage-estate/intent.json" \
  "$symlinked_estate_intent/estate-intent-target.json"
ln -s "$symlinked_estate_intent/estate-intent-target.json" \
  "$symlinked_estate_intent/opt/hash/bootstrap-storage-estate/intent.json"
if run_subject "$symlinked_estate_intent" preflight --config "$symlinked_estate_intent/config.json" \
    --maintenance-receipt "$symlinked_estate_intent/maintenance.json" \
    --key-escrow-receipt "$symlinked_estate_intent/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a symlinked bootstrap storage-estate intent'
fi
[[ ! -s "$symlinked_estate_intent/docker.log" && ! -s "$symlinked_estate_intent/restic.log" ]] \
  || fail 'symlinked bootstrap storage-estate intent reached a runtime or repository'

hardlinked_estate_receipt="$fixture_root/hardlinked-bootstrap-estate-receipt"
setup_fixture "$hardlinked_estate_receipt"
ln "$hardlinked_estate_receipt/opt/hash/bootstrap-storage-estate/receipt/receipt.json" \
  "$hardlinked_estate_receipt/estate-receipt-second-link.json"
if run_subject "$hardlinked_estate_receipt" preflight --config "$hardlinked_estate_receipt/config.json" \
    --maintenance-receipt "$hardlinked_estate_receipt/maintenance.json" \
    --key-escrow-receipt "$hardlinked_estate_receipt/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a multiply-linked bootstrap storage-estate receipt'
fi
[[ ! -s "$hardlinked_estate_receipt/docker.log" && ! -s "$hardlinked_estate_receipt/restic.log" ]] \
  || fail 'hardlinked bootstrap storage-estate receipt reached a runtime or repository'

permissive_estate_dir="$fixture_root/permissive-bootstrap-estate-directory"
setup_fixture "$permissive_estate_dir"
chmod 0750 "$permissive_estate_dir/opt/hash/bootstrap-storage-estate/receipt"
if run_subject "$permissive_estate_dir" preflight --config "$permissive_estate_dir/config.json" \
    --maintenance-receipt "$permissive_estate_dir/maintenance.json" \
    --key-escrow-receipt "$permissive_estate_dir/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a non-0700 bootstrap storage-estate directory'
fi
[[ ! -s "$permissive_estate_dir/docker.log" && ! -s "$permissive_estate_dir/restic.log" ]] \
  || fail 'permissive bootstrap storage-estate directory reached a runtime or repository'

wrong_estate_mode="$fixture_root/wrong-bootstrap-estate-file-mode"
setup_fixture "$wrong_estate_mode"
chmod 0400 "$wrong_estate_mode/opt/hash/bootstrap-storage-estate/intent.json"
if run_subject "$wrong_estate_mode" preflight --config "$wrong_estate_mode/config.json" \
    --maintenance-receipt "$wrong_estate_mode/maintenance.json" \
    --key-escrow-receipt "$wrong_estate_mode/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a bootstrap storage-estate file whose mode was not exactly 0600'
fi
[[ ! -s "$wrong_estate_mode/docker.log" && ! -s "$wrong_estate_mode/restic.log" ]] \
  || fail 'wrong bootstrap storage-estate file mode reached a runtime or repository'

unknown_estate_entry="$fixture_root/unknown-bootstrap-estate-entry"
setup_fixture "$unknown_estate_entry"
: > "$unknown_estate_entry/opt/hash/bootstrap-storage-estate/leftover.tmp"
chmod 0600 "$unknown_estate_entry/opt/hash/bootstrap-storage-estate/leftover.tmp"
if run_subject "$unknown_estate_entry" preflight --config "$unknown_estate_entry/config.json" \
    --maintenance-receipt "$unknown_estate_entry/maintenance.json" \
    --key-escrow-receipt "$unknown_estate_entry/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted an unknown bootstrap storage-estate control entry'
fi
[[ ! -s "$unknown_estate_entry/docker.log" && ! -s "$unknown_estate_entry/restic.log" ]] \
  || fail 'unknown bootstrap storage-estate entry reached a runtime or repository'

mismatched_estate_pair="$fixture_root/mismatched-bootstrap-estate-pair"
setup_fixture "$mismatched_estate_pair"
jq '.marker_sha256 = "1212121212121212121212121212121212121212121212121212121212121212"' \
  "$mismatched_estate_pair/opt/hash/bootstrap-storage-estate/receipt/receipt.json" \
  > "$mismatched_estate_pair/receipt.tmp"
mv "$mismatched_estate_pair/receipt.tmp" \
  "$mismatched_estate_pair/opt/hash/bootstrap-storage-estate/receipt/receipt.json"
chmod 0600 "$mismatched_estate_pair/opt/hash/bootstrap-storage-estate/receipt/receipt.json"
jq --arg identity "$(stat_identity "$mismatched_estate_pair/opt/hash/bootstrap-storage-estate/receipt/receipt.json")" \
   --arg digest "$(sha256_file "$mismatched_estate_pair/opt/hash/bootstrap-storage-estate/receipt/receipt.json")" \
  '.bootstrap_storage_estate.receipt_identity = $identity |
   .bootstrap_storage_estate.receipt_sha256 = $digest' \
  "$mismatched_estate_pair/config.json" > "$mismatched_estate_pair/config.tmp"
mv "$mismatched_estate_pair/config.tmp" "$mismatched_estate_pair/config.json"
chmod 0600 "$mismatched_estate_pair/config.json"
if run_subject "$mismatched_estate_pair" preflight --config "$mismatched_estate_pair/config.json" \
    --maintenance-receipt "$mismatched_estate_pair/maintenance.json" \
    --key-escrow-receipt "$mismatched_estate_pair/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted mismatched bootstrap storage-estate intent and receipt'
fi
[[ ! -s "$mismatched_estate_pair/docker.log" && ! -s "$mismatched_estate_pair/restic.log" ]] \
  || fail 'mismatched bootstrap storage-estate pair reached a runtime or repository'

wrong_estate_retention="$fixture_root/wrong-bootstrap-estate-retention"
setup_fixture "$wrong_estate_retention"
jq '.marker_retain_until = "2032-12-31T00:00:00Z"' \
  "$wrong_estate_retention/opt/hash/bootstrap-storage-estate/intent.json" \
  > "$wrong_estate_retention/intent.tmp"
mv "$wrong_estate_retention/intent.tmp" \
  "$wrong_estate_retention/opt/hash/bootstrap-storage-estate/intent.json"
chmod 0600 "$wrong_estate_retention/opt/hash/bootstrap-storage-estate/intent.json"
jq --arg identity "$(stat_identity "$wrong_estate_retention/opt/hash/bootstrap-storage-estate/intent.json")" \
   --arg digest "$(sha256_file "$wrong_estate_retention/opt/hash/bootstrap-storage-estate/intent.json")" \
  '.bootstrap_storage_estate.intent_identity = $identity |
   .bootstrap_storage_estate.intent_sha256 = $digest' \
  "$wrong_estate_retention/config.json" > "$wrong_estate_retention/config.tmp"
mv "$wrong_estate_retention/config.tmp" "$wrong_estate_retention/config.json"
chmod 0600 "$wrong_estate_retention/config.json"
if run_subject "$wrong_estate_retention" preflight --config "$wrong_estate_retention/config.json" \
    --maintenance-receipt "$wrong_estate_retention/maintenance.json" \
    --key-escrow-receipt "$wrong_estate_retention/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a bootstrap marker retention that was not exactly seven calendar years'
fi
[[ ! -s "$wrong_estate_retention/docker.log" && ! -s "$wrong_estate_retention/restic.log" ]] \
  || fail 'wrong bootstrap storage-estate retention reached a runtime or repository'

leap_estate_retention="$fixture_root/leap-bootstrap-estate-retention"
setup_fixture "$leap_estate_retention"
jq '.created_at = "2024-02-29T12:34:56Z" |
    .marker_retain_until = "2031-03-01T12:34:56Z"' \
  "$leap_estate_retention/opt/hash/bootstrap-storage-estate/intent.json" \
  > "$leap_estate_retention/intent.tmp"
mv "$leap_estate_retention/intent.tmp" \
  "$leap_estate_retention/opt/hash/bootstrap-storage-estate/intent.json"
jq '.marker_retain_until = "2031-03-01T12:34:56Z"' \
  "$leap_estate_retention/opt/hash/bootstrap-storage-estate/receipt/receipt.json" \
  > "$leap_estate_retention/receipt.tmp"
mv "$leap_estate_retention/receipt.tmp" \
  "$leap_estate_retention/opt/hash/bootstrap-storage-estate/receipt/receipt.json"
chmod 0600 "$leap_estate_retention/opt/hash/bootstrap-storage-estate/intent.json" \
  "$leap_estate_retention/opt/hash/bootstrap-storage-estate/receipt/receipt.json"
jq --arg intent_identity "$(stat_identity "$leap_estate_retention/opt/hash/bootstrap-storage-estate/intent.json")" \
   --arg intent_digest "$(sha256_file "$leap_estate_retention/opt/hash/bootstrap-storage-estate/intent.json")" \
   --arg receipt_identity "$(stat_identity "$leap_estate_retention/opt/hash/bootstrap-storage-estate/receipt/receipt.json")" \
   --arg receipt_digest "$(sha256_file "$leap_estate_retention/opt/hash/bootstrap-storage-estate/receipt/receipt.json")" \
  '.bootstrap_storage_estate.intent_identity = $intent_identity |
   .bootstrap_storage_estate.intent_sha256 = $intent_digest |
   .bootstrap_storage_estate.receipt_identity = $receipt_identity |
   .bootstrap_storage_estate.receipt_sha256 = $receipt_digest' \
  "$leap_estate_retention/config.json" > "$leap_estate_retention/config.tmp"
mv "$leap_estate_retention/config.tmp" "$leap_estate_retention/config.json"
chmod 0600 "$leap_estate_retention/config.json"
if ! run_subject "$leap_estate_retention" preflight --config "$leap_estate_retention/config.json" \
    --maintenance-receipt "$leap_estate_retention/maintenance.json" \
    --key-escrow-receipt "$leap_estate_retention/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight rejected Go-compatible Feb-29 seven-calendar-year retention normalization'
fi

remote_s3="$fixture_root/remote-s3-primary"
setup_fixture "$remote_s3"
jq '.endpoint = "s3.eu-central-1.amazonaws.com:443"' \
  "$remote_s3/opt/hash/storage-contract.json" > "$remote_s3/opt/hash/storage-contract.tmp"
mv "$remote_s3/opt/hash/storage-contract.tmp" "$remote_s3/opt/hash/storage-contract.json"
chmod 0600 "$remote_s3/opt/hash/storage-contract.json"
if run_subject "$remote_s3" preflight --config "$remote_s3/config.json" \
    --maintenance-receipt "$remote_s3/maintenance.json" \
    --key-escrow-receipt "$remote_s3/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a remote object store as a raw-MinIO cold-backup primary'
fi
[[ "$(grep -c '^stop ' "$remote_s3/docker.log" || true)" == 0 \
    && "$(grep -c '^backup --json' "$remote_s3/restic.log" || true)" == 0 ]] \
  || fail 'remote S3 rejection mutated a container or repository'

mismatched_writer_s3="$fixture_root/mismatched-writer-s3"
setup_fixture "$mismatched_writer_s3"
if FAKE_DOCKER_APP_S3_ENDPOINT=other-minio:9000 run_subject "$mismatched_writer_s3" \
    preflight --config "$mismatched_writer_s3/config.json" \
    --maintenance-receipt "$mismatched_writer_s3/maintenance.json" \
    --key-escrow-receipt "$mismatched_writer_s3/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a Hash writer using a different S3 endpoint'
fi
[[ "$(grep -c '^stop ' "$mismatched_writer_s3/docker.log" || true)" == 0 ]] \
  || fail 'writer S3 mismatch mutated a container'

duplicate_minio_alias="$fixture_root/duplicate-minio-alias"
setup_fixture "$duplicate_minio_alias"
if FAKE_DUPLICATE_MINIO_ALIAS=1 run_subject "$duplicate_minio_alias" preflight \
    --config "$duplicate_minio_alias/config.json" \
    --maintenance-receipt "$duplicate_minio_alias/maintenance.json" \
    --key-escrow-receipt "$duplicate_minio_alias/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a rogue container sharing the pinned MinIO alias'
fi

duplicate_postgres_alias="$fixture_root/duplicate-postgres-alias"
setup_fixture "$duplicate_postgres_alias"
if FAKE_DUPLICATE_POSTGRES_ALIAS=1 run_subject "$duplicate_postgres_alias" preflight \
    --config "$duplicate_postgres_alias/config.json" \
    --maintenance-receipt "$duplicate_postgres_alias/maintenance.json" \
    --key-escrow-receipt "$duplicate_postgres_alias/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a rogue container sharing the pinned PostgreSQL alias'
fi

mismatched_writer_db="$fixture_root/mismatched-writer-db"
setup_fixture "$mismatched_writer_db"
wrong_db_url='postgres://hash:do-not-log@remote-postgres:5432/hash_fixture?sslmode=disable'
if FAKE_DOCKER_WORKER_DB_URL="$wrong_db_url" run_subject "$mismatched_writer_db" \
    preflight --config "$mismatched_writer_db/config.json" \
    --maintenance-receipt "$mismatched_writer_db/maintenance.json" \
    --key-escrow-receipt "$mismatched_writer_db/key-escrow.json" \
    >"$mismatched_writer_db/output" 2>"$mismatched_writer_db/error"; then
  fail 'preflight accepted a Hash worker using a different PostgreSQL target'
fi
if grep -Fq 'do-not-log' "$mismatched_writer_db/output" \
    || grep -Fq 'do-not-log' "$mismatched_writer_db/error" \
    || grep -Fq 'do-not-log' "$mismatched_writer_db/docker.log"; then
  fail 'database mismatch leaked credential-bearing URL material'
fi

query_override_db="$fixture_root/query-override-db"
setup_fixture "$query_override_db"
override_db_url='postgres://hash:query-secret@postgres:5432/hash_fixture?sslmode=disable&%68ost=remote-postgres'
printf 'HASH_DB_URL=%s\n' "$override_db_url" \
  > "$query_override_db/opt/hash/runtime-secrets/hash-db.env"
chmod 0600 "$query_override_db/opt/hash/runtime-secrets/hash-db.env"
if FAKE_DOCKER_DB_URL_OVERRIDE="$override_db_url" run_subject "$query_override_db" preflight \
    --config "$query_override_db/config.json" \
    --maintenance-receipt "$query_override_db/maintenance.json" \
    --key-escrow-receipt "$query_override_db/key-escrow.json" \
    >"$query_override_db/output" 2>"$query_override_db/error"; then
  fail 'preflight accepted a percent-encoded database target query override'
fi
if grep -Fq 'query-secret' "$query_override_db/output" \
    || grep -Fq 'query-secret' "$query_override_db/error" \
    || grep -Fq 'query-secret' "$query_override_db/docker.log"; then
  fail 'database query-override rejection leaked credential-bearing URL material'
fi

duplicate_query_db="$fixture_root/duplicate-query-db"
setup_fixture "$duplicate_query_db"
duplicate_query_url='postgres://hash:duplicate-query-secret@postgres:5432/hash_fixture?sslmode=disable&SSLMODE=require'
printf 'HASH_DB_URL=%s\n' "$duplicate_query_url" \
  > "$duplicate_query_db/opt/hash/runtime-secrets/hash-db.env"
chmod 0600 "$duplicate_query_db/opt/hash/runtime-secrets/hash-db.env"
if FAKE_DOCKER_DB_URL_OVERRIDE="$duplicate_query_url" run_subject "$duplicate_query_db" preflight \
    --config "$duplicate_query_db/config.json" \
    --maintenance-receipt "$duplicate_query_db/maintenance.json" \
    --key-escrow-receipt "$duplicate_query_db/key-escrow.json" \
    >"$duplicate_query_db/output" 2>"$duplicate_query_db/error"; then
  fail 'preflight accepted duplicate case-insensitive database URL query options'
fi
if grep -Fq 'duplicate-query-secret' "$duplicate_query_db/output" \
    || grep -Fq 'duplicate-query-secret' "$duplicate_query_db/error" \
    || grep -Fq 'duplicate-query-secret' "$duplicate_query_db/docker.log"; then
  fail 'duplicate database query-option rejection leaked credential material'
fi

pgoptions_override="$fixture_root/pgoptions-override"
setup_fixture "$pgoptions_override"
pgoptions_value='PGOPTIONS=-c search_path=hostile-do-not-log'
if FAKE_DOCKER_PG_ENV="$pgoptions_value" FAKE_DOCKER_PG_ENV_TARGET=hash-app \
    run_subject "$pgoptions_override" preflight \
    --config "$pgoptions_override/config.json" \
    --maintenance-receipt "$pgoptions_override/maintenance.json" \
    --key-escrow-receipt "$pgoptions_override/key-escrow.json" \
    >"$pgoptions_override/output" 2>"$pgoptions_override/error"; then
  fail 'preflight accepted a Hash writer PGOPTIONS override'
fi
if grep -Fq 'hostile-do-not-log' "$pgoptions_override/output" \
    || grep -Fq 'hostile-do-not-log' "$pgoptions_override/error" \
    || grep -Fq 'hostile-do-not-log' "$pgoptions_override/docker.log"; then
  fail 'PGOPTIONS rejection leaked its value'
fi

pgservice_override="$fixture_root/pgservice-override"
setup_fixture "$pgservice_override"
if FAKE_DOCKER_PG_ENV='PGSERVICE=hostile-service-do-not-log' \
    FAKE_DOCKER_PG_ENV_TARGET=hash-worker \
    run_subject "$pgservice_override" preflight \
    --config "$pgservice_override/config.json" \
    --maintenance-receipt "$pgservice_override/maintenance.json" \
    --key-escrow-receipt "$pgservice_override/key-escrow.json" \
    >"$pgservice_override/output" 2>"$pgservice_override/error"; then
  fail 'preflight accepted a Hash writer PGSERVICE override'
fi
if grep -Fq 'hostile-service-do-not-log' "$pgservice_override/output" \
    || grep -Fq 'hostile-service-do-not-log' "$pgservice_override/error" \
    || grep -Fq 'hostile-service-do-not-log' "$pgservice_override/docker.log"; then
  fail 'PGSERVICE rejection leaked its value'
fi

wrong_database_oid="$fixture_root/wrong-database-oid"
setup_fixture "$wrong_database_oid"
if FAKE_POSTGRES_DATABASE_OID=16385 run_subject "$wrong_database_oid" preflight \
    --config "$wrong_database_oid/config.json" \
    --maintenance-receipt "$wrong_database_oid/maintenance.json" \
    --key-escrow-receipt "$wrong_database_oid/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a recreated PostgreSQL database with a different OID'
fi

writer_identity_unsafe="$fixture_root/writer-database-identity-unsafe"
setup_fixture "$writer_identity_unsafe"
if FAKE_DB_IDENTITY_UNSAFE=1 run_subject "$writer_identity_unsafe" preflight \
    --config "$writer_identity_unsafe/config.json" \
    --maintenance-receipt "$writer_identity_unsafe/maintenance.json" \
    --key-escrow-receipt "$writer_identity_unsafe/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a database identity rejected through a writer DSN'
fi

wrong_current="$fixture_root/wrong-current-release"
setup_fixture "$wrong_current"
rm "$wrong_current/opt/hash/current"
ln -s releases/ffffffffffffffffffffffffffffffffffffffff "$wrong_current/opt/hash/current"
if run_subject "$wrong_current" preflight --config "$wrong_current/config.json" \
    --maintenance-receipt "$wrong_current/maintenance.json" \
    --key-escrow-receipt "$wrong_current/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted /opt/hash/current selecting a different release'
fi

wrong_release_basename="$fixture_root/wrong-release-basename"
setup_fixture "$wrong_release_basename"
wrong_release_dir="$(fixture_release_dir "$wrong_release_basename")"
jq '.commit_sha = "ffffffffffffffffffffffffffffffffffffffff"' \
  "$wrong_release_dir/manifest.json" > "$wrong_release_dir/manifest.tmp"
mv "$wrong_release_dir/manifest.tmp" "$wrong_release_dir/manifest.json"
chmod 0600 "$wrong_release_dir/manifest.json"
if run_subject "$wrong_release_basename" preflight --config "$wrong_release_basename/config.json" \
    --maintenance-receipt "$wrong_release_basename/maintenance.json" \
    --key-escrow-receipt "$wrong_release_basename/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a release directory whose basename differed from its manifest commit'
fi

hardlinked_hash_secret="$fixture_root/hardlinked-hash-secret"
setup_fixture "$hardlinked_hash_secret"
ln "$hardlinked_hash_secret/opt/hash/.env" \
  "$hardlinked_hash_secret/volume/hash-runtime-secret-hardlink"
if run_subject "$hardlinked_hash_secret" preflight --config "$hardlinked_hash_secret/config.json" \
    --maintenance-receipt "$hardlinked_hash_secret/maintenance.json" \
    --key-escrow-receipt "$hardlinked_hash_secret/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a Hash secret hard-linked into the raw MinIO volume'
fi
[[ "$(grep -c '^stop ' "$hardlinked_hash_secret/docker.log" || true)" == 0 ]] \
  || fail 'hardlinked Hash secret rejection mutated a container'

symlinked_env="$fixture_root/symlinked-restic-env-parent"
setup_fixture "$symlinked_env"
mkdir -m 0700 "$symlinked_env/volume/embedded-secrets"
mv "$symlinked_env/restic.env" "$symlinked_env/volume/embedded-secrets/restic.env"
ln -s "$symlinked_env/volume/embedded-secrets" "$symlinked_env/restic-env-link"
jq --arg env_file "$symlinked_env/restic-env-link/restic.env" \
  '.restic.env_file = $env_file' "$symlinked_env/config.json" > "$symlinked_env/config.tmp"
mv "$symlinked_env/config.tmp" "$symlinked_env/config.json"
chmod 0600 "$symlinked_env/config.json"
if run_subject "$symlinked_env" preflight --config "$symlinked_env/config.json" \
    --maintenance-receipt "$symlinked_env/maintenance.json" \
    --key-escrow-receipt "$symlinked_env/key-escrow.json" \
    >"$symlinked_env/output" 2>"$symlinked_env/error"; then
  fail 'preflight accepted a Restic credential path through a symlinked parent into MinIO'
fi
grep -Fq 'Restic credential file must not be inside the MinIO data volume' \
  "$symlinked_env/error" \
  || fail "symlinked Restic credential parent failed for the wrong reason: $(<"$symlinked_env/error")"
[[ "$(grep -c '^stop ' "$symlinked_env/docker.log" || true)" == 0 ]] \
  || fail 'symlinked credential containment failure mutated a container'
[[ "$(grep -c '^backup --json' "$symlinked_env/restic.log" || true)" == 0 ]] \
  || fail 'symlinked credential containment failure wrote a snapshot'

hardlinked_env="$fixture_root/hardlinked-restic-env"
setup_fixture "$hardlinked_env"
ln "$hardlinked_env/restic.env" "$hardlinked_env/volume/restic-credential-hardlink"
if run_subject "$hardlinked_env" preflight --config "$hardlinked_env/config.json" \
    --maintenance-receipt "$hardlinked_env/maintenance.json" \
    --key-escrow-receipt "$hardlinked_env/key-escrow.json" \
    >"$hardlinked_env/output" 2>"$hardlinked_env/error"; then
  fail 'preflight accepted multiply-linked Restic credentials that could enter the MinIO snapshot'
fi
grep -Fq 'Restic environment file must have exactly one hard link' "$hardlinked_env/error" \
  || fail 'hardlinked Restic credential failed for the wrong reason'
[[ ! -s "$hardlinked_env/docker.log" && ! -s "$hardlinked_env/restic.log" ]] \
  || fail 'hardlinked Restic credential failure reached a mutable runtime or repository'

mismatched_release_env="$fixture_root/mismatched-release-env"
setup_fixture "$mismatched_release_env"
mismatched_release_dir="$(fixture_release_dir "$mismatched_release_env")"
printf '%s\n' \
  'HASH_IMAGE=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' \
  'HASH_GOTENBERG_IMAGE=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' \
  'HASH_RELEASE=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' \
  'HASH_ENVIRONMENT=production' > "$mismatched_release_dir/release.env"
if run_subject "$mismatched_release_env" preflight --config "$mismatched_release_env/config.json" \
    --maintenance-receipt "$mismatched_release_env/maintenance.json" \
    --key-escrow-receipt "$mismatched_release_env/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a release.env that did not match the release manifest'
fi
[[ "$(grep -c '^stop ' "$mismatched_release_env/docker.log" || true)" == 0 \
    && "$(grep -c '^backup --json' "$mismatched_release_env/restic.log" || true)" == 0 ]] \
  || fail 'release environment mismatch reached a mutable runtime or repository'

symlinked_staging="$fixture_root/symlinked-staging"
setup_fixture "$symlinked_staging"
mkdir -m 0700 "$symlinked_staging/outside-staging"
printf '%s\n' untouched > "$symlinked_staging/outside-staging/sentinel"
ln -s "$symlinked_staging/outside-staging" "$symlinked_staging/state/staging"
if run_subject "$symlinked_staging" backup --config "$symlinked_staging/config.json" \
    --maintenance-receipt "$symlinked_staging/maintenance.json" \
    --key-escrow-receipt "$symlinked_staging/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup accepted a pre-existing symlinked staging directory'
fi
[[ "$(<"$symlinked_staging/outside-staging/sentinel")" == untouched \
    && "$(find "$symlinked_staging/outside-staging" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" == 1 ]] \
  || fail 'symlinked staging failure mutated the external target'
[[ ! -s "$symlinked_staging/docker.log" && ! -s "$symlinked_staging/restic.log" \
    && ! -s "$symlinked_staging/flock.log" ]] \
  || fail 'symlinked staging failure reached a mutable runtime or lock operation'

symlinked_receipts="$fixture_root/symlinked-receipts"
setup_fixture "$symlinked_receipts"
mkdir -m 0700 "$symlinked_receipts/outside-receipts"
printf '%s\n' untouched > "$symlinked_receipts/outside-receipts/sentinel"
ln -s "$symlinked_receipts/outside-receipts" "$symlinked_receipts/state/receipts"
if run_subject "$symlinked_receipts" backup --config "$symlinked_receipts/config.json" \
    --maintenance-receipt "$symlinked_receipts/maintenance.json" \
    --key-escrow-receipt "$symlinked_receipts/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup accepted a pre-existing symlinked receipts directory'
fi
[[ "$(<"$symlinked_receipts/outside-receipts/sentinel")" == untouched \
    && "$(find "$symlinked_receipts/outside-receipts" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" == 1 ]] \
  || fail 'symlinked receipts failure mutated the external target'
[[ ! -s "$symlinked_receipts/docker.log" && ! -s "$symlinked_receipts/restic.log" \
    && ! -s "$symlinked_receipts/flock.log" ]] \
  || fail 'symlinked receipts failure reached a mutable runtime or lock operation'

permissive_staging="$fixture_root/permissive-staging"
setup_fixture "$permissive_staging"
mkdir -m 0755 "$permissive_staging/state/staging"
if run_subject "$permissive_staging" backup --config "$permissive_staging/config.json" \
    --maintenance-receipt "$permissive_staging/maintenance.json" \
    --key-escrow-receipt "$permissive_staging/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup accepted a pre-existing staging directory visible to group/other'
fi
[[ ! -s "$permissive_staging/docker.log" && ! -s "$permissive_staging/restic.log" \
    && ! -s "$permissive_staging/flock.log" ]] \
  || fail 'insecure staging permissions reached a mutable runtime or lock operation'

contended="$fixture_root/maintenance-lock-contended"
setup_fixture "$contended"
if FAKE_FLOCK_FAIL=1 run_subject "$contended" backup --config "$contended/config.json" \
    --maintenance-receipt "$contended/maintenance.json" \
    --key-escrow-receipt "$contended/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup proceeded while the shared Hash maintenance lock was contended'
fi
[[ "$(wc -l < "$contended/flock.log" | tr -d ' ')" == 1 ]] \
  || fail 'backup did not make exactly one nonblocking shared-lock attempt'
grep -Eq '^--exclusive --nonblock [0-9]+$' "$contended/flock.log" \
  || fail 'backup did not request the shared lock with the required flock contract'
[[ ! -s "$contended/docker.log" && ! -s "$contended/restic.log" ]] \
  || fail 'lock contention mutated a container or repository'
[[ ! -e "$contended/state/staging" && ! -e "$contended/state/receipts" ]] \
  || fail 'lock contention created backup staging or receipt state'

missing_lock="$fixture_root/maintenance-lock-missing"
setup_fixture "$missing_lock"
rm "$(fixture_lock_file "$missing_lock")"
if run_subject "$missing_lock" backup --config "$missing_lock/config.json" \
    --maintenance-receipt "$missing_lock/maintenance.json" \
    --key-escrow-receipt "$missing_lock/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup created or accepted a missing release-owned maintenance lock'
fi
[[ ! -e "$(fixture_lock_file "$missing_lock")" && ! -s "$missing_lock/docker.log" \
    && ! -s "$missing_lock/restic.log" && ! -s "$missing_lock/flock.log" ]] \
  || fail 'missing maintenance lock failure mutated state or reached a runtime operation'

symlinked_lock="$fixture_root/maintenance-lock-symlink"
setup_fixture "$symlinked_lock"
printf '%s\n' untouched > "$symlinked_lock/outside-lock-target"
rm "$(fixture_lock_file "$symlinked_lock")"
ln -s "$symlinked_lock/outside-lock-target" "$(fixture_lock_file "$symlinked_lock")"
if run_subject "$symlinked_lock" backup --config "$symlinked_lock/config.json" \
    --maintenance-receipt "$symlinked_lock/maintenance.json" \
    --key-escrow-receipt "$symlinked_lock/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup accepted a symlinked maintenance lock'
fi
[[ "$(<"$symlinked_lock/outside-lock-target")" == untouched && ! -s "$symlinked_lock/docker.log" \
    && ! -s "$symlinked_lock/restic.log" && ! -s "$symlinked_lock/flock.log" ]] \
  || fail 'symlinked maintenance lock failure mutated its target or a runtime'

linked_lock="$fixture_root/maintenance-lock-hardlinked"
setup_fixture "$linked_lock"
ln "$(fixture_lock_file "$linked_lock")" "$linked_lock/second-lock-link"
if run_subject "$linked_lock" backup --config "$linked_lock/config.json" \
    --maintenance-receipt "$linked_lock/maintenance.json" \
    --key-escrow-receipt "$linked_lock/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup accepted a multiply-linked maintenance lock'
fi
[[ ! -s "$linked_lock/docker.log" && ! -s "$linked_lock/restic.log" \
    && ! -s "$linked_lock/flock.log" ]] \
  || fail 'hardlinked maintenance lock failure reached a mutable runtime'

permissive_lock="$fixture_root/maintenance-lock-permissive"
setup_fixture "$permissive_lock"
chmod 0640 "$(fixture_lock_file "$permissive_lock")"
if run_subject "$permissive_lock" backup --config "$permissive_lock/config.json" \
    --maintenance-receipt "$permissive_lock/maintenance.json" \
    --key-escrow-receipt "$permissive_lock/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup accepted a maintenance lock whose mode was not exactly 0600'
fi
[[ ! -s "$permissive_lock/docker.log" && ! -s "$permissive_lock/restic.log" \
    && ! -s "$permissive_lock/flock.log" ]] \
  || fail 'permissive maintenance lock failure reached a mutable runtime'

stale_recovery="$fixture_root/stale-recovery-sentinel"
setup_fixture "$stale_recovery"
stale_recovery_sentinel="$(fixture_recovery_sentinel "$stale_recovery")"
printf '%s\n' '{"schema_version":1,"state":"cold-backup-recovery-required"}' \
  > "$stale_recovery_sentinel"
chmod 0600 "$stale_recovery_sentinel"
stale_sha="$(sha256_file "$stale_recovery_sentinel")"
if run_subject "$stale_recovery" backup --config "$stale_recovery/config.json" \
    --maintenance-receipt "$stale_recovery/maintenance.json" \
    --key-escrow-receipt "$stale_recovery/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup ignored a stale canonical recovery-required sentinel'
fi
[[ "$(sha256_file "$stale_recovery_sentinel")" == "$stale_sha" \
    && ! -s "$stale_recovery/docker.log" && ! -s "$stale_recovery/restic.log" ]] \
  || fail 'stale recovery sentinel was changed or runtime preflight proceeded'
[[ "$(wc -l < "$stale_recovery/flock.log" | tr -d ' ')" == 1 ]] \
  || fail 'stale recovery sentinel was not checked while holding the shared flock'

abrupt="$fixture_root/abrupt-after-sentinel"
setup_fixture "$abrupt"
abrupt_sentinel="$(fixture_recovery_sentinel "$abrupt")"
FAKE_DOCKER_BLOCK_IMAGE_SAVE=1 run_subject "$abrupt" backup --config "$abrupt/config.json" \
  --maintenance-receipt "$abrupt/maintenance.json" \
  --key-escrow-receipt "$abrupt/key-escrow.json" >"$abrupt/output" 2>"$abrupt/error" &
abrupt_pid=$!
abrupt_ready=0
abrupt_deadline=$((SECONDS + 60))
while ((SECONDS < abrupt_deadline)); do
  if [[ -f "$abrupt_sentinel" && -f "$abrupt/image-save.blocked" ]]; then
    abrupt_ready=1
    break
  fi
  if ! kill -0 "$abrupt_pid" 2>/dev/null; then
    : > "$abrupt/image-save.release"
    if wait "$abrupt_pid"; then
      abrupt_status=0
    else
      abrupt_status=$?
    fi
    fail "backup exited early with status $abrupt_status before installing its recovery sentinel and reaching image staging: $(<"$abrupt/error")"
  fi
  sleep 0.05
done
if [[ "$abrupt_ready" != 1 ]]; then
  : > "$abrupt/image-save.release"
  kill "$abrupt_pid" 2>/dev/null || true
  wait "$abrupt_pid" 2>/dev/null || true
  fail 'backup did not install its canonical recovery sentinel before staging images within 60 seconds'
fi
kill -9 "$abrupt_pid"
: > "$abrupt/image-save.release"
wait "$abrupt_pid" 2>/dev/null || true
[[ -f "$abrupt_sentinel" && ! -L "$abrupt_sentinel" ]] \
  || fail 'SIGKILL did not leave the canonical recovery-required sentinel'
[[ "$(grep -c '^stop ' "$abrupt/docker.log" || true)" == 0 \
    && "$(grep -c '^backup --json' "$abrupt/restic.log" || true)" == 0 ]] \
  || fail 'abrupt staging test reached container quiesce or Restic capture'

wrong_gotenberg="$fixture_root/wrong-gotenberg"
setup_fixture "$wrong_gotenberg"
wrong_gotenberg_release="$(fixture_release_dir "$wrong_gotenberg")"
jq '.gotenberg_image_id = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"' \
  "$wrong_gotenberg_release/manifest.json" > "$wrong_gotenberg_release/manifest.tmp"
mv "$wrong_gotenberg_release/manifest.tmp" "$wrong_gotenberg_release/manifest.json"
chmod 0600 "$wrong_gotenberg_release/manifest.json"
if run_subject "$wrong_gotenberg" preflight --config "$wrong_gotenberg/config.json" \
    --maintenance-receipt "$wrong_gotenberg/maintenance.json" \
    --key-escrow-receipt "$wrong_gotenberg/key-escrow.json" >/dev/null 2>&1; then
  fail 'preflight accepted a live Gotenberg image different from the release manifest'
fi
[[ "$(grep -c '^stop ' "$wrong_gotenberg/docker.log" || true)" == 0 ]] \
  || fail 'Gotenberg provenance failure mutated a container'

incomplete_keys="$fixture_root/incomplete-key-rotation"
setup_fixture "$incomplete_keys"
jq '(.key_sets[] | select(.purpose == "hash-webhook-encryption") |
      .covers_all_versions_at_snapshot) = false' \
  "$incomplete_keys/key-escrow.json" > "$incomplete_keys/key-escrow.tmp"
mv "$incomplete_keys/key-escrow.tmp" "$incomplete_keys/key-escrow.json"
chmod 0600 "$incomplete_keys/key-escrow.json"
if run_subject "$incomplete_keys" backup --dry-run --config "$incomplete_keys/config.json" \
    --maintenance-receipt "$incomplete_keys/maintenance.json" \
    --key-escrow-receipt "$incomplete_keys/key-escrow.json" >/dev/null 2>&1; then
  fail 'dry-run accepted incomplete webhook rotation-key coverage'
fi
[[ "$(grep -c '^stop ' "$incomplete_keys/docker.log" || true)" == 0 ]] \
  || fail 'key-rotation receipt failure mutated a container'

replaced_before_stop="$fixture_root/replaced-before-stop"
setup_fixture "$replaced_before_stop"
if FAKE_DOCKER_REPLACE_DURING_STAGE=1 run_subject "$replaced_before_stop" backup \
    --config "$replaced_before_stop/config.json" \
    --maintenance-receipt "$replaced_before_stop/maintenance.json" \
    --key-escrow-receipt "$replaced_before_stop/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup accepted a mutable-name container replacement before quiescing'
fi
[[ "$(grep -c '^stop ' "$replaced_before_stop/docker.log" || true)" == 0 ]] \
  || fail 'pre-quiesce container replacement stopped a container'
[[ "$(grep -c '^backup --json' "$replaced_before_stop/restic.log" || true)" == 0 ]] \
  || fail 'pre-quiesce container replacement wrote a snapshot'
[[ -f "$(fixture_recovery_sentinel "$replaced_before_stop")" \
    && -d "$replaced_before_stop/state/.hash-cold-backup.lock" ]] \
  || fail 'pre-quiesce identity uncertainty did not retain both recovery alarms'

current_replaced_before_stop="$fixture_root/current-replaced-before-stop"
setup_fixture "$current_replaced_before_stop"
if FAKE_DOCKER_REPLACE_CURRENT_DURING_STAGE=1 run_subject "$current_replaced_before_stop" backup \
    --config "$current_replaced_before_stop/config.json" \
    --maintenance-receipt "$current_replaced_before_stop/maintenance.json" \
    --key-escrow-receipt "$current_replaced_before_stop/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup accepted replacement of the current-release symlink before quiescing'
fi
[[ "$(grep -c '^stop ' "$current_replaced_before_stop/docker.log" || true)" == 0 \
    && "$(grep -c '^backup --json' "$current_replaced_before_stop/restic.log" || true)" == 0 ]] \
  || fail 'current-release replacement reached quiesce or Restic capture'
[[ -f "$(fixture_recovery_sentinel "$current_replaced_before_stop")" ]] \
  || fail 'current-release identity uncertainty did not retain the recovery alarm'

estate_replaced_before_stop="$fixture_root/bootstrap-estate-replaced-before-stop"
setup_fixture "$estate_replaced_before_stop"
if FAKE_DOCKER_REPLACE_BOOTSTRAP_ESTATE_DURING_STAGE=1 run_subject "$estate_replaced_before_stop" backup \
    --config "$estate_replaced_before_stop/config.json" \
    --maintenance-receipt "$estate_replaced_before_stop/maintenance.json" \
    --key-escrow-receipt "$estate_replaced_before_stop/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup accepted replacement of the bootstrap storage-estate intent before quiescing'
fi
[[ "$(grep -c '^stop ' "$estate_replaced_before_stop/docker.log" || true)" == 0 \
    && "$(grep -c '^backup --json' "$estate_replaced_before_stop/restic.log" || true)" == 0 ]] \
  || fail 'bootstrap storage-estate replacement reached quiesce or Restic capture'
[[ -f "$(fixture_recovery_sentinel "$estate_replaced_before_stop")" ]] \
  || fail 'bootstrap storage-estate identity uncertainty did not retain the recovery alarm'

secret_linked_before_capture="$fixture_root/secret-linked-before-capture"
setup_fixture "$secret_linked_before_capture"
if FAKE_DOCKER_LINK_SECRET_AFTER_MINIO_STOP=1 run_subject "$secret_linked_before_capture" backup \
    --config "$secret_linked_before_capture/config.json" \
    --maintenance-receipt "$secret_linked_before_capture/maintenance.json" \
    --key-escrow-receipt "$secret_linked_before_capture/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup accepted a Hash secret hard-linked into MinIO immediately before capture'
fi
[[ "$(grep -c '^backup --json' "$secret_linked_before_capture/restic.log" || true)" == 0 ]] \
  || fail 'late hardlinked Hash secret reached Restic capture'
[[ -f "$(fixture_recovery_sentinel "$secret_linked_before_capture")" ]] \
  || fail 'late secret hardlink uncertainty did not retain the recovery alarm'

dry="$fixture_root/dry-run"
setup_fixture "$dry"
if ! run_subject "$dry" backup --dry-run --config "$dry/config.json" \
    --maintenance-receipt "$dry/maintenance.json" \
    --key-escrow-receipt "$dry/key-escrow.json" >"$dry/output" 2>"$dry/error"; then
  fail "valid dry-run failed: $(<"$dry/error")"
fi
[[ "$(grep -c '^stop ' "$dry/docker.log" || true)" == 0 ]] || fail 'dry-run stopped a container'
[[ "$(grep -c '^backup --json' "$dry/restic.log" || true)" == 0 ]] || fail 'dry-run wrote a snapshot'

success="$fixture_root/success"
setup_fixture "$success"
if ! run_subject "$success" backup --config "$success/config.json" \
    --maintenance-receipt "$success/maintenance.json" \
    --key-escrow-receipt "$success/key-escrow.json" >"$success/output" 2>"$success/error"; then
  fail "valid cold backup failed: $(<"$success/error")"
fi
actions="$(grep -E '^(stop|start) ' "$success/docker.log")"
expected_actions="$(printf 'stop --time 5 %s\nstop --time 5 %s\nstop --time 5 %s\nstart %s\nstart %s\nstart %s' \
  "$(<"$success/state/hash-worker.original-id")" \
  "$(<"$success/state/hash-app.original-id")" \
  "$(<"$success/state/minio-fixture.original-id")" \
  "$(<"$success/state/minio-fixture.original-id")" \
  "$(<"$success/state/hash-app.original-id")" \
  "$(<"$success/state/hash-worker.original-id")")"
[[ "$actions" == "$expected_actions" ]] || fail "unexpected stop/start order: $actions"
grep -Fq "$success/volume" "$success/restic.log" || fail 'complete MinIO data root was not passed to Restic'
grep -Fq '/staging/hash-cold-' "$success/restic.log" || fail 'coordinated staging root was not passed to Restic'
grep -Fq '/bootstrap-storage-estate/intent.json' "$success/restic.log" \
  || fail 'new snapshot was not checked for the bootstrap storage-estate intent'
grep -Fq '/bootstrap-storage-estate/receipt/receipt.json' "$success/restic.log" \
  || fail 'new snapshot was not checked for the bootstrap storage-estate receipt'
[[ "$(grep -c -- '--exclude' "$success/restic.log" || true)" == 0 ]] || fail 'Restic backup used an exclusion'
if grep -Fq 'fixture-only-not-a-secret' "$success/restic.log" \
    || grep -Fq 'fixture-only-not-a-secret' "$success/output" \
    || grep -Fq 'fixture-only-not-a-secret' "$success/error"; then
  fail 'Restic password sentinel leaked into logged command or workflow output'
fi
[[ ! -d "$success/state/.hash-cold-backup.lock" ]] || fail 'successful run left its lock behind'
[[ ! -e "$(fixture_recovery_sentinel "$success")" ]] \
  || fail 'successful recovered run left the canonical recovery sentinel behind'
[[ "$(find "$success/state/receipts" -name '*.receipt.json' | wc -l | tr -d ' ')" == 1 ]] \
  || fail 'successful run did not write one verified receipt'
for name in hash-app hash-worker minio-fixture; do
  [[ "$(<"$success/state/$name.running")" == 1 ]] || fail "$name was not restarted"
done
success_receipt="$(find "$success/state/receipts" -name '*.receipt.json' -print -quit)"
jq -e '.schema_version == 2 and .status == "capture-uploaded-subset-checked" and
  .bootstrap_storage_estate.marker_key == "_hash/bootstrap-estate/v1" and
  (.bootstrap_storage_estate.marker_version_id | length > 0) and
  (.bootstrap_storage_estate.owner_uid | type == "number") and
  (.bootstrap_storage_estate.root_path | endswith("/opt/hash/bootstrap-storage-estate")) and
  (.bootstrap_storage_estate.intent_path | endswith("/opt/hash/bootstrap-storage-estate/intent.json")) and
  (.bootstrap_storage_estate.receipt_dir_path | endswith("/opt/hash/bootstrap-storage-estate/receipt")) and
  (.bootstrap_storage_estate.receipt_path | endswith("/opt/hash/bootstrap-storage-estate/receipt/receipt.json")) and
  (.bootstrap_storage_estate.root_identity | test("^[0-9]+:[0-9]+$")) and
  (.bootstrap_storage_estate.receipt_dir_identity | test("^[0-9]+:[0-9]+$")) and
  (.bootstrap_storage_estate.intent_identity | test("^[0-9]+:[0-9]+$")) and
  (.bootstrap_storage_estate.receipt_identity | test("^[0-9]+:[0-9]+$")) and
  (.bootstrap_storage_estate.intent_sha256 | test("^[0-9a-f]{64}$")) and
  (.bootstrap_storage_estate.receipt_sha256 | test("^[0-9a-f]{64}$")) and
  .repository_subset_check_passed == true and
  .exact_snapshot_readback_verified == false and .isolated_restore_required == true' \
  "$success_receipt" >/dev/null \
  || fail 'successful receipt overclaimed exact readback verification'

unstable_worker="$fixture_root/unstable-worker-after-restart"
setup_fixture "$unstable_worker"
if FAKE_DOCKER_WORKER_UNSTABLE=1 run_subject "$unstable_worker" backup \
    --config "$unstable_worker/config.json" \
    --maintenance-receipt "$unstable_worker/maintenance.json" \
    --key-escrow-receipt "$unstable_worker/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup accepted a worker whose restart count changed during the settling interval'
fi
[[ -f "$(fixture_recovery_sentinel "$unstable_worker")" \
    && -d "$unstable_worker/state/.hash-cold-backup.lock" ]] \
  || fail 'unstable worker recovery did not retain both operator alarms'
[[ "$(find "$unstable_worker/state/receipts" -name '*.receipt.json' | wc -l | tr -d ' ')" == 0 ]] \
  || fail 'unstable worker recovery wrote a successful receipt'

replaced_before_capture="$fixture_root/replaced-before-capture"
setup_fixture "$replaced_before_capture"
if FAKE_DOCKER_REPLACE_AFTER_MINIO_STOP=1 run_subject "$replaced_before_capture" backup \
    --config "$replaced_before_capture/config.json" \
    --maintenance-receipt "$replaced_before_capture/maintenance.json" \
    --key-escrow-receipt "$replaced_before_capture/key-escrow.json" >/dev/null 2>&1; then
  fail 'backup accepted a MinIO container replacement before Restic capture'
fi
[[ "$(grep -c '^backup --json' "$replaced_before_capture/restic.log" || true)" == 0 ]] \
  || fail 'pre-capture MinIO replacement wrote a snapshot'
for name in hash-app hash-worker minio-fixture; do
  [[ "$(<"$replaced_before_capture/state/$name.running")" == 1 ]] \
    || fail "$name stayed stopped after pre-capture identity failure"
done
[[ -f "$(fixture_recovery_sentinel "$replaced_before_capture")" \
    && -d "$replaced_before_capture/state/.hash-cold-backup.lock" ]] \
  || fail 'pre-capture identity uncertainty did not retain both recovery alarms'

failed="$fixture_root/restic-failure"
setup_fixture "$failed"
if FAKE_RESTIC_FAIL_BACKUP=1 run_subject "$failed" backup --config "$failed/config.json" \
    --maintenance-receipt "$failed/maintenance.json" \
    --key-escrow-receipt "$failed/key-escrow.json" >/dev/null 2>&1; then
  fail 'Restic failure returned success'
fi
actions="$(grep -E '^(stop|start) ' "$failed/docker.log")"
[[ "$actions" == "$expected_actions" ]] || fail 'Restic failure did not restart services in dependency order'
[[ ! -d "$failed/state/.hash-cold-backup.lock" ]] || fail 'recovered failure left its lock behind'
[[ ! -e "$(fixture_recovery_sentinel "$failed")" ]] \
  || fail 'recovered Restic failure left the canonical recovery sentinel behind'
for name in hash-app hash-worker minio-fixture; do
  [[ "$(<"$failed/state/$name.running")" == 1 ]] || fail "$name stayed stopped after Restic failure"
done

restart_failed="$fixture_root/restart-failure"
setup_fixture "$restart_failed"
if FAKE_RESTIC_FAIL_BACKUP=1 FAKE_DOCKER_FAIL_START=minio-fixture \
    run_subject "$restart_failed" backup --config "$restart_failed/config.json" \
    --maintenance-receipt "$restart_failed/maintenance.json" \
    --key-escrow-receipt "$restart_failed/key-escrow.json" >/dev/null 2>&1; then
  fail 'failed MinIO restart returned success'
fi
[[ -d "$restart_failed/state/.hash-cold-backup.lock" ]] \
  || fail 'incomplete restart did not retain its operator lock'
restart_failed_sentinel="$(fixture_recovery_sentinel "$restart_failed")"
[[ -f "$restart_failed_sentinel" && ! -L "$restart_failed_sentinel" ]] \
  || fail 'incomplete restart did not retain its canonical recovery sentinel'
sentinel_mode="$(stat -c '%a' "$restart_failed_sentinel" 2>/dev/null \
  || stat -f '%Lp' "$restart_failed_sentinel")"
sentinel_links="$(stat -c '%h' "$restart_failed_sentinel" 2>/dev/null \
  || stat -f '%l' "$restart_failed_sentinel")"
[[ "$sentinel_mode" == 600 && "$sentinel_links" == 1 ]] \
  || fail 'retained canonical recovery sentinel has unsafe metadata'
[[ "$(find "$restart_failed/state/staging" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" == 1 ]] \
  || fail 'incomplete restart did not retain its private staging evidence'
actions="$(grep -E '^(stop|start) ' "$restart_failed/docker.log")"
expected_failed_actions="$(printf 'stop --time 5 %s\nstop --time 5 %s\nstop --time 5 %s\nstart %s' \
  "$(<"$restart_failed/state/hash-worker.original-id")" \
  "$(<"$restart_failed/state/hash-app.original-id")" \
  "$(<"$restart_failed/state/minio-fixture.original-id")" \
  "$(<"$restart_failed/state/minio-fixture.original-id")")"
[[ "$actions" == "$expected_failed_actions" ]] \
  || fail "incomplete restart did not stop safely at the failed dependency: $actions"

printf '%s\n' 'storagebox cold-backup contract tests: PASS'
