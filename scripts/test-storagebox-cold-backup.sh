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

fail() {
  printf 'test failure: %s\n' "$*" >&2
  exit 1
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
emit_container() {
  local name="$1" running health image ref project service exit_code mounts cmd
  running="$(state "$name")"
  exit_code=0
  mounts='[]'
  cmd='[]'
  case "$name" in
    hash-app) image="$app_id"; ref='hash-fixture:release'; project='hash-fixture'; service='app'; health='healthy' ;;
    hash-worker) image="$app_id"; ref='hash-fixture:release'; project='hash-fixture'; service='worker'; health='none' ;;
    hash-gotenberg) image="sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"; ref='gotenberg:fixture'; project='hash-fixture'; service='gotenberg'; health='healthy' ;;
    pg-fixture) image="$postgres_id"; ref='postgres:fixture'; project='database-fixture'; service='postgres'; health='healthy' ;;
    minio-fixture)
      image="$minio_id"; ref='minio/minio:fixture'; project='minio-fixture'; service='minio'; health='healthy'
      mounts="$(jq -n --arg source "$root/volume" '[{Type:"volume",Name:"minio-fixture-data",Source:$source,Destination:"/data"}]')"
      cmd='["server","/data","--console-address",":9001"]'
      ;;
    *) exit 1 ;;
  esac
  [[ "$running" == 1 ]] || health='none'
  jq -n --arg name "$name" --arg image "$image" --arg ref "$ref" \
    --arg project "$project" --arg service "$service" --arg health "$health" \
    --arg release "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    --argjson running "$( [[ "$running" == 1 ]] && printf true || printf false )" \
    --argjson exit_code "$exit_code" --argjson mounts "$mounts" --argjson cmd "$cmd" \
    '[{Name:$name,Image:$image,Config:{Image:$ref,Cmd:$cmd,Env:["HASH_RELEASE="+$release],
      Labels:{"com.docker.compose.project":$project,"com.docker.compose.service":$service}},
      State:{Running:$running,ExitCode:$exit_code,Health:{Status:$health}},Mounts:$mounts}]'
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
  ps)
    if [[ "$(state minio-fixture)" == 1 ]]; then printf '%s\n' minio-fixture; fi
    ;;
  stop)
    name="${@: -1}"
    if [[ "${FAKE_DOCKER_FAIL_STOP:-0}" == 1 ]]; then exit 41; fi
    printf '0\n' > "$root/state/$name.running"
    ;;
  start)
    name="$2"
    if [[ "${FAKE_DOCKER_FAIL_START:-}" == "$name" ]]; then exit 42; fi
    printf '1\n' > "$root/state/$name.running"
    printf '%s\n' "$name"
    ;;
  image)
    if [[ "${2:-}" == inspect && "${3:-}" == --format ]]; then
      printf '%s\n' 1048576
    elif [[ "${2:-}" == save && "${3:-}" == --output ]]; then
      printf 'fixture image archive for %s\n' "$5" > "$4"
    else
      exit 2
    fi
    ;;
  exec)
    shift
    [[ "${1:-}" == -i ]] && shift
    container="$1"; shift
    case "${1:-}" in
      psql)
        if [[ " $* " == *' --command '* ]]; then
          printf '%s\n' 1048576
        else
          cat >/dev/null
          printf '%s\n' 'YQ==\t"a"\tdocument_final_pdf\tdocument:1\torg\t-\tf\tt\t1\tversion-fixture\tf\tf'
        fi
        ;;
      pg_dump)
        printf 'fixture custom PostgreSQL dump\n'
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
    if [[ "${FAKE_RESTIC_FAIL_BACKUP:-0}" == 1 ]]; then
      printf '%s\n' 'fixture backup failure' >&2
      exit 62
    fi
    printf '{"message_type":"summary","snapshot_id":"%s"}\n' "$snapshot"
    ;;
  ls)
    if [[ "${2:-}" == --help ]]; then printf '%s\n' '  --recursive'; exit 0; fi
    path="${@: -1}"
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

setup_fixture() {
  local root="$1" repo repo_sha archive_sha archive_bytes compose_sha inventory_sha verifier_sha now
  mkdir -p "$root/bin" "$root/state" "$root/release" "$root/volume/.minio.sys" "$root/volume/hash-bucket"
  chmod 0700 "$root/state"
  printf 'fixture minio metadata\n' > "$root/volume/.minio.sys/config"
  printf 'fixture retained object\n' > "$root/volume/hash-bucket/object"
  printf 'fixture release image archive\n' > "$root/release/images.tar"
  printf 'services: {}\n' > "$root/release/docker-compose.yml"
  archive_sha="$(sha256_file "$root/release/images.tar")"
  archive_bytes="$(wc -c < "$root/release/images.tar" | tr -d ' ')"
  compose_sha="$(sha256_file "$root/release/docker-compose.yml")"
  jq -n --arg archive_sha "$archive_sha" --argjson archive_bytes "$archive_bytes" \
    --arg compose_sha "$compose_sha" \
    '{schema_version:3,commit_sha:"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      app_image_id:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      gotenberg_image_id:"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      image_archive_sha256:$archive_sha,image_archive_bytes:$archive_bytes,
      compose_sha256:$compose_sha}' > "$root/release/manifest.json"

  repo='sftp:u00000@u00000.your-storagebox.de:/home/hash-cold-fixture'
  repo_sha="$(printf '%s' "$repo" | sha256_text)"
  {
    printf 'RESTIC_REPOSITORY=%s\n' "$repo"
    printf '%s' 'RESTIC_PASS'
    printf '%s\n' 'WORD=fixture-only-not-a-secret'
  } > "$root/restic.env"
  chmod 0600 "$root/restic.env"

  inventory_sha="$(sha256_file "$script_dir/../ops/recovery-object-inventory.sql")"
  verifier_sha="$(sha256_file "$script_dir/verify-recovery-objects.sh")"
  jq -n --arg root "$root" --arg repo_sha "$repo_sha" --arg inventory_sha "$inventory_sha" \
    --arg verifier_sha "$verifier_sha" \
    '{schema_version:1,
      compose:{project:"hash-fixture",app_service:"app",worker_service:"worker",gotenberg_service:"gotenberg"},
      containers:{app:"hash-app",worker:"hash-worker",gotenberg:"hash-gotenberg",postgres:"pg-fixture",minio:"minio-fixture"},
      postgres:{database:"hash_fixture",user:"hash_dump"},
      minio:{volume:"minio-fixture-data",data_path:($root+"/volume"),mount_destination:"/data",
        expected_image_id:"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
      release_dir:($root+"/release"),
      inventory_sql:"'"$script_dir"'/../ops/recovery-object-inventory.sql",
      inventory_sql_sha256:$inventory_sha,
      verifier_script:"'"$script_dir"'/verify-recovery-objects.sh",
      verifier_script_sha256:$verifier_sha,
      state_dir:($root+"/state"),
      restic:{env_file:($root+"/restic.env"),repository_variable:"RESTIC_REPOSITORY",
        password_variable:"RESTIC_PASSWORD",repository_sha256:$repo_sha,host:"hash-fixture",
        config_id:"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        stop_timeout_seconds:5,health_timeout_seconds:5,integrity_subset:"1%"}}' \
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
  : > "$root/docker.log"
  : > "$root/restic.log"
  write_fake_docker "$root"
  write_fake_restic "$root"
}

run_subject() {
  local root="$1"; shift
  FAKE_ROOT="$root" PATH="$root/bin:$PATH" "$subject" "$@"
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
  "$symlinked_env/error" || fail 'symlinked Restic credential parent failed for the wrong reason'
[[ "$(grep -c '^stop ' "$symlinked_env/docker.log" || true)" == 0 ]] \
  || fail 'symlinked credential containment failure mutated a container'
[[ "$(grep -c '^backup --json' "$symlinked_env/restic.log" || true)" == 0 ]] \
  || fail 'symlinked credential containment failure wrote a snapshot'

wrong_gotenberg="$fixture_root/wrong-gotenberg"
setup_fixture "$wrong_gotenberg"
jq '.gotenberg_image_id = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"' \
  "$wrong_gotenberg/release/manifest.json" > "$wrong_gotenberg/release/manifest.tmp"
mv "$wrong_gotenberg/release/manifest.tmp" "$wrong_gotenberg/release/manifest.json"
chmod 0600 "$wrong_gotenberg/release/manifest.json"
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
expected_actions=$'stop --time 5 hash-worker\nstop --time 5 hash-app\nstop --time 5 minio-fixture\nstart minio-fixture\nstart hash-app\nstart hash-worker'
[[ "$actions" == "$expected_actions" ]] || fail "unexpected stop/start order: $actions"
grep -Fq "$success/volume" "$success/restic.log" || fail 'complete MinIO data root was not passed to Restic'
grep -Fq '/staging/hash-cold-' "$success/restic.log" || fail 'coordinated staging root was not passed to Restic'
[[ "$(grep -c -- '--exclude' "$success/restic.log" || true)" == 0 ]] || fail 'Restic backup used an exclusion'
if grep -Fq 'fixture-only-not-a-secret' "$success/restic.log" \
    || grep -Fq 'fixture-only-not-a-secret' "$success/output" \
    || grep -Fq 'fixture-only-not-a-secret' "$success/error"; then
  fail 'Restic password sentinel leaked into logged command or workflow output'
fi
[[ ! -d "$success/state/.hash-cold-backup.lock" ]] || fail 'successful run left its lock behind'
[[ "$(find "$success/state/receipts" -name '*.receipt.json' | wc -l | tr -d ' ')" == 1 ]] \
  || fail 'successful run did not write one verified receipt'
for name in hash-app hash-worker minio-fixture; do
  [[ "$(<"$success/state/$name.running")" == 1 ]] || fail "$name was not restarted"
done

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
[[ "$(find "$restart_failed/state/staging" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" == 1 ]] \
  || fail 'incomplete restart did not retain its private staging evidence'
actions="$(grep -E '^(stop|start) ' "$restart_failed/docker.log")"
expected_failed_actions=$'stop --time 5 hash-worker\nstop --time 5 hash-app\nstop --time 5 minio-fixture\nstart minio-fixture'
[[ "$actions" == "$expected_failed_actions" ]] \
  || fail "incomplete restart did not stop safely at the failed dependency: $actions"

printf '%s\n' 'storagebox cold-backup contract tests: PASS'
