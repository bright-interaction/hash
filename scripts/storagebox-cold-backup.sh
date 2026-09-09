#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Copyright (c) Bright Interaction
#
# Create one quiesced Hash recovery snapshot in an existing Hetzner Storage Box
# Restic repository. This is deliberately a cold, operator-started workflow. It
# is not suitable for primary object storage and is not called by the ordinary
# estate backup timer.

set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
Usage:
  scripts/storagebox-cold-backup.sh status --config FILE
  scripts/storagebox-cold-backup.sh preflight --config FILE \
    --maintenance-receipt FILE --key-escrow-receipt FILE
  scripts/storagebox-cold-backup.sh backup --config FILE \
    --maintenance-receipt FILE --key-escrow-receipt FILE [--dry-run]

The configuration names every live container, the exact MinIO volume and image,
the exact Hash release, and the already-initialised Storage Box Restic repo.
It also pins the completed bootstrap storage-estate intent/receipt identities
and digests; both control files are captured with the coordinated recovery set.
`backup` refuses to run without two non-secret receipts: a current maintenance
approval and proof that the required recovery keys are escrowed somewhere other
than the data-backup repository. No secret value is copied into the snapshot or
printed.

This script always snapshots the COMPLETE MinIO volume, including `.minio.sys`.
It offers no exclude flag. Storage Box is backup/DR only, never Hash's S3
endpoint or MinIO data mount.

The backup and every Hash deployment/rollback must take an exclusive,
nonblocking flock(2) on the same maintenance lock file for their entire
operation. Host provisioning owns the root-owned, mode-0755, non-writable
/opt/hash-lock directory and pre-provisions its canonical maintenance.lock as a
single-link regular file owned by UID 1000 with mode 0600. Hash workflows
validate but never create or replace either path. Once a real
capture begins it atomically creates /opt/hash/.cold-backup-recovery-required;
deployments must refuse to mutate Hash while that sentinel exists. Only a fully
recovered and cleaned-up backup removes it.
EOF
}

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"
}

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

contains_control() {
  case "$1" in
    *$'\n'*|*$'\r'*|*$'\t'*) return 0 ;;
  esac
  return 1
}

valid_name() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]
}

valid_db_identifier() {
  [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]]
}

valid_image_id() {
  [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]
}

valid_container_id() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

valid_port() {
  [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$1 <= 65535))
}

stat_identity() {
  local path="$1" follow="${2:-false}"
  if [[ "$follow" == true ]]; then
    stat -Lc '%d:%i' "$path" 2>/dev/null || stat -f '%d:%i' -L "$path"
  else
    stat -c '%d:%i' "$path" 2>/dev/null || stat -f '%d:%i' "$path"
  fi
}

stat_links() {
  stat -c '%h' "$1" 2>/dev/null || stat -f '%l' "$1"
}

stat_owner() {
  stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1"
}

require_single_link_file() {
  local path="$1" description="$2"
  [[ -f "$path" && ! -L "$path" ]] \
    || die "$description must be a regular non-symlink file: $path"
  [[ "$(stat_links "$path")" == 1 ]] \
    || die "$description must have exactly one hard link"
}

require_owned_private_single_link_file() {
  local path="$1" description="$2" expected_uid="$3" mode mode_value
  require_single_link_file "$path" "$description"
  [[ "$(stat_owner "$path")" == "$expected_uid" ]] \
    || die "$description must be owned by UID $expected_uid"
  if mode="$(stat -c '%a' "$path" 2>/dev/null)"; then :; else
    mode="$(stat -f '%Lp' "$path")" || die "cannot inspect permissions for $description"
  fi
  mode_value=$((8#$mode))
  (( (mode_value & 077) == 0 )) \
    || die "$description permissions must deny group/other access (mode $mode)"
}

require_owned_exact_private_single_link_file() {
  local path="$1" description="$2" expected_uid="$3" expected_mode="$4" mode
  require_single_link_file "$path" "$description"
  [[ "$(stat_owner "$path")" == "$expected_uid" ]] \
    || die "$description must be owned by UID $expected_uid"
  if mode="$(stat -c '%a' "$path" 2>/dev/null)"; then :; else
    mode="$(stat -f '%Lp' "$path")" || die "cannot inspect permissions for $description"
  fi
  [[ "$mode" == "$expected_mode" ]] \
    || die "$description must have mode $expected_mode (mode $mode)"
}

require_owned_exact_private_dir() {
  local path="$1" description="$2" expected_uid="$3" expected_mode="$4" mode
  [[ -d "$path" && ! -L "$path" ]] \
    || die "$description must be a real non-symlink directory: $path"
  [[ "$(stat_owner "$path")" == "$expected_uid" ]] \
    || die "$description must be owned by UID $expected_uid"
  if mode="$(stat -c '%a' "$path" 2>/dev/null)"; then :; else
    mode="$(stat -f '%Lp' "$path")" || die "cannot inspect permissions for $description"
  fi
  [[ "$mode" == "$expected_mode" ]] \
    || die "$description must have mode $expected_mode (mode $mode)"
}

require_secure_file() {
  local path="$1" description="$2" mode owner links current_uid
  [[ -f "$path" && ! -L "$path" ]] || die "$description must be a regular non-symlink file: $path"
  if mode="$(stat -c '%a' "$path" 2>/dev/null)"; then
    owner="$(stat -c '%u' "$path")"
    links="$(stat -c '%h' "$path")"
  else
    mode="$(stat -f '%Lp' "$path")" || die "cannot inspect permissions for $description"
    owner="$(stat -f '%u' "$path")" || die "cannot inspect owner for $description"
    links="$(stat -f '%l' "$path")" || die "cannot inspect link count for $description"
  fi
  current_uid="$(id -u)"
  [[ "$owner" == "$current_uid" ]] || die "$description must be owned by the invoking user"
  [[ "$links" == 1 ]] || die "$description must have exactly one hard link"
  (( (8#$mode & 077) == 0 )) || die "$description permissions must deny group/other access (mode $mode)"
}

require_secure_dir() {
  local path="$1" description="$2" mode owner current_uid
  [[ -d "$path" && ! -L "$path" ]] || die "$description must be a non-symlink directory: $path"
  if mode="$(stat -c '%a' "$path" 2>/dev/null)"; then
    owner="$(stat -c '%u' "$path")"
  else
    mode="$(stat -f '%Lp' "$path")" || die "cannot inspect permissions for $description"
    owner="$(stat -f '%u' "$path")" || die "cannot inspect owner for $description"
  fi
  current_uid="$(id -u)"
  [[ "$owner" == "$current_uid" ]] || die "$description must be owned by the invoking user"
  (( (8#$mode & 077) == 0 )) || die "$description permissions must deny group/other access (mode $mode)"
}

require_lock_parent() {
  local path="$1" description="$2" mode owner
  [[ -d "$path" && ! -L "$path" ]] || die "$description must be a non-symlink directory: $path"
  if mode="$(stat -c '%a' "$path" 2>/dev/null)"; then
    owner="$(stat -c '%u' "$path")"
  else
    mode="$(stat -f '%Lp' "$path")" || die "cannot inspect permissions for $description"
    owner="$(stat -f '%u' "$path")" || die "cannot inspect owner for $description"
  fi
  [[ "$owner" == "$maintenance_lock_parent_expected_uid" ]] \
    || die "$description must be owned by UID $maintenance_lock_parent_expected_uid"
  [[ "$mode" == "$maintenance_lock_parent_expected_mode" ]] \
    || die "$description must have mode $maintenance_lock_parent_expected_mode (mode $mode)"
}

require_absolute_path() {
  local value="$1" description="$2"
  [[ "$value" == /* ]] || die "$description must be an absolute path"
  contains_control "$value" && die "$description contains a control character"
  case "$value" in
    /|/var|/var/lib|/var/lib/docker|/var/lib/docker/volumes|/opt|/etc|/tmp)
      die "$description is dangerously broad: $value"
      ;;
  esac
}

path_is_within() {
  local child="${1%/}/" parent="${2%/}/"
  [[ "$child" == "$parent"* ]]
}

validate_private_state_child() {
  local path="$1" description="$2" canonical
  [[ -e "$path" || -L "$path" ]] || die "$description does not exist: $path"
  [[ -d "$path" && ! -L "$path" ]] || die "$description must be a non-symlink directory: $path"
  require_secure_dir "$path" "$description"
  canonical="$(cd "$path" && pwd -P)" || die "cannot canonicalize $description"
  path_is_within "$canonical" "$state_dir" || die "$description escapes the cold-backup state directory"
  [[ "$canonical" != "$state_dir" ]] || die "$description resolves to the cold-backup state directory"
  printf '%s' "$canonical"
}

validate_existing_state_layout() {
  local path
  for path in "$state_dir/staging" "$state_dir/receipts"; do
    if [[ -e "$path" || -L "$path" ]]; then
      validate_private_state_child "$path" "cold-backup $(basename "$path") directory" >/dev/null
    fi
  done
}

prepare_state_layout() {
  local requested
  requested="$state_dir/staging"
  if [[ ! -e "$requested" && ! -L "$requested" ]]; then
    mkdir -m 0700 -- "$requested" || die 'cannot create private cold-backup staging directory'
  fi
  staging_root="$(validate_private_state_child "$requested" 'cold-backup staging directory')"

  requested="$state_dir/receipts"
  if [[ ! -e "$requested" && ! -L "$requested" ]]; then
    mkdir -m 0700 -- "$requested" || die 'cannot create private cold-backup receipts directory'
  fi
  receipts_dir="$(validate_private_state_child "$requested" 'cold-backup receipts directory')"
}

assert_maintenance_lock_fd_identity() {
  local path_identity fd_identity fd_path
  if [[ -e "/proc/$$/fd/$maintenance_lock_fd" ]]; then
    fd_path="/proc/$$/fd/$maintenance_lock_fd"
    path_identity="$(stat -Lc '%d:%i' "$maintenance_lock_file" 2>/dev/null)" \
      || die 'cannot identify Hash maintenance lock path'
    fd_identity="$(stat -Lc '%d:%i' "$fd_path" 2>/dev/null)" \
      || die 'cannot identify open Hash maintenance lock descriptor'
  else
    # Darwin's /dev/fd reports the devfs device rather than the target device,
    # but preserves the target inode. Production Linux takes the stronger
    # device+inode branch above; this branch keeps hermetic tests portable.
    fd_path="/dev/fd/$maintenance_lock_fd"
    path_identity="$(stat -f '%i' "$maintenance_lock_file" 2>/dev/null)" \
      || die 'cannot identify Hash maintenance lock path'
    fd_identity="$(stat -f '%i' "$fd_path" 2>/dev/null)" \
      || die 'cannot identify open Hash maintenance lock descriptor'
  fi
  [[ "$path_identity" == "$fd_identity" ]] \
    || die 'Hash maintenance lock path was replaced while opening it'
}

acquire_maintenance_lock() {
  local parent requested_parent mode owner links
  require_absolute_path "$maintenance_lock_file" 'Hash maintenance lock file'
  requested_parent="$(dirname "$maintenance_lock_file")"
  [[ -d "$requested_parent" ]] || die 'Hash maintenance lock parent does not exist'
  parent="$(cd "$requested_parent" && pwd -P)" || die 'cannot canonicalize Hash maintenance lock parent'
  require_lock_parent "$parent" 'Hash maintenance lock parent'
  maintenance_lock_file="$parent/$(basename "$maintenance_lock_file")"
  [[ ! -L "$maintenance_lock_file" ]] || die 'Hash maintenance lock file must not be a symlink'
  [[ -f "$maintenance_lock_file" ]] \
    || die 'Hash maintenance lock must be pre-provisioned as a regular file'
  if mode="$(stat -c '%a' "$maintenance_lock_file" 2>/dev/null)"; then
    owner="$(stat -c '%u' "$maintenance_lock_file")"
    links="$(stat -c '%h' "$maintenance_lock_file")"
  else
    mode="$(stat -f '%Lp' "$maintenance_lock_file")" \
      || die 'cannot inspect Hash maintenance lock permissions'
    owner="$(stat -f '%u' "$maintenance_lock_file")" \
      || die 'cannot inspect Hash maintenance lock owner'
    links="$(stat -f '%l' "$maintenance_lock_file")" \
      || die 'cannot inspect Hash maintenance lock link count'
  fi
  [[ "$mode" == 600 ]] || die "Hash maintenance lock must have mode 0600 (mode $mode)"
  [[ "$owner" == "$maintenance_lock_expected_uid" ]] \
    || die "Hash maintenance lock must be owned by UID $maintenance_lock_expected_uid"
  [[ "$links" == 1 ]] || die 'Hash maintenance lock must have exactly one hard link'
  exec {maintenance_lock_fd}>>"$maintenance_lock_file" \
    || die 'cannot open Hash maintenance lock file'
  [[ -f "$maintenance_lock_file" && ! -L "$maintenance_lock_file" ]] \
    || die 'Hash maintenance lock changed while it was opened'
  assert_maintenance_lock_fd_identity
  if ! "$FLOCK" --exclusive --nonblock "$maintenance_lock_fd"; then
    exec {maintenance_lock_fd}>&-
    maintenance_lock_fd=""
    die 'another Hash deployment, rollback, or cold backup holds the maintenance lock'
  fi
  [[ -f "$maintenance_lock_file" && ! -L "$maintenance_lock_file" ]] \
    || die 'Hash maintenance lock changed after acquisition'
  assert_maintenance_lock_fd_identity
}

release_maintenance_lock() {
  [[ -n "${maintenance_lock_fd:-}" ]] || return 0
  exec {maintenance_lock_fd}>&-
  maintenance_lock_fd=""
}

validate_recovery_sentinel_file() {
  local path="${1:-$recovery_sentinel_file}" mode owner links
  [[ -f "$path" && ! -L "$path" ]] \
    || die 'Hash cold-backup recovery sentinel must be a regular non-symlink file'
  if mode="$(stat -c '%a' "$path" 2>/dev/null)"; then
    owner="$(stat -c '%u' "$path")"
    links="$(stat -c '%h' "$path")"
  else
    mode="$(stat -f '%Lp' "$path")" \
      || die 'cannot inspect Hash cold-backup recovery sentinel permissions'
    owner="$(stat -f '%u' "$path")" \
      || die 'cannot inspect Hash cold-backup recovery sentinel owner'
    links="$(stat -f '%l' "$path")" \
      || die 'cannot inspect Hash cold-backup recovery sentinel link count'
  fi
  [[ "$mode" == 600 ]] || die "Hash cold-backup recovery sentinel must have mode 0600 (mode $mode)"
  [[ "$owner" == "$maintenance_lock_expected_uid" ]] \
    || die "Hash cold-backup recovery sentinel must be owned by UID $maintenance_lock_expected_uid"
  [[ "$links" == 1 ]] || die 'Hash cold-backup recovery sentinel must have exactly one hard link'
}

reject_stale_recovery_sentinel() {
  if [[ -e "$recovery_sentinel_file" || -L "$recovery_sentinel_file" ]]; then
    die "Hash cold-backup recovery is required; sentinel exists: $recovery_sentinel_file"
  fi
}

create_recovery_sentinel() {
  local temp_file current_owner
  reject_stale_recovery_sentinel
  temp_file="$recovery_sentinel_file.tmp.$run_id"
  [[ ! -e "$temp_file" && ! -L "$temp_file" ]] \
    || die 'refusing to replace an existing recovery-sentinel temporary file'
  if ! (set -o noclobber; jq -n --arg run_id "$run_id" \
      --arg created_at "$(date -u +%FT%TZ)" \
      '{schema_version:1,state:"cold-backup-recovery-required",run_id:$run_id,
        created_at:$created_at}' > "$temp_file") 2>/dev/null; then
    die 'cannot atomically create the recovery-sentinel temporary file'
  fi
  chmod 0600 "$temp_file" || { rm -f -- "$temp_file"; die 'cannot secure recovery-sentinel permissions'; }
  if current_owner="$(stat -c '%u' "$temp_file" 2>/dev/null)"; then :; else
    current_owner="$(stat -f '%u' "$temp_file")" \
      || { rm -f -- "$temp_file"; die 'cannot inspect recovery-sentinel owner'; }
  fi
  if [[ "$current_owner" != "$maintenance_lock_expected_uid" ]]; then
    chown "$maintenance_lock_expected_uid" "$temp_file" \
      || { rm -f -- "$temp_file"; die 'cannot set recovery-sentinel owner'; }
  fi
  validate_recovery_sentinel_file "$temp_file"
  if ! mv -n -- "$temp_file" "$recovery_sentinel_file"; then
    rm -f -- "$temp_file"
    die 'cannot atomically install the Hash recovery sentinel'
  fi
  if [[ -e "$temp_file" || -L "$temp_file" ]]; then
    rm -f -- "$temp_file"
    die 'Hash recovery sentinel already existed; it was not replaced'
  fi
  validate_recovery_sentinel_file
  sync
  recovery_sentinel_active=1
}

remove_recovery_sentinel() {
  [[ "${recovery_sentinel_active:-0}" == 1 ]] || return 0
  validate_recovery_sentinel_file
  rm -- "$recovery_sentinel_file" || return 1
  [[ ! -e "$recovery_sentinel_file" && ! -L "$recovery_sentinel_file" ]] || return 1
  sync
  recovery_sentinel_active=0
}

json_string() {
  local file="$1" filter="$2" description="$3" value
  value="$(jq -er "$filter | select(type == \"string\" and length > 0)" "$file")" \
    || die "$description is missing or invalid"
  contains_control "$value" && die "$description contains a control character"
  printf '%s' "$value"
}

json_positive_integer() {
  local file="$1" filter="$2" description="$3" value
  value="$(jq -er "$filter | select(type == \"number\" and . >= 1 and floor == .)" "$file")" \
    || die "$description is missing or invalid"
  printf '%s' "$value"
}

read_env_value() {
  local file="$1" key="$2" line value found=0
  ENV_VALUE=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == "$key="* ]] || continue
    ((found += 1))
    ((found == 1)) || die "$file defines $key more than once"
    value="${line#*=}"
    [[ -n "$value" ]] || die "$file defines empty $key"
    case "$value" in
      \"*|\'*) die "$file must use literal, unquoted $key=value syntax" ;;
    esac
    contains_control "$value" && die "$file contains a control character in $key"
    ENV_VALUE="$value"
  done < "$file"
  ((found == 1)) || die "$file does not define $key"
}

container_json() {
  local name="$1"
  "$DOCKER" inspect "$name" 2>/dev/null || die "cannot inspect required container: $name"
}

container_field() {
  local name="$1" filter="$2" description="$3" value
  value="$(container_json "$name" | jq -er ".[0] | $filter")" || die "cannot read $description from $name"
  printf '%s' "$value"
}

container_running() {
  [[ "$(container_field "$1" '.State.Running' 'running state')" == true ]]
}

container_health() {
  local name="$1"
  container_json "$name" | jq -er '.[0].State.Health.Status // "none"'
}

wait_running() {
  local name="$1" deadline now
  deadline=$(( $(date +%s) + health_timeout_seconds ))
  while :; do
    if container_running "$name"; then
      return 0
    fi
    now="$(date +%s)"
    ((now < deadline)) || return 1
    sleep 1
  done
}

wait_running_stable() {
  local name="$1" deadline stable_deadline now restart_count current_restart_count
  deadline=$(( $(date +%s) + health_timeout_seconds ))
  if ! container_running "$name"; then
    return 1
  fi
  restart_count="$(container_field "$name" '.RestartCount // 0' 'restart count')"
  [[ "$restart_count" =~ ^[0-9]+$ ]] || return 1
  stable_deadline=$(( $(date +%s) + worker_settle_seconds ))
  while :; do
    sleep 1
    if ! container_running "$name"; then
      return 1
    fi
    current_restart_count="$(container_field "$name" '.RestartCount // 0' 'restart count')"
    [[ "$current_restart_count" == "$restart_count" ]] || return 1
    now="$(date +%s)"
    ((now >= stable_deadline)) && return 0
    ((now < deadline)) || return 1
  done
}

wait_healthy() {
  local name="$1" deadline now health
  deadline=$(( $(date +%s) + health_timeout_seconds ))
  while :; do
    if container_running "$name"; then
      health="$(container_health "$name")"
      [[ "$health" == healthy ]] && return 0
      [[ "$health" == unhealthy ]] && return 1
      # A production recovery dependency without a health check cannot prove it
      # is ready before downstream writers restart.
      [[ "$health" != none ]] || return 1
    fi
    now="$(date +%s)"
    ((now < deadline)) || return 1
    sleep 1
  done
}

assert_running_healthy() {
  local name="$1" role="$2" health
  container_running "$name" || die "$role container is not running: $name"
  health="$(container_health "$name")"
  [[ "$health" == healthy ]] || die "$role container is not healthy: $name ($health)"
}

assert_compose_identity() {
  local name="$1" service="$2" role="$3" actual_project actual_service
  actual_project="$(container_field "$name" '.Config.Labels["com.docker.compose.project"] // ""' 'Compose project label')"
  actual_service="$(container_field "$name" '.Config.Labels["com.docker.compose.service"] // ""' 'Compose service label')"
  [[ "$actual_project" == "$compose_project" ]] \
    || die "$role container belongs to Compose project $actual_project, expected $compose_project"
  [[ "$actual_service" == "$service" ]] \
    || die "$role container is Compose service $actual_service, expected $service"
}

pin_container_id() {
  local name="$1" role="$2" id
  id="$(container_field "$name" '.Id' 'immutable container ID')"
  valid_container_id "$id" || die "$role container returned an invalid immutable ID"
  printf '%s' "$id"
}

assert_name_maps_to_id() {
  local name="$1" expected_id="$2" role="$3" actual_id
  actual_id="$(container_field "$name" '.Id' 'immutable container ID')"
  [[ "$actual_id" == "$expected_id" ]] \
    || die "$role container name was replaced during the cold-backup operation"
}

validate_bootstrap_storage_estate() {
  local root_identity receipt_dir_identity intent_identity receipt_identity
  local intent_sha receipt_sha

  require_owned_exact_private_dir "$bootstrap_estate_root" \
    'bootstrap storage-estate root' "$bootstrap_estate_owner_uid" 700
  [[ "$(cd "$bootstrap_estate_root" && pwd -P)" == "$bootstrap_estate_root" ]] \
    || die 'bootstrap storage-estate root path must already be canonical'
  require_owned_exact_private_dir "$bootstrap_estate_receipt_dir" \
    'bootstrap storage-estate receipt directory' "$bootstrap_estate_owner_uid" 700
  [[ "$(cd "$bootstrap_estate_receipt_dir" && pwd -P)" == "$bootstrap_estate_receipt_dir" \
      && "$(dirname "$bootstrap_estate_receipt_dir")" == "$bootstrap_estate_root" ]] \
    || die 'bootstrap storage-estate receipt directory must be a canonical direct child of its root'
  require_owned_exact_private_single_link_file "$bootstrap_estate_intent" \
    'bootstrap storage-estate intent' "$bootstrap_estate_owner_uid" 600
  require_owned_exact_private_single_link_file "$bootstrap_estate_receipt" \
    'bootstrap storage-estate receipt' "$bootstrap_estate_owner_uid" 600
  [[ "$(cd "$(dirname "$bootstrap_estate_intent")" && pwd -P)/$(basename "$bootstrap_estate_intent")" == "$bootstrap_estate_intent" \
      && "$(dirname "$bootstrap_estate_intent")" == "$bootstrap_estate_root" ]] \
    || die 'bootstrap storage-estate intent path must already be canonical'
  [[ "$(cd "$(dirname "$bootstrap_estate_receipt")" && pwd -P)/$(basename "$bootstrap_estate_receipt")" == "$bootstrap_estate_receipt" \
      && "$(dirname "$bootstrap_estate_receipt")" == "$bootstrap_estate_receipt_dir" ]] \
    || die 'bootstrap storage-estate receipt path must already be canonical'
  [[ "$(find "$bootstrap_estate_root" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')" == 2 \
      && "$(find "$bootstrap_estate_receipt_dir" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')" == 1 ]] \
    || die 'bootstrap storage-estate control directories contain an unknown or temporary entry'

  root_identity="$(stat_identity "$bootstrap_estate_root")"
  receipt_dir_identity="$(stat_identity "$bootstrap_estate_receipt_dir")"
  intent_identity="$(stat_identity "$bootstrap_estate_intent")"
  receipt_identity="$(stat_identity "$bootstrap_estate_receipt")"
  intent_sha="$(sha256_file "$bootstrap_estate_intent")"
  receipt_sha="$(sha256_file "$bootstrap_estate_receipt")"
  [[ "$root_identity" == "$expected_bootstrap_estate_root_identity" \
      && "$receipt_dir_identity" == "$expected_bootstrap_estate_receipt_dir_identity" \
      && "$intent_identity" == "$expected_bootstrap_estate_intent_identity" \
      && "$receipt_identity" == "$expected_bootstrap_estate_receipt_identity" ]] \
    || die 'bootstrap storage-estate directory or file identity does not match the pinned configuration'
  [[ "$intent_sha" == "$expected_bootstrap_estate_intent_sha" \
      && "$receipt_sha" == "$expected_bootstrap_estate_receipt_sha" ]] \
    || die 'bootstrap storage-estate digest does not match the pinned configuration'

  jq -s -e 'length == 1' "$bootstrap_estate_intent" >/dev/null \
    || die 'bootstrap storage-estate intent must contain exactly one JSON value'
  jq -s -e 'length == 1' "$bootstrap_estate_receipt" >/dev/null \
    || die 'bootstrap storage-estate receipt must contain exactly one JSON value'

  jq -e '
    type == "object" and
    (keys | sort) == (["candidate","created_at","marker_key","marker_nonce_hex","marker_retain_until","marker_sha256","retention_years","schema_version","storage"] | sort) and
    .schema_version == 1 and
    (.candidate | type == "object" and
      (keys | sort) == (["app_image_id","commit_sha","lifecycle_contract_version","migrations_sha256","phase","schema_version"] | sort) and
      .schema_version == 2 and .phase == "foundation-empty-database" and
      (.commit_sha | type == "string" and test("^[0-9a-f]{40}([0-9a-f]{24})?$")) and
      (.app_image_id | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
      (.migrations_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.lifecycle_contract_version | type == "number" and . >= 1 and floor == .)) and
    (.storage | type == "object") and
    .marker_key == "_hash/bootstrap-estate/v1" and
    .retention_years == 7 and
    ((.created_at | type) == "string") and
    (.created_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
    ((.created_at | fromdateiso8601 | type) == "number") and
    (.marker_nonce_hex | type == "string" and test("^[0-9a-f]{64}$")) and
    (.marker_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    ((.marker_retain_until | type) == "string") and
    (.marker_retain_until | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
    ((.marker_retain_until | fromdateiso8601 | type) == "number") and
    (. as $intent |
      (($intent.created_at | strptime("%Y-%m-%dT%H:%M:%SZ") |
        .[0] += 7 | mktime | strftime("%Y-%m-%dT%H:%M:%SZ")) ==
       $intent.marker_retain_until))
  ' "$bootstrap_estate_intent" >/dev/null \
    || die 'bootstrap storage-estate intent schema is invalid or has unknown fields'
  jq -e '
    type == "object" and
    (keys | sort) == (["marker_key","marker_retain_until","marker_sha256","marker_version_id","schema_version"] | sort) and
    .schema_version == 1 and
    .marker_key == "_hash/bootstrap-estate/v1" and
    ((.marker_version_id | type) == "string") and
    ((.marker_version_id | length) >= 1 and (.marker_version_id | length) <= 1024) and
    (.marker_version_id | explode | all(. >= 32 and . != 127)) and
    (.marker_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    ((.marker_retain_until | type) == "string") and
    (.marker_retain_until | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
    ((.marker_retain_until | fromdateiso8601 | type) == "number")
  ' "$bootstrap_estate_receipt" >/dev/null \
    || die 'bootstrap storage-estate receipt schema is invalid or has unknown fields'
  jq -e --slurpfile receipt "$bootstrap_estate_receipt" \
      --slurpfile contract "$storage_contract" '
    (.storage == $contract[0]) and
    (.marker_key == $receipt[0].marker_key) and
    (.marker_sha256 == $receipt[0].marker_sha256) and
    (.marker_retain_until == $receipt[0].marker_retain_until)
  ' "$bootstrap_estate_intent" >/dev/null \
    || die 'bootstrap storage-estate intent, receipt, and immutable storage contract do not match'

  # Recheck after every content read so path replacement cannot turn validation
  # into a claim about a different inode with the same pathname.
  [[ "$(stat_identity "$bootstrap_estate_root")" == "$expected_bootstrap_estate_root_identity" \
      && "$(stat_identity "$bootstrap_estate_receipt_dir")" == "$expected_bootstrap_estate_receipt_dir_identity" \
      && "$(stat_identity "$bootstrap_estate_intent")" == "$expected_bootstrap_estate_intent_identity" \
      && "$(stat_identity "$bootstrap_estate_receipt")" == "$expected_bootstrap_estate_receipt_identity" \
      && "$(sha256_file "$bootstrap_estate_intent")" == "$expected_bootstrap_estate_intent_sha" \
      && "$(sha256_file "$bootstrap_estate_receipt")" == "$expected_bootstrap_estate_receipt_sha" ]] \
    || die 'bootstrap storage-estate artifacts changed while they were validated'

  bootstrap_marker_key="$(json_string "$bootstrap_estate_receipt" '.marker_key' 'bootstrap marker key')"
  bootstrap_marker_version_id="$(json_string "$bootstrap_estate_receipt" '.marker_version_id' 'bootstrap marker VersionID')"
  bootstrap_marker_sha="$(json_string "$bootstrap_estate_receipt" '.marker_sha256' 'bootstrap marker digest')"
  bootstrap_marker_retain_until="$(json_string "$bootstrap_estate_receipt" '.marker_retain_until' 'bootstrap marker retention')"
}

load_config() {
  require_secure_file "$config_file" 'cold-backup configuration'
  jq -s -e 'length == 1' "$config_file" >/dev/null \
    || die 'cold-backup configuration must contain exactly one JSON value'
  jq -e '
    type == "object" and
    (keys | sort) == (["bootstrap_storage_estate","compose","containers","contracts","inventory_sql","inventory_sql_sha256","minio","postgres","release","restic","schema_version","secret_sources","state_dir","verifier_script","verifier_script_sha256"] | sort) and
    .schema_version == 3 and
    (.compose | type == "object" and (keys | sort) == (["app_service","gotenberg_service","project","worker_service"] | sort)) and
    (.containers | type == "object" and (keys | sort) == (["app","gotenberg","minio","postgres","worker"] | sort)) and
    (.contracts | type == "object" and (keys | sort) == (["database","owner_uid","storage"] | sort)) and
    (.contracts.owner_uid | type == "number" and . >= 0 and floor == .) and
    (.bootstrap_storage_estate | type == "object" and
      (keys | sort) == (["intent","intent_identity","intent_sha256","owner_uid","receipt","receipt_dir","receipt_dir_identity","receipt_identity","receipt_sha256","root","root_identity"] | sort)) and
    (.bootstrap_storage_estate.owner_uid | type == "number" and . >= 0 and floor == .) and
    (.bootstrap_storage_estate.root_identity | type == "string" and test("^[0-9]+:[0-9]+$")) and
    (.bootstrap_storage_estate.receipt_dir_identity | type == "string" and test("^[0-9]+:[0-9]+$")) and
    (.bootstrap_storage_estate.intent_identity | type == "string" and test("^[0-9]+:[0-9]+$")) and
    (.bootstrap_storage_estate.receipt_identity | type == "string" and test("^[0-9]+:[0-9]+$")) and
    (.bootstrap_storage_estate.intent_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    (.bootstrap_storage_estate.receipt_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    (.release | type == "object" and (keys | sort) == (["current_symlink","dir","owner_uid","store"] | sort)) and
    (.release.owner_uid | type == "number" and . >= 0 and floor == .) and
    (.postgres | type == "object" and (keys | sort) == (["application_user","database","database_oid","host","network","port","ssl_mode","system_identifier","user"] | sort)) and
    (.postgres.port | type == "number" and . >= 1 and . <= 65535 and floor == .) and
    (.postgres.system_identifier | type == "string" and test("^[1-9][0-9]{0,19}$")) and
    (.postgres.database_oid | type == "number" and . >= 1 and . <= 4294967295 and floor == .) and
    (.postgres.ssl_mode == "disable" or .postgres.ssl_mode == "require" or
      .postgres.ssl_mode == "verify-ca" or .postgres.ssl_mode == "verify-full") and
    (.minio | type == "object" and (keys | sort) == (["bucket","data_path","endpoint_host","endpoint_port","expected_image_id","mount_destination","network","volume"] | sort)) and
    (.minio.endpoint_port | type == "number" and . >= 1 and . <= 65535 and floor == .) and
    (.secret_sources | type == "array" and length >= 3 and all(.[ ];
      type == "object" and (keys | sort) == (["owner_uid","path","purpose"] | sort) and
      (.owner_uid | type == "number" and . >= 0 and floor == .) and
      (.path | type == "string" and length > 0) and
      (.purpose | type == "string" and
        test("^(hash-runtime-env|hash-database-env|minio-runtime-env:[A-Za-z0-9_.-]+)$")))) and
    ([.secret_sources[] | select(.purpose == "hash-runtime-env")] | length) == 1 and
    ([.secret_sources[] | select(.purpose == "hash-database-env")] | length) == 1 and
    ([.secret_sources[] | select(.purpose | startswith("minio-runtime-env:"))] | length) >= 1 and
    ([.secret_sources[].path] | length) == ([.secret_sources[].path] | unique | length) and
    ([.secret_sources[].purpose] | length) == ([.secret_sources[].purpose] | unique | length) and
    (.restic | type == "object" and (keys | sort) == (["config_id","env_file","health_timeout_seconds","host","integrity_subset","password_variable","repository_sha256","repository_variable","stop_timeout_seconds","worker_settle_seconds"] | sort))
  ' "$config_file" >/dev/null || die 'cold-backup configuration schema is invalid or has unknown fields'

  compose_project="$(json_string "$config_file" '.compose.project' 'Compose project')"
  app_service="$(json_string "$config_file" '.compose.app_service' 'app Compose service')"
  worker_service="$(json_string "$config_file" '.compose.worker_service' 'worker Compose service')"
  gotenberg_service="$(json_string "$config_file" '.compose.gotenberg_service' 'Gotenberg Compose service')"
  app_container="$(json_string "$config_file" '.containers.app' 'app container')"
  worker_container="$(json_string "$config_file" '.containers.worker' 'worker container')"
  gotenberg_container="$(json_string "$config_file" '.containers.gotenberg' 'Gotenberg container')"
  postgres_container="$(json_string "$config_file" '.containers.postgres' 'PostgreSQL container')"
  minio_container="$(json_string "$config_file" '.containers.minio' 'MinIO container')"
  postgres_database="$(json_string "$config_file" '.postgres.database' 'PostgreSQL database')"
  postgres_user="$(json_string "$config_file" '.postgres.user' 'PostgreSQL user')"
  postgres_application_user="$(json_string "$config_file" '.postgres.application_user' 'PostgreSQL application user')"
  postgres_host="$(json_string "$config_file" '.postgres.host' 'PostgreSQL network host')"
  postgres_port="$(json_positive_integer "$config_file" '.postgres.port' 'PostgreSQL network port')"
  postgres_network="$(json_string "$config_file" '.postgres.network' 'PostgreSQL Docker network')"
  expected_postgres_system_identifier="$(json_string "$config_file" '.postgres.system_identifier' 'PostgreSQL system identifier')"
  expected_postgres_database_oid="$(jq -er '.postgres.database_oid' "$config_file")"
  postgres_ssl_mode="$(json_string "$config_file" '.postgres.ssl_mode' 'PostgreSQL SSL mode')"
  minio_volume="$(json_string "$config_file" '.minio.volume' 'MinIO volume')"
  minio_data_path_requested="$(json_string "$config_file" '.minio.data_path' 'MinIO data path')"
  minio_mount_destination="$(json_string "$config_file" '.minio.mount_destination' 'MinIO mount destination')"
  expected_minio_image_id="$(json_string "$config_file" '.minio.expected_image_id' 'expected MinIO image ID')"
  minio_endpoint_host="$(json_string "$config_file" '.minio.endpoint_host' 'MinIO endpoint host')"
  minio_endpoint_port="$(json_positive_integer "$config_file" '.minio.endpoint_port' 'MinIO endpoint port')"
  minio_network="$(json_string "$config_file" '.minio.network' 'MinIO Docker network')"
  minio_bucket="$(json_string "$config_file" '.minio.bucket' 'MinIO bucket')"
  release_store_requested="$(json_string "$config_file" '.release.store' 'Hash release store')"
  release_dir_requested="$(json_string "$config_file" '.release.dir' 'Hash release directory')"
  current_symlink="$(json_string "$config_file" '.release.current_symlink' 'Hash current-release symlink')"
  release_owner_uid="$(jq -er '.release.owner_uid' "$config_file")"
  storage_contract_requested="$(json_string "$config_file" '.contracts.storage' 'Hash storage contract')"
  database_contract_requested="$(json_string "$config_file" '.contracts.database' 'Hash database contract')"
  contract_owner_uid="$(jq -er '.contracts.owner_uid' "$config_file")"
  bootstrap_estate_root_requested="$(json_string "$config_file" '.bootstrap_storage_estate.root' 'bootstrap storage-estate root')"
  expected_bootstrap_estate_root_identity="$(json_string "$config_file" '.bootstrap_storage_estate.root_identity' 'bootstrap storage-estate root identity')"
  bootstrap_estate_intent_requested="$(json_string "$config_file" '.bootstrap_storage_estate.intent' 'bootstrap storage-estate intent')"
  expected_bootstrap_estate_intent_identity="$(json_string "$config_file" '.bootstrap_storage_estate.intent_identity' 'bootstrap storage-estate intent identity')"
  expected_bootstrap_estate_intent_sha="$(json_string "$config_file" '.bootstrap_storage_estate.intent_sha256' 'bootstrap storage-estate intent digest')"
  bootstrap_estate_receipt_dir_requested="$(json_string "$config_file" '.bootstrap_storage_estate.receipt_dir' 'bootstrap storage-estate receipt directory')"
  expected_bootstrap_estate_receipt_dir_identity="$(json_string "$config_file" '.bootstrap_storage_estate.receipt_dir_identity' 'bootstrap storage-estate receipt-directory identity')"
  bootstrap_estate_receipt_requested="$(json_string "$config_file" '.bootstrap_storage_estate.receipt' 'bootstrap storage-estate receipt')"
  expected_bootstrap_estate_receipt_identity="$(json_string "$config_file" '.bootstrap_storage_estate.receipt_identity' 'bootstrap storage-estate receipt identity')"
  expected_bootstrap_estate_receipt_sha="$(json_string "$config_file" '.bootstrap_storage_estate.receipt_sha256' 'bootstrap storage-estate receipt digest')"
  bootstrap_estate_owner_uid="$(jq -er '.bootstrap_storage_estate.owner_uid' "$config_file")"
  inventory_sql_requested="$(json_string "$config_file" '.inventory_sql' 'canonical inventory SQL')"
  expected_inventory_sql_sha="$(json_string "$config_file" '.inventory_sql_sha256' 'canonical inventory SQL digest')"
  verifier_script_requested="$(json_string "$config_file" '.verifier_script' 'canonical recovery verifier')"
  expected_verifier_script_sha="$(json_string "$config_file" '.verifier_script_sha256' 'canonical recovery verifier digest')"
  state_dir_requested="$(json_string "$config_file" '.state_dir' 'cold-backup state directory')"
  restic_env="$(json_string "$config_file" '.restic.env_file' 'Restic environment file')"
  restic_repository_variable="$(json_string "$config_file" '.restic.repository_variable' 'Restic repository variable')"
  restic_password_variable="$(json_string "$config_file" '.restic.password_variable' 'Restic password variable')"
  expected_repository_sha="$(json_string "$config_file" '.restic.repository_sha256' 'Restic repository fingerprint')"
  expected_restic_config_id="$(json_string "$config_file" '.restic.config_id' 'Restic config identity')"
  restic_host="$(json_string "$config_file" '.restic.host' 'Restic host label')"
  integrity_subset="$(json_string "$config_file" '.restic.integrity_subset' 'Restic integrity subset')"
  stop_timeout_seconds="$(json_positive_integer "$config_file" '.restic.stop_timeout_seconds' 'stop timeout')"
  health_timeout_seconds="$(json_positive_integer "$config_file" '.restic.health_timeout_seconds' 'health timeout')"
  worker_settle_seconds="$(json_positive_integer "$config_file" '.restic.worker_settle_seconds' 'worker settle interval')"

  for name in "$compose_project" "$app_service" "$worker_service" "$gotenberg_service" \
      "$app_container" "$worker_container" "$gotenberg_container" "$postgres_container" \
      "$minio_container" "$minio_volume" "$restic_host" "$postgres_host" \
      "$postgres_network" "$minio_endpoint_host" "$minio_network"; do
    valid_name "$name" || die "invalid container/service/host identifier in configuration: $name"
  done
  [[ "$(printf '%s\n' "$app_service" "$worker_service" "$gotenberg_service" | LC_ALL=C sort -u | wc -l | tr -d ' ')" == 3 ]] \
    || die 'Hash app, worker, and Gotenberg service identities must be distinct'
  [[ "$(printf '%s\n' "$app_container" "$worker_container" "$gotenberg_container" "$postgres_container" "$minio_container" | LC_ALL=C sort -u | wc -l | tr -d ' ')" == 5 ]] \
    || die 'all configured container identities must be distinct'
  valid_db_identifier "$postgres_database" || die 'invalid PostgreSQL database identifier'
  valid_db_identifier "$postgres_user" || die 'invalid PostgreSQL user identifier'
  [[ "$postgres_application_user" =~ ^[a-z_][a-z0-9_]{0,62}$ ]] \
    || die 'invalid PostgreSQL application user identifier'
  valid_port "$postgres_port" || die 'invalid PostgreSQL network port'
  [[ "$expected_postgres_system_identifier" =~ ^[1-9][0-9]{0,19}$ ]] \
    || die 'invalid PostgreSQL system identifier'
  [[ "$expected_postgres_database_oid" =~ ^[1-9][0-9]{0,9}$ ]] \
    && ((10#$expected_postgres_database_oid <= 4294967295)) \
    || die 'invalid PostgreSQL database OID'
  valid_port "$minio_endpoint_port" || die 'invalid MinIO endpoint port'
  [[ "$minio_bucket" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ && "$minio_bucket" != *..* ]] \
    || die 'invalid MinIO bucket name'
  valid_image_id "$expected_minio_image_id" || die 'expected MinIO image must be a full sha256 content ID'
  [[ "$expected_repository_sha" =~ ^[0-9a-f]{64}$ ]] || die 'Restic repository fingerprint must be 64 lowercase hex characters'
  [[ "$expected_restic_config_id" =~ ^[0-9a-f]{64}$ ]] || die 'Restic config identity must be 64 lowercase hex characters'
  [[ "$expected_inventory_sql_sha" =~ ^[0-9a-f]{64}$ ]] || die 'canonical inventory SQL digest must be 64 lowercase hex characters'
  [[ "$expected_verifier_script_sha" =~ ^[0-9a-f]{64}$ ]] || die 'canonical recovery verifier digest must be 64 lowercase hex characters'
  [[ "$integrity_subset" =~ ^([1-9][0-9]?|100)%$ ]] || die 'Restic integrity subset must be 1% through 100%'
  ((worker_settle_seconds <= health_timeout_seconds && worker_settle_seconds <= 60)) \
    || die 'worker settle interval must not exceed the health timeout or 60 seconds'
  case "$restic_repository_variable:$restic_password_variable" in
    RESTIC_REPOSITORY:RESTIC_PASSWORD|OFFSITE_RESTIC_REPOSITORY:OFFSITE_RESTIC_PASSWORD) ;;
    *) die 'Restic variable names must select a matching RESTIC_* or OFFSITE_RESTIC_* pair' ;;
  esac

  require_absolute_path "$release_store_requested" 'Hash release store'
  require_absolute_path "$release_dir_requested" 'Hash release directory'
  require_absolute_path "$current_symlink" 'Hash current-release symlink'
  require_absolute_path "$storage_contract_requested" 'Hash storage contract'
  require_absolute_path "$database_contract_requested" 'Hash database contract'
  require_absolute_path "$bootstrap_estate_root_requested" 'bootstrap storage-estate root'
  require_absolute_path "$bootstrap_estate_intent_requested" 'bootstrap storage-estate intent'
  require_absolute_path "$bootstrap_estate_receipt_dir_requested" 'bootstrap storage-estate receipt directory'
  require_absolute_path "$bootstrap_estate_receipt_requested" 'bootstrap storage-estate receipt'
  require_absolute_path "$inventory_sql_requested" 'canonical inventory SQL'
  require_absolute_path "$verifier_script_requested" 'canonical recovery verifier'
  require_absolute_path "$state_dir_requested" 'cold-backup state directory'
  require_absolute_path "$restic_env" 'Restic environment file'
  require_absolute_path "$minio_data_path_requested" 'MinIO data path'
  require_absolute_path "$minio_mount_destination" 'MinIO mount destination'

  [[ "$release_store_requested" == "$hash_runtime_root/releases" ]] \
    || die 'Hash release store must be the canonical production release store'
  [[ "$current_symlink" == "$hash_runtime_root/current" ]] \
    || die 'Hash current-release symlink must use the canonical production path'
  [[ "$storage_contract_requested" == "$hash_runtime_root/storage-contract.json" ]] \
    || die 'Hash storage contract must use the canonical production path'
  [[ "$database_contract_requested" == "$hash_runtime_root/database-contract.json" ]] \
    || die 'Hash database contract must use the canonical production path'
  [[ "$bootstrap_estate_root_requested" == "$hash_runtime_root/bootstrap-storage-estate" \
      && "$bootstrap_estate_intent_requested" == "$hash_runtime_root/bootstrap-storage-estate/intent.json" \
      && "$bootstrap_estate_receipt_dir_requested" == "$hash_runtime_root/bootstrap-storage-estate/receipt" \
      && "$bootstrap_estate_receipt_requested" == "$hash_runtime_root/bootstrap-storage-estate/receipt/receipt.json" ]] \
    || die 'bootstrap storage-estate artifacts must use their canonical production paths'
  [[ -d "$release_store_requested" && ! -L "$release_store_requested" ]] \
    || die 'Hash release store must be a real non-symlink directory'
  release_store="$(cd "$release_store_requested" && pwd -P)"
  [[ "$release_store" == "$release_store_requested" ]] \
    || die 'Hash release store must already be canonical'
  [[ -d "$release_dir_requested" && ! -L "$release_dir_requested" ]] \
    || die 'Hash release directory must be a real non-symlink directory'
  release_dir="$(cd "$release_dir_requested" && pwd -P)"
  [[ "$(dirname "$release_dir")" == "$release_store" ]] \
    || die 'Hash release directory must be a direct child of the canonical release store'
  require_secure_dir "$state_dir_requested" 'cold-backup state directory'
  state_dir="$(cd "$state_dir_requested" && pwd -P)"
  [[ -f "$inventory_sql_requested" && ! -L "$inventory_sql_requested" ]] || die 'canonical inventory SQL must be a regular non-symlink file'
  inventory_sql="$(cd "$(dirname "$inventory_sql_requested")" && pwd -P)/$(basename "$inventory_sql_requested")"
  [[ "$(sha256_file "$inventory_sql")" == "$expected_inventory_sql_sha" ]] \
    || die 'canonical inventory SQL does not match the pinned digest'
  [[ -f "$verifier_script_requested" && ! -L "$verifier_script_requested" ]] || die 'canonical recovery verifier must be a regular non-symlink file'
  verifier_script="$(cd "$(dirname "$verifier_script_requested")" && pwd -P)/$(basename "$verifier_script_requested")"
  [[ "$(sha256_file "$verifier_script")" == "$expected_verifier_script_sha" ]] \
    || die 'canonical recovery verifier does not match the pinned digest'
  bash -n "$verifier_script" || die 'canonical recovery verifier has invalid shell syntax'
  require_secure_file "$restic_env" 'Restic environment file'
  # Resolve a symlinked parent before credentials are read. Checking only the
  # final file component would otherwise let an apparently external path point
  # into the MinIO volume and be captured with the cold snapshot.
  restic_env="$(cd "$(dirname "$restic_env")" && pwd -P)/$(basename "$restic_env")"
  restic_env_identity="$(stat_identity "$restic_env")"
  restic_env_sha="$(sha256_file "$restic_env")"

  require_owned_private_single_link_file "$storage_contract_requested" \
    'Hash storage contract' "$contract_owner_uid"
  storage_contract="$(cd "$(dirname "$storage_contract_requested")" && pwd -P)/$(basename "$storage_contract_requested")"
  [[ "$storage_contract" == "$storage_contract_requested" ]] \
    || die 'Hash storage contract path must already be canonical'
  require_owned_private_single_link_file "$database_contract_requested" \
    'Hash database contract' "$contract_owner_uid"
  database_contract="$(cd "$(dirname "$database_contract_requested")" && pwd -P)/$(basename "$database_contract_requested")"
  [[ "$database_contract" == "$database_contract_requested" ]] \
    || die 'Hash database contract path must already be canonical'

  bootstrap_estate_root="$bootstrap_estate_root_requested"
  bootstrap_estate_intent="$bootstrap_estate_intent_requested"
  bootstrap_estate_receipt_dir="$bootstrap_estate_receipt_dir_requested"
  bootstrap_estate_receipt="$bootstrap_estate_receipt_requested"
  validate_bootstrap_storage_estate

  secret_paths=()
  secret_owners=()
  secret_purposes=()
  secret_identities=()
  secret_sha256s=()
  while IFS=$'\t' read -r secret_path secret_owner secret_purpose; do
    requested_secret_path="$secret_path"
    require_absolute_path "$secret_path" "$secret_purpose secret source"
    contains_control "$secret_purpose" && die 'secret-source purpose contains a control character'
    require_owned_private_single_link_file "$secret_path" "$secret_purpose secret source" "$secret_owner"
    secret_path="$(cd "$(dirname "$secret_path")" && pwd -P)/$(basename "$secret_path")"
    [[ "$secret_path" == "$requested_secret_path" ]] \
      || die "$secret_purpose secret source path must already be canonical"
    secret_paths+=("$secret_path")
    secret_owners+=("$secret_owner")
    secret_purposes+=("$secret_purpose")
    secret_identities+=("$(stat_identity "$secret_path")")
    secret_sha256s+=("$(sha256_file "$secret_path")")
  done < <(jq -r '.secret_sources[] | [.path, (.owner_uid|tostring), .purpose] | @tsv' "$config_file")
  [[ "${#secret_paths[@]}" -ge 3 ]] || die 'secret-source inventory is incomplete'

  hash_env_source="$(jq -r '.secret_sources[] | select(.purpose == "hash-runtime-env") | .path' "$config_file")"
  database_env_source="$(jq -r '.secret_sources[] | select(.purpose == "hash-database-env") | .path' "$config_file")"
  [[ "$hash_env_source" == "$hash_runtime_root/.env" ]] \
    || die 'Hash runtime environment must use the canonical production secret source'
  [[ "$database_env_source" == "$hash_runtime_root/runtime-secrets/hash-db.env" ]] \
    || die 'Hash database environment must use the canonical production secret source'

  path_is_within "$state_dir" "$release_dir" && die 'state directory must not be inside the Hash release directory'
  path_is_within "$release_dir" "$state_dir" && die 'Hash release directory must not be inside the state directory'
  return 0
}

load_restic_environment() {
  local optional_temp=""
  # Clear every selector that could silently redirect this operation before
  # installing the two exact values from the reviewed Storage Box env file.
  unset RESTIC_REPOSITORY RESTIC_PASSWORD RESTIC_PASSWORD_FILE RESTIC_PASSWORD_COMMAND \
    RESTIC_FROM_REPOSITORY RESTIC_FROM_PASSWORD RESTIC_FROM_PASSWORD_FILE \
    RESTIC_FROM_PASSWORD_COMMAND RESTIC_REPOSITORY_FILE

  read_env_value "$restic_env" "$restic_repository_variable"
  RESTIC_REPOSITORY="$ENV_VALUE"
  read_env_value "$restic_env" "$restic_password_variable"
  RESTIC_PASSWORD="$ENV_VALUE"
  if grep -q '^RESTIC_TEMP_DIR=' "$restic_env"; then
    read_env_value "$restic_env" RESTIC_TEMP_DIR
    optional_temp="$ENV_VALUE"
    require_absolute_path "$optional_temp" 'Restic temporary directory'
    [[ -d "$optional_temp" && -w "$optional_temp" ]] || die 'Restic temporary directory does not exist or is not writable'
    restic_temp_dir="$(cd "$optional_temp" && pwd -P)"
  else
    restic_temp_dir=""
  fi

  [[ "$RESTIC_REPOSITORY" =~ ^sftp:[A-Za-z0-9._-]+@([A-Za-z0-9-]+\.)+your-storagebox\.de:/[^[:space:]]+$ ]] \
    || die 'Restic repository is not a credential-free SFTP Hetzner Storage Box URI'
  repository_sha="$(printf '%s' "$RESTIC_REPOSITORY" | sha256_text)"
  [[ "$repository_sha" == "$expected_repository_sha" ]] \
    || die 'Restic repository does not match the pinned configuration fingerprint'
}

restic_cmd() (
  # Export credentials only in the child shell and replace that shell directly
  # with Restic. In particular, never place the password in `env` argv, where
  # it could be sampled from the process table before `env` execs Restic.
  export RESTIC_REPOSITORY RESTIC_PASSWORD
  if [[ -n "$restic_temp_dir" ]]; then
    RESTIC_TEMP_DIR="$restic_temp_dir"
    export RESTIC_TEMP_DIR
  else
    unset RESTIC_TEMP_DIR
  fi
  exec "$RESTIC" "$@"
)

container_env_value() {
  local name="$1" key="$2" description="$3" allow_empty="${4:-false}" value
  value="$(container_json "$name" | jq -er --arg prefix "$key=" '
    [.[0].Config.Env[]? | select(startswith($prefix))] as $matches |
    select($matches | length == 1) |
    $matches[0] | ltrimstr($prefix)
  ')" || die "cannot read exactly one $description from the pinned container"
  if [[ "$allow_empty" != true && -z "$value" ]]; then
    die "$description must not be empty"
  fi
  contains_control "$value" && die "$description contains a control character"
  printf '%s' "$value"
}

assert_no_pg_environment_overrides() {
  local name="$1"
  container_json "$name" | jq -e '
    [.[0].Config.Env[]? | select(type != "string" or startswith("PG"))] |
    length == 0
  ' >/dev/null || die 'a Hash writer declares a forbidden PG* environment override'
}

container_network_id() {
  local name="$1" network="$2" role="$3" network_id
  network_id="$(container_json "$name" | jq -er --arg network "$network" '
    .[0].NetworkSettings.Networks[$network] |
    select(type == "object") |
    .NetworkID | select(type == "string" and length > 0)
  ')" || die "$role is not attached to the configured Docker network"
  printf '%s' "$network_id"
}

assert_container_network_alias() {
  local name="$1" network="$2" alias="$3" role="$4"
  container_json "$name" | jq -e --arg network "$network" --arg alias "$alias" '
    .[0].NetworkSettings.Networks[$network] as $n |
    ($n | type == "object") and
    (([$n.Aliases[]?, $n.DNSNames[]?] | any(. == $alias)))
  ' >/dev/null || die "$role does not own the configured network alias"
}

assert_unique_network_alias_owner() {
  local network="$1" alias="$2" expected_id="$3" role="$4" network_json endpoint_id
  local owner_count=0 expected_count=0
  network_json="$("$DOCKER" network inspect "$network" 2>/dev/null)" \
    || die "cannot inspect the configured $role Docker network"
  jq -e 'type == "array" and length == 1 and .[0].Containers != null and
    (.[0].Containers | type == "object")' <<<"$network_json" >/dev/null \
    || die "configured $role Docker network returned invalid topology"
  while IFS= read -r endpoint_id; do
    valid_container_id "$endpoint_id" \
      || die "configured $role Docker network returned an invalid container ID"
    if container_json "$endpoint_id" | jq -e --arg network "$network" --arg alias "$alias" '
        .[0].NetworkSettings.Networks[$network] as $n |
        ($n | type == "object") and
        (([$n.Aliases[]?, $n.DNSNames[]?] | any(. == $alias)))
      ' >/dev/null; then
      ((owner_count += 1))
      [[ "$endpoint_id" == "$expected_id" ]] && ((expected_count += 1))
    fi
  done < <(jq -r '.[0].Containers | keys[]' <<<"$network_json" | LC_ALL=C sort)
  [[ "$owner_count" == 1 && "$expected_count" == 1 ]] \
    || die "$role network alias is not uniquely owned by the pinned container"
}

assert_shared_network_target() {
  local target="$1" network="$2" alias="$3" role="$4" target_network app_network worker_network
  target_network="$(container_network_id "$target" "$network" "$role")"
  app_network="$(container_network_id "$app_container_id" "$network" 'Hash app')"
  worker_network="$(container_network_id "$worker_container_id" "$network" 'Hash worker')"
  [[ "$target_network" == "$app_network" && "$target_network" == "$worker_network" ]] \
    || die "$role and both Hash writers do not share the exact configured Docker network"
  assert_container_network_alias "$target" "$network" "$alias" "$role"
  assert_unique_network_alias_owner "$network" "$alias" "$target" "$role"
}

assert_container_exposes_port() {
  local name="$1" port="$2" role="$3"
  container_json "$name" | jq -e --arg port "$port/tcp" \
    '.[0].Config.ExposedPorts[$port] != null' >/dev/null \
    || die "$role does not expose the configured internal TCP port"
}

read_database_env_source() {
  local line found=0
  database_url=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == HASH_DB_URL=* ]] \
      || die 'Hash database environment snapshot must contain only HASH_DB_URL'
    ((found += 1))
    ((found == 1)) || die 'Hash database environment snapshot defines HASH_DB_URL more than once'
    database_url="${line#HASH_DB_URL=}"
    [[ -n "$database_url" ]] || die 'Hash database environment snapshot contains an empty HASH_DB_URL'
    contains_control "$database_url" && die 'Hash database URL contains a control character'
  done < "$database_env_source"
  ((found == 1)) || die 'Hash database environment snapshot does not define HASH_DB_URL'
}

parse_database_url_target() {
  local pair key value normalized_key seen_keys='|' ssl_mode_seen=0
  # Parse in this shell so the credential-bearing URL is never copied into a
  # child process argument (and therefore never exposed via the process list).
  # The deliberately narrow grammar also rejects alternate URL authorities,
  # fragments, percent-encoded target components, and implicit ports.
  if [[ "$database_url" =~ ^postgres(ql)?://([A-Za-z_][A-Za-z0-9_.-]*):([^/@]+)@([A-Za-z0-9][A-Za-z0-9_.-]*):([0-9]{1,5})/([A-Za-z_][A-Za-z0-9_.-]*)([?]([^#]*))?$ ]]; then
    parsed_db_username="${BASH_REMATCH[2]}"
    parsed_db_host="${BASH_REMATCH[4]}"
    parsed_db_port="${BASH_REMATCH[5]}"
    parsed_db_database="${BASH_REMATCH[6]}"
    parsed_db_query="${BASH_REMATCH[8]:-}"
  else
    die 'Hash database URL must use an explicit local Docker host, port, and database'
  fi
  parsed_db_ssl_mode=""
  valid_db_identifier "$parsed_db_username" || die 'Hash database URL username is invalid'
  valid_name "$parsed_db_host" || die 'Hash database URL host is invalid'
  valid_port "$parsed_db_port" || die 'Hash database URL port is invalid'
  valid_db_identifier "$parsed_db_database" || die 'Hash database URL database is invalid'
  if [[ -n "$parsed_db_query" ]]; then
    IFS='&' read -r -a database_query_pairs <<<"$parsed_db_query"
    for pair in "${database_query_pairs[@]}"; do
      [[ "$pair" == *=* ]] || die 'Hash database URL query options must use key=value syntax'
      key="${pair%%=*}"
      value="${pair#*=}"
      [[ "$key" =~ ^[A-Za-z][A-Za-z0-9_.-]*$ ]] \
        || die 'Hash database URL query contains a non-canonical option name'
      normalized_key="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')"
      case "$seen_keys" in
        *"|$normalized_key|"*) die 'Hash database URL query defines an option more than once' ;;
      esac
      seen_keys+="$normalized_key|"
      case "$normalized_key" in
        sslmode)
          [[ "$value" == disable || "$value" == require || "$value" == verify-ca || "$value" == verify-full ]] \
            || die 'Hash database URL contains an invalid SSL mode'
          parsed_db_ssl_mode="$value"
          ssl_mode_seen=1
          ;;
        connect_timeout|application_name|pool_max_conns|pool_min_conns|pool_max_conn_lifetime|pool_max_conn_idle_time|pool_health_check_period|pool_max_conn_lifetime_jitter)
          ;;
        host|port|dbname|database|user|password|service|servicefile|passfile|options)
          die 'Hash database URL query must not override connection target, credential, or role fields'
          ;;
        *) die 'Hash database URL query contains an unsupported option' ;;
      esac
    done
  fi
  ((ssl_mode_seen == 1)) || die 'Hash database URL must explicitly select one SSL mode'
}

validate_storage_contract() {
  local endpoint expected_endpoint writer value source_mount app_source worker_source
  require_owned_private_single_link_file "$storage_contract" 'Hash storage contract' "$contract_owner_uid"
  jq -e '
    type == "object" and
    (keys | sort) == (["bucket","bucket_lookup","endpoint","mode","region","schema_version","sse_c_key_sha256","use_ssl"] | sort) and
    .schema_version == 1 and
    (.endpoint | type == "string" and length > 0) and
    (.region | type == "string" and length > 0) and
    (.bucket | type == "string" and length > 0) and
    (.use_ssl | type == "boolean") and
    (.bucket_lookup == "auto" or .bucket_lookup == "path" or .bucket_lookup == "dns") and
    (.mode == "sse-s3" or .mode == "sse-c") and
    (.sse_c_key_sha256 | type == "string") and
    (if .mode == "sse-c" then (.use_ssl == true and (.sse_c_key_sha256 | test("^[0-9a-f]{64}$")))
     else .sse_c_key_sha256 == "" end)
  ' "$storage_contract" >/dev/null || die 'Hash storage contract schema is invalid or has unknown fields'
  storage_endpoint="$(json_string "$storage_contract" '.endpoint' 'storage-contract endpoint')"
  storage_region="$(json_string "$storage_contract" '.region' 'storage-contract region')"
  storage_bucket="$(json_string "$storage_contract" '.bucket' 'storage-contract bucket')"
  storage_use_ssl="$(jq -er '.use_ssl | tostring' "$storage_contract")"
  storage_bucket_lookup="$(json_string "$storage_contract" '.bucket_lookup' 'storage-contract bucket lookup')"
  storage_mode="$(json_string "$storage_contract" '.mode' 'storage-contract encryption mode')"
  storage_sse_c_sha="$(jq -er '.sse_c_key_sha256' "$storage_contract")"
  expected_endpoint="$minio_endpoint_host:$minio_endpoint_port"
  [[ "$storage_endpoint" == "$expected_endpoint" && "$storage_bucket" == "$minio_bucket" ]] \
    || die 'Hash storage contract is not bound to the configured local MinIO endpoint and bucket'
  storage_contract_identity="$(stat_identity "$storage_contract")"
  storage_contract_sha="$(sha256_file "$storage_contract")"

  for writer in "$app_container_id" "$worker_container_id"; do
    [[ "$(container_env_value "$writer" HASH_S3_ENDPOINT 'Hash S3 endpoint')" == "$storage_endpoint" ]] \
      || die 'a Hash writer S3 endpoint does not match the immutable storage contract'
    [[ "$(container_env_value "$writer" HASH_S3_REGION 'Hash S3 region')" == "$storage_region" ]] \
      || die 'a Hash writer S3 region does not match the immutable storage contract'
    [[ "$(container_env_value "$writer" HASH_S3_BUCKET 'Hash S3 bucket')" == "$storage_bucket" ]] \
      || die 'a Hash writer S3 bucket does not match the immutable storage contract'
    [[ "$(container_env_value "$writer" HASH_S3_USE_SSL 'Hash S3 TLS selector')" == "$storage_use_ssl" ]] \
      || die 'a Hash writer S3 TLS selector does not match the immutable storage contract'
    [[ "$(container_env_value "$writer" HASH_S3_BUCKET_LOOKUP 'Hash S3 bucket lookup')" == "$storage_bucket_lookup" ]] \
      || die 'a Hash writer S3 bucket lookup does not match the immutable storage contract'
    [[ "$(container_env_value "$writer" HASH_S3_SSE_MODE 'Hash S3 encryption mode')" == "$storage_mode" ]] \
      || die 'a Hash writer S3 encryption mode does not match the immutable storage contract'
  done

  assert_shared_network_target "$minio_container_id" "$minio_network" \
    "$minio_endpoint_host" 'MinIO container'
  assert_container_exposes_port "$minio_container_id" "$minio_endpoint_port" 'MinIO container'

  app_source="$(container_json "$app_container_id" | jq -er '
    [.[0].Mounts[]? | select(.Destination == "/run/secrets/hash-s3-sse-c")] as $m |
    if ($m | length) == 0 then "" elif ($m | length) == 1 and $m[0].Type == "bind" and $m[0].RW == false
    then $m[0].Source else error("invalid SSE-C mount") end
  ')" || die 'Hash app has an invalid SSE-C key mount'
  worker_source="$(container_json "$worker_container_id" | jq -er '
    [.[0].Mounts[]? | select(.Destination == "/run/secrets/hash-s3-sse-c")] as $m |
    if ($m | length) == 0 then "" elif ($m | length) == 1 and $m[0].Type == "bind" and $m[0].RW == false
    then $m[0].Source else error("invalid SSE-C mount") end
  ')" || die 'Hash worker has an invalid SSE-C key mount'
  case "$storage_mode" in
    sse-s3)
      for writer in "$app_container_id" "$worker_container_id"; do
        [[ -z "$(container_env_value "$writer" HASH_S3_SSE_C_KEY_FILE 'Hash SSE-C key selector' true)" ]] \
          || die 'an SSE-S3 Hash writer unexpectedly selects an SSE-C key file'
      done
      [[ -z "$app_source" && -z "$worker_source" ]] \
        || die 'an SSE-S3 Hash writer unexpectedly mounts an SSE-C key source'
      sse_c_source=""
      ;;
    sse-c)
      for writer in "$app_container_id" "$worker_container_id"; do
        [[ "$(container_env_value "$writer" HASH_S3_SSE_C_KEY_FILE 'Hash SSE-C key selector')" == '/run/secrets/hash-s3-sse-c' ]] \
          || die 'an SSE-C Hash writer does not select the canonical key mount'
      done
      [[ "$app_source" == "$worker_source" && "$app_source" == "$hash_runtime_root/runtime-secrets/s3-sse-c.key" ]] \
        || die 'SSE-C Hash writers do not share the canonical host key source'
      sse_c_source="$app_source"
      require_single_link_file "$sse_c_source" 'Hash SSE-C key source'
      [[ "$(cd "$(dirname "$sse_c_source")" && pwd -P)/$(basename "$sse_c_source")" == "$sse_c_source" ]] \
        || die 'Hash SSE-C key source path must already be canonical'
      [[ "$(stat_owner "$sse_c_source")" == "$contract_owner_uid" ]] \
        || die 'Hash SSE-C key source has the wrong owner'
      [[ "$(wc -c < "$sse_c_source" | tr -d ' ')" == 32 ]] \
        || die 'Hash SSE-C key source must be exactly 32 bytes'
      [[ "$(sha256_file "$sse_c_source")" == "$storage_sse_c_sha" ]] \
        || die 'Hash SSE-C key source does not match the immutable storage contract'
      sse_c_source_identity="$(stat_identity "$sse_c_source")"
      ;;
  esac
}

validate_database_contract() {
  local probe_writers="${1:-true}" writer writer_url observed probe_output
  require_owned_private_single_link_file "$database_contract" 'Hash database contract' "$contract_owner_uid"
  jq -e '
    type == "object" and
    (keys | sort) == (["database","database_oid","host","port","schema_version","ssl_mode","system_identifier","username"] | sort) and
    .schema_version == 1 and
    (.host | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9_.-]*$")) and
    (.port | type == "number" and . >= 1 and . <= 65535 and floor == .) and
    (.database | type == "string" and test("^[A-Za-z_][A-Za-z0-9_.-]*$")) and
    (.username | type == "string" and test("^[a-z_][a-z0-9_]{0,62}$")) and
    (.ssl_mode == "disable" or .ssl_mode == "require" or
      .ssl_mode == "verify-ca" or .ssl_mode == "verify-full") and
    (.system_identifier | type == "string" and test("^[1-9][0-9]{0,19}$")) and
    (.database_oid | type == "number" and . >= 1 and . <= 4294967295 and floor == .)
  ' "$database_contract" >/dev/null || die 'Hash database contract schema is invalid or has unknown fields'
  database_contract_host="$(json_string "$database_contract" '.host' 'database-contract host')"
  database_contract_port="$(jq -er '.port' "$database_contract")"
  database_contract_database="$(json_string "$database_contract" '.database' 'database-contract database')"
  database_contract_username="$(json_string "$database_contract" '.username' 'database-contract username')"
  database_contract_ssl_mode="$(json_string "$database_contract" '.ssl_mode' 'database-contract SSL mode')"
  database_contract_system_identifier="$(json_string "$database_contract" '.system_identifier' 'database-contract system identifier')"
  database_contract_database_oid="$(jq -er '.database_oid' "$database_contract")"
  [[ "$database_contract_host" == "$postgres_host" && "$database_contract_port" == "$postgres_port" \
      && "$database_contract_database" == "$postgres_database" \
      && "$database_contract_username" == "$postgres_application_user" \
      && "$database_contract_ssl_mode" == "$postgres_ssl_mode" \
      && "$database_contract_system_identifier" == "$expected_postgres_system_identifier" \
      && "$database_contract_database_oid" == "$expected_postgres_database_oid" ]] \
    || die 'Hash database contract does not match the reviewed PostgreSQL target'

  read_database_env_source
  parse_database_url_target
  [[ "$parsed_db_username" == "$postgres_application_user" \
      && "$parsed_db_host" == "$postgres_host" && "$parsed_db_port" == "$postgres_port" \
      && "$parsed_db_database" == "$postgres_database" \
      && "$parsed_db_ssl_mode" == "$postgres_ssl_mode" ]] \
    || die 'Hash database URL is not bound to the configured local PostgreSQL target'
  for writer in "$app_container_id" "$worker_container_id"; do
    assert_no_pg_environment_overrides "$writer"
    writer_url="$(container_env_value "$writer" HASH_DB_URL 'Hash database URL')"
    [[ "$writer_url" == "$database_url" ]] \
      || die 'a Hash writer database URL does not match the canonical private runtime snapshot'
  done
  assert_shared_network_target "$postgres_container_id" "$postgres_network" \
    "$postgres_host" 'PostgreSQL container'
  assert_container_exposes_port "$postgres_container_id" "$postgres_port" 'PostgreSQL container'
  observed="$("$DOCKER" exec "$postgres_container_id" psql --no-psqlrc --no-password \
    --username "$postgres_user" --dbname "$postgres_database" --tuples-only --no-align \
    --field-separator $'\t' \
    --command 'SELECT current_database(), system_identifier::text, (SELECT oid::text FROM pg_database WHERE datname = current_database()) FROM pg_control_system()' \
    2>/dev/null | tr -d '\r' | sed '/^[[:space:]]*$/d')" \
    || die 'cannot query the configured PostgreSQL database identity'
  [[ "$observed" == "$postgres_database"$'\t'"$expected_postgres_system_identifier"$'\t'"$expected_postgres_database_oid" ]] \
    || die 'live PostgreSQL database, cluster system identifier, or database OID does not match the reviewed target'
  if [[ "$probe_writers" == true ]]; then
    for writer in "$app_container_id" "$worker_container_id"; do
      probe_output="$("$DOCKER" exec "$writer" /usr/local/bin/hash-rollback-check \
        --database-identity "$postgres_database" "$postgres_application_user" \
        "$expected_postgres_system_identifier" "$expected_postgres_database_oid" 2>/dev/null)" \
        || die 'a Hash writer could not verify its database identity through its effective DSN'
      jq -e 'type == "object" and (keys | sort) == (["complete","safe"] | sort) and
        .complete == true and .safe == true' <<<"$probe_output" >/dev/null \
        || die 'a Hash writer rejected its database identity through its effective DSN'
    done
  fi
  database_contract_identity="$(stat_identity "$database_contract")"
  database_contract_sha="$(sha256_file "$database_contract")"
}

validate_secret_sources_against_volume() {
  local index path
  for index in "${!secret_paths[@]}"; do
    path="${secret_paths[$index]}"
    require_owned_private_single_link_file "$path" "${secret_purposes[$index]} secret source" \
      "${secret_owners[$index]}"
    [[ "$(stat_identity "$path")" == "${secret_identities[$index]}" \
        && "$(sha256_file "$path")" == "${secret_sha256s[$index]}" ]] \
      || die 'a declared Hash or MinIO secret source changed after preflight'
    path_is_within "$path" "$minio_data_path" \
      && die 'a declared Hash or MinIO secret source is inside the MinIO data volume'
  done
  path_is_within "$storage_contract" "$minio_data_path" \
    && die 'Hash storage contract must not be inside the MinIO data volume'
  path_is_within "$database_contract" "$minio_data_path" \
    && die 'Hash database contract must not be inside the MinIO data volume'
  if [[ -n "$sse_c_source" ]]; then
    require_single_link_file "$sse_c_source" 'Hash SSE-C key source'
    [[ "$(stat_identity "$sse_c_source")" == "$sse_c_source_identity" \
        && "$(sha256_file "$sse_c_source")" == "$storage_sse_c_sha" ]] \
      || die 'Hash SSE-C key source changed after preflight'
    path_is_within "$sse_c_source" "$minio_data_path" \
      && die 'Hash SSE-C key source must not be inside the MinIO data volume'
  fi
}

reject_multiply_linked_minio_files() {
  local linked
  linked="$(find "$minio_data_path" -xdev -type f -links +1 -print -quit)"
  [[ -z "$linked" ]] \
    || die 'MinIO data volume contains a multiply-linked regular file; secret-safe whole-volume capture is not provable'
}

require_release_artifact() {
  local path="$1" description="$2"
  require_single_link_file "$path" "$description"
  [[ "$(stat_owner "$path")" == "$release_owner_uid" ]] \
    || die "$description must be owned by the reviewed release UID"
}

validate_current_release_selection() {
  local link_text resolved expected_text
  [[ -L "$current_symlink" ]] || die 'Hash current-release selector must be a symlink'
  link_text="$(readlink "$current_symlink")" || die 'cannot read Hash current-release selector'
  expected_text="releases/$release_commit"
  [[ "$link_text" == "$expected_text" ]] \
    || die 'Hash current-release symlink text does not select the exact manifest commit'
  resolved="$(cd "$(dirname "$current_symlink")/$(dirname "$link_text")" && pwd -P)/$(basename "$link_text")" \
    || die 'cannot resolve Hash current-release selector'
  [[ "$resolved" == "$release_dir" ]] \
    || die 'Hash current-release symlink does not resolve to the configured release directory'
  [[ "$(stat_identity "$current_symlink" true)" == "$(stat_identity "$release_dir" true)" ]] \
    || die 'Hash current-release target inode differs from the configured release directory'
  current_symlink_text="$link_text"
  current_symlink_identity="$(stat_identity "$current_symlink")"
  release_dir_identity="$(stat_identity "$release_dir" true)"
}

validate_release() {
  local manifest="$release_dir/manifest.json" archive="$release_dir/images.tar"
  local compose="$release_dir/docker-compose.yml" sse_c_compose="$release_dir/docker-compose.sse-c.yml"
  local release_env="$release_dir/release.env"
  local release_inventory release_verifier
  require_release_artifact "$manifest" 'release manifest'
  require_release_artifact "$archive" 'release images.tar'
  require_release_artifact "$compose" 'release Compose file'
  require_release_artifact "$sse_c_compose" 'release SSE-C Compose file'
  require_release_artifact "$release_env" 'release.env'
  [[ "$(jq -er '.schema_version' "$manifest")" == 4 ]] || die 'Hash release manifest schema is not supported'
  release_manifest_sha="$(sha256_file "$manifest")"
  release_commit="$(jq -er '.commit_sha' "$manifest")"
  [[ "$release_commit" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || die 'Hash release commit is invalid'
  [[ "$(basename "$release_dir")" == "$release_commit" ]] \
    || die 'Hash release directory basename does not equal the manifest commit'
  validate_current_release_selection
  release_app_image_id="$(jq -er '.app_image_id' "$manifest")"
  release_gotenberg_image_id="$(jq -er '.gotenberg_image_id' "$manifest")"
  valid_image_id "$release_app_image_id" || die 'Hash release app image ID is invalid'
  valid_image_id "$release_gotenberg_image_id" || die 'Hash release Gotenberg image ID is invalid'
  cmp -s "$release_env" <(printf 'HASH_IMAGE=%s\nHASH_GOTENBERG_IMAGE=%s\nHASH_RELEASE=%s\nHASH_ENVIRONMENT=production\n' \
    "$release_app_image_id" "$release_gotenberg_image_id" "$release_commit") \
    || die 'release.env does not match the exact release manifest'
  release_env_sha="$(sha256_file "$release_env")"
  release_archive_sha="$(jq -er '.image_archive_sha256' "$manifest")"
  release_archive_bytes="$(jq -er '.image_archive_bytes' "$manifest")"
  [[ "$release_archive_sha" =~ ^[0-9a-f]{64}$ ]] || die 'Hash release archive digest is invalid'
  [[ "$release_archive_bytes" =~ ^[1-9][0-9]*$ ]] || die 'Hash release archive size is invalid'
  [[ "$(sha256_file "$archive")" == "$release_archive_sha" ]] || die 'Hash release archive digest does not match manifest'
  [[ "$(wc -c < "$archive" | tr -d ' ')" == "$release_archive_bytes" ]] || die 'Hash release archive size does not match manifest'
  release_compose_sha="$(jq -er '.compose_sha256' "$manifest")"
  [[ "$release_compose_sha" =~ ^[0-9a-f]{64}$ ]] || die 'Hash release Compose digest is invalid'
  [[ "$(sha256_file "$compose")" == "$release_compose_sha" ]] || die 'Hash release Compose digest does not match manifest'

  [[ "$(jq -er '.sse_c_compose' "$manifest")" == 'docker-compose.sse-c.yml' ]] \
    || die 'Hash release SSE-C Compose filename is invalid'
  release_sse_c_compose_sha="$(jq -er '.sse_c_compose_sha256' "$manifest")"
  [[ "$release_sse_c_compose_sha" =~ ^[0-9a-f]{64}$ ]] || die 'Hash release SSE-C Compose digest is invalid'
  [[ "$(sha256_file "$sse_c_compose")" == "$release_sse_c_compose_sha" ]] \
    || die 'Hash release SSE-C Compose digest does not match manifest'

  [[ "$(jq -er '.recovery_inventory' "$manifest")" == 'recovery-object-inventory.sql' ]] \
    || die 'Hash release recovery inventory filename is invalid'
  release_inventory_sha="$(jq -er '.recovery_inventory_sha256' "$manifest")"
  [[ "$release_inventory_sha" =~ ^[0-9a-f]{64}$ ]] || die 'Hash release recovery inventory digest is invalid'
  release_inventory="$release_dir/recovery-object-inventory.sql"
  require_release_artifact "$release_inventory" 'release recovery inventory'
  [[ "$(sha256_file "$release_inventory")" == "$release_inventory_sha" ]] \
    || die 'release recovery inventory digest does not match manifest'
  [[ "$inventory_sql" == "$release_inventory" && "$expected_inventory_sql_sha" == "$release_inventory_sha" ]] \
    || die 'configured recovery inventory is not the release-bound artifact'

  [[ "$(jq -er '.recovery_verifier' "$manifest")" == 'verify-recovery-objects.sh' ]] \
    || die 'Hash release recovery verifier filename is invalid'
  release_verifier_sha="$(jq -er '.recovery_verifier_sha256' "$manifest")"
  [[ "$release_verifier_sha" =~ ^[0-9a-f]{64}$ ]] || die 'Hash release recovery verifier digest is invalid'
  release_verifier="$release_dir/verify-recovery-objects.sh"
  require_release_artifact "$release_verifier" 'release recovery verifier'
  [[ "$(sha256_file "$release_verifier")" == "$release_verifier_sha" ]] \
    || die 'release recovery verifier digest does not match manifest'
  [[ "$verifier_script" == "$release_verifier" && "$expected_verifier_script_sha" == "$release_verifier_sha" ]] \
    || die 'configured recovery verifier is not the release-bound artifact'
}

revalidate_release_files() {
  local manifest="$release_dir/manifest.json" link_text resolved
  [[ -d "$release_store" && ! -L "$release_store" \
      && "$(cd "$release_store" && pwd -P)" == "$release_store" ]] \
    || die 'Hash release store changed after preflight'
  [[ -d "$release_dir" && ! -L "$release_dir" \
      && "$(dirname "$release_dir")" == "$release_store" \
      && "$(basename "$release_dir")" == "$release_commit" \
      && "$(stat_identity "$release_dir" true)" == "$release_dir_identity" ]] \
    || die 'Hash release directory changed after preflight'
  [[ -L "$current_symlink" && "$(stat_identity "$current_symlink")" == "$current_symlink_identity" ]] \
    || die 'Hash current-release symlink identity changed after preflight'
  link_text="$(readlink "$current_symlink")" || die 'cannot reread Hash current-release symlink'
  [[ "$link_text" == "$current_symlink_text" && "$link_text" == "releases/$release_commit" ]] \
    || die 'Hash current-release symlink text changed after preflight'
  resolved="$(cd "$(dirname "$current_symlink")/$(dirname "$link_text")" && pwd -P)/$(basename "$link_text")" \
    || die 'cannot re-resolve Hash current-release symlink'
  [[ "$resolved" == "$release_dir" \
      && "$(stat_identity "$current_symlink" true)" == "$release_dir_identity" ]] \
    || die 'Hash current-release selector no longer resolves to the pinned release inode'
  require_release_artifact "$manifest" 'release manifest'
  [[ "$(sha256_file "$manifest")" == "$release_manifest_sha" ]] \
    || die 'Hash release manifest changed after preflight'
  require_release_artifact "$release_dir/images.tar" 'release images.tar'
  [[ "$(sha256_file "$release_dir/images.tar")" == "$release_archive_sha" ]] \
    || die 'Hash release archive changed after preflight'
  [[ "$(wc -c < "$release_dir/images.tar" | tr -d ' ')" == "$release_archive_bytes" ]] \
    || die 'Hash release archive size changed after preflight'
  require_release_artifact "$release_dir/docker-compose.yml" 'release Compose file'
  [[ "$(sha256_file "$release_dir/docker-compose.yml")" == "$release_compose_sha" ]] \
    || die 'Hash release Compose file changed after preflight'
  require_release_artifact "$release_dir/docker-compose.sse-c.yml" 'release SSE-C Compose file'
  [[ "$(sha256_file "$release_dir/docker-compose.sse-c.yml")" == "$release_sse_c_compose_sha" ]] \
    || die 'Hash release SSE-C Compose file changed after preflight'
  require_release_artifact "$release_dir/release.env" 'release.env'
  [[ "$(sha256_file "$release_dir/release.env")" == "$release_env_sha" ]] \
    || die 'Hash release environment changed after preflight'
  require_release_artifact "$inventory_sql" 'release recovery inventory'
  [[ "$(sha256_file "$inventory_sql")" == "$release_inventory_sha" ]] \
    || die 'Hash release recovery inventory changed after preflight'
  require_release_artifact "$verifier_script" 'release recovery verifier'
  [[ "$(sha256_file "$verifier_script")" == "$release_verifier_sha" ]] \
    || die 'Hash release recovery verifier changed after preflight'
}

validate_container_topology() {
  local actual_image app_release worker_release volume_mount running_consumers
  app_container_id="$(pin_container_id "$app_container" 'Hash app')"
  worker_container_id="$(pin_container_id "$worker_container" 'Hash worker')"
  gotenberg_container_id="$(pin_container_id "$gotenberg_container" 'Gotenberg')"
  postgres_container_id="$(pin_container_id "$postgres_container" 'PostgreSQL')"
  minio_container_id="$(pin_container_id "$minio_container" 'MinIO')"
  [[ "$(printf '%s\n' "$app_container_id" "$worker_container_id" "$gotenberg_container_id" \
      "$postgres_container_id" "$minio_container_id" | LC_ALL=C sort -u | wc -l | tr -d ' ')" == 5 ]] \
    || die 'all live container IDs must be distinct'

  assert_name_maps_to_id "$app_container" "$app_container_id" 'Hash app'
  assert_name_maps_to_id "$worker_container" "$worker_container_id" 'Hash worker'
  assert_name_maps_to_id "$gotenberg_container" "$gotenberg_container_id" 'Gotenberg'
  assert_name_maps_to_id "$postgres_container" "$postgres_container_id" 'PostgreSQL'
  assert_name_maps_to_id "$minio_container" "$minio_container_id" 'MinIO'

  assert_running_healthy "$app_container_id" 'Hash app'
  container_running "$worker_container_id" || die "Hash worker container is not running: $worker_container"
  assert_running_healthy "$gotenberg_container_id" 'Gotenberg'
  assert_running_healthy "$minio_container_id" 'MinIO'
  container_running "$postgres_container_id" || die "PostgreSQL container is not running: $postgres_container"

  assert_compose_identity "$app_container_id" "$app_service" 'Hash app'
  assert_compose_identity "$worker_container_id" "$worker_service" 'Hash worker'
  assert_compose_identity "$gotenberg_container_id" "$gotenberg_service" 'Gotenberg'

  actual_image="$(container_field "$app_container_id" '.Image' 'image ID')"
  [[ "$actual_image" == "$release_app_image_id" ]] || die 'running Hash app image does not match the exact release manifest'
  actual_image="$(container_field "$worker_container_id" '.Image' 'image ID')"
  [[ "$actual_image" == "$release_app_image_id" ]] || die 'running Hash worker image does not match the exact release manifest'
  actual_image="$(container_field "$gotenberg_container_id" '.Image' 'image ID')"
  [[ "$actual_image" == "$release_gotenberg_image_id" ]] || die 'running Gotenberg image does not match the exact release manifest'
  actual_image="$(container_field "$minio_container_id" '.Image' 'image ID')"
  [[ "$actual_image" == "$expected_minio_image_id" ]] || die 'running MinIO image does not match the pinned content ID'

  app_release="$(container_field "$app_container_id" '[.Config.Env[] | select(startswith("HASH_RELEASE="))][0] // "" | sub("^HASH_RELEASE="; "")' 'Hash release environment')"
  worker_release="$(container_field "$worker_container_id" '[.Config.Env[] | select(startswith("HASH_RELEASE="))][0] // "" | sub("^HASH_RELEASE="; "")' 'Hash worker release environment')"
  [[ "$app_release" == "$release_commit" && "$worker_release" == "$release_commit" ]] \
    || die 'running Hash release identity does not match the exact release manifest'

  minio_data_path="$("$DOCKER" volume inspect --format '{{.Mountpoint}}' "$minio_volume" 2>/dev/null)" \
    || die "cannot inspect MinIO volume: $minio_volume"
  [[ "$minio_data_path" == "$minio_data_path_requested" ]] \
    || die 'Docker volume mountpoint does not match the explicit MinIO data path'
  [[ -d "$minio_data_path" && ! -L "$minio_data_path" ]] || die 'MinIO data path must be a non-symlink directory'
  [[ -d "$minio_data_path/.minio.sys" && ! -L "$minio_data_path/.minio.sys" ]] \
    || die 'MinIO internal .minio.sys directory is missing or is a symlink'
  path_is_within "$state_dir" "$minio_data_path" && die 'state directory must not be inside the MinIO data volume'
  path_is_within "$minio_data_path" "$state_dir" && die 'MinIO data volume must not be inside the state directory'
  path_is_within "$release_dir" "$minio_data_path" && die 'Hash release directory must not be inside the MinIO data volume'
  path_is_within "$minio_data_path" "$release_dir" && die 'MinIO data volume must not be inside the Hash release directory'
  path_is_within "$bootstrap_estate_root" "$minio_data_path" \
    && die 'bootstrap storage-estate control artifacts must not be inside the MinIO data volume'
  path_is_within "$minio_data_path" "$bootstrap_estate_root" \
    && die 'MinIO data volume must not be inside the bootstrap storage-estate control directory'
  path_is_within "$restic_env" "$minio_data_path" \
    && die 'Restic credential file must not be inside the MinIO data volume'
  if [[ -n "$restic_temp_dir" ]]; then
    path_is_within "$restic_temp_dir" "$minio_data_path" \
      && die 'Restic temporary directory must not be inside the MinIO data volume'
    path_is_within "$minio_data_path" "$restic_temp_dir" \
      && die 'MinIO data volume must not be inside the Restic temporary directory'
  fi

  volume_mount="$(container_json "$minio_container_id" | jq -er --arg destination "$minio_mount_destination" '
    [.[0].Mounts[] | select(.Destination == $destination)] as $m |
    select($m | length == 1) | $m[0] | [.Type, (.Name // ""), .Source] | @tsv
  ')" || die 'MinIO container does not have exactly one configured data mount'
  [[ "$volume_mount" == $'volume\t'"$minio_volume"$'\t'"$minio_data_path" ]] \
    || die 'MinIO container data mount is not the exact pinned Docker volume'
  container_json "$minio_container_id" | jq -e --arg data "$minio_mount_destination" '
    .[0].Config.Cmd as $cmd |
    ($cmd | type == "array") and
    ([ $cmd[] | select(. == "server") ] | length == 1) and
    ([ $cmd[] | select(type == "string" and startswith("/")) ] == [$data]) and
    ([ $cmd[] | select(type == "string" and
        (test("^https?://") or contains("{") or contains("}"))) ] | length == 0)
  ' >/dev/null || die 'MinIO command does not prove a single local data root at the pinned mount destination'

  running_consumers="$("$DOCKER" ps --filter "volume=$minio_volume" --format '{{.Names}}' | LC_ALL=C sort)"
  [[ "$running_consumers" == "$minio_container" ]] \
    || die 'the MinIO volume has an unexpected running consumer; refuse to claim a cold snapshot'

  postgres_image_id="$(container_field "$postgres_container_id" '.Image' 'PostgreSQL image ID')"
  valid_image_id "$postgres_image_id" || die 'running PostgreSQL image ID is invalid'
  app_image_ref="$(container_field "$app_container_id" '.Config.Image' 'Hash app image reference')"
  worker_image_ref="$(container_field "$worker_container_id" '.Config.Image' 'Hash worker image reference')"
  minio_image_ref="$(container_field "$minio_container_id" '.Config.Image' 'MinIO image reference')"
  postgres_image_ref="$(container_field "$postgres_container_id" '.Config.Image' 'PostgreSQL image reference')"
  gotenberg_image_ref="$(container_field "$gotenberg_container_id" '.Config.Image' 'Gotenberg image reference')"

  [[ -d "$minio_data_path/$minio_bucket" && ! -L "$minio_data_path/$minio_bucket" ]] \
    || die 'the immutable storage-contract bucket is not present in the complete raw MinIO volume'
  validate_storage_contract
  validate_bootstrap_storage_estate
  validate_database_contract
  database_url_expected="$database_url"
  validate_secret_sources_against_volume
  path_is_within "$restic_env" "$minio_data_path" \
    && die 'Restic credential file must not be inside the MinIO data volume'
  reject_multiply_linked_minio_files
}

revalidate_runtime_bindings() {
  local phase="${1:?runtime binding phase is required}"
  local expected_storage_identity="$storage_contract_identity"
  local expected_storage_sha="$storage_contract_sha"
  local expected_database_identity="$database_contract_identity"
  local expected_database_sha="$database_contract_sha"
  local expected_database_url="$database_url_expected"
  local expected_sse_identity="${sse_c_source_identity:-}"

  [[ -n "${maintenance_lock_fd:-}" ]] \
    || die 'Hash maintenance lock is not held at a destructive boundary'
  assert_maintenance_lock_fd_identity
  validate_storage_contract
  [[ "$storage_contract_identity" == "$expected_storage_identity" \
      && "$storage_contract_sha" == "$expected_storage_sha" ]] \
    || die 'Hash storage contract changed after preflight'
  validate_bootstrap_storage_estate
  if [[ -n "$expected_sse_identity" ]]; then
    [[ "$sse_c_source_identity" == "$expected_sse_identity" ]] \
      || die 'Hash SSE-C key source identity changed after preflight'
  fi
  if [[ "$phase" == 'immediately before Restic capture' ]]; then
    validate_database_contract false
  else
    validate_database_contract true
  fi
  [[ "$database_contract_identity" == "$expected_database_identity" \
      && "$database_contract_sha" == "$expected_database_sha" \
      && "$database_url" == "$expected_database_url" ]] \
    || die 'Hash database contract or private runtime snapshot changed after preflight'
  database_url_expected="$expected_database_url"

  require_secure_file "$restic_env" 'Restic environment file'
  [[ "$(stat_identity "$restic_env")" == "$restic_env_identity" \
      && "$(sha256_file "$restic_env")" == "$restic_env_sha" ]] \
    || die 'Restic environment file changed after preflight'
  validate_secret_sources_against_volume
  [[ -d "$minio_data_path/$minio_bucket" && ! -L "$minio_data_path/$minio_bucket" ]] \
    || die 'the immutable storage-contract bucket left the raw MinIO volume after preflight'
  reject_multiply_linked_minio_files
  assert_maintenance_lock_fd_identity
}

revalidate_pinned_topology() {
  local phase="$1" actual volume_mount current_data_path running_consumers

  assert_name_maps_to_id "$app_container" "$app_container_id" 'Hash app'
  assert_name_maps_to_id "$worker_container" "$worker_container_id" 'Hash worker'
  assert_name_maps_to_id "$gotenberg_container" "$gotenberg_container_id" 'Gotenberg'
  assert_name_maps_to_id "$postgres_container" "$postgres_container_id" 'PostgreSQL'
  assert_name_maps_to_id "$minio_container" "$minio_container_id" 'MinIO'

  actual="$(container_field "$app_container_id" '.Image' 'Hash app image ID')"
  [[ "$actual" == "$release_app_image_id" ]] || die "Hash app image changed $phase"
  actual="$(container_field "$worker_container_id" '.Image' 'Hash worker image ID')"
  [[ "$actual" == "$release_app_image_id" ]] || die "Hash worker image changed $phase"
  actual="$(container_field "$gotenberg_container_id" '.Image' 'Gotenberg image ID')"
  [[ "$actual" == "$release_gotenberg_image_id" ]] || die "Gotenberg image changed $phase"
  actual="$(container_field "$postgres_container_id" '.Image' 'PostgreSQL image ID')"
  [[ "$actual" == "$postgres_image_id" ]] || die "PostgreSQL image changed $phase"
  actual="$(container_field "$minio_container_id" '.Image' 'MinIO image ID')"
  [[ "$actual" == "$expected_minio_image_id" ]] || die "MinIO image changed $phase"

  [[ "$(container_field "$app_container_id" '.Config.Image' 'Hash app image reference')" == "$app_image_ref" ]] \
    || die "Hash app image reference changed $phase"
  [[ "$(container_field "$worker_container_id" '.Config.Image' 'Hash worker image reference')" == "$worker_image_ref" ]] \
    || die "Hash worker image reference changed $phase"
  [[ "$(container_field "$gotenberg_container_id" '.Config.Image' 'Gotenberg image reference')" == "$gotenberg_image_ref" ]] \
    || die "Gotenberg image reference changed $phase"
  [[ "$(container_field "$postgres_container_id" '.Config.Image' 'PostgreSQL image reference')" == "$postgres_image_ref" ]] \
    || die "PostgreSQL image reference changed $phase"
  [[ "$(container_field "$minio_container_id" '.Config.Image' 'MinIO image reference')" == "$minio_image_ref" ]] \
    || die "MinIO image reference changed $phase"

  assert_compose_identity "$app_container_id" "$app_service" 'Hash app'
  assert_compose_identity "$worker_container_id" "$worker_service" 'Hash worker'
  assert_compose_identity "$gotenberg_container_id" "$gotenberg_service" 'Gotenberg'
  [[ "$(container_field "$app_container_id" '[.Config.Env[] | select(startswith("HASH_RELEASE="))][0] // "" | sub("^HASH_RELEASE="; "")' 'Hash release environment')" == "$release_commit" ]] \
    || die "Hash app release identity changed $phase"
  [[ "$(container_field "$worker_container_id" '[.Config.Env[] | select(startswith("HASH_RELEASE="))][0] // "" | sub("^HASH_RELEASE="; "")' 'Hash worker release environment')" == "$release_commit" ]] \
    || die "Hash worker release identity changed $phase"

  current_data_path="$("$DOCKER" volume inspect --format '{{.Mountpoint}}' "$minio_volume" 2>/dev/null)" \
    || die "cannot re-inspect MinIO volume $phase"
  [[ "$current_data_path" == "$minio_data_path" ]] || die "MinIO volume mountpoint changed $phase"
  [[ -d "$minio_data_path" && ! -L "$minio_data_path" ]] || die "MinIO data path changed type $phase"
  [[ -d "$minio_data_path/.minio.sys" && ! -L "$minio_data_path/.minio.sys" ]] \
    || die "MinIO .minio.sys changed type $phase"
  volume_mount="$(container_json "$minio_container_id" | jq -er --arg destination "$minio_mount_destination" '
    [.[0].Mounts[] | select(.Destination == $destination)] as $m |
    select($m | length == 1) | $m[0] | [.Type, (.Name // ""), .Source] | @tsv
  ')" || die "cannot revalidate the pinned MinIO data mount $phase"
  [[ "$volume_mount" == $'volume\t'"$minio_volume"$'\t'"$minio_data_path" ]] \
    || die "MinIO data mount changed $phase"

  assert_running_healthy "$gotenberg_container_id" 'Gotenberg'
  container_running "$postgres_container_id" || die "PostgreSQL is not running $phase"
  running_consumers="$("$DOCKER" ps --filter "volume=$minio_volume" --format '{{.Names}}' | LC_ALL=C sort)"
  case "$phase" in
    'immediately before quiescing'|'after cold-backup recovery')
      assert_running_healthy "$app_container_id" 'Hash app'
      if [[ "$phase" == 'after cold-backup recovery' ]]; then
        wait_running_stable "$worker_container_id" \
          || die 'Hash worker was not continuously stable before clearing the recovery sentinel'
      else
        container_running "$worker_container_id" || die "Hash worker is not running $phase"
      fi
      assert_running_healthy "$minio_container_id" 'MinIO'
      [[ "$running_consumers" == "$minio_container" ]] \
        || die "MinIO volume consumers changed $phase"
      ;;
    'immediately before Restic capture')
      ! container_running "$app_container_id" || die 'Hash app restarted before Restic capture'
      ! container_running "$worker_container_id" || die 'Hash worker restarted before Restic capture'
      ! container_running "$minio_container_id" || die 'MinIO restarted before Restic capture'
      [[ -z "$running_consumers" ]] || die 'a running container mounted the MinIO volume before Restic capture'
      ;;
    *) die "internal error: unsupported topology revalidation phase: $phase" ;;
  esac
  revalidate_runtime_bindings "$phase"
}

preflight_database_and_capacity() {
  local database_bytes minio_image_bytes postgres_image_bytes required_bytes free_kib free_bytes
  "$DOCKER" exec "$postgres_container_id" pg_dump --version >/dev/null 2>&1 \
    || die 'pg_dump is unavailable in the configured PostgreSQL container'
  database_bytes="$("$DOCKER" exec "$postgres_container_id" psql --no-psqlrc --no-password \
    --username "$postgres_user" --dbname "$postgres_database" --tuples-only --no-align \
    --command 'SELECT pg_database_size(current_database())' 2>/dev/null | tr -d '[:space:]')" \
    || die 'cannot connect to the configured Hash database with the dump role'
  [[ "$database_bytes" =~ ^[1-9][0-9]*$ ]] || die 'PostgreSQL did not return a valid non-zero database size'
  minio_image_bytes="$("$DOCKER" image inspect --format '{{.Size}}' "$expected_minio_image_id" 2>/dev/null)" \
    || die 'cannot inspect exact MinIO image size'
  postgres_image_bytes="$("$DOCKER" image inspect --format '{{.Size}}' "$postgres_image_id" 2>/dev/null)" \
    || die 'cannot inspect exact PostgreSQL image size'
  [[ "$minio_image_bytes" =~ ^[1-9][0-9]*$ && "$postgres_image_bytes" =~ ^[1-9][0-9]*$ ]] \
    || die 'Docker returned an invalid recovery image size'
  free_kib="$(df -Pk "$state_dir" | awk 'NR > 1 {free=$4} END {print free}')"
  [[ "$free_kib" =~ ^[1-9][0-9]*$ ]] || die 'cannot determine free staging capacity'
  free_bytes=$((free_kib * 1024))
  # The dump is normally compressed and Docker layers may deduplicate, but use
  # their full reported sizes plus 2 GiB working headroom before any writer is
  # stopped. Failing early is cheaper than discovering a full disk in outage.
  required_bytes=$((release_archive_bytes + minio_image_bytes + postgres_image_bytes + database_bytes + 2147483648))
  ((free_bytes >= required_bytes)) \
    || die "insufficient private staging capacity: need at least $required_bytes bytes, have $free_bytes"
}

validate_maintenance_receipt() {
  local approved_epoch now_epoch
  require_secure_file "$maintenance_receipt" 'maintenance receipt'
  jq -e '
    type == "object" and
    (keys | sort) == (["approved_at","approved_by","hash_writers_authorized_to_stop","ingress_drained","maintenance_window_id","schema_version","scope","shared_minio_consumers_quiesced"] | sort) and
    .schema_version == 1 and .scope == "hash-storagebox-cold-backup" and
    .ingress_drained == true and .hash_writers_authorized_to_stop == true and
    .shared_minio_consumers_quiesced == true and
    (.maintenance_window_id | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$")) and
    (.approved_by | type == "string" and length >= 2 and length <= 200) and
    (.approved_at | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  ' "$maintenance_receipt" >/dev/null || die 'maintenance receipt is invalid, incomplete, or has unknown fields'
  maintenance_window_id="$(jq -er '.maintenance_window_id' "$maintenance_receipt")"
  contains_control "$maintenance_window_id" && die 'maintenance-window ID contains a control character'
  approved_epoch="$(jq -er '.approved_at | fromdateiso8601' "$maintenance_receipt")" \
    || die 'maintenance approval timestamp is invalid'
  now_epoch="$(date -u +%s)"
  ((approved_epoch <= now_epoch + 300)) || die 'maintenance approval timestamp is in the future'
  ((approved_epoch >= now_epoch - 86400)) || die 'maintenance approval is older than 24 hours'
}

validate_key_escrow_receipt() {
  local purpose verified_epoch now_epoch
  require_secure_file "$key_escrow_receipt" 'key-escrow receipt'
  jq -e --arg data_repo "$repository_sha" '
    type == "object" and
    (keys | sort) == (["data_decryption_keysets_complete","data_repository_sha256","escrow_reference","escrow_system_identity_sha256","key_sets","rotation_state_reviewed","schema_version","scope","separate_failure_domain","verified_at","verified_by"] | sort) and
    .schema_version == 1 and .scope == "hash-storagebox-cold-backup-key-escrow" and
    .separate_failure_domain == true and
    .rotation_state_reviewed == true and
    .data_decryption_keysets_complete == true and
    .data_repository_sha256 == $data_repo and
    (.escrow_system_identity_sha256 | type == "string" and test("^[0-9a-f]{64}$") and . != $data_repo) and
    (.escrow_reference | type == "string" and length >= 3 and length <= 300) and
    (.verified_by | type == "string" and length >= 2 and length <= 200) and
    (.verified_at | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
    (.key_sets | type == "array" and length >= 7 and all(.[ ];
      type == "object" and (keys | sort) == (["covers_all_versions_at_snapshot","manifest_reference","purpose"] | sort) and
      .covers_all_versions_at_snapshot == true and
      (.manifest_reference | type == "string" and length >= 3 and length <= 300) and
      (.purpose | type == "string")
    ))
  ' "$key_escrow_receipt" >/dev/null || die 'key-escrow receipt is invalid, co-located, incomplete, or has unknown fields'
  verified_epoch="$(jq -er '.verified_at | fromdateiso8601' "$key_escrow_receipt")" \
    || die 'key-escrow review timestamp is invalid'
  now_epoch="$(date -u +%s)"
  ((verified_epoch <= now_epoch + 300)) || die 'key-escrow review timestamp is in the future'
  ((verified_epoch >= now_epoch - 86400)) || die 'key-escrow rotation review is older than 24 hours'
  for purpose in restic-repository-decryption minio-object-decryption \
      hash-audit-signing hash-signer-token hash-session hash-webhook-encryption hash-ai-shield; do
    [[ "$(jq -r --arg purpose "$purpose" '[.key_sets[] | select(.purpose == $purpose)] | length' "$key_escrow_receipt")" == 1 ]] \
      || die "key-escrow receipt must contain exactly one complete $purpose key-set reference"
  done
}

preflight_repository() {
  local error_file config_json
  restic_cmd backup --help 2>/dev/null | grep -Fq -- '--json' \
    || die 'installed Restic does not support JSON backup summaries'
  restic_cmd ls --help 2>/dev/null | grep -Fq -- '--recursive' \
    || die 'installed Restic does not support bounded snapshot path inspection'
  restic_cmd check --help 2>/dev/null | grep -Fq -- '--read-data-subset' \
    || die 'installed Restic does not support repository data-subset checks'
  error_file="$(mktemp "${TMPDIR:-/tmp}/hash-cold-restic-preflight.XXXXXX")"
  chmod 0600 "$error_file"
  if ! config_json="$(restic_cmd cat config 2>"$error_file")"; then
    rm -f "$error_file"
    die 'cannot authenticate to the pinned, already-initialised Storage Box Restic repository'
  fi
  rm -f "$error_file"
  restic_config_id="$(jq -er '.id | select(type == "string" and test("^[0-9a-f]{64}$"))' <<<"$config_json")" \
    || die 'Restic repository returned an invalid config identity'
  [[ "$restic_config_id" == "$expected_restic_config_id" ]] \
    || die 'authenticated Restic repository config ID does not match the pinned identity'
}

common_preflight() {
  for tool in jq awk sed grep sort find wc cp cmp mktemp stat date du df sync bash tr env readlink \
      chmod chown mkdir rm rmdir mv sleep dirname basename "$DOCKER" "$RESTIC" "$FLOCK"; do
    command -v "$tool" >/dev/null 2>&1 || die "required command not found: $tool"
  done
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    die 'sha256sum or shasum is required'
  fi
  [[ "$-" != *x* ]] || die 'shell xtrace must be disabled because subprocesses carry credentials'
  load_config
  if [[ "$mode" == backup && "$dry_run" == 0 ]]; then
    # Reject hostile pre-existing state paths before creating the shared lock,
    # then hold that lock before reading any mutable container/release state.
    validate_existing_state_layout
    acquire_maintenance_lock
    reject_stale_recovery_sentinel
  fi
  load_restic_environment
  validate_release
  validate_container_topology
  preflight_database_and_capacity
  preflight_repository
}

receipt_preflight() {
  [[ -n "$maintenance_receipt" ]] || die '--maintenance-receipt is required'
  [[ -n "$key_escrow_receipt" ]] || die '--key-escrow-receipt is required'
  require_absolute_path "$maintenance_receipt" 'maintenance receipt'
  require_absolute_path "$key_escrow_receipt" 'key-escrow receipt'
  validate_maintenance_receipt
  validate_key_escrow_receipt
}

restart_one() {
  local id="$1" name="$2" require_health="$3"
  assert_maintenance_lock_fd_identity
  if ! "$DOCKER" start "$id" >/dev/null 2>&1; then
    log "ERROR: failed to restart $name ($id)"
    return 1
  fi
  if [[ "$require_health" == true ]]; then
    if ! wait_healthy "$id"; then
      log "ERROR: $name ($id) did not become healthy after restart"
      return 1
    fi
  elif ! wait_running_stable "$id"; then
    log "ERROR: $name ($id) did not remain continuously running with a stable restart count"
    return 1
  fi
}

restart_services() {
  local failed=0
  if [[ "$minio_stopped" == 1 ]]; then
    log 'restarting MinIO before Hash writers'
    restart_one "$minio_container_id" "$minio_container" true || failed=1
    [[ "$failed" == 0 ]] && minio_stopped=0
  fi
  if [[ "$app_stopped" == 1 ]]; then
    if [[ "$failed" == 0 ]]; then
      log 'restarting Hash app'
      restart_one "$app_container_id" "$app_container" true || failed=1
      [[ "$failed" == 0 ]] && app_stopped=0
    fi
  fi
  if [[ "$worker_stopped" == 1 ]]; then
    if [[ "$failed" == 0 ]]; then
      log 'restarting Hash worker last'
      restart_one "$worker_container_id" "$worker_container" false || failed=1
      [[ "$failed" == 0 ]] && worker_stopped=0
    fi
  fi
  return "$failed"
}

safe_remove_stage() {
  [[ -n "${stage_dir:-}" && -n "${run_id:-}" ]] || return 0
  case "$stage_dir" in
    "$staging_root/$run_id") ;;
    *) log 'ERROR: refusing to remove an unexpected staging path'; return 1 ;;
  esac
  if ! validate_private_state_child "$staging_root" 'cold-backup staging directory' >/dev/null; then
    log 'ERROR: refusing cleanup because the staging root is no longer safe'
    return 1
  fi
  if ! validate_private_state_child "$stage_dir" 'cold-backup run staging directory' >/dev/null; then
    log 'ERROR: refusing cleanup because the run staging directory is no longer safe'
    return 1
  fi
  if ! require_secure_file "$stage_dir/.hash-cold-backup-owned" 'cold-backup staging ownership marker'; then
    log 'ERROR: refusing to remove staging without ownership marker'
    return 1
  fi
  rm -rf -- "$stage_dir"
}

release_lock() {
  [[ -n "${lock_dir:-}" && -n "${run_id:-}" ]] || return 0
  [[ "$lock_dir" == "$state_dir/.hash-cold-backup.lock" ]] || return 1
  validate_private_state_child "$lock_dir" 'cold-backup operator lock directory' >/dev/null || return 1
  require_secure_file "$lock_dir/run-id" 'cold-backup operator lock run ID' || return 1
  [[ "$(<"$lock_dir/run-id")" == "$run_id" ]] || return 1
  rm -f "$lock_dir/run-id"
  rmdir "$lock_dir"
}

on_exit() {
  local rc=$? cleanup_failed=0 final_rc
  trap - EXIT INT TERM
  if [[ "${minio_stopped:-0}" == 1 || "${app_stopped:-0}" == 1 || "${worker_stopped:-0}" == 1 ]]; then
    restart_services || cleanup_failed=1
  fi
  if [[ "$cleanup_failed" == 0 && "${recovery_sentinel_active:-0}" == 1 ]]; then
    # Absence of a stop flag is not enough: prove every pinned dependency is
    # back on the exact release and mount before clearing cross-workflow alarm.
    revalidate_release_files
    revalidate_pinned_topology 'after cold-backup recovery'
  fi
  if [[ "$cleanup_failed" == 1 ]]; then
    printf 'FAIL: cold-backup restart was incomplete; staging and lock retained for immediate operator action\n' >&2
    final_rc=1
  elif ! safe_remove_stage; then
    printf 'FAIL: cold-backup staging cleanup was incomplete; lock retained for operator inspection\n' >&2
    final_rc=1
  elif ! release_lock; then
    printf 'FAIL: cold-backup lock cleanup was incomplete; inspect it before retrying\n' >&2
    final_rc=1
  elif ! remove_recovery_sentinel; then
    printf 'FAIL: recovery-required sentinel could not be cleared; deployments remain blocked\n' >&2
    final_rc=1
  else
    final_rc="$rc"
  fi
  # The advisory lock remains held through every restart, cleanup, remote
  # verification, and receipt action attempted by this process.
  release_maintenance_lock
  exit "$final_rc"
}

stop_container() {
  local id="$1" role="$2" exit_code
  assert_maintenance_lock_fd_identity
  log "stopping $role"
  "$DOCKER" stop --time "$stop_timeout_seconds" "$id" >/dev/null \
    || die "failed to stop $role container"
  container_running "$id" && die "$role container is still running after stop"
  exit_code="$(container_field "$id" '.State.ExitCode' 'exit code')"
  [[ "$exit_code" == 0 ]] || die "$role did not stop gracefully (exit $exit_code)"
}

write_sanitized_receipts() {
  jq -S '{schema_version,scope,maintenance_window_id,approved_by,approved_at,
    ingress_drained,hash_writers_authorized_to_stop,shared_minio_consumers_quiesced}' \
    "$maintenance_receipt" > "$stage_dir/metadata/maintenance-receipt.json"
  jq -S '{schema_version,scope,data_repository_sha256,escrow_system_identity_sha256,
    escrow_reference,separate_failure_domain,rotation_state_reviewed,
    data_decryption_keysets_complete,verified_by,verified_at,key_sets}' \
    "$key_escrow_receipt" > "$stage_dir/metadata/key-escrow-receipt.json"
}

write_manifest() {
  local inventory_sha dump_sha inventory_sql_sha verifier_script_sha minio_archive_sha postgres_archive_sha
  local minio_kib minio_files capture_at
  inventory_sha="$(sha256_file "$stage_dir/postgresql/recovery-object-inventory.tsv")"
  dump_sha="$(sha256_file "$stage_dir/postgresql/hash.pgdump")"
  inventory_sql_sha="$(sha256_file "$inventory_sql")"
  verifier_script_sha="$(sha256_file "$verifier_script")"
  minio_archive_sha="$(sha256_file "$stage_dir/images/minio-image.tar")"
  postgres_archive_sha="$(sha256_file "$stage_dir/images/postgres-image.tar")"
  minio_kib="$(du -sk "$minio_data_path" | awk '{print $1}')"
  minio_files="$(find "$minio_data_path" -xdev -type f -print | wc -l | tr -d ' ')"
  capture_at="$(date -u +%FT%TZ)"

  jq -n \
    --arg run_id "$run_id" \
    --arg captured_at "$capture_at" \
    --arg maintenance_window_id "$maintenance_window_id" \
    --arg repository_sha256 "$repository_sha" \
    --arg restic_config_id "$restic_config_id" \
    --arg release_commit "$release_commit" \
    --arg app_image_id "$release_app_image_id" \
    --arg gotenberg_image_id "$release_gotenberg_image_id" \
    --arg gotenberg_image_ref "$gotenberg_image_ref" \
    --arg release_env_sha256 "$release_env_sha" \
    --arg minio_image_id "$expected_minio_image_id" \
    --arg minio_image_ref "$minio_image_ref" \
    --arg postgres_image_id "$postgres_image_id" \
    --arg postgres_image_ref "$postgres_image_ref" \
    --arg postgres_database "$postgres_database" \
    --arg postgres_username "$postgres_application_user" \
    --arg postgres_host "$postgres_host" \
    --argjson postgres_port "$postgres_port" \
    --arg postgres_network "$postgres_network" \
    --arg postgres_system_identifier "$expected_postgres_system_identifier" \
    --arg postgres_ssl_mode "$postgres_ssl_mode" \
    --argjson postgres_database_oid "$expected_postgres_database_oid" \
    --arg database_contract_sha256 "$database_contract_sha" \
    --arg minio_volume "$minio_volume" \
    --arg minio_data_path "$minio_data_path" \
    --arg minio_endpoint "$storage_endpoint" \
    --arg minio_network "$minio_network" \
    --arg minio_bucket "$minio_bucket" \
    --arg storage_contract_sha256 "$storage_contract_sha" \
    --arg bootstrap_estate_root "$bootstrap_estate_root" \
    --arg bootstrap_estate_root_identity "$expected_bootstrap_estate_root_identity" \
    --arg bootstrap_estate_intent "$bootstrap_estate_intent" \
    --arg bootstrap_estate_intent_identity "$expected_bootstrap_estate_intent_identity" \
    --arg bootstrap_estate_intent_sha256 "$expected_bootstrap_estate_intent_sha" \
    --arg bootstrap_estate_receipt_dir "$bootstrap_estate_receipt_dir" \
    --arg bootstrap_estate_receipt_dir_identity "$expected_bootstrap_estate_receipt_dir_identity" \
    --arg bootstrap_estate_receipt "$bootstrap_estate_receipt" \
    --arg bootstrap_estate_receipt_identity "$expected_bootstrap_estate_receipt_identity" \
    --arg bootstrap_estate_receipt_sha256 "$expected_bootstrap_estate_receipt_sha" \
    --arg bootstrap_marker_key "$bootstrap_marker_key" \
    --arg bootstrap_marker_version_id "$bootstrap_marker_version_id" \
    --arg bootstrap_marker_sha256 "$bootstrap_marker_sha" \
    --arg bootstrap_marker_retain_until "$bootstrap_marker_retain_until" \
    --argjson bootstrap_estate_owner_uid "$bootstrap_estate_owner_uid" \
    --arg inventory_sha256 "$inventory_sha" \
    --arg dump_sha256 "$dump_sha" \
    --arg inventory_sql_sha256 "$inventory_sql_sha" \
    --arg verifier_script_sha256 "$verifier_script_sha" \
    --arg minio_archive_sha256 "$minio_archive_sha" \
    --arg postgres_archive_sha256 "$postgres_archive_sha" \
    --argjson minio_kib "$minio_kib" \
    --argjson minio_files "$minio_files" \
    '{schema_version:2,workflow:"hash-storagebox-cold-backup-v2",run_id:$run_id,
      captured_at:$captured_at,maintenance_window_id:$maintenance_window_id,
      backup:{provider:"hetzner-storage-box",transport:"restic-sftp",
        repository_sha256:$repository_sha256,restic_config_id:$restic_config_id,
        whole_minio_volume:true,exclusions:[]},
      release:{commit_sha:$release_commit,app_image_id:$app_image_id,
        gotenberg_image_id:$gotenberg_image_id,gotenberg_image_ref:$gotenberg_image_ref,
        release_env_sha256:$release_env_sha256},
      postgres:{host:$postgres_host,port:$postgres_port,database:$postgres_database,
        username:$postgres_username,
        network:$postgres_network,ssl_mode:$postgres_ssl_mode,
        system_identifier:$postgres_system_identifier,database_oid:$postgres_database_oid,
        contract_sha256:$database_contract_sha256,image_id:$postgres_image_id,
        image_ref:$postgres_image_ref,dump_sha256:$dump_sha256,
        inventory_sha256:$inventory_sha256,inventory_sql_sha256:$inventory_sql_sha256,
        verifier_script_sha256:$verifier_script_sha256},
      minio:{endpoint:$minio_endpoint,network:$minio_network,bucket:$minio_bucket,
        storage_contract_sha256:$storage_contract_sha256,
        volume:$minio_volume,data_path:$minio_data_path,image_id:$minio_image_id,
        image_ref:$minio_image_ref,image_archive_sha256:$minio_archive_sha256,
        data_kib:$minio_kib,file_count:$minio_files,minio_sys_present:true},
      bootstrap_storage_estate:{owner_uid:$bootstrap_estate_owner_uid,
        root:{source_path:$bootstrap_estate_root,
          source_identity:$bootstrap_estate_root_identity},
        intent:{source_path:$bootstrap_estate_intent,
          source_identity:$bootstrap_estate_intent_identity,
          sha256:$bootstrap_estate_intent_sha256,
          snapshot_path:"bootstrap-storage-estate/intent.json"},
        receipt_dir:{source_path:$bootstrap_estate_receipt_dir,
          source_identity:$bootstrap_estate_receipt_dir_identity},
        receipt:{source_path:$bootstrap_estate_receipt,
          source_identity:$bootstrap_estate_receipt_identity,
          sha256:$bootstrap_estate_receipt_sha256,
          snapshot_path:"bootstrap-storage-estate/receipt/receipt.json"},
        marker_key:$bootstrap_marker_key,marker_version_id:$bootstrap_marker_version_id,
        marker_sha256:$bootstrap_marker_sha256,
        marker_retain_until:$bootstrap_marker_retain_until},
      recovery_images:{postgres_archive_sha256:$postgres_archive_sha256},
      keys:{material_in_snapshot:false,receipt:"metadata/key-escrow-receipt.json"}}' \
    > "$stage_dir/metadata/backup-manifest.json"
}

write_checksums() {
  (
    cd "$stage_dir"
    while IFS= read -r -d '' file; do
      printf '%s  %s\n' "$(sha256_file "$file")" "${file#./}"
    done < <(find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z)
  ) > "$stage_dir/SHA256SUMS"
}

verify_snapshot_path() {
  local snapshot="$1" path="$2" output error
  output="$(mktemp "${TMPDIR:-/tmp}/hash-cold-restic-ls.XXXXXX")"
  error="$(mktemp "${TMPDIR:-/tmp}/hash-cold-restic-ls-error.XXXXXX")"
  chmod 0600 "$output" "$error"
  if ! restic_cmd ls --json --recursive=false "$snapshot" "$path" >"$output" 2>"$error"; then
    rm -f "$output" "$error"
    die 'Restic could not read the newly-created snapshot'
  fi
  if ! jq -s -e --arg path "$path" '
      any(.[]; .struct_type == "node" and ((.path | ltrimstr("/")) == ($path | ltrimstr("/"))))
    ' "$output" >/dev/null; then
    rm -f "$output" "$error"
    die "new Restic snapshot is missing required path: $path"
  fi
  rm -f "$output" "$error"
}

run_backup() {
  local archive_file error_file snapshot_id restic_rc receipt_tmp
  run_id="hash-cold-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  prepare_state_layout
  lock_dir="$state_dir/.hash-cold-backup.lock"
  if ! mkdir -m 0700 "$lock_dir" 2>/dev/null; then
    die "another cold backup may be active; inspect this lock before removing it: $lock_dir"
  fi
  validate_private_state_child "$lock_dir" 'cold-backup operator lock directory' >/dev/null
  printf '%s\n' "$run_id" > "$lock_dir/run-id"
  chmod 0600 "$lock_dir/run-id"
  require_secure_file "$lock_dir/run-id" 'cold-backup operator lock run ID'
  trap on_exit EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  # From this point onward, SIGKILL or host loss leaves a canonical alarm that
  # deployment workflows can see even though state_dir is operator-selected.
  create_recovery_sentinel

  stage_dir="$staging_root/$run_id"
  mkdir -m 0700 "$stage_dir"
  validate_private_state_child "$stage_dir" 'cold-backup run staging directory' >/dev/null
  : > "$stage_dir/.hash-cold-backup-owned"
  chmod 0600 "$stage_dir/.hash-cold-backup-owned"
  mkdir -m 0700 "$stage_dir/postgresql" "$stage_dir/minio" "$stage_dir/images" \
    "$stage_dir/release" "$stage_dir/metadata" "$stage_dir/tools" \
    "$stage_dir/tools/scripts" "$stage_dir/tools/ops" \
    "$stage_dir/bootstrap-storage-estate" "$stage_dir/bootstrap-storage-estate/receipt"
  validate_private_state_child "$stage_dir" 'cold-backup run staging directory' >/dev/null
  write_sanitized_receipts
  cp "$storage_contract" "$stage_dir/metadata/storage-contract.json"
  cp "$database_contract" "$stage_dir/metadata/database-contract.json"
  cp "$bootstrap_estate_intent" "$stage_dir/bootstrap-storage-estate/intent.json"
  cp "$bootstrap_estate_receipt" "$stage_dir/bootstrap-storage-estate/receipt/receipt.json"
  [[ "$(sha256_file "$stage_dir/metadata/storage-contract.json")" == "$storage_contract_sha" ]] \
    || die 'Hash storage contract changed during staging'
  [[ "$(sha256_file "$stage_dir/metadata/database-contract.json")" == "$database_contract_sha" ]] \
    || die 'Hash database contract changed during staging'
  [[ "$(sha256_file "$stage_dir/bootstrap-storage-estate/intent.json")" == "$expected_bootstrap_estate_intent_sha" \
      && "$(sha256_file "$stage_dir/bootstrap-storage-estate/receipt/receipt.json")" == "$expected_bootstrap_estate_receipt_sha" ]] \
    || die 'bootstrap storage-estate artifacts changed during staging'

  # Archive exact recovery images before downtime. Hash/Gotenberg already ship
  # as the manifest-bound release archive; MinIO and PostgreSQL are saved by
  # exact local content ID so a Storage-Box-only drill never pulls a mutable tag.
  log 'staging exact release and recovery images before maintenance begins'
  cp "$release_dir/manifest.json" "$stage_dir/release/manifest.json"
  cp "$release_dir/release.env" "$stage_dir/release/release.env"
  cp "$release_dir/docker-compose.yml" "$stage_dir/release/docker-compose.yml"
  cp "$release_dir/docker-compose.sse-c.yml" "$stage_dir/release/docker-compose.sse-c.yml"
  cp "$release_dir/images.tar" "$stage_dir/release/images.tar"
  cp "$inventory_sql" "$stage_dir/tools/ops/recovery-object-inventory.sql"
  cp "$verifier_script" "$stage_dir/tools/scripts/verify-recovery-objects.sh"
  [[ "$(sha256_file "$stage_dir/release/manifest.json")" == "$release_manifest_sha" ]] \
    || die 'Hash release manifest changed during staging'
  [[ "$(sha256_file "$stage_dir/release/release.env")" == "$release_env_sha" ]] \
    || die 'Hash release environment changed during copy'
  [[ "$(sha256_file "$stage_dir/release/images.tar")" == "$(jq -er '.image_archive_sha256' "$stage_dir/release/manifest.json")" ]] \
    || die 'staged Hash release archive digest changed during copy'
  [[ "$(sha256_file "$stage_dir/release/docker-compose.yml")" == "$(jq -er '.compose_sha256' "$stage_dir/release/manifest.json")" ]] \
    || die 'staged Hash release Compose digest changed during copy'
  [[ "$(sha256_file "$stage_dir/release/docker-compose.sse-c.yml")" == "$(jq -er '.sse_c_compose_sha256' "$stage_dir/release/manifest.json")" ]] \
    || die 'staged Hash release SSE-C Compose digest changed during copy'
  [[ "$(sha256_file "$stage_dir/tools/ops/recovery-object-inventory.sql")" == "$expected_inventory_sql_sha" ]] \
    || die 'canonical inventory SQL changed during staging'
  [[ "$(sha256_file "$stage_dir/tools/scripts/verify-recovery-objects.sh")" == "$expected_verifier_script_sha" ]] \
    || die 'canonical recovery verifier changed during staging'
  "$DOCKER" image save --output "$stage_dir/images/minio-image.tar" "$expected_minio_image_id" \
    >/dev/null || die 'failed to archive exact MinIO image'
  "$DOCKER" image save --output "$stage_dir/images/postgres-image.tar" "$postgres_image_id" \
    >/dev/null || die 'failed to archive exact PostgreSQL image'
  [[ -s "$stage_dir/images/minio-image.tar" && -s "$stage_dir/images/postgres-image.tar" ]] \
    || die 'one or more recovery image archives are empty'

  revalidate_release_files
  revalidate_pinned_topology 'immediately before quiescing'

  worker_stopped=1
  stop_container "$worker_container_id" 'Hash worker'
  app_stopped=1
  stop_container "$app_container_id" 'Hash app'

  log 'capturing canonical inventory and PostgreSQL dump while Hash writers are stopped'
  "$DOCKER" exec -i "$postgres_container_id" psql --no-psqlrc --no-password \
    --username "$postgres_user" --dbname "$postgres_database" --set ON_ERROR_STOP=1 \
    --tuples-only --no-align --field-separator $'\t' --pset footer=off \
    < "$inventory_sql" > "$stage_dir/postgresql/recovery-object-inventory.before.tsv" \
    || die 'failed to capture pre-dump canonical object inventory'
  "$DOCKER" exec "$postgres_container_id" pg_dump --no-password \
    --username "$postgres_user" --dbname "$postgres_database" --format=custom \
    --compress=9 --no-owner --no-acl \
    > "$stage_dir/postgresql/hash.pgdump" \
    || die 'PostgreSQL dump failed'
  [[ -s "$stage_dir/postgresql/hash.pgdump" ]] || die 'PostgreSQL dump is empty'
  "$DOCKER" exec -i "$postgres_container_id" psql --no-psqlrc --no-password \
    --username "$postgres_user" --dbname "$postgres_database" --set ON_ERROR_STOP=1 \
    --tuples-only --no-align --field-separator $'\t' --pset footer=off \
    < "$inventory_sql" > "$stage_dir/postgresql/recovery-object-inventory.tsv" \
    || die 'failed to capture post-dump canonical object inventory'
  cmp -s "$stage_dir/postgresql/recovery-object-inventory.before.tsv" \
    "$stage_dir/postgresql/recovery-object-inventory.tsv" \
    || die 'canonical object inventory changed during dump; recovery point is not coordinated'
  rm -f "$stage_dir/postgresql/recovery-object-inventory.before.tsv"

  minio_stopped=1
  stop_container "$minio_container_id" 'MinIO'
  [[ -z "$("$DOCKER" ps --filter "volume=$minio_volume" --format '{{.Names}}')" ]] \
    || die 'a running container still mounts the MinIO volume after shutdown'
  sync
  [[ -d "$minio_data_path/.minio.sys" ]] || die '.minio.sys disappeared after MinIO shutdown'

  # This marker makes the relationship explicit inside the snapshot. The data
  # directory itself is passed as a second Restic root; it is not copied,
  # mirrored, mounted elsewhere, or filtered.
  jq -n --arg volume "$minio_volume" --arg data_path "$minio_data_path" \
    '{schema_version:1,volume:$volume,data_path:$data_path,whole_volume:true,
      includes_minio_sys:true,exclusions:[]}' > "$stage_dir/minio/whole-volume-source.json"
  write_manifest
  write_checksums

  validate_private_state_child "$stage_dir" 'cold-backup run staging directory' >/dev/null
  receipts_dir="$(validate_private_state_child "$receipts_dir" 'cold-backup receipts directory')"
  archive_file="$receipts_dir/$run_id.restic.jsonl"
  error_file="$receipts_dir/$run_id.restic.stderr"
  : > "$archive_file"
  : > "$error_file"
  chmod 0600 "$archive_file" "$error_file"

  # These are the final live-identity reads before the snapshot call. Any
  # cooperative deployment is excluded by the shared flock; any uncooperative
  # name replacement, image/release drift, or mount swap fails before Restic.
  revalidate_release_files
  revalidate_pinned_topology 'immediately before Restic capture'
  log 'writing one coordinated PostgreSQL + complete MinIO-volume Restic snapshot'
  set +e
  restic_cmd backup --json --host "$restic_host" \
    --tag hash-cold-backup --tag "release:$release_commit" \
    --tag "maintenance:$maintenance_window_id" --tag "run:$run_id" \
    "$stage_dir" "$minio_data_path" > "$archive_file" 2> "$error_file"
  restic_rc=$?
  set -e
  ((restic_rc == 0)) \
    || die "Restic backup failed; private diagnostics retained under $receipts_dir/$run_id.restic.*"
  snapshot_id="$(jq -sr '[.[] | select(.message_type == "summary") | .snapshot_id] | last // empty' "$archive_file")"
  [[ "$snapshot_id" =~ ^[0-9a-f]{64}$ ]] || die 'Restic backup did not return a full snapshot ID'

  # The immutable point already exists remotely. Restore availability promptly,
  # then verify the remote snapshot and repository while Hash is online again.
  restart_services || die 'services did not recover after the cold capture'

  verify_snapshot_path "$snapshot_id" "$stage_dir/metadata/backup-manifest.json"
  verify_snapshot_path "$snapshot_id" "$stage_dir/metadata/storage-contract.json"
  verify_snapshot_path "$snapshot_id" "$stage_dir/metadata/database-contract.json"
  verify_snapshot_path "$snapshot_id" "$stage_dir/bootstrap-storage-estate/intent.json"
  verify_snapshot_path "$snapshot_id" "$stage_dir/bootstrap-storage-estate/receipt/receipt.json"
  verify_snapshot_path "$snapshot_id" "$stage_dir/postgresql/hash.pgdump"
  verify_snapshot_path "$snapshot_id" "$stage_dir/postgresql/recovery-object-inventory.tsv"
  verify_snapshot_path "$snapshot_id" "$stage_dir/release/images.tar"
  verify_snapshot_path "$snapshot_id" "$stage_dir/release/release.env"
  verify_snapshot_path "$snapshot_id" "$stage_dir/release/docker-compose.sse-c.yml"
  verify_snapshot_path "$snapshot_id" "$stage_dir/images/minio-image.tar"
  verify_snapshot_path "$snapshot_id" "$stage_dir/tools/scripts/verify-recovery-objects.sh"
  verify_snapshot_path "$snapshot_id" "$stage_dir/tools/ops/recovery-object-inventory.sql"
  verify_snapshot_path "$snapshot_id" "$minio_data_path/.minio.sys"

  log "checking $integrity_subset of the Storage Box repository"
  restic_cmd check --read-data-subset="$integrity_subset" >/dev/null 2>&1 \
    || die 'Restic repository integrity check failed'

  receipts_dir="$(validate_private_state_child "$receipts_dir" 'cold-backup receipts directory')"
  receipt_tmp="$receipts_dir/.$run_id.receipt.tmp"
  jq -n --arg run_id "$run_id" --arg snapshot_id "$snapshot_id" \
    --arg repository_sha256 "$repository_sha" --arg restic_config_id "$restic_config_id" \
    --arg release_commit "$release_commit" --arg completed_at "$(date -u +%FT%TZ)" \
    --arg maintenance_window_id "$maintenance_window_id" \
    --arg bootstrap_estate_root "$bootstrap_estate_root" \
    --arg bootstrap_estate_root_identity "$expected_bootstrap_estate_root_identity" \
    --arg bootstrap_estate_intent "$bootstrap_estate_intent" \
    --arg bootstrap_estate_intent_identity "$expected_bootstrap_estate_intent_identity" \
    --arg bootstrap_estate_intent_sha256 "$expected_bootstrap_estate_intent_sha" \
    --arg bootstrap_estate_receipt_dir "$bootstrap_estate_receipt_dir" \
    --arg bootstrap_estate_receipt_dir_identity "$expected_bootstrap_estate_receipt_dir_identity" \
    --arg bootstrap_estate_receipt "$bootstrap_estate_receipt" \
    --arg bootstrap_estate_receipt_identity "$expected_bootstrap_estate_receipt_identity" \
    --arg bootstrap_estate_receipt_sha256 "$expected_bootstrap_estate_receipt_sha" \
    --arg bootstrap_marker_key "$bootstrap_marker_key" \
    --arg bootstrap_marker_version_id "$bootstrap_marker_version_id" \
    --arg bootstrap_marker_sha256 "$bootstrap_marker_sha" \
    --arg bootstrap_marker_retain_until "$bootstrap_marker_retain_until" \
    --argjson bootstrap_estate_owner_uid "$bootstrap_estate_owner_uid" \
      '{schema_version:2,status:"capture-uploaded-subset-checked",run_id:$run_id,snapshot_id:$snapshot_id,
      repository_sha256:$repository_sha256,restic_config_id:$restic_config_id,
      release_commit:$release_commit,maintenance_window_id:$maintenance_window_id,
      bootstrap_storage_estate:{owner_uid:$bootstrap_estate_owner_uid,
        root_path:$bootstrap_estate_root,root_identity:$bootstrap_estate_root_identity,
        intent_path:$bootstrap_estate_intent,intent_identity:$bootstrap_estate_intent_identity,
        intent_sha256:$bootstrap_estate_intent_sha256,
        receipt_dir_path:$bootstrap_estate_receipt_dir,
        receipt_dir_identity:$bootstrap_estate_receipt_dir_identity,
        receipt_path:$bootstrap_estate_receipt,receipt_identity:$bootstrap_estate_receipt_identity,
        receipt_sha256:$bootstrap_estate_receipt_sha256,
        marker_key:$bootstrap_marker_key,marker_version_id:$bootstrap_marker_version_id,
        marker_sha256:$bootstrap_marker_sha256,
        marker_retain_until:$bootstrap_marker_retain_until},
      whole_minio_volume:true,minio_sys_verified_in_snapshot:true,
      services_restarted:true,repository_subset_check_passed:true,
      exact_snapshot_readback_verified:false,isolated_restore_required:true,
      completed_at:$completed_at}' \
    > "$receipt_tmp"
  chmod 0600 "$receipt_tmp"
  mv "$receipt_tmp" "$receipts_dir/$run_id.receipt.json"
  rm -f "$archive_file" "$error_file"
  log "cold snapshot uploaded and repository subset check complete; isolated restore remains required: snapshot $snapshot_id"
}

show_status() {
  local snapshots newest count
  snapshots="$(restic_cmd snapshots --json --tag hash-cold-backup 2>/dev/null)" \
    || die 'cannot list Hash cold-backup snapshots from the pinned repository'
  count="$(jq -er 'length' <<<"$snapshots")"
  newest="$(jq -r 'sort_by(.time) | last | if . == null then "none" else (.short_id // (.id[0:8])) + " " + .time end' <<<"$snapshots")"
  printf 'Hash release: %s\n' "$release_commit"
  printf 'Hash image: %s\n' "$release_app_image_id"
  printf 'Gotenberg image: %s\n' "$release_gotenberg_image_id"
  printf 'MinIO image: %s\n' "$expected_minio_image_id"
  printf 'MinIO volume: %s (complete volume; no excludes)\n' "$minio_volume"
  printf 'Bootstrap storage-estate marker SHA-256: %s\n' "$bootstrap_marker_sha"
  printf 'Storage Box repository SHA-256: %s\n' "$repository_sha"
  printf 'Restic repository config ID: %s\n' "$restic_config_id"
  printf 'Tagged cold snapshots (restore-drill status not implied): %s; newest: %s\n' "$count" "$newest"
}

mode="${1:-}"
[[ -n "$mode" ]] || { usage; exit 2; }
shift || true
config_file=""
maintenance_receipt=""
key_escrow_receipt=""
dry_run=0
while (($# > 0)); do
  case "$1" in
    --config) (($# >= 2)) || die '--config requires a file'; config_file="$2"; shift 2 ;;
    --maintenance-receipt) (($# >= 2)) || die '--maintenance-receipt requires a file'; maintenance_receipt="$2"; shift 2 ;;
    --key-escrow-receipt) (($# >= 2)) || die '--key-escrow-receipt requires a file'; key_escrow_receipt="$2"; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ -n "$config_file" ]] || die '--config is required'
require_absolute_path "$config_file" 'cold-backup configuration'

DOCKER="$(command -v docker || true)"
RESTIC="$(command -v restic || true)"
FLOCK="$(command -v flock || true)"
[[ -n "$DOCKER" ]] || die 'required command not found: docker'
[[ -n "$RESTIC" ]] || die 'required command not found: restic'
[[ -n "$FLOCK" ]] || die 'required command not found: flock'

if [[ -n "${HASH_COLD_BACKUP_HERMETIC_ROOT:-}" ]]; then
  require_absolute_path "$HASH_COLD_BACKUP_HERMETIC_ROOT" 'hermetic test root'
  require_secure_dir "$HASH_COLD_BACKUP_HERMETIC_ROOT" 'hermetic test root'
  hermetic_root="$(cd "$HASH_COLD_BACKUP_HERMETIC_ROOT" && pwd -P)"
  for tool_path in "$DOCKER" "$RESTIC" "$FLOCK"; do
    path_is_within "$tool_path" "$hermetic_root/bin" \
      || die 'hermetic lock override requires all intercepted tools under its private bin directory'
  done
  hash_runtime_root="$hermetic_root/opt/hash"
  maintenance_lock_file="$hermetic_root/opt/hash-lock/maintenance.lock"
  recovery_sentinel_file="$hash_runtime_root/.cold-backup-recovery-required"
  maintenance_lock_expected_uid="$(id -u)"
  maintenance_lock_parent_expected_uid="$(id -u)"
  maintenance_lock_parent_expected_mode=755
else
  hash_runtime_root='/opt/hash'
  maintenance_lock_file='/opt/hash-lock/maintenance.lock'
  recovery_sentinel_file='/opt/hash/.cold-backup-recovery-required'
  maintenance_lock_expected_uid=1000
  maintenance_lock_parent_expected_uid=0
  maintenance_lock_parent_expected_mode=755
fi
maintenance_lock_fd=""
recovery_sentinel_active=0

worker_stopped=0
app_stopped=0
minio_stopped=0
stage_dir=""
staging_root=""
receipts_dir=""
lock_dir=""
run_id=""

case "$mode" in
  status)
    ((dry_run == 0)) || die '--dry-run is valid only with backup'
    [[ -z "$maintenance_receipt" && -z "$key_escrow_receipt" ]] \
      || die 'status does not accept maintenance or key-escrow receipts'
    common_preflight
    show_status
    ;;
  preflight)
    ((dry_run == 0)) || die '--dry-run is valid only with backup'
    common_preflight
    receipt_preflight
    log 'preflight PASS: exact release/topology, Storage Box repository, maintenance, and separate key escrow verified'
    ;;
  backup)
    common_preflight
    receipt_preflight
    if ((dry_run == 1)); then
      log 'dry run PASS; no container was stopped and no snapshot was written'
      printf 'Would stop: %s, then %s, then %s\n' "$worker_container" "$app_container" "$minio_container"
      printf 'Would capture one snapshot root set: private staging data + complete %s\n' "$minio_data_path"
      printf 'Would restart: %s, then %s, then %s\n' "$minio_container" "$app_container" "$worker_container"
      exit 0
    fi
    run_backup
    ;;
  *) usage; exit 2 ;;
esac
