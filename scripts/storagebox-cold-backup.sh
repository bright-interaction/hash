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
`backup` refuses to run without two non-secret receipts: a current maintenance
approval and proof that the required recovery keys are escrowed somewhere other
than the data-backup repository. No secret value is copied into the snapshot or
printed.

This script always snapshots the COMPLETE MinIO volume, including `.minio.sys`.
It offers no exclude flag. Storage Box is backup/DR only, never Hash's S3
endpoint or MinIO data mount.
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

require_secure_file() {
  local path="$1" description="$2" mode owner current_uid
  [[ -f "$path" && ! -L "$path" ]] || die "$description must be a regular non-symlink file: $path"
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

load_config() {
  require_secure_file "$config_file" 'cold-backup configuration'
  jq -e '
    type == "object" and
    (keys | sort) == (["compose","containers","inventory_sql","inventory_sql_sha256","minio","postgres","release_dir","restic","schema_version","state_dir","verifier_script","verifier_script_sha256"] | sort) and
    .schema_version == 1 and
    (.compose | type == "object" and (keys | sort) == (["app_service","gotenberg_service","project","worker_service"] | sort)) and
    (.containers | type == "object" and (keys | sort) == (["app","gotenberg","minio","postgres","worker"] | sort)) and
    (.postgres | type == "object" and (keys | sort) == (["database","user"] | sort)) and
    (.minio | type == "object" and (keys | sort) == (["data_path","expected_image_id","mount_destination","volume"] | sort)) and
    (.restic | type == "object" and (keys | sort) == (["config_id","env_file","health_timeout_seconds","host","integrity_subset","password_variable","repository_sha256","repository_variable","stop_timeout_seconds"] | sort))
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
  minio_volume="$(json_string "$config_file" '.minio.volume' 'MinIO volume')"
  minio_data_path_requested="$(json_string "$config_file" '.minio.data_path' 'MinIO data path')"
  minio_mount_destination="$(json_string "$config_file" '.minio.mount_destination' 'MinIO mount destination')"
  expected_minio_image_id="$(json_string "$config_file" '.minio.expected_image_id' 'expected MinIO image ID')"
  release_dir_requested="$(json_string "$config_file" '.release_dir' 'Hash release directory')"
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

  for name in "$compose_project" "$app_service" "$worker_service" "$gotenberg_service" \
      "$app_container" "$worker_container" "$gotenberg_container" "$postgres_container" \
      "$minio_container" "$minio_volume" "$restic_host"; do
    valid_name "$name" || die "invalid container/service/host identifier in configuration: $name"
  done
  [[ "$(printf '%s\n' "$app_service" "$worker_service" "$gotenberg_service" | LC_ALL=C sort -u | wc -l | tr -d ' ')" == 3 ]] \
    || die 'Hash app, worker, and Gotenberg service identities must be distinct'
  [[ "$(printf '%s\n' "$app_container" "$worker_container" "$gotenberg_container" "$postgres_container" "$minio_container" | LC_ALL=C sort -u | wc -l | tr -d ' ')" == 5 ]] \
    || die 'all configured container identities must be distinct'
  valid_db_identifier "$postgres_database" || die 'invalid PostgreSQL database identifier'
  valid_db_identifier "$postgres_user" || die 'invalid PostgreSQL user identifier'
  valid_image_id "$expected_minio_image_id" || die 'expected MinIO image must be a full sha256 content ID'
  [[ "$expected_repository_sha" =~ ^[0-9a-f]{64}$ ]] || die 'Restic repository fingerprint must be 64 lowercase hex characters'
  [[ "$expected_restic_config_id" =~ ^[0-9a-f]{64}$ ]] || die 'Restic config identity must be 64 lowercase hex characters'
  [[ "$expected_inventory_sql_sha" =~ ^[0-9a-f]{64}$ ]] || die 'canonical inventory SQL digest must be 64 lowercase hex characters'
  [[ "$expected_verifier_script_sha" =~ ^[0-9a-f]{64}$ ]] || die 'canonical recovery verifier digest must be 64 lowercase hex characters'
  [[ "$integrity_subset" =~ ^([1-9][0-9]?|100)%$ ]] || die 'Restic integrity subset must be 1% through 100%'
  case "$restic_repository_variable:$restic_password_variable" in
    RESTIC_REPOSITORY:RESTIC_PASSWORD|OFFSITE_RESTIC_REPOSITORY:OFFSITE_RESTIC_PASSWORD) ;;
    *) die 'Restic variable names must select a matching RESTIC_* or OFFSITE_RESTIC_* pair' ;;
  esac

  require_absolute_path "$release_dir_requested" 'Hash release directory'
  require_absolute_path "$inventory_sql_requested" 'canonical inventory SQL'
  require_absolute_path "$verifier_script_requested" 'canonical recovery verifier'
  require_absolute_path "$state_dir_requested" 'cold-backup state directory'
  require_absolute_path "$restic_env" 'Restic environment file'
  require_absolute_path "$minio_data_path_requested" 'MinIO data path'
  require_absolute_path "$minio_mount_destination" 'MinIO mount destination'

  [[ -d "$release_dir_requested" ]] || die 'Hash release directory does not exist'
  release_dir="$(cd "$release_dir_requested" && pwd -P)"
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
  restic_env="$(cd "$(dirname "$restic_env")" && pwd -P)/$(basename "$restic_env")"

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

validate_release() {
  local manifest="$release_dir/manifest.json" archive="$release_dir/images.tar"
  local compose="$release_dir/docker-compose.yml" archive_sha compose_sha
  [[ -f "$manifest" && ! -L "$manifest" ]] || die 'release manifest must be a regular non-symlink file'
  [[ -f "$archive" && ! -L "$archive" ]] || die 'release images.tar must be a regular non-symlink file'
  [[ -f "$compose" && ! -L "$compose" ]] || die 'release Compose file must be a regular non-symlink file'
  [[ "$(jq -er '.schema_version' "$manifest")" == 3 ]] || die 'Hash release manifest schema is not supported'
  release_manifest_sha="$(sha256_file "$manifest")"
  release_commit="$(jq -er '.commit_sha' "$manifest")"
  [[ "$release_commit" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || die 'Hash release commit is invalid'
  release_app_image_id="$(jq -er '.app_image_id' "$manifest")"
  release_gotenberg_image_id="$(jq -er '.gotenberg_image_id' "$manifest")"
  valid_image_id "$release_app_image_id" || die 'Hash release app image ID is invalid'
  valid_image_id "$release_gotenberg_image_id" || die 'Hash release Gotenberg image ID is invalid'
  archive_sha="$(jq -er '.image_archive_sha256' "$manifest")"
  release_archive_bytes="$(jq -er '.image_archive_bytes' "$manifest")"
  [[ "$archive_sha" =~ ^[0-9a-f]{64}$ ]] || die 'Hash release archive digest is invalid'
  [[ "$release_archive_bytes" =~ ^[1-9][0-9]*$ ]] || die 'Hash release archive size is invalid'
  [[ "$(sha256_file "$archive")" == "$archive_sha" ]] || die 'Hash release archive digest does not match manifest'
  [[ "$(wc -c < "$archive" | tr -d ' ')" == "$release_archive_bytes" ]] || die 'Hash release archive size does not match manifest'
  compose_sha="$(jq -er '.compose_sha256' "$manifest")"
  [[ "$compose_sha" =~ ^[0-9a-f]{64}$ ]] || die 'Hash release Compose digest is invalid'
  [[ "$(sha256_file "$compose")" == "$compose_sha" ]] || die 'Hash release Compose digest does not match manifest'
}

validate_container_topology() {
  local actual_image app_release worker_release volume_mount running_consumers
  assert_running_healthy "$app_container" 'Hash app'
  container_running "$worker_container" || die "Hash worker container is not running: $worker_container"
  assert_running_healthy "$gotenberg_container" 'Gotenberg'
  assert_running_healthy "$minio_container" 'MinIO'
  container_running "$postgres_container" || die "PostgreSQL container is not running: $postgres_container"

  assert_compose_identity "$app_container" "$app_service" 'Hash app'
  assert_compose_identity "$worker_container" "$worker_service" 'Hash worker'
  assert_compose_identity "$gotenberg_container" "$gotenberg_service" 'Gotenberg'

  actual_image="$(container_field "$app_container" '.Image' 'image ID')"
  [[ "$actual_image" == "$release_app_image_id" ]] || die 'running Hash app image does not match the exact release manifest'
  actual_image="$(container_field "$worker_container" '.Image' 'image ID')"
  [[ "$actual_image" == "$release_app_image_id" ]] || die 'running Hash worker image does not match the exact release manifest'
  actual_image="$(container_field "$gotenberg_container" '.Image' 'image ID')"
  [[ "$actual_image" == "$release_gotenberg_image_id" ]] || die 'running Gotenberg image does not match the exact release manifest'
  actual_image="$(container_field "$minio_container" '.Image' 'image ID')"
  [[ "$actual_image" == "$expected_minio_image_id" ]] || die 'running MinIO image does not match the pinned content ID'

  app_release="$(container_field "$app_container" '[.Config.Env[] | select(startswith("HASH_RELEASE="))][0] // "" | sub("^HASH_RELEASE="; "")' 'Hash release environment')"
  worker_release="$(container_field "$worker_container" '[.Config.Env[] | select(startswith("HASH_RELEASE="))][0] // "" | sub("^HASH_RELEASE="; "")' 'Hash worker release environment')"
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
  path_is_within "$restic_env" "$minio_data_path" \
    && die 'Restic credential file must not be inside the MinIO data volume'
  if [[ -n "$restic_temp_dir" ]]; then
    path_is_within "$restic_temp_dir" "$minio_data_path" \
      && die 'Restic temporary directory must not be inside the MinIO data volume'
    path_is_within "$minio_data_path" "$restic_temp_dir" \
      && die 'MinIO data volume must not be inside the Restic temporary directory'
  fi

  volume_mount="$(container_json "$minio_container" | jq -er --arg destination "$minio_mount_destination" '
    [.[0].Mounts[] | select(.Destination == $destination)] as $m |
    select($m | length == 1) | $m[0] | [.Type, (.Name // ""), .Source] | @tsv
  ')" || die 'MinIO container does not have exactly one configured data mount'
  [[ "$volume_mount" == $'volume\t'"$minio_volume"$'\t'"$minio_data_path" ]] \
    || die 'MinIO container data mount is not the exact pinned Docker volume'
  container_json "$minio_container" | jq -e --arg data "$minio_mount_destination" '
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

  postgres_image_id="$(container_field "$postgres_container" '.Image' 'PostgreSQL image ID')"
  valid_image_id "$postgres_image_id" || die 'running PostgreSQL image ID is invalid'
  minio_image_ref="$(container_field "$minio_container" '.Config.Image' 'MinIO image reference')"
  postgres_image_ref="$(container_field "$postgres_container" '.Config.Image' 'PostgreSQL image reference')"
  gotenberg_image_ref="$(container_field "$gotenberg_container" '.Config.Image' 'Gotenberg image reference')"
}

preflight_database_and_capacity() {
  local database_bytes minio_image_bytes postgres_image_bytes required_bytes free_kib free_bytes
  "$DOCKER" exec "$postgres_container" pg_dump --version >/dev/null 2>&1 \
    || die 'pg_dump is unavailable in the configured PostgreSQL container'
  database_bytes="$("$DOCKER" exec "$postgres_container" psql --no-psqlrc --no-password \
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
  for tool in jq awk sed grep sort find wc cp cmp mktemp stat date du df sync bash tr env \
      chmod mkdir rm rmdir mv sleep dirname basename "$DOCKER" "$RESTIC"; do
    command -v "$tool" >/dev/null 2>&1 || die "required command not found: $tool"
  done
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    die 'sha256sum or shasum is required'
  fi
  [[ "$-" != *x* ]] || die 'shell xtrace must be disabled because subprocesses carry credentials'
  load_config
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
  local name="$1" require_health="$2"
  if ! "$DOCKER" start "$name" >/dev/null 2>&1; then
    log "ERROR: failed to restart $name"
    return 1
  fi
  if [[ "$require_health" == true ]]; then
    if ! wait_healthy "$name"; then
      log "ERROR: $name did not become healthy after restart"
      return 1
    fi
  elif ! wait_running "$name"; then
    log "ERROR: $name did not remain running after restart"
    return 1
  fi
}

restart_services() {
  local failed=0
  if [[ "$minio_stopped" == 1 ]]; then
    log 'restarting MinIO before Hash writers'
    restart_one "$minio_container" true || failed=1
    [[ "$failed" == 0 ]] && minio_stopped=0
  fi
  if [[ "$app_stopped" == 1 ]]; then
    if [[ "$failed" == 0 ]]; then
      log 'restarting Hash app'
      restart_one "$app_container" true || failed=1
      [[ "$failed" == 0 ]] && app_stopped=0
    fi
  fi
  if [[ "$worker_stopped" == 1 ]]; then
    if [[ "$failed" == 0 ]]; then
      log 'restarting Hash worker last'
      restart_one "$worker_container" false || failed=1
      [[ "$failed" == 0 ]] && worker_stopped=0
    fi
  fi
  return "$failed"
}

safe_remove_stage() {
  [[ -n "${stage_dir:-}" && -n "${run_id:-}" ]] || return 0
  case "$stage_dir" in
    "$state_dir/staging/$run_id") ;;
    *) log 'ERROR: refusing to remove an unexpected staging path'; return 1 ;;
  esac
  [[ -f "$stage_dir/.hash-cold-backup-owned" ]] || {
    log 'ERROR: refusing to remove staging without ownership marker'
    return 1
  }
  rm -rf -- "$stage_dir"
}

release_lock() {
  [[ -n "${lock_dir:-}" && -n "${run_id:-}" ]] || return 0
  [[ "$lock_dir" == "$state_dir/.hash-cold-backup.lock" ]] || return 1
  [[ -f "$lock_dir/run-id" && ! -L "$lock_dir/run-id" ]] || return 1
  [[ "$(<"$lock_dir/run-id")" == "$run_id" ]] || return 1
  rm -f "$lock_dir/run-id"
  rmdir "$lock_dir"
}

on_exit() {
  local rc=$? cleanup_failed=0
  trap - EXIT INT TERM
  if [[ "${minio_stopped:-0}" == 1 || "${app_stopped:-0}" == 1 || "${worker_stopped:-0}" == 1 ]]; then
    restart_services || cleanup_failed=1
  fi
  if [[ "$cleanup_failed" == 1 ]]; then
    printf 'FAIL: cold-backup restart was incomplete; staging and lock retained for immediate operator action\n' >&2
    exit 1
  fi
  if ! safe_remove_stage; then
    printf 'FAIL: cold-backup staging cleanup was incomplete; lock retained for operator inspection\n' >&2
    exit 1
  fi
  if ! release_lock; then
    printf 'FAIL: cold-backup lock cleanup was incomplete; inspect it before retrying\n' >&2
    exit 1
  fi
  exit "$rc"
}

stop_container() {
  local name="$1" role="$2" exit_code
  log "stopping $role"
  "$DOCKER" stop --time "$stop_timeout_seconds" "$name" >/dev/null \
    || die "failed to stop $role container"
  container_running "$name" && die "$role container is still running after stop"
  exit_code="$(container_field "$name" '.State.ExitCode' 'exit code')"
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
    --arg minio_image_id "$expected_minio_image_id" \
    --arg minio_image_ref "$minio_image_ref" \
    --arg postgres_image_id "$postgres_image_id" \
    --arg postgres_image_ref "$postgres_image_ref" \
    --arg postgres_database "$postgres_database" \
    --arg minio_volume "$minio_volume" \
    --arg minio_data_path "$minio_data_path" \
    --arg inventory_sha256 "$inventory_sha" \
    --arg dump_sha256 "$dump_sha" \
    --arg inventory_sql_sha256 "$inventory_sql_sha" \
    --arg verifier_script_sha256 "$verifier_script_sha" \
    --arg minio_archive_sha256 "$minio_archive_sha" \
    --arg postgres_archive_sha256 "$postgres_archive_sha" \
    --argjson minio_kib "$minio_kib" \
    --argjson minio_files "$minio_files" \
    '{schema_version:1,workflow:"hash-storagebox-cold-backup-v1",run_id:$run_id,
      captured_at:$captured_at,maintenance_window_id:$maintenance_window_id,
      backup:{provider:"hetzner-storage-box",transport:"restic-sftp",
        repository_sha256:$repository_sha256,restic_config_id:$restic_config_id,
        whole_minio_volume:true,exclusions:[]},
      release:{commit_sha:$release_commit,app_image_id:$app_image_id,
        gotenberg_image_id:$gotenberg_image_id,gotenberg_image_ref:$gotenberg_image_ref},
      postgres:{database:$postgres_database,image_id:$postgres_image_id,
        image_ref:$postgres_image_ref,dump_sha256:$dump_sha256,
        inventory_sha256:$inventory_sha256,inventory_sql_sha256:$inventory_sql_sha256,
        verifier_script_sha256:$verifier_script_sha256},
      minio:{volume:$minio_volume,data_path:$minio_data_path,image_id:$minio_image_id,
        image_ref:$minio_image_ref,image_archive_sha256:$minio_archive_sha256,
        data_kib:$minio_kib,file_count:$minio_files,minio_sys_present:true},
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
  lock_dir="$state_dir/.hash-cold-backup.lock"
  if ! mkdir -m 0700 "$lock_dir" 2>/dev/null; then
    die "another cold backup may be active; inspect this lock before removing it: $lock_dir"
  fi
  printf '%s\n' "$run_id" > "$lock_dir/run-id"
  chmod 0600 "$lock_dir/run-id"
  trap on_exit EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  mkdir -p -m 0700 "$state_dir/staging" "$state_dir/receipts"
  stage_dir="$state_dir/staging/$run_id"
  mkdir -m 0700 "$stage_dir"
  : > "$stage_dir/.hash-cold-backup-owned"
  mkdir -m 0700 "$stage_dir/postgresql" "$stage_dir/minio" "$stage_dir/images" \
    "$stage_dir/release" "$stage_dir/metadata" "$stage_dir/tools" \
    "$stage_dir/tools/scripts" "$stage_dir/tools/ops"
  write_sanitized_receipts

  # Archive exact recovery images before downtime. Hash/Gotenberg already ship
  # as the manifest-bound release archive; MinIO and PostgreSQL are saved by
  # exact local content ID so a Storage-Box-only drill never pulls a mutable tag.
  log 'staging exact release and recovery images before maintenance begins'
  cp "$release_dir/manifest.json" "$stage_dir/release/manifest.json"
  cp "$release_dir/docker-compose.yml" "$stage_dir/release/docker-compose.yml"
  cp "$release_dir/images.tar" "$stage_dir/release/images.tar"
  cp "$inventory_sql" "$stage_dir/tools/ops/recovery-object-inventory.sql"
  cp "$verifier_script" "$stage_dir/tools/scripts/verify-recovery-objects.sh"
  [[ "$(sha256_file "$stage_dir/release/manifest.json")" == "$release_manifest_sha" ]] \
    || die 'Hash release manifest changed during staging'
  [[ "$(sha256_file "$stage_dir/release/images.tar")" == "$(jq -er '.image_archive_sha256' "$stage_dir/release/manifest.json")" ]] \
    || die 'staged Hash release archive digest changed during copy'
  [[ "$(sha256_file "$stage_dir/release/docker-compose.yml")" == "$(jq -er '.compose_sha256' "$stage_dir/release/manifest.json")" ]] \
    || die 'staged Hash release Compose digest changed during copy'
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

  worker_stopped=1
  stop_container "$worker_container" 'Hash worker'
  app_stopped=1
  stop_container "$app_container" 'Hash app'

  log 'capturing canonical inventory and PostgreSQL dump while Hash writers are stopped'
  "$DOCKER" exec -i "$postgres_container" psql --no-psqlrc --no-password \
    --username "$postgres_user" --dbname "$postgres_database" --set ON_ERROR_STOP=1 \
    --tuples-only --no-align --field-separator $'\t' --pset footer=off \
    < "$inventory_sql" > "$stage_dir/postgresql/recovery-object-inventory.before.tsv" \
    || die 'failed to capture pre-dump canonical object inventory'
  "$DOCKER" exec "$postgres_container" pg_dump --no-password \
    --username "$postgres_user" --dbname "$postgres_database" --format=custom \
    --compress=9 --no-owner --no-acl \
    > "$stage_dir/postgresql/hash.pgdump" \
    || die 'PostgreSQL dump failed'
  [[ -s "$stage_dir/postgresql/hash.pgdump" ]] || die 'PostgreSQL dump is empty'
  "$DOCKER" exec -i "$postgres_container" psql --no-psqlrc --no-password \
    --username "$postgres_user" --dbname "$postgres_database" --set ON_ERROR_STOP=1 \
    --tuples-only --no-align --field-separator $'\t' --pset footer=off \
    < "$inventory_sql" > "$stage_dir/postgresql/recovery-object-inventory.tsv" \
    || die 'failed to capture post-dump canonical object inventory'
  cmp -s "$stage_dir/postgresql/recovery-object-inventory.before.tsv" \
    "$stage_dir/postgresql/recovery-object-inventory.tsv" \
    || die 'canonical object inventory changed during dump; recovery point is not coordinated'
  rm -f "$stage_dir/postgresql/recovery-object-inventory.before.tsv"

  minio_stopped=1
  stop_container "$minio_container" 'MinIO'
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

  archive_file="$state_dir/receipts/$run_id.restic.jsonl"
  error_file="$state_dir/receipts/$run_id.restic.stderr"
  : > "$archive_file"
  : > "$error_file"
  chmod 0600 "$archive_file" "$error_file"
  log 'writing one coordinated PostgreSQL + complete MinIO-volume Restic snapshot'
  set +e
  restic_cmd backup --json --host "$restic_host" \
    --tag hash-cold-backup --tag "release:$release_commit" \
    --tag "maintenance:$maintenance_window_id" --tag "run:$run_id" \
    "$stage_dir" "$minio_data_path" > "$archive_file" 2> "$error_file"
  restic_rc=$?
  set -e
  ((restic_rc == 0)) \
    || die "Restic backup failed; private diagnostics retained under $state_dir/receipts/$run_id.restic.*"
  snapshot_id="$(jq -sr '[.[] | select(.message_type == "summary") | .snapshot_id] | last // empty' "$archive_file")"
  [[ "$snapshot_id" =~ ^[0-9a-f]{64}$ ]] || die 'Restic backup did not return a full snapshot ID'

  # The immutable point already exists remotely. Restore availability promptly,
  # then verify the remote snapshot and repository while Hash is online again.
  restart_services || die 'services did not recover after the cold capture'

  verify_snapshot_path "$snapshot_id" "$stage_dir/metadata/backup-manifest.json"
  verify_snapshot_path "$snapshot_id" "$stage_dir/postgresql/hash.pgdump"
  verify_snapshot_path "$snapshot_id" "$stage_dir/postgresql/recovery-object-inventory.tsv"
  verify_snapshot_path "$snapshot_id" "$stage_dir/release/images.tar"
  verify_snapshot_path "$snapshot_id" "$stage_dir/images/minio-image.tar"
  verify_snapshot_path "$snapshot_id" "$stage_dir/tools/scripts/verify-recovery-objects.sh"
  verify_snapshot_path "$snapshot_id" "$stage_dir/tools/ops/recovery-object-inventory.sql"
  verify_snapshot_path "$snapshot_id" "$minio_data_path/.minio.sys"

  log "checking $integrity_subset of the Storage Box repository"
  restic_cmd check --read-data-subset="$integrity_subset" >/dev/null 2>&1 \
    || die 'Restic repository integrity check failed'

  receipt_tmp="$state_dir/receipts/.$run_id.receipt.tmp"
  jq -n --arg run_id "$run_id" --arg snapshot_id "$snapshot_id" \
    --arg repository_sha256 "$repository_sha" --arg restic_config_id "$restic_config_id" \
    --arg release_commit "$release_commit" --arg completed_at "$(date -u +%FT%TZ)" \
    --arg maintenance_window_id "$maintenance_window_id" \
      '{schema_version:1,status:"capture-verified",run_id:$run_id,snapshot_id:$snapshot_id,
      repository_sha256:$repository_sha256,restic_config_id:$restic_config_id,
      release_commit:$release_commit,maintenance_window_id:$maintenance_window_id,
      whole_minio_volume:true,minio_sys_verified_in_snapshot:true,
      services_restarted:true,repository_check_passed:true,completed_at:$completed_at}' \
    > "$receipt_tmp"
  chmod 0600 "$receipt_tmp"
  mv "$receipt_tmp" "$state_dir/receipts/$run_id.receipt.json"
  rm -f "$archive_file" "$error_file"
  log "cold snapshot capture and repository checks complete: snapshot $snapshot_id"
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
[[ -n "$DOCKER" ]] || die 'required command not found: docker'
[[ -n "$RESTIC" ]] || die 'required command not found: restic'

worker_stopped=0
app_stopped=0
minio_stopped=0
stage_dir=""
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
