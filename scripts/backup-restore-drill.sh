#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Copyright (c) Bright Interaction
#
# Exercise a coupled PostgreSQL + S3 backup and restore without touching an
# existing Hash environment. The drill creates uniquely named, labelled Docker
# resources on a local Docker engine, restores into separate volumes, verifies
# every database-referenced object byte-for-byte, and removes only resources
# bearing this run's label. Synthetic artifacts and the report are retained.

set -euo pipefail

readonly LABEL_KEY="com.brightinteraction.hash.restore-drill"
readonly POSTGRES_IMAGE="${HASH_DRILL_POSTGRES_IMAGE:-postgres:16.15-alpine3.24@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685}"
readonly MINIO_IMAGE="${HASH_DRILL_MINIO_IMAGE:-minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e}"
readonly DB_NAME="hashdrill"
readonly DB_USER="hashdrill"
readonly DB_PASSWORD="hash-drill-only-password"
readonly S3_ACCESS_KEY="hashdrillaccess"
readonly S3_SECRET_KEY="hashdrillsecret123456"
readonly S3_BUCKET="hash-drill"
readonly ORG_ID="11111111-1111-4111-8111-111111111111"
readonly DOCUMENT_ID="22222222-2222-4222-8222-222222222222"
readonly ENVELOPE_CHILD_ID="22222222-2222-4222-8222-222222222223"
readonly FINALIZING_DOCUMENT_ID="22222222-2222-4222-8222-222222222224"
readonly TEMPLATE_ID="33333333-3333-4333-8333-333333333333"
readonly VERSION_ID="44444444-4444-4444-8444-444444444444"
readonly RECIPIENT_ID="55555555-5555-4555-8555-555555555555"
readonly FIELD_ID="66666666-6666-4666-8666-666666666666"
readonly SIGNATURE_ID="77777777-7777-4777-8777-777777777777"

usage() {
  cat <<'EOF'
Usage: scripts/backup-restore-drill.sh [--output NEW_DIRECTORY]

Runs a destructive-to-itself recovery drill using only newly created,
uniquely labelled Docker containers, volumes, and a network. It refuses remote
Docker contexts and never reads Hash .env files or production credentials.

The output directory must not already exist. If omitted, a new directory under
TMPDIR is created. Synthetic backup artifacts and drill-report.txt are retained
as evidence; Docker resources are always removed after the run.

Optional image overrides (intended for testing a release candidate):
  HASH_DRILL_POSTGRES_IMAGE
  HASH_DRILL_MINIO_IMAGE
EOF
}

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

decode_base64() {
  if [[ "$base64_decoder" == "gnu" ]]; then
    base64 --decode
  else
    base64 -D
  fi
}

output_request=""
while (($# > 0)); do
  case "$1" in
    --output)
      (($# >= 2)) || die "--output requires a directory"
      output_request="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

for tool in docker awk base64 shasum; do
  if [[ "$tool" == "shasum" ]] && command -v sha256sum >/dev/null 2>&1; then
    continue
  fi
  command -v "$tool" >/dev/null 2>&1 || die "required command not found: $tool"
done
if printf '' | base64 --decode >/dev/null 2>&1; then
  base64_decoder="gnu"
elif printf '' | base64 -D >/dev/null 2>&1; then
  base64_decoder="bsd"
else
  die "base64 decoder is unavailable"
fi
readonly base64_decoder

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
inventory_sql="$script_dir/../ops/recovery-object-inventory.sql"
[[ -r "$inventory_sql" ]] || die "canonical inventory SQL is missing: $inventory_sql"
readonly inventory_sql

run_id="hash-drill-$(date -u +%s)-$$"
[[ "$run_id" =~ ^hash-drill-[0-9]+-[0-9]+$ ]] || die "unsafe generated run id"
readonly run_id

context="$(docker context show 2>/dev/null)" || die "Docker is not available"
if [[ -n "${DOCKER_HOST:-}" ]]; then
  endpoint="$DOCKER_HOST"
else
  endpoint="$(docker context inspect "$context" --format '{{.Endpoints.docker.Host}}' 2>/dev/null)" \
    || die "cannot inspect Docker context: $context"
fi
case "$endpoint" in
  unix://*|npipe://*) ;;
  *) die "refusing non-local Docker endpoint scheme: ${endpoint%%:*}" ;;
esac
endpoint_scheme="${endpoint%%:*}"
readonly endpoint_scheme

umask 077
if [[ -n "$output_request" ]]; then
  output_parent="$(dirname "$output_request")"
  output_base="$(basename "$output_request")"
  [[ -d "$output_parent" ]] || die "output parent does not exist: $output_parent"
  output_parent="$(cd "$output_parent" && pwd -P)"
  output_dir="$output_parent/$output_base"
  [[ ! -e "$output_dir" ]] || die "output path already exists: $output_dir"
  mkdir -m 0700 "$output_dir"
else
  output_dir="$(mktemp -d "${TMPDIR:-/tmp}/hash-backup-restore-drill.XXXXXX")"
fi
readonly output_dir

containers=()
volumes=()
networks=()

label_for_container() {
  docker container inspect --format "{{ index .Config.Labels \"$LABEL_KEY\" }}" "$1" 2>/dev/null || true
}

label_for_volume() {
  docker volume inspect --format "{{ index .Labels \"$LABEL_KEY\" }}" "$1" 2>/dev/null || true
}

label_for_network() {
  docker network inspect --format "{{ index .Labels \"$LABEL_KEY\" }}" "$1" 2>/dev/null || true
}

cleanup() {
  local rc=$? resource actual cleanup_rc=0
  trap - EXIT INT TERM
  set +e

  for resource in "${containers[@]}"; do
    if docker container inspect "$resource" >/dev/null 2>&1; then
      actual="$(label_for_container "$resource")"
      if [[ "$actual" == "$run_id" ]]; then
        docker rm --force "$resource" >/dev/null || cleanup_rc=1
      else
        printf 'REFUSED cleanup of unlabelled container: %s\n' "$resource" >&2
        cleanup_rc=1
      fi
    fi
  done
  for resource in "${volumes[@]}"; do
    if docker volume inspect "$resource" >/dev/null 2>&1; then
      actual="$(label_for_volume "$resource")"
      if [[ "$actual" == "$run_id" ]]; then
        docker volume rm "$resource" >/dev/null || cleanup_rc=1
      else
        printf 'REFUSED cleanup of unlabelled volume: %s\n' "$resource" >&2
        cleanup_rc=1
      fi
    fi
  done
  for resource in "${networks[@]}"; do
    if docker network inspect "$resource" >/dev/null 2>&1; then
      actual="$(label_for_network "$resource")"
      if [[ "$actual" == "$run_id" ]]; then
        docker network rm "$resource" >/dev/null || cleanup_rc=1
      else
        printf 'REFUSED cleanup of unlabelled network: %s\n' "$resource" >&2
        cleanup_rc=1
      fi
    fi
  done

  if ((cleanup_rc != 0 && rc == 0)); then
    rc=1
  fi
  if ((rc != 0)); then
    printf 'Drill failed; diagnostic artifacts retained at %s\n' "$output_dir" >&2
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ensure_absent() {
  local kind="$1" name="$2"
  if docker "$kind" inspect "$name" >/dev/null 2>&1; then
    die "refusing to reuse existing Docker $kind: $name"
  fi
}

create_volume() {
  local name="$1"
  ensure_absent volume "$name"
  volumes+=("$name")
  docker volume create --label "$LABEL_KEY=$run_id" "$name" >/dev/null
}

wait_for_postgres() {
  local container="$1" attempt
  for ((attempt = 1; attempt <= 60; attempt++)); do
    if docker exec -e PGPASSWORD="$DB_PASSWORD" "$container" \
      pg_isready --quiet --username "$DB_USER" --dbname "$DB_NAME"; then
      return 0
    fi
    sleep 1
  done
  docker logs "$container" >&2 || true
  die "PostgreSQL did not become ready: $container"
}

wait_for_minio() {
  local container="$1" alias="$2" attempt
  for ((attempt = 1; attempt <= 60; attempt++)); do
    if docker exec "$container" mc alias set "$alias" http://127.0.0.1:9000 \
        "$S3_ACCESS_KEY" "$S3_SECRET_KEY" >/dev/null 2>&1 \
      && docker exec "$container" mc ready "$alias" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  docker logs "$container" >&2 || true
  die "MinIO did not become ready: $container"
}

start_postgres() {
  local container="$1" volume="$2"
  ensure_absent container "$container"
  containers+=("$container")
  docker run --detach \
    --name "$container" \
    --network "$network" \
    --label "$LABEL_KEY=$run_id" \
    --env POSTGRES_DB="$DB_NAME" \
    --env POSTGRES_USER="$DB_USER" \
    --env POSTGRES_PASSWORD="$DB_PASSWORD" \
    --volume "$volume:/var/lib/postgresql/data" \
    "$POSTGRES_IMAGE" >/dev/null
  wait_for_postgres "$container"
}

start_minio() {
  local container="$1" volume="$2" output_mode="$3"
  ensure_absent container "$container"
  containers+=("$container")
  docker run --detach \
    --name "$container" \
    --network "$network" \
    --label "$LABEL_KEY=$run_id" \
    --env MINIO_ROOT_USER="$S3_ACCESS_KEY" \
    --env MINIO_ROOT_PASSWORD="$S3_SECRET_KEY" \
    --volume "$volume:/data" \
    --volume "$output_dir:/drill-output:$output_mode" \
    "$MINIO_IMAGE" server /data --console-address :9001 >/dev/null
}

log "using local Docker context $context ($endpoint_scheme)"
for image in "$POSTGRES_IMAGE" "$MINIO_IMAGE"; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    log "pulling missing drill image $image"
    docker pull "$image"
  fi
done

postgres_image_id="$(docker image inspect --format '{{.Id}}' "$POSTGRES_IMAGE")"
minio_image_id="$(docker image inspect --format '{{.Id}}' "$MINIO_IMAGE")"

network="$run_id-net"
ensure_absent network "$network"
networks+=("$network")
docker network create --label "$LABEL_KEY=$run_id" "$network" >/dev/null

pg_source_volume="$run_id-pg-source"
s3_source_volume="$run_id-s3-source"
pg_restore_volume="$run_id-pg-restore"
s3_restore_volume="$run_id-s3-restore"
create_volume "$pg_source_volume"
create_volume "$s3_source_volume"
create_volume "$pg_restore_volume"
create_volume "$s3_restore_volume"

pg_source="$run_id-pg-source"
s3_source="$run_id-s3-source"
pg_restore_container="$run_id-pg-restore"
s3_restore="$run_id-s3-restore"

started_at="$(date -u +%FT%TZ)"
total_started_epoch="$(date -u +%s)"

log "starting isolated source stores"
start_postgres "$pg_source" "$pg_source_volume"
start_minio "$s3_source" "$s3_source_volume" rw
wait_for_minio "$s3_source" source
docker exec "$s3_source" mc mb --ignore-existing "source/$S3_BUCKET" >/dev/null
docker exec "$s3_source" mc version enable "source/$S3_BUCKET" >/dev/null

mkdir -p "$output_dir/seed" "$output_dir/snapshot/objects" "$output_dir/restored"
for pdf_name in template.pdf source.pdf rendered.pdf final.pdf audit.pdf pending-final.pdf pending-audit.pdf; do
  printf '%s\n' \
    '%PDF-1.4' \
    '1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj' \
    '2 0 obj << /Type /Pages /Count 0 >> endobj' \
    "% Hash recovery drill $pdf_name artifact" \
    '%%EOF' > "$output_dir/seed/$pdf_name"
done
printf '%s\n' '<section data-hash-audit="synthetic">signed audit payload</section>' \
  > "$output_dir/seed/audit.payload.txt"
printf '%s\n' 'synthetic-detached-ed25519-signature' \
  > "$output_dir/seed/audit.signature.txt"
printf '%s\n' '<section data-hash-audit="synthetic-pending">staged finalization payload</section>' \
  > "$output_dir/seed/pending-audit.payload.txt"
printf '%s\n' 'synthetic-pending-detached-ed25519-signature' \
  > "$output_dir/seed/pending-audit.signature.txt"
printf '%s\n' '<span class="hash-signature">Synthetic Signer</span>' \
  > "$output_dir/seed/signature.html"
printf '%s\n' 'synthetic-document-image-bytes' > "$output_dir/seed/document-image.png"
printf '%s\n' 'synthetic-template-image-bytes' > "$output_dir/seed/template-image.png"
printf '%s\n' 'synthetic-version-image-bytes' > "$output_dir/seed/version-image.png"
printf '%s\n' '<svg xmlns="http://www.w3.org/2000/svg"><text>org logo</text></svg>' \
  > "$output_dir/seed/org-logo.svg"
printf '%s\n' 'synthetic-document-logo-png-bytes' > "$output_dir/seed/document-logo.png"

final_content_sha="$(sha256_file "$output_dir/seed/final.pdf")"
audit_content_sha="$(sha256_file "$output_dir/seed/audit.pdf")"
audit_payload_content_sha="$(sha256_file "$output_dir/seed/audit.payload.txt")"
audit_signature_content_sha="$(sha256_file "$output_dir/seed/audit.signature.txt")"
pending_final_content_sha="$(sha256_file "$output_dir/seed/pending-final.pdf")"
pending_audit_content_sha="$(sha256_file "$output_dir/seed/pending-audit.pdf")"
pending_payload_content_sha="$(sha256_file "$output_dir/seed/pending-audit.payload.txt")"
pending_signature_content_sha="$(sha256_file "$output_dir/seed/pending-audit.signature.txt")"

seed_names=(
  template.pdf
  source.pdf
  rendered.pdf
  final.pdf
  audit.pdf
  audit.payload.txt
  audit.signature.txt
  signature.html
  document-image.png
  template-image.png
  version-image.png
  org-logo.svg
  document-logo.png
  pending-final.pdf
  pending-audit.pdf
  pending-audit.payload.txt
  pending-audit.signature.txt
)
seed_keys=(
  "org/$ORG_ID/templates/$TEMPLATE_ID.pdf"
  "org/$ORG_ID/documents/source-$DOCUMENT_ID.pdf"
  "org/$ORG_ID/documents/$DOCUMENT_ID/rendered.pdf"
  "org/$ORG_ID/documents/$DOCUMENT_ID/final-$final_content_sha.pdf"
  "org/$ORG_ID/documents/$DOCUMENT_ID/audit-$audit_content_sha.pdf"
  "org/$ORG_ID/documents/$DOCUMENT_ID/audit-payload-$audit_payload_content_sha.txt"
  "org/$ORG_ID/documents/$DOCUMENT_ID/audit-signature-$audit_signature_content_sha.txt"
  "org/$ORG_ID/signatures/$SIGNATURE_ID.html"
  "org/$ORG_ID/assets/document-image.png"
  "org/$ORG_ID/assets/template-image.png"
  "org/$ORG_ID/assets/version-image.png"
  "branding/$ORG_ID/logo.svg"
  "branding/$ORG_ID/logo.png"
  "org/$ORG_ID/documents/$FINALIZING_DOCUMENT_ID/final-$pending_final_content_sha.pdf"
  "org/$ORG_ID/documents/$FINALIZING_DOCUMENT_ID/audit-$pending_audit_content_sha.pdf"
  "org/$ORG_ID/documents/$FINALIZING_DOCUMENT_ID/audit-payload-$pending_payload_content_sha.txt"
  "org/$ORG_ID/documents/$FINALIZING_DOCUMENT_ID/audit-signature-$pending_signature_content_sha.txt"
)
seed_hashes=()
for i in "${!seed_names[@]}"; do
  seed_hashes+=("$(sha256_file "$output_dir/seed/${seed_names[$i]}")")
  docker exec "$s3_source" mc cp \
    "/drill-output/seed/${seed_names[$i]}" \
    "source/$S3_BUCKET/${seed_keys[$i]}" >/dev/null
done

docker exec -i -e PGPASSWORD="$DB_PASSWORD" "$pg_source" \
  psql --no-psqlrc --set ON_ERROR_STOP=1 --username "$DB_USER" --dbname "$DB_NAME" \
    --set org_id="$ORG_ID" \
    --set document_id="$DOCUMENT_ID" \
    --set envelope_child_id="$ENVELOPE_CHILD_ID" \
    --set finalizing_document_id="$FINALIZING_DOCUMENT_ID" \
    --set template_id="$TEMPLATE_ID" \
    --set version_id="$VERSION_ID" \
    --set recipient_id="$RECIPIENT_ID" \
    --set field_id="$FIELD_ID" \
    --set signature_id="$SIGNATURE_ID" \
    --set template_key="${seed_keys[0]}" \
    --set source_key="${seed_keys[1]}" \
    --set rendered_key="${seed_keys[2]}" \
    --set final_key="${seed_keys[3]}" \
    --set audit_key="${seed_keys[4]}" \
    --set audit_payload_key="${seed_keys[5]}" \
    --set audit_signature_key="${seed_keys[6]}" \
    --set signature_key="${seed_keys[7]}" \
    --set document_image_key="${seed_keys[8]}" \
    --set template_image_key="${seed_keys[9]}" \
    --set version_image_key="${seed_keys[10]}" \
    --set pending_final_key="${seed_keys[13]}" \
    --set pending_audit_key="${seed_keys[14]}" \
    --set pending_payload_key="${seed_keys[15]}" \
    --set pending_signature_key="${seed_keys[16]}" \
    --set template_sha="${seed_hashes[0]}" \
    --set source_sha="${seed_hashes[1]}" \
    --set rendered_sha="${seed_hashes[2]}" \
    --set final_sha="${seed_hashes[3]}" \
    --set audit_sha="${seed_hashes[4]}" \
    --set audit_payload_sha="${seed_hashes[5]}" \
    --set audit_signature_sha="${seed_hashes[6]}" \
    --set signature_sha="${seed_hashes[7]}" \
    --set pending_final_sha="${seed_hashes[13]}" \
    --set pending_audit_sha="${seed_hashes[14]}" \
    --set pending_payload_sha="${seed_hashes[15]}" \
    --set pending_signature_sha="${seed_hashes[16]}" <<'SQL' >/dev/null
CREATE TABLE templates (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL,
    blocks_json jsonb,
    pdf_storage_key text,
    pdf_sha256 bytea,
    pdf_storage_version_id text,
    evidence_version_pin_required boolean NOT NULL DEFAULT false
);
CREATE TABLE documents (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL,
    status text NOT NULL,
    requires_signature boolean NOT NULL,
    blocks_json jsonb,
    rendered_pdf_key text,
    rendered_pdf_sha bytea,
    pdf_storage_key text,
    pdf_sha256 bytea,
    final_pdf_key text,
    final_pdf_sha bytea,
    audit_cert_key text,
    audit_cert_sha256 bytea,
    audit_payload_key text,
    audit_payload_sha256 bytea,
    audit_signature_key text,
    audit_signature_sha256 bytea,
    pdf_storage_version_id text,
    rendered_pdf_version_id text,
    final_pdf_version_id text,
    audit_cert_version_id text,
    audit_payload_version_id text,
    audit_signature_version_id text,
    evidence_version_pins_required boolean NOT NULL DEFAULT false,
    parent_envelope_id uuid,
    deleted_at timestamptz
);
CREATE TABLE document_versions (
    id uuid PRIMARY KEY,
    document_id uuid NOT NULL,
    org_id uuid NOT NULL,
    block_tree_json jsonb
);
CREATE TABLE signatures (
    id uuid PRIMARY KEY,
    document_id uuid NOT NULL,
    image_storage_key text NOT NULL,
    image_sha256 bytea NOT NULL,
    image_version_id text,
    image_version_pin_required boolean NOT NULL DEFAULT false
);
CREATE TABLE document_finalization_intents (
    document_id uuid PRIMARY KEY,
    org_id uuid NOT NULL,
    mode text NOT NULL,
    final_pdf_key text NOT NULL,
    final_pdf_sha256 bytea NOT NULL,
    final_pdf_version_id text,
    audit_cert_key text NOT NULL,
    audit_cert_sha256 bytea NOT NULL,
    audit_cert_version_id text,
    audit_payload_key text NOT NULL,
    audit_payload_sha256 bytea NOT NULL,
    audit_payload_version_id text,
    audit_signature_key text NOT NULL,
    audit_signature_sha256 bytea NOT NULL,
    audit_signature_version_id text,
    evidence_version_pins_required boolean NOT NULL DEFAULT false
);
CREATE TABLE org_branding (
    org_id uuid PRIMARY KEY,
    logo_url text NOT NULL
);
CREATE TABLE document_branding_override (
    document_id uuid PRIMARY KEY,
    logo_url text
);
CREATE TABLE hash_restore_drill (
    document_id text PRIMARY KEY,
    status text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO templates (id, org_id, blocks_json, pdf_storage_key, pdf_sha256)
VALUES (
    :'template_id', :'org_id',
    jsonb_build_object(
      'version', 1,
      'blocks', jsonb_build_array(jsonb_build_object(
        'id', 'template-container', 'type', 'callout',
        'content', jsonb_build_array(jsonb_build_object(
          'id', 'template-image', 'type', 'image',
          'attrs', jsonb_build_object('storage_key', :'template_image_key')
        ))
      ))
    ),
    :'template_key', decode(:'template_sha', 'hex')
);
INSERT INTO documents (
    id, org_id, status, requires_signature, blocks_json,
    rendered_pdf_key, rendered_pdf_sha, pdf_storage_key, pdf_sha256,
    final_pdf_key, final_pdf_sha, audit_cert_key, audit_cert_sha256,
    audit_payload_key, audit_payload_sha256,
    audit_signature_key, audit_signature_sha256
) VALUES (
    :'document_id', :'org_id', 'completed', true,
    jsonb_build_object(
      'version', 1,
      'blocks', jsonb_build_array(jsonb_build_object(
        'id', 'document-container', 'type', 'callout',
        'content', jsonb_build_array(jsonb_build_object(
          'id', 'document-image', 'type', 'image',
          'attrs', jsonb_build_object('storage_key', :'document_image_key')
        ))
      ))
    ),
    :'rendered_key', decode(:'rendered_sha', 'hex'),
    :'source_key', decode(:'source_sha', 'hex'),
    :'final_key', decode(:'final_sha', 'hex'), :'audit_key', decode(:'audit_sha', 'hex'),
    :'audit_payload_key', decode(:'audit_payload_sha', 'hex'),
    :'audit_signature_key', decode(:'audit_signature_sha', 'hex')
);
-- Crash-consistent staged finalization: none of these four artifact identities
-- has reached documents yet. Recovery must discover them solely through the
-- durable intent or the exact bytes needed to resume would be omitted.
INSERT INTO documents (id, org_id, status, requires_signature)
VALUES (:'finalizing_document_id', :'org_id', 'finalizing', true);
INSERT INTO document_finalization_intents (
    document_id, org_id, mode,
    final_pdf_key, final_pdf_sha256,
    audit_cert_key, audit_cert_sha256,
    audit_payload_key, audit_payload_sha256,
    audit_signature_key, audit_signature_sha256
) VALUES (
    :'finalizing_document_id', :'org_id', 'signature',
    :'pending_final_key', decode(:'pending_final_sha', 'hex'),
    :'pending_audit_key', decode(:'pending_audit_sha', 'hex'),
    :'pending_payload_key', decode(:'pending_payload_sha', 'hex'),
    :'pending_signature_key', decode(:'pending_signature_sha', 'hex')
);
-- An envelope child inherits the parent's one terminal artifact/evidence set.
-- It must not become a second signed root in the canonical object inventory.
INSERT INTO documents (
    id, org_id, status, requires_signature, parent_envelope_id,
    final_pdf_key, final_pdf_sha, audit_cert_key, audit_cert_sha256,
    audit_payload_key, audit_payload_sha256,
    audit_signature_key, audit_signature_sha256
) VALUES (
    :'envelope_child_id', :'org_id', 'completed', true, :'document_id',
    :'final_key', decode(:'final_sha', 'hex'), :'audit_key', decode(:'audit_sha', 'hex'),
    :'audit_payload_key', decode(:'audit_payload_sha', 'hex'),
    :'audit_signature_key', decode(:'audit_signature_sha', 'hex')
);
-- A deleted draft deliberately retains its database row for the 90-day grace
-- period after its transient source/preview/tree objects have been removed.
-- The canonical recovery inventory must not report those absent objects as
-- lost evidence, while the completed agreement above remains fully covered.
INSERT INTO documents (
    id, org_id, status, requires_signature, deleted_at, blocks_json,
    rendered_pdf_key, rendered_pdf_sha, pdf_storage_key, pdf_sha256
) VALUES (
    'dddddddd-dddd-4ddd-8ddd-dddddddddddd', :'org_id', 'draft', true, now(),
    jsonb_build_object('blocks', jsonb_build_array(jsonb_build_object(
      'type', 'image',
      'attrs', jsonb_build_object('storage_key', 'org/deleted/assets/draft-image.png')
    ))),
    'org/deleted/documents/draft/rendered.pdf', decode(repeat('11', 32), 'hex'),
    'org/deleted/documents/draft/source.pdf', decode(repeat('22', 32), 'hex')
);
INSERT INTO document_versions (id, document_id, org_id, block_tree_json)
VALUES (
    :'version_id', :'document_id', :'org_id',
    jsonb_build_object(
      'version', 1,
      'blocks', jsonb_build_array(jsonb_build_object(
        'id', 'version-image', 'type', 'image',
        'attrs', jsonb_build_object('storage_key', :'version_image_key')
      ))
    )
);
INSERT INTO document_versions (id, document_id, org_id, block_tree_json)
VALUES (
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    'dddddddd-dddd-4ddd-8ddd-dddddddddddd', :'org_id',
    jsonb_build_object('blocks', jsonb_build_array(jsonb_build_object(
      'type', 'image',
      'attrs', jsonb_build_object('storage_key', 'org/deleted/assets/version-image.png')
    )))
);
INSERT INTO signatures (id, document_id, image_storage_key, image_sha256)
VALUES (:'signature_id', :'document_id', :'signature_key', decode(:'signature_sha', 'hex'));
INSERT INTO org_branding (org_id, logo_url)
VALUES (:'org_id', 'https://hash.invalid/branding/logo/' || :'org_id' || '.svg');
INSERT INTO document_branding_override (document_id, logo_url)
VALUES (:'document_id', '/branding/logo/' || :'org_id' || '.png');
INSERT INTO hash_restore_drill (document_id, status)
VALUES ('drill-document-1', 'completed');
SQL

quiesced_at="$(date -u +%FT%TZ)"
source_db_marker="$(docker exec -e PGPASSWORD="$DB_PASSWORD" "$pg_source" \
  psql --no-psqlrc --tuples-only --no-align --username "$DB_USER" --dbname "$DB_NAME" \
  --command "SELECT document_id || '|' || status || '|' || pg_current_wal_lsn()::text FROM hash_restore_drill;")"
[[ "$source_db_marker" == drill-document-1\|completed\|* ]] \
  || die "source database marker was not committed"

backup_started_epoch="$(date -u +%s)"
log "capturing coupled snapshot after synthetic writes were quiesced"
docker exec -e PGPASSWORD="$DB_PASSWORD" "$pg_source" \
  pg_dump --format=custom --compress=9 --no-owner --no-acl \
  --username "$DB_USER" --dbname "$DB_NAME" \
  > "$output_dir/snapshot/postgres.pgdump"
[[ -s "$output_dir/snapshot/postgres.pgdump" ]] || die "database dump is empty"
docker exec -i "$pg_source" pg_restore --list \
  < "$output_dir/snapshot/postgres.pgdump" >/dev/null
docker exec -i -e PGPASSWORD="$DB_PASSWORD" "$pg_source" \
  psql --no-psqlrc --set ON_ERROR_STOP=1 --tuples-only --no-align \
  --field-separator $'\t' --pset footer=off \
  --username "$DB_USER" --dbname "$DB_NAME" \
  < "$inventory_sql" > "$output_dir/snapshot/recovery-object-inventory.tsv"
inventory_count="$(wc -l < "$output_dir/snapshot/recovery-object-inventory.tsv" | tr -d ' ')"
[[ "$inventory_count" == "${#seed_keys[@]}" ]] \
  || die "canonical source inventory has $inventory_count objects; expected ${#seed_keys[@]}"
docker exec "$s3_source" mc mirror --overwrite \
  "source/$S3_BUCKET" /drill-output/snapshot/objects >/dev/null

for i in "${!seed_names[@]}"; do
  backup_object="$output_dir/snapshot/objects/${seed_keys[$i]}"
  [[ -f "$backup_object" ]] || die "snapshot is missing object: ${seed_keys[$i]}"
  [[ "$(sha256_file "$backup_object")" == "${seed_hashes[$i]}" ]] \
    || die "snapshot checksum mismatch: ${seed_keys[$i]}"
done

dump_sha256="$(sha256_file "$output_dir/snapshot/postgres.pgdump")"
{
  printf '%s  %s\n' "$dump_sha256" postgres.pgdump
  printf '%s  %s\n' "$(sha256_file "$output_dir/snapshot/recovery-object-inventory.tsv")" recovery-object-inventory.tsv
  for i in "${!seed_names[@]}"; do
    printf '%s  %s\n' "${seed_hashes[$i]}" "objects/${seed_keys[$i]}"
  done
} > "$output_dir/snapshot/SHA256SUMS"
backup_seconds=$(( $(date -u +%s) - backup_started_epoch ))

log "stopping source stores and restoring into independent volumes"
docker stop "$pg_source" "$s3_source" >/dev/null

restore_started_epoch="$(date -u +%s)"
start_postgres "$pg_restore_container" "$pg_restore_volume"
start_minio "$s3_restore" "$s3_restore_volume" ro
wait_for_minio "$s3_restore" recovery
docker exec "$s3_restore" mc mb --ignore-existing "recovery/$S3_BUCKET" >/dev/null
docker exec "$s3_restore" mc version enable "recovery/$S3_BUCKET" >/dev/null

docker exec -i -e PGPASSWORD="$DB_PASSWORD" "$pg_restore_container" \
  pg_restore --exit-on-error --single-transaction --no-owner --no-acl \
  --username "$DB_USER" --dbname "$DB_NAME" \
  < "$output_dir/snapshot/postgres.pgdump"
docker exec "$s3_restore" mc mirror --overwrite \
  /drill-output/snapshot/objects "recovery/$S3_BUCKET" >/dev/null

restored_row="$(docker exec -e PGPASSWORD="$DB_PASSWORD" "$pg_restore_container" \
  psql --no-psqlrc --tuples-only --no-align --field-separator '|' \
  --username "$DB_USER" --dbname "$DB_NAME" \
  --command 'SELECT document_id, status FROM hash_restore_drill;')"
IFS='|' read -r restored_id restored_status <<< "$restored_row"

[[ "$restored_id" == "drill-document-1" && "$restored_status" == "completed" ]] \
  || die "restored database marker is missing or corrupt"

docker exec -i -e PGPASSWORD="$DB_PASSWORD" "$pg_restore_container" \
  psql --no-psqlrc --set ON_ERROR_STOP=1 --tuples-only --no-align \
  --field-separator $'\t' --pset footer=off \
  --username "$DB_USER" --dbname "$DB_NAME" \
  < "$inventory_sql" > "$output_dir/restored/recovery-object-inventory.tsv"
cmp -s "$output_dir/snapshot/recovery-object-inventory.tsv" "$output_dir/restored/recovery-object-inventory.tsv" \
  || die "restored canonical object inventory differs from the source inventory"

for i in "${!seed_names[@]}"; do
  docker exec "$s3_restore" mc cat "recovery/$S3_BUCKET/${seed_keys[$i]}" \
    > "$output_dir/restored/${seed_names[$i]}"
  [[ "$(sha256_file "$output_dir/restored/${seed_names[$i]}")" == "${seed_hashes[$i]}" ]] \
    || die "restored object checksum mismatch: ${seed_keys[$i]}"
  cmp -s "$output_dir/seed/${seed_names[$i]}" "$output_dir/restored/${seed_names[$i]}" \
    || die "restored object differs byte-for-byte: ${seed_keys[$i]}"
done

inventory_verified=0
while IFS=$'\t' read -r key_b64 key_json classes owners org_ids expected_sha conflict legal refs expected_version version_conflict legacy_lookup; do
  [[ -n "$key_b64" ]] || continue
  key="$(printf '%s' "$key_b64" | decode_base64)" || die "invalid base64 key in canonical inventory"
  [[ "$conflict" == "f" ]] || die "canonical inventory contains a database hash conflict: $key_json"
  [[ "$version_conflict" == "f" ]] || die "canonical inventory contains a database VersionId conflict: $key_json"
  found_index=""
  for i in "${!seed_keys[@]}"; do
    if [[ "$key" == "${seed_keys[$i]}" ]]; then
      found_index="$i"
      break
    fi
  done
  [[ -n "$found_index" ]] || die "database inventory references an unexpected object: $key"
  if [[ "$expected_sha" != "-" && "$expected_sha" != "${seed_hashes[$found_index]}" ]]; then
    die "database hash differs from restored object hash: $key"
  fi
  case ",$classes," in
    *,document_final_pdf,*|*,document_audit_certificate,*|*,document_audit_payload,*|*,document_audit_signature,*)
      [[ ",$owners," != *",document:$ENVELOPE_CHILD_ID,"* ]] ||
        die "envelope child was inventoried as an independent legal root: $key"
      ;;
  esac
	case ",$classes," in
	  *,finalization_intent_final_pdf,*|*,finalization_intent_audit_certificate,*|*,finalization_intent_audit_payload,*|*,finalization_intent_audit_signature,*)
	    [[ ",$owners," == *",document_finalization_intent:$FINALIZING_DOCUMENT_ID,"* ]] ||
	      die "staged finalization object lacks its durable intent owner: $key"
	    ;;
	esac
  if [[ "$expected_sha" != "-" ]]; then
    [[ "$expected_version" == "-" && "$legacy_lookup" == "t" ]] ||
      die "legacy drill row did not preserve explicit bounded-lookup state: $key_json"
  fi
  inventory_verified=$((inventory_verified + 1))
done < "$output_dir/restored/recovery-object-inventory.tsv"
[[ "$inventory_verified" == "${#seed_keys[@]}" ]] \
  || die "verified $inventory_verified inventory objects; expected ${#seed_keys[@]}"

for pdf_name in template.pdf source.pdf rendered.pdf final.pdf audit.pdf pending-final.pdf pending-audit.pdf; do
  [[ "$(LC_ALL=C head -c 5 "$output_dir/restored/$pdf_name")" == '%PDF-' ]] \
    || die "restored $pdf_name artifact is not a PDF"
done

restored_object_count="$(docker exec "$s3_restore" mc ls --recursive "recovery/$S3_BUCKET" | wc -l | tr -d ' ')"
[[ "$restored_object_count" == "${#seed_keys[@]}" ]] \
  || die "restored bucket has $restored_object_count objects; expected ${#seed_keys[@]}"
restored_row_count="$(docker exec -e PGPASSWORD="$DB_PASSWORD" "$pg_restore_container" \
  psql --no-psqlrc --tuples-only --no-align --username "$DB_USER" --dbname "$DB_NAME" \
  --command 'SELECT count(*) FROM hash_restore_drill;')"
[[ "$restored_row_count" == "1" ]] || die "restored database row count mismatch"
restored_finalization_state="$(docker exec -e PGPASSWORD="$DB_PASSWORD" "$pg_restore_container" \
  psql --no-psqlrc --tuples-only --no-align --field-separator '|' \
  --username "$DB_USER" --dbname "$DB_NAME" \
  --command "SELECT d.status, count(i.*) FROM documents d LEFT JOIN document_finalization_intents i ON i.document_id = d.id WHERE d.id = '$FINALIZING_DOCUMENT_ID' GROUP BY d.status;")"
[[ "$restored_finalization_state" == "finalizing|1" ]] \
  || die "restored durable finalization intent is missing or corrupt"

restore_seconds=$(( $(date -u +%s) - restore_started_epoch ))
total_seconds=$(( $(date -u +%s) - total_started_epoch ))
completed_at="$(date -u +%FT%TZ)"

cat > "$output_dir/drill-report.txt" <<EOF
HASH_BACKUP_RESTORE_DRILL_VERSION=3
RESULT=PASS
RUN_ID=$run_id
STARTED_AT_UTC=$started_at
QUIESCED_AT_UTC=$quiesced_at
COMPLETED_AT_UTC=$completed_at
BACKUP_SECONDS=$backup_seconds
DATA_RESTORE_AND_VERIFY_SECONDS=$restore_seconds
TOTAL_SECONDS=$total_seconds
CONTROLLED_SNAPSHOT_DATA_LOSS_ROWS=0
CONTROLLED_SNAPSHOT_DATA_LOSS_OBJECTS=0
CONTROLLED_SNAPSHOT_RPO_SECONDS=0
RESTORED_DATABASE_ROWS=$restored_row_count
RESTORED_OBJECTS=$restored_object_count
CANONICAL_INVENTORY_OBJECTS=$inventory_verified
CANONICAL_INVENTORY_SHA256=$(sha256_file "$output_dir/restored/recovery-object-inventory.tsv")
POSTGRES_IMAGE=$POSTGRES_IMAGE
POSTGRES_IMAGE_ID=$postgres_image_id
MINIO_IMAGE=$MINIO_IMAGE
MINIO_IMAGE_ID=$minio_image_id
DATABASE_DUMP_SHA256=$dump_sha256
SOURCE_PDF_SHA256=${seed_hashes[1]}
FINAL_PDF_SHA256=${seed_hashes[3]}
AUDIT_CERT_SHA256=${seed_hashes[4]}
FINALIZING_INTENT_RESTORED=1
PENDING_FINAL_PDF_SHA256=${seed_hashes[13]}
PENDING_AUDIT_CERT_SHA256=${seed_hashes[14]}
DOCKER_CONTEXT=$context
DOCKER_ENDPOINT_SCHEME=$endpoint_scheme
EOF

log "PASS: canonical PostgreSQL inventory and all $restored_object_count S3 objects restored byte-for-byte"
printf 'Backup duration: %ss\n' "$backup_seconds"
printf 'Data restore + verification duration: %ss\n' "$restore_seconds"
printf 'Controlled quiesced-snapshot data loss: 0 rows, 0 objects\n'
printf 'Evidence retained at %s\n' "$output_dir"
