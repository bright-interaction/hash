#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Copyright (c) Bright Interaction
#
# Upload the exact staging-tested images.tar to a separate immutable vault,
# read back that exact VersionId, verify its bytes and COMPLIANCE retention,
# and atomically write the non-secret gate consumed by deploy-hash-prod.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/prepare-release-backup-gate.sh \
  --release-dir DIR --endpoint HTTPS_URL --bucket BUCKET \
  --failure-domain DESCRIPTION --approved-by NAME --output NEW_FILE

Standard AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN and region
environment variables select the dedicated release-vault writer. Do not use
the Hash runtime S3 principal. AWS CLI v2 and GNU date are required on the
Linux release host. The output must not already exist.
EOF
}

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

release_dir=""
endpoint=""
bucket=""
failure_domain=""
approved_by=""
output=""
while (($# > 0)); do
  case "$1" in
    --release-dir) (($# >= 2)) || die '--release-dir requires a value'; release_dir=$2; shift 2 ;;
    --endpoint) (($# >= 2)) || die '--endpoint requires a value'; endpoint=$2; shift 2 ;;
    --bucket) (($# >= 2)) || die '--bucket requires a value'; bucket=$2; shift 2 ;;
    --failure-domain) (($# >= 2)) || die '--failure-domain requires a value'; failure_domain=$2; shift 2 ;;
    --approved-by) (($# >= 2)) || die '--approved-by requires a value'; approved_by=$2; shift 2 ;;
    --output) (($# >= 2)) || die '--output requires a value'; output=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

for tool in aws jq awk date wc; do
  command -v "$tool" >/dev/null 2>&1 || die "required command not found: $tool"
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  die 'sha256sum or shasum is required'
fi
[[ -d "$release_dir" ]] || die 'release directory does not exist'
case "$endpoint" in
  https://?*) ;;
  *) die 'release-vault endpoint must be an absolute HTTPS URL' ;;
esac
endpoint_rest="${endpoint#https://}"
endpoint_authority="${endpoint_rest%%/*}"
[[ -n "$endpoint_authority" ]] || die 'release-vault endpoint has no authority'
case "$endpoint" in
  *'@'*|*'?'*|*'#'*|*$'\n'*|*$'\r'*|*$'\t'*|*' '*)
    die 'release-vault endpoint must not contain credentials, query, fragment, or whitespace'
    ;;
esac
[[ -n "$bucket" && "$bucket" != *'<'* && "$bucket" != *'>'* ]] || die 'invalid release-vault bucket'
[[ -n "$failure_domain" && "$failure_domain" != *'<'* && "$failure_domain" != *'>'* ]] || die 'real failure-domain description is required'
[[ -n "$approved_by" && "$approved_by" != *'<'* && "$approved_by" != *'>'* ]] || die 'named approver is required'
case "$failure_domain$approved_by$bucket" in *$'\n'*|*$'\r'*|*$'\t'*) die 'control characters are not allowed' ;; esac
[[ -n "$output" ]] || die '--output is required'
[[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]] \
  || die 'dedicated release-vault AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required'
[[ -n "${AWS_REGION:-}" || -n "${AWS_DEFAULT_REGION:-}" ]] \
  || die 'dedicated release-vault AWS_REGION or AWS_DEFAULT_REGION is required'
if [[ -n "${AWS_REGION:-}" && -n "${AWS_DEFAULT_REGION:-}" && "$AWS_REGION" != "$AWS_DEFAULT_REGION" ]]; then
  die 'AWS_REGION and AWS_DEFAULT_REGION conflict'
fi
# Do not let a deployment-host profile, role selector, metadata endpoint, or
# endpoint override replace the explicitly injected release-vault principal.
unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN \
  AWS_ROLE_SESSION_NAME AWS_CONTAINER_CREDENTIALS_RELATIVE_URI \
  AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_EC2_METADATA_SERVICE_ENDPOINT \
  AWS_ENDPOINT_URL AWS_ENDPOINT_URL_S3 AWS_CA_BUNDLE
export AWS_CONFIG_FILE=/dev/null
export AWS_SHARED_CREDENTIALS_FILE=/dev/null
export AWS_EC2_METADATA_DISABLED=true
export AWS_CLI_AUTO_PROMPT=off
export AWS_PAGER=
export AWS_RETRY_MODE=standard
export AWS_MAX_ATTEMPTS=3
date -u -d '@0' +%s >/dev/null 2>&1 \
  || die 'GNU date is required on the Linux release host'
output_parent="$(dirname "$output")"
[[ -d "$output_parent" ]] || die 'output parent does not exist'
output_parent="$(cd "$output_parent" && pwd -P)"
output="$output_parent/$(basename "$output")"
[[ ! -e "$output" ]] || die 'output gate already exists'

manifest="$release_dir/manifest.json"
archive="$release_dir/images.tar"
[[ -f "$manifest" && ! -L "$manifest" ]] || die 'release manifest must be a regular file'
[[ -f "$archive" && ! -L "$archive" ]] || die 'release archive must be a regular file'
[[ "$(jq -er .schema_version "$manifest")" == 3 ]] || die 'release manifest schema is not supported'
commit="$(jq -er .commit_sha "$manifest")"
[[ "$commit" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || die 'release manifest commit is invalid'
archive_sha="$(jq -er .image_archive_sha256 "$manifest")"
[[ "$archive_sha" =~ ^[0-9a-f]{64}$ ]] || die 'release manifest archive digest is invalid'
archive_bytes="$(jq -er .image_archive_bytes "$manifest")"
[[ "$archive_bytes" =~ ^[1-9][0-9]*$ ]] || die 'release manifest archive size is invalid'
[[ "$(sha256_file "$archive")" == "$archive_sha" ]] || die 'local archive digest does not match manifest'
[[ "$(wc -c < "$archive" | tr -d ' ')" == "$archive_bytes" ]] || die 'local archive size does not match manifest'

aws_args=(aws --endpoint-url "$endpoint" --output json --no-cli-pager \
  --cli-connect-timeout 10 --cli-read-timeout 30 s3api)
versioning="$("${aws_args[@]}" get-bucket-versioning --bucket "$bucket")"
[[ "$(jq -er .Status <<<"$versioning")" == Enabled ]] || die 'release-vault bucket versioning is not enabled'
lock_config="$("${aws_args[@]}" get-object-lock-configuration --bucket "$bucket")"
[[ "$(jq -er .ObjectLockEnabled <<<"$lock_config")" == Enabled ]] || die 'release-vault bucket Object Lock is not enabled'

backup_key="hash-releases/$commit/images-$archive_sha.tar"
retain_until="$(date -u -d '+7 years +1 day' +%FT%TZ)"
put_result="$("${aws_args[@]}" put-object \
  --bucket "$bucket" --key "$backup_key" --body "$archive" \
  --object-lock-mode COMPLIANCE --object-lock-retain-until-date "$retain_until")"
version_id="$(jq -er .VersionId <<<"$put_result")"
[[ -n "$version_id" && "$version_id" != null ]] || die 'provider did not return an immutable VersionId'

umask 077
readback="$(mktemp "${TMPDIR:-/tmp}/hash-release-readback.XXXXXX")"
gate_tmp="$(mktemp "$output_parent/.hash-release-backup-gate.XXXXXX")"
cleanup() { rm -f "$readback" "$gate_tmp"; }
trap cleanup EXIT INT TERM

head_result="$("${aws_args[@]}" head-object --bucket "$bucket" --key "$backup_key" --version-id "$version_id")"
[[ "$(jq -er .VersionId <<<"$head_result")" == "$version_id" ]] || die 'exact-version HEAD returned a different VersionId'
[[ "$(jq -er .ContentLength <<<"$head_result")" == "$archive_bytes" ]] || die 'remote archive size does not match manifest'
[[ "$(jq -er .ObjectLockMode <<<"$head_result")" == COMPLIANCE ]] || die 'exact remote version is not COMPLIANCE locked'
last_modified="$(jq -er .LastModified <<<"$head_result")"
head_retain_until="$(jq -er .ObjectLockRetainUntilDate <<<"$head_result")"

get_result="$("${aws_args[@]}" get-object --bucket "$bucket" --key "$backup_key" \
  --version-id "$version_id" "$readback")"
[[ "$(jq -er .VersionId <<<"$get_result")" == "$version_id" ]] || die 'readback returned a different VersionId'
readback_sha="$(sha256_file "$readback")"
[[ "$readback_sha" == "$archive_sha" ]] || die 'remote exact-version readback digest mismatch'
[[ "$(wc -c < "$readback" | tr -d ' ')" == "$archive_bytes" ]] || die 'remote exact-version readback size mismatch'

retention_result="$("${aws_args[@]}" get-object-retention --bucket "$bucket" --key "$backup_key" --version-id "$version_id")"
[[ "$(jq -er .Retention.Mode <<<"$retention_result")" == COMPLIANCE ]] || die 'exact remote version retention is not COMPLIANCE'
verified_retain_until="$(jq -er .Retention.RetainUntilDate <<<"$retention_result")"
verified_at="$(date -u +%FT%TZ)"
required_from_object="$(date -u -d "$last_modified +7 years" +%s)"
verified_retain_epoch="$(date -u -d "$verified_retain_until" +%s)"
head_retain_epoch="$(date -u -d "$head_retain_until" +%s)"
[[ "$head_retain_epoch" -ge "$required_from_object" ]] \
  || die 'exact-version HEAD retention is shorter than seven calendar years from upload'
[[ "$verified_retain_epoch" -ge "$required_from_object" ]] \
  || die 'exact remote version retention is shorter than seven calendar years from upload'
[[ "$verified_retain_epoch" -ge "$(date -u -d "$verified_at +7 years" +%s)" ]] \
  || die 'exact remote version retention is shorter than seven calendar years'
[[ "$verified_retain_epoch" -ge "$head_retain_epoch" ]] \
  || die 'retention API returned an earlier horizon than exact-version HEAD'

jq -n \
  --arg commit "$commit" \
  --arg archive_sha "$archive_sha" \
  --argjson archive_bytes "$archive_bytes" \
  --arg backup_uri "s3://$bucket/$backup_key" \
  --arg version_id "$version_id" \
  --arg retain_until "$verified_retain_until" \
  --arg readback_sha "$readback_sha" \
  --arg failure_domain "$failure_domain" \
  --arg verified_at "$verified_at" \
  --arg approved_by "$approved_by" \
  '{schema_version:3,commit_sha:$commit,image_archive_sha256:$archive_sha,
    image_archive_bytes:$archive_bytes,backup_uri:$backup_uri,
    backup_object_version:$version_id,bucket_versioning_status:"Enabled",
    bucket_object_lock_enabled:true,object_lock_mode:"COMPLIANCE",
    retain_until:$retain_until,remote_readback_sha256:$readback_sha,
    failure_domain:$failure_domain,immutable_copy_verified:true,
    verified_at:$verified_at,approved_by:$approved_by}' > "$gate_tmp"
chmod 0600 "$gate_tmp"
mv "$gate_tmp" "$output"
trap - EXIT INT TERM
rm -f "$readback"
printf 'Release archive gate created for %s at %s\n' "$commit" "$output"
