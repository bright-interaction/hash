#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Copyright (c) Bright Interaction
#
# Read-only verifier for an isolated Hash database + recovery bucket. It uses
# the canonical SQL inventory, verifies every referenced object and available
# DB hash, then classifies every bucket object that the recovered DB does not
# reference. It never deletes or modifies an object.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/verify-recovery-objects.sh --bucket BUCKET [options]

Required:
  --bucket BUCKET       isolated recovery bucket (never the damaged source)

Options:
  --database DBNAME     psql database/connection target; otherwise PG* applies
  --endpoint URL        S3-compatible recovery endpoint; omit for AWS default
  --output NEW_DIR      evidence directory; default is a new TMPDIR directory
  --self-test           validate object classification only; use no services
  -h, --help

Authentication is inherited from PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSFILE
and the standard AWS environment/config chain. The verifier performs only
SELECT, list, head, and get operations. It exits 1 for missing/hash-invalid
objects and 2 when unreferenced objects or recovered shadow versions require
operator review.
EOF
}

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

rfc3339_epoch() {
  local value="$1"
  jq -nr --arg value "$value" '
    $value
    | sub("\\+00:00$"; "Z")
    | sub("\\.[0-9]+Z$"; "Z")
    | fromdateiso8601
  '
}

seven_calendar_year_horizon_epoch() {
  local value="$1" normalized year suffix candidate
  normalized="$(jq -nr --arg value "$value" '
    $value | sub("\\+00:00$"; "Z") | sub("\\.[0-9]+Z$"; "Z")
  ')" || return 1
  [[ "$normalized" =~ ^([0-9]{4})(-[0-9]{2}-[0-9]{2}T.*Z)$ ]] || return 1
  year="${BASH_REMATCH[1]}"
  suffix="${BASH_REMATCH[2]}"
  candidate="$((10#$year + 7))$suffix"
  if rfc3339_epoch "$candidate" >/dev/null 2>&1; then
    rfc3339_epoch "$candidate"
    return
  fi
  # Go's time.AddDate, used by Hash retention writes, normalizes a leap-day
  # anniversary in a non-leap year to March 1.
  [[ "$suffix" == -02-29T* ]] || return 1
  candidate="$((10#$year + 7))-03-01T${suffix#-02-29T}"
  rfc3339_epoch "$candidate"
}

retention_is_sufficient() {
  local mode="$1" retain_until="$2" last_modified="$3"
  local actual_epoch horizon_epoch
  [[ "$mode" == "COMPLIANCE" ]] || return 1
  actual_epoch="$(rfc3339_epoch "$retain_until")" || return 1
  horizon_epoch="$(seven_calendar_year_horizon_epoch "$last_modified")" || return 1
  # PutEvidence derives retain-until immediately before the provider records
  # LastModified. Allow at most five minutes for upload and bounded clock skew;
  # a larger gap is not evidence of seven-calendar-year protection.
  ((actual_epoch >= horizon_epoch - 300))
}

decode_base64() {
  if [[ "$base64_decoder" == "gnu" ]]; then
    base64 --decode
  else
    base64 -D
  fi
}

classify_unreferenced() {
  local key="$1"
  if [[ "$key" =~ ^org/[^/]+/documents/[^/]+/(final|audit)-[[:xdigit:]]{64}\.pdf$ ]] ||
     [[ "$key" =~ ^org/[^/]+/documents/[^/]+/audit-(payload|signature)-[[:xdigit:]]{64}\.txt$ ]] ||
     [[ "$key" =~ ^org/[^/]+/documents/[^/]+/audit-[[:xdigit:]]{64}\.(payload|signature)\.txt$ ]]; then
    printf '%s' orphan_legal_document_evidence
    return
  fi
  case "$key" in
    org/*/documents/*/final.pdf|org/*/documents/*/audit.pdf|org/*/documents/*/audit.payload.txt|org/*/documents/*/audit.signature.txt)
      printf '%s' orphan_legal_document_evidence
      ;;
    org/*/signatures/*)
      printf '%s' orphan_signature_evidence
      ;;
    org/*/documents/*)
      printf '%s' orphan_document_asset
      ;;
    org/*/templates/*)
      printf '%s' orphan_template_asset
      ;;
    org/*/assets/*)
      printf '%s' orphan_block_tree_image
      ;;
    branding/*)
      printf '%s' orphan_branding_asset
      ;;
    *)
      printf '%s' unclassified_object
      ;;
  esac
}

is_unverified_audit_sidecar() {
  local classes="$1" expected_sha="$2"
  [[ "$expected_sha" == "-" ]] || return 1
  case ",$classes," in
    *,document_audit_payload,*|*,document_audit_signature,*|*,legacy_derived_audit_payload,*|*,legacy_derived_audit_signature,*)
      return 0
      ;;
  esac
  return 1
}

classifier_self_test() {
  local digest key expected actual
  digest="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  while IFS=$'\t' read -r key expected; do
    actual="$(classify_unreferenced "$key")"
    [[ "$actual" == "$expected" ]] ||
      die "classifier self-test: $key = $actual, want $expected"
  done <<EOF
org/o/documents/d/final-$digest.pdf	orphan_legal_document_evidence
org/o/documents/d/audit-$digest.pdf	orphan_legal_document_evidence
org/o/documents/d/audit-payload-$digest.txt	orphan_legal_document_evidence
org/o/documents/d/audit-signature-$digest.txt	orphan_legal_document_evidence
org/o/documents/d/audit-$digest.payload.txt	orphan_legal_document_evidence
org/o/documents/d/audit-$digest.signature.txt	orphan_legal_document_evidence
org/o/documents/d/final.pdf	orphan_legal_document_evidence
org/o/documents/d/audit.payload.txt	orphan_legal_document_evidence
org/o/documents/d/preview.png	orphan_document_asset
EOF
  is_unverified_audit_sidecar 'legacy_derived_audit_payload' '-' ||
    die 'classifier self-test: legacy payload without SHA must fail closed'
  is_unverified_audit_sidecar 'document_audit_signature,document_audit_payload' '-' ||
    die 'classifier self-test: modern sidecar without SHA must fail closed'
  if is_unverified_audit_sidecar 'document_audit_payload' "$digest"; then
    die 'classifier self-test: digest-bound sidecar was marked unverified'
  fi
  retention_is_sufficient COMPLIANCE '2031-03-01T12:00:00Z' '2024-02-29T12:00:00Z' ||
    die 'classifier self-test: valid seven-year leap-day retention was rejected'
  if retention_is_sufficient GOVERNANCE '2032-03-01T12:00:00Z' '2024-02-29T12:00:00Z'; then
    die 'classifier self-test: governance retention was accepted'
  fi
  if retention_is_sufficient COMPLIANCE '2031-02-28T11:50:00Z' '2024-02-28T12:00:00Z'; then
    die 'classifier self-test: short compliance retention was accepted'
  fi
}

bucket=""
database=""
endpoint=""
output_request=""
self_test=0
while (($# > 0)); do
  case "$1" in
    --bucket)
      (($# >= 2)) || die "--bucket requires a value"
      bucket="$2"
      shift 2
      ;;
    --database)
      (($# >= 2)) || die "--database requires a value"
      database="$2"
      shift 2
      ;;
    --endpoint)
      (($# >= 2)) || die "--endpoint requires a value"
      endpoint="$2"
      shift 2
      ;;
    --output)
      (($# >= 2)) || die "--output requires a directory"
      output_request="$2"
      shift 2
      ;;
    --self-test)
      self_test=1
      shift
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

if [[ "$self_test" == "1" ]]; then
  command -v jq >/dev/null 2>&1 || die "required command not found: jq"
  classifier_self_test
  printf '%s\n' 'recovery object classifier self-test: PASS'
  exit 0
fi

[[ -n "$bucket" ]] || die "--bucket is required"
for tool in psql aws jq awk sort comm base64 tr wc; do
  command -v "$tool" >/dev/null 2>&1 || die "required command not found: $tool"
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  die "sha256sum or shasum is required"
fi
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
  output_dir="$(mktemp -d "${TMPDIR:-/tmp}/hash-recovery-inventory.XXXXXX")"
fi
readonly output_dir

download_tmp="$(mktemp "${TMPDIR:-/tmp}/hash-recovery-object.XXXXXX")"
head_tmp="$(mktemp "${TMPDIR:-/tmp}/hash-recovery-head.XXXXXX")"
retention_tmp="$(mktemp "${TMPDIR:-/tmp}/hash-recovery-retention.XXXXXX")"
versions_tmp="$(mktemp "${TMPDIR:-/tmp}/hash-recovery-versions.XXXXXX")"
get_result_tmp="$(mktemp "${TMPDIR:-/tmp}/hash-recovery-get-result.XXXXXX")"
cleanup() {
  rm -f "$download_tmp" "$head_tmp" "$retention_tmp" "$versions_tmp" "$get_result_tmp"
}
trap cleanup EXIT INT TERM

psql_args=(psql --no-psqlrc --set ON_ERROR_STOP=1 --tuples-only --no-align --field-separator $'\t' --pset footer=off)
if [[ -n "$database" ]]; then
  psql_args+=(--dbname "$database")
fi
aws_args=(aws)
if [[ -n "$endpoint" ]]; then
  aws_args+=(--endpoint-url "$endpoint")
fi

inventory_tsv="$output_dir/db-object-inventory.tsv"
"${psql_args[@]}" --file "$inventory_sql" > "$inventory_tsv"

expected_keys="$output_dir/expected-keys.txt"
expected_detail="$output_dir/expected-object-detail.tsv"
hash_conflicts="$output_dir/hash-conflicts.tsv"
version_conflicts="$output_dir/version-conflicts.tsv"
missing="$output_dir/missing-referenced-objects.tsv"
hash_mismatches="$output_dir/hash-mismatches.tsv"
unverified_sidecars="$output_dir/unverified-audit-sidecars.tsv"
missing_legal_versions="$output_dir/legal-evidence-without-version.tsv"
verified_versions="$output_dir/verified-object-versions.tsv"
invalid_legal_retention="$output_dir/invalid-legal-evidence-retention.tsv"
verified_legal_retention="$output_dir/verified-legal-evidence-retention.tsv"
shadowed_references="$output_dir/shadowed-referenced-objects.tsv"
version_resolved_hidden_keys="$output_dir/version-resolved-hidden-keys.txt"
: > "$expected_keys"
: > "$expected_detail"
: > "$hash_conflicts"
: > "$version_conflicts"
: > "$missing"
: > "$hash_mismatches"
: > "$unverified_sidecars"
: > "$missing_legal_versions"
: > "$verified_versions"
: > "$invalid_legal_retention"
: > "$verified_legal_retention"
: > "$shadowed_references"
: > "$version_resolved_hidden_keys"

while IFS=$'\t' read -r key_b64 key_json classes owners org_ids expected_sha conflict legal refs expected_version version_conflict legacy_lookup; do
  [[ -n "$key_b64" ]] || continue
  key="$(printf '%s' "$key_b64" | decode_base64)" || die "invalid base64 object key in inventory"
  # Bash command substitution cannot preserve trailing newlines. Re-encoding
  # also rejects every other control-separated key that could corrupt reports.
  roundtrip="$(printf '%s' "$key" | base64 | tr -d '\r\n')"
  [[ "$roundtrip" == "$key_b64" ]] || die "object key cannot be represented safely: $key_json"
  case "$key" in
    *$'\n'*|*$'\r'*|*$'\t'*) die "object key contains a control separator: $key_json" ;;
  esac
  printf '%s\n' "$key" >> "$expected_keys"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$key" "$classes" "$owners" "$org_ids" "$expected_sha" "$legal" "$refs" \
    "$expected_version" "$version_conflict" "$legacy_lookup" >> "$expected_detail"
  if is_unverified_audit_sidecar "$classes" "$expected_sha"; then
    printf '%s\t%s\t%s\n' "$key" "$classes" "$owners" >> "$unverified_sidecars"
  fi
  if [[ "$conflict" == "t" ]]; then
    printf '%s\t%s\t%s\n' "$key" "$classes" "$owners" >> "$hash_conflicts"
  fi
  if [[ "$version_conflict" == "t" ]]; then
    printf '%s\t%s\t%s\n' "$key" "$classes" "$owners" >> "$version_conflicts"
  fi
done < "$inventory_tsv"
LC_ALL=C sort -u -o "$expected_keys" "$expected_keys"

while IFS=$'\t' read -r key classes owners org_ids expected_sha legal refs expected_version version_conflict legacy_lookup; do
  selected_version_id=""
  selected_last_modified=""
  latest_version_id=""
  latest_last_modified=""
  head_available=0
  shadow_reported=0
  actual_sha="-"

  # A conflicting or required-but-missing database pin has no unique legal
  # object identity. Never guess one from provider history.
  if [[ "$version_conflict" == "t" ]]; then
    continue
  fi

  if [[ "$expected_version" != "-" ]]; then
    # Modern rows are read directly by the exact VersionId committed in the
    # recovered database. No list operation is permitted on this path.
    selected_version_id="$expected_version"
    : > "$download_tmp"
    : > "$get_result_tmp"
    if ! "${aws_args[@]}" s3api get-object --bucket "$bucket" --key "$key" \
        --version-id "$selected_version_id" "$download_tmp" > "$get_result_tmp" 2>/dev/null; then
      printf '%s\t%s\tEXACT_VERSION_GET_FAILED:%s\n' \
        "$key" "$expected_sha" "$selected_version_id" >> "$hash_mismatches"
      continue
    fi
    returned_version_id="$(jq -r '.VersionId // empty' "$get_result_tmp" 2>/dev/null || true)"
    if [[ "$returned_version_id" != "$selected_version_id" ]]; then
      printf '%s\t%s\tEXACT_VERSION_GET_MISMATCH:%s\n' \
        "$key" "$expected_sha" "$selected_version_id" >> "$hash_mismatches"
      continue
    fi
    if [[ "$expected_sha" != "-" ]]; then
      actual_sha="$(sha256_file "$download_tmp")"
      if [[ "$actual_sha" != "$expected_sha" ]]; then
        printf '%s\t%s\t%s\n' "$key" "$expected_sha" "$actual_sha" >> "$hash_mismatches"
        continue
      fi
    fi
  else
    # Only explicitly legacy/unpinned database rows may resolve a digest from
    # bounded version history. Existence-only mutable assets use latest HEAD
    # and never enter the digest-history path.
    : > "$head_tmp"
    if "${aws_args[@]}" s3api head-object --bucket "$bucket" --key "$key" > "$head_tmp" 2>/dev/null; then
      head_available=1
      latest_version_id="$(jq -r '.VersionId // empty' "$head_tmp")"
      latest_last_modified="$(jq -r '.LastModified // empty' "$head_tmp")"
      selected_version_id="$latest_version_id"
      selected_last_modified="$latest_last_modified"
    elif [[ "$expected_sha" == "-" ]]; then
      printf '%s\t%s\t%s\t%s\n' "$key" "$classes" "$legal" "$owners" >> "$missing"
      continue
    fi

    if [[ "$expected_sha" != "-" ]]; then
      if [[ "$legacy_lookup" != "t" ]]; then
        printf '%s\t%s\tMISSING_VERSION_WITHOUT_LEGACY_MARKER\n' \
          "$key" "$expected_sha" >> "$hash_mismatches"
        continue
      fi
      if [[ "$head_available" == "1" ]]; then
        : > "$download_tmp"
        : > "$get_result_tmp"
        get_args=(s3api get-object --bucket "$bucket" --key "$key")
        if [[ -n "$latest_version_id" && "$latest_version_id" != "null" ]]; then
          get_args+=(--version-id "$latest_version_id")
        fi
        if "${aws_args[@]}" "${get_args[@]}" "$download_tmp" > "$get_result_tmp" 2>/dev/null; then
          returned_version_id="$(jq -r '.VersionId // empty' "$get_result_tmp" 2>/dev/null || true)"
          if [[ -n "$latest_version_id" && "$latest_version_id" != "null" && "$returned_version_id" != "$latest_version_id" ]]; then
            actual_sha="VERSION_ID_MISMATCH"
          else
            actual_sha="$(sha256_file "$download_tmp")"
          fi
        else
          actual_sha="DOWNLOAD_FAILED"
        fi
      else
        actual_sha="LATEST_NOT_HEADABLE"
      fi

      if [[ "$actual_sha" != "$expected_sha" ]]; then
        : > "$versions_tmp"
        if ! "${aws_args[@]}" s3api list-object-versions --no-paginate \
            --bucket "$bucket" --prefix "$key" --max-keys 101 > "$versions_tmp" 2>/dev/null; then
          printf '%s\t%s\tVERSION_LIST_FAILED\n' "$key" "$expected_sha" >> "$hash_mismatches"
          continue
        fi
        candidate_count="$(jq -r --arg key "$key" \
          '([(.Versions // [])[], (.DeleteMarkers // [])[]] | map(select(.Key == $key)) | length)' "$versions_tmp")"
        if [[ "$(jq -r '.IsTruncated // false' "$versions_tmp")" == "true" ]] || ((candidate_count > 100)); then
          printf '%s\t%s\tVERSION_SEARCH_EXCEEDS_100\n' "$key" "$expected_sha" >> "$hash_mismatches"
          continue
        fi
        selected_version_id=""
        selected_last_modified=""
        while IFS=$'\t' read -r candidate_version candidate_modified; do
          [[ -n "$candidate_version" && "$candidate_version" != "null" ]] || continue
          case "$candidate_version" in *$'\n'*|*$'\r'*|*$'\t'*) continue ;; esac
          : > "$download_tmp"
          : > "$get_result_tmp"
          if ! "${aws_args[@]}" s3api get-object --bucket "$bucket" --key "$key" \
              --version-id "$candidate_version" "$download_tmp" > "$get_result_tmp" 2>/dev/null; then
            continue
          fi
          returned_version_id="$(jq -r '.VersionId // empty' "$get_result_tmp" 2>/dev/null || true)"
          [[ "$returned_version_id" == "$candidate_version" ]] || continue
          candidate_sha="$(sha256_file "$download_tmp")"
          if [[ "$candidate_sha" == "$expected_sha" ]]; then
            selected_version_id="$candidate_version"
            selected_last_modified="$candidate_modified"
            actual_sha="$candidate_sha"
            break
          fi
        done < <(jq -r --arg key "$key" \
          '(.Versions // [])[] | select(.Key == $key) | [.VersionId, .LastModified] | @tsv' "$versions_tmp")
        if [[ -z "$selected_version_id" ]]; then
          printf '%s\t%s\t%s\n' "$key" "$expected_sha" "$actual_sha" >> "$hash_mismatches"
          continue
        fi
        shadow_reason="LATEST_BYTES_DID_NOT_MATCH_DB_COMMITMENT"
        if [[ "$head_available" == "0" ]]; then
          shadow_reason="LATEST_KEY_NOT_HEADABLE_MATCHING_VERSION_RECOVERED"
          printf '%s\n' "$key" >> "$version_resolved_hidden_keys"
        fi
        printf '%s\t%s\t%s\t%s\t%s\n' \
          "$key" "${latest_version_id:-UNAVAILABLE}" "$selected_version_id" "$expected_sha" "$shadow_reason" >> "$shadowed_references"
        shadow_reported=1
      fi
    fi
  fi

  # Re-HEAD the selected immutable version rather than trusting a mutable
  # latest HEAD or a version-list timestamp for retention calculations.
  if [[ -n "$selected_version_id" && "$selected_version_id" != "null" ]]; then
    : > "$head_tmp"
    if ! "${aws_args[@]}" s3api head-object --bucket "$bucket" --key "$key" \
        --version-id "$selected_version_id" > "$head_tmp" 2>/dev/null; then
      printf '%s\t%s\tEXACT_VERSION_HEAD_FAILED:%s\n' "$key" "$expected_sha" "$selected_version_id" >> "$hash_mismatches"
      continue
    fi
    exact_head_version="$(jq -r '.VersionId // empty' "$head_tmp")"
    exact_head_modified="$(jq -r '.LastModified // empty' "$head_tmp")"
    if [[ "$exact_head_version" != "$selected_version_id" || -z "$exact_head_modified" ]]; then
      printf '%s\t%s\tEXACT_VERSION_HEAD_MISMATCH:%s\n' "$key" "$expected_sha" "$selected_version_id" >> "$hash_mismatches"
      continue
    fi
    selected_last_modified="$exact_head_modified"
  fi

  if [[ "$legal" == "t" && ( -z "$selected_version_id" || "$selected_version_id" == "null" ) ]]; then
    printf '%s\t%s\t%s\n' "$key" "$classes" "$owners" >> "$missing_legal_versions"
  fi

  if [[ "$legal" == "t" && -n "$selected_version_id" && "$selected_version_id" != "null" ]]; then
    : > "$retention_tmp"
    if ! "${aws_args[@]}" s3api get-object-retention \
        --bucket "$bucket" --key "$key" --version-id "$selected_version_id" > "$retention_tmp" 2>/dev/null; then
      printf '%s\t%s\t%s\tRETENTION_READ_FAILED\n' "$key" "$classes" "$selected_version_id" >> "$invalid_legal_retention"
    else
      retention_mode="$(jq -r '.Retention.Mode // empty' "$retention_tmp")"
      retain_until="$(jq -r '.Retention.RetainUntilDate // empty' "$retention_tmp")"
      if ! retention_is_sufficient "$retention_mode" "$retain_until" "$selected_last_modified"; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$key" "$classes" "$selected_version_id" "${retention_mode:-MISSING}" "${retain_until:-MISSING}" "${selected_last_modified:-MISSING}" >> "$invalid_legal_retention"
      else
        required_epoch="$(seven_calendar_year_horizon_epoch "$selected_last_modified")"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$key" "$selected_version_id" "$retention_mode" "$retain_until" "$selected_last_modified" "$required_epoch" >> "$verified_legal_retention"
      fi
    fi
  fi

  # A logical-key HEAD is diagnostic only. Exact pinned reads above remain
  # authoritative even when a delete marker or hostile newer version hides
  # them, but that shadowing is retained as an operator-review finding.
  if [[ -n "$selected_version_id" && "$selected_version_id" != "null" ]]; then
    : > "$head_tmp"
    if ! "${aws_args[@]}" s3api head-object --bucket "$bucket" --key "$key" > "$head_tmp" 2>/dev/null; then
      if [[ "$shadow_reported" == "0" ]]; then
        printf '%s\t%s\t%s\t%s\t%s\n' \
          "$key" "$selected_version_id" "UNAVAILABLE" "$expected_sha" "PINNED_VERSION_HIDDEN_BY_LATEST_STATE" >> "$shadowed_references"
      fi
      printf '%s\n' "$key" >> "$version_resolved_hidden_keys"
    else
      latest_after_verify="$(jq -r '.VersionId // empty' "$head_tmp")"
      if [[ "$latest_after_verify" != "$selected_version_id" && "$shadow_reported" == "0" ]]; then
        printf '%s\t%s\t%s\t%s\t%s\n' \
          "$key" "$selected_version_id" "${latest_after_verify:-UNVERSIONED}" "$expected_sha" "LATEST_VERSION_DIFFERS_FROM_DB_PIN" >> "$shadowed_references"
      fi
    fi
  fi

  if [[ "$expected_sha" != "-" ]]; then
    [[ "$actual_sha" == "$expected_sha" ]] || {
      printf '%s\t%s\t%s\n' "$key" "$expected_sha" "$actual_sha" >> "$hash_mismatches"
      continue
    }
    printf '%s\t%s\t%s\n' "$key" "${selected_version_id:-UNVERSIONED}" "$actual_sha" >> "$verified_versions"
  fi
done < "$expected_detail"
: > "$download_tmp"
LC_ALL=C sort -u -o "$version_resolved_hidden_keys" "$version_resolved_hidden_keys"

bucket_raw="$output_dir/bucket-keys.json"
bucket_keys_b64="$output_dir/bucket-keys.b64"
bucket_keys="$output_dir/bucket-keys.txt"
"${aws_args[@]}" s3api list-objects-v2 --bucket "$bucket" --query 'Contents[].Key' --output json > "$bucket_raw"
jq -r '.[]? | @base64' "$bucket_raw" > "$bucket_keys_b64"
: > "$bucket_keys"
while IFS= read -r key_b64; do
  [[ -n "$key_b64" ]] || continue
  key="$(printf '%s' "$key_b64" | decode_base64)" || die "invalid base64 key in bucket listing"
  roundtrip="$(printf '%s' "$key" | base64 | tr -d '\r\n')"
  [[ "$roundtrip" == "$key_b64" ]] || die "bucket key cannot be represented safely"
  case "$key" in
    *$'\n'*|*$'\r'*|*$'\t'*) die "bucket key contains a control separator" ;;
  esac
  printf '%s\n' "$key" >> "$bucket_keys"
done < "$bucket_keys_b64"
current_bucket_count="$(wc -l < "$bucket_keys" | tr -d ' ')"
cat "$version_resolved_hidden_keys" >> "$bucket_keys"
LC_ALL=C sort -u -o "$bucket_keys" "$bucket_keys"
rm -f "$bucket_raw" "$bucket_keys_b64"

# A HEAD failure is already detailed above. The set comparison independently
# catches listing/permission inconsistencies and all bucket-only objects.
comm -23 "$expected_keys" "$bucket_keys" > "$output_dir/missing-from-bucket-inventory.txt"
comm -13 "$expected_keys" "$bucket_keys" > "$output_dir/unreferenced-bucket-keys.txt"

unreferenced_report="$output_dir/unreferenced-bucket-objects.tsv"
: > "$unreferenced_report"
while IFS= read -r key; do
  [[ -n "$key" ]] || continue
  printf '%s\t%s\n' "$(classify_unreferenced "$key")" "$key" >> "$unreferenced_report"
done < "$output_dir/unreferenced-bucket-keys.txt"

expected_count="$(wc -l < "$expected_keys" | tr -d ' ')"
recoverable_key_count="$(wc -l < "$bucket_keys" | tr -d ' ')"
missing_count="$(wc -l < "$missing" | tr -d ' ')"
listing_missing_count="$(wc -l < "$output_dir/missing-from-bucket-inventory.txt" | tr -d ' ')"
hash_mismatch_count="$(wc -l < "$hash_mismatches" | tr -d ' ')"
hash_conflict_count="$(wc -l < "$hash_conflicts" | tr -d ' ')"
version_conflict_count="$(wc -l < "$version_conflicts" | tr -d ' ')"
unverified_sidecar_count="$(wc -l < "$unverified_sidecars" | tr -d ' ')"
missing_legal_version_count="$(wc -l < "$missing_legal_versions" | tr -d ' ')"
invalid_legal_retention_count="$(wc -l < "$invalid_legal_retention" | tr -d ' ')"
shadowed_reference_count="$(wc -l < "$shadowed_references" | tr -d ' ')"
unreferenced_count="$(wc -l < "$unreferenced_report" | tr -d ' ')"

result="PASS"
exit_code=0
if ((missing_count > 0 || listing_missing_count > 0 || hash_mismatch_count > 0 || hash_conflict_count > 0 || version_conflict_count > 0 || unverified_sidecar_count > 0 || missing_legal_version_count > 0 || invalid_legal_retention_count > 0)); then
  result="FAIL"
  exit_code=1
elif ((unreferenced_count > 0 || shadowed_reference_count > 0)); then
  result="REVIEW"
  exit_code=2
fi

cat > "$output_dir/recovery-object-verification-report.txt" <<EOF
HASH_RECOVERY_OBJECT_VERIFIER_VERSION=5
RESULT=$result
VERIFIED_AT_UTC=$(date -u +%FT%TZ)
EXPECTED_DB_OBJECTS=$expected_count
BUCKET_OBJECTS=$current_bucket_count
RECOVERABLE_VERSION_KEYS=$recoverable_key_count
MISSING_HEAD_OBJECTS=$missing_count
MISSING_FROM_BUCKET_INVENTORY=$listing_missing_count
HASH_MISMATCHES=$hash_mismatch_count
DB_HASH_CONFLICTS=$hash_conflict_count
DB_VERSION_ID_CONFLICTS=$version_conflict_count
UNVERIFIED_AUDIT_SIDECARS=$unverified_sidecar_count
LEGAL_EVIDENCE_WITHOUT_VERSION=$missing_legal_version_count
INVALID_LEGAL_EVIDENCE_RETENTION=$invalid_legal_retention_count
SHADOWED_REFERENCED_OBJECTS=$shadowed_reference_count
UNREFERENCED_BUCKET_OBJECTS=$unreferenced_count
RECOVERY_BUCKET=$bucket
RECOVERY_ENDPOINT=${endpoint:-AWS_DEFAULT}
EOF

printf 'Recovery object verification: %s\n' "$result"
printf 'DB references: %s; bucket objects: %s; missing: %s; hash mismatches: %s; unreferenced: %s\n' \
  "$expected_count" "$current_bucket_count" "$missing_count" "$hash_mismatch_count" "$unreferenced_count"
printf 'Evidence retained at %s\n' "$output_dir"
exit "$exit_code"
