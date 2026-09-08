# Hash backup and disaster-recovery runbook

Hash has two coupled durable stores: PostgreSQL holds workflow and audit state;
S3 holds uploads, final PDFs, audit certificates, and evidence artifacts. A
database-only restore is not a usable restore. Treat the database, object
versions, deployment image, and cryptographic configuration as one recovery
set.

## Recovery objectives

The production targets are:

| Objective | Target | Required mechanism |
|---|---:|---|
| Recovery point objective (RPO) | 15 minutes | PostgreSQL continuous WAL/PITR plus versioned, replicated object storage |
| Recovery time objective (RTO) | 4 hours | Automated provisioning, documented restore, and quarterly drills |
| PITR window | 35 days | Encrypted base backups and continuous WAL archive in a separate failure domain |
| Logical backup retention | 35 daily, 12 monthly | Encrypted custom-format `pg_dump` copies |

These are engineering targets, not a measured SLA, until a timed restore drill
has met them. Record actual data-loss window and elapsed recovery time after
every drill or incident. Customer/legal retention for signed agreements is a
separate policy; expiring backup generations must never be used to shorten it.

## Required production controls

Before Sales Partner data is accepted, verify all of the following:

- PostgreSQL has encrypted automated base backups and continuous WAL archiving,
  with restore-to-time enabled and alerts for a stopped archive stream.
- The Hash S3 bucket itself has versioning and Object Lock enabled, and every
  signed-agreement, audit, and evidence-object version is protected for at
  least seven years by compliance-mode Object Lock (not governance mode). This
  is a fail-closed boot and launch requirement, not an optional provider
  feature. Independently replicate the protected versions to an immutable
  vault in a separate account/project and failure domain, and alert on
  replication lag greater than 15 minutes.
- Verify through the provider API and a sacrificial retained object that the
  application principal cannot shorten retention, bypass the lock, or
  permanently delete protected versions; retain the API response and denied
  delete attempt as launch evidence. Verify the active versioning, retention,
  replication, and lifecycle rules after every storage-policy change. Lifecycle
  expiry may prune backup generations only after legal retention expires and
  must never be the control that promises seven-year preservation.
- The runtime app principal has `GetObjectLockConfiguration`,
  `PutObjectRetention`, `GetObjectRetention`, `ListBucketVersions`,
  `GetObjectVersion`, and its necessary object read/write permissions, but no
  governance-bypass or bucket-policy authority. Current records read and retain
  only their database-pinned VersionId. Version listing is reserved for an
  explicitly legacy row whose VersionId is NULL, and any resolved legacy pin is
  persisted before the lifecycle continues.
  Hash checks bucket Object Lock during server/worker startup and reads each
  evidence object's seven-calendar-year COMPLIANCE retention back after write;
  missing support or permissions is a hard failure.
- Record the exact estate object-store product, version/image digest, security
  support status, and compensating controls with every launch/recovery review.
  The local/CI MinIO `RELEASE.2025-09-07T16-13-09Z` drill pin is not a
  production-security attestation: that line is affected by
  `GHSA-xh8f-g2qw-gcm7`, and the later 2025-10-15 MinIO release also addressed
  a privilege-escalation CVE. Before partner launch the estate service must be
  on a vendor-supported, non-affected release with the advisory path tested,
  isolated behind least-privilege credentials and network policy, or replaced
  by a supported S3 service. A synthetic backup pass does not mitigate an
  object-store vulnerability.
- Daily logical database dumps and a daily object inventory are copied to the
  backup account. Backup jobs emit success, byte count, and newest recoverable
  timestamp; absence of a success signal alerts.
- Backup encryption keys and the secret-manager recovery procedure are held by
  at least two authorised operators. Backups are never written to the same
  host, database cluster, or object-store account as production.
- Secret-manager history protects `HASH_AUDIT_PRIVATE_KEY`,
  `HASH_SIGNER_TOKEN_KEY`, `HASH_SESSION_KEY`,
  `HASH_WEBHOOK_ENCRYPTION_KEY` (and its previous value while any retained
  database backup needs it), legacy webhook secrets, OIDC settings, and storage
  credentials. A database restore containing webhook endpoints is unusable
  without its matching webhook encryption key; do not substitute a newly
  generated key. Backups captured before the encrypted-secret cutover may
  contain legacy webhook plaintext and require the same restricted access and
  verified expiry/disposal as other credential-bearing backups. Preserve the non-secret
  `HASH_AUDIT_TRUSTED_PUBLIC_KEYS` rotation set with recovery configuration so
  retired-issuer ceremony certificates remain verifiable. Retired keys do not
  have authority to sign a fresh evidence-export manifest; only the recovered
  current signer does. Do not put `.env` in a database or S3 backup.
- Every staged release contains `images.tar`, a portable `docker image save`
  archive holding the exact tested Hash and Gotenberg content IDs, with its
  SHA-256, byte length, and lifecycle contract bound into manifest schema v3.
  Before production cutover that archive
  is copied to COMPLIANCE-locked storage in a separate account/failure domain,
  downloaded, checksum-verified, and recorded in the private release-backup
  gate. A local tag, pin container, or image ID alone is not a backup. Restore
  the matching images first; upgrade only after recovery verification.

### Exact-VersionId launch gate

The release archive gate records and always uses its exact S3 VersionId. Hash
now persists exact VersionIds for current source, rendered, final, certificate,
payload, detached-signature, signature-span, finalization-intent, and inherited
envelope artifacts. Digest-history search is limited to explicitly legacy rows
with a NULL VersionId, which are upgraded before send/finalization continues.
Do not clear the Sales Partner launch gate until the combined migration,
provider, inventory, and restore gates pass. The provider drill must prove that
more than 100 newer shadows cannot strand a current pinned artifact, while an
over-limit legacy lookup fails closed and is routed to remediation.

Grant the backup principal read-only access to the production bucket and only
the PostgreSQL privileges needed for backup. Grant the restore principal write
access only to a newly created recovery database and recovery bucket.

For an SSE-C bucket, retain the historical 32-byte raw key with the recovery
set in a separate secret manager and mount it read-only into each recovery job.
Every invocation of `scripts/verify-recovery-objects.sh` must add
`--sse-c-key-file "$HASH_RECOVERY_S3_SSE_C_KEY_FILE"` (use the corresponding
source-key path when verifying the source bucket). The verifier supplies that
file with `fileb://` on every GET and HEAD, so arbitrary binary bytes do not
enter an environment value or process argument. It rejects non-HTTPS custom
endpoints and files that are not exactly 32 bytes. Never enable shell tracing
around an SSE-C recovery job.

## Dedicated Hetzner Storage Box cold recovery snapshot

A Hetzner Storage Box is a valid encrypted **cold backup destination**, not a
replacement for Hash's S3 object store. Hash depends on provider VersionIds,
exact-version reads, versioning, SSE, and per-version COMPLIANCE Object Lock.
SFTP, WebDAV, SMB, and a filesystem mounted below MinIO do not implement that
contract. Keep live Hash on a tested S3 backend and use
`scripts/storagebox-cold-backup.sh` only as an operator-started DR copy.

The ordinary Dockyard nightly backup intentionally continues to exclude
`*/minio_minio-data/**`. Removing that exclusion would race a running MinIO and
would produce a PostgreSQL and object-store generation captured at different
times. The dedicated workflow instead:

1. validates the exact running Hash release, app/worker and Gotenberg images,
   MinIO image, Docker volume mount, and pinned Storage Box Restic repository;
2. requires a less-than-24-hour maintenance receipt confirming ingress is
   drained and every consumer of the shared MinIO is quiesced;
3. requires a fresh non-secret rotation receipt proving the Restic decryption
   password, every MinIO object-decryption key, and the Hash audit,
   signer-token, session, webhook-encryption, and AI-shield key sets are held in
   a different failure domain from the Storage Box data repository;
4. archives the exact Hash/Gotenberg release plus the exact MinIO and
   PostgreSQL images before downtime;
5. stops the worker and app, captures the canonical object inventory before and
   after one custom-format PostgreSQL dump, and rejects a changed inventory;
6. gracefully stops MinIO and rejects any remaining running volume consumer;
7. sends the private staging set and the **entire** MinIO data root, including
   `.minio.sys`, to one Restic `backup` invocation with no exclusions; and
8. restarts MinIO, the app, and the worker in dependency order even when a
   dump, snapshot, or verification fails. It then proves required paths exist
   in the new snapshot and runs a repository data-subset check.

The whole MinIO volume is necessary: `.minio.sys` contains the provider's
versioning/Object-Lock metadata, while PostgreSQL stores the exact VersionIds
that Hash reads. `mc mirror`, `aws s3 sync`, copying only bucket objects, or
re-uploading bytes assigns different versions and is not a recovery mechanism
for current records. The workflow deliberately has no exclude option. Do not
exclude an old Restic bucket from this volume merely because its name looks
obsolete; removal or exclusion needs separate evidence that the repository has
already been restored from the Storage Box, is no longer referenced, and does
not share data with Hash.

### Provision and preflight

Copy, fill, and lock down the three reviewed JSON templates alongside the
existing root-only Restic environment file. Every container name, volume path,
digest, and database identity must come from read-only inspection of the target
host; the examples intentionally contain invalid placeholders. The state
directory must already exist, be owned by the invoking operator, and have mode
`0700`. All four JSON/env files must be regular non-symlink files owned by that
operator with no group/other permissions.

```bash
install -d -m 0700 /var/lib/hash-storagebox-cold-backup /etc/hash-backup
install -m 0600 ops/storagebox-cold-backup.config.example.json \
  /etc/hash-backup/storagebox-cold-backup.json
install -m 0600 ops/storagebox-maintenance-receipt.example.json \
  /etc/hash-backup/maintenance.json
install -m 0600 ops/storagebox-key-escrow-receipt.example.json \
  /etc/hash-backup/key-escrow.json
```

The configuration accepts either the direct `RESTIC_REPOSITORY` /
`RESTIC_PASSWORD` pair or the matching `OFFSITE_RESTIC_REPOSITORY` /
`OFFSITE_RESTIC_PASSWORD` pair from the existing root-only env file. It parses
only those selected literal assignments; it never sources the file. The
repository must be an `sftp:` URL under `*.your-storagebox.de`, must already be
initialised, and must match the configured SHA-256 fingerprint. Compute the
fingerprint without printing the repository URI:

```bash
repo_uri="$(sed -n 's/^RESTIC_REPOSITORY=//p' /etc/dockyard-backup/restic.env)"
test -n "$repo_uri"
printf %s "$repo_uri" | sha256sum
unset repo_uri
```

In the same trace-disabled root shell, export the URI and password only as
environment variables, run `restic cat config | jq -er .id`, record the
64-character ID in `restic.config_id`, and immediately unset both values. The
script will neither initialise a repository nor accept a different config ID.

Pin the SHA-256 of the exact `recovery-object-inventory.sql` and
`verify-recovery-objects.sh` installed with the deployed release. Never point
the configuration at a mutable checkout without updating and reviewing both
digests. Likewise, derive the MinIO content ID from `docker inspect`; a tag is
not accepted. If `/opt/hash/current/manifest.json` is absent, the release store
is incomplete and this workflow correctly refuses to run rather than guessing
which source, schema, or image belongs to the data.

The key-escrow receipt contains versioned key-set/manifest references only,
never key values. Its `data_repository_sha256` must equal the configured
Storage Box repository fingerprint; `escrow_system_identity_sha256` must be
different. Its review must be less than 24 hours old and attest that rotation
state was reviewed and every key version needed by this snapshot is covered.
That includes the non-reissuable Restic repository password, every MinIO KMS or
historical SSE-C key needed to decrypt retained object versions, and
`HASH_WEBHOOK_ENCRYPTION_KEY_PREVIOUS` while retained rows still require it.
The AI-shield reference may point to a separately reviewed not-configured
record when no AI provider was enabled at capture time. Operational Storage Box
login credentials are reissuable through the separately tested account
recovery procedure; they are not treated as object-decryption keys. Keep the
actual key sets in the named break-glass system. Do not put them,
`/opt/hash/.env`, a MinIO env file, or the Restic password in this snapshot.

Run the read-only checks and a no-mutation rehearsal first:

```bash
scripts/storagebox-cold-backup.sh status \
  --config /etc/hash-backup/storagebox-cold-backup.json

scripts/storagebox-cold-backup.sh preflight \
  --config /etc/hash-backup/storagebox-cold-backup.json \
  --maintenance-receipt /etc/hash-backup/maintenance.json \
  --key-escrow-receipt /etc/hash-backup/key-escrow.json

scripts/storagebox-cold-backup.sh backup --dry-run \
  --config /etc/hash-backup/storagebox-cold-backup.json \
  --maintenance-receipt /etc/hash-backup/maintenance.json \
  --key-escrow-receipt /etc/hash-backup/key-escrow.json
```

Only inside the approved window, after observing the same preflight output, run
the command again without `--dry-run`. Record the full snapshot ID printed on
success and retain the root-only local receipt. A leftover
`.hash-cold-backup.lock` is not removed automatically after an uncatchable host
crash; inspect running processes and container state before removing it.

Restic encryption protects confidentiality in transit and at rest, but a
Storage Box repository and Storage Box snapshots are mutable by an account that
holds their credentials. This cold copy does not satisfy the independent
COMPLIANCE-locked archive control by itself, and its retention must never be
used to shorten the legal retention of signed evidence.

### Storage-Box-only isolated restore drill

Perform this drill on a disposable host/network with no route to production.
Assume the original Hash host, local MinIO, local registry cache, and Git remote
are unavailable. The allowed inputs are the selected Storage Box Restic
snapshot, the separately escrowed break-glass material, and base OS tooling
(`restic`, Docker, `jq`, `psql`, and AWS CLI). Do not restore onto an existing
Docker volume or database.

1. Recover or reissue Storage Box access and recover the Restic decryption
   password from the separate escrow system into a root-only file on a tmpfs.
   Disable shell tracing, list snapshots by the `hash-cold-backup` and exact
   `release:<commit>` tags, and select the recorded full snapshot ID.
   Confirm the Restic config ID and repository-URI fingerprint match the local
   backup receipt. Run `restic check` before restore.
2. Restore the selected snapshot into a new empty `0700` directory. Find the
   single `metadata/backup-manifest.json`, require schema 1,
   `whole_minio_volume=true`, `exclusions=[]`, and
   `minio_sys_present=true`, then run `sha256sum --check SHA256SUMS` from that
   snapshot's staging root. Require exactly one restored MinIO data root at the
   manifest-recorded suffix and confirm its `.minio.sys` directory exists.
3. Load `release/images.tar`, `images/minio-image.tar`, and
   `images/postgres-image.tar`. Inspect the loaded content IDs and require exact
   equality with the manifest. Do not pull a tag or rebuild source as a
   substitute.
4. Recover every MinIO object-decryption key set and the other named Hash key
   sets from the separate escrow system into root-only files on a tmpfs outside
   the Restic restore directory. This includes every historical KMS/SSE-C key
   referenced by a retained version, not merely the key current at backup time.
   Create fresh recovery-only MinIO root credentials; those access credentials
   are reissuable, while the captured objects' decryption keys are not. Never
   print a key value or pass one as a command-line argument.
5. Start the archived PostgreSQL image and exact MinIO image on a new private
   Docker network. Bind-mount only the newly restored MinIO data root at the
   recorded destination. Publish MinIO, if needed for the verifier, on a
   loopback-only port. Keep ingress, SMTP, webhooks, CRM calls, and
   `hash-worker` disabled.
6. Create an empty recovery database and restore
   `postgresql/hash.pgdump` with `pg_restore --exit-on-error
   --single-transaction --no-owner --no-acl`. Run the restored
   `tools/ops/recovery-object-inventory.sql` against it with `ON_ERROR_STOP=1`
   and compare the result byte-for-byte to
   `postgresql/recovery-object-inventory.tsv`. Any difference fails the drill.
7. Point the restored `tools/scripts/verify-recovery-objects.sh` at that
   isolated database and restored MinIO bucket. Inject PostgreSQL and S3
   credentials through root-only password/config files, not arguments or
   logs. Require exit `0`, not review exit `2`. This performs exact-VersionId
   GET/HEAD, digest checks, canonical bucket-to-database inventory comparison,
   and `GetObjectRetention` verification of per-version COMPLIANCE retention.
8. Start one exact Hash server image only after the data checks pass. Use an
   isolation-specific configuration, the recovered audit/key history, and the
   recovered bucket/database; leave the worker and all external effects off.
   Open and cryptographically verify sampled old and recent evidence bundles,
   download representative PDFs, and record counts, elapsed recovery time,
   image IDs, snapshot ID, and verifier evidence.

Example verifier invocation after the database and MinIO have been restored:

```bash
set +x
export PGHOST=127.0.0.1 PGPORT=<isolated-postgres-port>
export PGDATABASE=hash_recovery PGUSER=<recovery-role>
export PGPASSFILE=/run/hash-recovery/postgres.pass
export AWS_SHARED_CREDENTIALS_FILE=/run/hash-recovery/aws-credentials
export AWS_CONFIG_FILE=/run/hash-recovery/aws-config

restored_stage=/srv/hash-storagebox-restore/<restored-staging-root>
"$restored_stage/tools/scripts/verify-recovery-objects.sh" \
  --database hash_recovery \
  --endpoint http://127.0.0.1:<isolated-minio-port> \
  --bucket <recovered-hash-bucket> \
  --output /srv/hash-storagebox-restore/verification
```

An exact-version mismatch, missing object, short/non-COMPLIANCE retention,
inventory conflict, unverified sidecar, orphan/review result, image mismatch,
missing escrow history, or inability to boot the exact MinIO image fails the
restore. Preserve the isolated evidence and do not promote it over production.

## Daily backup verification

The platform's PITR and version-aware replication facilities are the
load-bearing backups. The following quiesced logical snapshot is a supplementary
copy of PostgreSQL plus each key's latest visible bytes and is useful for
forensics and explicitly legacy/unpinned rows. It is **not** an independent
current-record recovery path: `s3 sync` does not preserve provider VersionIds or
version history, while modern Hash rows commit exact VersionIds in PostgreSQL.
Commands assume `PGHOST`, `PGPORT`,
`PGDATABASE=hash`, `PGUSER`, `PGPASSFILE`, and the AWS-compatible credentials
have been injected by the secret manager; do not place passwords on the command
line. `HASH_SOURCE_S3_URL` is the production source endpoint including its
scheme (for example `https://s3.eu.example`); it is deliberately distinct from
the separate backup-account endpoint used for the final immutable copy.

For a consistent on-demand snapshot, schedule a short maintenance window and
quiesce both Hash processes before copying either store:

```bash
hash_source_dir=/root/automations/hash
test -f "$hash_source_dir/ops/recovery-object-inventory.sql"
test -L /opt/hash/current
test -f /opt/hash/current/manifest.json
hash_compose() {
  env -u HASH_IMAGE -u HASH_GOTENBERG_IMAGE -u HASH_RELEASE \
    -u HASH_ENVIRONMENT \
    docker compose --project-directory /opt/hash/current \
    --env-file /opt/hash/current/release.env \
    -p hash -f /opt/hash/current/docker-compose.yml "$@"
}
hash_compose config -q
hash_compose stop hash-worker hash
restart_hash() { hash_compose up -d --no-build --wait --wait-timeout 120; }
trap restart_hash EXIT

snapshot_id="$(date -u +%Y%m%dT%H%M%SZ)"
snapshot_dir="/srv/hash-backups/$snapshot_id"
umask 077
install -d -m 0700 "$snapshot_dir/objects"

pg_dump \
  --format=custom \
  --compress=9 \
  --no-owner \
  --no-acl \
  --file="$snapshot_dir/hash.pgdump"

# SSE-C protects reads as well as writes. Pass only a file URI to the AWS CLI;
# the raw key bytes never enter an environment value or process argument.
source_sse_args=()
if [[ "${HASH_S3_SSE_MODE:-sse-s3}" == "sse-c" ]]; then
  test -n "${HASH_SOURCE_S3_SSE_C_KEY_FILE:?mount the source SSE-C key file}"
  case "$HASH_SOURCE_S3_URL" in https://?*) ;; *) exit 1;; esac
  case "$HASH_SOURCE_S3_SSE_C_KEY_FILE" in /*) ;; *) exit 1;; esac
  test -f "$HASH_SOURCE_S3_SSE_C_KEY_FILE"
  test -r "$HASH_SOURCE_S3_SSE_C_KEY_FILE"
  test "$(wc -c < "$HASH_SOURCE_S3_SSE_C_KEY_FILE" | tr -d ' ')" = 32
  source_sse_args=(--sse-c AES256 --sse-c-key "fileb://$HASH_SOURCE_S3_SSE_C_KEY_FILE")
fi

# Supplementary latest-byte copy only. This does not preserve object history or
# the provider VersionIds committed by current Hash database rows.
aws --endpoint-url "$HASH_SOURCE_S3_URL" s3 sync \
  "s3://$HASH_S3_BUCKET" \
  "$snapshot_dir/objects" \
  "${source_sse_args[@]}" \
  --only-show-errors

# Store the canonical DB-side object inventory with the same quiesced
# generation. The first column is the exact key encoded as single-line base64;
# the JSON-escaped key and reference provenance remain human-readable.
psql --no-psqlrc --set ON_ERROR_STOP=1 --tuples-only --no-align \
  --field-separator $'\t' --pset footer=off \
  --file="$hash_source_dir/ops/recovery-object-inventory.sql" \
  > "$snapshot_dir/recovery-object-inventory.tsv"

# Prove that the DB inventory resolves to the exact active object versions
# before accepting this generation. This records each checked VersionId and
# SHA-256; a shadow is a review finding, while unversioned legal evidence,
# legacy existence-only audit sidecars, missing objects, conflicts, or orphans
# block acceptance.
source_verify_sse_args=()
if [[ "${HASH_S3_SSE_MODE:-sse-s3}" == "sse-c" ]]; then
  source_verify_sse_args=(--sse-c-key-file "$HASH_SOURCE_S3_SSE_C_KEY_FILE")
fi
"$hash_source_dir/scripts/verify-recovery-objects.sh" \
  --database "${PGDATABASE:-hash}" \
  --endpoint "$HASH_SOURCE_S3_URL" \
  --bucket "$HASH_S3_BUCKET" \
  --output "$snapshot_dir/source-object-verification" \
  "${source_verify_sse_args[@]}"

readlink /opt/hash/current > "$snapshot_dir/current-release.txt"
cp /opt/hash/current/manifest.json "$snapshot_dir/release-manifest.json"
cp /opt/hash/current/release.env "$snapshot_dir/release.env"
cp /opt/hash/current/docker-compose.yml "$snapshot_dir/docker-compose.yml"
cp /opt/hash/current/images.tar "$snapshot_dir/images.tar"
release_commit="$(jq -er .commit_sha /opt/hash/current/manifest.json)"
cp "/opt/hash/release-backup-gates/$release_commit.json" \
  "$snapshot_dir/release-backup-gate.json"
test "$(sha256sum "$snapshot_dir/images.tar" | awk '{print $1}')" = \
  "$(jq -er .image_archive_sha256 "$snapshot_dir/release-manifest.json")"
test "$(wc -c < "$snapshot_dir/images.tar" | tr -d ' ')" = \
  "$(jq -er .image_archive_bytes "$snapshot_dir/release-manifest.json")"
docker inspect hash hash-worker hash-gotenberg \
  --format '{{.Name}} {{.Config.Image}} {{.Image}}' > "$snapshot_dir/image.txt"
date -u +%FT%TZ > "$snapshot_dir/completed-at.txt"

(
  cd "$snapshot_dir"
  find . -type f ! -name SHA256SUMS -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum
) > "$snapshot_dir/SHA256SUMS"

# Copy the completed directory to the encrypted, immutable backup repository,
# then download and verify it there. The provider-specific upload is
# intentionally omitted: it must target the separate backup account, never the
# production bucket. `images.tar` is already required to have a verified,
# versioned COMPLIANCE-locked separate-account copy before its release can enter
# production; this snapshot is an additional recovery-set copy.
(cd "$snapshot_dir" && sha256sum --check SHA256SUMS)

restart_hash
trap - EXIT
```

If service downtime is not acceptable, rely on the PostgreSQL provider's
online base-backup/PITR mechanism and a provider recovery mechanism proven to
preserve every exact VersionId stored in PostgreSQL. Merely copying all object
bytes or creating new destination versions is insufficient. An implementation
that assigns new IDs would require a separately designed and audited atomic
database-remap procedure; Hash does not currently ship or approve one. Record
one UTC recovery timestamp common to both systems. Never combine an arbitrary
database dump with an older unversioned object copy and call it consistent.

Each day, an operator or automated verifier must confirm:

1. newest PostgreSQL recoverable timestamp is no more than 15 minutes old;
2. object replication lag is no more than 15 minutes, failed-object count is
   zero, and the approved recovery mechanism retains the source VersionIds;
3. the newest logical dump and `recovery-object-inventory.tsv` are non-empty
   and their checksums pass, and the release `images.tar` checksum matches both
   `release-manifest.json` and the separately downloaded immutable object;
4. the backup account can read them using the recovery role;
5. no backup credential can delete or overwrite production data.

## Schema-changing release gate

The production pipeline compares the candidate release's migration-tree digest
with `/opt/hash/current/manifest.json`. If it differs—or if the running legacy
deployment has no manifest—it refuses the cutover unless
`/opt/hash/migration-gates/<candidate-commit>.json` exists, is a regular file
owned by the current deployment UID with mode no broader than `0600`, and
records all of the following:

- the candidate full commit and exact currently running app image ID;
- the previous release commit (`legacy` for the one-time transition);
- a verified coupled PostgreSQL+S3 backup completed within the previous hour;
- a restricted evidence path or backup-job identifier; and
- a named operator's explicit conclusion whether the old app image can still
  run against the schema after candidate migrations apply;
- the previous and candidate `lifecycle_contract_version` comparison derived
  from the release manifests, not an operator override; and
- explicit approval of the fail-closed maintenance fallback when either the
  schema review is incompatible or those lifecycle contracts differ.

Use the atomic template in `PRODUCTION-CUTOVER.md`; do not set
`old_image_schema_compatible` or `maintenance_fallback_approved` mechanically.
If schema compatibility cannot be demonstrated, record it as false and approve
the maintenance/verified-backup restore posture; automatic old-image restart is
then unavailable. Prefer an expand/contract migration when uninterrupted
rollback is a release requirement. Even with schema compatibility, an old image
is never restarted after candidate writes unless its lifecycle contract matches
and the exact candidate rollback checker finds no sealing or finalizing
state/intent. The gate is release-specific and cannot authorize another commit
or prior image.

## Restore procedure

### 1. Contain and choose a recovery point

Declare an incident commander and separate database, storage, and application
verifiers. Stop `hash-worker` first to prevent reminders, email, webhooks,
expiration, or retry finalisation. Stop or put the server in maintenance mode
before restoring production.

Choose UTC time `T` immediately before the destructive event or corruption.
Record why `T` was selected, the newest available PostgreSQL WAL timestamp, and
the newest replicated S3 version timestamp. The later of those two lags is the
actual RPO.

### 2. Restore into isolation

Never restore over the damaged database or bucket first. Provision a new
database (`hash_recovery_<incident>`) and a new versioned bucket. Block public
ingress, disable SMTP, and leave the worker stopped.

For PITR, use the PostgreSQL provider to restore the cluster/database to `T`.
For a logical snapshot, restore into an empty database:

```bash
createdb hash_recovery
pg_restore \
  --exit-on-error \
  --single-transaction \
  --no-owner \
  --no-acl \
  --dbname=hash_recovery \
  /srv/hash-backups/<snapshot>/hash.pgdump
```

Restore S3 object versions as of `T` using a provider job that preserves every
exact VersionId stored in the recovered PostgreSQL database. Prove that property
with exact-version GETs; a job that restores the same bytes under newly assigned
IDs is not compatible with current Hash records. A separately designed and
audited atomic database-remap mechanism could support such a provider, but Hash
does not currently ship one. Create the isolated bucket with Object Lock enabled
at creation time and a default seven-calendar-year COMPLIANCE retention rule
before copying any legal object; record the provider configuration response. A
merely versioned recovery bucket is insufficient.

The logical `s3 sync` snapshot may be attempted only when the inventory proves
that every row is explicitly legacy/unpinned. This fail-closed guard prevents an
operator from silently turning current evidence into unreachable new versions.
Even on the legacy path, the canonical verifier below remains mandatory because
the latest-byte snapshot can omit a digest-matching version hidden by a newer
shadow:

```bash
inventory=/srv/hash-backups/<snapshot>/recovery-object-inventory.tsv
test -s "$inventory"
if awk -F '\t' '$10 != "-" { pinned=1 } END { exit pinned ? 0 : 1 }' "$inventory"; then
  echo 'portable logical restore refused: inventory contains exact VersionId pins' >&2
  exit 1
fi
recovery_sse_args=()
if [[ "${HASH_RECOVERY_S3_SSE_MODE:-sse-s3}" == "sse-c" ]]; then
  test -n "${HASH_RECOVERY_S3_SSE_C_KEY_FILE:?mount the recovery SSE-C key file}"
  case "$HASH_RECOVERY_S3_ENDPOINT" in https://?*) ;; *) exit 1;; esac
  case "$HASH_RECOVERY_S3_SSE_C_KEY_FILE" in /*) ;; *) exit 1;; esac
  test -f "$HASH_RECOVERY_S3_SSE_C_KEY_FILE"
  test -r "$HASH_RECOVERY_S3_SSE_C_KEY_FILE"
  test "$(wc -c < "$HASH_RECOVERY_S3_SSE_C_KEY_FILE" | tr -d ' ')" = 32
  recovery_sse_args=(--sse-c AES256 --sse-c-key "fileb://$HASH_RECOVERY_S3_SSE_C_KEY_FILE")
fi
aws --endpoint-url "$HASH_RECOVERY_S3_ENDPOINT" s3 sync \
  /srv/hash-backups/<snapshot>/objects \
  "s3://$HASH_RECOVERY_BUCKET" \
  "${recovery_sse_args[@]}" \
  --only-show-errors
```

Load and verify the exact application artifacts before starting Compose. Fetch
`images.tar` from its separately locked URI/version when the snapshot copy is
unavailable; never substitute a newly rebuilt image or a same-named tag:

```bash
cd /srv/hash-backups/<snapshot>
archive_sha="$(jq -er .image_archive_sha256 release-manifest.json)"
gate_sha="$(jq -er .image_archive_sha256 release-backup-gate.json)"
test "$gate_sha" = "$archive_sha"
test "$(jq -er .schema_version release-manifest.json)" = 3
test "$(jq -er .schema_version release-backup-gate.json)" = 3
test "$(jq -er .commit_sha release-backup-gate.json)" = \
  "$(jq -er .commit_sha release-manifest.json)"
archive_bytes="$(jq -er .image_archive_bytes release-manifest.json)"
test "$(jq -er .image_archive_bytes release-backup-gate.json)" = "$archive_bytes"
test "$(jq -er .remote_readback_sha256 release-backup-gate.json)" = "$archive_sha"
test "$(jq -er .bucket_versioning_status release-backup-gate.json)" = Enabled
test "$(jq -er .bucket_object_lock_enabled release-backup-gate.json)" = true
test "$(jq -er .immutable_copy_verified release-backup-gate.json)" = true

# Always re-read the exact protected version through the separate read-only
# recovery principal. A snapshot's convenience copy does not prove that the
# independent failure domain is usable. Never fall back to an unversioned key
# or a same-named image tag. This endpoint is the immutable release-backup
# account, not HASH_SOURCE_S3_URL or the production app bucket.
test -n "${HASH_RELEASE_BACKUP_S3_URL:?scheme plus backup endpoint required}"
case "$HASH_RELEASE_BACKUP_S3_URL" in https://?*) ;; *) exit 1;; esac
backup_uri="$(jq -er .backup_uri release-backup-gate.json)"
backup_version="$(jq -er .backup_object_version release-backup-gate.json)"
gate_retain_until="$(jq -er .retain_until release-backup-gate.json)"
test "$(jq -er .object_lock_mode release-backup-gate.json)" = COMPLIANCE
test -n "$backup_version"
test "$backup_version" != null
case "$backup_uri" in s3://*/*) ;; *) echo 'invalid release backup URI' >&2; exit 1;; esac
bucket_and_key="${backup_uri#s3://}"
backup_bucket="${bucket_and_key%%/*}"
backup_key="${bucket_and_key#*/}"
test -n "$backup_bucket"
test -n "$backup_key"

aws_vault=(aws --endpoint-url "$HASH_RELEASE_BACKUP_S3_URL" --output json \
  --no-cli-pager --cli-connect-timeout 10 --cli-read-timeout 30 s3api)
test "$("${aws_vault[@]}" get-bucket-versioning --bucket "$backup_bucket" | jq -er .Status)" = Enabled
test "$("${aws_vault[@]}" get-object-lock-configuration --bucket "$backup_bucket" | jq -er .ObjectLockEnabled)" = Enabled
head_json="$("${aws_vault[@]}" head-object --bucket "$backup_bucket" \
  --key "$backup_key" --version-id "$backup_version")"
test "$(jq -er .VersionId <<<"$head_json")" = "$backup_version"
test "$(jq -er .ContentLength <<<"$head_json")" = "$archive_bytes"
test "$(jq -er .ObjectLockMode <<<"$head_json")" = COMPLIANCE
last_modified="$(jq -er .LastModified <<<"$head_json")"
head_retain_until="$(jq -er .ObjectLockRetainUntilDate <<<"$head_json")"
retention_json="$("${aws_vault[@]}" get-object-retention \
  --bucket "$backup_bucket" --key "$backup_key" --version-id "$backup_version")"
test "$(jq -er .Retention.Mode <<<"$retention_json")" = COMPLIANCE
provider_retain_until="$(jq -er .Retention.RetainUntilDate <<<"$retention_json")"
required_retain_epoch="$(date -u -d "$last_modified +7 years" +%s)"
test "$(date -u -d "$head_retain_until" +%s)" -ge "$required_retain_epoch"
test "$(date -u -d "$provider_retain_until" +%s)" -ge "$required_retain_epoch"
test "$(date -u -d "$provider_retain_until" +%s)" -ge \
  "$(date -u -d "$gate_retain_until" +%s)"

remote_archive="$(mktemp ./images.remote.XXXXXX.tar)"
trap 'rm -f "$remote_archive"' EXIT
get_json="$("${aws_vault[@]}" get-object --bucket "$backup_bucket" \
  --key "$backup_key" --version-id "$backup_version" "$remote_archive")"
test "$(jq -er .VersionId <<<"$get_json")" = "$backup_version"
test "$(sha256sum "$remote_archive" | awk '{print $1}')" = "$archive_sha"
test "$(wc -c < "$remote_archive" | tr -d ' ')" = "$archive_bytes"
if test -f images.tar; then
  test "$(sha256sum images.tar | awk '{print $1}')" = "$archive_sha"
  test "$(wc -c < images.tar | tr -d ' ')" = "$archive_bytes"
fi
docker image load --input "$remote_archive"
rm -f "$remote_archive"
trap - EXIT

app_ref="$(jq -er .app_promotion_ref release-manifest.json)"
app_id="$(jq -er .app_image_id release-manifest.json)"
gote_ref="$(jq -er .gotenberg_promotion_ref release-manifest.json)"
gote_id="$(jq -er .gotenberg_image_id release-manifest.json)"
test "$(docker image inspect --format '{{.Id}}' "$app_ref")" = "$app_id"
test "$(docker image inspect --format '{{.Id}}' "$gote_ref")" = "$gote_id"
```

Configure an isolated Hash server with the recovered DB/bucket, the original
audit private key, its `HASH_AUDIT_TRUSTED_PUBLIC_KEYS` retired-issuer set, and
the exact app and Gotenberg IDs in
`release-manifest.json`. Use the recorded `docker-compose.yml` plus non-secret
`release.env`, a recovery-only hostname, and SMTP/integrations disabled. Do not
start `hash-worker`.

### 3. Verify integrity and function

Run database checks before exposing the recovery instance:

```bash
psql --dbname=hash_recovery --set ON_ERROR_STOP=1 --command "
  SELECT status, count(*) FROM documents GROUP BY status ORDER BY status;
  SELECT count(*) AS completed_without_pdf
    FROM documents
   WHERE status = 'completed' AND final_pdf_key IS NULL;
  SELECT count(*) AS completed_without_certificate
    FROM documents
   WHERE status = 'completed'
     AND parent_envelope_id IS NULL
     AND audit_cert_key IS NULL;
  SELECT count(*) AS completed_root_without_bound_sidecars
    FROM documents
   WHERE status = 'completed'
     AND parent_envelope_id IS NULL
     AND (
       audit_payload_key IS NULL OR audit_payload_sha256 IS NULL
       OR octet_length(audit_payload_sha256) <> 32
       OR audit_signature_key IS NULL OR audit_signature_sha256 IS NULL
       OR octet_length(audit_signature_sha256) <> 32
     );
  SELECT count(*) AS invalid_completed_envelope_children
    FROM documents child
    LEFT JOIN documents parent ON parent.id = child.parent_envelope_id
   WHERE child.status = 'completed'
     AND child.parent_envelope_id IS NOT NULL
     AND (
       parent.id IS NULL OR parent.status <> 'completed'
       OR child.final_pdf_key IS DISTINCT FROM parent.final_pdf_key
       OR child.final_pdf_sha IS DISTINCT FROM parent.final_pdf_sha
       OR child.audit_cert_key IS DISTINCT FROM parent.audit_cert_key
       OR child.audit_payload_key IS DISTINCT FROM parent.audit_payload_key
       OR child.audit_payload_sha256 IS DISTINCT FROM parent.audit_payload_sha256
       OR child.audit_signature_key IS DISTINCT FROM parent.audit_signature_key
       OR child.audit_signature_sha256 IS DISTINCT FROM parent.audit_signature_sha256
     );
"
```

All three missing/invalid-artifact counts must be zero. Signature and
acknowledgement lifecycle roots both require a certificate plus the exact
digest-bound payload/signature sidecars. Envelope children are not independent
signed roots: they must inherit the parent's identical artifact set, and the
inventory counts that shared set only through the parent. Then run the read-only
canonical inventory verifier against the isolated recovery database and bucket:

```bash
recovery_sse_args=()
if [[ "${HASH_RECOVERY_S3_SSE_MODE:-sse-s3}" == "sse-c" ]]; then
  test -n "${HASH_RECOVERY_S3_SSE_C_KEY_FILE:?mount the recovery SSE-C key file}"
  recovery_sse_args=(--sse-c-key-file "$HASH_RECOVERY_S3_SSE_C_KEY_FILE")
fi
/root/automations/hash/scripts/verify-recovery-objects.sh \
  --database hash_recovery \
  --endpoint "$HASH_RECOVERY_S3_ENDPOINT" \
  --bucket "$HASH_RECOVERY_BUCKET" \
  --output "/srv/hash-recovery-verification/$incident_id" \
  "${recovery_sse_args[@]}"
```

For AWS S3 itself, omit `--endpoint`. The verifier uses
`ops/recovery-object-inventory.sql` as the single source of truth and covers:

- every document object column: rendered PDF, uploaded/source PDF, final PDF,
  and audit certificate;
- template PDFs and their database SHA-256 values;
- captured signature images and their database SHA-256 values;
- image `attrs.storage_key` references recursively nested in current document,
  template, and document-version block trees;
- each lifecycle root's exact `audit-payload-<own SHA-256>.txt` and
  `audit-signature-<own SHA-256>.txt` key plus independently persisted digest;
  legacy cert-stem-derived names are reported but cannot pass as verified; and
- every exact staged artifact held only by a `document_finalization_intents`
  row while a document is `finalizing`: final PDF, audit certificate, payload,
  and detached signature with their four independent SHA-256 commitments; and
- Hash-hosted organisation and document-override logos whose stable route is
  `/branding/logo/<org UUID>.<ext>`. Truly external logo URLs are not bucket
  objects and are excluded.

Document/template/source/final/signature rows carry their expected SHA-256 and,
for current records, their exact expected VersionId. Content-addressed
audit-certificate rows carry both values as independent columns. Audit
payload/signature sidecars must always carry their own persisted digest; a
NULL/unknown value (including a legacy derived name) is a hard failure requiring
explicit evidence remediation. The inventory fails on conflicting non-null
VersionIds for one key or on a pin-required row with a NULL/synthetic pin.
For a pinned object the verifier directly issues exact-version GET and HEAD,
requires the provider response VersionId to equal the database value, and never
lists history. Only when every digest-bearing NULL reference is explicitly
legacy may it request one non-paginated page with `--max-keys 101`; more than 100
candidates or any truncation fails closed. It selects only bytes matching the
legacy digest. The verifier then calls `GetObjectRetention` for that exact
selected VersionId and requires
COMPLIANCE mode through seven calendar years from that version's provider
timestamp (with a bounded five-minute upload/clock-skew allowance). A newer
shadow no longer makes authentic retained bytes look lost, but it produces
`RESULT=REVIEW` and a `shadowed-referenced-objects.tsv` security finding. No
matching version, an exhausted/truncated search, or invalid retention fails.
`verified-object-versions.tsv` and
`verified-legal-evidence-retention.tsv` record the exact selected version,
digest, mode, retain-until, object timestamp, and required horizon.
Any conflicting DB hash or VersionId for one key, required-but-missing pin,
missing object with no digest-resolved legacy version, unversioned legal
evidence, absent/short/non-COMPLIANCE retention, exhausted version search, or
hash mismatch fails.

The verifier also compares the complete bucket listing to the DB set. It never
deletes extras. It exits `2` with `RESULT=REVIEW` for either an unreferenced
object or an authentic referenced version recovered behind a newer shadow.
Unreferenced objects are classified as orphan legal-document evidence,
signature evidence, document assets, template assets, block-tree images,
branding assets, or unknown. Preserve every legal/signature candidate while
incident and privacy owners reconcile the database recovery point. Exit `0`
(`PASS`) requires an exact set match with no shadow finding; exit `1` is an
integrity failure.

Rows for intentionally soft-deleted drafts remain in PostgreSQL during the
90-day grace period after their transient owned objects are removed. The
canonical inventory excludes only those drafts' source/rendered/tree assets;
it does not exclude shared template objects or any sent/terminal legal
evidence. The synthetic drill carries an absent-object deleted-draft fixture so
this lifecycle rule cannot regress into a false missing-evidence failure.

Finally:

- run `scripts/cutover-smoke.sh` against the recovery hostname with the exact
  full release commit selected for recovery; a healthy stale proxy target or
  non-production runtime must fail the identity checks;
- open and cryptographically verify evidence bundles for all agreements
  completed since the previous verified backup plus a random older sample;
- download those final PDFs and check the `%PDF-` header;
- complete one throwaway create → send-to-mail-sink → browser sign → final PDF
  flow with external email and webhooks still disabled;
- compare organisation, document, recipient, signature, and event counts to the
  most recent inventory/monitoring snapshot.

Any missing referenced object, hash mismatch, unresolved unreferenced object,
broken audit verification, unexpected migration, or count discrepancy fails
the restore. Preserve the isolated environment for forensics and choose an
earlier recovery point.

### 4. Promote and resume

Obtain incident-commander approval. Take one final backup of the damaged stores,
switch Hash to the recovered database and bucket, and start the server with
external integrations still disabled. Confirm `/health`, login, document list,
and signed-PDF download. Enable SMTP/webhooks, then start `hash-worker` last and
watch its first retry/reminder cycles for duplicates.

Keep the damaged stores read-only until legal/incident review authorises their
retirement. Record the selected recovery point, actual RPO/RTO, image IDs,
checksums, validation results, approvers, and any messages replayed or suppressed.

## Restore drills

Run a full isolated restore quarterly and after any database, storage, encryption,
or deployment-topology change. At least annually, assume the primary account and
host are unavailable and recover using only the backup account plus the documented
secret-manager break-glass path. A checklist review without restoring and opening
real sampled artifacts is not a restore drill.

### Safe local legacy/unpinned byte-copy preflight

Before using provider backups, validate the logical snapshot mechanics and
canonical inventory coverage for explicitly legacy/unpinned rows on a
workstation or disposable recovery host. This does not validate recovery of
current exact-VersionId records:

```bash
cd /path/to/hash
./scripts/backup-restore-drill.sh
```

The script does not read `.env`, use AWS credentials, publish ports, or attach to
the Hash Compose stack. It refuses a TCP/SSH Docker endpoint. On a local Docker
engine it creates uniquely named and labelled source and recovery containers,
four disposable volumes, and one private network. Cleanup first verifies that
each resource still carries the current run label; it refuses to delete a name
that does not. The output directory is retained and printed at the end.

The pinned MinIO image makes the local drill repeatable; it is disposable test
infrastructure, not approval of that release for an exposed or production
object store. The production security/version gate above remains independent.

The drill creates only synthetic data and deliberately seeds every
digest-bearing row as legacy/unpinned (`expected_version == '-'`); it neither
preserves nor validates provider VersionIds. Its miniature Hash schema
represents a completed document, a crash-staged `finalizing` document whose four artifacts
exist only in its durable intent, a template, version, signature, and both
branding scopes. It
stores representative objects for every inventory class: all document PDF key
columns, template PDF, signature image, recursively nested document/template/
version block images, audit PDF plus both independently digest-addressed
sidecars, all four intent-only staged finalization objects, one envelope child
that inherits (but does not duplicate) its
parent's legal evidence, and internally
hosted organisation/document branding logos. It then:

1. quiesces synthetic writes and creates a custom-format `pg_dump` plus an
   `mc mirror` object snapshot;
2. stops the source stores and restores into new PostgreSQL and MinIO volumes;
3. runs the same `ops/recovery-object-inventory.sql` used in a real restore,
   checks the dump can be listed, the database rows and all object classes
   survived, the DB and bucket sets match exactly, representative PDFs retain
   their magic header, and every object matches its original bytes (plus all
   database hashes where the schema carries one);
4. writes `drill-report.txt` and `snapshot/SHA256SUMS`, including elapsed times
   and exact container image IDs.

Use `--output /absolute/new/directory` when the evidence must be retained at a
known location. The path must not already exist. Attach the report and checksum
manifest to the release or recovery ticket; the database dump and objects are
synthetic and can remain in restricted engineering evidence storage.

`CONTROLLED_SNAPSHOT_RPO_SECONDS=0` means only that the deliberately quiesced
synthetic marker was recovered without loss. It does **not** demonstrate the
15-minute production RPO. `DATA_RESTORE_AND_VERIFY_SECONDS` measures local data
restore and integrity checks; it excludes infrastructure provisioning, secret
recovery, Hash startup, smoke/evidence verification, traffic switching, and
integration replay, so it does **not** by itself demonstrate the four-hour RTO.

### Production launch gate

The Sales Partner launch gate is met only when a timed, isolated provider-level
drill records all of the following:

- a common UTC recovery point `T` reached by both PostgreSQL PITR and S3 object
  versions, with measured WAL-archive and object-replication lag no greater than
  15 minutes;
- a restored Hash instance using the recorded immutable image and recovered
  cryptographic key material, with the worker and external integrations disabled;
- the manifest-bound `images.tar` was fetched by its recorded immutable backup
  URI/version, its SHA-256 passed, `docker image load` restored it, and both the
  app and Gotenberg refs resolved to their recorded content IDs on the recovery
  host (no source rebuild or mutable-tag pull);
- zero missing database-referenced objects, passing evidence-bundle signature
  verification, representative PDFs that open, matching record counts, and one
  successful throwaway end-to-end signing flow;
- every exact VersionId stored in the recovered database resolves directly in
  the recovery bucket and the provider returns that same ID; a byte-identical
  object under a newly assigned VersionId does not satisfy this gate;
- no more than four hours from incident declaration to the verified recovery
  instance being ready for an approved traffic switch.
- the estate object store's recorded version/digest is vendor-supported and
  cleared of the applicable privilege-escalation and path-traversal advisories,
  or a documented replacement/mitigation has passed security review.
- provider API evidence proves bucket versioning and Object Lock are enabled,
  and the application writes and reads back a COMPLIANCE retain-until date of
  at least seven years for signed agreements, audit certificates, and evidence
  artifacts; a sacrificial protected version survives an attempted
  permanent delete by the application principal, and the verified lifecycle
  rules cannot expire it early.
- the exact application principal used by server and worker successfully reads
  bucket lock configuration, writes and reads back a retained proof object, and
  receives an access-denied response when it attempts to permanently delete
  that protected version; retain the object version ID, retain-until timestamp,
  API output, and denial in the launch ticket.

Record timestamps for each phase rather than extrapolating the local synthetic
timing. A local preflight pass is necessary tooling evidence, but provider backup
configuration, production-scale transfer time, and secret/application recovery
remain separate launch evidence.
