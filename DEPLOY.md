# Deploying Hash

Hash is deployment-controlled, self-hostable e-signing. It runs as **two processes
built from one container image**, plus a few standard backing services. There
is no dependency on any particular CI system or host: anything that can build a
container and run it (Docker Compose, Kubernetes, a plain VM) works.

> Bright Interaction's own instance is deployed with its in-house CI. Nothing
> below requires it.
> GitHub Actions, GitLab CI, Jenkins, Drone, or a manual `docker build` are all
> equally fine.

## Components

| Component | What | Notes |
|-----------|------|-------|
| `hash` server | HTTP API + embedded SvelteKit UI on `:8080` | default container entrypoint |
| `hash` worker | background loops: email dispatch, reminders, expirations, webhook redrive, finalize-retry, quota warnings | same image, `hash-worker` entrypoint |
| PostgreSQL 16+ | primary datastore | migrations run automatically on boot |
| Contract-tested S3 storage | signed PDFs, audit certs, uploads | must pass Hash's exact-VersionId, version-listing, encryption, and seven-year COMPLIANCE Object Lock conformance suite; generic “S3 compatible” branding is insufficient |
| Gotenberg 8.36.0 | HTML -> PDF rendering | select an immutable registry digest in production |
| SMTP server | outbound email | required for the worker; bundled development uses MailHog, non-development uses STARTTLS |
| OIDC provider | sender login | any OIDC IdP: Zitadel, Keycloak, Auth0, ... |

Production supports exactly one `hash` HTTP-server replica. A production server
holds a database-scoped singleton lease for its full lifetime, so a second
server fails boot instead of joining the traffic pool. This is a hard topology
contract, not an availability recommendation: signer rate limits,
collaboration rooms, and BrightCRM webhook cache invalidation are process-local.
Do not set a Kubernetes replica count above one or use
`docker compose --scale hash=...`; move all three facilities to shared backends
before horizontal server scaling. The separate `hash-worker` process is not an
HTTP-server replica.

Optional: an EU-hosted AI provider (Mistral / Anthropic-EU) for the AI features
and Mollie for billing. AES and QES signing are intentionally unavailable in
this release; `HASH_QES_PROVIDER` must remain unset.

Before production use, implement and drill the coupled PostgreSQL + S3 recovery
procedure in [`ops/BACKUP-RESTORE.md`](./ops/BACKUP-RESTORE.md). A database-only
backup cannot recover signed PDFs or audit certificates.

Production object storage is also a boot-time legal-retention dependency. The
configured bucket must already have S3 Object Lock enabled. Grant the Hash app
principal `GetBucketVersioning`, `GetObjectLockConfiguration`, `PutObjectRetention`,
`GetObjectRetention`, `ListBucketVersions`, and `GetObjectVersion` plus its
normal object permissions. Version listing is a bounded legacy/shadow recovery
path; committed evidence reads and retention target the exact matching object
version. Hash applies and reads back seven-calendar-year COMPLIANCE retention on
legal evidence; it refuses to start or complete evidence writes when Object
Lock support/permissions are missing. Do not grant governance-bypass,
bucket-policy, or key-only `s3:DeleteObject` authority. Grant
`s3:DeleteObjectVersion` only on the exact transient and draft/compensating
prefixes Hash cleans **and the single** `_hash/bootstrap-estate/v1` control
key. The control-key permission is required so its denied-delete conformance
probe proves Object Lock rather than an unrelated IAM denial; it does not grant
delete authority on customer evidence. COMPLIANCE retention independently
prevents deletion of legal evidence before its deadline. Lifecycle expiration is only for
explicitly transient objects and does not enforce legal retention.
Production Hash, its worker, and the storage pre-cutover check require this
bucket to exist already; they never auto-create a missing bucket. Disposable
local development and E2E are the only paths that retain explicit bucket
creation behavior.

Production server and worker processes never replace the bucket lifecycle
configuration. The operator must install and review any expiration rule for
Hash's transient namespace during provider/bootstrap provisioning; this avoids
erasing unrelated rules on a shared operator-owned bucket and removes lifecycle
mutation permission from normal writers.

The first-install estate claim uses exactly one reserved control object,
`_hash/bootstrap-estate/v1`, and the create-only host pair
`/opt/hash/bootstrap-storage-estate/intent.json` plus
`/opt/hash/bootstrap-storage-estate/receipt/receipt.json`. The marker is written
with the selected runtime encryption and seven-calendar-year COMPLIANCE
retention, then exact-VersionId GET/HEAD/encryption/retention and exhaustive
versions/delete-markers/multipart inventories are proved. The conformance gate
re-applies the exact provider-reported COMPLIANCE deadline (so the effective
deadline is unchanged), reads it back, requires an explicit provider `403` for
an early exact-version delete, and proves the same marker bytes and deadline
remain afterward. It is not a user object and must never be returned by a
document/list API or treated as an orphan after its exact receipt-bound
verification. Ordinary production deploys repeat this receipt-bound marker and
retention proof with the candidate's exact S3/SSE policy before their transient
read/write/delete canary.
Because S3 has no transaction spanning LIST and PUT, bootstrap also requires an
exclusive bucket/IAM maintenance window: no other principal, replication job,
lifecycle actor, or writer may mutate the bucket from the initial inventory
through the last pre-writer recheck. The workflow detects raced durable state,
but exclusive IAM closes the unavoidable final LIST/PUT gap.

### S3 encryption and addressing

Hash defaults to `HASH_S3_SSE_MODE=sse-s3` and
`HASH_S3_BUCKET_LOOKUP=auto`, preserving the MinIO deployment behavior. Some
S3-compatible providers require explicit `path` or `dns` bucket addressing;
select it with `HASH_S3_BUCKET_LOOKUP` only after a provider conformance run.

For providers such as Hetzner Object Storage that support customer-provided
encryption keys rather than SSE-S3, set `HASH_S3_SSE_MODE=sse-c`, require
`HASH_S3_USE_SSL=true`, and set `HASH_S3_SSE_C_KEY_FILE` to a file path inside
the container. The file must contain exactly 32 raw random bytes—not 64 hex
characters, base64, or a trailing newline. For a local Compose file-backed
secret, protect access with the parent directory and make the source file
readable by Hash's non-root container user:

```bash
secret_dir=/opt/hash/runtime-secrets
install -d -o 1000 -g 1000 -m 0700 "$secret_dir"
secret_file="$secret_dir/s3-sse-c.key"
test ! -e "$secret_file"
test ! -L "$secret_file"
# Run the exclusive create as the final owner. noclobber gives O_EXCL-like
# no-truncation behavior; a crash leaves either no file or a fail-closed file.
setpriv --reuid 1000 --regid 1000 --clear-groups -- sh -c \
  'set -euC; umask 0333; openssl rand 32 > "$1"' sh "$secret_file"
test "$(wc -c < "$secret_file" | tr -d ' ')" = 32
test ! -L "$secret_file"
test "$(stat -c %u:%g "$secret_file")" = 1000:1000
test "$(stat -c %h "$secret_file")" = 1
test "$(stat -c %a "$secret_dir")" = 700
test "$(stat -c %a "$secret_file")" = 444
sync -f "$secret_file"
HASH_S3_SSE_C_KEY_SHA256="$(sha256sum "$secret_file" | awk '{print $1}')"
test "${#HASH_S3_SSE_C_KEY_SHA256}" -eq 64
case "$HASH_S3_SSE_C_KEY_SHA256" in *[!0-9a-f]*) exit 1 ;; esac
export HASH_S3_SSE_C_KEY_HOST_FILE="$secret_file"
export HASH_S3_SSE_C_KEY_SHA256
```

The apparently unusual `0444` source-file mode is intentional: non-Swarm
Compose implements a file-backed secret as a direct bind mount and preserves
its host mode, while the container runs as `USER hash`. The root/operator-only
`0700` host directory prevents other host users from traversing to that file;
only explicitly attached single-purpose containers see the direct mount. Do
not relax the directory mode or create links to the key.

Set the env-file path to `/run/secrets/hash-s3-sse-c` and mount that same file
read-only into the server, worker, `hash-config-check`, `hash-audit-verify`, and
`hash-storage-check` and recovery jobs. Never place the key bytes in an
environment variable, image, URL, command argument, log, database, or S3
backup. Direct browser-presigned GETs fail closed in SSE-C mode because they
would require secret request headers; downloads must go through Hash's
authenticated server path.
This release accepts one SSE-C key at a time. Do not rotate it in place: old
versions would become unreadable. A future rotation must use a separately
proved re-encryption/remapping procedure while retaining every historical key.

For Compose, keep the raw host key outside the checkout, set only its path in
`HASH_S3_SSE_C_KEY_HOST_FILE`, and explicitly add the matching override. The
standalone override also requires the external endpoint, region, bucket,
credentials, and bucket-lookup mode rather than falling back to bundled MinIO.
The override grants both processes the same read-only Docker service secret:

```bash
# External-S3 standalone stack (services `hash` and `worker`, no MinIO):
docker compose -f docker-compose.yml -f docker-compose.sse-c.yml up -d

# Production config check remains networkless. Use the exact image selected by
# the release and mount the one key file directly (its host parent stays 0700).
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --env-file /opt/hash/.env \
  --mount type=bind,src="$HASH_S3_SSE_C_KEY_HOST_FILE",dst=/run/secrets/hash-s3-sse-c,readonly \
  --entrypoint /usr/local/bin/hash-config-check "$HASH_IMAGE"

# Standalone read-only audit inherits the same secret and local networks.
docker compose -f docker-compose.yml -f docker-compose.sse-c.yml \
  run --rm --no-deps --entrypoint /usr/local/bin/hash-audit-verify hash
```

After the candidate image passes the non-networked config check, run its
mutating storage canary before starting either writer. It loads the complete
Hash environment and uses the same `HASH_S3_ENDPOINT`, region, bucket,
credentials, TLS setting, bucket lookup, encryption mode, and mounted SSE-C key
as the server and worker. The canary writes only 32 random bytes beneath a
unique `transient/hash-storage-check/` key, proves an encrypted PUT,
exact-version GET and HEAD, then deletes that returned VersionId and proves no
version or delete marker remains. A missing configured bucket is a hard failure
and is never created.
For SSE-S3, the exact-version HEAD must report
`X-Amz-Server-Side-Encryption: AES256`. Because S3 implementations may omit
SSE-C response metadata, SSE-C proof instead requires the correct key to read
the exact version and a separately generated, distinct 32-byte key to fail on
both exact-version HEAD and GET; neither key nor its request MD5 is rendered in
errors. `/ready` remains non-mutating.

```bash
docker compose -f docker-compose.yml -f docker-compose.sse-c.yml \
  run --rm --no-deps --entrypoint /usr/local/bin/hash-storage-check hash
```

For external SSE-S3, configure every `HASH_S3_*` value in `.env` and omit
`-f docker-compose.sse-c.yml`; the binary and all other arguments are
identical. Do not add `docker-compose.local-minio.yml` to either external-S3
command: that development-only overlay is the sole definition of the bundled
MinIO service and its startup dependencies.

The production Compose files are CI-managed. Do not invoke them
directly: they intentionally require `HASH_DEPLOY_S3_ENDPOINT`,
`HASH_DEPLOY_S3_REGION`, `HASH_DEPLOY_S3_BUCKET`, `HASH_DEPLOY_S3_USE_SSL`,
`HASH_DEPLOY_S3_BUCKET_LOOKUP`, and `HASH_DEPLOY_S3_SSE_MODE` values that the
workflow derives from and pins against the private production contract. The
standalone examples above use the generic Compose pair and its ordinary
`HASH_S3_*` inputs. Production has no encryption-mode fallback: a missing
workflow selector fails Compose interpolation instead of silently selecting
SSE-S3 on an SSE-C estate.

The storage check records the VersionId returned by its 32-byte probe PUT,
deletes exactly that version, and proves both that VersionId and the latest-key
view are absent. A concurrent shadow version therefore fails the check instead
of being hidden behind a delete marker. Grant `s3:DeleteObjectVersion` only on
`transient/hash-storage-check/*` for this check; it never calls key-only
`DeleteObject` and has no optional logical-delete mode.

The separate bootstrap control-marker gate is intentionally non-accumulating:
it creates no per-deploy retained canary and never touches customer evidence.
It requires `s3:PutObjectRetention`, `s3:GetObjectRetention`, and exact-version
delete authority on `_hash/bootstrap-estate/v1`; because the ordinary mutable
canary independently proves exact-version delete authority, the marker's
explicit `403` is meaningful Object-Lock evidence rather than a network error.

Application draft deletion and failed-write compensation use the same exact
contract: persist the VersionId returned by PUT, then delete only that version.
Scope `s3:DeleteObjectVersion` to the Hash prefixes where these paths operate
and keep key-only `s3:DeleteObject` forbidden/unused. Seven-year legal
artifacts remain protected by COMPLIANCE retention, so even the exact-version
permission cannot remove them before their retention deadline.

Both overrides mount the key read-only at `/run/secrets/hash-s3-sse-c` for the
server and worker and set only that in-container path in their environments.
Omitting the override preserves SSE-S3 and requires no key file. Bright
Interaction's release workflow now binds both production Compose files into
manifest schema v4, selects the overlay from the validated private environment,
and injects the identical read-only mount into configcheck, storagecheck,
migration, rollback, audit, server, and worker containers. It requires the
canonical host file `/opt/hash/runtime-secrets/s3-sse-c.key`; the generic
standalone commands above may use another protected host path.

Production also has a write-once `/opt/hash/storage-contract.json` containing
the canonical non-secret endpoint, region, bucket, TLS flag, bucket-lookup
mode, encryption mode, and—for SSE-C—the SHA-256 fingerprint of the 32 random
key (never the key bytes). The proven empty-estate bootstrap creates it before
any writer can start. Every schema-v4 normal deployment and automatic rollback
requires an exact match, and the workflow forces those validated selectors into
configcheck, storagecheck, migration, rollback, audit, server, and worker
containers instead of allowing a later env-file edit to redirect one path.
The original bootstrap intent/receipt remain permanent estate controls after
the one-time foundation marker is consumed. Every ordinary production deploy
validates their original release identity and current immutable storage
contract, then exact-reads/HEADs the receipt-bound provider VersionId and
repeats its no-op COMPLIANCE/denied-delete proof before allowing the mutable
storage canary or any writer/migration mutation.
An existing legacy production install without this marker is deliberately
blocked: do not infer or hand-write the marker from the desired `.env`; perform
a separately reviewed SSE-S3 adoption that proves both running writers have no
SSE-C key mount and records the current contract first. Until that adoption is
recorded, production promotion remains HOLD. A schema-v3 current release may be
loaded and have its `current` pointer restored only as an SSE-S3 rollback anchor
during the first schema-v4 promotion; it is never considered SSE-C-capable. Its
legacy Compose file does not pin the immutable storage selectors, so automatic
rollback deliberately leaves the app and worker stopped for an explicitly
reviewed recovery instead of rereading mutable `/opt/hash/.env`. Changing
endpoint, region, bucket, TLS/addressing mode, encryption mode, or an SSE-C key
in place remains unsupported because the result can redirect or make historical
provider VersionIDs unreadable; use a proved migration/remapping procedure and
retain externally escrowed historical keys.

The access and secret key are intentionally absent from that non-secret
contract. Production snapshots only those two values into the exact two-line,
UID/GID-1000, mode-`0600`, single-link file
`/opt/hash/runtime-secrets/hash-s3.env`. It is loaded after `/opt/hash/.env` by
every exact-image one-shot and both writers, and its inode/content identity is
rechecked at migration, cutover, rollback, and post-start boundaries. This
closes mid-deploy `.env` replacement races without publishing a password
verifier. To make Docker `--env-file` and Compose `env_file` parsing identical,
both values must be unquoted and use only ASCII letters, digits, `+`, `/`, `_`,
`=`, `.`, and `-`; comment, quote, backslash, dollar, whitespace, and shell
syntax are rejected. Changing an access/secret pair for the same immutable storage target
is possible without VersionID remapping, but this release has no separately
authorized, drained online credential-rotation workflow. Keep the prior pair
active and HOLD promotion if the desired `.env` pair differs from the canonical
snapshot; never delete or hand-edit the snapshot to force rotation.

Production database identity is pinned independently in the private, write-once
`/opt/hash/database-contract.json`. Schema v1 contains only non-credential
identity: `host`, `port`, `database`, `username`, `ssl_mode`, PostgreSQL
`system_identifier`, and the nonzero `database_oid`. The system/OID pair changes
if the selected database is moved or dropped/recreated, even on the same named
cluster. The authenticated candidate must also prove `session_user` and
`current_user` equal the contract username, `public` is the sole effective
schema, the role owns the Hash database, and it has none of superuser,
create-role, create-database, replication, or bypass-RLS privileges.

The credential-bearing URL exists only in the single-line
`/opt/hash/runtime-secrets/hash-db.env` (`HASH_DB_URL=...`), owned by UID/GID
1000 with mode `0600` and link count one. Production Compose loads this file
after `/opt/hash/.env`, and every exact-image configcheck, storagecheck,
migration, rollback, and audit one-shot loads the same snapshot before forced
`HASH_RELEASE` and `HASH_ENVIRONMENT=production` overrides. The URL never
appears in argv, logs, or the contract. All libpq `PG*` entries are forbidden,
and URL query parameters are a narrow allowlist; target, role, service,
passfile, TLS-client-file, `options`, and `search_path` overrides fail closed.

Changing only the password is supported: under the shared maintenance lock the
workflow stages a private candidate file, proves through the exact image that it
still authenticates to the same role/system/OID/public schema, then atomically
replaces the canonical snapshot and revalidates its inode/content identity at
mutation boundaries. Never delete or hand-edit either database control file.
The empty-estate bootstrap creates the contract after its read-only database
proof. A live legacy estate must use the explicit
`adopt-hash-prod-database-contract` workflow described in
[`PRODUCTION-CUTOVER.md`](./PRODUCTION-CUTOVER.md); normal promotion remains
HOLD when the contract is absent.

Production/bootstrap/proxy deploys and cold backup share the pre-provisioned
`/opt/hash-lock/maintenance.lock`. Root must own `/opt/hash-lock` at mode `0755`;
the lock must be a UID/GID-1000, mode-`0600`, single-link regular file.
Workflows validate but never create or replace it. Do not move this file under
deploy-owned `/opt/hash`, where a rename could split flock contenders.

Hetzner Storage Box is SFTP/SMB/WebDAV storage, not an S3 object store, and is
not a valid primary Hash backend. Hetzner Object Storage is a distinct service.
The current Storage Box cold workflow preserves Hash's exact VersionIDs by
snapshotting the complete raw local MinIO volume. It cannot provide the same
guarantee for a Hetzner Object Storage primary: object replication is not
available there, and exporting then re-uploading objects assigns new
VersionIDs. That architecture needs a separately implemented atomic database
VersionID-remap restore path plus an independent recovery control before it is
production-approved.

With Hetzner Object Storage SSE-C, the provider does not retain the customer
key: losing any historical key permanently loses the corresponding object
versions. Keep separately escrowed key history for the full retention period.
SSE-C also does not encrypt object metadata, so object keys and user-supplied
metadata must remain opaque identifiers and must not carry customer data.
Before using it, run the Object Lock E2E test below against a dedicated,
pre-created private Object-Lock bucket and prove exact VersionId reads,
seven-year COMPLIANCE retention, and denied permanent deletion. The basic live
test writes one retained version under a unique prefix and therefore requires
the explicit `HASH_E2E_S3_LIVE_CONFORMANCE=true` acknowledgement plus
`HASH_E2E_S3_BUCKET`. It consumes `HASH_E2E_S3_REGION`,
`HASH_E2E_S3_USE_SSL`, `HASH_E2E_S3_SSE_MODE`,
`HASH_E2E_S3_SSE_C_KEY_FILE`, `HASH_E2E_S3_SSE_C_KEY_SHA256`, and
`HASH_E2E_S3_BUCKET_LOOKUP`.
The full send/sign test consumes the same variables (and
`HASH_E2E_S3_BUCKET`) instead of hard-coding plaintext local MinIO, so it can
exercise TLS/SSE-C artifact writes and exact-VersionId reads while requiring
the production bucket-versioning and Object-Lock contract after its Postgres
and Gotenberg dependencies are supplied. Local CI keeps the prior defaults: no
TLS, SSE-S3, automatic bucket lookup, and the `hash-e2e` bucket. Use only a
dedicated test bucket for live full-flow runs because the signing test
intentionally leaves its generated artifacts for inspection.

```bash
# Set credentials in the process environment without placing them on this
# command line. HASH_E2E_S3_SSE_C_KEY_FILE is the host path in this Go test.
HASH_E2E_S3_LIVE_CONFORMANCE=true \
  go test -tags=e2e ./internal/e2e -run '^TestEvidenceObjectLockE2E$' -v
```

The deeper shadow/version stress proof runs automatically for ephemeral local
MinIO. On a live provider it additionally requires
`HASH_E2E_S3_LIVE_STRESS_CONFORMANCE=true`. Use that only with a disposable,
dedicated bucket: it permanently extends the first version to eight years and
writes 101 shadow versions plus one additional seven-year retained recovery
version. A default bucket-retention rule may retain the shadows as well. The
test deliberately cannot promise cleanup under the least-privilege principal.

Do not switch an existing Hash database to a copied bucket: S3 copy/replication
creates provider-local VersionIds, while Hash persists the original opaque IDs.
Use a new deployment or a separately designed, atomic migration/remapping
procedure, retain every historical SSE-C key for its objects' full retention
period, and prove a coupled PostgreSQL/object restore before cutover.
Likewise, do not change the encryption mode or SSE-C key of a bucket containing
existing Hash objects: one configured key cannot read objects written under a
different policy.

### Block-evidence production limitations

Drafts may contain image blocks and `raw_html` references to
`/api/v1/storage/...`, but this release deliberately refuses to send or
finalize them. Those authoring references persist only a mutable storage key;
they do not yet bind the exact provider VersionId, SHA-256, and COMPLIANCE
retention proof into the document snapshot. The recursive gate covers nested
blocks, envelope children, initial sends, automation sends, and both
`in_progress` and `finalizing` retry paths. Do not bypass it or classify a
legacy non-draft block asset as recoverable. Production support requires an
end-to-end schema/API/renderer/recovery change that pins and exact-reads the
retained object version.

The same canonical gate rejects `initial_field`, `text_field`, `date_field`,
and `checkbox` blocks. Hash does not yet persist and rebind those values by
block ID into the immutable signer and terminal-PDF evidence; only the supported
signature-field flow may cross the send boundary. Send, finalization,
candidate-cutover recovery, and the ordinary release audit all invoke the same
recursive validator so a legacy or pre-gate ceremony cannot bypass this rule.

The ordinary pre-cutover and post-start `hash-audit-verify` scans both current
trees and every `document_versions.block_tree_json` for the same frozen-state
predicate, including envelope children. Promotion requires
`invalid_immutable_block_tree_count=0`; legacy irreversible image/raw-HTML
references and unsupported interactive fields therefore fail closed before a
writer starts.

### Branding evidence limitation

Production logo upload and every non-empty REST/MCP `logo_url` update are
disabled in this release. The old upload path used one stable, unversioned key,
could leave prior versions or extension-specific orphan keys, and could orphan
an upload when the client never saved the returned URL. Do not re-enable it
until the branding schema pins an exact VersionId, SHA-256, and COMPLIANCE
retention proof and all reads use that exact version. Draft/local-development
logo previews remain non-production functionality.

Color/font branding is frozen safely: in the same row-locked send transaction,
Hash materializes every effective theme field into a complete per-document
override for the root and each envelope child before sealing. Later org-theme
changes cannot alter signer or terminal rendering. Migration 00065 takes a
write-excluding cutover lock, refuses any non-draft legacy document without a
complete, valid, logo-free snapshot (including canonical font lists of at most
256 bytes), and refuses every non-empty organization or document logo before
installing lifecycle triggers. The triggers serialize draft branding writes
with Send's document lock, prevent any writer from leaving draft without the
same valid snapshot, and reject update/delete after the document leaves draft.
Sealing is logo-free in every environment; development may preview/upload a
logo but must clear it before Send. The down migration refuses rollback while
any document is non-draft or has durable send history, including a ceremony
later reopened to draft. The release audit independently applies the same
snapshot and logo predicates.
Promotion requires
`invalid_frozen_branding_count=0` and `unsupported_branding_logo_count=0`.

## 1. Configure

Copy `.env.example` to `.env` and fill it in. `.env.example` is the
authoritative, annotated list of every variable (kept in lockstep with
`internal/config/config.go`); each is marked `[required]`, `[required-prod]`,
or `[optional]`.

Generate the secrets:

```bash
openssl rand -hex 32                                   # SIGNER_TOKEN_KEY, SESSION_KEY, WEBHOOK_ENCRYPTION_KEY, AI_SHIELD_KEY
openssl genpkey -algorithm ed25519 -outform DER | tail -c 32 | base64   # AUDIT_PRIVATE_KEY
```

An omitted `HASH_ENVIRONMENT` fails closed to `production`. Development-only
relaxations require both `HASH_ENVIRONMENT=development` and a loopback,
`*.localhost`, or `*.local` `HASH_PUBLIC_URL`; a local-looking URL alone never
selects development mode. Outside that explicit local-dev combination, the app
**fail-closes on boot** unless the production guards hold: a stable
`HASH_AUDIT_PRIVATE_KEY`;
an exact lowercase full 40- or 64-hex commit in `HASH_RELEASE` (the image digest
is selected separately by the orchestrator);
retain every retired issuer's raw Ed25519 public key in the comma-separated
`HASH_AUDIT_TRUSTED_PUBLIC_KEYS` rotation set for as long as its certificates
must verify (the current private key is auto-trusted; malformed historical
entries fail boot). Those retired keys authenticate historical ceremony
certificates only; they do not authorize a newly exported evidence manifest,
which is trusted only under the current signer's public key;
the factual instance identity `HASH_OPERATOR_NAME`, one plain-email
`HASH_PRIVACY_CONTACT`, and the deployment's applicable
`HASH_SUPERVISORY_AUTHORITY`, plus the operator's absolute HTTPS
`HASH_PRIVACY_POLICY_URL` (these values are rendered to every signer; the
software does not assume Bright Interaction owns a self-hosted instance or
link self-hosted signers to Bright Interaction's policy);
`HASH_QES_PROVIDER` left unset (AES/QES are fail-closed), a real fully keyed
`HASH_BILLING_PROVIDER=mollie` configuration (unset or `mock` is development-only); and -- if any AI provider key
is set -- a 64-hex `HASH_AI_SHIELD_KEY` with an EU provider host.
See the "Production boot guards" list in `.env.example`.

`HASH_WEBHOOK_ENCRYPTION_KEY` is a dedicated AES-256-GCM key and is required
by both the server and worker. Do not reuse another Hash key. Store the same
value in both services through the deployment's secret manager; Google Secret
Manager environment injection is supported, but no Google-specific runtime is
required. Retain the key with every database backup that may contain webhook
endpoints.

The first encrypted-secret release is not safe for a mixed-version rolling
deploy. An old worker treats a new row's intentionally blank plaintext column
as a legacy global-secret row, while a new server never writes plaintext. For
that release, drain in-flight webhook work, stop every old server and worker,
take a coupled backup, set the encryption key on both services, and only then
start the new server. Startup applies the additive migration and atomically
encrypts every legacy endpoint before accepting traffic. Start the new worker
after this query returns zero in both columns:

```sql
SELECT
  count(*) FILTER (WHERE secret_ciphertext IS NULL) AS unencrypted,
  count(*) FILTER (WHERE secret <> '') AS plaintext
FROM webhook_endpoints;
```

If a legacy endpoint row has an empty `secret`, temporarily set
`HASH_WEBHOOK_SECRET` to the receiver's existing verifier secret (at least 32
non-identical characters) on the backfilling process. A fresh install leaves it
blank. Authentication, malformed ciphertext, or a dual-written secret mismatch
fails startup closed; never clear or hand-edit a failed row. After successful
backfill, remove the legacy global secret and verify one signed delivery per
endpoint.

Once any endpoint has ciphertext, migration 00064 is intentionally
non-reversible: its down migration refuses to discard the only durable secret
copy. Roll forward or restore the coupled pre-migration backup; do not force a
column drop.

For a later encryption-key rotation, stop/drain both services again, place the
old key in `HASH_WEBHOOK_ENCRYPTION_KEY_PREVIOUS` and the new key in
`HASH_WEBHOOK_ENCRYPTION_KEY` on both, restart the server to rewrap, verify the
query above, then start the worker. Remove the previous key on the next
coordinated restart. Never overlap a process that knows only the old key with a
process that can rewrap rows under the new key.

## 2. Build the image

```bash
# Use an immutable release tag; publish and deploy by registry digest in prod.
docker build -t registry.example.com/hash:<git-commit-sha> .
docker push registry.example.com/hash:<git-commit-sha>
```

One image contains both runtime binaries plus the release-administration
binaries. The Dockerfile builds the SvelteKit frontend with Bun (embedded into
the server), then compiles `cmd/server`, `cmd/worker`, `cmd/configcheck`,
`cmd/migrate`, `cmd/auditverify`, and `cmd/rollbackcheck`.

To build binaries without Docker: `cd frontend && bun install && bun run build`,
copy `frontend/build` to `cmd/server/frontend/build`, then `go build ./...`.

## 3. Run

Run **two containers from the same image**, sharing the same environment:

```bash
export HASH_IMAGE='registry.example.com/hash@sha256:<manifest-digest>'
s3_secret_mount=()
if [[ -n "${HASH_S3_SSE_C_KEY_HOST_FILE:-}" ]]; then
  s3_secret_mount=(
    --mount "type=bind,src=$HASH_S3_SSE_C_KEY_HOST_FILE,dst=/run/secrets/hash-s3-sse-c,readonly"
  )
fi

# server (publishes 8080)
docker run -d --name hash --env-file .env \
  "${s3_secret_mount[@]}" -p 8080:8080 "$HASH_IMAGE"

# worker (no port; override the entrypoint)
docker run -d --name hash-worker --env-file .env \
  "${s3_secret_mount[@]}" \
  --entrypoint /usr/local/bin/hash-worker "$HASH_IMAGE"
```

For SSE-C, export the protected host file path in
`HASH_S3_SSE_C_KEY_HOST_FILE` and the lowercase SHA-256 digest (never the key
bytes) in `HASH_S3_SSE_C_KEY_SHA256`; `.env` must still point
`HASH_S3_SSE_C_KEY_FILE` at `/run/secrets/hash-s3-sse-c` and carry that same
digest for direct `docker run`. With SSE-S3, leave the host-path and digest
variables unset and the array adds no mount.

For a self-contained local-development stack, explicitly add
`docker-compose.local-minio.yml`. It is the only file that defines MinIO and
adds MinIO readiness dependencies to the server and worker. The base plus
external-S3 overlay contains neither, so Hetzner Object Storage and other
external providers run without an unused local MinIO container. The worker
always creates an SMTP client, including in development, so keep MailHog running
or configure another reachable SMTP endpoint when running the worker:

```bash
cp .env.example .env   # edit first
docker compose -f docker-compose.yml -f docker-compose.local-minio.yml up -d
```

For production, point the env at your managed Postgres / S3 / SMTP / OIDC rather
than the bundled dev containers. Server and worker retain an automatic,
advisory-lock-serialized migration safety net. A controlled production release
should nevertheless take and verify the coupled backup first, run the exact
candidate image's `/usr/local/bin/hash-config-check` under `--network none`
before stopping writers or applying schema
changes (force the selected `HASH_RELEASE` and `HASH_ENVIRONMENT=production` in
that one-shot), run it with `--entrypoint /usr/local/bin/hash-migrate`, then run
that same image with `--entrypoint /usr/local/bin/hash-audit-verify` before moving
traffic. The verifier must cover every org from one complete snapshot and exit
zero; it also requires complete lifecycle-root sidecar commitments, exact
envelope-child inheritance, and (when a completed root exists) hashes/parses one
real stored payload and verifies its detached signature against the trusted
certificate-issuer set. Fresh evidence manifests remain separately restricted
to the current signer. Corruption or legacy-unverifiable rows block the release,
never trigger a hash repair. Re-run it in the live server after readiness.
Stop every old server and worker before applying a migration that changes the
durable ceremony contract, and keep them stopped through the switch or a
contract-compatible rollback decision. In particular, the explicit lawful-
basis migration refuses active pre-control ceremonies and deployment automation
must never manufacture controller confirmation from the historic `contract`
column default. The SES-only cutover likewise refuses active AES/QES routing
rules and non-terminal AES/QES documents. Organization owners must deactivate
or reset those through the authenticated pre-cutover application so the change
has an audit trail; never silently rewrite assurance choices in SQL.
The Article 13 epoch cutover additionally requires send sealing to be drained
and refuses every active sent/in-progress/changes-requested document whose
latest `document.sent` row lacks a supported schema marker exactly bound to its
authoritative `sent_at`. After migrations, run the same candidate image's
`hash-rollback-check --article13-cutover` before starting either writer. Drain
or explicitly terminate invalid old ceremonies; never fabricate a disclosure
marker for a notice that was not shown.

The immediately preceding completion/retention migrations also require every
send-sealing and finalization operation to be drained. They refuse to invent a
completion instant or Object Lock deadline for an operation started by an older
writer. After the first durable BrightCRM receipt at schema 62, rollback across
that migration is intentionally blocked so replay protection cannot be erased.
Coordinate `HASH_BRIGHTCRM_WEBHOOK_SECRET` rotation with a stopped and drained
BrightCRM retry queue; receipt correlations are keyed for audit privacy.

Before the first production start, upload a harmless proof object through the
same application principal, apply COMPLIANCE retention, read the retention back,
then confirm an attempted permanent version delete by that principal is denied.
Retain the provider API output and denied-delete result with launch evidence.

## 4. Reverse proxy, TLS, health

Terminate TLS at a controlled proxy (Caddy, nginx, Traefik, or a cloud load
balancer) and forward to the server on `:8080`. Production Hash requires the
proxy to overwrite (not append) exactly one `X-Hash-Proxy-Auth` value matching
the independent 32-byte `HASH_PROXY_AUTH` secret and exactly one
`X-Hash-Client-IP` containing the proxy's authenticated, single parsed client
address. Direct co-tenant calls, duplicate values, generic forwarding chains,
and missing/wrong proxy authentication are rejected before routing or rate
limiting. Keep the Hash port private; the exact loopback `/health` probe is the
only no-header production exception. The app emits its own security headers
(CSP, HSTS, X-Frame-Options, ...). Set `HASH_PUBLIC_URL` to the externally
reachable HTTPS URL -- signer magic links and the audit-verify endpoint are built
from it.

Readiness check: `GET /health` returns `200` only when PostgreSQL, object
storage, and Gotenberg are reachable. Treat `503` as not ready and do not route
traffic. The response also carries `X-Hash-Release` and
`X-Hash-Environment`; a production cutover must compare those to the exact
approved release and `production`, rather than accepting a generic healthy
response that could have come from the previous proxy target. The published
audit verification key is served at
`/.well-known/hash-public-key` once the server boots.

`HASH_EVIDENCE_OTS_ENABLED` is an explicit local-development experiment only.
The built-in verifier does not validate OpenTimestamps calendar proofs, so
staging/production reject it and no timestamp-authority claim should rely on it.

## 5. Continuous deployment (any CI)

Hash has no CI coupling. Any pipeline that can build a container image and
then tell your host to run it will do. The shape is always: **build image ->
push to a registry -> host pulls + restarts**.

Minimal GitHub Actions example (adapt the registry + deploy step to your host):

```yaml
name: deploy-hash
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: ./hash
          push: true
          tags: ghcr.io/<owner>/hash:${{ github.sha }}
      # Then deploy: SSH + `docker compose pull && docker compose up -d`,
      # `kubectl set image ...`, or your platform's deploy action.
```

GitLab CI, Jenkins, Drone, etc. follow the same two steps (`docker build` /
`docker push`, then a deploy command). The dev `.gitlab-ci.yml` / `Jenkinsfile`
is whatever your org standardises on; Hash only needs the resulting image run
with the env from step 1.

## Testing

Unit + build suite (no external services):

```bash
bash scripts/ci.sh
go test -race -count=1 -timeout=120s ./...
```

End-to-end (real send -> sign -> stamped-PDF plus transactional auth, handler,
and signing checks against live Postgres + MinIO + Gotenberg). Tagged tests live
in `internal/e2e`, `internal/auth`, `internal/handler`, and `internal/sign`; they
skip unless `HASH_E2E_*` is set, so they never run in the unit suite. To run all
of them locally:

```bash
docker run -d -p 5432:5432 -e POSTGRES_USER=hash -e POSTGRES_PASSWORD=e2e -e POSTGRES_DB=hash postgres:16.15-alpine3.24
export HASH_E2E_MINIO_KMS_KEY="$(openssl rand -base64 32)"
docker run -d -p 9000:9000 \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  -e "MINIO_KMS_SECRET_KEY=hash-e2e-key:${HASH_E2E_MINIO_KMS_KEY}" \
  minio/minio:RELEASE.2025-09-07T16-13-09Z server /data
unset HASH_E2E_MINIO_KMS_KEY
docker run -d -p 3000:3000 \
  gotenberg/gotenberg@sha256:87c16b9f364279d321bc9772d31fa58aa6abe036423c270698bd636c3a8e9466

HASH_E2E_DB_URL='postgres://hash:e2e@localhost:5432/hash?sslmode=disable' \
HASH_E2E_S3_ENDPOINT=localhost:9000 \
HASH_E2E_S3_ACCESS_KEY=minioadmin HASH_E2E_S3_SECRET_KEY=minioadmin \
HASH_E2E_S3_EPHEMERAL_BUCKET=true \
HASH_E2E_GOTENBERG_URL=http://localhost:3000 \
go test -tags e2e -count=1 -timeout=180s ./...
```

CI runs all of this; the `e2e` job in `.github/workflows/hash-ci.yml` starts
the three services and runs every tagged Go package. Its `browser-e2e` job
builds a live Hash + worker + MailHog stack, verifies worker stability, seeds a
public non-secret test identity and signed session cookie, and runs the full
Playwright suite. The signing journey uses the real MCP send result and drives the signer
SPA through Article 13 acknowledgement, signature adoption, finalisation,
stable PDF download, and queued invite delivery through the real worker SMTP
path.

## 6. Upgrades

Resolve the new image to a registry digest and restart both the server and the
worker with that exact reference. Keep the server, worker, pre-cutover migrator,
and all-org audit verifier on the same digest so their embedded schema and hash
rules match. Use the backup/migrate/verify ordering above; follow
`ops/BACKUP-RESTORE.md` for the recoverable coupled snapshot.
