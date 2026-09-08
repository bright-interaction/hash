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
| S3-compatible storage | signed PDFs, audit certs, uploads | MinIO, AWS S3, Cloudflare R2, Scaleway, ... |
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
principal `GetObjectLockConfiguration`, `PutObjectRetention`,
`GetObjectRetention`, `ListBucketVersions`, and `GetObjectVersion` plus its
normal object permissions. Version listing is a bounded legacy/shadow recovery
path; committed evidence reads and retention target the exact matching object
version. Hash applies and reads back seven-calendar-year COMPLIANCE retention on
legal evidence; it refuses to start or complete evidence writes when Object
Lock support/permissions are missing. Do not grant governance-bypass,
bucket-policy, or permanent-version-delete authority. Lifecycle expiration is
only for explicitly transient objects and does not enforce legal retention.

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
install -d -m 0700 "$secret_dir"
test ! -e "$secret_dir/s3-sse-c.key"
test ! -L "$secret_dir/s3-sse-c.key"
(set -o noclobber; umask 0333; openssl rand 32 > "$secret_dir/s3-sse-c.key")
test "$(wc -c < "$secret_dir/s3-sse-c.key" | tr -d ' ')" = 32
test ! -L "$secret_dir/s3-sse-c.key"
test "$(stat -c %h "$secret_dir/s3-sse-c.key")" = 1
test "$(stat -c %a "$secret_dir")" = 700
test "$(stat -c %a "$secret_dir/s3-sse-c.key")" = 444
export HASH_S3_SSE_C_KEY_HOST_FILE="$secret_dir/s3-sse-c.key"
```

The apparently unusual `0444` source-file mode is intentional: non-Swarm
Compose implements a file-backed secret as a direct bind mount and preserves
its host mode, while the container runs as `USER hash`. The root/operator-only
`0700` host directory prevents other host users from traversing to that file;
only explicitly attached single-purpose containers see the direct mount. Do
not relax the directory mode or create links to the key.

Set the env-file path to `/run/secrets/hash-s3-sse-c` and mount that same file
read-only into the server, worker, `hash-config-check`, `hash-audit-verify`, and
recovery jobs. Never place the key bytes in an environment variable, image,
URL, command argument, log, database, or S3 backup. Direct browser-presigned
GETs fail closed in SSE-C mode because they would require secret request
headers; downloads must go through Hash's authenticated server path.
This release accepts one SSE-C key at a time. Do not rotate it in place: old
versions would become unreadable. A future rotation must use a separately
proved re-encryption/remapping procedure while retaining every historical key.

For Compose, keep the raw host key outside the checkout, set only its path in
`HASH_S3_SSE_C_KEY_HOST_FILE`, and explicitly add the matching override. The
standalone override also requires the external endpoint, region, bucket,
credentials, and bucket-lookup mode rather than falling back to bundled MinIO.
The override grants both processes the same read-only Docker service secret:

```bash
# Bundled/standalone stack (services `hash` and `worker`):
docker compose -f docker-compose.yml -f docker-compose.sse-c.yml up -d

# Production config check remains networkless. Use the exact image selected by
# the release and mount the one key file directly (its host parent stays 0700).
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --env-file /opt/hash/.env \
  --mount type=bind,src="$HASH_S3_SSE_C_KEY_HOST_FILE",dst=/run/secrets/hash-s3-sse-c,readonly \
  --entrypoint /usr/local/bin/hash-config-check "$HASH_IMAGE"

# Production read-only audit needs both database and object-storage networks;
# the service-derived one-shot container inherits the secret and networks.
docker compose -f docker-compose.prod.yml -f docker-compose.prod.sse-c.yml \
  run --rm --no-deps --entrypoint /usr/local/bin/hash-audit-verify hash
```

Both overrides mount the key read-only at `/run/secrets/hash-s3-sse-c` for the
server and worker and set only that in-container path in their environments.
Omitting the override preserves SSE-S3 and requires no key file. Bright
Interaction's current automated production workflow publishes and invokes only
`docker-compose.prod.yml` and creates its config/audit containers directly. It
must be updated to carry the equivalent read-only key mount before an SSE-C
production cutover; this manual override does not alter that automation.

Hetzner Storage Box is SFTP/SMB/WebDAV storage, not an S3 object store, and is
not a valid primary Hash backend. Hetzner Object Storage is a distinct service.
Before using it, run the Object Lock E2E test below against a dedicated,
pre-created private Object-Lock bucket and prove exact VersionId reads,
seven-year COMPLIANCE retention, and denied permanent deletion. The basic live
test writes one retained version under a unique prefix and therefore requires
the explicit `HASH_E2E_S3_LIVE_CONFORMANCE=true` acknowledgement plus
`HASH_E2E_S3_BUCKET`. It consumes `HASH_E2E_S3_REGION`,
`HASH_E2E_S3_USE_SSL`, `HASH_E2E_S3_SSE_MODE`,
`HASH_E2E_S3_SSE_C_KEY_FILE`, and `HASH_E2E_S3_BUCKET_LOOKUP`.

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

For SSE-C, export only the protected host file path in
`HASH_S3_SSE_C_KEY_HOST_FILE`; `.env` must still point
`HASH_S3_SSE_C_KEY_FILE` at `/run/secrets/hash-s3-sse-c`. With SSE-S3, leave
the host-path variable unset and the array adds no mount.

Or use the bundled `docker-compose.yml`, which also brings up Postgres, MinIO,
Gotenberg, and MailHog for a one-command local stack. The worker always creates
an SMTP client, including in development, so keep MailHog running or configure
another reachable SMTP endpoint when running the worker:

```bash
cp .env.example .env   # edit first
docker compose up -d
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

End-to-end (real send -> sign -> stamped-PDF loop against live Postgres + MinIO +
Gotenberg). The test in `internal/e2e` is behind the `e2e` build tag and skips
unless `HASH_E2E_*` is set, so it never runs in the unit suite. To run it
locally:

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
go test -tags e2e -count=1 -timeout=180s ./internal/e2e/...
```

CI runs all of this; the `e2e` job in `.github/workflows/hash-ci.yml` starts
the three services and runs the tagged Go test. Its `browser-e2e` job builds a
live Hash + worker + MailHog stack, verifies worker stability, seeds a public
non-secret test identity and signed session cookie, and runs the full Playwright
suite. The signing journey uses the real MCP send result and drives the signer
SPA through Article 13 acknowledgement, signature adoption, finalisation,
stable PDF download, and queued invite delivery through the real worker SMTP
path.

## 6. Upgrades

Resolve the new image to a registry digest and restart both the server and the
worker with that exact reference. Keep the server, worker, pre-cutover migrator,
and all-org audit verifier on the same digest so their embedded schema and hash
rules match. Use the backup/migrate/verify ordering above; follow
`ops/BACKUP-RESTORE.md` for the recoverable coupled snapshot.
