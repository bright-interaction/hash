# Deploying Hash

Hash is self-hostable EU-sovereign e-signing. It runs as **two processes
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
| Gotenberg 8 | HTML -> PDF rendering | `docker run gotenberg/gotenberg:8` |
| SMTP server | outbound email | optional; unset = no mail sent (queue still records) |
| OIDC provider | sender login | any OIDC IdP: Zitadel, Keycloak, Auth0, ... |

Optional: an EU-hosted AI provider (Mistral / Anthropic-EU) for the AI features,
a QTSP for qualified signatures (e.g. Idura) and Mollie for billing. All off by
default.

## 1. Configure

Copy `.env.example` to `.env` and fill it in. `.env.example` is the
authoritative, annotated list of every variable (kept in lockstep with
`internal/config/config.go`); each is marked `[required]`, `[required-prod]`,
or `[optional]`.

Generate the secrets:

```bash
openssl rand -hex 32                                   # SIGNER_TOKEN_KEY, SESSION_KEY, AI_SHIELD_KEY
openssl genpkey -algorithm ed25519 -outform DER | tail -c 32 | base64   # AUDIT_PRIVATE_KEY
```

Outside local dev (any non-loopback `HASH_PUBLIC_URL`), the app **fail-closes
on boot** unless the production guards hold: a stable `HASH_AUDIT_PRIVATE_KEY`;
QES + billing providers either left unset (SES-only, unmetered) or real and
fully keyed, never the dev-only `mock` providers; and -- if any AI provider key
is set -- a 64-hex `HASH_AI_SHIELD_KEY` with an EU provider host.
See the "Production boot guards" list in `.env.example`.

## 2. Build the image

```bash
docker build -t hash:latest .
```

One image, both binaries. The Dockerfile builds the SvelteKit frontend with Bun
(embedded into the server), then compiles `cmd/server` and `cmd/worker`.

To build binaries without Docker: `cd frontend && bun install && bun run build`,
copy `frontend/build` to `cmd/server/frontend/build`, then
`go build ./cmd/server` and `go build ./cmd/worker`.

## 3. Run

Run **two containers from the same image**, sharing the same environment:

```bash
# server (publishes 8080)
docker run -d --name hash --env-file .env -p 8080:8080 hash:latest

# worker (no port; override the entrypoint)
docker run -d --name hash-worker --env-file .env \
  --entrypoint /usr/local/bin/hash-worker hash:latest
```

Or use the bundled `docker-compose.yml`, which also brings up Postgres, MinIO,
and Gotenberg for a one-command local stack:

```bash
cp .env.example .env   # edit first
docker compose up -d
```

For production, point the env at your managed Postgres / S3 / SMTP / OIDC rather
than the bundled dev containers. Database migrations run automatically when
either binary boots (forward-only goose migrations), so there is no separate
migrate step; both processes are safe to start together.

## 4. Reverse proxy, TLS, health

Terminate TLS at any proxy (Caddy, nginx, Traefik, or a cloud load balancer) and
forward to the server on `:8080`. The app emits its own security headers
(CSP, HSTS, X-Frame-Options, ...). Set `HASH_PUBLIC_URL` to the externally
reachable HTTPS URL -- signer magic links and the audit-verify endpoint are built
from it.

Health check: `GET /health` returns `200`. The published audit verification key
is served at `/.well-known/hash-public-key` once the server boots.

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
go build ./... && go vet ./... && go test ./...     # backend
cd frontend && bun install && bun run build && bun run check   # frontend
```

End-to-end (real send -> sign -> stamped-PDF loop against live Postgres + MinIO +
Gotenberg). The test in `internal/e2e` is behind the `e2e` build tag and skips
unless `HASH_E2E_*` is set, so it never runs in the unit suite. To run it
locally:

```bash
docker run -d -p 5432:5432 -e POSTGRES_USER=hash -e POSTGRES_PASSWORD=e2e -e POSTGRES_DB=hash postgres:16-alpine
docker run -d -p 9000:9000 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin minio/minio:latest server /data
docker run -d -p 3000:3000 gotenberg/gotenberg:8

HASH_E2E_DB_URL='postgres://hash:e2e@localhost:5432/hash?sslmode=disable' \
HASH_E2E_S3_ENDPOINT=localhost:9000 \
HASH_E2E_S3_ACCESS_KEY=minioadmin HASH_E2E_S3_SECRET_KEY=minioadmin \
HASH_E2E_GOTENBERG_URL=http://localhost:3000 \
go test -tags e2e ./internal/e2e/...
```

CI runs all of this; the `e2e` job in `.github/workflows/hash-ci.yml` starts
the three services and runs the tagged test. A Playwright browser smoke test of
the signer UI is a planned follow-up.

## 6. Upgrades

Pull the new image and restart both the server and the worker. Migrations apply
on boot. Keep the server and worker on the same image tag so their embedded
migration sets match.
