# Hash

EU-sovereign self-hosted document creation + e-signing platform. Agent-native authoring via MCP. Replaces the retired Documenso. The name comes from the Roman/Indo-Iranian deity of contracts and oaths ,  "Mithra" literally means *covenant*.

See [PLAN.md](./PLAN.md) for the six-week build plan and architectural decisions.

## Stack

- Go + chi + sqlc + goose (server + background worker, one image)
- SvelteKit + Svelte 5 + TipTap (block editor), embedded into the server binary
- PostgreSQL 16+
- Any S3-compatible object store (MinIO, AWS S3, Cloudflare R2, ...) for blobs
- Any SMTP server for outbound email
- Any OIDC provider for sender SSO (Zitadel, Keycloak, Auth0, ...)
- Gotenberg for HTML→PDF rendering
- pdfcpu for PDF signature/field stamping

(The Bright Interaction instance uses MinIO, Postal, and Zitadel; nothing is
hard-wired to them.)

## Quick start

```bash
cp .env.example .env
# edit .env, then:
make docker-up
# Hash at http://localhost:8080, Postgres at 5432, MinIO at 9000
```

## Deploy

- **[DEPLOY.md](./DEPLOY.md)**: generic, CI- and host-neutral deployment
  (Docker / Compose / Kubernetes; GitHub Actions, GitLab CI, or any pipeline).
- **[.env.example](./.env.example)**: every config var, annotated.
- **[PRODUCTION-CUTOVER.md](./PRODUCTION-CUTOVER.md)**: the Bright Interaction
  internal runbook (CI + the shared cluster).

## Status

Week 1 of v1 ,  foundations. See `PLAN.md` for what's shipped and what's next.
