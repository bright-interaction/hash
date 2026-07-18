# Hash

EU-sovereign self-hosted document creation + e-signing platform. Agent-native
authoring via MCP. The name comes from the product's spine: every signing event
lands in a hash-chained audit timeline, and every completed envelope exports an
evidence bundle you can verify offline against the instance's published key.

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

## License

Hash is fair-code, licensed under the Hash Sustainable Use License: self-host
free, use it commercially for your own business and your own clients, have
anyone sign on your instance; you may not resell it as a hosted e-sign service.
See [LICENSE](./LICENSE) and [LICENSING.md](./LICENSING.md).
