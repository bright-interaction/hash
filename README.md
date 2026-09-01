# Hash

Deployment-controlled, self-hosted document creation + e-signing platform. Agent-native
authoring via MCP. The name comes from the product's spine: every signing event
lands in a hash-chained audit timeline. Completed documents receive a final PDF
and audit certificate; plans with the `evidence_bundle` feature can also export
a bundle designed for independent verification against the instance's published
key. The bundled `/verify` web page is server-assisted and uploads
the supplied certificate or evidence bundle; it is not an offline verifier.

## Stack

- Go + chi + sqlc + goose (server + background worker, one image)
- SvelteKit + Svelte 5 + TipTap (block editor), embedded into the server binary
- PostgreSQL 16+
- An S3-compatible object store that implements the versioning, version-specific access, Object Lock
  retention, and legal-hold APIs Hash requires in non-local deployments
- An SMTP submission server that supports STARTTLS on a plain SMTP connection (implicit-TLS-only
  endpoints are not supported)
- Any OIDC provider for sender SSO (Zitadel, Keycloak, Auth0, ...)
- Gotenberg for HTML→PDF rendering
- pdfcpu for PDF signature/field stamping

(The Bright Interaction instance uses MinIO, Postal, and Zitadel. Alternatives must satisfy the
runtime contracts above and the OIDC claim requirements enforced at boot/login.)

The built-in legal pages are Bright Interaction draft templates, not reusable operator terms. A
self-hosting operator must replace or obtain approval for its own notices, DPA, sub-processor and
retention schedules before processing customer data.

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
- **[ops/BACKUP-RESTORE.md](./ops/BACKUP-RESTORE.md)**: coupled PostgreSQL + S3
  backup, restore, validation, RPO/RTO, and drill procedure.
- **[.env.example](./.env.example)**: every config var, annotated.

## License

Hash is fair-code, licensed under the Hash Sustainable Use License: self-host
free, use it commercially for your own business and your own clients, have
anyone sign on your instance; you may not resell it as a hosted e-sign service.
See [LICENSE](./LICENSE) and [LICENSING.md](./LICENSING.md).
