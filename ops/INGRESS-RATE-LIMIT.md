# Production ingress and aggregate signer limits

Hash currently supports **one production HTTP server**. Signer rate-limit
buckets and collaborative-editing rooms are process-local, so horizontal HTTP
scaling would split both kinds of state.

This is an enforced runtime invariant, not an operator convention:

- `cmd/server` acquires PostgreSQL advisory lock `5206534214317659730`
  (`HASHSRVR`) on a dedicated connection before migrations or listener start
  when `HASH_ENVIRONMENT=production`.
- The production Compose artifact pins `HASH_ENVIRONMENT: production`
  literally for both server and worker; release metadata and invoking-shell
  values cannot downgrade that safety mode.
- A second production server using the same Hash database exits non-zero before
  it can accept traffic.
- The server probes the dedicated connection every five seconds and exits if
  the session is lost. PostgreSQL releases all session advisory locks when that
  connection closes.
- `docker-compose.prod.yml` declares exactly one fixed `hash` container and no
  published host port. Caddy reaches that container on `web-proxy` as
  `hash:8080`.

Consequently the in-process global IP, per-token, download, telemetry, and AI
clarification buckets in `internal/handler/server.go` are aggregate production
limits. Do not add replicas, an alternate public upstream, or a published Hash
port. Horizontal scaling requires a shared rate-limit backend and a shared Yjs
room backend first.

## Release evidence

`deploy-hash-prod` now fails closed and retains workflow evidence for all of the
following:

1. Before migrations, Caddy's loopback admin API returned valid active JSON and
   both `hash.brightinteraction.com` and `esign.brightinteraction.com` had
   one host-only, terminal route whose unconditional handler chain contained
   exactly one reverse proxy with exactly one upstream, `hash:8080`. An earlier
   route which could shadow either hostname, a nested path/header matcher, or a
   competing response/redirect/terminal handler fails the gate. Each approved
   reverse proxy must have the exact allowlisted JSON shape and overwrite both
   `X-Hash-Proxy-Auth` from `{env.HASH_PROXY_AUTH}` and
   `X-Hash-Client-IP` from Caddy's strict `{client_ip}` value. Server-level
   trusted proxies are exactly the host nginx bridge (`10.0.6.1/32`), with
   strict XFF processing. The workflow never re-adapts the bind-mounted source
   file, which may be a stale inode.
2. The host's assembled effective `nginx -T` configuration passed the exact
   two-host TLS/listener/location parser in memory, then the actual loopback
   443 listener returned the singleton contract marker for both hosts. Active
   nginx/Caddy configuration is never written to workflow logs.
3. After candidate startup, exactly one `web-proxy` endpoint owned alias
   `hash`: the running `/hash` container with Compose identity `hash/hash`, the
   manifest-selected image ID, and no host port bindings. The running
   `/web-proxy-caddy` container was attached to the same network.
4. The same topology assertion passed after any automatic rollback before the
   workflow reported the prior release restored.
5. The exact-release public `/health` probe passed on both hostnames with
   `environment=production`. A production server cannot listen before acquiring
   the singleton lease.
6. The server log contained `production singleton HTTP-server lease acquired`
   for the deployed container and no subsequent `production singleton lease
   lost` fatal event.

The active Caddy JSON can contain expanded header secrets. The workflow holds
it only in memory, never logs it or embeds observed values in errors, and asks
Docker only for whitelisted identity/network fields rather than container
environment data.

The lock behavior is covered without any external service:

```bash
GOCACHE=/private/tmp/hash-go-cache go test ./cmd/server -count=1
GOCACHE=/private/tmp/hash-go-cache go test -race ./cmd/server -count=1
```

## Authenticated client address boundary

Production Hash does not derive limiter/audit identity from XFF, `X-Real-IP`,
or `True-Client-IP`. Caddy is the only accepted non-loopback HTTP peer: it
overwrites a 32-byte independently generated `X-Hash-Proxy-Auth` value and a
single `X-Hash-Client-IP` value. Hash verifies the proxy secret in constant
time, rejects missing/duplicate/malformed client-IP headers (private and VPN
addresses remain valid identities), strips both internal headers, and only then
serves the request. The sole exception is exact loopback `/health`, used by the
container readiness check; loopback cannot use that exception for any other
path.

nginx appends the actual peer to the outer forwarding chain, while Caddy's
strict right-to-left parser trusts only the exact host bridge address, not all
RFC1918 or `web-proxy` peers. It therefore stops at the real untrusted
client even when that client supplied a forged leftmost entry. A
co-tenant that dials Hash directly lacks the proxy secret; a co-tenant that
dials Caddy cannot make Caddy trust attacker-supplied XFF. The private Hash and
Caddy env files must contain the same strong secret, but neither value is ever
logged. Manual Caddy/nginx edits, Docker-network changes, route CRUD, published
Hash ports, or bypass listeners invalidate this boundary and are rejected by
the serialized production workflows.
