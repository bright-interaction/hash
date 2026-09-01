# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# Stage 1: build the SvelteKit frontend with Bun (repo policy: no npm/pnpm/yarn).
FROM oven/bun:1.3.9-alpine@sha256:9028ee7a60a04777190f0c3129ce49c73384d3fc918f3e5c75f5af188e431981 AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile
COPY frontend/ .
RUN bun run build

# Stage 2: build the Go server.
FROM golang:1.26.7-alpine3.24@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS backend
WORKDIR /app
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download
COPY . .
COPY --from=frontend /app/frontend/build ./cmd/server/frontend/build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/server ./cmd/server && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/worker ./cmd/worker && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/config-check ./cmd/configcheck && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/audit-verify ./cmd/auditverify && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/rollback-check ./cmd/rollbackcheck && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/migrate ./cmd/migrate

# Stage 3: runtime image. Distroless-static would be tighter but alpine
# stays consistent with brightcrm and gives us a shell for emergency debug.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
# The current official 3.24 base contains OpenSSL 3.5.7-r0. Keep the base
# immutable, but fail closed unless Alpine can install the CVE-2026-14456 fix.
RUN apk add --no-cache \
        'libcrypto3>=3.5.8-r0' \
        'libssl3>=3.5.8-r0' \
        ca-certificates \
        tzdata && \
    addgroup -S hash && adduser -S -G hash hash
COPY --from=backend /out/server /usr/local/bin/hash-server
COPY --from=backend /out/worker /usr/local/bin/hash-worker
COPY --from=backend /out/config-check /usr/local/bin/hash-config-check
COPY --from=backend /out/audit-verify /usr/local/bin/hash-audit-verify
COPY --from=backend /out/rollback-check /usr/local/bin/hash-rollback-check
COPY --from=backend /out/migrate /usr/local/bin/hash-migrate
EXPOSE 8080
USER hash:hash
ENTRYPOINT ["/usr/local/bin/hash-server"]
