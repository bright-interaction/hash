# syntax=docker/dockerfile:1.7

# Stage 1: build the SvelteKit frontend with Bun (repo policy: no npm/pnpm/yarn).
FROM oven/bun:1-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile
COPY frontend/ .
RUN bun run build

# Stage 2: build the Go server.
FROM golang:1.26.6-alpine AS backend
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
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/worker ./cmd/worker

# Stage 3: runtime image. Distroless-static would be tighter but alpine
# stays consistent with brightcrm and gives us a shell for emergency debug.
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S hash && adduser -S -G hash hash
COPY --from=backend /out/server /usr/local/bin/hash-server
COPY --from=backend /out/worker /usr/local/bin/hash-worker
EXPOSE 8080
USER hash:hash
ENTRYPOINT ["/usr/local/bin/hash-server"]
