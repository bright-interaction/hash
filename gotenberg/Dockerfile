# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM golang:1.26.7-alpine3.24@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS builder
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY gotenberg/go.mod gotenberg/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download \
    && go mod verify \
    && install -d /out \
    && cp -R /go/pkg/mod/github.com/gotenberg/gotenberg/v8@v8.36.0/build/chromium-hyphen-data /out/ \
    && cp /go/pkg/mod/github.com/gotenberg/gotenberg/v8@v8.36.0/LICENSE /out/GOTENBERG-MIT.txt
COPY gotenberg/*.go ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags='-s -w -X github.com/gotenberg/gotenberg/v8/cmd.Version=8.36.0-hash.1' \
      -o /out/gotenberg .

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
LABEL org.opencontainers.image.title="Hash Chromium renderer" \
      org.opencontainers.image.description="Minimal Gotenberg-compatible HTML-to-PDF renderer for Hash" \
      org.opencontainers.image.version="8.36.0-hash.1" \
      org.opencontainers.image.authors="Bright Interaction" \
      org.opencontainers.image.vendor="Bright Interaction" \
      org.opencontainers.image.licenses="LicenseRef-Hash-Sustainable-Use-License" \
      io.brightinteraction.hash.gotenberg.upstream.source="https://github.com/gotenberg/gotenberg" \
      io.brightinteraction.hash.gotenberg.upstream.license="MIT" \
      io.brightinteraction.hash.gotenberg.upstream.version="8.36.0" \
      io.brightinteraction.hash.gotenberg.upstream.revision="c0f487e333a78b5b5f3617c0d2978f900b0cc3f2" \
      io.brightinteraction.hash.gotenberg.upstream.module-h1="h1:K4VDxqHRBIh/yKJbEStzQlaWOl286AnNjFwRFDtoKYc=" \
      io.brightinteraction.hash.gotenberg.upstream.module-h1-sha256="2b8543c6a1d104887fc8a25b112b734256963a5dbce809cd8c5c11143b682987"

# Alpine 3.24 currently supplies Chromium 152, above the patched security
# floor. The lower bounds make repository lag fail the build closed.
RUN apk add --no-cache \
      'chromium>=152.0.7977.82-r0' \
      'libcrypto3>=3.5.8-r0' \
      'libssl3>=3.5.8-r0' \
      ca-certificates \
      font-noto \
      font-noto-cjk \
      font-noto-emoji \
      tini \
    && addgroup -g 1001 -S gotenberg \
    && adduser -u 1001 -S -D -H -G gotenberg gotenberg \
    && install -d -o gotenberg -g gotenberg /home/gotenberg /opt/gotenberg/chromium-hyphen-data

COPY --from=builder /out/gotenberg /usr/local/bin/gotenberg
COPY --from=builder --chown=1001:1001 /out/chromium-hyphen-data/ /opt/gotenberg/chromium-hyphen-data/
COPY LICENSE /licenses/HASH.txt
COPY --from=builder /out/GOTENBERG-MIT.txt /licenses/GOTENBERG-MIT.txt

# Alpine Chromium 152 starts Crashpad even in headless mode. Keep its config
# database on the only writable filesystem in the read-only runtime; otherwise
# the first conversion fails with "chrome_crashpad_handler: --database is
# required" while the API health endpoint remains green. Auto-start makes
# container readiness exercise this browser bootstrap before Hash sends work.
ENV XDG_CONFIG_HOME=/tmp/.config \
    CHROMIUM_AUTO_START=true \
    CHROMIUM_BIN_PATH=/usr/bin/chromium \
    CHROMIUM_HYPHEN_DATA_DIR_PATH=/opt/gotenberg/chromium-hyphen-data \
    CHROMIUM_DENY_PRIVATE_IPS=true \
    CHROMIUM_DENY_PUBLIC_IPS=true \
    CHROMIUM_DENY_LIST=^https?://.* \
    API_DISABLE_DOWNLOAD_FROM=true \
    OTEL_TRACES_EXPORTER=none \
    OTEL_METRICS_EXPORTER=none \
    OTEL_LOGS_EXPORTER=none \
    PDFENGINES_DISABLE_ROUTES=true \
    PDFENGINES_MERGE_ENGINES=hash-render-only \
    PDFENGINES_SPLIT_ENGINES=hash-render-only \
    PDFENGINES_FLATTEN_ENGINES=hash-render-only \
    PDFENGINES_CONVERT_ENGINES=hash-render-only \
    PDFENGINES_OPTIMIZE_IMAGES_ENGINES=hash-render-only \
    PDFENGINES_READ_METADATA_ENGINES=hash-render-only \
    PDFENGINES_WRITE_METADATA_ENGINES=hash-render-only \
    PDFENGINES_ENCRYPT_ENGINES=hash-render-only \
    PDFENGINES_EMBED_ENGINES=hash-render-only \
    PDFENGINES_EMBED_METADATA_ENGINES=hash-render-only \
    PDFENGINES_READ_BOOKMARKS_ENGINES=hash-render-only \
    PDFENGINES_WRITE_BOOKMARKS_ENGINES=hash-render-only \
    PDFENGINES_WATERMARK_ENGINES=hash-render-only \
    PDFENGINES_STAMP_ENGINES=hash-render-only \
    PDFENGINES_ROTATE_ENGINES=hash-render-only \
    PDFENGINES_FACTUR_X_ENGINES=hash-render-only

USER gotenberg:gotenberg
WORKDIR /home/gotenberg
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=12 \
    CMD wget -q -O /dev/null http://127.0.0.1:3000/health || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["gotenberg", "--pdfengines-disable-routes=true", "--api-disable-download-from=true"]
