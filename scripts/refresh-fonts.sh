#!/usr/bin/env bash
# refresh-fonts.sh - re-fetch every self-hosted woff2 binary Hash needs.
#
# We host fonts ourselves (no Google Fonts, no third-party CDN at runtime).
# When upstream refreshes a face we re-run this script, commit the new bytes
# alongside the Go embed assets, and a single deploy ships the new fonts.
#
# Idempotent: skips downloads that already exist on disk. Pass -f to force.
# Source: Google Fonts CSS2 API (returns @font-face declarations pointing at
# gstatic). All eight families are SIL OFL-licensed; redistribution OK.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/frontend/static/fonts"
ASSET_DIR="$ROOT/internal/render/assets"
UA='Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0'

force="false"
if [ "${1-}" = "-f" ] || [ "${1-}" = "--force" ]; then
    force="true"
fi

mkdir -p "$DIR" "$ASSET_DIR"
cd "$DIR"

queries=(
    "family=Inter:wght@300..700&display=swap"
    "family=Geist:wght@300..700&display=swap"
    "family=JetBrains+Mono:wght@400;500&display=swap"
    "family=Caveat&display=swap"
    "family=Dancing+Script&display=swap"
    "family=Great+Vibes&display=swap"
    "family=Sacramento&display=swap"
    "family=Homemade+Apple&display=swap"
)

raw="$(mktemp)"
trap 'rm -f "$raw"' EXIT
: > "$raw"
for q in "${queries[@]}"; do
    curl -fsSA "$UA" "https://fonts.googleapis.com/css2?$q" >> "$raw"
    printf '\n/* ---- */\n' >> "$raw"
done

# Download every gstatic woff2 referenced by the upstream CSS.
grep -oE "url\(https://fonts\.gstatic\.com[^)]+\)" "$raw" \
    | sed 's#^url(##;s#)$##' \
    | sort -u \
    | while IFS= read -r url; do
        fn="$(basename "$url")"
        if [ "$force" = "true" ] || [ ! -s "$fn" ]; then
            curl -fsSA "$UA" -o "$fn" "$url"
        fi
done

# Rewrite gstatic URLs to local /fonts/ paths and ship the result as fonts.css.
sed -E 's#https://fonts\.gstatic\.com/s/[^/]+/v[0-9]+/([^)]+\.woff2)#/fonts/\1#g' "$raw" > fonts.css

# Refresh the curated Go embed assets used by the PDF renderer. Friendly
# names so the rendered HTML can reference url('./Caveat.woff2') etc.
declare -A MAP=(
    [Caveat]='Caveat[a-zA-Z0-9_-]*\.woff2'
    [DancingScript]='Dancing[A-Za-z0-9_-]*\.woff2'
    [GreatVibes]='Great[A-Za-z0-9_-]*Vibes[A-Za-z0-9_-]*\.woff2'
    [Sacramento]='Sacramento[A-Za-z0-9_-]*\.woff2'
    [HomemadeApple]='Homemade[A-Za-z0-9_-]*\.woff2'
    [Inter]='Inter[A-Za-z0-9_-]*\.woff2'
    [Geist]='Geist[A-Za-z0-9_-]*\.woff2'
)

# The gstatic filenames are opaque hashes, so map by family slug from the
# upstream URL path instead: /s/<slug>/v<n>/<hash>.woff2.
declare -A SLUG=(
    [Caveat]='caveat'
    [DancingScript]='dancingscript'
    [GreatVibes]='greatvibes'
    [Sacramento]='sacramento'
    [HomemadeApple]='homemadeapple'
    [Inter]='inter'
    [Geist]='geist'
)

for friendly in "${!SLUG[@]}"; do
    slug="${SLUG[$friendly]}"
    latin_url="$(grep -B1 'unicode-range: U+0000-00FF' "$raw" \
        | grep -oE "url\(https://fonts\.gstatic\.com/s/$slug/v[0-9]+/[^)]+\.woff2\)" \
        | head -1 | sed 's#^url(##;s#)$##' || true)"
    if [ -z "$latin_url" ]; then
        # Calligraphy faces ship a single latin face without that comment.
        latin_url="$(grep -oE "url\(https://fonts\.gstatic\.com/s/$slug/v[0-9]+/[^)]+\.woff2\)" "$raw" \
            | head -1 | sed 's#^url(##;s#)$##' || true)"
    fi
    if [ -z "$latin_url" ]; then
        echo "warn: no latin face for $friendly ($slug); skipping embed" >&2
        continue
    fi
    src="$DIR/$(basename "$latin_url")"
    dst="$ASSET_DIR/$friendly.woff2"
    if [ -s "$src" ]; then
        cp "$src" "$dst"
    fi
done

echo "Refreshed fonts in $DIR + $ASSET_DIR"
echo "Re-run 'go test ./internal/render/...' to verify woff2 magic."
