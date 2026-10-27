#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p server/dist dist
VERSION="${PLUGIN_VERSION:-$(sed -nE 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' plugin.json | head -n 1)}"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid plugin version: $VERSION (expected X.Y.Z)" >&2
    exit 1
fi
# Mattermost's public plugin API dependencies are downloaded by Go on a machine with network access.
go mod tidy
go mod download
for arch in amd64 arm64; do
    echo "Building linux-${arch}..."
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags='-s -w' \
        -o "server/dist/plugin-linux-${arch}" ./server
done
STAGING_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGING_DIR"' EXIT
sed -E "s/^([[:space:]]*\"version\"[[:space:]]*:[[:space:]]*\")[^\"]+(\".*)$/\1${VERSION}\2/" plugin.json > "$STAGING_DIR/plugin.json"
BUNDLE="dist/com.fmotalleb.impersonate-${VERSION}.tar.gz"
tar -czf "$BUNDLE" -C "$STAGING_DIR" plugin.json -C "$ROOT" \
    server/dist/plugin-linux-amd64 server/dist/plugin-linux-arm64 webapp/dist/main.js
echo "Bundle ready: $BUNDLE"
