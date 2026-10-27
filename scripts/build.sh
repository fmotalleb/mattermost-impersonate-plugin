#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p server/dist dist
# Mattermost's public plugin API dependencies are downloaded by Go on a machine with network access.
go mod tidy
go mod download
for arch in amd64 arm64; do
    echo "Building linux-${arch}..."
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags='-s -w' \
        -o "server/dist/plugin-linux-${arch}" ./server
done
tar -czf dist/com.example.impersonate-0.1.0.tar.gz plugin.json \
    server/dist/plugin-linux-amd64 server/dist/plugin-linux-arm64 webapp/dist/main.js
echo "Bundle ready: dist/com.example.impersonate-0.1.0.tar.gz"
