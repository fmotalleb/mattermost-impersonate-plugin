# Repository Guidelines

## Project Structure

This repository contains a server-side Mattermost plugin written in Go. `server/main.go` is the plugin entry point; `server/plugin.go` implements HTTP routes, user/session checks, CSRF protections, and audit logging. Handler tests live beside the implementation in `server/plugin_test.go`. `plugin.json` defines the plugin manifest and Linux executable paths. The web and desktop client bundle is the plain JavaScript file at `webapp/dist/main.js`. `scripts/build.sh` builds and packages the release archive.

## Build, Test, and Development

- `go test ./server -v` runs the HTTP-handler tests.
- `go test ./...` runs all Go tests in the module.
- `./scripts/build.sh` tidies and downloads Go modules, builds Linux amd64 and arm64 executables, then creates `dist/com.example.impersonate-0.1.0.tar.gz`.

The build requires Go 1.26.7 or newer and access to the Go module proxy. Build output is generated under `server/dist/` and `dist/`.

## Coding Style

Use standard Go formatting (`gofmt`) and keep implementation in the existing `server` package unless a clear module boundary requires otherwise. Name Go tests `Test...` and keep focused handler tests in `server/plugin_test.go`. Keep the webapp bundle dependency-free unless the project adds and documents a frontend build system.

## Testing Guidelines

Add or update handler tests for changes to routes, authorization, CSRF, session creation/revocation, or plugin lifecycle behavior. Use the fake Mattermost API in `plugin_test.go` for isolated cases. These tests do not replace staging validation against a live Mattermost server; authentication and cookie behavior must be checked end to end before deployment.

## Security and Configuration

Treat session tokens, impersonation records, and audit reasons as sensitive. Never expose session tokens in logs, URLs, client-side code, or responses. Preserve admin-only authorization, target-account restrictions, Mattermost and plugin CSRF checks, short session expiry, and explicit session revocation. Use HTTPS outside loopback development and verify `SiteURL` and any proxy or cookie configuration in staging.

## Commits and Pull Requests

The repository history currently contains only the initial `init` commit, so no established message convention is available. Use a short imperative commit subject describing one change. Pull requests should explain the behavior and security impact, list validation commands and their results, and include staging evidence for changes affecting authentication or cookies.
