# Mattermost Admin Impersonation Plugin

**Status:** source implementation / security-sensitive prototype. Tested at the HTTP-handler level with fake Mattermost API objects. **Not compiled against or integration-tested with a live Mattermost server in this environment.** Perform an end-to-end test on a staging server before production use.

## Purpose

Allows a Mattermost **system administrator** to temporarily act as a *non-admin* user in the Mattermost web or desktop client, using a **new server-side user session**. This is a real account switch, **not read-only preview mode**. Messages and changes made during the session are attributed by Mattermost to the target user. Server logs link the impersonation session to the administrator and the required reason.

## Included features

- Admin-only menu shortcut and standalone user-switch form, with a mandatory audit reason.
- Creates a session with exactly the target user's existing roles; session lifetime is 15 minutes.
- Restricts impersonation of system admins, bot accounts, disabled accounts, remote users, and yourself.
- Session markers and an opaque KV record used to identify impersonation sessions. The KV key is a SHA-256 hash of the browser session token; the token itself is **never put in logs, JSON responses, URLs or local storage**.
- Web/desktop banner identifies the admin and the target user and links to a session exit page. The banner is not implemented for native mobile clients.
- Explicit **Stop impersonation and sign out** action revokes the target session and clears Mattermost auth cookies.
- Start/stop events are written to the Mattermost server logs with admin, target, session ID and reason.
- Mattermost and plugin CSRF checks, no-cache response headers and session cookie security settings.
- Best-effort revocation of active sessions on plugin deactivation, plus 15-minute server session expiry.

## Dependencies

- Mattermost server **11.x or later** is the declared minimum (validate with your deployed version).
- Go toolchain **1.26.7 or newer** for the pinned `github.com/mattermost/mattermost/server/public v0.5.0` module.
- Outbound access to Go modules when building.
- Mattermost **SiteURL configured correctly**, including the subpath if you use one.
- **HTTPS** in production. Only localhost/loopback HTTP is accepted for development.
- Built-in server plugins and plugin uploads must be enabled.

## Build

```bash
# Unzip this source package, then:
cd mattermost-impersonate-plugin
./scripts/build.sh
```

This generates a Linux x86-64 + ARM64 Mattermost plugin install bundle at `dist/com.fmotalleb.impersonate-VERSION.tar.gz`. By default, `VERSION` comes from `plugin.json`; set `PLUGIN_VERSION=1.2.3` to override it. The manifest version inside the bundle uses the same value.

The script runs `go mod tidy` and `go mod download`, builds the Go server executables and creates the Mattermost upload archive. The bundled `webapp/main.js` is plain JavaScript (copied to `webapp/dist/main.js` during packaging) and does not need an npm step. Pushing a `vX.Y.Z` Git tag runs the GitHub Actions build and uploads the matching bundle as a workflow artifact.

## Installation

1. Back up your Mattermost configuration and test first on staging.
2. In Mattermost System Console, enable plugins and plugin uploads (or configure `PluginSettings.Enable` and `PluginSettings.EnableUploads` appropriately).
3. Upload `dist/com.fmotalleb.impersonate-VERSION.tar.gz` under **System Console → Plugins → Plugin Management** and enable the plugin.
4. Sign in with a system admin account using the web browser.
5. Choose **Impersonate user** from the main menu, or open:

   `https://YOUR-MATTERMOST-HOST/plugins/com.fmotalleb.impersonate/`

   If Mattermost is hosted under a subpath, prepend it, e.g. `/mattermost/plugins/com.fmotalleb.impersonate/`.
6. Enter a non-admin target username and an audit reason; select **Start impersonation**.
7. In the next page, select **Open Mattermost**. A banner indicates the impersonated identity.
8. Select **Stop impersonation** from the banner, then **Stop impersonation and sign out**. Sign in again as admin normally.

## Security properties and operational limitations

**This is powerful by design.** Mattermost documents that trusted server plugins can perform actions on behalf of users. Only install after code review and approval.

- **No return-to-admin token:** the stop action never creates or restores an administrator session. It revokes the temporary user session and redirects to `/login`, preventing a stolen impersonation session from being exchanged for administrator privileges.
- **Same-origin browser cookie jar:** all Mattermost tabs on the same hostname share auth cookies. Start in an isolated browser profile or separate private browsing context if you want to leave your primary admin login intact. Refresh any other Mattermost tabs after switching.
- **Audit limitations:** Mattermost records ordinary posts/actions as the *target user*. The plugin's separate start/stop log connects the session to the initiating admin, but does **not** append the admin identity to each message or create an immutable audit ledger. Forward server logs to a tamper-evident external log store. Existing Mattermost compliance/retention policies continue to apply.
- **Authentication policy:** this workflow intentionally bypasses the target account's password, SSO and MFA challenge by creating a new session. An authorized admin should use it only with approved procedures and a documented reason.
- **Banner scope:** the webapp banner can be hidden by changing the client; it is a visibility aid, not an enforcement boundary. Native mobile clients are not supported by the banner.
- **Expiry:** the target session itself expires in 15 minutes; the browser cookies are also given that lifetime. If the session expires while the page is open, you will have to sign in again.
- **Plugin disable/crash:** the plugin attempts to revoke active impersonation sessions on orderly deactivation. A hard server crash or outage can prevent that callback; the short server-side expiry remains the fallback. Disable the plugin only after checking active sessions on production systems.
- **Cookie scope:** the plugin mirrors Mattermost's standard `MMAUTHTOKEN`, `MMUSERID` and `MMCSRF` cookies and its `AllowCookiesForSubdomains` setting. Verify custom reverse proxies, embedded deployments, and authentication layers in staging.
- **Not a complete delegated access control system:** there is no separate approval step, per-action identity tagging or enterprise audit export. If your governance rules require those, additional integration is needed.

## Test

`go test ./server -v` runs the included handler tests when Mattermost dependencies can be resolved. Tests cover admin access, prohibited target accounts, CSRF, session creation with target roles, status isolation, stop/revoke and plugin deactivation. These tests do not replace a live-server test.

## Project layout

```text
plugin.json                     Plugin manifest (webapp + Linux server executables)
go.mod                          Go dependency declaration
server/main.go                  Plugin entry point
server/plugin.go                Authentication/session logic, routes, audit logging
server/plugin_test.go           HTTP-handler tests
webapp/main.js                  Web/desktop banner and admin menu item source
scripts/build.sh                Build and archive script
```

## Deployment checklist

- [ ] Confirm compatibility with your Mattermost version and custom authentication setup.
- [ ] Review access policy for target accounts, including MFA users.
- [ ] Test on staging with a dedicated system admin and test user.
- [ ] Verify start, stop, timeout, restart, plugin-disable behavior and audit output.
- [ ] Verify all browser tabs and the desktop app when an account switches.
- [ ] Forward the Mattermost server logs to your monitoring or security log pipeline.
