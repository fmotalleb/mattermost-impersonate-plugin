package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

const (
	pluginID          = "com.fmotalleb.impersonate"
	formCSRFCookie    = "MMIMPERSONATECSRF"
	sessionLifetime   = 15 * time.Minute
	formLifetime      = 5 * time.Minute
	maxReasonLength   = 240
	minReasonLength   = 8
	maxUsernameLength = 64
)

// Plugin is deliberately server-only as far as authentication is concerned:
// no user session token ever reaches client-side JavaScript or HTML.
type Plugin struct {
	plugin.MattermostPlugin
}

// Best-effort revocation when the plugin is disabled. An abrupt process or
// server failure cannot call this hook, so all sessions additionally expire
// at the database layer after 15 minutes.
func (p *Plugin) OnDeactivate() error {
	var keys []string
	for page := 0; ; page++ {
		pageKeys, err := p.API.KVList(page, 100)
		if err != nil {
			p.API.LogError("Impersonation: unable to list sessions during shutdown", "error", err.Error())
			return err
		}
		for _, key := range pageKeys {
			if strings.HasPrefix(key, "session:") {
				keys = append(keys, key)
			}
		}
		if len(pageKeys) < 100 {
			break
		}
	}
	for _, key := range keys {
		data, err := p.API.KVGet(key)
		if err != nil {
			p.API.LogWarn("Impersonation: unable to read session on shutdown", "error", err.Error())
			continue
		}
		var record impersonation
		if json.Unmarshal(data, &record) != nil || record.SessionID == "" {
			continue
		}
		if err := p.API.RevokeSession(record.SessionID); err != nil {
			p.API.LogWarn("Impersonation: unable to revoke session on shutdown", "session_id", record.SessionID, "error", err.Error())
		} else {
			_ = p.API.KVDelete(key)
		}
	}
	return nil
}

type impersonation struct {
	ActorID    string `json:"actor_id"`
	ActorName  string `json:"actor_name"`
	TargetID   string `json:"target_id"`
	TargetName string `json:"target_name"`
	SessionID  string `json:"session_id"`
	ExpiresAt  int64  `json:"expires_at"`
	CSRF       string `json:"csrf"`
	Reason     string `json:"reason"`
}

func (p *Plugin) ServeHTTP(_ *plugin.Context, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")

	// Mattermost injects this identity header only for authenticated requests.
	// Never trust a user_id supplied in a form, URL, or JSON body. Some valid
	// browser sessions also carry an Authorization header, so its presence alone
	// does not make the server-provided identity untrusted.
	if r.Header.Get("Mattermost-User-Id") == "" {
		http.Error(w, "A Mattermost browser login is required", http.StatusUnauthorized)
		return
	}

	siteURL, err := p.siteURL()
	if err != nil {
		p.API.LogError("Impersonation: invalid Mattermost SiteURL", "error", err.Error())
		http.Error(w, "Mattermost SiteURL must be configured", http.StatusServiceUnavailable)
		return
	}

	switch r.URL.Path {
	case "/", "":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		p.adminPage(w, r, siteURL)
	case "/start":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		p.start(w, r, siteURL)
	case "/session":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		p.sessionPage(w, r, siteURL)
	case "/status":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		p.status(w, r)
	case "/stop":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		p.stop(w, r, siteURL)
	default:
		http.NotFound(w, r)
	}
}

func methodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// SiteURL must be the canonical browser URL, including any Mattermost subpath.
// HTTPS is mandatory except for loopback development servers.
func (p *Plugin) siteURL() (*url.URL, error) {
	config := p.API.GetConfig()
	if config == nil || config.ServiceSettings.SiteURL == nil {
		return nil, errors.New("SiteURL is empty")
	}
	u, err := url.Parse(*config.ServiceSettings.SiteURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid SiteURL")
	}
	if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "[::1]" && u.Hostname() != "::1" {
		return nil, errors.New("HTTPS is required outside localhost")
	}
	return u, nil
}

func rootPath(site *url.URL) string {
	base := strings.TrimSuffix(site.EscapedPath(), "/")
	if base == "" {
		return "/"
	}
	return base
}

func pluginPath(site *url.URL) string {
	base := rootPath(site)
	if base == "/" {
		base = ""
	}
	return base + "/plugins/" + pluginID
}

func mattermostHome(site *url.URL) string { return rootPath(site) }

func (p *Plugin) cookieDomain(site *url.URL) string {
	cfg := p.API.GetConfig()
	if cfg != nil && cfg.ServiceSettings.AllowCookiesForSubdomains != nil && *cfg.ServiceSettings.AllowCookiesForSubdomains {
		return site.Hostname()
	}
	return ""
}

func (p *Plugin) setAuthCookies(w http.ResponseWriter, site *url.URL, session *model.Session, lifetime time.Duration) {
	path := rootPath(site)
	domain := p.cookieDomain(site)
	maxAge := int(lifetime / time.Second)
	cookie := func(name, value string, httpOnly bool) {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: value, Path: path, Domain: domain,
			MaxAge: maxAge, Expires: time.Now().Add(lifetime),
			HttpOnly: httpOnly, Secure: site.Scheme == "https", SameSite: http.SameSiteLaxMode,
		})
	}
	cookie(model.SessionCookieToken, session.Token, true)
	cookie(model.SessionCookieUser, session.UserId, false)
	cookie(model.SessionCookieCsrf, session.GetCSRF(), false)
}

func (p *Plugin) clearAuthCookies(w http.ResponseWriter, site *url.URL) {
	for _, name := range []string{model.SessionCookieToken, model.SessionCookieUser, model.SessionCookieCsrf} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: rootPath(site), Domain: p.cookieDomain(site),
			MaxAge: -1, Expires: time.Unix(1, 0), Secure: site.Scheme == "https",
			SameSite: http.SameSiteLaxMode, HttpOnly: name == model.SessionCookieToken,
		})
	}
}

func newCSRF() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func sameOrigin(r *http.Request, site *url.URL) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	} // Browser form POSTs include Origin; fail closed.
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != site.Scheme || !strings.EqualFold(u.Host, site.Host) || u.User != nil {
		return false
	}
	return u.Path == "" || u.Path == "/"
}

func verifyFormCSRF(r *http.Request, name, supplied string) bool {
	cookie, err := r.Cookie(name)
	return err == nil && len(supplied) > 0 &&
		len(cookie.Value) == len(supplied) &&
		subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(supplied)) == 1
}

func tokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "session:" + hex.EncodeToString(sum[:])
}

func (p *Plugin) lookup(r *http.Request) (*impersonation, bool) {
	cookie, err := r.Cookie(model.SessionCookieToken)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	data, appErr := p.API.KVGet(tokenKey(cookie.Value))
	if appErr != nil {
		p.API.LogError("Impersonation: KVGet failed", "error", appErr.Error())
		return nil, false
	}
	if len(data) == 0 {
		return nil, false
	}
	var record impersonation
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, false
	}
	if record.TargetID != r.Header.Get("Mattermost-User-Id") ||
		record.ExpiresAt <= model.GetMillis() || record.SessionID == "" {
		return nil, false
	}
	return &record, true
}

func (p *Plugin) requireAdmin(w http.ResponseWriter, r *http.Request) *model.User {
	user, appErr := p.API.GetUser(r.Header.Get("Mattermost-User-Id"))
	if appErr != nil || user == nil || user.DeleteAt != 0 || !user.IsSystemAdmin() {
		http.Error(w, "Only Mattermost system administrators may impersonate users", http.StatusForbidden)
		return nil
	}
	return user
}

var adminTmpl = template.Must(template.New("admin").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Impersonation</title><style>
body{font-family:system-ui,sans-serif;max-width:650px;margin:4rem auto;padding:0 1.2rem;line-height:1.5}input,textarea,select,button{font:inherit;padding:.7rem;width:100%;box-sizing:border-box;margin:.35rem 0 1.1rem}button{background:#155fc1;color:white;border:0;border-radius:5px;cursor:pointer}aside{background:#fff4de;padding:1rem;border-left:4px solid #b97110}small{color:#555}
</style></head><body><h1>Impersonate a user</h1><p>Signed in as <b>{{.Admin}}</b> (system admin).</p><aside><b>Privileged action:</b> all activity will run with the target user's permissions, be identified as their activity inside Mattermost, and be logged with your admin account in server logs. This is not a read-only preview. The temporary session lasts 15 minutes. On exit you must log in again as admin. Other tabs in this browser will also switch accounts.</aside><form method="POST" action="{{.Base}}/start"><input type="hidden" name="csrf" value="{{.CSRF}}"><label for="username">Target user</label><select id="username" name="username" required><option value="" selected disabled>Select a user</option>{{range .Targets}}<option value="{{.Username}}">@{{.Username}}{{if .FullName}} — {{.FullName}}{{end}}</option>{{end}}</select><label for="reason">Audit reason (8 to 240 characters)</label><textarea id="reason" name="reason" required minlength="8" maxlength="240" rows="3"></textarea><button type="submit">Start impersonation</button></form><small>System admins, bot users, disabled users, remote users, and your own account are excluded. Use a private browser window if you need your normal admin session open elsewhere.</small></body></html>`))

type userOption struct {
	Username string
	FullName string
}

var sessionTmpl = template.Must(template.New("session").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Impersonation Active</title><style>body{font-family:system-ui,sans-serif;max-width:650px;margin:4rem auto;padding:0 1.2rem;line-height:1.5}article{padding:1.5rem;background:#fff2d4;border-left:5px solid #ba6e00}button{font:inherit;padding:.8rem 1.2rem;background:#aa261d;color:white;border:0;border-radius:5px;cursor:pointer}a{display:inline-block;margin:1rem 0}</style></head><body><article><h1>Impersonation is active</h1><p>You are acting as <b>@{{.Target}}</b> on behalf of system admin <b>@{{.Actor}}</b>.</p><p>Temporary session expiration: <b>{{.Expiry}}</b> (UTC).</p><p>Activity will appear to others as the target user. Follow your organization's approval policy.</p></article><p><a href="{{.Home}}">Open Mattermost as @{{.Target}}</a></p><form method="POST" action="{{.Base}}/stop"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">Stop impersonation and sign out</button></form></body></html>`))

func htmlPage(w http.ResponseWriter, tmpl *template.Template, data any, scriptNonce string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	csp := "default-src 'none'; base-uri 'none'; form-action 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'"
	if scriptNonce != "" {
		csp += "; script-src 'nonce-" + scriptNonce + "'"
	}
	w.Header().Set("Content-Security-Policy", csp)
	if err := tmpl.Execute(w, data); err != nil {
		// This is after the response has started, so only log it in callers if desired.
		return
	}
}

func (p *Plugin) adminPage(w http.ResponseWriter, r *http.Request, site *url.URL) {
	admin := p.requireAdmin(w, r)
	if admin == nil {
		return
	}
	targets, err := p.eligibleUsers(admin)
	if err != nil {
		p.API.LogError("Impersonation: unable to list target users", "error", err.Error())
		http.Error(w, "Unable to load users", http.StatusInternalServerError)
		return
	}
	token, err := newCSRF()
	if err != nil {
		http.Error(w, "Unable to prepare form", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: formCSRFCookie, Value: token, Path: pluginPath(site),
		MaxAge: int(formLifetime.Seconds()), Expires: time.Now().Add(formLifetime),
		HttpOnly: true, Secure: site.Scheme == "https", SameSite: http.SameSiteStrictMode})
	htmlPage(w, adminTmpl, struct {
		Admin, Base, CSRF string
		Targets           []userOption
	}{admin.Username, pluginPath(site), token, targets}, "")
}

func (p *Plugin) eligibleUsers(admin *model.User) ([]userOption, error) {
	const pageSize = 200
	options := make([]userOption, 0)
	for page := 0; ; page++ {
		users, appErr := p.API.GetUsers(&model.UserGetOptions{Page: page, PerPage: pageSize})
		if appErr != nil {
			return nil, appErr
		}
		for _, user := range users {
			if user == nil || user.Id == admin.Id || user.DeleteAt != 0 || user.IsSystemAdmin() || user.IsBot || user.IsRemote() {
				continue
			}
			options = append(options, userOption{Username: user.Username, FullName: user.GetFullName()})
		}
		if len(users) < pageSize {
			break
		}
	}
	sort.Slice(options, func(i, j int) bool {
		return strings.ToLower(options[i].Username) < strings.ToLower(options[j].Username)
	})
	return options, nil
}

func (p *Plugin) start(w http.ResponseWriter, r *http.Request, site *url.URL) {
	admin := p.requireAdmin(w, r)
	if admin == nil {
		return
	}
	if !sameOrigin(r, site) || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		http.Error(w, "Invalid request origin or content type", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	if !verifyFormCSRF(r, formCSRFCookie, r.PostForm.Get("csrf")) {
		http.Error(w, "Invalid or expired CSRF token", http.StatusForbidden)
		return
	}
	username := strings.TrimPrefix(strings.TrimSpace(r.PostForm.Get("username")), "@")
	reason := strings.TrimSpace(r.PostForm.Get("reason"))
	if len(username) < 1 || len(username) > maxUsernameLength || !model.IsValidUsername(username) ||
		len(reason) < minReasonLength || len(reason) > maxReasonLength || strings.ContainsAny(reason, "\x00\r\n") {
		http.Error(w, "Invalid target username or audit reason", http.StatusBadRequest)
		return
	}
	target, appErr := p.API.GetUserByUsername(username)
	if appErr != nil || target == nil {
		http.Error(w, "Target user not found", http.StatusNotFound)
		return
	}
	if target.Id == admin.Id || target.IsSystemAdmin() || target.IsBot || target.IsRemote() || target.DeleteAt != 0 {
		p.API.LogWarn("Impersonation denied for ineligible target", "actor_id", admin.Id, "target_id", target.Id)
		http.Error(w, "The requested account cannot be impersonated", http.StatusForbidden)
		return
	}

	// Use precisely the target's own role set: no admin permissions are inherited.
	sess := &model.Session{
		UserId:    target.Id,
		Roles:     target.GetRawRoles(),
		ExpiresAt: model.GetMillis() + int64(sessionLifetime/time.Millisecond),
		Props: model.StringMap{
			"impersonation_plugin":        pluginID,
			"impersonated_by":             admin.Id,
			model.SessionPropPlatform:     "web",
			model.SessionPropBrowser:      "Admin Impersonation",
			model.UserAuthServiceIsMobile: "false",
			model.SessionPropIsGuest:      "false",
		},
	}
	if target.IsGuest() {
		sess.Props[model.SessionPropIsGuest] = "true"
	}
	sess.GenerateCSRF()
	created, appErr := p.API.CreateSession(sess)
	if appErr != nil || created == nil || created.Token == "" || created.Id == "" {
		p.API.LogError("Impersonation: failed to create session", "actor_id", admin.Id, "target_id", target.Id)
		http.Error(w, "Unable to create impersonation session", http.StatusInternalServerError)
		return
	}

	rec := impersonation{
		ActorID: admin.Id, ActorName: admin.Username,
		TargetID: target.Id, TargetName: target.Username,
		SessionID: created.Id, ExpiresAt: created.ExpiresAt,
		CSRF: created.GetCSRF(), Reason: reason,
	}
	data, err := json.Marshal(rec)
	if err != nil || p.API.KVSetWithExpiry(tokenKey(created.Token), data, int64((sessionLifetime+time.Hour)/time.Second)) != nil {
		_ = p.API.RevokeSession(created.Id)
		p.API.LogError("Impersonation: failed to persist session metadata", "actor_id", admin.Id, "target_id", target.Id)
		http.Error(w, "Unable to persist impersonation session", http.StatusInternalServerError)
		return
	}

	// Clear one-time form cookie to prevent replay through another admin session.
	http.SetCookie(w, &http.Cookie{Name: formCSRFCookie, Value: "", Path: pluginPath(site),
		MaxAge: -1, HttpOnly: true, Secure: site.Scheme == "https", SameSite: http.SameSiteStrictMode})
	p.API.LogInfo("Impersonation started", "actor_id", admin.Id, "actor_username", admin.Username,
		"target_id", target.Id, "target_username", target.Username,
		"impersonation_session_id", created.Id, "expires_at", created.ExpiresAt, "reason", reason)
	p.setAuthCookies(w, site, created, sessionLifetime)
	http.Redirect(w, r, pluginPath(site)+"/session", http.StatusSeeOther)
}

func (p *Plugin) sessionPage(w http.ResponseWriter, r *http.Request, site *url.URL) {
	rec, ok := p.lookup(r)
	if !ok {
		http.Error(w, "No active impersonation session", http.StatusForbidden)
		return
	}
	htmlPage(w, sessionTmpl, struct{ Target, Actor, Base, Home, Expiry, CSRF string }{
		rec.TargetName, rec.ActorName, pluginPath(site), mattermostHome(site),
		time.UnixMilli(rec.ExpiresAt).UTC().Format("2006-01-02 15:04:05"), rec.CSRF,
	}, "")
}

func (p *Plugin) status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rec, ok := p.lookup(r)
	if !ok {
		_, _ = w.Write([]byte(`{"active":false}`))
		return
	}
	_ = json.NewEncoder(w).Encode(struct {
		Active    bool   `json:"active"`
		Target    string `json:"target"`
		Actor     string `json:"actor"`
		ExpiresAt int64  `json:"expires_at"`
	}{true, rec.TargetName, rec.ActorName, rec.ExpiresAt})
}

func (p *Plugin) stop(w http.ResponseWriter, r *http.Request, site *url.URL) {
	rec, ok := p.lookup(r)
	if !ok {
		http.Error(w, "No active impersonation session", http.StatusForbidden)
		return
	}
	if !sameOrigin(r, site) || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		http.Error(w, "Invalid request origin or content type", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	csrfCookie, err := r.Cookie(model.SessionCookieCsrf)
	if err != nil || !verifyFormCSRF(r, model.SessionCookieCsrf, r.PostForm.Get("csrf")) ||
		len(csrfCookie.Value) != len(rec.CSRF) || subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(rec.CSRF)) != 1 {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Never mint or return an administrator token here. A stolen target session
	// must not become a system administrator session through the /stop endpoint.
	if appErr := p.API.RevokeSession(rec.SessionID); appErr != nil {
		p.API.LogError("Impersonation: unable to revoke", "session_id", rec.SessionID, "error", appErr.Error())
		http.Error(w, "Unable to revoke impersonation session", http.StatusInternalServerError)
		return
	}
	if cookie, err := r.Cookie(model.SessionCookieToken); err == nil {
		if err := p.API.KVDelete(tokenKey(cookie.Value)); err != nil {
			p.API.LogWarn("Impersonation: unable to remove expired session metadata", "session_id", rec.SessionID)
		}
	}
	p.API.LogInfo("Impersonation ended", "actor_id", rec.ActorID,
		"target_id", rec.TargetID, "session_id", rec.SessionID, "reason", rec.Reason)
	p.clearAuthCookies(w, site)
	http.Redirect(w, r, strings.TrimSuffix(mattermostHome(site), "/")+"/login", http.StatusSeeOther)
}
