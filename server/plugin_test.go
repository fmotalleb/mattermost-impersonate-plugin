package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

type testAPI struct {
	plugin.API // Other unused methods are supplied by the embedded interface.
	config     *model.Config
	users      map[string]*model.User
	byName     map[string]*model.User
	kv         map[string][]byte
	created    []*model.Session
	revoked    []string
}

func newTestPlugin() (*Plugin, *testAPI) {
	site := "https://chat.example.test"
	subdomains := false
	a := &testAPI{
		config: &model.Config{ServiceSettings: model.ServiceSettings{SiteURL: &site, AllowCookiesForSubdomains: &subdomains}},
		users: map[string]*model.User{
			"admin": {Id: "admin", Username: "admin", Roles: "system_user system_admin"},
			"bob":   {Id: "bob", Username: "bob", Roles: "system_user"},
			"root":  {Id: "root", Username: "root", Roles: "system_user system_admin"},
		},
		kv: make(map[string][]byte),
	}
	a.byName = map[string]*model.User{"admin": a.users["admin"], "bob": a.users["bob"], "root": a.users["root"]}
	p := &Plugin{}
	p.API = a
	return p, a
}

func (a *testAPI) GetConfig() *model.Config                                  { return a.config }
func (a *testAPI) GetUser(id string) (*model.User, *model.AppError)          { return a.users[id], nil }
func (a *testAPI) GetUserByUsername(s string) (*model.User, *model.AppError) { return a.byName[s], nil }
func (a *testAPI) GetUsers(options *model.UserGetOptions) ([]*model.User, *model.AppError) {
	users := make([]*model.User, 0, len(a.users))
	for _, user := range a.users {
		users = append(users, user)
	}
	start := options.Page * options.PerPage
	if start >= len(users) {
		return nil, nil
	}
	end := start + options.PerPage
	if end > len(users) {
		end = len(users)
	}
	return users[start:end], nil
}
func (a *testAPI) CreateSession(s *model.Session) (*model.Session, *model.AppError) {
	s.Id = "created-session"
	s.Token = "created-secret-token"
	a.created = append(a.created, s)
	return s, nil
}
func (a *testAPI) RevokeSession(id string) *model.AppError {
	a.revoked = append(a.revoked, id)
	return nil
}
func (a *testAPI) KVSetWithExpiry(key string, value []byte, ttl int64) *model.AppError {
	a.kv[key] = value
	return nil
}
func (a *testAPI) KVGet(key string) ([]byte, *model.AppError) { return a.kv[key], nil }
func (a *testAPI) KVDelete(key string) *model.AppError        { delete(a.kv, key); return nil }
func (a *testAPI) KVList(page, size int) ([]string, *model.AppError) {
	var keys []string
	for k := range a.kv {
		keys = append(keys, k)
	}
	start := page * size
	if start >= len(keys) {
		return nil, nil
	}
	end := start + size
	if end > len(keys) {
		end = len(keys)
	}
	return keys[start:end], nil
}
func (*testAPI) LogError(string, ...any) {}
func (*testAPI) LogInfo(string, ...any)  {}
func (*testAPI) LogWarn(string, ...any)  {}

func call(p *Plugin, method, route, userID, contentType, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://chat.example.test"+route, strings.NewReader(body))
	r.URL.Path = route
	r.Header.Set("Mattermost-User-Id", userID)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
		r.Header.Set("Origin", "https://chat.example.test")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(nil, w, r)
	return w
}

func TestAdminOnlyPage(t *testing.T) {
	p, _ := newTestPlugin()
	if got := call(p, "GET", "/", "bob", "", "").Code; got != http.StatusForbidden {
		t.Fatalf("non-admin got %d, wanted 403", got)
	}
	res := call(p, "GET", "/", "admin", "", "")
	if res.Code != 200 {
		t.Fatalf("admin got %d", res.Code)
	}
	if len(res.Result().Cookies()) == 0 {
		t.Fatal("missing CSRF cookie")
	}
}

func TestCompleteSessionLifecycle(t *testing.T) {
	p, api := newTestPlugin()
	form := call(p, "GET", "/", "admin", "", "")
	csrf := form.Result().Cookies()[0]
	values := url.Values{"username": {"bob"}, "reason": {"Investigating channel memberships"}, "csrf": {csrf.Value}}
	start := call(p, "POST", "/start", "admin", "application/x-www-form-urlencoded", values.Encode(), csrf)
	if start.Code != http.StatusSeeOther {
		t.Fatalf("start returned %d: %s", start.Code, start.Body.String())
	}
	if len(api.created) != 1 || api.created[0].UserId != "bob" || api.created[0].Roles != "system_user" {
		t.Fatal("session not created with target identity and roles")
	}
	if api.created[0].ExpiresAt <= model.GetMillis() || api.created[0].ExpiresAt > model.GetMillis()+int64(16*time.Minute/time.Millisecond) {
		t.Fatal("invalid session expiry")
	}
	var auth, user, antiCSRF *http.Cookie
	for _, c := range start.Result().Cookies() {
		switch c.Name {
		case model.SessionCookieToken:
			auth = c
		case model.SessionCookieUser:
			user = c
		case model.SessionCookieCsrf:
			antiCSRF = c
		}
	}
	if auth == nil || user == nil || antiCSRF == nil || !auth.HttpOnly {
		t.Fatal("missing or insecure session cookies")
	}
	if user.Value != "bob" || auth.Value != api.created[0].Token {
		t.Fatal("cookies do not correspond to impersonated session")
	}
	status := call(p, "GET", "/status", "bob", "", "", auth)
	var result struct {
		Active bool   `json:"active"`
		Target string `json:"target"`
	}
	if status.Code != 200 || json.Unmarshal(status.Body.Bytes(), &result) != nil || !result.Active || result.Target != "bob" {
		t.Fatalf("unexpected status: %s", status.Body.String())
	}
	// A normal user session with a different token must not match this impersonation.
	other := call(p, "GET", "/status", "bob", "", "", &http.Cookie{Name: model.SessionCookieToken, Value: "normal-user-session"})
	if strings.Contains(other.Body.String(), `"active":true`) {
		t.Fatal("normal user session spoofed an impersonation")
	}

	bad := call(p, "POST", "/stop", "bob", "application/x-www-form-urlencoded", "csrf=wrong", auth, antiCSRF)
	if bad.Code != 403 || len(api.revoked) != 0 {
		t.Fatal("bad CSRF should not stop the session")
	}
	stop := call(p, "POST", "/stop", "bob", "application/x-www-form-urlencoded", url.Values{"csrf": {antiCSRF.Value}}.Encode(), auth, antiCSRF)
	if stop.Code != http.StatusSeeOther || len(api.revoked) != 1 || api.revoked[0] != api.created[0].Id {
		t.Fatalf("stop failed: %d %v", stop.Code, api.revoked)
	}
	if len(api.created) != 1 {
		t.Fatal("stop unexpectedly granted another (possibly admin) session")
	}
	if len(api.kv) != 0 {
		t.Fatal("session metadata was not removed")
	}
}

func TestRejectAdminTargetAndCSRF(t *testing.T) {
	p, api := newTestPlugin()
	form := call(p, "GET", "/", "admin", "", "")
	cookie := form.Result().Cookies()[0]
	values := url.Values{"username": {"root"}, "reason": {"Investigating an administrator"}, "csrf": {cookie.Value}}
	result := call(p, "POST", "/start", "admin", "application/x-www-form-urlencoded", values.Encode(), cookie)
	if result.Code != http.StatusForbidden || len(api.created) != 0 {
		t.Fatalf("admin-to-admin impersonation should be rejected (%d)", result.Code)
	}
	values.Set("username", "bob")
	values.Set("csrf", "invalid")
	result = call(p, "POST", "/start", "admin", "application/x-www-form-urlencoded", values.Encode(), cookie)
	if result.Code != http.StatusForbidden || len(api.created) != 0 {
		t.Fatal("CSRF bypass")
	}
}

func TestStopOnPluginShutdown(t *testing.T) {
	p, api := newTestPlugin()
	record, _ := json.Marshal(impersonation{SessionID: "active-session"})
	api.kv["session:abc"] = record
	if err := p.OnDeactivate(); err != nil {
		t.Fatal(err)
	}
	if len(api.revoked) != 1 || api.revoked[0] != "active-session" {
		t.Fatal("active session not revoked")
	}
}
