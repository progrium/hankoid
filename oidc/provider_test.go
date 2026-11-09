package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/progrium/hankoid/frontend"
	"golang.org/x/oauth2"
)

// hostTransport routes requests to in-process handlers by host, so tests need no sockets.
type hostTransport map[string]http.Handler

func (t hostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h, ok := t[req.URL.Host]
	if !ok {
		h = http.NotFoundHandler()
	}
	rec := httptest.NewRecorder()
	req = req.Clone(req.Context())
	if req.RemoteAddr == "" {
		req.RemoteAddr = "192.0.2.1:1234"
	}
	h.ServeHTTP(rec, req)
	res := rec.Result()
	res.Request = req
	return res, nil
}

// fakeHanko is the Hanko public and admin APIs. Cookie "hanko=<user>" is a session.
type fakeHanko struct {
	mu       sync.Mutex
	sessions map[string]string // session id -> user id
	users    map[string]string // user id -> admin API user JSON
	orgs     map[string]string // user id -> validate "organizations" JSON
	logouts  int
}

func newFakeHanko() *fakeHanko {
	return &fakeHanko{
		sessions: map[string]string{"s-alice": "alice", "s-bob": "bob"},
		users: map[string]string{
			"alice": `{"id":"alice","emails":[{"address":"alice@x.io","is_verified":true,"is_primary":true}],"username":{"username":"alice"},"name":"Alice A","organizations":[{"id":"o1","name":"Mail","roles":[{"slug":"editor"}]}]}`,
			"bob":   `{"id":"bob","emails":[{"address":"bob@x.io","is_verified":true,"is_primary":true}]}`,
		},
		orgs: map[string]string{"alice": `[{"id":"o1","name":"Mail","roles":["editor"]}]`},
	}
}

func (f *fakeHanko) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cookieSession := func() (sid, uid string) {
		c, err := r.Cookie("hanko")
		if err != nil {
			return "", ""
		}
		sid = "s-" + c.Value
		return sid, f.sessions[sid]
	}
	switch {
	case r.Host == "public.test" && r.URL.Path == "/sessions/validate":
		sid, uid := cookieSession()
		if uid == "" {
			io.WriteString(w, `{"is_valid":false}`)
			return
		}
		var u struct {
			Emails []struct {
				Address    string `json:"address"`
				IsVerified bool   `json:"is_verified"`
			} `json:"emails"`
		}
		_ = json.Unmarshal([]byte(f.users[uid]), &u)
		orgs := f.orgs[uid]
		if orgs == "" {
			orgs = "[]"
		}
		io.WriteString(w, `{"is_valid":true,"claims":{"subject":"`+uid+`","session_id":"`+sid+`","issued_at":"2026-01-01T00:00:00Z","email":{"address":"`+u.Emails[0].Address+`","is_verified":true}},"organizations":`+orgs+`}`)
	case r.Host == "public.test" && r.URL.Path == "/logout" && r.Method == http.MethodPost:
		sid, uid := cookieSession()
		if uid == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		delete(f.sessions, sid)
		f.logouts++
		http.SetCookie(w, &http.Cookie{Name: "hanko", Value: "", Path: "/", MaxAge: -1})
		w.WriteHeader(http.StatusNoContent)
	case r.Host == "admin.test":
		if r.Header.Get("Authorization") != "Bearer admintok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		switch {
		case len(parts) == 2 && parts[0] == "users" && r.Method == http.MethodGet:
			u, ok := f.users[parts[1]]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			io.WriteString(w, u)
		case len(parts) == 3 && parts[2] == "sessions" && r.Method == http.MethodGet:
			var list []string
			for sid, uid := range f.sessions {
				if uid == parts[1] {
					list = append(list, `{"id":"`+sid+`","created_at":"2026-01-01T00:00:00Z","last_used":"2026-01-01T00:00:00Z"}`)
				}
			}
			io.WriteString(w, "["+strings.Join(list, ",")+"]")
		case len(parts) == 4 && parts[2] == "sessions" && r.Method == http.MethodDelete:
			delete(f.sessions, parts[3])
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

const testConfig = `
secrets:
  keys: [test-secret-key-0123456789-0123456789abcdef]
oidc:
  clients:
    - id: app
      name: Test App
      secret: s3cret-app-client-secret
      redirect_uris: [https://app.test/callback]
      post_logout_redirect_uris: [https://app.test/bye]
      access:
        any_user: true
    - id: mail
      secret: mail-client-secret-123
      redirect_uris: [https://mail.test/cb]
      require_pkce: true
      roles_claim: true
      access:
        organization: Mail
        roles: [editor]
`

type env struct {
	t      *testing.T
	hanko  *fakeHanko
	prov   *Provider
	client *http.Client // browser: cookie jar, no auto-redirects
	ctx    context.Context
	now    time.Time
}

func newEnv(t *testing.T) *env { return newEnvStore(t, nil) }

// newEnvStore builds a test environment around store; nil means the in-memory store.
func newEnvStore(t *testing.T, store CodeStore) *env {
	t.Helper()
	cfg, err := LoadConfig([]byte(testConfig), "http://idp.test", "")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := LoadKeys(cfg)
	if err != nil {
		t.Fatal(err)
	}
	fh := newFakeHanko()
	pub, _ := url.Parse("http://public.test")
	adm, _ := url.Parse("http://admin.test")
	tr := hostTransport{"public.test": fh, "admin.test": fh}
	auth := frontend.NewAuth(pub, frontend.AccessRule{})
	api := frontend.NewAdminAPI(adm, "admintok")
	setTransport(t, tr)
	p, err := New(cfg, keys, NewHanko(auth, api), store)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, hanko: fh, prov: p, now: time.Now()}
	p.now = func() time.Time { return e.now }
	setStoreClock(p.codes, p.now)
	front := frontend.Handler(frontend.Options{Admin: adm, Public: pub, Token: "admintok",
		Extra: map[string]http.Handler{"/oidc/": p.Handler()}, Labelers: []frontend.NextLabeler{p.Label}})
	tr["idp.test"] = front
	tr["app.test"] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "app") })
	tr["mail.test"] = tr["app.test"]
	jar, _ := cookiejar.New(nil)
	e.client = &http.Client{Transport: tr, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	e.ctx = gooidc.ClientContext(context.Background(), &http.Client{Transport: tr})
	return e
}

// setTransport swaps http.DefaultTransport, which the frontend's internal clients use.
func setTransport(t *testing.T, tr http.RoundTripper) {
	old := http.DefaultTransport
	http.DefaultTransport = tr
	t.Cleanup(func() { http.DefaultTransport = old })
}

func (e *env) signIn(user string) {
	u, _ := url.Parse("http://idp.test/")
	e.client.Jar.SetCookies(u, []*http.Cookie{{Name: "hanko", Value: user, Path: "/"}})
}

func (e *env) get(raw string) *http.Response {
	e.t.Helper()
	res, err := e.client.Get(raw)
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

// follow walks redirects on idp.test until leaving it, returning the final location.
func (e *env) follow(raw string) (*url.URL, *http.Response) {
	e.t.Helper()
	for i := 0; i < 10; i++ {
		res := e.get(raw)
		loc := res.Header.Get("Location")
		if loc == "" {
			return nil, res
		}
		next, _ := url.Parse(raw)
		next, _ = next.Parse(loc)
		if next.Host != "idp.test" {
			return next, res
		}
		raw = next.String()
	}
	e.t.Fatal("too many redirects")
	return nil, nil
}

func TestEndToEnd(t *testing.T) { forEachStore(t, testEndToEnd) }

func testEndToEnd(t *testing.T, store CodeStore) {
	e := newEnvStore(t, store)
	provider, err := gooidc.NewProvider(e.ctx, "http://idp.test/oidc")
	if err != nil {
		t.Fatal(err)
	}
	conf := oauth2.Config{ClientID: "app", ClientSecret: "s3cret-app-client-secret", Endpoint: provider.Endpoint(),
		RedirectURL: "https://app.test/callback", Scopes: []string{gooidc.ScopeOpenID, "email", "profile"}}
	verifier := oauth2.GenerateVerifier()
	authURL := conf.AuthCodeURL("st4te", gooidc.Nonce("n0nce"), oauth2.S256ChallengeOption(verifier))

	// Not signed in: sent to /signin, which names the client.
	res := e.get(authURL)
	signin, _ := url.Parse(res.Header.Get("Location"))
	if signin.Path != "/signin" || !strings.HasPrefix(signin.Query().Get("next"), "/oidc/authorize?") {
		t.Fatalf("expected redirect to /signin, got %s", signin)
	}
	_, res = e.follow("http://idp.test" + signin.String())
	if !strings.Contains(res.Request.URL.RawQuery, "to=Test+App") || res.StatusCode != 200 {
		t.Fatalf("signin page should be labeled with client name, got %d %s", res.StatusCode, res.Request.URL)
	}

	// Sign in, then the sign-in page bounces back through authorize to the client.
	e.signIn("alice")
	cb, _ := e.follow("http://idp.test" + signin.String())
	if cb == nil || cb.Host != "app.test" || cb.Query().Get("state") != "st4te" || cb.Query().Get("code") == "" {
		t.Fatalf("expected callback with code and state, got %v", cb)
	}
	if cb.Query().Get("iss") != "http://idp.test/oidc" {
		t.Errorf("callback iss = %q", cb.Query().Get("iss"))
	}

	tok, err := conf.Exchange(e.ctx, cb.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal(err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := provider.Verifier(&gooidc.Config{ClientID: "app"}).Verify(e.ctx, rawID)
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Nonce, Email, Name, Sid string
		EmailVerified           bool     `json:"email_verified"`
		PreferredUsername       string   `json:"preferred_username"`
		AuthTime                int64    `json:"auth_time"`
		Roles                   []string `json:"roles"`
	}
	_ = idt.Claims(&claims)
	if idt.Subject != "alice" || claims.Nonce != "n0nce" || claims.Email != "alice@x.io" || !claims.EmailVerified ||
		claims.Name != "Alice A" || claims.PreferredUsername != "alice" || claims.Sid != "s-alice" || claims.Roles != nil {
		t.Errorf("unexpected id token claims: sub=%s %+v", idt.Subject, claims)
	}
	if claims.AuthTime != time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix() {
		t.Errorf("auth_time = %d", claims.AuthTime)
	}

	ui, err := provider.UserInfo(e.ctx, oauth2.StaticTokenSource(tok))
	if err != nil {
		t.Fatal(err)
	}
	if ui.Subject != "alice" || ui.Email != "alice@x.io" || !ui.EmailVerified {
		t.Errorf("unexpected userinfo: %+v", ui)
	}

	// The code is single use.
	if _, err := conf.Exchange(e.ctx, cb.Query().Get("code"), oauth2.VerifierOption(verifier)); err == nil {
		t.Error("replayed code was accepted")
	}

	// Already signed in: authorize goes straight to the client.
	cb, _ = e.follow(conf.AuthCodeURL("again", oauth2.S256ChallengeOption(verifier)))
	if cb == nil || cb.Query().Get("code") == "" {
		t.Fatal("signed-in authorize should return a code")
	}

	// End session: Hanko logout, then the registered post-logout redirect with state.
	res = e.get("http://idp.test/oidc/logout?id_token_hint=" + rawID + "&post_logout_redirect_uri=" + url.QueryEscape("https://app.test/bye") + "&state=x")
	if loc := res.Header.Get("Location"); loc != "https://app.test/bye?state=x" || e.hanko.logouts != 1 || res.StatusCode != http.StatusSeeOther {
		t.Errorf("logout: location=%q logouts=%d", loc, e.hanko.logouts)
	}
	// The access token no longer works once the session is gone.
	if _, err := provider.UserInfo(e.ctx, oauth2.StaticTokenSource(tok)); err == nil {
		t.Error("userinfo should fail after logout")
	}
}

func authorizeURL(client, redirect string, extra url.Values) string {
	q := url.Values{"client_id": {client}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid email"}, "state": {"s"}}
	for k, v := range extra {
		q[k] = v
	}
	return "http://idp.test/oidc/authorize?" + q.Encode()
}

func (e *env) code(client, redirect string, extra url.Values) string {
	e.t.Helper()
	cb, res := e.follow(authorizeURL(client, redirect, extra))
	if cb == nil {
		b, _ := io.ReadAll(res.Body)
		e.t.Fatalf("no callback: %d %s", res.StatusCode, b)
	}
	return cb.Query().Get("code")
}

func (e *env) exchange(form url.Values, user, pass string) (int, map[string]any) {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "http://idp.test/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	res, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res.StatusCode, body
}

func challenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestAuthorizeErrors(t *testing.T) {
	e := newEnv(t)
	e.signIn("alice")
	cases := []struct {
		name     string
		url      string
		status   int
		errParam string // expected ?error= on the redirect; "" means an error page (no redirect)
	}{
		{"unknown client", authorizeURL("nope", "https://app.test/callback", nil), 400, ""},
		{"unregistered redirect", authorizeURL("app", "http://evil.test/cb", nil), 400, ""},
		{"missing openid", authorizeURL("app", "https://app.test/callback", url.Values{"scope": {"email"}}), 302, "invalid_scope"},
		{"bad response type", authorizeURL("app", "https://app.test/callback", url.Values{"response_type": {"token"}}), 302, "unsupported_response_type"},
		{"plain pkce", authorizeURL("app", "https://app.test/callback", url.Values{"code_challenge": {"x"}, "code_challenge_method": {"plain"}}), 302, "invalid_request"},
		{"pkce required", authorizeURL("mail", "https://mail.test/cb", nil), 302, "invalid_request"},
	}
	for _, c := range cases {
		res := e.get(c.url)
		loc, _ := url.Parse(res.Header.Get("Location"))
		switch {
		case res.StatusCode != c.status:
			t.Errorf("%s: status %d, want %d", c.name, res.StatusCode, c.status)
		case c.errParam == "" && res.Header.Get("Location") != "":
			t.Errorf("%s: must not redirect, got %s", c.name, loc)
		case c.errParam != "" && (loc.Query().Get("error") != c.errParam || loc.Query().Get("state") != "s"):
			t.Errorf("%s: redirect %s, want error=%s with state", c.name, loc, c.errParam)
		}
	}

	// prompt=login doesn't sign out on GET: it sends to /signin?fresh=1 with min_auth_time set.
	res := e.get(authorizeURL("app", "https://app.test/callback", url.Values{"prompt": {"login"}}))
	loc, _ := url.Parse(res.Header.Get("Location"))
	next := loc.Query().Get("next")
	if loc.Path != "/signin" || loc.Query().Get("fresh") != "1" || strings.Contains(next, "prompt") || !strings.Contains(next, "min_auth_time=") || e.hanko.logouts != 0 {
		t.Errorf("prompt=login: %s logouts=%d", loc, e.hanko.logouts)
	}
	// /signin?fresh=1 shows the form rather than bouncing back with the old session.
	if res := e.get("http://idp.test" + loc.String()); res.StatusCode != 200 && !strings.HasPrefix(res.Header.Get("Location"), "/signin?") {
		t.Errorf("fresh signin should show the form, got %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	// Coming back with the same (old) session is refused: re-authentication didn't happen.
	res = e.get("http://idp.test" + next)
	if l, _ := url.Parse(res.Header.Get("Location")); l.Query().Get("error") != "login_required" {
		t.Errorf("stale session after prompt=login: %s", l)
	}

	// prompt=none without a session.
	e.hanko.mu.Lock()
	delete(e.hanko.sessions, "s-alice")
	e.hanko.mu.Unlock()
	res = e.get(authorizeURL("app", "https://app.test/callback", url.Values{"prompt": {"none"}}))
	if loc, _ := url.Parse(res.Header.Get("Location")); loc.Query().Get("error") != "login_required" {
		t.Errorf("prompt=none: got %s", loc)
	}
}

func TestAccessAndRoles(t *testing.T) {
	e := newEnv(t)
	v := oauth2.GenerateVerifier()
	pkce := url.Values{"code_challenge": {challenge(v)}, "code_challenge_method": {"S256"}, "scope": {"openid email roles"}}

	// bob isn't an editor in "mail": access_denied.
	e.signIn("bob")
	res := e.get(authorizeURL("mail", "https://mail.test/cb", pkce))
	if loc, _ := url.Parse(res.Header.Get("Location")); loc.Query().Get("error") != "access_denied" {
		t.Fatalf("bob should be denied, got %s", loc)
	}

	// alice is: roles claim carries her role slugs in that organization.
	e.signIn("alice")
	code := e.code("mail", "https://mail.test/cb", pkce)
	status, body := e.exchange(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://mail.test/cb"}, "code_verifier": {v}}, "mail", "mail-client-secret-123")
	if status != 200 {
		t.Fatalf("token: %d %v", status, body)
	}
	parts := strings.Split(body["id_token"].(string), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if !strings.Contains(string(payload), `"roles":["editor"]`) {
		t.Errorf("roles claim missing: %s", payload)
	}

	// Membership revoked between authorize and token: the code is refused.
	code = e.code("mail", "https://mail.test/cb", pkce)
	e.hanko.mu.Lock()
	e.hanko.users["alice"] = strings.Replace(e.hanko.users["alice"], `"slug":"editor"`, `"slug":"viewer"`, 1)
	e.hanko.mu.Unlock()
	status, body = e.exchange(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://mail.test/cb"}, "code_verifier": {v}}, "mail", "mail-client-secret-123")
	if status != 400 || body["error"] != "invalid_grant" {
		t.Errorf("revoked membership: %d %v", status, body)
	}
}

func TestTokenErrors(t *testing.T) { forEachStore(t, testTokenErrors) }

func testTokenErrors(t *testing.T, store CodeStore) {
	e := newEnvStore(t, store)
	e.signIn("alice")
	redirect := "https://app.test/callback"
	form := func(code string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}}
	}

	if s, b := e.exchange(form(e.code("app", redirect, nil)), "app", "wrong"); s != 401 || b["error"] != "invalid_client" {
		t.Errorf("wrong secret: %d %v", s, b)
	}
	if s, b := e.exchange(form(e.code("app", redirect, nil)), "mail", "mail-client-secret-123"); s != 400 || b["error"] != "invalid_grant" {
		t.Errorf("code for another client: %d %v", s, b)
	}
	f := form(e.code("app", redirect, nil))
	f.Set("redirect_uri", "https://app.test/other")
	if s, b := e.exchange(f, "app", "s3cret-app-client-secret"); s != 400 || b["error"] != "invalid_grant" {
		t.Errorf("redirect mismatch: %d %v", s, b)
	}
	f = form(e.code("app", redirect, nil))
	f.Set("grant_type", "refresh_token")
	if s, b := e.exchange(f, "app", "s3cret-app-client-secret"); s != 400 || b["error"] != "unsupported_grant_type" {
		t.Errorf("grant type: %d %v", s, b)
	}
	// client_secret_post works.
	f = form(e.code("app", redirect, nil))
	f.Set("client_id", "app")
	f.Set("client_secret", "s3cret-app-client-secret")
	if s, b := e.exchange(f, "", ""); s != 200 {
		t.Errorf("client_secret_post: %d %v", s, b)
	}

	// PKCE mismatch.
	v := oauth2.GenerateVerifier()
	f = form(e.code("app", redirect, url.Values{"code_challenge": {challenge(v)}, "code_challenge_method": {"S256"}}))
	f.Set("code_verifier", "wrong-verifier-wrong-verifier-wrong-verifier-123")
	if s, b := e.exchange(f, "app", "s3cret-app-client-secret"); s != 400 || b["error"] != "invalid_grant" {
		t.Errorf("pkce mismatch: %d %v", s, b)
	}

	// PKCE downgrade: verifier sent for a code issued without a challenge.
	f = form(e.code("app", redirect, nil))
	f.Set("code_verifier", v)
	if s, b := e.exchange(f, "app", "s3cret-app-client-secret"); s != 400 || b["error"] != "invalid_grant" {
		t.Errorf("pkce downgrade: %d %v", s, b)
	}

	// Expired code.
	code := e.code("app", redirect, nil)
	e.now = e.now.Add(2 * time.Minute)
	if s, b := e.exchange(form(code), "app", "s3cret-app-client-secret"); s != 400 || b["error"] != "invalid_grant" {
		t.Errorf("expired: %d %v", s, b)
	}
	e.now = time.Now()

	// Session ended between authorize and token.
	code = e.code("app", redirect, nil)
	e.hanko.mu.Lock()
	delete(e.hanko.sessions, "s-alice")
	e.hanko.mu.Unlock()
	if s, b := e.exchange(form(code), "app", "s3cret-app-client-secret"); s != 400 || b["error"] != "invalid_grant" {
		t.Errorf("ended session: %d %v", s, b)
	}
}

func TestConfigValidation(t *testing.T) {
	const strongKeys = "secrets:\n  keys: [0123456789abcdef0123456789abcdef]\n"
	client := func(extra string) string {
		return "oidc:\n  clients:\n    - id: a\n      secret: a-strong-client-secret\n      redirect_uris: [https://a.example/cb]\n      access: {any_user: true}\n" + extra
	}
	load := func(y, public string) error {
		_, err := LoadConfig([]byte(y), public, "")
		return err
	}
	if err := load(strongKeys+client(""), "https://idp.example"); err != nil {
		t.Fatalf("baseline should be valid: %v", err)
	}
	bad := map[string]struct{ yaml, public string }{
		"no secret":            {strongKeys + strings.Replace(client(""), "secret: a-strong-client-secret\n", "", 1), "https://idp.example"},
		"no redirect":          {strongKeys + strings.Replace(client(""), "redirect_uris: [https://a.example/cb]\n", "", 1), "https://idp.example"},
		"relative redirect":    {strongKeys + strings.Replace(client(""), "https://a.example/cb", "/cb", 1), "https://idp.example"},
		"http redirect":        {strongKeys + strings.Replace(client(""), "https://a.example/cb", "http://a.example/cb", 1), "https://idp.example"},
		"javascript redirect":  {strongKeys + strings.Replace(client(""), "https://a.example/cb", "javascript://a.example/cb", 1), "https://idp.example"},
		"no openid":            {strongKeys + client("      scopes: [email]\n"), "https://idp.example"},
		"no access":            {strongKeys + strings.Replace(client(""), "      access: {any_user: true}\n", "", 1), "https://idp.example"},
		"any_user plus users":  {strongKeys + strings.Replace(client(""), "{any_user: true}", "{any_user: true, users: [bob]}", 1), "https://idp.example"},
		"roles without org":    {strongKeys + client("      roles_claim: true\n"), "https://idp.example"},
		"short client secret":  {strongKeys + strings.Replace(client(""), "a-strong-client-secret", "short", 1), "https://idp.example"},
		"placeholder key":      {"secrets:\n  keys: [change-me-local-dev-secret-key-0123456789]\n" + client(""), "https://idp.example"},
		"short key":            {"secrets:\n  keys: [0123456789abcdef]\n" + client(""), "https://idp.example"},
		"duplicate client ids": {strongKeys + client("    - id: a\n      secret: another-strong-secret\n      redirect_uris: [https://a.example/cb]\n      access: {any_user: true}\n"), "https://idp.example"},
	}
	for name, c := range bad {
		if load(c.yaml, c.public) == nil {
			t.Errorf("%s should be invalid", name)
		}
	}
	// Local issuers allow the dev conveniences.
	if err := load("secrets:\n  keys: [change-me-local-dev-secret-key-0123456789]\n"+strings.NewReplacer("https://a.example/cb", "http://localhost:9000/cb", "a-strong-client-secret", "short").Replace(client("")), "http://localhost:8080"); err != nil {
		t.Errorf("localhost dev config should be valid: %v", err)
	}
	c, err := LoadConfig([]byte("oidc: {}\n"), "http://localhost:8080", "")
	if err != nil || c.Enabled() {
		t.Errorf("no clients should be valid and disabled: %v", err)
	}
	t.Setenv("OIDC_CLIENTS_MY_APP_SECRET", "fromenv")
	c, err = LoadConfig([]byte("secrets:\n  keys: [0123456789abcdef]\noidc:\n  clients:\n    - id: my-app\n      redirect_uris: [https://a/cb]\n      access: {any_user: true}\n"), "http://localhost:8080/", "")
	if err != nil || c.Clients[0].Secret != "fromenv" || c.Issuer != "http://localhost:8080/oidc" {
		t.Errorf("env secret / issuer: %v %+v", err, c)
	}
}

func TestLogoutCSRF(t *testing.T) {
	e := newEnv(t)
	e.signIn("alice")
	// A bare GET (e.g. a link on another site) shows a confirmation page and doesn't sign out.
	res := e.get("http://idp.test/oidc/logout")
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.Contains(string(body), `method="post"`) || e.hanko.logouts != 0 {
		t.Fatalf("bare GET logout: %d logouts=%d", res.StatusCode, e.hanko.logouts)
	}
	// A cross-site POST is refused even with the cookie.
	post := func(form url.Values, origin string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, "http://idp.test/oidc/logout", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		res, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	csrf := strings.SplitN(strings.SplitN(string(body), `name="csrf" value="`, 2)[1], `"`, 2)[0]
	if res := post(url.Values{"csrf": {csrf}}, "https://evil.test"); res.StatusCode != 403 || e.hanko.logouts != 0 {
		t.Errorf("cross-site POST: %d logouts=%d", res.StatusCode, e.hanko.logouts)
	}
	if res := post(url.Values{"csrf": {"wrong"}}, "http://idp.test"); res.StatusCode != 403 || e.hanko.logouts != 0 {
		t.Errorf("bad csrf token: %d logouts=%d", res.StatusCode, e.hanko.logouts)
	}
	// The confirmation form itself works.
	if res := post(url.Values{"csrf": {csrf}}, "http://idp.test"); res.StatusCode != 200 || e.hanko.logouts != 1 {
		t.Errorf("confirmed POST: %d logouts=%d", res.StatusCode, e.hanko.logouts)
	}
}

func TestLogoutHintChecks(t *testing.T) {
	e := newEnv(t)
	e.signIn("alice")
	provider, err := gooidc.NewProvider(e.ctx, "http://idp.test/oidc")
	if err != nil {
		t.Fatal(err)
	}
	conf := oauth2.Config{ClientID: "app", ClientSecret: "s3cret-app-client-secret", Endpoint: provider.Endpoint(),
		RedirectURL: "https://app.test/callback", Scopes: []string{gooidc.ScopeOpenID}}
	cb, _ := e.follow(conf.AuthCodeURL("s"))
	tok, err := conf.Exchange(e.ctx, cb.Query().Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	// An access token isn't accepted as id_token_hint.
	res := e.get("http://idp.test/oidc/logout?id_token_hint=" + tok.AccessToken)
	if res.StatusCode != 400 || e.hanko.logouts != 0 {
		t.Errorf("access token as hint: %d logouts=%d", res.StatusCode, e.hanko.logouts)
	}
	// An ID token isn't accepted at userinfo.
	idt := tok.Extra("id_token").(string)
	req, _ := http.NewRequest(http.MethodGet, "http://idp.test/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+idt)
	if res, _ := e.client.Do(req); res.StatusCode != 401 {
		t.Errorf("id token at userinfo: %d", res.StatusCode)
	}
	// Mismatched client_id is refused.
	if res := e.get("http://idp.test/oidc/logout?id_token_hint=" + idt + "&client_id=mail"); res.StatusCode != 400 {
		t.Errorf("client_id mismatch: %d", res.StatusCode)
	}
	// Too-old hints are refused.
	e.now = e.now.Add(maxHintAge + time.Hour)
	if res := e.get("http://idp.test/oidc/logout?id_token_hint=" + idt); res.StatusCode != 400 || e.hanko.logouts != 0 {
		t.Errorf("old hint: %d logouts=%d", res.StatusCode, e.hanko.logouts)
	}
}

func TestRateLimiterAndProxies(t *testing.T) {
	cfg := &Config{SecretKeys: []string{"0123456789abcdef0123456789abcdef"}, TrustedProxies: []string{"10.0.0.0/8"}}
	p, err := New(cfg, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "10.1.2.3:5555"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9, 10.9.9.9")
	if ip := p.clientIP(r); ip != "203.0.113.9" {
		t.Errorf("trusted proxy chain: got %s", ip)
	}
	r.RemoteAddr = "198.51.100.1:5555"
	if ip := p.clientIP(r); ip != "198.51.100.1" {
		t.Errorf("untrusted peer must ignore XFF: got %s", ip)
	}
	l := p.limiter("k")
	for i := 0; i < 10; i++ {
		l.Allow()
	}
	for i := 0; i < 10001; i++ {
		p.limiter(fmt.Sprint("x", i))
	}
	if p.limiter("k") != l || p.limiter("k").Allow() {
		t.Error("an active bucket must survive a flood of new keys")
	}
}
