package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/progrium/hankoid/frontend"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// Provider is the OIDC provider. Mount Handler() at /oidc/ on the frontend.
type Provider struct {
	cfg   *Config
	keys  *Keys
	codes CodeStore
	hanko Hanko
	now   func() time.Time

	limitMu  sync.Mutex
	limiters map[string]*limiterEntry
	proxies  frontend.Proxies

	devices     *DeviceStore // nil unless oidc.store is postgres
	hookMu      sync.Mutex
	revokeHooks []func([]string)
}

// New builds a provider. cfg must already be validated. A nil store keeps codes in memory
// (sealed blobs plus an in-memory replay set); see NewPostgresCodes for the shared store.
func New(cfg *Config, keys *Keys, h Hanko, store CodeStore) (*Provider, error) {
	if store == nil {
		m, err := newMemoryCodes(cfg.SecretKeys)
		if err != nil {
			return nil, err
		}
		store = m
	}
	proxies, err := frontend.ParseProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	return &Provider{cfg: cfg, keys: keys, codes: store, hanko: h, now: time.Now, limiters: map[string]*limiterEntry{}, proxies: proxies}, nil
}

func (p *Provider) endpoint(name string) string { return p.cfg.Issuer + "/" + name }

// Label names an /oidc/authorize sign-in destination after its client, for the /signin page.
func (p *Provider) Label(next string) string {
	u, err := url.Parse(next)
	if err != nil || u.Path != "/oidc/authorize" {
		return ""
	}
	if c := p.cfg.Client(u.Query().Get("client_id")); c != nil {
		return c.DisplayName()
	}
	return ""
}

// Handler serves the provider under /oidc/.
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oidc/.well-known/openid-configuration", cors(p.discovery))
	mux.HandleFunc("GET /oidc/jwks.json", cors(p.jwks))
	mux.HandleFunc("GET /oidc/authorize", p.authorize)
	mux.HandleFunc("POST /oidc/token", p.token)
	mux.HandleFunc("POST /oidc/device_authorization", p.deviceAuthorization)
	mux.HandleFunc("POST /oidc/introspect", p.introspect)
	mux.HandleFunc("GET /oidc/revocations", p.revocations)
	mux.HandleFunc("POST /oidc/revoke", p.revoke)
	mux.HandleFunc("GET /oidc/userinfo", cors(p.userinfo))
	mux.HandleFunc("POST /oidc/userinfo", cors(p.userinfo))
	mux.HandleFunc("OPTIONS /oidc/userinfo", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("GET /oidc/logout", p.logout)
	mux.HandleFunc("POST /oidc/logout", p.logout)
	return mux
}

func cors(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		h(w, r)
	}
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	scopes := []string{"openid", "email", "profile"}
	claims := []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "sid", "azp",
		"email", "email_verified", "name", "given_name", "family_name", "preferred_username", "picture"}
	for _, c := range p.cfg.Clients {
		if c.RolesClaim {
			scopes = append(scopes, "roles")
			claims = append(claims, "roles")
			break
		}
	}
	grants := []string{GrantAuthorizationCode}
	auth := []string{"client_secret_basic", "client_secret_post"}
	doc := map[string]any{
		"issuer":                                p.cfg.Issuer,
		"authorization_endpoint":                p.endpoint("authorize"),
		"token_endpoint":                        p.endpoint("token"),
		"userinfo_endpoint":                     p.endpoint("userinfo"),
		"end_session_endpoint":                  p.endpoint("logout"),
		"jwks_uri":                              p.endpoint("jwks.json"),
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 &grants,
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": &auth,
		"scopes_supported":                      &scopes,
		"claims_supported":                      claims,
		"prompt_values_supported":               []string{"none", "login"},
	}
	if p.cfg.DeviceEnabled() && p.devices != nil {
		doc["device_authorization_endpoint"] = p.endpoint("device_authorization")
		doc["revocation_endpoint"] = p.endpoint("revoke")
		doc["introspection_endpoint"] = p.endpoint("introspect")
		grants = append(grants, GrantDeviceCode, GrantRefreshToken)
		auth = append(auth, "none")
		scopes = append(scopes, "offline_access")
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, doc)
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, p.keys.public)
}

// authorize implements the authorization endpoint (OIDC Core §3.1.2).
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client := p.cfg.Client(q.Get("client_id"))
	if client == nil {
		errorPage(w, http.StatusBadRequest, "Unknown application", "The application that sent you here isn't registered.")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !client.AllowsGrant(GrantAuthorizationCode) || !slices.Contains(client.RedirectURIs, redirectURI) {
		errorPage(w, http.StatusBadRequest, "Invalid redirect", "The application sent an unregistered redirect address.")
		return
	}
	state := q.Get("state")
	fail := func(code, desc string) { redirectError(w, r, redirectURI, state, code, desc) }
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}
	scopes := strings.Fields(q.Get("scope"))
	if !slices.Contains(scopes, "openid") {
		fail("invalid_scope", "scope must include openid")
		return
	}
	var granted []string
	for _, s := range scopes {
		if client.AllowsScope(s) && !slices.Contains(granted, s) {
			granted = append(granted, s)
		}
	}
	challenge, method := q.Get("code_challenge"), q.Get("code_challenge_method")
	switch {
	case challenge == "" && client.RequirePKCE:
		fail("invalid_request", "code_challenge is required")
		return
	case challenge != "" && method != "S256":
		fail("invalid_request", "code_challenge_method must be S256")
		return
	}
	prompt := strings.Fields(q.Get("prompt"))

	s, err := p.hanko.Session(r)
	if err != nil {
		log.Printf("oidc: session validation failed: %v", err)
		fail("server_error", "session validation unavailable")
		return
	}
	authTime := time.Time{}
	if s != nil {
		authTime = p.authTime(r, s)
	}
	needLogin := s == nil || slices.Contains(prompt, "login")
	if v := q.Get("min_auth_time"); v != "" && s != nil {
		// Set by our own re-authentication redirect: the session must be newer than the request
		// that asked for it. A stale session here means the user didn't actually sign in again.
		if t, err := strconv.ParseInt(v, 10, 64); err == nil && authTime.Unix() < t {
			if slices.Contains(prompt, "none") {
				fail("login_required", "")
			} else {
				fail("login_required", "re-authentication did not complete")
			}
			return
		}
	}
	if maxAge := q.Get("max_age"); maxAge != "" && s != nil {
		if secs, err := strconv.Atoi(maxAge); err == nil && p.now().Sub(authTime) > time.Duration(secs)*time.Second {
			needLogin = true
		}
	}
	if needLogin {
		if slices.Contains(prompt, "none") {
			fail("login_required", "")
			return
		}
		// Re-authentication never signs anyone out on a GET (that would be logout CSRF). The
		// sign-in page is shown even with an existing session; signing in replaces the session.
		// The return URL carries the time of this request as min_auth_time, so the new session
		// must be newer than it.
		next := *r.URL
		nq := next.Query()
		nq.Del("prompt")
		nq.Del("max_age")
		if s != nil {
			nq.Set("min_auth_time", strconv.FormatInt(p.now().Unix(), 10))
		}
		next.RawQuery = nq.Encode()
		signin := frontend.SignInURL(next.RequestURI())
		if s != nil {
			signin += "&fresh=1"
		}
		http.Redirect(w, r, signin, http.StatusFound)
		return
	}
	if !client.Allows(s) {
		log.Printf("oidc: denied %s (%s) access to client %q", s.Name(), s.UserID, client.ID)
		fail("access_denied", "this account may not sign in to "+client.DisplayName())
		return
	}
	code, err := p.codes.Issue(r.Context(), codeData{
		ClientID: client.ID, RedirectURI: redirectURI, UserID: s.UserID, SessionID: s.SessionID,
		Nonce: q.Get("nonce"), CodeChallenge: challenge, Scope: strings.Join(granted, " "),
		AuthTime: authTime, Exp: p.now().Add(p.cfg.CodeTTL),
	})
	if err != nil {
		log.Printf("oidc: issue code: %v", err)
		fail("temporarily_unavailable", "")
		return
	}
	u, _ := url.Parse(redirectURI)
	rq := u.Query()
	rq.Set("code", code)
	if state != "" {
		rq.Set("state", state)
	}
	rq.Set("iss", p.cfg.Issuer)
	u.RawQuery = rq.Encode()
	noStore(w)
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// authTime is when the user signed in: the session token's iat, or else the session's creation time.
func (p *Provider) authTime(r *http.Request, s *frontend.Session) time.Time {
	if !s.IssuedAt.IsZero() {
		return s.IssuedAt
	}
	if s.SessionID != "" {
		if us, err := p.hanko.UserSession(r.Context(), s.UserID, s.SessionID); err == nil && us != nil {
			return us.CreatedAt
		}
	}
	return p.now()
}

type limiterEntry struct {
	l    *rate.Limiter
	seen time.Time
}

// limiter returns the token bucket for key. Entries idle for over 10 minutes are evicted when the
// table grows, so a flood of new keys can't reset everyone's buckets.
func (p *Provider) limiter(key string) *rate.Limiter {
	return p.limiterN(key, time.Second, 10)
}

// limiterN is limiter with a bucket that refills one token per every, holding burst. Keys must
// not be shared between different rates.
func (p *Provider) limiterN(key string, every time.Duration, burst int) *rate.Limiter {
	p.limitMu.Lock()
	defer p.limitMu.Unlock()
	now := p.now()
	if e, ok := p.limiters[key]; ok {
		e.seen = now
		return e.l
	}
	if len(p.limiters) >= 10000 {
		for k, e := range p.limiters {
			if now.Sub(e.seen) > 10*time.Minute {
				delete(p.limiters, k)
			}
		}
		if len(p.limiters) >= 10000 {
			// Still full of active keys: share one strict bucket for newcomers.
			key = "overflow"
			if e, ok := p.limiters[key]; ok {
				return e.l
			}
		}
	}
	e := &limiterEntry{l: rate.NewLimiter(rate.Every(every), burst), seen: now}
	p.limiters[key] = e
	return e.l
}

func (p *Provider) clientIP(r *http.Request) string { return p.proxies.ClientIP(r) }

// authenticateClient checks client_secret_basic or client_secret_post credentials.
func (p *Provider) authenticateClient(r *http.Request) *Client {
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	client := p.cfg.Client(id)
	if client != nil && client.Public() {
		// A public client is identified by client_id alone, and must not present a secret.
		if secret != "" {
			return nil
		}
		return client
	}
	if client == nil || secret == "" {
		return nil
	}
	if client.SecretHash != "" {
		if bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(secret)) != nil {
			return nil
		}
		return client
	}
	if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(secret)) != 1 {
		return nil
	}
	return client
}

// token implements the token endpoint: the authorization_code grant (OIDC Core §3.1.3), and for
// device clients the device_code (RFC 8628) and refresh_token grants.
func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	if !p.limiter("ip:" + p.clientIP(r)).Allow() {
		w.Header().Set("Retry-After", "1")
		tokenError(w, http.StatusTooManyRequests, "slow_down", "too many requests")
		return
	}
	client := p.authenticateClient(r)
	if client == nil {
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	// Public clients share one client_id across every device, so a per-client bucket would let
	// anyone stall everyone's logins. Device polling is paced per grant instead.
	if !client.Public() && !p.limiter("client:"+client.ID).Allow() {
		w.Header().Set("Retry-After", "1")
		tokenError(w, http.StatusTooManyRequests, "slow_down", "too many requests")
		return
	}
	switch gt := grantAlias(r.PostForm.Get("grant_type")); {
	case gt == GrantAuthorizationCode && client.AllowsGrant(gt):
		p.authorizationCodeGrant(w, r, client)
	case (gt == GrantDeviceCode || gt == GrantRefreshToken) && p.devices != nil && client.IsDevice():
		if gt == GrantDeviceCode {
			p.deviceCodeGrant(w, r, client)
		} else {
			p.refreshTokenGrant(w, r, client)
		}
	case gt == GrantAuthorizationCode || (p.devices != nil && (gt == GrantDeviceCode || gt == GrantRefreshToken)):
		tokenError(w, http.StatusBadRequest, "unauthorized_client", "this client may not use "+gt)
	default:
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

// authorizationCodeGrant redeems an authorization code (OIDC Core §3.1.3).
func (p *Provider) authorizationCodeGrant(w http.ResponseWriter, r *http.Request, client *Client) {
	d, err := p.codes.Redeem(r.Context(), r.PostForm.Get("code"))
	if err != nil && !errors.Is(err, errBadCode) {
		log.Printf("oidc: redeem code: %v", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "code store unavailable")
		return
	}
	if err != nil || d.ClientID != client.ID || d.RedirectURI != r.PostForm.Get("redirect_uri") {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "invalid, expired, or already used code")
		return
	}
	verifier := r.PostForm.Get("code_verifier")
	if d.CodeChallenge == "" && verifier != "" {
		// RFC 9700 §2.1.1: a verifier without a challenge signals a PKCE downgrade.
		tokenError(w, http.StatusBadRequest, "invalid_grant", "code_verifier sent but no code_challenge was used")
		return
	}
	if d.CodeChallenge != "" {
		if !validVerifier(verifier) {
			tokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
		sum := sha256.Sum256([]byte(verifier))
		if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(d.CodeChallenge)) != 1 {
			tokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	}
	if d.SessionID != "" {
		us, err := p.hanko.UserSession(r.Context(), d.UserID, d.SessionID)
		if err != nil {
			log.Printf("oidc: session check failed: %v", err)
			tokenError(w, http.StatusInternalServerError, "server_error", "session check failed")
			return
		}
		if us == nil {
			tokenError(w, http.StatusBadRequest, "invalid_grant", "the session has ended")
			return
		}
	}
	u, err := p.lookupUser(r, d.UserID, d.Scope, client)
	if errors.Is(err, errAccessRevoked) {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "access to this client was revoked")
		return
	}
	if err != nil {
		log.Printf("oidc: load user %s: %v", d.UserID, err)
		tokenError(w, http.StatusBadRequest, "invalid_grant", "user unavailable")
		return
	}
	p.writeTokens(w, tokenGrant{client: client, userID: d.UserID, sessionID: d.SessionID, nonce: d.Nonce,
		scope: d.Scope, authTime: d.AuthTime, user: u})
}

// validVerifier checks RFC 7636 §4.1: 43-128 characters of [A-Za-z0-9-._~].
func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	return true
}

func (p *Provider) sign(t jwt.Token) (string, error) {
	return p.signTyp(t, "JWT")
}

// signTyp signs with an explicit typ header. Access tokens use "at+jwt" (RFC 9068) so they can't be
// mistaken for ID tokens.
func (p *Provider) signTyp(t jwt.Token, typ string) (string, error) {
	h := jws.NewHeaders()
	_ = h.Set(jws.TypeKey, typ)
	b, err := jwt.Sign(t, jwt.WithKey(jwa.RS256, p.keys.signing, jws.WithProtectedHeaders(h)))
	return string(b), err
}

// tokenTyp returns a compact JWS's typ header.
func tokenTyp(raw string) string {
	msg, err := jws.Parse([]byte(raw))
	if err != nil || len(msg.Signatures()) == 0 {
		return ""
	}
	return msg.Signatures()[0].ProtectedHeaders().Type()
}

var (
	errAccessRevoked = errors.New("access revoked")
	errUserGone      = errors.New("user no longer exists")
)

// userInfo is a user's claims for a client, and their username and session-like identity.
type userInfo struct {
	claims   map[string]any
	username string
	session  *frontend.Session
}

// lookupUser loads a user through the admin API, re-checks the client's access rule (so a revoked
// membership takes effect), and builds their claims for scope. A deleted user is errUserGone.
func (p *Provider) lookupUser(r *http.Request, userID, scope string, client *Client) (*userInfo, error) {
	u, err := p.hanko.User(r.Context(), userID)
	if errors.Is(err, frontend.ErrNotFound) {
		return nil, errUserGone
	}
	if err != nil {
		return nil, err
	}
	email, verified := u.PrimaryEmail()
	username := ""
	if u.Username != nil {
		username = u.Username.Username
	}
	who := &frontend.Session{UserID: userID, Email: email, EmailVerified: verified, Username: username, Organizations: u.Organizations()}
	if !client.Allows(who) {
		return nil, errAccessRevoked
	}
	scopes := strings.Fields(scope)
	claims := map[string]any{}
	if slices.Contains(scopes, "email") && email != "" {
		claims["email"] = email
		claims["email_verified"] = verified
	}
	if slices.Contains(scopes, "profile") {
		for k, v := range map[string]string{"name": u.Name, "given_name": u.GivenName, "family_name": u.FamilyName, "picture": u.Picture} {
			if v != "" {
				claims[k] = v
			}
		}
		if username != "" {
			claims["preferred_username"] = username
		}
	}
	if client.RolesClaim && (slices.Contains(scopes, "roles") || slices.Contains(scopes, "profile")) {
		roles := []string{}
		if org := client.Access.Org(who); org != nil {
			roles = append(roles, org.Roles...)
		}
		claims["roles"] = roles
	}
	return &userInfo{claims: claims, username: username, session: who}, nil
}

// userClaims is lookupUser's claims.
func (p *Provider) userClaims(r *http.Request, userID, scope string, client *Client) (map[string]any, error) {
	u, err := p.lookupUser(r, userID, scope, client)
	if err != nil {
		return nil, err
	}
	return u.claims, nil
}

// userinfo returns claims for a bearer access token (OIDC Core §5.3).
func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	raw := ""
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		raw = strings.TrimSpace(h[7:])
	} else if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		raw = r.PostFormValue("access_token")
	}
	invalid := func(desc string) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+desc+`"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": desc})
	}
	if raw == "" {
		w.Header().Set("WWW-Authenticate", `Bearer`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_request"})
		return
	}
	if !strings.EqualFold(tokenTyp(raw), "at+jwt") {
		invalid("not an access token")
		return
	}
	tok, err := jwt.Parse([]byte(raw), jwt.WithKeySet(p.keys.public), jwt.WithValidate(true),
		jwt.WithIssuer(p.cfg.Issuer), jwt.WithAudience(p.endpoint("userinfo")), jwt.WithClock(jwt.ClockFunc(p.now)))
	if err != nil {
		invalid("token is invalid or expired")
		return
	}
	clientID, _ := tok.Get("client_id")
	client := p.cfg.Client(stringOf(clientID))
	if client == nil {
		invalid("unknown client")
		return
	}
	if did, ok := tok.Get("did"); ok {
		active := false
		var err error
		if p.devices != nil {
			active, err = p.devices.DeviceActive(r.Context(), stringOf(did))
		}
		if err != nil {
			log.Printf("oidc: device check failed: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		if !active {
			invalid("the device was signed out")
			return
		}
	}
	if sid, ok := tok.Get("sid"); ok {
		us, err := p.hanko.UserSession(r.Context(), tok.Subject(), stringOf(sid))
		if err != nil {
			log.Printf("oidc: session check failed: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		if us == nil {
			invalid("the session has ended")
			return
		}
	}
	scope, _ := tok.Get("scope")
	claims, err := p.userClaims(r, tok.Subject(), stringOf(scope), client)
	if errors.Is(err, errAccessRevoked) {
		invalid("access to this client was revoked")
		return
	}
	if err != nil {
		invalid("user unavailable")
		return
	}
	claims["sub"] = tok.Subject()
	writeJSON(w, http.StatusOK, claims)
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}

// maxHintAge bounds how old an id_token_hint may be. Expired hints are accepted (RP-Initiated
// Logout allows it), but not indefinitely.
const maxHintAge = 30 * 24 * time.Hour

// parseHint verifies an id_token_hint: our signature and issuer, an ID token (not an access
// token), issued to a configured client, and not too old.
func (p *Provider) parseHint(raw string) (jwt.Token, *Client, error) {
	if typ := tokenTyp(raw); strings.EqualFold(typ, "at+jwt") {
		return nil, nil, errors.New("access token is not a valid id_token_hint")
	}
	t, err := jwt.Parse([]byte(raw), jwt.WithKeySet(p.keys.public), jwt.WithValidate(false))
	if err != nil {
		return nil, nil, err
	}
	if t.Issuer() != p.cfg.Issuer {
		return nil, nil, errors.New("wrong issuer")
	}
	if _, isAccess := t.Get("client_id"); isAccess {
		return nil, nil, errors.New("access token is not a valid id_token_hint")
	}
	if len(t.Audience()) != 1 {
		return nil, nil, errors.New("hint must have a single audience")
	}
	client := p.cfg.Client(t.Audience()[0])
	if client == nil {
		return nil, nil, errors.New("hint audience is not a configured client")
	}
	if iat := t.IssuedAt(); iat.IsZero() || p.now().Sub(iat) > maxHintAge {
		return nil, nil, errors.New("hint is too old")
	}
	return t, client, nil
}

// logout implements RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0). With a valid
// id_token_hint it signs out immediately; otherwise it asks the user to confirm with a POST, so a
// third-party page can't sign people out by linking here.
func (p *Provider) logout(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			errorPage(w, http.StatusBadRequest, "Invalid sign-out request", "The sign-out request was malformed.")
			return
		}
		q = r.PostForm
	}
	var hint jwt.Token
	var hintClient *Client
	if raw := q.Get("id_token_hint"); raw != "" {
		t, c, err := p.parseHint(raw)
		if err != nil {
			errorPage(w, http.StatusBadRequest, "Invalid sign-out request", "The sign-out request couldn't be verified.")
			return
		}
		hint, hintClient = t, c
	}
	client := hintClient
	if id := q.Get("client_id"); id != "" {
		if hintClient != nil && id != hintClient.ID {
			errorPage(w, http.StatusBadRequest, "Invalid sign-out request", "The sign-out request is inconsistent.")
			return
		}
		client = p.cfg.Client(id)
	}
	redirect := q.Get("post_logout_redirect_uri")
	if redirect != "" && (client == nil || !slices.Contains(client.PostLogoutRedirectURIs, redirect)) {
		errorPage(w, http.StatusBadRequest, "Invalid sign-out redirect", "The application sent an unregistered sign-out redirect address.")
		return
	}

	if hint == nil {
		if r.Method != http.MethodPost {
			p.logoutConfirm(w, q, client)
			return
		}
		// A POST without a hint must come from our own confirmation page.
		if !sameOrigin(r, p.cfg.Issuer) || !p.checkLogoutToken(r, q.Get("csrf")) {
			errorPage(w, http.StatusForbidden, "Invalid sign-out request", "The sign-out request couldn't be verified. Please try again.")
			return
		}
	}

	if err := p.hanko.Logout(w, r); err != nil {
		log.Printf("oidc: logout failed: %v", err)
	}
	if hint != nil && r.Header.Get("Cookie") == "" {
		if sid, ok := hint.Get("sid"); ok {
			if err := p.hanko.DeleteSession(r.Context(), hint.Subject(), stringOf(sid)); err != nil && !errors.Is(err, frontend.ErrNotFound) {
				log.Printf("oidc: delete session failed: %v", err)
			}
		}
	}
	noStore(w)
	if redirect == "" {
		errorPage(w, http.StatusOK, "Signed out", "You have been signed out.")
		return
	}
	u, _ := url.Parse(redirect)
	if state := q.Get("state"); state != "" {
		uq := u.Query()
		uq.Set("state", state)
		u.RawQuery = uq.Encode()
	}
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// sameOrigin requires the request's Origin (or, failing that, Sec-Fetch-Site) to be our own.
func sameOrigin(r *http.Request, issuer string) bool {
	if o := r.Header.Get("Origin"); o != "" {
		iu, err := url.Parse(issuer)
		return err == nil && o == iu.Scheme+"://"+iu.Host
	}
	return r.Header.Get("Sec-Fetch-Site") == "same-origin"
}

const logoutCookie = "hankoid_logout"

// checkLogoutToken compares the form token with the double-submit cookie.
func (p *Provider) checkLogoutToken(r *http.Request, token string) bool {
	c, err := r.Cookie(logoutCookie)
	return err == nil && token != "" && subtle.ConstantTimeCompare([]byte(c.Value), []byte(token)) == 1
}

func (p *Provider) logoutConfirm(w http.ResponseWriter, q url.Values, client *Client) {
	token := randomID()
	http.SetCookie(w, &http.Cookie{Name: logoutCookie, Value: token, Path: "/oidc/logout", HttpOnly: true,
		Secure: strings.HasPrefix(p.cfg.Issuer, "https://"), SameSite: http.SameSiteStrictMode, MaxAge: 600})
	app := "this site"
	if client != nil {
		app = client.DisplayName()
	}
	hidden := ""
	for _, k := range []string{"client_id", "post_logout_redirect_uri", "state"} {
		if v := q.Get(k); v != "" {
			hidden += `<input type="hidden" name="` + k + `" value="` + html.EscapeString(v) + `">`
		}
	}
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	fmt.Fprintf(w, logoutPage, html.EscapeString(app), html.EscapeString(p.endpoint("logout")), html.EscapeString(token), hidden)
}

const logoutPage = `<!doctype html><meta charset="utf-8"><title>Sign out?</title>
<body style="font:14px system-ui;background:#f4f6f9;color:#263248;display:grid;place-items:center;min-height:90vh">
<form method="post" action="%[2]s" style="background:white;border:1px solid #dbe1ea;border-radius:9px;padding:28px;max-width:420px;text-align:center">
<h1 style="font-size:20px;margin:0 0 8px">Sign out?</h1><p>%[1]s asked to sign you out of your account.</p>
<input type="hidden" name="csrf" value="%[3]s">%[4]s
<button style="cursor:pointer;border:0;border-radius:6px;background:#245fd4;color:white;padding:9px 16px">Sign out</button>
</form>`
