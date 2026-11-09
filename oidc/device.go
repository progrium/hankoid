package oidc

import (
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// refreshReuseGrace is how long after rotation a refresh token is still accepted, as a concurrent
// refresh rather than theft. Many mounts on one host reconnect at once after a server restart.
const refreshReuseGrace = 30 * time.Second

// SetDeviceStore enables the device grant, refresh tokens and the resource-server endpoints.
func (p *Provider) SetDeviceStore(ds *DeviceStore) { p.devices = ds }

// DeviceStore returns the provider's device store, or nil.
func (p *Provider) DeviceStore() *DeviceStore { return p.devices }

// OnRevoke registers fn to be called with device IDs revoked by this instance, so a gateway in
// the same process can close their connections at once. Other instances learn of revocations
// through the revocations feed.
func (p *Provider) OnRevoke(fn func(deviceIDs []string)) {
	p.hookMu.Lock()
	defer p.hookMu.Unlock()
	p.revokeHooks = append(p.revokeHooks, fn)
}

func (p *Provider) notifyRevoked(ids ...string) {
	if len(ids) == 0 {
		return
	}
	p.hookMu.Lock()
	hooks := slices.Clone(p.revokeHooks)
	p.hookMu.Unlock()
	for _, h := range hooks {
		h(ids)
	}
}

// grantedScope keeps the requested scopes the client may have, in order, without duplicates.
func grantedScope(client *Client, requested string) []string {
	var granted []string
	for _, s := range strings.Fields(requested) {
		if client.AllowsScope(s) && !slices.Contains(granted, s) {
			granted = append(granted, s)
		}
	}
	return granted
}

// pickResource resolves an RFC 8707 resource parameter to one of the client's resources. With
// none given, a client with exactly one resource gets it; otherwise the token is for userinfo.
func (p *Provider) pickResource(client *Client, raw string) (*Resource, bool) {
	if raw == "" {
		if len(client.Resources) == 1 {
			return p.cfg.Resource(client.Resources[0]), true
		}
		return nil, true
	}
	for _, id := range client.Resources {
		if r := p.cfg.Resource(id); r != nil && r.Audience == raw {
			return r, true
		}
	}
	return nil, false
}

// cleanDeviceName keeps a short, printable device name from the requester.
func cleanDeviceName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > 64 {
		s = string(r[:64])
	}
	return s
}

// deviceAuthorization implements the device authorization endpoint (RFC 8628 §3.1).
func (p *Provider) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	ip := p.clientIP(r)
	if !p.limiterN("devauth:"+ip, 6*time.Second, 10).Allow() {
		w.Header().Set("Retry-After", "6")
		tokenError(w, http.StatusTooManyRequests, "slow_down", "too many requests")
		return
	}
	client := p.authenticateClient(r)
	if client == nil {
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if !client.IsDevice() || p.devices == nil {
		tokenError(w, http.StatusBadRequest, "unauthorized_client", "this client may not use the device grant")
		return
	}
	resource, ok := p.pickResource(client, r.PostForm.Get("resource"))
	if !ok {
		tokenError(w, http.StatusBadRequest, "invalid_target", "unknown resource for this client")
		return
	}
	aud := ""
	if resource != nil {
		aud = resource.Audience
	}
	now := p.now()
	geo := ""
	if h := p.cfg.Device.GeoHeader; h != "" {
		geo = cleanDeviceName(r.Header.Get(h))
	}
	ua := r.UserAgent()
	if len(ua) > 256 {
		ua = ua[:256]
	}
	g := DeviceGrant{ClientID: client.ID, Scope: strings.Join(grantedScope(client, r.PostForm.Get("scope")), " "),
		Resource: aud, RequesterIP: ip, RequesterGeo: geo, RequesterUA: ua, DeviceName: cleanDeviceName(r.PostForm.Get("device_name")),
		Interval: p.cfg.Device.Interval, CreatedAt: now, ExpiresAt: now.Add(p.cfg.Device.CodeTTL)}
	deviceCode, userCode, err := p.devices.CreateGrant(r.Context(), g)
	if err != nil {
		log.Printf("oidc: device authorization: %v", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "device store unavailable")
		return
	}
	verify := strings.TrimSuffix(p.cfg.Issuer, "/oidc") + "/device"
	noStore(w)
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 FormatUserCode(userCode),
		"verification_uri":          verify,
		"verification_uri_complete": verify + "?user_code=" + FormatUserCode(userCode),
		"expires_in":                int(p.cfg.Device.CodeTTL.Seconds()),
		"interval":                  int(p.cfg.Device.Interval.Seconds()),
	})
}

// deviceCodeGrant answers a token-endpoint poll with a device code (RFC 8628 §3.4, §3.5).
func (p *Provider) deviceCodeGrant(w http.ResponseWriter, r *http.Request, client *Client) {
	deviceCode := r.PostForm.Get("device_code")
	res, g, err := p.devices.Poll(r.Context(), deviceCode, client.ID)
	if err != nil {
		log.Printf("oidc: device poll: %v", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "device store unavailable")
		return
	}
	switch res {
	case PollSlowDown:
		tokenError(w, http.StatusBadRequest, "slow_down", "polling too fast")
		return
	case PollPending:
		tokenError(w, http.StatusBadRequest, "authorization_pending", "")
		return
	case PollDenied:
		tokenError(w, http.StatusBadRequest, "access_denied", "the user denied the request")
		return
	case PollExpired:
		tokenError(w, http.StatusBadRequest, "expired_token", "the device code has expired")
		return
	case PollUnknown:
		tokenError(w, http.StatusBadRequest, "invalid_grant", "invalid or already used device code")
		return
	}
	raw := r.PostForm.Get("resource")
	if raw == "" {
		raw = g.Resource
	}
	resource, ok := p.pickResource(client, raw)
	if !ok {
		tokenError(w, http.StatusBadRequest, "invalid_target", "unknown resource for this client")
		return
	}
	u, err := p.lookupUser(r, g.UserID, g.Scope, client)
	if errors.Is(err, errAccessRevoked) {
		tokenError(w, http.StatusBadRequest, "access_denied", "this account may not use "+client.DisplayName())
		return
	}
	if err != nil {
		log.Printf("oidc: load user %s: %v", g.UserID, err)
		tokenError(w, http.StatusBadRequest, "invalid_grant", "user unavailable")
		return
	}
	now := p.now()
	nd := NewDevice{Name: g.DeviceName, IP: g.RequesterIP}
	if client.RefreshTokenMaxTTL > 0 {
		exp := now.Add(client.RefreshTokenMaxTTL)
		nd.ExpiresAt = &exp
	}
	if slices.Contains(strings.Fields(g.Scope), "offline_access") {
		if nd.RefreshToken, err = randomToken("hkrt_"); err != nil {
			tokenError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		nd.RefreshExp = refreshExpiry(now, client.RefreshTokenIdleTTL, nd.ExpiresAt)
	}
	d, err := p.devices.Consume(r.Context(), deviceCode, nd)
	if errors.Is(err, errNotFound) {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "invalid or already used device code")
		return
	}
	if err != nil {
		log.Printf("oidc: consume device grant: %v", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "device store unavailable")
		return
	}
	log.Printf("oidc: device %s (%q) approved for %s on client %q from %s", d.ID, d.Name, g.UserID, client.ID, g.RequesterIP)
	p.writeTokens(w, tokenGrant{client: client, userID: g.UserID, deviceID: d.ID, scope: g.Scope, authTime: g.AuthTime,
		resource: resource, user: u, refreshToken: nd.RefreshToken})
}

func refreshExpiry(now time.Time, idle time.Duration, max *time.Time) time.Time {
	exp := now.Add(idle)
	if max != nil && max.Before(exp) {
		exp = *max
	}
	return exp
}

// refreshTokenGrant rotates a device's refresh token (RFC 6749 §6, RFC 9700 §4.14.2).
func (p *Provider) refreshTokenGrant(w http.ResponseWriter, r *http.Request, client *Client) {
	newToken, err := randomToken("hkrt_")
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	now := p.now()
	// The device's absolute lifetime is applied by the store (expired devices can't refresh);
	// the idle lifetime starts again here.
	res, d, err := p.devices.Refresh(r.Context(), client.ID, r.PostForm.Get("refresh_token"), newToken,
		now.Add(client.RefreshTokenIdleTTL), p.clientIP(r), refreshReuseGrace)
	if err != nil {
		log.Printf("oidc: refresh: %v", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "device store unavailable")
		return
	}
	switch res {
	case RefreshReused:
		log.Printf("oidc: refresh token reuse for device %s (user %s); device revoked", d.ID, d.UserID)
		p.notifyRevoked(d.ID)
		tokenError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected; the device was signed out")
		return
	case RefreshInvalid:
		tokenError(w, http.StatusBadRequest, "invalid_grant", "invalid, expired or revoked refresh token")
		return
	}
	scope := d.Scope
	if req := r.PostForm.Get("scope"); req != "" {
		for _, s := range strings.Fields(req) {
			if !slices.Contains(strings.Fields(d.Scope), s) {
				tokenError(w, http.StatusBadRequest, "invalid_scope", "scope exceeds the original grant")
				return
			}
		}
		scope = req
	}
	resource, ok := p.pickResource(client, r.PostForm.Get("resource"))
	if !ok {
		tokenError(w, http.StatusBadRequest, "invalid_target", "unknown resource for this client")
		return
	}
	u, err := p.lookupUser(r, d.UserID, scope, client)
	if errors.Is(err, errAccessRevoked) || errors.Is(err, errUserGone) {
		if ok, rerr := p.devices.RevokeDevice(r.Context(), d.ID, "", "access"); rerr == nil && ok {
			p.notifyRevoked(d.ID)
		}
		tokenError(w, http.StatusBadRequest, "invalid_grant", "access to this client was revoked")
		return
	}
	if err != nil {
		log.Printf("oidc: load user %s: %v", d.UserID, err)
		tokenError(w, http.StatusInternalServerError, "server_error", "user lookup failed")
		return
	}
	p.writeTokens(w, tokenGrant{client: client, userID: d.UserID, deviceID: d.ID, scope: scope, authTime: d.AuthTime,
		resource: resource, user: u, refreshToken: newToken})
}

// tokenGrant is what a successful token request issues tokens for.
type tokenGrant struct {
	client       *Client
	userID       string
	sessionID    string // Hanko session, for the authorization-code grant
	deviceID     string // device, for the device and refresh grants
	nonce        string
	scope        string
	authTime     time.Time
	resource     *Resource // nil: an access token for userinfo
	user         *userInfo
	refreshToken string
}

// writeTokens signs and sends the ID token (when openid was granted), the access token, and any
// refresh token.
func (p *Provider) writeTokens(w http.ResponseWriter, g tokenGrant) {
	now := p.now()
	set := func(t jwt.Token, k string, v any) { _ = t.Set(k, v) }
	body := map[string]any{"token_type": "Bearer", "expires_in": int(p.cfg.AccessTokenTTL.Seconds()), "scope": g.scope}
	if slices.Contains(strings.Fields(g.scope), "openid") {
		idt := jwt.New()
		set(idt, jwt.IssuerKey, p.cfg.Issuer)
		set(idt, jwt.SubjectKey, g.userID)
		set(idt, jwt.AudienceKey, []string{g.client.ID})
		set(idt, jwt.IssuedAtKey, now)
		set(idt, jwt.ExpirationKey, now.Add(p.cfg.IDTokenTTL))
		set(idt, "auth_time", g.authTime.Unix())
		set(idt, "azp", g.client.ID)
		if g.nonce != "" {
			set(idt, "nonce", g.nonce)
		}
		if g.sessionID != "" {
			set(idt, "sid", g.sessionID)
		}
		for k, v := range g.user.claims {
			set(idt, k, v)
		}
		idToken, err := p.sign(idt)
		if err != nil {
			log.Printf("oidc: sign id token: %v", err)
			tokenError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		body["id_token"] = idToken
	}
	at := jwt.New()
	aud := p.endpoint("userinfo")
	if g.resource != nil {
		aud = g.resource.Audience
	}
	set(at, jwt.IssuerKey, p.cfg.Issuer)
	set(at, jwt.SubjectKey, g.userID)
	set(at, jwt.AudienceKey, []string{aud})
	set(at, jwt.IssuedAtKey, now)
	set(at, jwt.ExpirationKey, now.Add(p.cfg.AccessTokenTTL))
	set(at, jwt.JwtIDKey, randomID())
	set(at, "client_id", g.client.ID)
	set(at, "scope", g.scope)
	if g.sessionID != "" {
		set(at, "sid", g.sessionID)
	}
	if g.deviceID != "" {
		set(at, "did", g.deviceID)
		set(at, "auth_time", g.authTime.Unix())
		if g.user.username != "" {
			set(at, "preferred_username", g.user.username)
		}
	}
	accessToken, err := p.signTyp(at, "at+jwt")
	if err != nil {
		log.Printf("oidc: sign access token: %v", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	body["access_token"] = accessToken
	if g.refreshToken != "" {
		body["refresh_token"] = g.refreshToken
	}
	noStore(w)
	writeJSON(w, http.StatusOK, body)
}

// Handlers are the provider's routes for the frontend's mux, keyed by pattern.
func (p *Provider) Handlers() map[string]http.Handler {
	h := map[string]http.Handler{"/oidc/": p.Handler()}
	if p.devices != nil {
		h["/device"] = p.DeviceHandler()
		h["/account/"] = p.AccountHandler()
	}
	if len(p.cfg.Resources) > 0 {
		h["GET /.well-known/oauth-protected-resource/"] = http.HandlerFunc(p.resourceMetadata)
	}
	return h
}
