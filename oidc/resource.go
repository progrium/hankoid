package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/progrium/hankoid/frontend"
	"golang.org/x/crypto/bcrypt"
)

// The contract for protected resources (such as 9P servers): introspection (RFC 7662), a feed
// of revoked devices, token revocation (RFC 7009) for clients, and protected-resource metadata
// (RFC 9728). The built-in gateway uses the same checks in process.

// Principal is who a resource's access token (or ticket) speaks for.
type Principal struct {
	UserID   string
	Username string
	DeviceID string
	ClientID string
	Audience string
	Scope    string
	Expiry   time.Time
}

// ErrInvalidToken is returned when a credential is refused (see IsInvalidToken).
var ErrInvalidToken = errors.New("invalid token")

// Authenticate verifies an access token for audience: our signature and issuer, typ at+jwt, not
// expired, and audience among its aud. A token naming a device is only valid while the device is.
func (p *Provider) Authenticate(ctx context.Context, raw, audience string) (*Principal, error) {
	if raw == "" || !strings.EqualFold(tokenTyp(raw), "at+jwt") {
		return nil, ErrInvalidToken
	}
	tok, err := jwt.Parse([]byte(raw), jwt.WithKeySet(p.keys.public), jwt.WithValidate(true),
		jwt.WithIssuer(p.cfg.Issuer), jwt.WithAudience(audience), jwt.WithClock(jwt.ClockFunc(p.now)))
	if err != nil {
		return nil, ErrInvalidToken
	}
	get := func(k string) string { v, _ := tok.Get(k); return stringOf(v) }
	pr := &Principal{UserID: tok.Subject(), Username: get("preferred_username"), DeviceID: get("did"),
		ClientID: get("client_id"), Audience: audience, Scope: get("scope"), Expiry: tok.Expiration()}
	if p.cfg.Client(pr.ClientID) == nil {
		return nil, ErrInvalidToken
	}
	if pr.DeviceID != "" {
		if p.devices == nil {
			return nil, ErrInvalidToken
		}
		ok, err := p.devices.DeviceActive(ctx, pr.DeviceID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrInvalidToken
		}
	}
	return pr, nil
}

// IssueTicket returns a single-use ticket standing for pr, valid for ttl, for clients (browsers)
// that can't send an Authorization header with a WebSocket handshake.
func (p *Provider) IssueTicket(ctx context.Context, pr *Principal, ttl time.Duration) (string, error) {
	if p.devices == nil {
		return "", errors.New("tickets need oidc.store: postgres")
	}
	return p.devices.CreateTicket(ctx, Ticket{Resource: pr.Audience, UserID: pr.UserID, DeviceID: pr.DeviceID,
		ClientID: pr.ClientID, Username: pr.Username}, ttl)
}

// RedeemTicket returns the principal a ticket for audience stands for, once.
func (p *Provider) RedeemTicket(ctx context.Context, ticket, audience string) (*Principal, error) {
	if p.devices == nil {
		return nil, ErrInvalidToken
	}
	t, err := p.devices.RedeemTicket(ctx, ticket, audience)
	if errors.Is(err, errNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	if t.DeviceID != "" {
		ok, err := p.devices.DeviceActive(ctx, t.DeviceID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrInvalidToken
		}
	}
	return &Principal{UserID: t.UserID, Username: t.Username, DeviceID: t.DeviceID, ClientID: t.ClientID, Audience: audience}, nil
}

// IsInvalidToken reports whether err means the credential was refused (as opposed to a failure
// to check it).
func IsInvalidToken(err error) bool { return errors.Is(err, ErrInvalidToken) }

// UserSession loads a user's identity and organizations through the admin API, for access rules.
func (p *Provider) UserSession(ctx context.Context, userID string) (*frontend.Session, error) {
	u, err := p.hanko.User(ctx, userID)
	if err != nil {
		return nil, err
	}
	email, verified := u.PrimaryEmail()
	s := &frontend.Session{UserID: userID, Email: email, EmailVerified: verified, Organizations: u.Organizations()}
	if u.Username != nil {
		s.Username = u.Username.Username
	}
	return s, nil
}

// RevokedSince lists devices revoked after since, for servers in this process that poll for
// revocations made by other instances.
func (p *Provider) RevokedSince(ctx context.Context, since time.Time) ([]Revocation, time.Time, error) {
	if p.devices == nil {
		return nil, since, nil
	}
	return p.devices.RevokedSince(ctx, since, 500)
}

// ResourceMetadataURL is where a resource's RFC 9728 metadata is served, when hankoid serves it
// (the resource is on the frontend's host): https://host/.well-known/oauth-protected-resource/path.
func (p *Provider) ResourceMetadataURL(audience string) string {
	u, err := url.Parse(audience)
	if err != nil {
		return ""
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	}
	return u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource" + strings.TrimSuffix(u.Path, "/")
}

// authenticateResource checks a resource's credentials: HTTP Basic (or form fields client_id and
// client_secret) with the resource ID and its secret.
func (p *Provider) authenticateResource(r *http.Request) *Resource {
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	res := p.cfg.Resource(id)
	if res == nil || secret == "" {
		return nil
	}
	if res.SecretHash != "" {
		if bcrypt.CompareHashAndPassword([]byte(res.SecretHash), []byte(secret)) != nil {
			return nil
		}
		return res
	}
	if res.Secret == "" || subtle.ConstantTimeCompare([]byte(res.Secret), []byte(secret)) != 1 {
		return nil
	}
	return res
}

func (p *Provider) resourceUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="oidc resource"`)
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
}

// introspect implements RFC 7662 for registered resources: a token is active only for the
// resource's own audience, and only while its device is.
func (p *Provider) introspect(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	res := p.authenticateResource(r)
	if res == nil {
		p.resourceUnauthorized(w)
		return
	}
	pr, err := p.Authenticate(r.Context(), r.PostForm.Get("token"), res.Audience)
	if IsInvalidToken(err) {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	if err != nil {
		log.Printf("oidc: introspect: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := map[string]any{"active": true, "token_type": "Bearer", "iss": p.cfg.Issuer, "sub": pr.UserID,
		"aud": res.Audience, "client_id": pr.ClientID, "scope": pr.Scope, "exp": pr.Expiry.Unix()}
	if pr.Username != "" {
		out["username"] = pr.Username
	}
	if pr.DeviceID != "" {
		out["did"] = pr.DeviceID
	}
	writeJSON(w, http.StatusOK, out)
}

// revocations lists devices revoked since a cursor, for resources that close live connections.
func (p *Provider) revocations(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if res := p.authenticateResource(r); res == nil {
		p.resourceUnauthorized(w)
		return
	}
	since := p.now().Add(-5 * time.Minute)
	if v := r.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "since must be RFC 3339"})
			return
		}
		since = t
	}
	if p.devices == nil {
		writeJSON(w, http.StatusOK, map[string]any{"revocations": []Revocation{}, "cursor": since.UTC().Format(time.RFC3339Nano)})
		return
	}
	list, cursor, err := p.devices.RevokedSince(r.Context(), since, 500)
	if err != nil {
		log.Printf("oidc: revocations: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revocations": list, "cursor": cursor.UTC().Format(time.RFC3339Nano)})
}

// revoke implements RFC 7009 for refresh tokens: revoking one signs its device out.
func (p *Provider) revoke(w http.ResponseWriter, r *http.Request) {
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
	noStore(w)
	if p.devices != nil && client.IsDevice() {
		id, err := p.devices.RevokeByRefreshToken(r.Context(), r.PostForm.Get("token"), client.ID)
		if err != nil {
			log.Printf("oidc: revoke: %v", err)
			tokenError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
			return
		}
		if id != "" {
			log.Printf("oidc: device %s signed out by its client %q", id, client.ID)
			p.notifyRevoked(id)
		}
	}
	// RFC 7009 §2.2: unknown tokens get the same answer.
	w.WriteHeader(http.StatusOK)
}

// resourceMetadata serves RFC 9728 metadata for resources on the frontend's own host, so a
// client holding only the resource's URL can find the issuer and its device client.
func (p *Provider) resourceMetadata(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/.well-known/oauth-protected-resource")
	issuer, _ := url.Parse(p.cfg.Issuer)
	var res *Resource
	for i := range p.cfg.Resources {
		u, err := url.Parse(p.cfg.Resources[i].Audience)
		if err == nil && strings.EqualFold(u.Host, issuer.Host) && strings.TrimSuffix(u.Path, "/") == strings.TrimSuffix(path, "/") {
			res = &p.cfg.Resources[i]
			break
		}
	}
	if res == nil {
		http.NotFound(w, r)
		return
	}
	doc := map[string]any{
		"resource":                 res.Audience,
		"authorization_servers":    []string{p.cfg.Issuer},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"openid", "profile", "offline_access"},
	}
	// Not part of RFC 9728: the public device client to log in with, so "hankoid login URL"
	// needs nothing but the URL.
	for _, c := range p.cfg.Clients {
		if c.IsDevice() && c.Public() && slices.Contains(c.Resources, res.ID) {
			doc["hankoid_device_client_id"] = c.ID
			break
		}
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, doc)
}
