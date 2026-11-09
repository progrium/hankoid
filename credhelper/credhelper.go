// Package credhelper signs a machine in to a resource protected by hankoid, with the OAuth
// device flow (RFC 8628), and hands out fresh access tokens for it. It backs the commands
// "hankoid login", "hankoid cred get" and "hankoid logout", which follow the credential helper
// contract in hyper9's design 0119: "COMMAND get URL" prints an Authorization header.
//
// Credentials live in one JSON file (by default ~/.config/hankoid/credentials.json, mode 0600),
// keyed by the resource's audience. Refresh tokens rotate on every use, so every read-modify-write
// of the file happens under a file lock.
package credhelper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrLoginRequired means there is no usable credential for the resource: run "hankoid login".
var ErrLoginRequired = errors.New("login required")

// Credential is what the file keeps for one resource.
type Credential struct {
	Resource           string    `json:"resource"`
	Issuer             string    `json:"issuer"`
	ClientID           string    `json:"client_id"`
	TokenEndpoint      string    `json:"token_endpoint"`
	RevocationEndpoint string    `json:"revocation_endpoint,omitempty"`
	RefreshToken       string    `json:"refresh_token"`
	AccessToken        string    `json:"access_token,omitempty"`
	AccessExpiry       time.Time `json:"access_expiry,omitempty"`
}

type file struct {
	Credentials map[string]*Credential `json:"credentials"`
}

// Helper holds the file path and the HTTP client the commands share.
type Helper struct {
	Path   string
	Client *http.Client
	Now    func() time.Time
	// Early is how long before expiry a cached access token is replaced. Default 60s.
	Early time.Duration
}

// DefaultPath is ~/.config/hankoid/credentials.json (or the OS's user config directory).
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "hankoid", "credentials.json"), nil
}

func (h *Helper) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return http.DefaultClient
}

func (h *Helper) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// update runs fn on the file's contents under an exclusive lock and saves them if fn returns
// save true.
func (h *Helper) update(fn func(f *file) (save bool, err error)) error {
	if err := os.MkdirAll(filepath.Dir(h.Path), 0o700); err != nil {
		return err
	}
	unlock, err := lockFile(h.Path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	f := &file{Credentials: map[string]*Credential{}}
	b, err := os.ReadFile(h.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, f); err != nil {
			return fmt.Errorf("%s: %w", h.Path, err)
		}
		if f.Credentials == nil {
			f.Credentials = map[string]*Credential{}
		}
	}
	save, err := fn(f)
	if !save {
		return err
	}
	out, merr := json.MarshalIndent(f, "", "  ")
	if merr != nil {
		return merr
	}
	tmp := h.Path + ".tmp"
	if werr := os.WriteFile(tmp, out, 0o600); werr != nil {
		return werr
	}
	if rerr := os.Rename(tmp, h.Path); rerr != nil {
		return rerr
	}
	return err
}

// find returns the credential for rawURL: its exact resource, or the longest resource that is
// a path prefix of it.
func (f *file) find(rawURL string) *Credential {
	want := strings.TrimSuffix(rawURL, "/")
	var best *Credential
	for _, c := range f.Credentials {
		r := strings.TrimSuffix(c.Resource, "/")
		if (want == r || strings.HasPrefix(want, r+"/")) && (best == nil || len(r) > len(strings.TrimSuffix(best.Resource, "/"))) {
			best = c
		}
	}
	return best
}

// Endpoints is what discovery finds for a resource.
type Endpoints struct {
	Resource           string
	Issuer             string
	ClientID           string
	DeviceEndpoint     string
	TokenEndpoint      string
	RevocationEndpoint string
}

// MetadataURL is where a resource's RFC 9728 metadata lives: ws(s) becomes http(s), and the
// resource's path goes after /.well-known/oauth-protected-resource.
func MetadataURL(resource string) (string, error) {
	u, err := url.Parse(resource)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid resource URL %q", resource)
	}
	switch u.Scheme {
	case "wss", "https":
		u.Scheme = "https"
	case "ws", "http":
		u.Scheme = "http"
	default:
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	return u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource" + strings.TrimSuffix(u.Path, "/"), nil
}

// Discover finds the issuer and endpoints for resource. issuer and clientID override what the
// resource's metadata says; with both set, the metadata isn't fetched.
func (h *Helper) Discover(ctx context.Context, resource, issuer, clientID string) (*Endpoints, error) {
	ep := &Endpoints{Resource: resource, Issuer: issuer, ClientID: clientID}
	if issuer == "" || clientID == "" {
		mu, err := MetadataURL(resource)
		if err != nil {
			return nil, err
		}
		var md struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
			DeviceClientID       string   `json:"hankoid_device_client_id"`
		}
		if err := h.getJSON(ctx, mu, &md); err != nil {
			return nil, fmt.Errorf("resource metadata: %w (pass --issuer and --client if the resource doesn't publish it)", err)
		}
		if md.Resource != "" {
			ep.Resource = md.Resource
		}
		if ep.Issuer == "" && len(md.AuthorizationServers) > 0 {
			ep.Issuer = md.AuthorizationServers[0]
		}
		if ep.ClientID == "" {
			ep.ClientID = md.DeviceClientID
		}
	}
	if ep.Issuer == "" || ep.ClientID == "" {
		return nil, errors.New("the resource's metadata names no issuer or device client; pass --issuer and --client")
	}
	var disco struct {
		Issuer             string `json:"issuer"`
		DeviceEndpoint     string `json:"device_authorization_endpoint"`
		TokenEndpoint      string `json:"token_endpoint"`
		RevocationEndpoint string `json:"revocation_endpoint"`
	}
	if err := h.getJSON(ctx, strings.TrimSuffix(ep.Issuer, "/")+"/.well-known/openid-configuration", &disco); err != nil {
		return nil, fmt.Errorf("issuer discovery: %w", err)
	}
	if disco.Issuer != ep.Issuer || disco.DeviceEndpoint == "" || disco.TokenEndpoint == "" {
		return nil, fmt.Errorf("issuer %s doesn't offer device sign-in", ep.Issuer)
	}
	ep.DeviceEndpoint, ep.TokenEndpoint, ep.RevocationEndpoint = disco.DeviceEndpoint, disco.TokenEndpoint, disco.RevocationEndpoint
	return ep, nil
}

func (h *Helper) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := h.client().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, res.Status)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(v)
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	Description  string `json:"error_description"`
	// device authorization response
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	Interval                int    `json:"interval"`
}

func (h *Helper) postForm(ctx context.Context, u string, form url.Values) (int, *tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := h.client().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	var tr tokenResponse
	if res.StatusCode != http.StatusNoContent {
		_ = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&tr)
	}
	return res.StatusCode, &tr, nil
}

// LoginOptions are the inputs to Login.
type LoginOptions struct {
	Issuer, ClientID string // override discovery
	DeviceName       string // shown on the approval page; default the hostname
	Out              io.Writer
}

// Login runs the device flow for resource and saves the credential. It prints where to approve
// the sign-in to opts.Out and waits until the user approves, denies, or the code expires.
func (h *Helper) Login(ctx context.Context, resource string, opts LoginOptions) (*Credential, error) {
	ep, err := h.Discover(ctx, resource, opts.Issuer, opts.ClientID)
	if err != nil {
		return nil, err
	}
	name := opts.DeviceName
	if name == "" {
		name, _ = os.Hostname()
	}
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	status, da, err := h.postForm(ctx, ep.DeviceEndpoint, url.Values{"client_id": {ep.ClientID},
		"scope": {"openid profile offline_access"}, "resource": {ep.Resource}, "device_name": {name}})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || da.DeviceCode == "" {
		return nil, fmt.Errorf("device authorization: %s %s", da.Error, da.Description)
	}
	link := da.VerificationURIComplete
	if link == "" {
		link = da.VerificationURI
	}
	fmt.Fprintf(out, "To sign in, open %s\nand check that it shows the code %s.\n", link, da.UserCode)
	interval := time.Duration(max(da.Interval, 1)) * time.Second
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		status, tr, err := h.postForm(ctx, ep.TokenEndpoint, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {da.DeviceCode}, "client_id": {ep.ClientID}})
		if err != nil {
			return nil, err
		}
		switch {
		case status == http.StatusOK && tr.RefreshToken != "":
			c := &Credential{Resource: ep.Resource, Issuer: ep.Issuer, ClientID: ep.ClientID, TokenEndpoint: ep.TokenEndpoint,
				RevocationEndpoint: ep.RevocationEndpoint, RefreshToken: tr.RefreshToken, AccessToken: tr.AccessToken,
				AccessExpiry: h.now().Add(time.Duration(tr.ExpiresIn) * time.Second)}
			err := h.update(func(f *file) (bool, error) {
				f.Credentials[c.Resource] = c
				return true, nil
			})
			return c, err
		case status == http.StatusOK:
			return nil, errors.New("the issuer returned no refresh token")
		case tr.Error == "authorization_pending":
		case tr.Error == "slow_down":
			interval += 5 * time.Second
		case tr.Error == "access_denied":
			return nil, errors.New("sign-in was denied")
		case tr.Error == "expired_token":
			return nil, errors.New("the code expired; run login again")
		default:
			return nil, fmt.Errorf("token: %d %s %s", status, tr.Error, tr.Description)
		}
	}
}

// Token returns an access token for rawURL, refreshing it (and rotating the refresh token)
// when the cached one is near expiry or force is set. It returns ErrLoginRequired when no
// credential covers rawURL or the issuer refuses the refresh token.
func (h *Helper) Token(ctx context.Context, rawURL string, force bool) (string, error) {
	early := h.Early
	if early == 0 {
		early = time.Minute
	}
	var token string
	err := h.update(func(f *file) (bool, error) {
		c := f.find(rawURL)
		if c == nil {
			return false, ErrLoginRequired
		}
		if !force && c.AccessToken != "" && h.now().Add(early).Before(c.AccessExpiry) {
			token = c.AccessToken
			return false, nil
		}
		status, tr, err := h.postForm(ctx, c.TokenEndpoint, url.Values{"grant_type": {"refresh_token"},
			"refresh_token": {c.RefreshToken}, "client_id": {c.ClientID}, "resource": {c.Resource}})
		if err != nil {
			return false, err
		}
		if status == http.StatusBadRequest && (tr.Error == "invalid_grant" || tr.Error == "unauthorized_client") {
			delete(f.Credentials, c.Resource)
			return true, ErrLoginRequired
		}
		if status != http.StatusOK || tr.AccessToken == "" {
			return false, fmt.Errorf("refresh: %d %s %s", status, tr.Error, tr.Description)
		}
		if tr.RefreshToken != "" {
			c.RefreshToken = tr.RefreshToken
		}
		c.AccessToken, c.AccessExpiry = tr.AccessToken, h.now().Add(time.Duration(tr.ExpiresIn)*time.Second)
		token = c.AccessToken
		return true, nil
	})
	return token, err
}

// Logout signs the device out at the issuer (RFC 7009) and forgets the credential. It reports
// whether there was one.
func (h *Helper) Logout(ctx context.Context, rawURL string) (bool, error) {
	var found bool
	err := h.update(func(f *file) (bool, error) {
		c := f.find(rawURL)
		if c == nil {
			return false, nil
		}
		found = true
		delete(f.Credentials, c.Resource)
		if c.RevocationEndpoint != "" {
			if _, _, err := h.postForm(ctx, c.RevocationEndpoint, url.Values{"token": {c.RefreshToken},
				"token_type_hint": {"refresh_token"}, "client_id": {c.ClientID}}); err != nil {
				return true, fmt.Errorf("forgot the credential, but couldn't sign the device out: %w", err)
			}
		}
		return true, nil
	})
	return found, err
}
