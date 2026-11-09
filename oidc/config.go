// Package oidc is an OpenID Connect provider for the frontend. It signs users in with their
// Hanko session (via the frontend's /signin page) and issues ID tokens to configured clients.
// See PLAN.md.
package oidc

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/progrium/hankoid/frontend"
	"gopkg.in/yaml.v3"
)

// Config is the top-level "oidc" key of the Hanko config file.
type Config struct {
	// Issuer is derived from server.frontend.public_url + "/oidc"; it isn't read from the file.
	Issuer string `yaml:"-"`
	// SecretKeys are Hanko's secrets.keys, used to seal authorization codes.
	SecretKeys []string `yaml:"-"`

	SigningKeyFile         string        `yaml:"signing_key_file"`
	SigningKey             string        `yaml:"signing_key"`
	PreviousSigningKeyFile string        `yaml:"previous_signing_key_file"`
	CodeTTL                time.Duration `yaml:"code_ttl"`
	IDTokenTTL             time.Duration `yaml:"id_token_ttl"`
	AccessTokenTTL         time.Duration `yaml:"access_token_ttl"`
	// Store is where authorization codes live: "memory" (the default; one instance only) or
	// "postgres" (Hanko's database, in a separate hankoid schema; restart- and replica-safe).
	Store string `yaml:"store"`
	// Database is Hanko's top-level database section, read only when Store is "postgres".
	Database Database `yaml:"-"`
	// TrustedProxies is server.frontend.trusted_proxies, set by the caller; it's used to find the
	// client IP for rate limiting. Empty means the TCP peer address is used.
	TrustedProxies []string `yaml:"-"`
	Clients        []Client `yaml:"clients"`
	// Resources are protected servers (such as 9P servers) that accept this provider's access
	// tokens. Device clients get tokens for them.
	Resources []Resource `yaml:"resources"`
	// Device configures the device authorization grant (RFC 8628).
	Device DeviceSettings `yaml:"device"`
}

// DeviceSettings tune the device authorization grant.
type DeviceSettings struct {
	// CodeTTL is how long a device code and user code stay valid (default 10 minutes).
	CodeTTL time.Duration `yaml:"code_ttl"`
	// Interval is the minimum polling interval given to clients (default 5 seconds).
	Interval time.Duration `yaml:"interval"`
	// GeoHeader names a request header carrying the client's approximate location, such as one a
	// load balancer adds. It's shown on the /device confirmation page next to the IP address.
	GeoHeader string `yaml:"geo_header"`
	// MaxAuthAge is how recent a passkey sign-in must be to approve a device (default 5 minutes).
	MaxAuthAge time.Duration `yaml:"max_auth_age"`
}

// Resource is a protected server that accepts access tokens with its audience.
type Resource struct {
	ID string `yaml:"id"`
	// Audience is the aud of tokens for this resource: the URL clients connect to, such as
	// wss://files.example.com/9p/files.
	Audience string `yaml:"audience"`
	// Secret (or SecretHash, bcrypt) authenticates the resource at /oidc/introspect and
	// /oidc/revocations. Optional for a resource only served by the built-in gateway.
	Secret     string `yaml:"secret"`
	SecretHash string `yaml:"secret_hash"`
}

// Grant types.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	GrantRefreshToken      = "refresh_token"
)

// grantAlias accepts "device_code" as shorthand for the device grant's URN in config.
func grantAlias(g string) string {
	if g == "device_code" {
		return GrantDeviceCode
	}
	return g
}

// Client is a registered relying party.
type Client struct {
	ID                     string   `yaml:"id"`
	Name                   string   `yaml:"name"`
	Secret                 string   `yaml:"secret"`
	SecretHash             string   `yaml:"secret_hash"`
	RedirectURIs           []string `yaml:"redirect_uris"`
	PostLogoutRedirectURIs []string `yaml:"post_logout_redirect_uris"`
	Scopes                 []string `yaml:"scopes"`
	RequirePKCE            bool     `yaml:"require_pkce"`
	// Access decides who may sign in. Required; use {any_user: true} to allow every Hanko user.
	Access     *frontend.AccessRule `yaml:"access"`
	RolesClaim bool                 `yaml:"roles_claim"`
	// TokenEndpointAuthMethod is client_secret_basic/client_secret_post (the default: either is
	// accepted) or "none" for a public client, which only the device grant may use.
	TokenEndpointAuthMethod string `yaml:"token_endpoint_auth_method"`
	// GrantTypes the client may use: authorization_code (the default) and/or device_code.
	// Device clients also get refresh tokens when they ask for offline_access.
	GrantTypes []string `yaml:"grant_types"`
	// Resources are the IDs of oidc.resources this client may get access tokens for.
	Resources []string `yaml:"resources"`
	// RefreshTokenIdleTTL is how long an unused refresh token stays valid (default 30 days).
	// Each refresh starts it again.
	RefreshTokenIdleTTL time.Duration `yaml:"refresh_token_idle_ttl"`
	// RefreshTokenMaxTTL, if set, is a device's absolute lifetime from its approval.
	RefreshTokenMaxTTL time.Duration `yaml:"refresh_token_max_ttl"`
}

// Public reports whether the client has no secret (token_endpoint_auth_method: none).
func (c *Client) Public() bool { return c.TokenEndpointAuthMethod == "none" }

// AllowsGrant reports whether the client may use grant type g.
func (c *Client) AllowsGrant(g string) bool { return slices.Contains(c.GrantTypes, grantAlias(g)) }

// IsDevice reports whether the client uses the device grant.
func (c *Client) IsDevice() bool { return c.AllowsGrant(GrantDeviceCode) }

// DisplayName is the client's name for the sign-in page.
func (c *Client) DisplayName() string {
	if c.Name != "" {
		return c.Name
	}
	return c.ID
}

// Allows reports whether a user may sign in to this client.
func (c *Client) Allows(s *frontend.Session) bool {
	return c.Access != nil && c.Access.Allows(s)
}

// AllowsScope reports whether the client may request scope.
func (c *Client) AllowsScope(scope string) bool {
	return slices.Contains(c.Scopes, scope)
}

// Resource returns the resource with the given ID, or nil.
func (c *Config) Resource(id string) *Resource {
	for i := range c.Resources {
		if c.Resources[i].ID == id {
			return &c.Resources[i]
		}
	}
	return nil
}

// ResourceByAudience returns the resource with the given audience, or nil.
func (c *Config) ResourceByAudience(aud string) *Resource {
	for i := range c.Resources {
		if c.Resources[i].Audience == aud {
			return &c.Resources[i]
		}
	}
	return nil
}

// DeviceEnabled reports whether any client uses the device grant.
func (c *Config) DeviceEnabled() bool {
	for i := range c.Clients {
		if c.Clients[i].IsDevice() {
			return true
		}
	}
	return false
}

// Enabled reports whether the provider should be served.
func (c *Config) Enabled() bool { return len(c.Clients) > 0 }

// Client returns the client with the given ID, or nil.
func (c *Config) Client(id string) *Client {
	for i := range c.Clients {
		if c.Clients[i].ID == id {
			return &c.Clients[i]
		}
	}
	return nil
}

// Store values for Config.Store.
const (
	StoreMemory   = "memory"
	StorePostgres = "postgres"
)

type file struct {
	OIDC     Config   `yaml:"oidc"`
	Database Database `yaml:"database"`
	Secrets  struct {
		Keys []string `yaml:"keys"`
	} `yaml:"secrets"`
}

var envName = regexp.MustCompile(`[^A-Z0-9]+`)

// ClientEnvPrefix is the environment variable prefix for a client, e.g. OIDC_CLIENTS_MYAPP_.
func ClientEnvPrefix(id string) string {
	return "OIDC_CLIENTS_" + envName.ReplaceAllString(strings.ToUpper(id), "_") + "_"
}

// LoadConfig reads the top-level oidc key and secrets.keys from a Hanko config file's contents,
// applies environment overrides, and validates. publicURL is server.frontend.public_url.
// Relative key file paths are resolved against baseDir (the config file's directory).
//
// Environment: OIDC_SIGNING_KEY (PEM), OIDC_STORE, SECRETS_KEYS (comma-separated, like Hanko),
// Hanko's DATABASE_* variables, and per client OIDC_CLIENTS_<ID>_SECRET and
// OIDC_CLIENTS_<ID>_ACCESS_USERS (comma-separated).
func LoadConfig(raw []byte, publicURL, baseDir string) (*Config, error) {
	var f file
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse oidc config: %w", err)
	}
	c := &f.OIDC
	c.Issuer = strings.TrimRight(publicURL, "/") + "/oidc"
	c.SecretKeys = f.Secrets.Keys
	if v := os.Getenv("SECRETS_KEYS"); v != "" {
		c.SecretKeys = frontend.SplitList(v)
	}
	if v := os.Getenv("OIDC_SIGNING_KEY"); v != "" {
		c.SigningKey = v
	}
	if v := os.Getenv("OIDC_STORE"); v != "" {
		c.Store = v
	}
	if c.Store == "" {
		c.Store = StoreMemory
	}
	c.Database = f.Database
	c.Database.applyEnv()
	for _, f := range []*string{&c.SigningKeyFile, &c.PreviousSigningKeyFile} {
		if *f != "" && !filepath.IsAbs(*f) {
			*f = filepath.Join(baseDir, *f)
		}
	}
	if c.CodeTTL == 0 {
		c.CodeTTL = 60 * time.Second
	}
	if c.IDTokenTTL == 0 {
		c.IDTokenTTL = 5 * time.Minute
	}
	if c.AccessTokenTTL == 0 {
		c.AccessTokenTTL = 5 * time.Minute
	}
	for i := range c.Clients {
		cl := &c.Clients[i]
		prefix := ClientEnvPrefix(cl.ID)
		if v := os.Getenv(prefix + "SECRET"); v != "" {
			cl.Secret = v
		}
		if v := os.Getenv(prefix + "ACCESS_USERS"); v != "" {
			if cl.Access == nil {
				cl.Access = &frontend.AccessRule{}
			}
			cl.Access.Users = frontend.SplitList(v)
		}
		if len(cl.GrantTypes) == 0 {
			cl.GrantTypes = []string{GrantAuthorizationCode}
		}
		for j, g := range cl.GrantTypes {
			cl.GrantTypes[j] = grantAlias(g)
		}
		if len(cl.Scopes) == 0 {
			cl.Scopes = []string{"openid", "email", "profile"}
			if cl.IsDevice() {
				cl.Scopes = append(cl.Scopes, "offline_access")
			}
		}
		if cl.IsDevice() && cl.RefreshTokenIdleTTL == 0 {
			cl.RefreshTokenIdleTTL = 30 * 24 * time.Hour
		}
		if cl.RolesClaim && !cl.AllowsScope("roles") {
			cl.Scopes = append(cl.Scopes, "roles")
		}
	}
	for i := range c.Resources {
		r := &c.Resources[i]
		if v := os.Getenv(ResourceEnvPrefix(r.ID) + "SECRET"); v != "" {
			r.Secret = v
		}
	}
	if c.Device.CodeTTL == 0 {
		c.Device.CodeTTL = 10 * time.Minute
	}
	if c.Device.Interval == 0 {
		c.Device.Interval = 5 * time.Second
	}
	if c.Device.MaxAuthAge == 0 {
		c.Device.MaxAuthAge = 5 * time.Minute
	}
	return c, c.Validate()
}

// ResourceEnvPrefix is the environment variable prefix for a resource, e.g. OIDC_RESOURCES_FILES_.
func ResourceEnvPrefix(id string) string {
	return "OIDC_RESOURCES_" + envName.ReplaceAllString(strings.ToUpper(id), "_") + "_"
}

// Validate checks the provider configuration.
func (c *Config) Validate() error {
	if !c.Enabled() {
		return nil
	}
	var errs []error
	if c.CodeTTL <= 0 || c.IDTokenTTL <= 0 || c.AccessTokenTTL <= 0 {
		errs = append(errs, errors.New("oidc: TTLs must be positive"))
	}
	if len(c.SecretKeys) == 0 {
		errs = append(errs, errors.New("oidc: secrets.keys must be set (used to seal authorization codes)"))
	}
	switch c.Store {
	case "", StoreMemory:
	case StorePostgres:
		if _, err := c.Database.URL(); err != nil {
			errs = append(errs, fmt.Errorf("oidc: store postgres: %w", err))
		}
	default:
		errs = append(errs, fmt.Errorf("oidc: store must be %q or %q, not %q", StoreMemory, StorePostgres, c.Store))
	}
	if !isLoopbackURL(c.Issuer) {
		for _, k := range c.SecretKeys {
			if strings.Contains(strings.ToLower(k), "change-me") || len(k) < 32 {
				errs = append(errs, errors.New("oidc: secrets.keys looks like a placeholder or is shorter than 32 characters; set a strong secret for a non-local public_url"))
				break
			}
		}
	}
	seen := map[string]bool{}
	for i, cl := range c.Clients {
		where := fmt.Sprintf("oidc.clients[%d]", i)
		if cl.ID == "" {
			errs = append(errs, fmt.Errorf("%s: id is required", where))
		} else if seen[cl.ID] {
			errs = append(errs, fmt.Errorf("%s: duplicate id %q", where, cl.ID))
		}
		seen[cl.ID] = true
		where = fmt.Sprintf("oidc client %q", cl.ID)
		for _, g := range cl.GrantTypes {
			if g != GrantAuthorizationCode && g != GrantDeviceCode {
				errs = append(errs, fmt.Errorf("%s: unsupported grant type %q (authorization_code or device_code)", where, g))
			}
		}
		switch cl.TokenEndpointAuthMethod {
		case "", "client_secret_basic", "client_secret_post":
			if cl.Secret == "" && cl.SecretHash == "" {
				errs = append(errs, fmt.Errorf("%s: secret or secret_hash is required (or set %sSECRET)", where, ClientEnvPrefix(cl.ID)))
			}
		case "none":
			if cl.AllowsGrant(GrantAuthorizationCode) || !cl.IsDevice() {
				errs = append(errs, fmt.Errorf("%s: token_endpoint_auth_method none is only allowed with grant_types [device_code]", where))
			}
			if cl.Secret != "" || cl.SecretHash != "" {
				errs = append(errs, fmt.Errorf("%s: a public client (token_endpoint_auth_method none) must not have a secret", where))
			}
		default:
			errs = append(errs, fmt.Errorf("%s: token_endpoint_auth_method must be client_secret_basic, client_secret_post or none", where))
		}
		if cl.AllowsGrant(GrantAuthorizationCode) && len(cl.RedirectURIs) == 0 {
			errs = append(errs, fmt.Errorf("%s: at least one redirect_uri is required", where))
		}
		if cl.IsDevice() && c.Store != StorePostgres {
			errs = append(errs, fmt.Errorf("%s: the device grant needs oidc.store: postgres, so pending logins and refresh tokens survive restarts", where))
		}
		if cl.AllowsScope("offline_access") && !cl.IsDevice() {
			errs = append(errs, fmt.Errorf("%s: offline_access (refresh tokens) is only for device clients", where))
		}
		if cl.RefreshTokenIdleTTL < 0 || cl.RefreshTokenMaxTTL < 0 {
			errs = append(errs, fmt.Errorf("%s: refresh token TTLs must not be negative", where))
		}
		for _, id := range cl.Resources {
			if c.Resource(id) == nil {
				errs = append(errs, fmt.Errorf("%s: unknown resource %q", where, id))
			}
		}
		for _, u := range append(append([]string{}, cl.RedirectURIs...), cl.PostLogoutRedirectURIs...) {
			if err := validateRedirect(u); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", where, err))
			}
		}
		if !cl.AllowsScope("openid") {
			errs = append(errs, fmt.Errorf("%s: scopes must include openid", where))
		}
		if cl.Access == nil {
			errs = append(errs, fmt.Errorf("%s: access is required (users, organization, or any_user: true)", where))
		} else if err := cl.Access.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: access: %w", where, err))
		}
		if cl.Secret != "" && len(cl.Secret) < 16 && !isLoopbackURL(c.Issuer) {
			errs = append(errs, fmt.Errorf("%s: secret must be at least 16 characters", where))
		}
		if cl.RolesClaim && (cl.Access == nil || strings.TrimSpace(cl.Access.Organization) == "") {
			errs = append(errs, fmt.Errorf("%s: roles_claim requires access.organization", where))
		}
	}
	seenRes := map[string]bool{}
	for i, r := range c.Resources {
		where := fmt.Sprintf("oidc.resources[%d]", i)
		if r.ID == "" {
			errs = append(errs, fmt.Errorf("%s: id is required", where))
		} else if seenRes[r.ID] {
			errs = append(errs, fmt.Errorf("%s: duplicate id %q", where, r.ID))
		}
		seenRes[r.ID] = true
		where = fmt.Sprintf("oidc resource %q", r.ID)
		u, err := url.Parse(r.Audience)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
			(u.Scheme != "https" && u.Scheme != "wss" && !((u.Scheme == "http" || u.Scheme == "ws") && isLoopbackHost(u.Hostname()))) {
			errs = append(errs, fmt.Errorf("%s: audience must be an https:// or wss:// URL without query (http/ws only for localhost)", where))
		}
		if c.ResourceByAudience(r.Audience) != &c.Resources[i] {
			errs = append(errs, fmt.Errorf("%s: duplicate audience %q", where, r.Audience))
		}
		if r.Secret != "" && len(r.Secret) < 16 && !isLoopbackURL(c.Issuer) {
			errs = append(errs, fmt.Errorf("%s: secret must be at least 16 characters", where))
		}
	}
	if c.Device.CodeTTL < time.Minute || c.Device.Interval < time.Second || c.Device.MaxAuthAge <= 0 {
		errs = append(errs, errors.New("oidc.device: code_ttl must be at least 1m, interval at least 1s, max_auth_age positive"))
	}
	return errors.Join(errs...)
}

// validateRedirect allows https URLs, and http only for loopback hosts.
func validateRedirect(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("redirect URI %q must be absolute", raw)
	}
	if u.Fragment != "" || u.User != nil {
		return fmt.Errorf("redirect URI %q must not have a fragment or credentials", raw)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && isLoopbackHost(u.Hostname()):
	default:
		return fmt.Errorf("redirect URI %q must use https (http only for localhost)", raw)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && isLoopbackHost(u.Hostname())
}
