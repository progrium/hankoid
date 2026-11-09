// Package gateway is hankoid's built-in 9P gateway: routes on the frontend that accept 9P over
// WebSocket from clients signed in with device sign-in (or holding a ticket), and connect each
// one to a 9P backend over TCP, a unix socket or a WebSocket. It is a reference for the
// resource contract and a generic front end for 9P servers that know nothing about OIDC.
//
// The gateway reads 9P's framing and handles three messages: Tversion (only the route's
// dialects pass), Tauth (refused: authentication happened at the handshake) and Tattach
// (uname, n_uname and aname come from the route's identity, not the client). Everything else
// passes through. A device's connections close when the device is revoked.
package gateway

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/progrium/hankoid/frontend"
	"gopkg.in/yaml.v3"
)

// Config is the top-level gateway key.
type Config struct {
	Routes []Route `yaml:"routes"`
}

// Route is one 9P endpoint.
type Route struct {
	// Path is where clients connect, such as /9p/files. Default: the resource audience's path.
	Path string `yaml:"path"`
	// Resource is the ID of an oidc.resources entry; tokens must be issued for its audience.
	Resource string `yaml:"resource"`
	// Backend is tcp!host!port, unix!path, ws://… or wss://….
	Backend string `yaml:"backend"`
	// Versions are the dialects clients may negotiate. Default: all four.
	Versions []string `yaml:"versions"`
	Identity Identity `yaml:"identity"`
	// Access, if set, is checked at every connection on top of the client's own rule.
	Access *frontend.AccessRule `yaml:"access"`
	// AllowRebind lets 9P2000.L.Z's Trebind through on a route with an aname. Trebind binds a
	// fid by inode number, so it can reach outside the attach root unless the backend checks.
	AllowRebind bool `yaml:"allow_rebind"`
	// MaxMsize caps the negotiated message size. Default 1 MiB.
	MaxMsize uint32 `yaml:"max_msize"`
	// MaxConnsPerUser caps one user's open connections on this route. Default 16.
	MaxConnsPerUser int `yaml:"max_conns_per_user"`
	// Origins are extra browser origins (host patterns) allowed to connect. Same-origin is
	// always allowed, and clients that send no Origin header (not browsers) are unaffected.
	Origins []string `yaml:"origins"`
}

// Identity is who the backend sees. Templates may use {username} and {user_id}.
type Identity struct {
	Uname string  `yaml:"uname"` // default "{username}"
	Uid   *uint32 `yaml:"uid"`   // n_uname for .u and .L, and the 9P-Uid header
	Aname string  `yaml:"aname"` // if set, replaces the client's attach name
}

type file struct {
	Gateway Config `yaml:"gateway"`
}

// LoadConfig reads the gateway key from the config file's contents. audience maps a resource
// ID to its audience, or "" if there's no such resource.
func LoadConfig(raw []byte, audience func(id string) string) (*Config, error) {
	var f file
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse gateway config: %w", err)
	}
	c := &f.Gateway
	paths := map[string]bool{}
	for i := range c.Routes {
		r := &c.Routes[i]
		name := fmt.Sprintf("gateway.routes[%d]", i)
		aud := audience(r.Resource)
		if aud == "" {
			return nil, fmt.Errorf("%s: resource %q is not in oidc.resources", name, r.Resource)
		}
		u, err := url.Parse(aud)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if r.Path == "" {
			r.Path = u.Path
		}
		r.Path = "/" + strings.Trim(r.Path, "/")
		if r.Path != "/"+strings.Trim(u.Path, "/") {
			return nil, fmt.Errorf("%s: path %s doesn't match the resource audience %s", name, r.Path, aud)
		}
		if r.Path == "/" || strings.ContainsAny(r.Path, "{}") {
			return nil, fmt.Errorf("%s: invalid path %q", name, r.Path)
		}
		if paths[r.Path] {
			return nil, fmt.Errorf("%s: path %s is used twice", name, r.Path)
		}
		paths[r.Path] = true
		if err := checkBackend(r.Backend); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if len(r.Versions) == 0 {
			r.Versions = slices.Clone(knownVersions)
		}
		for _, v := range r.Versions {
			if !slices.Contains(knownVersions, v) {
				return nil, fmt.Errorf("%s: unsupported version %q (want %s)", name, v, strings.Join(knownVersions, ", "))
			}
		}
		if r.Identity.Uname == "" {
			r.Identity.Uname = "{username}"
		}
		for _, t := range []string{r.Identity.Uname, r.Identity.Aname} {
			if err := checkTemplate(t); err != nil {
				return nil, fmt.Errorf("%s.identity: %w", name, err)
			}
		}
		if r.Access != nil {
			if err := r.Access.Validate(); err != nil {
				return nil, fmt.Errorf("%s.access: %w", name, err)
			}
		}
		if r.MaxMsize == 0 {
			r.MaxMsize = 1 << 20
		}
		if r.MaxMsize < 4096 || r.MaxMsize > 16<<20 {
			return nil, fmt.Errorf("%s: max_msize must be between 4096 and 16 MiB", name)
		}
		if r.MaxConnsPerUser == 0 {
			r.MaxConnsPerUser = 16
		}
	}
	return c, nil
}

func checkBackend(b string) error {
	switch {
	case strings.HasPrefix(b, "tcp!"):
		if parts := strings.Split(b, "!"); len(parts) != 3 || parts[1] == "" || parts[2] == "" {
			return fmt.Errorf("backend %q: want tcp!host!port", b)
		}
	case strings.HasPrefix(b, "unix!"):
		if len(b) == len("unix!") {
			return fmt.Errorf("backend %q: want unix!path", b)
		}
	case strings.HasPrefix(b, "ws://"), strings.HasPrefix(b, "wss://"):
		if u, err := url.Parse(b); err != nil || u.Host == "" {
			return fmt.Errorf("backend %q: invalid URL", b)
		}
	case b == "":
		return errors.New("backend is required")
	default:
		return fmt.Errorf("backend %q: want tcp!host!port, unix!path, ws:// or wss://", b)
	}
	return nil
}

func checkTemplate(t string) error {
	rest := strings.NewReplacer("{username}", "", "{user_id}", "").Replace(t)
	if strings.ContainsAny(rest, "{}") {
		return fmt.Errorf("template %q: only {username} and {user_id} are known", t)
	}
	return nil
}

// expand fills in a template. It refuses values that could change an aname's meaning.
func expand(t, username, userID string) (string, error) {
	for _, v := range []struct{ name, val string }{{"{username}", username}, {"{user_id}", userID}} {
		if !strings.Contains(t, v.name) {
			continue
		}
		if v.val == "" || v.val == "." || v.val == ".." || strings.ContainsAny(v.val, "/\x00") {
			return "", fmt.Errorf("the account has no usable %s", strings.Trim(v.name, "{}"))
		}
		t = strings.ReplaceAll(t, v.name, v.val)
	}
	return t, nil
}
