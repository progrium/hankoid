package oidc

import (
	"strings"
	"testing"
	"time"
)

const deviceBase = `secrets:
  keys: [0123456789abcdef0123456789abcdef]
database:
  host: db
oidc:
  store: postgres
  resources:
    - id: files
      audience: wss://files.example/9p/files
      secret: resource-secret-0123456789
  clients:
    - id: hankfs
      token_endpoint_auth_method: none
      grant_types: [device_code]
      resources: [files]
      access: {any_user: true}
`

func TestDeviceConfig(t *testing.T) {
	c, err := LoadConfig([]byte(deviceBase), "https://idp.example", "")
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	cl := c.Client("hankfs")
	if !cl.IsDevice() || !cl.Public() || cl.AllowsGrant(GrantAuthorizationCode) || !cl.AllowsScope("offline_access") ||
		cl.RefreshTokenIdleTTL != 30*24*time.Hour || c.Device.CodeTTL != 10*time.Minute || c.Device.Interval != 5*time.Second {
		t.Errorf("defaults: %+v %+v", cl, c.Device)
	}
	if !c.DeviceEnabled() || c.ResourceByAudience("wss://files.example/9p/files").ID != "files" {
		t.Error("lookups")
	}
	bad := map[string]string{
		"memory store":            strings.Replace(deviceBase, "store: postgres", "store: memory", 1),
		"none with auth code":     strings.Replace(deviceBase, "[device_code]", "[device_code, authorization_code]", 1),
		"none with secret":        strings.Replace(deviceBase, "      grant_types", "      secret: a-strong-client-secret\n      grant_types", 1),
		"unknown grant":           strings.Replace(deviceBase, "[device_code]", "[device_code, password]", 1),
		"unknown resource":        strings.Replace(deviceBase, "resources: [files]", "resources: [nope]", 1),
		"http audience":           strings.Replace(deviceBase, "wss://files.example/9p/files", "ws://files.example/9p/files", 1),
		"audience with query":     strings.Replace(deviceBase, "wss://files.example/9p/files", "wss://files.example/9p?x=1", 1),
		"short resource secret":   strings.Replace(deviceBase, "resource-secret-0123456789", "short", 1),
		"bad auth method":         strings.Replace(deviceBase, "auth_method: none", "auth_method: private_key_jwt", 1),
		"offline on a web client": deviceBase + "    - id: web\n      secret: a-strong-client-secret\n      redirect_uris: [https://a.example/cb]\n      scopes: [openid, offline_access]\n      access: {any_user: true}\n",
		"duplicate audience":      strings.Replace(deviceBase, "  clients:", "    - id: again\n      audience: wss://files.example/9p/files\n  clients:", 1),
	}
	for name, y := range bad {
		if _, err := LoadConfig([]byte(y), "https://idp.example", ""); err == nil {
			t.Errorf("%s should be invalid", name)
		}
	}
	// A confidential client can use both grants; device-only clients need no redirect_uris.
	both := strings.Replace(strings.Replace(deviceBase, "token_endpoint_auth_method: none", "secret: a-strong-client-secret\n      redirect_uris: [https://a.example/cb]", 1),
		"[device_code]", "[authorization_code, device_code]", 1)
	if _, err := LoadConfig([]byte(both), "https://idp.example", ""); err != nil {
		t.Errorf("confidential client with both grants: %v", err)
	}
	t.Setenv("OIDC_RESOURCES_FILES_SECRET", "from-env-0123456789")
	if c, _ := LoadConfig([]byte(deviceBase), "https://idp.example", ""); c.Resource("files").Secret != "from-env-0123456789" {
		t.Error("resource secret from env")
	}
}
