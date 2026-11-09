package oidc

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

const deviceTestConfig = testConfig + `    - id: hankfs
      name: Hank filesystem
      token_endpoint_auth_method: none
      grant_types: [device_code]
      resources: [files]
      access:
        organization: Mail
    - id: cli
      token_endpoint_auth_method: none
      grant_types: [device_code]
      access: {any_user: true}
  resources:
    - id: files
      audience: wss://files.test/9p/files
      secret: files-resource-secret-123
  store: postgres
database:
  host: db
`

// sessionIssued is when the fake Hanko's sessions were signed in.
var sessionIssued = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func newDeviceEnv(t *testing.T) *env {
	t.Helper()
	ds, _ := testDeviceStore(t)
	e := newEnvConfig(t, deviceTestConfig, NewPostgresCodes(testPool(t)), ds)
	e.now = sessionIssued.Add(time.Minute) // a fresh sign-in
	return e
}

func (e *env) post(path string, form url.Values, header http.Header) (int, map[string]any) {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "http://idp.test"+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header[k] = v
	}
	res, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res.StatusCode, body
}

func (e *env) startDevice(client string) map[string]any {
	e.t.Helper()
	status, body := e.post("/oidc/device_authorization", url.Values{"client_id": {client}, "scope": {"openid profile offline_access"},
		"device_name": {"jeff-laptop\x00"}}, nil)
	if status != 200 {
		e.t.Fatalf("device_authorization: %d %v", status, body)
	}
	return body
}

func (e *env) poll(client, deviceCode string, extra url.Values) (int, map[string]any) {
	f := url.Values{"grant_type": {GrantDeviceCode}, "device_code": {deviceCode}, "client_id": {client}}
	for k, v := range extra {
		f[k] = v
	}
	return e.post("/oidc/token", f, nil)
}

// decide signs the browser in as user, opens the verification link and presses a button.
func (e *env) decide(user string, auth map[string]any, action string) (int, string) {
	e.t.Helper()
	e.signIn(user)
	res := e.get(auth["verification_uri_complete"].(string))
	page, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		e.t.Fatalf("confirm page: %d %s", res.StatusCode, page)
	}
	csrf := strings.SplitN(strings.SplitN(string(page), `name="csrf" value="`, 2)[1], `"`, 2)[0]
	code := strings.SplitN(strings.SplitN(string(page), `name="user_code" value="`, 2)[1], `"`, 2)[0]
	req, _ := http.NewRequest(http.MethodPost, "http://idp.test/device", strings.NewReader(url.Values{"csrf": {csrf}, "user_code": {code}, "action": {action}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://idp.test")
	res, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func jwtClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func TestDeviceFlow(t *testing.T) {
	e := newDeviceEnv(t)
	var revoked []string
	e.prov.OnRevoke(func(ids []string) { revoked = append(revoked, ids...) })

	res := e.get("http://idp.test/oidc/.well-known/openid-configuration")
	var disco map[string]any
	_ = json.NewDecoder(res.Body).Decode(&disco)
	if disco["device_authorization_endpoint"] != "http://idp.test/oidc/device_authorization" ||
		!strings.Contains(strings.Join(toStrings(disco["grant_types_supported"]), " "), GrantDeviceCode) {
		t.Errorf("discovery: %v", disco)
	}

	auth := e.startDevice("hankfs")
	if auth["verification_uri"] != "http://idp.test/device" || auth["interval"] != float64(5) || auth["expires_in"] != float64(600) ||
		len(auth["user_code"].(string)) != 9 {
		t.Fatalf("device_authorization response: %v", auth)
	}
	dc := auth["device_code"].(string)
	if s, b := e.poll("hankfs", dc, nil); s != 400 || b["error"] != "authorization_pending" {
		t.Errorf("first poll: %d %v", s, b)
	}
	if s, b := e.poll("hankfs", dc, nil); s != 400 || b["error"] != "slow_down" {
		t.Errorf("fast poll: %d %v", s, b)
	}

	// The confirm page names the client and the device, and approving works.
	e.signIn("alice")
	res = e.get(auth["verification_uri_complete"].(string))
	page, _ := io.ReadAll(res.Body)
	for _, want := range []string{"Hank filesystem", "jeff-laptop", auth["user_code"].(string), "Stay signed in", "192.0.2.1"} {
		if !strings.Contains(string(page), want) {
			t.Errorf("confirm page lacks %q", want)
		}
	}
	if status, body := e.decide("alice", auth, "approve"); status != 200 || !strings.Contains(body, "Device approved") {
		t.Fatalf("approve: %d %s", status, body)
	}
	e.now = e.now.Add(11 * time.Second)
	s, tok := e.poll("hankfs", dc, nil)
	if s != 200 || tok["refresh_token"] == nil || tok["id_token"] == nil {
		t.Fatalf("approved poll: %d %v", s, tok)
	}
	at := jwtClaims(t, tok["access_token"].(string))
	did, _ := at["did"].(string)
	if aud := toStrings(at["aud"]); len(aud) != 1 || aud[0] != "wss://files.test/9p/files" || did == "" || at["preferred_username"] != "alice" || at["sub"] != "alice" {
		t.Errorf("access token claims: %v", at)
	}
	if s, b := e.poll("hankfs", dc, nil); s != 400 || b["error"] != "invalid_grant" {
		t.Errorf("poll after success: %d %v", s, b)
	}

	// Refresh rotates; a quick replay of the old token is a concurrent refresh; a late one revokes.
	rt0 := tok["refresh_token"].(string)
	refresh := func(rt string) (int, map[string]any) {
		return e.post("/oidc/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"hankfs"},
			"resource": {"wss://files.test/9p/files"}}, nil)
	}
	s, t1 := refresh(rt0)
	if s != 200 || t1["refresh_token"] == rt0 || jwtClaims(t, t1["access_token"].(string))["did"] != did {
		t.Fatalf("refresh: %d %v", s, t1)
	}
	e.now = e.now.Add(5 * time.Second)
	if s, b := refresh(rt0); s != 200 {
		t.Errorf("refresh inside the grace window: %d %v", s, b)
	}
	if s, b := e.post("/oidc/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt0}, "client_id": {"hankfs"},
		"resource": {"wss://elsewhere.test"}}, nil); s != 400 || b["error"] != "invalid_target" {
		t.Errorf("unknown resource: %d %v", s, b)
	}
	e.now = e.now.Add(time.Minute)
	if s, b := refresh(rt0); s != 400 || b["error"] != "invalid_grant" {
		t.Errorf("late replay: %d %v", s, b)
	}
	if len(revoked) != 1 || revoked[0] != did {
		t.Errorf("revoke hook: %v", revoked)
	}
	if s, _ := refresh(t1["refresh_token"].(string)); s != 400 {
		t.Error("the device's newest token still works after a reuse revocation")
	}
}

func toStrings(v any) []string {
	var out []string
	switch v := v.(type) {
	case []any:
		for _, x := range v {
			s, _ := x.(string)
			out = append(out, s)
		}
	case string:
		out = []string{v}
	}
	return out
}

func TestDeviceDenials(t *testing.T) {
	e := newDeviceEnv(t)

	// Denied by the user.
	auth := e.startDevice("hankfs")
	if status, body := e.decide("alice", auth, "deny"); status != 200 || !strings.Contains(body, "denied") {
		t.Fatalf("deny: %d %s", status, body)
	}
	if s, b := e.poll("hankfs", auth["device_code"].(string), nil); b["error"] != "access_denied" {
		t.Errorf("poll after deny: %d %v", s, b)
	}

	// bob isn't in the client's organization: approving tells the device no.
	auth = e.startDevice("hankfs")
	if status, body := e.decide("bob", auth, "approve"); status != 403 || !strings.Contains(body, "may not use Hank filesystem") {
		t.Errorf("bob approves: %d %s", status, body)
	}
	if _, b := e.poll("hankfs", auth["device_code"].(string), nil); b["error"] != "access_denied" {
		t.Errorf("poll after a refused approval: %v", b)
	}

	// Expired.
	auth = e.startDevice("hankfs")
	e.now = e.now.Add(11 * time.Minute)
	if _, b := e.poll("hankfs", auth["device_code"].(string), nil); b["error"] != "expired_token" {
		t.Errorf("expired: %v", b)
	}

	// A stale sign-in is sent to /signin?fresh=1 with min_auth_time; coming back stale is refused.
	auth = e.startDevice("hankfs")
	e.signIn("alice")
	res := e.get(auth["verification_uri_complete"].(string))
	loc, _ := url.Parse(res.Header.Get("Location"))
	if loc.Path != "/signin" || loc.Query().Get("fresh") != "1" || !strings.Contains(loc.Query().Get("next"), "min_auth_time=") {
		t.Fatalf("stale session: %d %s", res.StatusCode, loc)
	}
	if res := e.get("http://idp.test" + loc.Query().Get("next")); res.StatusCode != 403 {
		t.Errorf("stale session coming back: %d", res.StatusCode)
	}
	// Not signed in at all: plain /signin.
	e.client.Jar, _ = newJar()
	if res := e.get("http://idp.test/device"); !strings.HasPrefix(res.Header.Get("Location"), "/signin?next=%2Fdevice") {
		t.Errorf("signed out: %s", res.Header.Get("Location"))
	}
}

func TestDeviceCodeEntryLimits(t *testing.T) {
	e := newDeviceEnv(t)
	e.signIn("alice")
	if res := e.get("http://idp.test/device?user_code=AAAA-0000"); res.StatusCode != 400 {
		t.Errorf("malformed code: %d", res.StatusCode)
	}
	for i := range codeSessionBurst {
		if res := e.get("http://idp.test/device?user_code=BBBB-BBBB"); res.StatusCode != 400 {
			t.Fatalf("wrong code %d: %d", i, res.StatusCode)
		}
	}
	if res := e.get("http://idp.test/device?user_code=BBBB-BBBB"); res.StatusCode != 429 {
		t.Errorf("after %d wrong codes: %d", codeSessionBurst, res.StatusCode)
	}
	// The confirm POST needs the double-submit token and a same-origin request.
	s, _ := e.post("/device", url.Values{"user_code": {"BBBB-BBBB"}, "action": {"approve"}, "csrf": {"x"}}, http.Header{"Origin": {"http://idp.test"}})
	if s != 403 {
		t.Errorf("forged confirm: %d", s)
	}
}

func TestDeviceClientRules(t *testing.T) {
	e := newDeviceEnv(t)
	// A public client must not send a secret; a web client can't use the device grant; the
	// device client can't use authorize.
	if s, b := e.post("/oidc/device_authorization", url.Values{"client_id": {"hankfs"}, "client_secret": {"x"}}, nil); s != 401 || b["error"] != "invalid_client" {
		t.Errorf("public client with a secret: %d %v", s, b)
	}
	if s, b := e.post("/oidc/device_authorization", url.Values{"client_id": {"app"}, "client_secret": {"s3cret-app-client-secret"}}, nil); s != 400 || b["error"] != "unauthorized_client" {
		t.Errorf("web client device_authorization: %d %v", s, b)
	}
	if s, b := e.exchange(url.Values{"grant_type": {GrantDeviceCode}, "device_code": {"x"}}, "app", "s3cret-app-client-secret"); s != 400 || b["error"] != "unauthorized_client" {
		t.Errorf("web client device_code: %d %v", s, b)
	}
	if res := e.get(authorizeURL("hankfs", "https://app.test/callback", nil)); res.StatusCode != 400 {
		t.Errorf("device client at authorize: %d", res.StatusCode)
	}
	if s, b := e.post("/oidc/device_authorization", url.Values{"client_id": {"hankfs"}, "resource": {"wss://nope.test"}}, nil); s != 400 || b["error"] != "invalid_target" {
		t.Errorf("unknown resource: %d %v", s, b)
	}

	// A client with no resources gets userinfo tokens; userinfo stops once the device is revoked.
	auth := e.startDevice("cli")
	e.decide("alice", auth, "approve")
	e.now = e.now.Add(6 * time.Second)
	s, tok := e.poll("cli", auth["device_code"].(string), nil)
	if s != 200 {
		t.Fatalf("cli poll: %d %v", s, tok)
	}
	userinfo := func() int {
		req, _ := http.NewRequest(http.MethodGet, "http://idp.test/oidc/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
		res, _ := e.client.Do(req)
		return res.StatusCode
	}
	if s := userinfo(); s != 200 {
		t.Errorf("userinfo with a device token: %d", s)
	}
	did := jwtClaims(t, tok["access_token"].(string))["did"].(string)
	if ok, _ := e.prov.devices.RevokeDevice(t.Context(), did, "alice", "user"); !ok {
		t.Fatal("revoke failed")
	}
	if s := userinfo(); s != 401 {
		t.Errorf("userinfo after revoke: %d", s)
	}
}

func newJar() (http.CookieJar, error) { return cookiejar.New(nil) }
