package oidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// approvedDevice runs the device flow for client as alice and returns the token response.
func (e *env) approvedDevice(client string) map[string]any {
	e.t.Helper()
	auth := e.startDevice(client)
	if status, body := e.decide("alice", auth, "approve"); status != 200 {
		e.t.Fatalf("approve: %d %s", status, body)
	}
	s, tok := e.poll(client, auth["device_code"].(string), nil)
	if s != 200 {
		e.t.Fatalf("poll: %d %v", s, tok)
	}
	return tok
}

func resourceAuth(secret string) http.Header {
	req, _ := http.NewRequest("GET", "/", nil)
	req.SetBasicAuth("files", secret)
	return req.Header
}

func TestIntrospectAndAuthenticate(t *testing.T) {
	e := newDeviceEnv(t)
	tok := e.approvedDevice("hankfs")
	at := tok["access_token"].(string)
	did := jwtClaims(t, at)["did"].(string)

	if s, _ := e.post("/oidc/introspect", url.Values{"token": {at}}, resourceAuth("wrong-secret-xxxxxxx")); s != 401 {
		t.Errorf("bad resource secret: %d", s)
	}
	s, b := e.post("/oidc/introspect", url.Values{"token": {at}}, resourceAuth("files-resource-secret-123"))
	if s != 200 || b["active"] != true || b["sub"] != "alice" || b["did"] != did || b["username"] != "alice" ||
		b["aud"] != "wss://files.test/9p/files" || b["client_id"] != "hankfs" {
		t.Errorf("introspect: %d %v", s, b)
	}
	// Form credentials work too; an ID token is not an access token.
	if s, b := e.post("/oidc/introspect", url.Values{"token": {tok["id_token"].(string)}, "client_id": {"files"},
		"client_secret": {"files-resource-secret-123"}}, nil); s != 200 || b["active"] != false {
		t.Errorf("introspect id token: %d %v", s, b)
	}

	pr, err := e.prov.Authenticate(context.Background(), at, "wss://files.test/9p/files")
	if err != nil || pr.UserID != "alice" || pr.DeviceID != did || pr.Username != "alice" {
		t.Fatalf("Authenticate: %v %+v", err, pr)
	}
	if _, err := e.prov.Authenticate(context.Background(), at, "wss://other.test/"); !IsInvalidToken(err) {
		t.Errorf("wrong audience: %v", err)
	}

	// Tickets are single use and bound to the audience.
	ticket, err := e.prov.IssueTicket(context.Background(), pr, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.prov.RedeemTicket(context.Background(), ticket, "wss://other.test/"); !IsInvalidToken(err) {
		t.Errorf("ticket for another audience: %v", err)
	}
	if got, err := e.prov.RedeemTicket(context.Background(), ticket, pr.Audience); err != nil || got.DeviceID != did {
		t.Errorf("redeem: %v %+v", err, got)
	}
	if _, err := e.prov.RedeemTicket(context.Background(), ticket, pr.Audience); !IsInvalidToken(err) {
		t.Errorf("second redeem: %v", err)
	}

	// Revoking the device (RFC 7009 with its refresh token) deactivates its access tokens.
	var hooked []string
	e.prov.OnRevoke(func(ids []string) { hooked = append(hooked, ids...) })
	ticket2, _ := e.prov.IssueTicket(context.Background(), pr, time.Minute)
	if s, _ := e.post("/oidc/revoke", url.Values{"token": {tok["refresh_token"].(string)}, "client_id": {"cli"}}, nil); s != 200 {
		t.Errorf("revoke by another client: %d", s)
	}
	if _, err := e.prov.Authenticate(context.Background(), at, pr.Audience); err != nil {
		t.Errorf("another client's revoke took effect: %v", err)
	}
	if s, _ := e.post("/oidc/revoke", url.Values{"token": {tok["refresh_token"].(string)}, "client_id": {"hankfs"}}, nil); s != 200 {
		t.Errorf("revoke: %d", s)
	}
	if len(hooked) != 1 || hooked[0] != did {
		t.Errorf("revoke hook: %v", hooked)
	}
	if s, b := e.post("/oidc/introspect", url.Values{"token": {at}}, resourceAuth("files-resource-secret-123")); s != 200 || b["active"] != false {
		t.Errorf("introspect after revoke: %d %v", s, b)
	}
	if _, err := e.prov.RedeemTicket(context.Background(), ticket2, pr.Audience); !IsInvalidToken(err) {
		t.Errorf("ticket after revoke: %v", err)
	}
	if s, _ := e.post("/oidc/revoke", url.Values{"token": {"nonsense"}, "client_id": {"hankfs"}}, nil); s != 200 {
		t.Errorf("unknown token: %d", s)
	}

	// The revocations feed lists the device to resources.
	req, _ := http.NewRequest("GET", "http://idp.test/oidc/revocations?since="+url.QueryEscape(e.now.Add(-time.Hour).Format(time.RFC3339Nano)), nil)
	req.SetBasicAuth("files", "files-resource-secret-123")
	res, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var feed struct {
		Revocations []map[string]any `json:"revocations"`
		Cursor      string           `json:"cursor"`
	}
	_ = json.NewDecoder(res.Body).Decode(&feed)
	if res.StatusCode != 200 || len(feed.Revocations) != 1 || feed.Cursor == "" {
		t.Errorf("revocations: %d %+v", res.StatusCode, feed)
	} else if b, _ := json.Marshal(feed.Revocations[0]); !strings.Contains(string(b), did) {
		t.Errorf("revocations entry: %s", b)
	}
	if res := e.get("http://idp.test/oidc/revocations"); res.StatusCode != 401 {
		t.Errorf("revocations without credentials: %d", res.StatusCode)
	}
}

func TestResourceMetadata(t *testing.T) {
	e := newDeviceEnv(t)
	e.prov.cfg.Resources = append(e.prov.cfg.Resources, Resource{ID: "local", Audience: "wss://idp.test/9p/local/"})
	e.prov.cfg.Clients[len(e.prov.cfg.Clients)-1].Resources = []string{"local"}

	res := e.get("http://idp.test/.well-known/oauth-protected-resource/9p/local")
	var doc map[string]any
	_ = json.NewDecoder(res.Body).Decode(&doc)
	if res.StatusCode != 200 || doc["resource"] != "wss://idp.test/9p/local/" || doc["hankoid_device_client_id"] != "cli" ||
		toStrings(doc["authorization_servers"])[0] != "http://idp.test/oidc" {
		t.Errorf("metadata: %d %v", res.StatusCode, doc)
	}
	// files lives on another host, so hankoid doesn't serve its metadata.
	if res := e.get("http://idp.test/.well-known/oauth-protected-resource/9p/files"); res.StatusCode != 404 {
		t.Errorf("foreign resource: %d", res.StatusCode)
	}
	if got := e.prov.ResourceMetadataURL("wss://idp.test/9p/local/"); got != "https://idp.test/.well-known/oauth-protected-resource/9p/local" {
		t.Errorf("ResourceMetadataURL: %s", got)
	}
}

func TestAccountDevices(t *testing.T) {
	e := newDeviceEnv(t)
	if res := e.get("http://idp.test/account/devices"); res.StatusCode != 302 || !strings.HasPrefix(res.Header.Get("Location"), "/signin") {
		t.Errorf("signed out: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	tok1 := e.approvedDevice("hankfs")
	e.now = e.now.Add(time.Second)
	e.approvedDevice("cli")
	did1 := jwtClaims(t, tok1["access_token"].(string))["did"].(string)
	var hooked []string
	e.prov.OnRevoke(func(ids []string) { hooked = append(hooked, ids...) })

	res := e.get("http://idp.test/account/api/devices")
	var list []map[string]any
	_ = json.NewDecoder(res.Body).Decode(&list)
	if res.StatusCode != 200 || len(list) != 2 {
		t.Fatalf("api list: %d %v", res.StatusCode, list)
	}

	// Another user sees none of alice's devices and can't remove them.
	e.signIn("bob")
	res = e.get("http://idp.test/account/api/devices")
	_ = json.NewDecoder(res.Body).Decode(&list)
	if len(list) != 0 {
		t.Errorf("bob sees %v", list)
	}
	del := func(id string, ui bool) int {
		req, _ := http.NewRequest("DELETE", "http://idp.test/account/api/devices/"+id, nil)
		if ui {
			req.Header.Set("X-Account-UI", "1")
		}
		res, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode
	}
	if s := del(did1, true); s != 404 {
		t.Errorf("bob removing alice's device: %d", s)
	}

	e.signIn("alice")
	if s := del(did1, false); s != 403 {
		t.Errorf("delete without UI header: %d", s)
	}
	if s := del(did1, true); s != 204 || len(hooked) != 1 || hooked[0] != did1 {
		t.Errorf("delete: %d %v", s, hooked)
	}

	// The page lists the remaining device and removes all with a verified form.
	res = e.get("http://idp.test/account/devices")
	page, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.Contains(string(page), "jeff-laptop") || strings.Count(string(page), `name="id"`) != 1 {
		t.Fatalf("page: %d %s", res.StatusCode, page)
	}
	csrf := strings.SplitN(strings.SplitN(string(page), `name="csrf" value="`, 2)[1], `"`, 2)[0]
	submit := func(csrf, origin string) int {
		req, _ := http.NewRequest("POST", "http://idp.test/account/devices", strings.NewReader(url.Values{"csrf": {csrf}, "action": {"remove_all"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		res, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode
	}
	if s := submit(csrf, "http://evil.test"); s != 403 {
		t.Errorf("cross-origin post: %d", s)
	}
	if s := submit("forged", "http://idp.test"); s != 403 {
		t.Errorf("forged csrf: %d", s)
	}
	if s := submit(csrf, "http://idp.test"); s != 303 || len(hooked) != 2 {
		t.Errorf("remove all: %d %v", s, hooked)
	}
	res = e.get("http://idp.test/account/api/devices")
	_ = json.NewDecoder(res.Body).Decode(&list)
	if len(list) != 0 {
		t.Errorf("devices left: %v", list)
	}
}

func TestAdminDevices(t *testing.T) {
	e := newDeviceEnv(t)
	tok := e.approvedDevice("hankfs")
	did := jwtClaims(t, tok["access_token"].(string))["did"].(string)
	h := e.prov.AdminDevicesHandler()

	rec := doHandler(h, "GET", "/admin/hankoid/devices?user_id=alice", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), did) || !strings.Contains(rec.Body.String(), "Hank filesystem") {
		t.Errorf("admin list: %d %s", rec.Code, rec.Body)
	}
	if rec := doHandler(h, "DELETE", "/admin/hankoid/devices/"+did, nil); rec.Code != 403 {
		t.Errorf("admin delete without header: %d", rec.Code)
	}
	if rec := doHandler(h, "DELETE", "/admin/hankoid/devices/"+did, http.Header{"X-Admin-Ui": {"1"}}); rec.Code != 204 {
		t.Errorf("admin delete: %d %s", rec.Code, rec.Body)
	}
	if ok, _ := e.prov.devices.DeviceActive(context.Background(), did); ok {
		t.Error("device still active")
	}
}

func doHandler(h http.Handler, method, target string, header http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	for k, v := range header {
		r.Header[k] = v
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}
