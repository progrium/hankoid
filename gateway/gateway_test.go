package gateway

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/progrium/hankoid/frontend"
	"github.com/progrium/hankoid/oidc"
)

const aud = "wss://files.test/9p/files"

// fakeProvider accepts tokens of the form "tok:USER:DEVICE".
type fakeProvider struct {
	mu      sync.Mutex
	hooks   []func([]string)
	tickets map[string]*oidc.Principal
	revoked []oidc.Revocation
	orgs    map[string]string
}

func (f *fakeProvider) Authenticate(_ context.Context, raw, audience string) (*oidc.Principal, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 3 || parts[0] != "tok" || audience != aud {
		return nil, oidc.ErrInvalidToken
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.revoked {
		if r.DeviceID == parts[2] {
			return nil, oidc.ErrInvalidToken
		}
	}
	return &oidc.Principal{UserID: "id-" + parts[1], Username: parts[1], DeviceID: parts[2], Audience: audience}, nil
}

func (f *fakeProvider) IssueTicket(_ context.Context, pr *oidc.Principal, _ time.Duration) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := fmt.Sprintf("tk%d", len(f.tickets))
	f.tickets[t] = pr
	return t, nil
}

func (f *fakeProvider) RedeemTicket(_ context.Context, t, audience string) (*oidc.Principal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pr := f.tickets[t]
	delete(f.tickets, t)
	if pr == nil || pr.Audience != audience {
		return nil, oidc.ErrInvalidToken
	}
	return pr, nil
}

func (f *fakeProvider) UserSession(_ context.Context, id string) (*frontend.Session, error) {
	s := &frontend.Session{UserID: id}
	if org := f.orgs[id]; org != "" {
		s.Organizations = []frontend.Organization{{Name: org}}
	}
	return s, nil
}

func (f *fakeProvider) OnRevoke(fn func([]string)) { f.hooks = append(f.hooks, fn) }

func (f *fakeProvider) RevokedSince(_ context.Context, since time.Time) ([]oidc.Revocation, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revoked, time.Now(), nil
}

func (f *fakeProvider) ResourceMetadataURL(string) string {
	return "https://files.test/.well-known/oauth-protected-resource/9p/files"
}

func (f *fakeProvider) revoke(device string) {
	f.mu.Lock()
	f.revoked = append(f.revoked, oidc.Revocation{DeviceID: device})
	hooks := f.hooks
	f.mu.Unlock()
	for _, h := range hooks {
		h([]string{device})
	}
}

// backend is a fake 9P server: it answers Tversion with its own version, Tattach with Rattach,
// and anything else with an Rlerror, and records what it got.
type backend struct {
	ln      net.Listener
	version string
	mu      sync.Mutex
	got     [][]byte
}

func newBackend(t *testing.T, version string) *backend {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &backend{ln: ln, version: version}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go b.serve(c)
		}
	}()
	return b
}

func (b *backend) addr() string {
	host, port, _ := net.SplitHostPort(b.ln.Addr().String())
	return "tcp!" + host + "!" + port
}

func (b *backend) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		m, err := readMsg(r, 1<<20)
		if err != nil {
			return
		}
		b.mu.Lock()
		b.got = append(b.got, m)
		b.mu.Unlock()
		var reply []byte
		switch msgType(m) {
		case tTversion:
			v, _ := parseVersion(m)
			v.version = b.version
			reply = versionMsg(tRversion, msgTag(m), v)
		case tTattach:
			reply = newMsg(tTattach+1, msgTag(m)).u32(0).u32(0).u32(0).finish()[:headerSz+13]
			binary.LittleEndian.PutUint32(reply, uint32(len(reply)))
		default:
			reply = newMsg(tRlerror, msgTag(m)).u32(38).finish()
		}
		if _, err := c.Write(reply); err != nil {
			return
		}
	}
}

func (b *backend) last() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.got) == 0 {
		return nil
	}
	return b.got[len(b.got)-1]
}

type testEnv struct {
	t    *testing.T
	prov *fakeProvider
	gw   *Gateway
	srv  *httptest.Server
	be   *backend
}

func newTestEnv(t *testing.T, cfgYAML, backendVersion string) *testEnv {
	t.Helper()
	be := newBackend(t, backendVersion)
	cfg, err := LoadConfig([]byte(strings.ReplaceAll(cfgYAML, "BACKEND", be.addr())), func(id string) string {
		if id == "files" {
			return aud
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	prov := &fakeProvider{tickets: map[string]*oidc.Principal{}, orgs: map[string]string{"id-alice": "staff"}}
	gw := New(cfg, prov, func(string) string { return aud })
	mux := http.NewServeMux()
	for p, h := range gw.Handlers() {
		mux.Handle(p, h)
	}
	srv := httptest.NewUnstartedServer(mux)
	// Like the frontend's server: short timeouts that a WebSocket must outlive.
	srv.Config.ReadTimeout, srv.Config.WriteTimeout = 300*time.Millisecond, 300*time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)
	return &testEnv{t: t, prov: prov, gw: gw, srv: srv, be: be}
}

const baseConfig = `
gateway:
  routes:
    - resource: files
      backend: BACKEND
      versions: [9P2000.L.Z, 9P2000.L, 9P2000]
      identity:
        uid: 1000
        aname: "/users/{username}"
      max_conns_per_user: 2
`

type client struct {
	t   *testing.T
	ws  *websocket.Conn
	res *http.Response
}

func (e *testEnv) dial(token, query string) (*client, *http.Response, error) {
	h := http.Header{}
	if token != "" {
		h.Set("Authorization", "Bearer "+token)
	}
	u := strings.Replace(e.srv.URL, "http", "ws", 1) + "/9p/files" + query
	ws, res, err := websocket.Dial(context.Background(), u, &websocket.DialOptions{HTTPHeader: h, Subprotocols: []string{"9p"}})
	if err != nil {
		return nil, res, err
	}
	e.t.Cleanup(func() { ws.CloseNow() })
	return &client{t: e.t, ws: ws, res: res}, res, nil
}

func (c *client) rpc(m []byte) []byte {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.ws.Write(ctx, websocket.MessageBinary, m); err != nil {
		c.t.Fatal(err)
	}
	_, b, err := c.ws.Read(ctx)
	if err != nil {
		c.t.Fatal(err)
	}
	return b
}

func (c *client) version(v string) version {
	c.t.Helper()
	r := c.rpc(versionMsg(tTversion, noTag, version{msize: 1 << 24, version: v}))
	got, err := parseVersion(r)
	if err != nil || msgType(r) != tRversion {
		c.t.Fatalf("Rversion: %v %x", err, r)
	}
	return got
}

func TestAttachRewrite(t *testing.T) {
	e := newTestEnv(t, baseConfig, V9P2000L)
	c, res, err := e.dial("tok:alice:dev1", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Header.Get("9P-User") != "alice" || res.Header.Get("9P-Uid") != "1000" || c.ws.Subprotocol() != "9p" {
		t.Errorf("handshake headers: %v %q", res.Header, c.ws.Subprotocol())
	}
	// The client asks for .L.Z; the backend answers .L, which the route allows.
	if v := c.version(V9P2000LZ); v.version != V9P2000L || v.msize != 1<<20 {
		t.Errorf("Rversion: %+v", v)
	}
	if v, _ := parseVersion(e.be.last()); v.version != V9P2000LZ || v.msize != 1<<20 {
		t.Errorf("backend got Tversion %+v", v)
	}
	// Tauth is refused locally, in the dialect's error form.
	if r := c.rpc(newMsg(tTauth, 1).u32(5).str("mallory").str("").u32(0).finish()); msgType(r) != tRlerror {
		t.Errorf("Tauth reply type %d", msgType(r))
	}
	// Tattach's identity comes from the route, whatever the client claims.
	r := c.rpc(attachMsg(2, attach{fid: 1, afid: 7, uname: "root", aname: "/", nUname: 0}, V9P2000L))
	if msgType(r) != tTattach+1 {
		t.Errorf("Rattach type %d", msgType(r))
	}
	a, err := parseAttach(e.be.last(), V9P2000L)
	if err != nil || a.fid != 1 || a.afid != noFid || a.uname != "alice" || a.aname != "/users/alice" || a.nUname != 1000 {
		t.Errorf("backend got Tattach %+v %v", a, err)
	}
	// Other messages pass through untouched.
	walk := newMsg(110, 3).u32(1).u32(2).finish()
	c.rpc(walk)
	if string(e.be.last()) != string(walk) {
		t.Errorf("Twalk changed: %x", e.be.last())
	}
	// The connection outlives the server's read and write timeouts.
	time.Sleep(500 * time.Millisecond)
	c.rpc(walk)
}

func TestVersions(t *testing.T) {
	e := newTestEnv(t, baseConfig, V9P2000)
	c, _, err := e.dial("tok:alice:dev1", "")
	if err != nil {
		t.Fatal(err)
	}
	if v := c.version("9P2000.u"); v.version != V9P2000 {
		t.Errorf(".u client: %+v", v)
	}
	if r := c.rpc(newMsg(tTauth, 1).u32(5).str("x").str("").finish()); msgType(r) != tRerror {
		t.Errorf("9P2000 Tauth reply type %d", msgType(r))
	}
	c.rpc(attachMsg(2, attach{fid: 1, afid: noFid, uname: "root", aname: "/"}, V9P2000))
	if a, err := parseAttach(e.be.last(), V9P2000); err != nil || a.uname != "alice" || a.aname != "/users/alice" {
		t.Errorf("9P2000 Tattach %+v %v", a, err)
	}
	if v := c.version("9P3000"); v.version != "unknown" {
		t.Errorf("unknown version: %+v", v)
	}
	// After a failed Tversion nothing else is accepted.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = c.ws.Write(ctx, websocket.MessageBinary, newMsg(110, 3).u32(1).u32(2).finish())
	if _, _, err := c.ws.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Errorf("message before version: %v", err)
	}
}

func TestBackendVersionNotAllowed(t *testing.T) {
	e := newTestEnv(t, strings.Replace(baseConfig, "[9P2000.L.Z, 9P2000.L, 9P2000]", "[9P2000.L.Z, 9P2000.L]", 1), V9P2000)
	c, _, err := e.dial("tok:alice:dev1", "")
	if err != nil {
		t.Fatal(err)
	}
	if v := c.version(V9P2000LZ); v.version != "unknown" {
		t.Errorf("backend answered 9P2000 on a .L-only route: %+v", v)
	}
}

func TestRebind(t *testing.T) {
	e := newTestEnv(t, baseConfig, V9P2000LZ)
	c, _, _ := e.dial("tok:alice:dev1", "")
	c.version(V9P2000LZ)
	if r := c.rpc(newMsg(tTrebind, 4).u32(1).finish()); msgType(r) != tRlerror || binary.LittleEndian.Uint32(r[headerSz:]) != errnoEPERM {
		t.Errorf("Trebind with an aname: %x", r)
	}
	e2 := newTestEnv(t, strings.Replace(baseConfig, "max_conns_per_user: 2", "max_conns_per_user: 2\n      allow_rebind: true", 1), V9P2000LZ)
	c2, _, _ := e2.dial("tok:alice:dev1", "")
	c2.version(V9P2000LZ)
	c2.rpc(newMsg(tTrebind, 4).u32(1).finish())
	if msgType(e2.be.last()) != tTrebind {
		t.Error("Trebind not passed through with allow_rebind")
	}
}

func TestHandshakeAuth(t *testing.T) {
	e := newTestEnv(t, strings.Replace(baseConfig, "max_conns_per_user: 2", "max_conns_per_user: 2\n      access: {organization: staff}", 1), V9P2000L)
	if _, res, err := e.dial("", ""); err == nil || res.StatusCode != 401 ||
		!strings.Contains(res.Header.Get("WWW-Authenticate"), `resource_metadata="https://files.test/.well-known/oauth-protected-resource/9p/files"`) {
		t.Errorf("no token: %v %v", err, res)
	}
	if _, res, _ := e.dial("tok:alice", ""); res.StatusCode != 401 || !strings.Contains(res.Header.Get("WWW-Authenticate"), "invalid_token") {
		t.Errorf("bad token: %v", res)
	}
	if _, res, _ := e.dial("tok:bob:dev9", ""); res.StatusCode != 403 {
		t.Errorf("bob isn't staff: %v", res.StatusCode)
	}
	if _, res, _ := e.dial("tok:a/b:dev9", ""); res == nil || res.StatusCode != 403 {
		t.Errorf("unsafe username")
	}
	// The connection cap is per user and route.
	for range 2 {
		if _, _, err := e.dial("tok:alice:dev1", ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, res, _ := e.dial("tok:alice:dev2", ""); res.StatusCode != 429 {
		t.Errorf("over the cap: %d", res.StatusCode)
	}
}

func TestTickets(t *testing.T) {
	e := newTestEnv(t, baseConfig, V9P2000L)
	post := func(header http.Header) (*http.Response, string) {
		req, _ := http.NewRequest("POST", e.srv.URL+"/9p/files/ticket", nil)
		for k, v := range header {
			req.Header[k] = v
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body struct{ Ticket string }
		_ = jsonDecode(res, &body)
		return res, body.Ticket
	}
	res, ticket := post(http.Header{"Authorization": {"Bearer tok:alice:dev1"}})
	if res.StatusCode != 200 || ticket == "" {
		t.Fatalf("ticket: %d", res.StatusCode)
	}
	if _, _, err := e.dial("", "?ticket="+ticket); err != nil {
		t.Errorf("ticket handshake: %v", err)
	}
	if _, res, _ := e.dial("", "?ticket="+ticket); res.StatusCode != 401 {
		t.Errorf("ticket reused: %d", res.StatusCode)
	}

	// A browser's session can get one too, with the UI header.
	e.gw.Session = func(r *http.Request) (*frontend.Session, error) {
		if c, _ := r.Cookie("hanko"); c != nil {
			return &frontend.Session{UserID: "id-" + c.Value, Username: c.Value}, nil
		}
		return nil, nil
	}
	if res, _ := post(http.Header{"Cookie": {"hanko=alice"}}); res.StatusCode != 403 {
		t.Errorf("session ticket without UI header: %d", res.StatusCode)
	}
	if res, _ := post(http.Header{"X-Gateway-Ui": {"1"}}); res.StatusCode != 401 {
		t.Errorf("no session: %d", res.StatusCode)
	}
	res, ticket = post(http.Header{"Cookie": {"hanko=alice"}, "X-Gateway-Ui": {"1"}})
	if res.StatusCode != 200 {
		t.Fatalf("session ticket: %d", res.StatusCode)
	}
	if _, res, err := e.dial("", "?ticket="+ticket); err != nil || res.Header.Get("9P-User") != "alice" {
		t.Errorf("session ticket handshake: %v", err)
	}
}

func TestRevocationCloses(t *testing.T) {
	e := newTestEnv(t, baseConfig, V9P2000L)
	c1, _, _ := e.dial("tok:alice:dev1", "")
	c2, _, _ := e.dial("tok:alice:dev2", "")
	c1.version(V9P2000L)
	c2.version(V9P2000L)
	e.prov.revoke("dev1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := c1.ws.Read(ctx); websocket.CloseStatus(err) != closeRevoked {
		t.Errorf("revoked device: %v", err)
	}
	c2.rpc(newMsg(110, 3).u32(1).u32(2).finish()) // the other device is unaffected
	deadline := time.Now().Add(2 * time.Second)
	for e.gw.Connections() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := e.gw.Connections(); n != 1 {
		t.Errorf("connections: %d", n)
	}
}

func TestConfigErrors(t *testing.T) {
	audience := func(id string) string {
		if id == "files" {
			return aud
		}
		return ""
	}
	for name, cfg := range map[string]string{
		"unknown resource": "gateway:\n  routes:\n    - {resource: nope, backend: tcp!h!1}",
		"path mismatch":    "gateway:\n  routes:\n    - {resource: files, path: /other, backend: tcp!h!1}",
		"bad backend":      "gateway:\n  routes:\n    - {resource: files, backend: 'h:564'}",
		"bad version":      "gateway:\n  routes:\n    - {resource: files, backend: tcp!h!1, versions: [9P2000.X]}",
		"bad template":     "gateway:\n  routes:\n    - {resource: files, backend: tcp!h!1, identity: {aname: '/{email}'}}",
		"twice":            "gateway:\n  routes:\n    - {resource: files, backend: tcp!h!1}\n    - {resource: files, backend: unix!/s}",
	} {
		if _, err := LoadConfig([]byte(cfg), audience); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c, err := LoadConfig([]byte("gateway:\n  routes:\n    - {resource: files, backend: 'wss://be.test/9p'}"), audience)
	if err != nil || c.Routes[0].Path != "/9p/files" || len(c.Routes[0].Versions) != 4 || c.Routes[0].Identity.Uname != "{username}" {
		t.Errorf("defaults: %+v %v", c, err)
	}
}

func TestPickVersion(t *testing.T) {
	all := knownVersions
	for _, tc := range []struct{ client, want string }{
		{"9P2000.L.Z", "9P2000.L.Z"}, {"9P2000.L", "9P2000.L"}, {"9P2000.u", "9P2000.u"},
		{"9P2000", "9P2000"}, {"9P2000.foo", "9P2000"}, {"9P1999", ""}, {"9P2000L", ""},
	} {
		if got := pickVersion(tc.client, all); got != tc.want {
			t.Errorf("%s: %q", tc.client, got)
		}
	}
	if got := pickVersion("9P2000.L.Z", []string{"9P2000"}); got != "9P2000" {
		t.Errorf("downgrade: %q", got)
	}
}

func jsonDecode(res *http.Response, v any) error {
	defer res.Body.Close()
	return json.NewDecoder(res.Body).Decode(v)
}

func TestWebSocketBackend(t *testing.T) {
	be := newBackend(t, V9P2000L)
	wsBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"9p"}})
		if err != nil {
			return
		}
		be.serve(websocket.NetConn(context.Background(), ws, websocket.MessageBinary))
	}))
	t.Cleanup(wsBackend.Close)
	e := newTestEnv(t, strings.Replace(baseConfig, "BACKEND", strings.Replace(wsBackend.URL, "http", "ws", 1), 1), V9P2000L)
	c, _, err := e.dial("tok:alice:dev1", "")
	if err != nil {
		t.Fatal(err)
	}
	if v := c.version(V9P2000L); v.version != V9P2000L {
		t.Errorf("over a ws backend: %+v", v)
	}
	if v, _ := parseVersion(be.last()); v.version != V9P2000L {
		t.Errorf("ws backend got %+v", v)
	}
}
