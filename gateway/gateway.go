package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/progrium/hankoid/frontend"
	"github.com/progrium/hankoid/oidc"
)

// Provider is what the gateway needs from the OIDC provider; *oidc.Provider implements it.
type Provider interface {
	Authenticate(ctx context.Context, raw, audience string) (*oidc.Principal, error)
	IssueTicket(ctx context.Context, pr *oidc.Principal, ttl time.Duration) (string, error)
	RedeemTicket(ctx context.Context, ticket, audience string) (*oidc.Principal, error)
	UserSession(ctx context.Context, userID string) (*frontend.Session, error)
	OnRevoke(fn func(deviceIDs []string))
	RevokedSince(ctx context.Context, since time.Time) ([]oidc.Revocation, time.Time, error)
	ResourceMetadataURL(audience string) string
}

const (
	pingEvery    = 30 * time.Second
	pollEvery    = 10 * time.Second
	ticketTTL    = 30 * time.Second
	closeRevoked = websocket.StatusCode(4401)
)

// Gateway serves the configured routes.
type Gateway struct {
	prov Provider
	// Session, if set, lets a signed-in browser get a ticket with its session cookie.
	Session func(*http.Request) (*frontend.Session, error)
	routes  []*route
	dial    func(ctx context.Context, backend string) (net.Conn, error)

	mu    sync.Mutex
	conns map[*clientConn]struct{}
}

type route struct {
	Route
	audience string
}

// New builds a gateway. audience maps a resource ID to its audience.
func New(cfg *Config, prov Provider, audience func(id string) string) *Gateway {
	g := &Gateway{prov: prov, conns: map[*clientConn]struct{}{}, dial: dialBackend}
	for _, r := range cfg.Routes {
		g.routes = append(g.routes, &route{Route: r, audience: audience(r.Resource)})
	}
	prov.OnRevoke(g.closeDevices)
	return g
}

// Handlers are the routes for the frontend's mux.
func (g *Gateway) Handlers() map[string]http.Handler {
	h := map[string]http.Handler{}
	for _, rt := range g.routes {
		h["GET "+rt.Path] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { g.serveConn(w, r, rt) })
		h["POST "+rt.Path+"/ticket"] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { g.serveTicket(w, r, rt) })
	}
	return h
}

// Run polls for devices revoked by other instances and closes their connections here, until
// ctx is done.
func (g *Gateway) Run(ctx context.Context) {
	cursor := time.Now()
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		list, next, err := g.prov.RevokedSince(ctx, cursor)
		if err != nil {
			log.Printf("gateway: revocations: %v", err)
			continue
		}
		cursor = next
		ids := make([]string, len(list))
		for i, r := range list {
			ids[i] = r.DeviceID
		}
		g.closeDevices(ids)
	}
}

func (g *Gateway) closeDevices(ids []string) {
	if len(ids) == 0 {
		return
	}
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	g.mu.Lock()
	var hit []*clientConn
	for c := range g.conns {
		if c.pr.DeviceID != "" && set[c.pr.DeviceID] {
			hit = append(hit, c)
		}
	}
	g.mu.Unlock()
	for _, c := range hit {
		log.Printf("gateway: closing %s for %s: device %s revoked", c.rt.Path, c.pr.UserID, c.pr.DeviceID)
		go c.close(closeRevoked, "device revoked")
	}
}

// Connections reports how many client connections are open.
func (g *Gateway) Connections() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.conns)
}

func (g *Gateway) register(c *clientConn) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for o := range g.conns {
		if o.rt == c.rt && o.pr.UserID == c.pr.UserID {
			n++
		}
	}
	if n >= c.rt.MaxConnsPerUser {
		return false
	}
	g.conns[c] = struct{}{}
	return true
}

func (g *Gateway) unregister(c *clientConn) {
	g.mu.Lock()
	delete(g.conns, c)
	g.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// unauthorized answers 401 with a pointer to the resource's metadata (RFC 9728 §5.1).
func (g *Gateway) unauthorized(w http.ResponseWriter, rt *route, errCode string) {
	v := fmt.Sprintf(`Bearer resource_metadata=%q`, g.prov.ResourceMetadataURL(rt.audience))
	if errCode != "" {
		v += fmt.Sprintf(`, error=%q`, errCode)
	}
	w.Header().Set("WWW-Authenticate", v)
	writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "Sign in required: run hankoid login " + rt.audience})
}

// principal authenticates a request by its bearer token, or (for WebSocket handshakes) a
// ticket in the query. It writes the response and returns nil on failure.
func (g *Gateway) principal(w http.ResponseWriter, r *http.Request, rt *route, allowTicket bool) *oidc.Principal {
	var pr *oidc.Principal
	var err error
	if h := r.Header.Get("Authorization"); h != "" {
		scheme, tok, _ := strings.Cut(h, " ")
		if !strings.EqualFold(scheme, "Bearer") {
			g.unauthorized(w, rt, "invalid_request")
			return nil
		}
		pr, err = g.prov.Authenticate(r.Context(), strings.TrimSpace(tok), rt.audience)
	} else if t := r.URL.Query().Get("ticket"); t != "" && allowTicket {
		pr, err = g.prov.RedeemTicket(r.Context(), t, rt.audience)
	} else {
		g.unauthorized(w, rt, "")
		return nil
	}
	if oidc.IsInvalidToken(err) {
		g.unauthorized(w, rt, "invalid_token")
		return nil
	}
	if err != nil {
		log.Printf("gateway: authenticate: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "Can't check credentials right now"})
		return nil
	}
	if rt.Access != nil {
		s, err := g.prov.UserSession(r.Context(), pr.UserID)
		if err != nil {
			log.Printf("gateway: load user %s: %v", pr.UserID, err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "Can't check access right now"})
			return nil
		}
		if !rt.Access.Allows(s) {
			writeJSON(w, http.StatusForbidden, map[string]string{"message": "Your account doesn't have access to " + rt.Path})
			return nil
		}
	}
	return pr
}

// serveTicket gives a short-lived, single-use ticket for a WebSocket handshake to clients that
// can't send an Authorization header with one (browsers). It takes a bearer token or, when the
// gateway has Session, the browser's own session.
func (g *Gateway) serveTicket(w http.ResponseWriter, r *http.Request, rt *route) {
	var pr *oidc.Principal
	if r.Header.Get("Authorization") == "" && g.Session != nil {
		if r.Header.Get("X-Gateway-UI") != "1" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			writeJSON(w, http.StatusForbidden, map[string]string{"message": "Missing UI header"})
			return
		}
		s, err := g.Session(r)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"message": "Session validation unavailable"})
			return
		}
		if s == nil {
			g.unauthorized(w, rt, "")
			return
		}
		if rt.Access != nil && !rt.Access.Allows(s) {
			writeJSON(w, http.StatusForbidden, map[string]string{"message": "Your account doesn't have access to " + rt.Path})
			return
		}
		pr = &oidc.Principal{UserID: s.UserID, Username: s.Username, Audience: rt.audience}
	} else if pr = g.principal(w, r, rt, false); pr == nil {
		return
	}
	t, err := g.prov.IssueTicket(r.Context(), pr, ticketTTL)
	if err != nil {
		log.Printf("gateway: ticket: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "Can't issue a ticket right now"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ticket": t, "expires_in": int(ticketTTL.Seconds())})
}

func (g *Gateway) serveConn(w http.ResponseWriter, r *http.Request, rt *route) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		w.Header().Set("Upgrade", "websocket")
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"message": "This is a 9P-over-WebSocket endpoint"})
		return
	}
	pr := g.principal(w, r, rt, true)
	if pr == nil {
		return
	}
	uname, err := expand(rt.Identity.Uname, pr.Username, pr.UserID)
	var aname string
	if err == nil && rt.Identity.Aname != "" {
		aname, err = expand(rt.Identity.Aname, pr.Username, pr.UserID)
	}
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"message": err.Error()})
		return
	}
	c := &clientConn{g: g, rt: rt, pr: pr, uname: uname, aname: aname, done: make(chan struct{})}
	if !g.register(c) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"message": "Too many open connections"})
		return
	}
	defer g.unregister(c)

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	backend, err := g.dial(ctx, rt.Backend)
	cancel()
	if err != nil {
		log.Printf("gateway: %s: dial %s: %v", rt.Path, rt.Backend, err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "The file server is unavailable"})
		return
	}
	c.backend = backend

	// The frontend's server has read and write timeouts; a hijacked connection keeps them.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	w.Header().Set("9P-User", uname)
	if rt.Identity.Uid != nil {
		w.Header().Set("9P-Uid", strconv.FormatUint(uint64(*rt.Identity.Uid), 10))
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"9p"}, OriginPatterns: rt.Origins})
	if err != nil {
		backend.Close()
		return
	}
	ws.SetReadLimit(int64(rt.MaxMsize) + 64)
	c.ws = ws
	log.Printf("gateway: %s connected as %s (user %s, device %s)", rt.Path, uname, pr.UserID, pr.DeviceID)
	c.run()
}

func dialBackend(ctx context.Context, b string) (net.Conn, error) {
	switch {
	case strings.HasPrefix(b, "tcp!"):
		parts := strings.Split(b, "!")
		var d net.Dialer
		return d.DialContext(ctx, "tcp", net.JoinHostPort(parts[1], parts[2]))
	case strings.HasPrefix(b, "unix!"):
		var d net.Dialer
		return d.DialContext(ctx, "unix", strings.TrimPrefix(b, "unix!"))
	default:
		c, _, err := websocket.Dial(ctx, b, &websocket.DialOptions{Subprotocols: []string{"9p"}})
		if err != nil {
			return nil, err
		}
		c.SetReadLimit(17 << 20)
		return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
	}
}

// clientConn is one client's session: a WebSocket on one side, a backend connection on the
// other, and the 9P state the gateway needs.
type clientConn struct {
	g       *Gateway
	rt      *route
	pr      *oidc.Principal
	uname   string
	aname   string
	ws      *websocket.Conn
	backend net.Conn

	wmu  sync.Mutex // serializes writes to the client
	mu   sync.Mutex
	st   p9state
	once sync.Once
	done chan struct{}
}

type p9state struct {
	dialect     string // negotiated; "" before
	msize       uint32
	versionTag  uint16 // tag of the Tversion in flight
	offered     string // version offered to the backend for it; "" if none in flight
	clientMsize uint32
}

func (c *clientConn) close(code websocket.StatusCode, reason string) {
	c.once.Do(func() {
		close(c.done)
		c.backend.Close()
		_ = c.ws.Close(code, reason)
	})
}

func (c *clientConn) toClient(ctx context.Context, m []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	wctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return c.ws.Write(wctx, websocket.MessageBinary, m)
}

func (c *clientConn) run() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 2)
	go func() { errc <- c.fromClient(ctx) }()
	go func() { errc <- c.fromBackend(ctx) }()
	go c.keepalive(ctx)
	var err error
	select {
	case err = <-errc:
	case <-c.done:
	}
	code, reason := websocket.StatusNormalClosure, ""
	var pe protocolError
	switch {
	case errors.As(err, &pe):
		code, reason = websocket.StatusPolicyViolation, string(pe)
	case errors.Is(err, errTooBig):
		code, reason = websocket.StatusMessageTooBig, err.Error()
	case err != nil && !errors.Is(err, io.EOF) && websocket.CloseStatus(err) == -1:
		code, reason = websocket.StatusGoingAway, "backend closed"
	}
	c.close(code, reason)
	log.Printf("gateway: %s disconnected (user %s): %v", c.rt.Path, c.pr.UserID, err)
}

// keepalive pings the client every 30 seconds and hangs up if it doesn't answer in time, which
// also keeps proxies from closing an idle connection.
func (c *clientConn) keepalive(ctx context.Context) {
	t := time.NewTicker(pingEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, pingEvery)
		err := c.ws.Ping(pctx)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				c.close(websocket.StatusGoingAway, "ping timeout")
			}
			return
		}
	}
}

type protocolError string

func (e protocolError) Error() string { return string(e) }

func (c *clientConn) limit() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st.dialect == "" {
		return preVersionMax
	}
	return c.st.msize
}

func (c *clientConn) fromClient(ctx context.Context) error {
	r := bufio.NewReaderSize(websocket.NetConn(ctx, c.ws, websocket.MessageBinary), 64<<10)
	for {
		m, err := readMsg(r, c.limit())
		if err != nil {
			return err
		}
		out, reply, err := c.filterClient(m)
		if err != nil {
			return err
		}
		if reply != nil {
			if err := c.toClient(ctx, reply); err != nil {
				return err
			}
		}
		if out != nil {
			if _, err := c.backend.Write(out); err != nil {
				return err
			}
		}
	}
}

// filterClient decides what happens to a client message: out goes to the backend, reply goes
// back to the client.
func (c *clientConn) filterClient(m []byte) (out, reply []byte, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tag := msgTag(m)
	switch msgType(m) {
	case tTversion:
		v, err := parseVersion(m)
		if err != nil {
			return nil, nil, protocolError(err.Error())
		}
		// A Tversion resets the session.
		c.st = p9state{}
		offer := pickVersion(v.version, c.rt.Versions)
		if offer == "" {
			return nil, versionMsg(tRversion, tag, version{msize: v.msize, version: "unknown"}), nil
		}
		v.msize = min(v.msize, c.rt.MaxMsize)
		c.st.versionTag, c.st.offered, c.st.clientMsize = tag, offer, v.msize
		return versionMsg(tTversion, tag, version{msize: v.msize, version: offer}), nil, nil
	}
	d := c.st.dialect
	if d == "" {
		return nil, nil, protocolError("9p: message before version negotiation")
	}
	switch msgType(m) {
	case tTauth:
		return nil, errorMsg(tag, d, "authentication not required", errnoEOPNOTSUPP), nil
	case tTattach:
		a, err := parseAttach(m, d)
		if err != nil {
			return nil, nil, protocolError(err.Error())
		}
		a.afid, a.uname = noFid, c.uname
		if c.aname != "" {
			a.aname = c.aname
		}
		a.nUname = noUname
		if c.rt.Identity.Uid != nil {
			a.nUname = *c.rt.Identity.Uid
		}
		return attachMsg(tag, a, d), nil, nil
	case tTrebind:
		if d == V9P2000LZ && c.aname != "" && !c.rt.AllowRebind {
			return nil, errorMsg(tag, d, "rebind not allowed", errnoEPERM), nil
		}
	}
	return m, nil, nil
}

func (c *clientConn) fromBackend(ctx context.Context) error {
	r := bufio.NewReaderSize(c.backend, 64<<10)
	for {
		m, err := readMsg(r, c.rt.MaxMsize+64)
		if err != nil {
			return err
		}
		if msgType(m) == tRversion {
			if m, err = c.backendVersion(m); err != nil {
				return err
			}
		}
		if err := c.toClient(ctx, m); err != nil {
			return err
		}
	}
}

// backendVersion records the negotiated dialect from an Rversion. A version the client didn't
// get offered, or the route doesn't allow, becomes "unknown".
func (c *clientConn) backendVersion(m []byte) ([]byte, error) {
	v, err := parseVersion(m)
	if err != nil {
		return nil, protocolError(err.Error())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st.offered == "" || msgTag(m) != c.st.versionTag {
		return nil, protocolError("9p: unexpected Rversion from the backend")
	}
	offered := c.st.offered
	c.st.offered = ""
	if v.version == "unknown" || pickVersion(offered, []string{v.version}) == "" || pickVersion(v.version, c.rt.Versions) != v.version {
		return versionMsg(tRversion, msgTag(m), version{msize: c.st.clientMsize, version: "unknown"}), nil
	}
	v.msize = min(v.msize, c.st.clientMsize)
	if v.msize < 256 {
		return nil, protocolError("9p: msize too small")
	}
	c.st.dialect, c.st.msize = v.version, v.msize
	return versionMsg(tRversion, msgTag(m), v), nil
}
