package oidc

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/progrium/hankoid/frontend"
)

// The /device page: a signed-in user enters (or follows a link with) a user code, sees who is
// asking and from where, and approves or denies. Approving needs a recent passkey sign-in.

const deviceCookie = "hankoid_device"

// Wrong-code limits: per Hanko session, 5 per 10 minutes; per IP, 20 per hour.
const (
	codeSessionEvery = 2 * time.Minute
	codeSessionBurst = 5
	codeIPEvery      = 3 * time.Minute
	codeIPBurst      = 20
)

// DeviceHandler serves GET and POST /device.
func (p *Provider) DeviceHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /device", p.devicePage)
	mux.HandleFunc("POST /device", p.deviceConfirm)
	return mux
}

// freshSession returns the signed-in session if its sign-in is recent enough to approve a device.
// Otherwise it has redirected to /signin (or shown an error) and returns nil.
func (p *Provider) freshSession(w http.ResponseWriter, r *http.Request, back string) (*frontend.Session, time.Time) {
	s, err := p.hanko.Session(r)
	if err != nil {
		log.Printf("oidc: session validation failed: %v", err)
		errorPage(w, http.StatusBadGateway, "Try again later", "Sign-in can't be checked right now.")
		return nil, time.Time{}
	}
	if s == nil {
		http.Redirect(w, r, frontend.SignInURL(back), http.StatusFound)
		return nil, time.Time{}
	}
	authTime := p.authTime(r, s)
	if p.now().Sub(authTime) <= p.cfg.Device.MaxAuthAge {
		return s, authTime
	}
	if r.Method == http.MethodGet && r.URL.Query().Get("min_auth_time") == "" {
		// Ask for a fresh passkey sign-in, and remember when we asked so a stale session coming
		// back can't pass for a new one (the same guard authorize uses for prompt=login).
		u, _ := url.Parse(back)
		q := u.Query()
		q.Set("min_auth_time", strconv.FormatInt(p.now().Unix(), 10))
		u.RawQuery = q.Encode()
		http.Redirect(w, r, frontend.SignInURL(u.RequestURI())+"&fresh=1", http.StatusFound)
		return nil, time.Time{}
	}
	devicePageHTML(w, http.StatusForbidden, "Sign in again", `<p>Approving a device needs a passkey sign-in from the last few minutes.</p>
<p><a href="/device">Start again</a></p>`)
	return nil, time.Time{}
}

func (p *Provider) devicePage(w http.ResponseWriter, r *http.Request) {
	if p.devices == nil {
		errorPage(w, http.StatusNotFound, "Not available", "Device sign-in isn't enabled.")
		return
	}
	q := r.URL.Query()
	back := "/device"
	if c := q.Get("user_code"); c != "" {
		back += "?user_code=" + url.QueryEscape(c)
	}
	s, _ := p.freshSession(w, r, back)
	if s == nil {
		return
	}
	raw := q.Get("user_code")
	if raw == "" {
		deviceEntryForm(w, "", "")
		return
	}
	code, ok := NormalizeUserCode(raw)
	if !ok {
		deviceEntryForm(w, raw, "Codes are 8 letters, like BCDF-GHJK.")
		return
	}
	ip := p.clientIP(r)
	sessLimit := p.limiterN("devcode:s:"+s.UserID+":"+s.SessionID, codeSessionEvery, codeSessionBurst)
	ipLimit := p.limiterN("devcode:ip:"+ip, codeIPEvery, codeIPBurst)
	if sessLimit.Tokens() < 1 || ipLimit.Tokens() < 1 {
		devicePageHTML(w, http.StatusTooManyRequests, "Too many attempts", "<p>Too many wrong codes. Wait a few minutes and try again.</p>")
		return
	}
	g, err := p.devices.PendingGrant(r.Context(), code)
	if errors.Is(err, errNotFound) {
		sessLimit.Allow()
		ipLimit.Allow()
		log.Printf("oidc: wrong device code from %s (%s) at %s", s.Name(), s.UserID, ip)
		deviceEntryForm(w, raw, "That code isn't valid, or it has expired. Check the code on your device.")
		return
	}
	if err != nil {
		log.Printf("oidc: device lookup: %v", err)
		errorPage(w, http.StatusInternalServerError, "Try again later", "Device sign-in is unavailable right now.")
		return
	}
	client := p.cfg.Client(g.ClientID)
	if client == nil {
		deviceEntryForm(w, raw, "That code isn't valid, or it has expired.")
		return
	}
	token := randomID()
	http.SetCookie(w, &http.Cookie{Name: deviceCookie, Value: token, Path: "/device", HttpOnly: true,
		Secure: strings.HasPrefix(p.cfg.Issuer, "https://"), SameSite: http.SameSiteStrictMode, MaxAge: 600})
	p.deviceConfirmPage(w, r, s, client, g, code, token)
}

func (p *Provider) deviceConfirm(w http.ResponseWriter, r *http.Request) {
	if p.devices == nil {
		errorPage(w, http.StatusNotFound, "Not available", "Device sign-in isn't enabled.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		errorPage(w, http.StatusBadRequest, "Invalid request", "The form was malformed.")
		return
	}
	c, cerr := r.Cookie(deviceCookie)
	if !sameOrigin(r, p.cfg.Issuer) || cerr != nil || r.PostForm.Get("csrf") == "" ||
		subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostForm.Get("csrf"))) != 1 {
		errorPage(w, http.StatusForbidden, "Invalid request", "The request couldn't be verified. Please start again on your device.")
		return
	}
	s, authTime := p.freshSession(w, r, "/device")
	if s == nil {
		return
	}
	code, ok := NormalizeUserCode(r.PostForm.Get("user_code"))
	if !ok {
		deviceEntryForm(w, "", "That code isn't valid.")
		return
	}
	g, err := p.devices.PendingGrant(r.Context(), code)
	if errors.Is(err, errNotFound) {
		devicePageHTML(w, http.StatusGone, "Code expired", "<p>This code has expired or was already used. Start again on your device.</p>")
		return
	}
	if err != nil {
		log.Printf("oidc: device lookup: %v", err)
		errorPage(w, http.StatusInternalServerError, "Try again later", "Device sign-in is unavailable right now.")
		return
	}
	client := p.cfg.Client(g.ClientID)
	approve := r.PostForm.Get("action") == "approve"
	denied := ""
	if approve && (client == nil || !client.Allows(s)) {
		approve = false
		denied = "This account may not use " + html.EscapeString(g.ClientID) + "."
		if client != nil {
			denied = "This account may not use " + html.EscapeString(client.DisplayName()) + "."
		}
	}
	ip := p.clientIP(r)
	if err := p.devices.Decide(r.Context(), code, approve, s.UserID, s.SessionID, ip, authTime); err != nil {
		if errors.Is(err, errNotFound) {
			devicePageHTML(w, http.StatusGone, "Code expired", "<p>This code has expired or was already used. Start again on your device.</p>")
			return
		}
		log.Printf("oidc: device decision: %v", err)
		errorPage(w, http.StatusInternalServerError, "Try again later", "Device sign-in is unavailable right now.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: deviceCookie, Value: "", Path: "/device", MaxAge: -1})
	verb := "denied"
	if approve {
		verb = "approved"
	}
	log.Printf("oidc: device request for client %q %s by %s (%s) at %s; requested from %s", g.ClientID, verb, s.Name(), s.UserID, ip, g.RequesterIP)
	switch {
	case denied != "":
		devicePageHTML(w, http.StatusForbidden, "Not allowed", "<p>"+denied+" The device was told no.</p>")
	case approve:
		devicePageHTML(w, http.StatusOK, "Device approved", "<p>You can close this page and return to your device.</p>"+
			`<p style="color:#5b6577">You can remove it any time from <a href="/account/devices">Your devices</a>.</p>`)
	default:
		devicePageHTML(w, http.StatusOK, "Request denied", "<p>The device won't get access. If someone sent you this code, you were right to deny it.</p>")
	}
}

var scopeWords = map[string]string{
	"openid":         "Know who you are",
	"profile":        "See your name and username",
	"email":          "See your email address",
	"roles":          "See your roles",
	"offline_access": "Stay signed in until you remove it from Your devices",
}

func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d seconds ago", int(d.Seconds()))
	case d < 2*time.Minute:
		return "a minute ago"
	default:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	}
}

func place(ip, geo string) string {
	s := html.EscapeString(ip)
	if s == "" {
		s = "an unknown address"
	}
	if geo != "" {
		s += ", near " + html.EscapeString(geo)
	}
	return s
}

func (p *Provider) deviceConfirmPage(w http.ResponseWriter, r *http.Request, s *frontend.Session, client *Client, g *DeviceGrant, code, csrf string) {
	myIP := p.clientIP(r)
	myGeo := ""
	if h := p.cfg.Device.GeoHeader; h != "" {
		myGeo = cleanDeviceName(r.Header.Get(h))
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<p style="font-size:16px"><b>%s</b> wants access to your account <b>%s</b>.</p>`,
		html.EscapeString(client.DisplayName()), html.EscapeString(s.Name()))
	fmt.Fprintf(&b, `<p style="font-size:30px;letter-spacing:4px;font-family:ui-monospace,monospace;margin:18px 0 4px">%s</p>
<p style="margin-top:0">Check that this matches the code on your device.</p>`, FormatUserCode(code))
	fmt.Fprintf(&b, `<table style="text-align:left;margin:16px auto;border-spacing:8px 4px">
<tr><td style="color:#5b6577">Requested from</td><td>%s, %s</td></tr>
<tr><td style="color:#5b6577">You are at</td><td>%s</td></tr>`, place(g.RequesterIP, g.RequesterGeo), ago(p.now().Sub(g.CreatedAt)), place(myIP, myGeo))
	if g.DeviceName != "" || g.RequesterUA != "" {
		name := g.DeviceName
		if name == "" {
			name = g.RequesterUA
		}
		fmt.Fprintf(&b, `<tr><td style="color:#5b6577">The device calls itself</td><td>%s</td></tr>`, html.EscapeString(name))
	}
	b.WriteString(`</table>`)
	if g.RequesterIP != myIP {
		b.WriteString(`<p style="background:#fff4e5;border:1px solid #f0c27b;border-radius:6px;padding:10px;text-align:left">` +
			`This request came from a different network than the one you're on. If someone sent you this code, <b>deny it</b>.</p>`)
	}
	b.WriteString(`<p style="text-align:left;margin-bottom:4px">If you approve, it can:</p><ul style="text-align:left;margin-top:0">`)
	for _, sc := range strings.Fields(g.Scope) {
		if words, ok := scopeWords[sc]; ok {
			fmt.Fprintf(&b, "<li>%s</li>", words)
		}
	}
	b.WriteString(`</ul><p style="color:#5b6577">Only approve if you just started signing in on your own device.</p>`)
	fmt.Fprintf(&b, `<form method="post" action="/device" style="display:flex;gap:10px;justify-content:center">
<input type="hidden" name="csrf" value="%s"><input type="hidden" name="user_code" value="%s">
<button name="action" value="deny" autofocus style="cursor:pointer;border:0;border-radius:6px;background:#245fd4;color:white;padding:9px 18px">Deny</button>
<button name="action" value="approve" style="cursor:pointer;border:1px solid #cbd3df;border-radius:6px;background:white;padding:9px 18px">Approve</button>
</form>`, html.EscapeString(csrf), html.EscapeString(code))
	devicePageHTML(w, http.StatusOK, "Approve a device?", b.String())
}

func deviceEntryForm(w http.ResponseWriter, value, problem string) {
	var b strings.Builder
	b.WriteString(`<p>Enter the code shown on your device.</p>`)
	if problem != "" {
		fmt.Fprintf(&b, `<p style="color:#b42318">%s</p>`, html.EscapeString(problem))
	}
	fmt.Fprintf(&b, `<form method="get" action="/device">
<input name="user_code" value="%s" placeholder="BCDF-GHJK" autocomplete="off" autocapitalize="characters" spellcheck="false" autofocus
 style="font:22px ui-monospace,monospace;letter-spacing:3px;text-align:center;width:12ch;padding:8px;border:1px solid #cbd3df;border-radius:6px">
<p><button style="cursor:pointer;border:0;border-radius:6px;background:#245fd4;color:white;padding:9px 18px">Continue</button></p>
</form>`, html.EscapeString(value))
	status := http.StatusOK
	if problem != "" {
		status = http.StatusBadRequest
	}
	devicePageHTML(w, status, "Sign in a device", b.String())
}

// devicePageHTML writes a page whose body is trusted, already-escaped HTML.
func devicePageHTML(w http.ResponseWriter, status int, title, body string) {
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title>
<body style="font:14px system-ui;background:#f4f6f9;color:#263248;display:grid;place-items:center;min-height:90vh;margin:0 16px">
<div style="background:white;border:1px solid #dbe1ea;border-radius:9px;padding:28px;max-width:460px;text-align:center">
<h1 style="font-size:20px;margin:0 0 8px">%s</h1>%s</div>`, html.EscapeString(title), html.EscapeString(title), body)
}
