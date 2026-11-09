package oidc

import (
	"crypto/subtle"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/progrium/hankoid/frontend"
)

// Your devices: a signed-in user's approved devices, each removable. /account/devices is a
// server-rendered page; /account/api/devices is the same as JSON.

const accountCookie = "hankoid_account"

// AccountHandler serves /account/devices and /account/api/devices.
func (p *Provider) AccountHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /account/devices", p.accountDevicesPage)
	mux.HandleFunc("POST /account/devices", p.accountDevicesPost)
	mux.HandleFunc("GET /account/api/devices", p.accountDevicesJSON)
	mux.HandleFunc("DELETE /account/api/devices/{id}", p.accountDeviceDelete)
	return mux
}

// AdminDevicesHandler lists and revokes any user's devices. The caller must restrict it to admins.
//
//	GET    /admin/hankoid/devices?user_id=…
//	DELETE /admin/hankoid/devices/{id}       (needs X-Admin-UI: 1, like the admin API proxy)
func (p *Provider) AdminDevicesHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/hankoid/devices", func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		user := r.URL.Query().Get("user_id")
		if user == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "user_id is required"})
			return
		}
		list, err := p.devices.UserDevices(r.Context(), user)
		if err != nil {
			log.Printf("oidc: list devices: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "device store unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, p.deviceViews(list))
	})
	mux.HandleFunc("DELETE /admin/hankoid/devices/{id}", func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		if r.Header.Get("X-Admin-UI") != "1" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			writeJSON(w, http.StatusForbidden, map[string]string{"message": "Missing UI header"})
			return
		}
		p.revokeOne(w, r, r.PathValue("id"), "", "admin")
	})
	return mux
}

type deviceView struct {
	Device
	ClientName string `json:"client_name"`
}

func (p *Provider) deviceViews(list []Device) []deviceView {
	out := make([]deviceView, len(list))
	for i, d := range list {
		out[i] = deviceView{Device: d, ClientName: d.ClientID}
		if c := p.cfg.Client(d.ClientID); c != nil {
			out[i].ClientName = c.DisplayName()
		}
	}
	return out
}

// accountSession returns the signed-in user, or writes a redirect (pages) or 401 (API).
func (p *Provider) accountSession(w http.ResponseWriter, r *http.Request, api bool) *frontend.Session {
	if p.devices == nil {
		http.NotFound(w, r)
		return nil
	}
	s, err := p.hanko.Session(r)
	if err != nil {
		log.Printf("oidc: session validation failed: %v", err)
		http.Error(w, "Session validation unavailable", http.StatusBadGateway)
		return nil
	}
	if s == nil {
		if api {
			noStore(w)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "Sign in required"})
		} else {
			http.Redirect(w, r, frontend.SignInURL(r.URL.RequestURI()), http.StatusFound)
		}
		return nil
	}
	return s
}

func (p *Provider) revokeOne(w http.ResponseWriter, r *http.Request, id, userID, by string) {
	ok, err := p.devices.RevokeDevice(r.Context(), id, userID, by)
	if err != nil {
		log.Printf("oidc: revoke device: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "device store unavailable"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "No such device"})
		return
	}
	log.Printf("oidc: device %s revoked (%s)", id, by)
	p.notifyRevoked(id)
	w.WriteHeader(http.StatusNoContent)
}

func (p *Provider) accountDevicesJSON(w http.ResponseWriter, r *http.Request) {
	s := p.accountSession(w, r, true)
	if s == nil {
		return
	}
	list, err := p.devices.UserDevices(r.Context(), s.UserID)
	if err != nil {
		log.Printf("oidc: list devices: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "device store unavailable"})
		return
	}
	noStore(w)
	writeJSON(w, http.StatusOK, p.deviceViews(list))
}

func (p *Provider) accountDeviceDelete(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.Header.Get("X-Account-UI") != "1" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		writeJSON(w, http.StatusForbidden, map[string]string{"message": "Missing UI header"})
		return
	}
	s := p.accountSession(w, r, true)
	if s == nil {
		return
	}
	p.revokeOne(w, r, r.PathValue("id"), s.UserID, "user")
}

func (p *Provider) accountDevicesPost(w http.ResponseWriter, r *http.Request) {
	s := p.accountSession(w, r, false)
	if s == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		errorPage(w, http.StatusBadRequest, "Invalid request", "The form was malformed.")
		return
	}
	c, cerr := r.Cookie(accountCookie)
	if !sameOrigin(r, p.cfg.Issuer) || cerr != nil || r.PostForm.Get("csrf") == "" ||
		subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostForm.Get("csrf"))) != 1 {
		errorPage(w, http.StatusForbidden, "Invalid request", "The request couldn't be verified. Please try again.")
		return
	}
	var ids []string
	if r.PostForm.Get("action") == "remove_all" {
		var err error
		if ids, err = p.devices.RevokeUserDevices(r.Context(), s.UserID, "user"); err != nil {
			log.Printf("oidc: revoke devices: %v", err)
			errorPage(w, http.StatusInternalServerError, "Try again later", "Devices can't be changed right now.")
			return
		}
	} else if id := r.PostForm.Get("id"); id != "" {
		ok, err := p.devices.RevokeDevice(r.Context(), id, s.UserID, "user")
		if err != nil {
			log.Printf("oidc: revoke device: %v", err)
			errorPage(w, http.StatusInternalServerError, "Try again later", "Devices can't be changed right now.")
			return
		}
		if ok {
			ids = []string{id}
		}
	}
	if len(ids) > 0 {
		log.Printf("oidc: %s (%s) removed %d device(s)", s.Name(), s.UserID, len(ids))
		p.notifyRevoked(ids...)
	}
	http.Redirect(w, r, "/account/devices", http.StatusSeeOther)
}

func (p *Provider) accountDevicesPage(w http.ResponseWriter, r *http.Request) {
	s := p.accountSession(w, r, false)
	if s == nil {
		return
	}
	list, err := p.devices.UserDevices(r.Context(), s.UserID)
	if err != nil {
		log.Printf("oidc: list devices: %v", err)
		errorPage(w, http.StatusInternalServerError, "Try again later", "Devices can't be listed right now.")
		return
	}
	token := randomID()
	http.SetCookie(w, &http.Cookie{Name: accountCookie, Value: token, Path: "/account", HttpOnly: true,
		Secure: strings.HasPrefix(p.cfg.Issuer, "https://"), SameSite: http.SameSiteStrictMode, MaxAge: 3600})
	csrf := html.EscapeString(token)
	var b strings.Builder
	fmt.Fprintf(&b, `<p>Signed in as <b>%s</b>. These devices stay signed in until you remove them.</p>`, html.EscapeString(s.Name()))
	if len(list) == 0 {
		b.WriteString(`<p style="color:#5b6577">No devices.</p>`)
	} else {
		b.WriteString(`<table style="width:100%;text-align:left;border-collapse:collapse;margin:12px 0">`)
		b.WriteString(`<tr style="color:#5b6577"><th style="padding:6px">Device</th><th style="padding:6px">Approved</th><th style="padding:6px">Last used</th><th></th></tr>`)
		for _, d := range p.deviceViews(list) {
			last := d.LastUsedAt.UTC().Format("Jan 2, 15:04 MST")
			if d.LastUsedIP != "" {
				last += " from " + d.LastUsedIP
			}
			fmt.Fprintf(&b, `<tr style="border-top:1px solid #e6eaf0"><td style="padding:6px"><b>%s</b><br><span style="color:#5b6577">%s</span></td>
<td style="padding:6px">%s<br><span style="color:#5b6577">%s</span></td><td style="padding:6px">%s</td>
<td style="padding:6px"><form method="post" action="/account/devices" style="margin:0"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s">
<button style="cursor:pointer;border:1px solid #cbd3df;border-radius:6px;background:white;padding:6px 10px">Remove</button></form></td></tr>`,
				html.EscapeString(d.Name), html.EscapeString(d.ClientName), d.CreatedAt.UTC().Format(time.DateOnly),
				html.EscapeString(d.CreatedIP), html.EscapeString(last), csrf, html.EscapeString(d.ID))
		}
		b.WriteString(`</table>`)
		fmt.Fprintf(&b, `<form method="post" action="/account/devices"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="action" value="remove_all">
<button style="cursor:pointer;border:0;border-radius:6px;background:#b42318;color:white;padding:9px 16px">Remove all devices</button></form>`, csrf)
	}
	devicePageHTML(w, http.StatusOK, "Your devices", b.String())
}
