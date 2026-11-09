package credhelper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixture is a tiny issuer that serves resource metadata, the device grant and refresh tokens,
// and accepts only the newest refresh token.
type fixture struct {
	srv       *httptest.Server
	mu        sync.Mutex
	polls     int
	newest    string
	n         int
	refreshes int
	revoked   []string
	deny      bool
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	iss := f.srv.URL + "/oidc"
	write := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/9p/files", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, map[string]any{"resource": strings.Replace(f.srv.URL, "http", "ws", 1) + "/9p/files",
			"authorization_servers": []string{iss}, "hankoid_device_client_id": "hankfs"})
	})
	mux.HandleFunc("GET /oidc/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, map[string]any{"issuer": iss, "device_authorization_endpoint": iss + "/device_authorization",
			"token_endpoint": iss + "/token", "revocation_endpoint": iss + "/revoke"})
	})
	mux.HandleFunc("POST /oidc/device_authorization", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("client_id") != "hankfs" || r.FormValue("device_name") != "testbox" || !strings.HasSuffix(r.FormValue("resource"), "/9p/files") {
			write(w, 400, map[string]string{"error": "invalid_request"})
			return
		}
		write(w, 200, map[string]any{"device_code": "dc", "user_code": "BCDF-GHJK", "verification_uri": iss + "/device",
			"verification_uri_complete": iss + "/device?code=BCDF-GHJK", "interval": 1, "expires_in": 600})
	})
	mux.HandleFunc("POST /oidc/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.FormValue("grant_type") {
		case "urn:ietf:params:oauth:grant-type:device_code":
			f.polls++
			if f.deny {
				write(w, 400, map[string]string{"error": "access_denied"})
				return
			}
			if f.polls < 2 {
				write(w, 400, map[string]string{"error": "authorization_pending"})
				return
			}
		case "refresh_token":
			if r.FormValue("refresh_token") != f.newest || r.FormValue("resource") == "" {
				write(w, 400, map[string]string{"error": "invalid_grant"})
				return
			}
			f.refreshes++
		}
		f.n++
		f.newest = fmt.Sprintf("rt%d", f.n)
		write(w, 200, map[string]any{"access_token": fmt.Sprintf("at%d", f.n), "refresh_token": f.newest, "expires_in": 300, "token_type": "Bearer"})
	})
	mux.HandleFunc("POST /oidc/revoke", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.revoked = append(f.revoked, r.FormValue("token"))
		f.mu.Unlock()
	})
	return f
}

func TestLoginTokenLogout(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	h := &Helper{Path: filepath.Join(t.TempDir(), "creds", "credentials.json"), Now: func() time.Time { return now }}
	ctx := context.Background()
	resource := strings.Replace(f.srv.URL, "http", "ws", 1) + "/9p/files"

	if _, err := h.Token(ctx, resource, false); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("before login: %v", err)
	}
	var out strings.Builder
	c, err := h.Login(ctx, resource, LoginOptions{DeviceName: "testbox", Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	if c.Resource != resource || c.ClientID != "hankfs" || !strings.Contains(out.String(), "BCDF-GHJK") {
		t.Errorf("login: %+v %q", c, out.String())
	}
	if st, _ := os.Stat(h.Path); st.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v", st.Mode())
	}

	// Cached until a minute before expiry, then refreshed; a subpath uses the same credential.
	if tok, err := h.Token(ctx, resource+"/sub/dir", false); err != nil || tok != "at1" {
		t.Errorf("cached: %q %v", tok, err)
	}
	now = now.Add(4*time.Minute + 30*time.Second)
	if tok, err := h.Token(ctx, resource, false); err != nil || tok != "at2" {
		t.Errorf("refresh near expiry: %q %v", tok, err)
	}
	if tok, err := h.Token(ctx, resource, true); err != nil || tok != "at3" {
		t.Errorf("forced: %q %v", tok, err)
	}

	// Parallel helpers serialize on the file lock, so none presents a stale refresh token.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h2 := &Helper{Path: h.Path, Now: h.Now}
			_, err := h2.Token(ctx, resource, true)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("parallel refresh: %v", err)
		}
	}
	if f.refreshes != 10 {
		t.Errorf("refreshes: %d", f.refreshes)
	}

	if ok, err := h.Logout(ctx, resource); !ok || err != nil || len(f.revoked) != 1 || f.revoked[0] != f.newest {
		t.Errorf("logout: %v %v %v", ok, err, f.revoked)
	}
	if _, err := h.Token(ctx, resource, false); !errors.Is(err, ErrLoginRequired) {
		t.Errorf("after logout: %v", err)
	}
}

func TestRefusedRefreshToken(t *testing.T) {
	f := newFixture(t)
	h := &Helper{Path: filepath.Join(t.TempDir(), "credentials.json")}
	ctx := context.Background()
	resource := strings.Replace(f.srv.URL, "http", "ws", 1) + "/9p/files"
	if _, err := h.Login(ctx, resource, LoginOptions{DeviceName: "testbox"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.newest = "revoked-elsewhere"
	f.mu.Unlock()
	if _, err := h.Token(ctx, resource, true); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("refused token: %v", err)
	}
	if ok, _ := h.Logout(ctx, resource); ok {
		t.Error("the refused credential was kept")
	}
}

func TestLoginDenied(t *testing.T) {
	f := newFixture(t)
	f.deny = true
	h := &Helper{Path: filepath.Join(t.TempDir(), "credentials.json")}
	resource := strings.Replace(f.srv.URL, "http", "ws", 1) + "/9p/files"
	if _, err := h.Login(context.Background(), resource, LoginOptions{DeviceName: "testbox"}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("denied: %v", err)
	}
}

func TestMetadataURL(t *testing.T) {
	for in, want := range map[string]string{
		"wss://h.test/9p/files/": "https://h.test/.well-known/oauth-protected-resource/9p/files",
		"ws://127.0.0.1:8080":    "http://127.0.0.1:8080/.well-known/oauth-protected-resource",
	} {
		if got, err := MetadataURL(in); err != nil || got != want {
			t.Errorf("%s: %s %v", in, got, err)
		}
	}
	if _, err := MetadataURL("tcp!h!564"); err == nil {
		t.Error("tcp address accepted")
	}
}
