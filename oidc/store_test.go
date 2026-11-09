package oidc

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The Postgres tests run when HANKOID_TEST_DATABASE_URL names a Postgres database they may
// write to, e.g. postgres://hanko:hanko@localhost:5432/hanko. They use the hankoid schema and
// empty hankoid.oidc_auth_codes first.
const testDatabaseEnv = "HANKOID_TEST_DATABASE_URL"

var (
	testPoolOnce sync.Once
	testPoolVal  *pgxpool.Pool
	testPoolErr  error
)

// testPool returns a migrated pool with an empty codes table, or skips the test.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv(testDatabaseEnv)
	if dsn == "" {
		t.Skip(testDatabaseEnv + " not set")
	}
	testPoolOnce.Do(func() {
		ctx := context.Background()
		testPoolVal, testPoolErr = OpenPostgres(ctx, dsn)
		if testPoolErr == nil {
			_, testPoolErr = Migrate(ctx, testPoolVal)
		}
	})
	if testPoolErr != nil {
		t.Fatal(testPoolErr)
	}
	if _, err := testPoolVal.Exec(context.Background(), "TRUNCATE hankoid.oidc_auth_codes"); err != nil {
		t.Fatal(err)
	}
	return testPoolVal
}

// forEachStore runs f against the memory store and, when configured, the Postgres store.
func forEachStore(t *testing.T, f func(*testing.T, CodeStore)) {
	t.Run("memory", func(t *testing.T) { f(t, nil) })
	t.Run("postgres", func(t *testing.T) { f(t, NewPostgresCodes(testPool(t))) })
}

func setStoreClock(s CodeStore, now func() time.Time) {
	switch s := s.(type) {
	case *memoryCodes:
		s.now = now
	case *PostgresCodes:
		s.now = now
	}
}

func testStores(t *testing.T) map[string]func(t *testing.T) CodeStore {
	return map[string]func(t *testing.T) CodeStore{
		"memory": func(t *testing.T) CodeStore {
			m, err := newMemoryCodes([]string{"0123456789abcdef0123456789abcdef"})
			if err != nil {
				t.Fatal(err)
			}
			return m
		},
		"postgres": func(t *testing.T) CodeStore { return NewPostgresCodes(testPool(t)) },
	}
}

func TestCodeStoreContract(t *testing.T) {
	for name, mk := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
			setStoreClock(s, func() time.Time { return now })
			ctx := context.Background()
			in := codeData{ClientID: "app", RedirectURI: "https://app.test/cb", UserID: "alice", SessionID: "s-alice",
				Nonce: "n", CodeChallenge: "cc", Scope: "openid email", AuthTime: now.Add(-time.Minute), Exp: now.Add(time.Minute)}
			code, err := s.Issue(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.Redeem(ctx, code)
			if err != nil {
				t.Fatal(err)
			}
			if got.ClientID != in.ClientID || got.RedirectURI != in.RedirectURI || got.UserID != in.UserID ||
				got.SessionID != in.SessionID || got.Nonce != in.Nonce || got.CodeChallenge != in.CodeChallenge ||
				got.Scope != in.Scope || !got.AuthTime.Equal(in.AuthTime) || !got.Exp.Equal(in.Exp) {
				t.Errorf("round trip: got %+v, want %+v", got, in)
			}
			if _, err := s.Redeem(ctx, code); !errors.Is(err, errBadCode) {
				t.Errorf("second redeem: %v", err)
			}

			// Optional fields stay empty.
			code, _ = s.Issue(ctx, codeData{ClientID: "app", UserID: "bob", Scope: "openid", AuthTime: now, Exp: now.Add(time.Minute)})
			if got, err := s.Redeem(ctx, code); err != nil || got.SessionID != "" || got.Nonce != "" || got.CodeChallenge != "" {
				t.Errorf("empty optionals: %+v %v", got, err)
			}

			code, _ = s.Issue(ctx, in)
			now = now.Add(2 * time.Minute)
			if _, err := s.Redeem(ctx, code); !errors.Is(err, errBadCode) {
				t.Errorf("expired: %v", err)
			}
			for _, bad := range []string{"", "nope", code + "x", strings.Repeat("a", 4096)} {
				if _, err := s.Redeem(ctx, bad); !errors.Is(err, errBadCode) {
					t.Errorf("redeem %.10q: %v", bad, err)
				}
			}
		})
	}
}

// TestCodeStoreRace redeems one code from many goroutines (and, for Postgres, effectively many
// replicas): exactly one may win.
func TestCodeStoreRace(t *testing.T) {
	for name, mk := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			code, err := s.Issue(ctx, codeData{ClientID: "app", UserID: "alice", Scope: "openid", AuthTime: time.Now(), Exp: time.Now().Add(time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			var wins, bad atomic.Int32
			var wg sync.WaitGroup
			for range 20 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := s.Redeem(ctx, code)
					switch {
					case err == nil:
						wins.Add(1)
					case errors.Is(err, errBadCode):
						bad.Add(1)
					default:
						t.Error(err)
					}
				}()
			}
			wg.Wait()
			if wins.Load() != 1 || bad.Load() != 19 {
				t.Errorf("wins=%d rejected=%d, want 1 and 19", wins.Load(), bad.Load())
			}
		})
	}
}

// TestPostgresReplicas: a code issued by one provider and redeemed by another can't be replayed
// on either, which the memory store can't promise.
func TestPostgresReplicas(t *testing.T) {
	pool := testPool(t)
	a, b := newEnvStore(t, NewPostgresCodes(pool)), newEnvStore(t, NewPostgresCodes(pool))
	a.signIn("alice")
	redirect := "https://app.test/callback"
	code := a.code("app", redirect, nil)
	form := map[string][]string{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}}
	if s, body := b.exchange(form, "app", "s3cret-app-client-secret"); s != 200 {
		t.Fatalf("redeem on the other replica: %d %v", s, body)
	}
	for name, e := range map[string]*env{"a": a, "b": b} {
		if s, body := e.exchange(form, "app", "s3cret-app-client-secret"); s != 400 || body["error"] != "invalid_grant" {
			t.Errorf("replay on %s: %d %v", name, s, body)
		}
	}
}

// TestPostgresUnavailable: a store failure is a server error, not a bad code.
func TestPostgresUnavailable(t *testing.T) {
	dsn := os.Getenv(testDatabaseEnv)
	if dsn == "" {
		t.Skip(testDatabaseEnv + " not set")
	}
	testPool(t)
	pool, err := OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnvStore(t, NewPostgresCodes(pool))
	e.signIn("alice")
	redirect := "https://app.test/callback"
	code := e.code("app", redirect, nil)
	pool.Close()
	form := map[string][]string{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}}
	if s, body := e.exchange(form, "app", "s3cret-app-client-secret"); s != 500 || body["error"] != "server_error" {
		t.Errorf("token with store down: %d %v", s, body)
	}
	res := e.get(authorizeURL("app", redirect, nil))
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "error=temporarily_unavailable") {
		t.Errorf("authorize with store down: %d %s", res.StatusCode, loc)
	}
}

func TestPostgresCleanup(t *testing.T) {
	s := NewPostgresCodes(testPool(t))
	ctx := context.Background()
	now := time.Now()
	s.now = func() time.Time { return now }
	old, _ := s.Issue(ctx, codeData{ClientID: "app", UserID: "a", Scope: "openid", AuthTime: now, Exp: now.Add(-2 * time.Hour)})
	recent, _ := s.Issue(ctx, codeData{ClientID: "app", UserID: "a", Scope: "openid", AuthTime: now, Exp: now.Add(-time.Minute)})
	n, err := s.DeleteExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("deleted %d, %v", n, err)
	}
	var left int
	_ = s.pool.QueryRow(ctx, "SELECT count(*) FROM hankoid.oidc_auth_codes WHERE code_hash = ANY($1)", [][]byte{hashCode(old), hashCode(recent)}).Scan(&left)
	if left != 1 {
		t.Errorf("rows left = %d, want the recently expired one", left)
	}
}

func TestMigrateConcurrently(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "DROP SCHEMA hankoid CASCADE"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var total atomic.Int32
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			applied, err := Migrate(ctx, pool)
			if err != nil {
				t.Error(err)
			}
			total.Add(int32(len(applied)))
		}()
	}
	wg.Wait()
	migs, _ := migrations()
	if int(total.Load()) != len(migs) {
		t.Errorf("applied %d migrations in total, want %d", total.Load(), len(migs))
	}
	if applied, err := Migrate(ctx, pool); err != nil || len(applied) != 0 {
		t.Errorf("rerun: %v %v", applied, err)
	}
}

func TestDatabaseURL(t *testing.T) {
	for _, k := range []string{"DATABASE_URL", "DATABASE_HOST", "DATABASE_PASSWORD", "DATABASE_DIALECT", "DATABASE_PORT", "DATABASE_USER", "DATABASE_DATABASE"} {
		t.Setenv(k, "")
	}
	d, _ := LoadDatabase([]byte("database:\n  host: db\n  user: u\n  password: p@ss\n  database: h\n"))
	if u, err := d.URL(); err != nil || u != "postgres://u:p%40ss@db:5432/h" {
		t.Errorf("fields: %q %v", u, err)
	}
	t.Setenv("DATABASE_PASSWORD", "env")
	d, _ = LoadDatabase([]byte("database:\n  host: db\n"))
	if u, _ := d.URL(); u != "postgres://hanko:env@db:5432/hanko" {
		t.Errorf("env override: %q", u)
	}
	d, _ = LoadDatabase([]byte("database:\n  url: postgres://x@y/z\n  host: ignored\n"))
	if u, _ := d.URL(); u != "postgres://x@y/z" {
		t.Errorf("url wins: %q", u)
	}
	for _, y := range []string{"database:\n  dialect: mysql\n", "database:\n  url: mysql://x@y/z\n"} {
		d, _ = LoadDatabase([]byte(y))
		if _, err := d.URL(); err == nil {
			t.Errorf("%q should be rejected", y)
		}
	}
}

func TestStoreConfig(t *testing.T) {
	const base = "secrets:\n  keys: [0123456789abcdef]\noidc:\n  clients:\n    - id: my-app\n      secret: x\n      redirect_uris: [https://a/cb]\n      access: {any_user: true}\n"
	c, err := LoadConfig([]byte(base), "http://localhost:8080", "")
	if err != nil || c.Store != StoreMemory {
		t.Errorf("default store: %q %v", c.Store, err)
	}
	if _, err := LoadConfig([]byte(base+"  store: redis\n"), "http://localhost:8080", ""); err == nil {
		t.Error("unknown store accepted")
	}
	if _, err := LoadConfig([]byte(base+"  store: postgres\ndatabase:\n  dialect: mysql\n"), "http://localhost:8080", ""); err == nil {
		t.Error("postgres store with a mysql database accepted")
	}
	c, err = LoadConfig([]byte(base+"  store: postgres\ndatabase:\n  host: db\n"), "http://localhost:8080", "")
	if err != nil || c.Store != StorePostgres {
		t.Errorf("postgres store: %v", err)
	}
}
