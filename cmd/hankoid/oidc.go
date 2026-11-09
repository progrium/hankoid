package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/progrium/hankoid/frontend"
	"github.com/progrium/hankoid/oidc"
	"gopkg.in/yaml.v3"
)

// oidcHandlers builds the OIDC provider from the top-level oidc config key, or returns nil if
// no clients are configured. It also returns a labeler naming clients on the sign-in page.
func oidcHandlers(cfg frontend.Config, up frontend.Upstreams) (map[string]http.Handler, frontend.NextLabeler, error) {
	oc, err := oidc.LoadConfig(cfg.Raw, cfg.PublicURL, cfg.Dir)
	if err != nil {
		return nil, nil, err
	}
	if !oc.Enabled() {
		return nil, nil, nil
	}
	oc.TrustedProxies = cfg.TrustedProxies
	keys, err := oidc.LoadKeys(oc)
	if err != nil {
		return nil, nil, err
	}
	hanko := oidc.NewHanko(frontend.NewAuth(up.Public, cfg.AdminAccess), frontend.NewAdminAPI(up.Admin, frontend.AdminToken()))
	ctx := context.Background()
	store, pool, err := oidcCodeStore(ctx, oc)
	if err != nil {
		return nil, nil, err
	}
	p, err := oidc.New(oc, keys, hanko, store)
	if err != nil {
		return nil, nil, err
	}
	if pool != nil {
		ds, err := oidc.NewDeviceStore(pool, oc.SecretKeys)
		if err != nil {
			return nil, nil, err
		}
		go runDeviceCleanup(ctx, ds)
		p.SetDeviceStore(ds)
		if oc.DeviceEnabled() {
			log.Printf("oidc: device sign-in enabled at %s/device", strings.TrimSuffix(oc.Issuer, "/oidc"))
		}
	}
	warnOIDCSetup(cfg, oc)
	log.Printf("oidc: issuer %s with %d client(s)", oc.Issuer, len(oc.Clients))
	return p.Handlers(), p.Label, nil
}

func runDeviceCleanup(ctx context.Context, ds *oidc.DeviceStore) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := ds.DeleteExpired(ctx); err != nil {
				log.Printf("oidc: delete expired device rows: %v", err)
			}
		}
	}
}

// oidcCodeStore returns nil (the in-memory store) unless oidc.store is postgres. Then it connects
// to Hanko's database, applies the hankoid schema migrations, starts expiring old codes, and also
// returns the pool for the device store.
func oidcCodeStore(ctx context.Context, oc *oidc.Config) (oidc.CodeStore, *pgxpool.Pool, error) {
	if oc.Store != oidc.StorePostgres {
		log.Printf("oidc: codes are kept in memory; run a single instance (set oidc.store: postgres for restarts and replicas)")
		return nil, nil, nil
	}
	pool, err := openOIDCDatabase(ctx, oc)
	if err != nil {
		return nil, nil, err
	}
	if _, err := oidc.Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, nil, err
	}
	store := oidc.NewPostgresCodes(pool)
	go store.RunCleanup(ctx, 10*time.Minute)
	log.Printf("oidc: codes are kept in postgres (schema hankoid)")
	return store, pool, nil
}

func openOIDCDatabase(ctx context.Context, oc *oidc.Config) (*pgxpool.Pool, error) {
	dsn, err := oc.Database.URL()
	if err != nil {
		return nil, err
	}
	return oidc.OpenPostgres(ctx, dsn)
}

// warnOIDCSetup flags Hanko settings that commonly break the OIDC flow.
func warnOIDCSetup(cfg frontend.Config, oc *oidc.Config) {
	if strings.EqualFold(cfg.SessionSameSite, "strict") {
		log.Printf("oidc: session.cookie.same_site is strict; the Hanko session cookie won't be sent when clients redirect to /oidc/authorize, so users will always appear signed out. Set it to lax.")
	}
	for _, c := range oc.Clients {
		if c.Access != nil && c.Access.AnyUser {
			log.Printf("oidc: client %q allows any Hanko user (access.any_user); make sure self-registration is what you want", c.ID)
		} else if c.Access != nil && c.Access.Empty() {
			log.Printf("oidc: client %q has an empty access rule; nobody may sign in to it", c.ID)
		}
	}
	var tenant struct {
		Webauthn struct {
			RelyingParty struct {
				Origins []string `yaml:"origins"`
			} `yaml:"relying_party"`
		} `yaml:"webauthn"`
		Cors struct {
			AllowOrigins []string `yaml:"allow_origins"`
		} `yaml:"cors"`
	}
	_ = yaml.Unmarshal(cfg.Raw, &tenant)
	origin := cfg.PublicURL
	if u, err := url.Parse(origin); err == nil {
		origin = u.Scheme + "://" + u.Host
	}
	if len(tenant.Webauthn.RelyingParty.Origins) > 0 && !slices.Contains(tenant.Webauthn.RelyingParty.Origins, origin) {
		log.Printf("oidc: %s is not in webauthn.relying_party.origins; passkeys on /signin will fail", origin)
	}
	if len(tenant.Cors.AllowOrigins) > 0 && !slices.Contains(tenant.Cors.AllowOrigins, origin) {
		log.Printf("oidc: %s is not in cors.allow_origins; hanko-elements on /signin may fail", origin)
	}
}
