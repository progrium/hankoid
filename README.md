# hankoid

[Hanko](https://github.com/teamhanko/hanko) with a frontend: a sign-in page, an admin web UI generated from Hanko's admin OpenAPI spec, and an OpenID Connect provider so other apps can sign users in with Hanko. See [NOTES.md](./NOTES.md) for how the spec becomes UI, [oidc/README.md](./oidc/README.md) for running the OIDC provider and [oidc/PLAN.md](./oidc/PLAN.md) for its design.

## Layout

- `webui/`: the UI pages, `admin.html` (the admin UI) and `signin.html` (Hanko sign-in).
  - Normal builds embed them.
  - `-tags dev` builds read them from disk and add a live-reload endpoint.
- `frontend/`: the frontend server component. Add new frontend endpoints in `frontend.Handler`. Routes:
  - `/signin?next=…`: Hanko sign-in (hanko-elements). Already-signed-in visitors are redirected to `next`, which must be a same-origin path.
  - `/admin/`: the admin UI. Anonymous visitors are redirected to `/signin`; signed-in users not allowed by `admin_access` get a 403 page.
  - `/admin/api/*`: proxied to the Hanko admin API with the same protection. Mutations also need the `X-Admin-UI: 1` header.
  - `/admin/session`: the signed-in admin as JSON.
  - `/oidc/*`: the OIDC provider, when `oidc.clients` is configured (see [OIDC provider](#oidc-provider)).
  - Everything else goes to the Hanko public API, so hanko-elements can call it same-origin (login flow, `/logout`, `/sessions/validate`, …).
- `oidc/`: the OIDC provider (authorization code flow with PKCE, ID tokens, userinfo, end session).
- `cmd/hankoid`: the Hanko CLI (v3.1.0) rebuilt around Hanko's own command packages, with additions:
  - `serve frontend`: serves the frontend against a running admin/public server. It reads only the `server`, `session.cookie`, `secrets.keys` and `oidc` sections of the config, so no database connection is needed.
  - `serve all`: starts public, admin, management and frontend. `--no-frontend` skips the UI.
  - `license`: prints the full AGPLv3 license text. The top-level help and `version` also mention the license and source URL.
  - `version`: prints the hankoid and Hanko versions. It replaces upstream's, which depends on a file missing from the published module.
  - `oidc genkey [-o file]`: generates an RSA signing key for the OIDC provider.
  - `dev`: only in `-tags dev` builds.

## Configuration

Everything is read from the Hanko config file (`--config`, default `./config/config.yaml`). Hanko ignores keys it doesn't know, so hankoid adds two of its own: `server.frontend` and the top-level `oidc`. Everything else is plain Hanko config.

```yaml
server:
  public:
    address: ":8000"                 # Hanko default
  admin:
    address: "127.0.0.1:8001"        # keep on loopback: Hanko's admin API has no authentication
  frontend:
    address: "127.0.0.1:8080"        # default when unset
    public_url: "https://auth.example.com"   # externally visible origin; default http://localhost:<port>
    admin_access:                    # who may use /admin; empty denies everyone
      users:
        - admin@example.com          # a verified email,
        - alice                      # a username,
        - 3c2ad943-586a-4adc-b633-29a00c8bdb56   # or a user ID
      organization: staff            # and/or members of a Hanko organization (ID or exact name)
      roles: [admin]                 #   optionally holding one of these role slugs
    trusted_proxies: [10.0.0.0/8]    # reverse proxies (IPs/CIDRs) whose X-Forwarded-For is believed
secrets:
  keys: ["<at least 32 random characters>"]   # Hanko's key; also seals OIDC codes
session:
  cookie:
    same_site: lax                   # needed for OIDC; Hanko's default is strict
    secure: true                     # Hanko default; false only for plain-http localhost
webauthn:
  relying_party:
    id: auth.example.com
    origins: [https://auth.example.com]   # must include public_url for passkeys on /signin
cors:
  allow_origins: [https://auth.example.com]   # the frontend's origin, for hanko-elements
oidc:
  clients: []                        # see "OIDC provider"
```

- `public_url` is the origin users see. The OIDC issuer is derived from it (`{public_url}/oidc`), so it must be exactly what browsers and clients use. Plain `http` is only accepted for localhost.
- `server.frontend.admins` (a plain list) still works as an alias for `admin_access.users`.
- The frontend proxies to the public and admin addresses. A blank or wildcard host (`:8001`, `0.0.0.0:8001`) is dialed as `127.0.0.1`.
- The `--frontend-listen` / `--frontend-admin` / `--frontend-public` flags override the file and environment. The admin/public flags take full URLs, which may include a path prefix.

### Environment variables

Environment variables override the file. Lists are comma-separated.

| Variable | Overrides |
|---|---|
| `SERVER_PUBLIC_ADDRESS`, `SERVER_ADMIN_ADDRESS`, `SERVER_FRONTEND_ADDRESS` | listen addresses |
| `SERVER_FRONTEND_PUBLIC_URL` | `server.frontend.public_url` |
| `SERVER_FRONTEND_ADMINS` | `admin_access.users` |
| `SERVER_FRONTEND_ADMIN_ACCESS_ORGANIZATION`, `SERVER_FRONTEND_ADMIN_ACCESS_ROLES` | `admin_access.organization`, `.roles` |
| `SERVER_FRONTEND_TRUSTED_PROXIES` | `server.frontend.trusted_proxies` |
| `SESSION_COOKIE_SAME_SITE`, `SESSION_COOKIE_SECURE` | `session.cookie.same_site`, `.secure` |
| `SECRETS_KEYS` | `secrets.keys` |
| `OIDC_SIGNING_KEY` | `oidc.signing_key` (PEM) |
| `OIDC_CLIENTS_<ID>_SECRET` | a client's `secret` (`<ID>` uppercased, non-alphanumerics as `_`) |
| `OIDC_CLIENTS_<ID>_ACCESS_USERS` | a client's `access.users` |
| `HANKO_ADMIN_TOKEN` | bearer token the frontend sends to the admin API (not in the file) |

Hanko's own settings follow the same scheme (e.g. `DATABASE_PASSWORD`, `EMAIL_DELIVERY_SMTP_HOST`).

### Client IP and reverse proxies

- The frontend takes the TCP peer as the client IP. If the peer is in `trusted_proxies`, it uses the right-most `X-Forwarded-For` address that isn't itself a trusted proxy.
- The OIDC rate limiter keys on this IP, and `/signin` shows it in faint grey text in the bottom-right corner, so you can check what the server sees.
- To find the right value: deploy, open `/signin`, and compare the IP shown with your real one. If it shows a proxy's address, add that proxy (or its range) and check again. Only trust proxies that clients can't bypass; otherwise they can forge `X-Forwarded-For`.
- **Platforms where the app is only reachable through the platform's proxy** (e.g. Cloudflare Containers, reached only via a Worker): have the proxy *overwrite* `X-Forwarded-For` with the real client IP (on Cloudflare, `CF-Connecting-IP`), and set `trusted_proxies: [0.0.0.0/0, "::/0"]`. Never use that on a host that's directly reachable.

## Admin access

- `/admin` is protected by Hanko itself.
  - The frontend forwards the visitor's session cookie to the public API's `/sessions/validate`, which checks signature, expiry, revocation and idle timeout.
  - That response also lists the user's organizations and role slugs, fresh from the database, so access changes apply on the next request.
- The user is then checked against `server.frontend.admin_access`. They're allowed if either rule matches:
  - `users` matches by user ID, username or **verified** email, case-insensitive.
  - `organization` matches by membership (organization ID, or its exact, case-sensitive name), plus one of `roles` if set.
  - `any_user` isn't accepted here; an empty rule denies everyone.
- To bootstrap:
  1. Admins are ordinary Hanko users, so register at `/signin` and list yourself in `users`. Registration must be enabled in Hanko.
  2. To manage admins in the UI instead, create an organization (e.g. `staff`) with an `admin` role, add members, then set `organization` and `roles`.
  3. Keep at least one `users` entry as a break-glass path.
- The browser never sees the admin API token. Admin API calls carry `HANKO_ADMIN_TOKEN` from the server, and cookies are stripped before forwarding.
- Mutating `/admin/api` requests need the `X-Admin-UI: 1` header and are refused cross-site.

## OIDC provider

The frontend can act as an OpenID Connect provider, so other apps (e.g. listmonk, Grafana, Gitea) can sign users in with Hanko. It's enabled when `oidc.clients` is non-empty, and the issuer is `{public_url}/oidc`.

```yaml
session:
  cookie:
    same_site: lax              # required: strict cookies aren't sent on redirects from clients
oidc:
  signing_key_file: oidc.pem    # RSA key (hankoid oidc genkey -o oidc.pem); relative to the config file
  # previous_signing_key_file: oidc-old.pem   # still published in JWKS during key rotation
  # code_ttl: 60s, id_token_ttl: 5m, access_token_ttl: 5m
  clients:
    - id: myapp
      name: My App              # shown on the sign-in page ("Sign in to continue to My App")
      secret: ""                # ≥16 chars; or secret_hash (bcrypt), or OIDC_CLIENTS_MYAPP_SECRET
      redirect_uris: [https://app.example.com/auth/callback]   # exact match; https (http only for localhost)
      post_logout_redirect_uris: [https://app.example.com/]
      # scopes: [openid, email, profile]
      # require_pkce: false
      access:                   # required; who may sign in to this client
        users: [alice@example.com]
        organization: MyApp     # organization ID, or its exact (case-sensitive) name
        roles: [member]
        # any_user: true        # instead of the above: any Hanko user (incl. self-registered ones)
      roles_claim: false        # true: add "roles" (the user's role slugs in access.organization)
```

**Setting up a client:**

1. In the client app, set the provider/issuer URL to `{public_url}/oidc`. It finds everything else through discovery.
2. Add the app's callback URL to `redirect_uris`, exactly as the app sends it.
3. Generate a secret (e.g. `openssl rand -base64 32`), pass it as `OIDC_CLIENTS_<ID>_SECRET`, and give the same value to the app.
4. Decide who gets in with `access`. It's evaluated at authorize and again at token time.
5. Set `session.cookie.same_site: lax`, and a persistent signing key (below).

See [oidc/README.md](./oidc/README.md) for protocol details, the roles claim, key rotation and troubleshooting, and `.local/LISTMONK.md` for a worked example (not committed).

**Endpoints:**

- discovery at `/oidc/.well-known/openid-configuration`
- `/oidc/jwks.json`
- `/oidc/authorize`
- `/oidc/token` (authorization code + PKCE S256; `client_secret_basic` or `client_secret_post`)
- `/oidc/userinfo`
- `/oidc/logout` (RP-initiated logout). With a valid `id_token_hint` it signs out and redirects to an allowed `post_logout_redirect_uri`. Without one it shows a confirmation page, and only a same-origin POST from that page (with its CSRF token) signs out, so a link elsewhere can't log users out.

**Behavior:**

- **Sign-in flow:** `authorize` reuses the Hanko session. Without one, it sends the browser to `/signin`, which names the client and returns afterwards.
  - `prompt=login`, `prompt=none` and `max_age` are supported. `prompt=login` and an exceeded `max_age` don't sign out on the GET; they send the user to `/signin?fresh=1`, and the returned request only succeeds with a session created after that point.
  - A user the client's `access` rule doesn't allow gets `error=access_denied`.
- **ID tokens** are RS256 with `sub` (the Hanko user ID), `email`, `email_verified`, `nonce`, `sid` and `auth_time`. The `profile` scope adds `name`, `preferred_username` and similar claims; with `roles_claim`, the `roles` (or `profile`) scope adds `roles`.
- **Access tokens** are JWTs with header `typ: at+jwt`. Userinfo accepts only those, and logout's `id_token_hint` accepts only ID tokens (single configured audience, issued within 30 days). There are no refresh tokens.
- **Codes** are encrypted with a key derived (HKDF) from `secrets.keys`, so no storage is needed. Each one works once, for 60 seconds.
  - The token endpoint checks the Hanko session still exists and the user is still allowed, so a sign-out or revoked membership in between invalidates the code.
  - Userinfo does the same check.
  - Replay protection is in memory: run a single instance (see `oidc/PLAN.md` for the tables multiple instances would need).
- **Rate limiting** on `/oidc/token` is per client and per IP (see [Client IP](#client-ip-and-reverse-proxies)).

**Signing keys:**

- Tokens are signed with the provider's own key, published at `/oidc/jwks.json`, not Hanko's session key.
- Without a configured key, a temporary one is generated at startup. Every token issued before a restart then fails to verify, so this is only suitable for dev.
- Create one with `hankoid oidc genkey -o oidc.pem` (or `OIDC_SIGNING_KEY="$(hankoid oidc genkey)"`).
- To rotate: make the new key `signing_key_file`, set the old one as `previous_signing_key_file` so tokens it signed still verify, and drop it after the longest token lifetime (and the clients' JWKS cache time) has passed.

**Startup checks.** When `public_url` isn't localhost, startup fails unless:

- client secrets are at least 16 characters;
- `secrets.keys` are at least 32 characters and not a `change-me` placeholder;
- redirect URIs are `https`, without credentials.

It also warns when:

- `same_site` is still `strict`, or `none`;
- a client allows `any_user`, or has an empty access rule;
- the admin API isn't on loopback;
- `public_url` is https but `session.cookie.secure` is false;
- `public_url` isn't in `webauthn.relying_party.origins` or `cors.allow_origins`.

## Security

**Production checklist:**

- [ ] Hanko's admin API (`server.admin.address`) listens on loopback only and isn't published or exposed. It has **no authentication**: anything that can reach it can manage every user. Reach it only through `/admin`.
- [ ] TLS terminates in front of the frontend; `public_url` is `https`; `session.cookie.secure` is true.
- [ ] `secrets.keys` is a strong random value (≥32 characters), kept out of the config file (`SECRETS_KEYS`).
- [ ] `admin_access` lists the intended admins, with at least one `users` entry as a break-glass path.
- [ ] For OIDC: a persistent signing key, `same_site: lax`, client secrets from the environment, and an `access` rule per client.
- [ ] `trusted_proxies` matches your actual proxy chain (check the IP on `/signin`).
- [ ] Only the frontend's port is reachable from outside. Hanko's public port only needs to be reachable by the frontend, which already forwards the public API.
- [ ] Hanko's own settings reviewed: registration (`account.allow_signup`), email delivery, session lifetime.

**What's built in:**

- **Admin UI:** protected by Hanko sessions validated by Hanko itself, plus `admin_access`. The admin token stays server-side.
- **Pages:** strict CSP (scripts only from this origin), `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `nosniff`, `no-store`.
- **Scripts are vendored.** The pages load Mithril and hanko-elements from `/assets/` (`webui/vendor/`, embedded in the binary), pinned by version and checked by hash in `webui/vendor_test.go`. No CDN is involved. See `webui/vendor/README.md` to update them.
- **Redirects:** `/signin?next=` only accepts same-origin paths; OIDC redirect URIs must match exactly; errors are only redirected once the redirect URI is validated.
- **OIDC:** PKCE S256 (downgrade attempts are refused), single-use short-lived codes bound to the session, typed tokens, constant-time secret comparison, CSRF-safe logout, rate-limited token endpoint.

**Known limitations:**

- The session cookie is shared between the frontend and the Hanko public API it forwards. They're the same origin here, but a cookie `domain` covering other hosts would expose the session to them.
- OIDC replay protection and rate limits are in memory, per instance.
- Access tokens can't be revoked before they expire (5 minutes by default); userinfo does check the session is still alive.
- Hanko's own security (passcodes, passkeys, sessions) is upstream's; hankoid uses it unmodified.

## Usage

```sh
go build -o hankoid ./cmd/hankoid
./hankoid migrate up --config hanko.yaml
./hankoid serve all --config hanko.yaml       # admin UI at http://127.0.0.1:8080/admin/
./hankoid serve frontend --config hanko.yaml  # UI only, against an already-running Hanko

go build -tags dev -o hankoid-dev ./cmd/hankoid
./hankoid-dev dev
```

For local development, run `./dev` from a fresh checkout (needs Go and Docker). It starts the compose Postgres and Mailpit, runs migrations, then runs a `-tags dev` build of `serve all` on the host with live reload. On first run it creates `.local/` (gitignored) with a config (`.local/hanko.yaml`, admins from `ADMINS` or your git email) and an OIDC signing key. Edit the config freely; it's never overwritten.

## Docker

```sh
ADMINS=you@example.com docker compose up --build
```

- Services:
  - `postgres` (17), published on `127.0.0.1:5432`.
  - `mailpit`, which catches Hanko's emails (registration passcodes and so on). Inbox at http://localhost:8025, SMTP on `127.0.0.1:1025`.
  - `migrate`, which runs `migrate up` once.
  - `hankoid` (`serve all`): public `:8000` and frontend `:8080`, published on localhost. The admin API (`8001`) listens on the container's loopback only and isn't published.
- The image uses `deploy/config.yaml`; per-environment values come from env vars set in `compose.yaml`.
- Override with:
  - `ADMINS`: comma-separated admin allowlist.
  - `SECRETS_KEYS`: change it outside local use. The OIDC provider refuses to start with the placeholder when `ORIGIN` isn't localhost.
  - `POSTGRES_PASSWORD`
  - `ORIGIN` / `RP_ID`: the frontend's public URL and WebAuthn relying party ID.
  - `COOKIE_SECURE=true`: when served over TLS (required in production).
  - `COOKIE_SAME_SITE`: session cookie SameSite, default `lax`, which the OIDC provider needs.
  - `OIDC_SIGNING_KEY`: PEM signing key for the OIDC provider, e.g. `OIDC_SIGNING_KEY="$(hankoid oidc genkey)"`. Without it a temporary key is generated at each start.
  - `SMTP_HOST` / `SMTP_PORT`: send email through a real SMTP server instead of Mailpit.
  - `PLATFORM`: container platform, default `linux/arm64`. Use `linux/amd64` on x86 hosts. `./dev` sets it from `uname -m`.
  - `TRUSTED_PROXIES`: see [Client IP](#client-ip-and-reverse-proxies).
- Register at http://localhost:8080/signin (the passcode arrives in Mailpit), then open http://localhost:8080/admin/.
- The compose file is for local use: Mailpit and the defaults aren't production settings. See the [checklist](#security).

## Adding commands

- Add `cobra` commands in `cmd/hankoid`.
- Dev-only commands go in a `//go:build dev` file that appends to `registrars` in an `init` function (see `cmd/hankoid/dev.go`).
- To change an upstream command, register your own in place of the upstream `RegisterCommands` call in `newRootCmd`. `registerServe` does this for `serve`.

## License

AGPLv3. See [LICENSE](./LICENSE). This project builds on Hanko, whose backend is AGPLv3.
