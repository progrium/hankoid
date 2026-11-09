# OIDC provider in the frontend: plan

> **Status:** implemented. This is the design record; for running it, see [README.md](./README.md) and the [main README](../README.md#oidc-provider). Implemented in `oidc/`, `frontend/access.go`, `frontend/adminapi.go`, and `cmd/hankoid/oidc*.go`. Tests are in `oidc/provider_test.go` (an end-to-end run with go-oidc + oauth2, plus edge cases) and `frontend/*_test.go`. Deviations from the plan are noted below, and in "Security hardening" at the end.

Goal: let OIDC clients (relying parties) sign users in with Hanko. Hanko stays unmodified. The provider is a new `oidc` package mounted by the frontend, next to `/signin` and `/admin/`.

## Why the frontend, not a Hanko fork

The original sketch put the provider inside Hanko's public router. Here, Hanko is an imported module and the frontend is a separate HTTP server that already:

- serves a `<hanko-auth>` sign-in page at `/signin?next=…`, on the same origin as everything else;
- validates Hanko sessions by forwarding the browser's cookie to the public API's `/sessions/validate`, so Hanko checks signature, expiry, revocation and idle timeout;
- calls the admin API with `HANKO_ADMIN_TOKEN`, which can read users and sessions and delete sessions;
- reads its settings from the Hanko config file.

That covers almost everything the provider needs from Hanko, without forking:

| Need | Original sketch (fork) | Here (frontend) |
|---|---|---|
| Login page | separate page + `login_url` config | existing `/signin?next=` |
| "Is there a session?" at authorize | new helper from `middleware.parseToken` | existing `frontend.Auth.Session(r)` |
| User email, username, name | persisters | admin API `GET /users/{id}` |
| "Session still alive?" at token time | session persister | admin API `GET /users/{id}/sessions` |
| Logout | delete session row + clear cookie | forward to public `POST /logout` with the browser cookie; fall back to admin `DELETE /users/{id}/sessions/{sid}` |
| Signing key | Hanko JWK manager | the provider's own RSA key (see §3) |
| Sealing codes | `crypto/aes_gcm` + `secrets.keys` | the same package and keys, read from the config |
| Multi-tenant issuer | `/:tenant_id` in issuer | out of scope; the frontend is single-tenant |

The upstream code needs no changes and no new database tables, so updating Hanko stays as easy as bumping the module version.

## What a typical client needs

The baseline is a confidential web app using the authorization-code flow with a standard library such as `coreos/go-oidc/v3`. That library is already in our `go.sum`, as an indirect dependency of Hanko's own SSO.

- **Discovery** at `{issuer}/.well-known/openid-configuration`. The `issuer` must exactly match the URL configured in the client.
- **Authorize** with `state` and `nonce`, plus PKCE `S256` when discovery advertises it, so we advertise and support it.
- **Token**: an `id_token` signed RS256, with `aud = client_id`, the `nonce`, `sub`, `email` and `email_verified`.
- **Userinfo**: some clients only call it when claims are missing from the ID token. We always include the core claims, but implement userinfo anyway.
- **End session** (optional): `end_session_endpoint` with `id_token_hint`.
- Clients commonly match users **by email**, so `email_verified` must be accurate.

## 1. Routes and issuer

Mount everything under `/oidc/` so nothing collides with Hanko's public routes, which the frontend proxies at `/`. Hanko's own `/.well-known/jwks.json` stays untouched.

- **Issuer:** `{server.frontend.public_url}/oidc`, e.g. `https://auth.example.com/oidc`. It is derived from config, never from request headers (see §2).

| Route | Purpose |
|---|---|
| `GET /oidc/.well-known/openid-configuration` | Discovery (see §4). |
| `GET /oidc/jwks.json` | The provider's public signing keys. |
| `GET /oidc/authorize` | Validate the request; redirect to `/signin` if there's no session, otherwise issue a code. |
| `POST /oidc/token` | Exchange the code for an ID token and an access token. |
| `GET, POST /oidc/userinfo` | Claims for a bearer access token. |
| `GET /oidc/logout` | End session. |

**Integration:** `cmd/hankoid` mounts `oidc.Handler(...)` at `/oidc/` through a new `frontend.Options.Extra` map, only when the config has clients. That way `frontend` never imports `oidc` (see §5). The `oidc` package receives what it needs through a small interface:

```go
type Hanko interface {
    Session(r *http.Request) (*frontend.Session, error)               // existing Auth.Session
    User(ctx context.Context, id string) (*User, error)                // admin GET /users/{id}
    SessionAlive(ctx context.Context, userID, sessionID string) (bool, error) // admin GET /users/{id}/sessions
    Logout(w http.ResponseWriter, r *http.Request) error               // public POST /logout with cookie
}
```

**Interface change:** `frontend.Session` gains `SessionID`, taken from the `session_id` claim, and `Organizations`. `/sessions/validate` already returns both.

**Access control:** the existing `X-Admin-UI`/`Sec-Fetch-Site` checks stay on `/admin/api/` only.

**CORS:**
- Discovery, JWKS and userinfo get permissive CORS (`Access-Control-Allow-Origin: *`, no credentials).
- Authorize, token and logout get none.

## 2. Config

The provider config is a top-level `oidc` key in the same Hanko config file, next to Hanko's own `saml` and `third_party`. Where the server listens and its public URL stay under `server.frontend`, where the frontend's other server settings already live.

- **Hanko ignores unknown top-level keys.** Its loader unmarshals only into its own struct, without strict mode. I checked that `config.Load` accepts a config with a top-level `oidc:` block.
- **Risk:** if a future Hanko release adds its own top-level `oidc` key, the two would collide.
  - Hanko's existing keys are `account`, `audit_log`, `cors`, `custom_claims`, `database`, `debug`, `default_email_delivery`, `email`, `email_delivery`, `flow_locker`, `log`, `mfa`, `multi_tenancy`, `passkey`, `password`, `privacy`, `rate_limiter`, `saml`, `secret_keys`, `secrets`, `security_notifications`, `server`, `service`, `session`, `third_party`, `username`, `webauthn` and `webhooks`. None of them is `oidc`.
  - Mitigation: add a test that loads Hanko's config struct and fails if it gains an `oidc` field, so a Hanko upgrade can't collide silently. Hanko already uses `oidc` in names of its *client* SSO code but has no provider config.
- `frontend.LoadServerConfig` becomes `frontend.LoadConfig` and still reads only `server.*`. The new `oidc.LoadConfig` reads the top-level `oidc` key from the same file, and `cmd/hankoid` loads both.

```yaml
server:
  frontend:
    address: ":8080"
    public_url: https://auth.example.com      # externally visible frontend URL (new; see below)

oidc:
  signing_key_file: /secrets/oidc.pem          # RSA private key, PEM; see §3
  code_ttl: 60s
  id_token_ttl: 5m
  access_token_ttl: 5m
  clients:
    - id: myapp
      name: My App                             # shown on the sign-in page
      secret: ""                               # or secret_hash (bcrypt); see env below
      redirect_uris: [https://app.example.com/auth/callback]
      post_logout_redirect_uris: [https://app.example.com/]
      scopes: [openid, email, profile]
      require_pkce: false
      access:                                  # who may sign in; see §2a
        users: [alice@example.com]             # static list (IDs, usernames, verified emails)
        organization: myapp                    # and/or members of a Hanko organization
        roles: []                              # empty = any member
      roles_claim: false                       # emit "roles" (slugs in access.organization); see §2b
```

The provider is enabled when `oidc.clients` is non-empty. There's no separate `enabled` flag, since an empty client list serves nothing useful.

**`server.frontend.public_url`** is a new frontend setting, alongside the existing `address`. It's the frontend's externally visible URL, the same idea as Hanko's own externally visible settings such as `webauthn.relying_party.origins`.
- It defaults to `http://` + `address` with wildcard hosts mapped to `localhost`, e.g. `http://localhost:8080`, so local dev needs no setting.
- The issuer is always `{public_url}/oidc`, with no separate `issuer` key, so the two can't drift apart.
- `SERVER_FRONTEND_PUBLIC_URL` overrides it.
- Startup warns if `public_url`'s origin isn't in `webauthn.relying_party.origins` or `cors.allow_origins`, since passkeys and hanko-elements need it there.

- **Environment overrides:**
  - `SERVER_FRONTEND_PUBLIC_URL`
  - `OIDC_SIGNING_KEY` (the PEM itself)
  - `OIDC_CLIENTS_<ID>_SECRET`, e.g. `OIDC_CLIENTS_MYAPP_SECRET`, so secrets stay out of the file and compose can pass them in. These follow Hanko's own naming (the key path, uppercased with `_`), so they look like Hanko's `SECRETS_KEYS` or `DATABASE_PASSWORD`.
- **Validation** at startup:
  - `public_url` is absolute and HTTPS, except `http://localhost` / `127.0.0.1` for dev, with no path, query or fragment.
  - Each client has a unique ID, a non-empty secret or secret hash, and at least one absolute redirect URI.
  - Redirect URIs must have no fragment and are matched exactly.
  - `scopes` includes `openid`.
  - The TTLs are positive.
  - `access.roles` requires `access.organization`, and so does `roles_claim: true`. The same check applies to `server.frontend.admin_access`.

### 2a. Who may sign in to a client

Each client has an optional `access` block with two kinds of rules, usable separately or together:

```yaml
oidc:
  clients:
    - id: myapp
      access:
        users:                       # static list, matched like server.frontend.admins
          - alice@example.com        # verified email
          - bob                      # username
          - 3c2ad943-586a-4adc-b633-29a00c8bdb56   # user ID
        organization: myapp          # Hanko organization, by ID or exact name
        roles: [admin, editor]       # optional; empty = any member of the organization
```

- **Semantics:**
  - A user is allowed if they match `users` **or** satisfy the organization rule.
  - The `access` block is **required** (security pass 2). `any_user: true` admits every Hanko user, explicitly, and startup logs it. It can't be combined with `users`/`organization`.
  - With `access` present but empty, nobody may, mirroring `admins: []`.
- **Static list (`users`):**
  - Entries are user IDs, usernames or **verified** emails, case-insensitive. This is exactly the matching `server.frontend.admins` uses; extract it from `Auth.IsAdmin` into a shared `matchUser(entries, session)`.
  - Best for a handful of people, or for bootstrapping before any organization exists. Every change is a config edit plus a restart.
  - Env override: `OIDC_CLIENTS_<ID>_ACCESS_USERS`, comma-separated, like `SERVER_FRONTEND_ADMINS`.
- **Organization rule (`organization`, `roles`):**
  - Hanko already stores organizations, memberships and role bindings, and the admin UI already manages them (Organizations → members → roles). Access is managed where users are managed, with no new storage and no config edits per person.
  - The frontend's existing `/sessions/validate` call already returns the user's `organizations` with role slugs, read fresh from the database on every call. So the check costs no extra request, and revoking membership takes effect at the next authorize.
- **What each piece needs to know:**
  - The client config holds the rule above, and nothing else.
  - `frontend.Session` gains `Organizations []{ID, Name, Roles}` from the validate response.
  - The `oidc` package evaluates the rule at authorize (`error=access_denied` if it fails) and again at token time, when the session-alive check re-validates the session.
  - The client needs no access rules of its own. What the user may do inside the client stays the client's business, unless it maps the roles claim (§2b).

**`/admin` uses the same rule shape.** `server.frontend.admin_access` has the same `{users, organization, roles}` shape as a client's `access`:

```yaml
server:
  frontend:
    admin_access:
      users: [progrium@gmail.com]    # bootstrap / break-glass
      organization: hankoid          # optional; once set up, manage admins in the admin UI
      roles: [admin]
```

- **Bootstrap:** start with `users`, sign in and create the organization in the admin UI. Add yourself and others as members with role `admin`, then add `organization`/`roles` to the config. From then on, admins are managed in the UI. Keep at least one `users` entry so a broken organization can't lock everyone out.
- **Compatibility:** the existing `server.frontend.admins` and `SERVER_FRONTEND_ADMINS` stay as aliases for `admin_access.users`. If both are set, the lists are merged.
- **Differences from clients:**
  - For `/admin`, a missing or empty rule denies everyone, with a startup warning, as today. Admin access must never be open by default.
  - For OIDC clients, a missing `access` block is a config error; open clients must say `any_user: true`. `/admin` rejects `any_user`.
- **Shared code:** a new `frontend/access.go` defines `AccessRule{Users, Organization, Roles}` with `Allows(*Session) bool`.
  - `Auth.IsAdmin` becomes `adminRule.Allows(s)`, and the `oidc` package uses the same type for clients.
  - `oidc` imports it from `frontend`, so `frontend` must not import `oidc` (see §5).
  - Matching `organization`: compare against the organization ID, or exactly against its name (case-insensitive name matching was dropped in the security review). `/sessions/validate` returns `id` and `name` but no slug, so "by slug" means by name.

### 2b. A `roles` claim

OIDC Core has no standard claim for roles or groups. Each provider invents one: Keycloak's `realm_access.roles`, Entra ID's `roles`, Okta's and Authentik's `groups`, and so on. Clients that support role mapping let you point them at a claim, e.g. Grafana's `role_attribute_path` (a JMESPath expression) or Gitea's group claim name. So the value of a roles claim depends entirely on whether the client can consume it.

**What it would carry.**
- The role slugs the user holds **in the client's `access.organization` only**, e.g. `["editor"]`. Never roles from other organizations: that would leak unrelated memberships to every client.
- No organization rule on the client → no roles to emit, so the claim is omitted.
- Users let in only by the static `users` list get an empty list.

**Freshness:**
- The ID token value is a snapshot from sign-in time.
- Userinfo re-reads the session (`/sessions/validate`), so it always reflects current membership.
- Clients that sync roles on every sign-in pick up changes on the next sign-in.

**Minimal version (first version).** One per-client switch, with no mapping and no static roles:

```yaml
oidc:
  clients:
    - id: grafana
      access:
        organization: grafana
      roles_claim: true            # emit "roles" with the user's role slugs in access.organization
```

- **Claim:** `roles`, an array of role slug strings, e.g. `["admin"]`. Only the client's organization is used; without `access.organization`, `roles_claim: true` is a validation error.
- **When included:** if `roles_claim` is on and the request asked for the `roles` scope or `profile`, so clients that don't ask still get it via the common `profile` scope. It goes in both the ID token and userinfo.
  - A user admitted only via `access.users` gets `roles: []`.
  - Discovery adds `roles` to `scopes_supported` and `claims_supported` when any client enables it.
- **Deferred until a client needs them:**
  - a custom claim name, e.g. `groups`;
  - a slug → value `map`, e.g. `admin` → `Admin`;
  - static roles for `users` entries;
  - an `organization` claim.
  - Each is additive; e.g. `roles_claim: true` can later become `roles_claim: {name: groups, map: {…}}` with `true` still meaning the defaults.

**Clients that can't map claims** simply ignore `roles`. For them, use `access` to decide *who* gets in, and manage permissions inside the client.

**Cautions:**
- **Trust:** a roles claim grants privileges in the client, so it's only safe if the client checks `iss` and `aud`. That's one more reason to keep ID tokens off Hanko's session key (§3).
- **Freshness:** a client that only reads roles at sign-in keeps stale roles until the user signs in again. If a client needs faster revocation, keep ID and access token lifetimes short (5 minutes by default). Its own session lifetime is out of our control.
- **Size:** emit slugs, not full objects. Avoid listing every organization.

### 2c. Hanko session settings

The operator must set these Hanko session settings. They are checked at startup by reading the `session.cookie` section of the same config:

- `session.cookie.same_site: lax`. The default `strict` cookie isn't sent on the cross-site top-level navigation from the client to `/oidc/authorize`, so the user would always look logged out. Log a warning if it's `strict`.
- Cookie mode, not `session.enable_auth_token_header`; a browser redirect only carries cookies.
- `session.cookie.domain` can usually stay unset. `/signin`, `/oidc/*` and the proxied Hanko API are all served by the frontend, so it's one origin.

## 3. Keys and statelessness

**Signing key (RS256).**
- Configured via `oidc.signing_key_file` / `OIDC_SIGNING_KEY`. The `kid` is the RFC 7638 thumbprint, and it's published at `/oidc/jwks.json`.
- Key rotation: accept an optional `previous_signing_key_file`, which is published in JWKS but never used to sign.
- If no key is configured, `hankoid` generates one on startup and logs a warning that tokens won't verify across restarts or replicas. That's fine for dev only.
- **Why a provider-owned key rather than Hanko's JWK set:**
  - *No database or Hanko internals in `serve frontend`.* Hanko keeps its private keys encrypted in its `jwks` table and only unseals them inside the server, via the JWK manager and `secrets.keys`. Signing with them would mean `serve frontend` opens the database and depends on Hanko's internal key manager API, which can change between Hanko releases, and the AWS KMS mode works differently again. Today `serve frontend` needs only the `server` section of the config.
  - *Different token types under one key are a confusion risk.* Hanko session JWTs and our ID tokens would be signed by the same key and published in the same JWKS, and apps that accept Hanko session tokens look up keys in that JWKS. An ID token issued to a client, with `aud=<client_id>`, would also verify against it. A Hanko-session consumer that doesn't strictly check `aud`/`iss` could then accept an ID token as a session, or the reverse. Separate keys and a separate JWKS (`/oidc/jwks.json`) remove that whole class of mistake.
  - *Independent lifecycle.* Rotating, revoking or leaking the OIDC key doesn't touch Hanko sessions, and the other way round.
  - *Nothing gained by sharing.* OIDC clients only ever fetch the key from our discovery document. No client needs it to be Hanko's.
  - Revisit only if a consumer must verify Hanko session tokens and ID tokens with one JWKS URL.
- **Single instance:** a generated key would work until a restart, then every outstanding ID or access token would fail to verify. Set `signing_key_file` (or the env var) in any deployment that isn't throwaway dev, or use the `oidc_keys` table below.

**Authorization code.** A sealed blob, not stored anywhere.
- It's encrypted with Hanko's `crypto/aes_gcm` (importable, no DB) keyed with `secrets.keys` from the config. Those keys are already required and shared across replicas.
- Payload: `{jti, client_id, redirect_uri, user_id, session_id, nonce, code_challenge, scope, auth_time, exp}`.
- At `/oidc/token`:
  - Open it, then check the client, redirect URI, expiry and PKCE.
  - Then call `SessionAlive(user_id, session_id)`, so a logout in between invalidates the code.
- **Single use:** an in-memory set of used `jti` values, kept until they expire. This is a single-instance deployment, so the set is exact. The only gap is a restart within a code's 60-second lifetime, which clears the set. A replay in that window still needs the client secret, a matching PKCE verifier and a live session, so that's acceptable. If it isn't, use the Postgres store below.

**Optional: Postgres as the provider's store.** Not needed for a single instance. These are the tables to add if we later want restart-safe codes, replicas, revocation, or managing clients from the admin UI instead of config.

> **Status:** the authorization-code part is built, as `oidc.store: postgres` (`oidc/pgstore.go`, migrations in `oidc/migrations/`). Differences from the sketch below: `user_id`/`session_id` are `text` (no type coupling to Hanko's IDs), `session_id` is nullable, expiry is checked against the provider's clock like the memory store, and migrations run at startup under an advisory lock as well as through `hankoid oidc migrate`. `oidc_clients`, `oidc_keys` and `oidc_access_tokens` are not built.

- Use the same database as Hanko, but our own schema (`hankoid`) so Hanko's migrations never see or touch them.
- Migrate with an embedded SQL file run by a new `hankoid migrate oidc` (or as part of `serve`).

```sql
CREATE SCHEMA IF NOT EXISTS hankoid;

-- Clients, if managed in the DB instead of (or in addition to) config.
CREATE TABLE hankoid.oidc_clients (
  id                        text PRIMARY KEY,           -- client_id
  name                      text NOT NULL,
  secret_hash               text NOT NULL,              -- bcrypt
  redirect_uris             text[] NOT NULL,
  post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
  scopes                    text[] NOT NULL DEFAULT '{openid,email,profile}',
  require_pkce              boolean NOT NULL DEFAULT false,
  access_organization_id    uuid,                       -- Hanko organization ID (no FK across schemas on purpose)
  access_roles              text[] NOT NULL DEFAULT '{}',
  created_at                timestamptz NOT NULL DEFAULT now(),
  updated_at                timestamptz NOT NULL DEFAULT now()
);

-- Single-use authorization codes. Exact replay protection across restarts and replicas;
-- codes could then be random handles instead of sealed blobs.
CREATE TABLE hankoid.oidc_auth_codes (
  code_hash      bytea PRIMARY KEY,                     -- sha256(code); never store the code itself
  client_id      text NOT NULL,
  user_id        uuid NOT NULL,                         -- Hanko user ID
  session_id     uuid NOT NULL,                         -- Hanko session ID
  redirect_uri   text NOT NULL,
  scope          text NOT NULL,
  nonce          text,
  code_challenge text,
  auth_time      timestamptz NOT NULL,
  expires_at     timestamptz NOT NULL,
  used_at        timestamptz                            -- set atomically: UPDATE … SET used_at = now() WHERE used_at IS NULL
);
CREATE INDEX ON hankoid.oidc_auth_codes (expires_at);

-- Signing keys, shared across instances and rotated without file juggling.
CREATE TABLE hankoid.oidc_keys (
  kid         text PRIMARY KEY,                         -- RFC 7638 thumbprint
  private_pem text NOT NULL,                            -- encrypted with aes_gcm + secrets.keys, like Hanko's jwks table
  created_at  timestamptz NOT NULL DEFAULT now(),
  active      boolean NOT NULL DEFAULT false,           -- exactly one signing key
  retired_at  timestamptz                               -- still published in JWKS until all tokens it signed expire
);

-- Only if access tokens must be revocable before expiry (e.g. "sign out everywhere" for a client).
CREATE TABLE hankoid.oidc_access_tokens (
  jti        uuid PRIMARY KEY,
  client_id  text NOT NULL,
  user_id    uuid NOT NULL,
  session_id uuid NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX ON hankoid.oidc_access_tokens (session_id);
```

- **Cleanup:** delete expired rows from `oidc_auth_codes` and `oidc_access_tokens` periodically, e.g. a ticker in `serve`, or a `hankoid cleanup oidc` command next to Hanko's `cleanup`.
- **What would still not need tables:**
  - Sessions and users, which stay in Hanko.
  - Organization-based access (§2a), which is Hanko's own data.
  - ID tokens, which are stateless.
- **Cost of adopting this:** `serve frontend` would need the database connection settings (`database.*` from the same config file). Today it deliberately doesn't. Gate it behind an `oidc.store: postgres` setting, defaulting to `memory`.

**Access token.**
- A JWT signed with the provider key.
- Claims: `iss`, `sub`, `aud = {issuer}/userinfo`, `client_id`, `scope`, `sid`, `exp` (5 minutes), and `jti`.
- At userinfo: verify the token, check `SessionAlive`, then read the user fresh from the admin API.
- **No refresh tokens** in the first version; typical web-app clients sign in again when their own session ends.

## 4. Endpoints in detail

**Discovery** is built from config:
- `issuer`
- `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint` and `end_session_endpoint`
- `jwks_uri`: `{issuer}/jwks.json`
- `response_types_supported: [code]`
- `subject_types_supported: [public]`
- `id_token_signing_alg_values_supported: [RS256]`
- `code_challenge_methods_supported: [S256]`
- `token_endpoint_auth_methods_supported: [client_secret_basic, client_secret_post]`
- `grant_types_supported: [authorization_code]`
- `scopes_supported: [openid, email, profile]`, plus `roles` when any client enables the roles claim
- `claims_supported`

**Authorize:**
1. Validate:
   - `client_id` exists and `redirect_uri` exactly matches its list. If either fails, render an error page and **never redirect**.
   - Then check `response_type=code` and that `scope` contains `openid`.
   - If a `code_challenge` is present, `code_challenge_method` must be `S256`. If the client has `require_pkce`, a challenge is required.
   - From here on, errors redirect to `redirect_uri?error=…&state=…`.
2. Look up the session with `Hanko.Session(r)`, the existing cookie-forwarding validation.
3. If there's no session, or `prompt=login`, or the session is older than `max_age`, redirect to `/signin?next=<this authorize URL>`.
   - The existing `safeNext` already blocks open redirects, since only same-origin paths are allowed.
   - For `prompt=login`, redirect with `prompt` removed, so it doesn't loop. (Built differently: no sign-out on GET; see "Security hardening".)
   - `prompt=none` with no session → `error=login_required`.
4. If the client has an `access` block and the user matches neither its `users` list nor its organization rule (§2a) → `error=access_denied`.
5. Seal a code and redirect with 302 to `redirect_uri?code=…&state=…`.

`auth_time`: Hanko's validate response has no session creation time. Use the token's `iat` from the claims if present. Otherwise read `created_at` from admin `GET /users/{id}/sessions`, which is also needed for `max_age`.

**Token:**
- Accepts only `grant_type=authorization_code`.
- Client authentication via Basic or form fields. Secrets are compared in constant time, or with bcrypt for `secret_hash`.
- Responses always carry `Cache-Control: no-store` and `Pragma: no-cache`.
- Errors are RFC 6749 JSON: `invalid_client` (401, with `WWW-Authenticate`), `invalid_grant`, `invalid_request`, `unsupported_grant_type`.
- Rate limited per client and IP with a small token bucket (`golang.org/x/time/rate`).
- On success, returns `access_token`, `token_type: Bearer`, `expires_in`, `id_token` and `scope`.

**ID token claims:**
- Always: `iss`, `sub` (the Hanko user ID), `aud` (the client ID), `azp`, `exp`, `iat`, `auth_time`, `nonce` and `sid`.
- From the admin API user record: `email` and `email_verified`, using the primary email.
- With the `profile` scope: `name`, `given_name`, `family_name`, `preferred_username` (the username) and `picture`, when set.
- With `roles_claim: true` and the `roles` or `profile` scope: `roles` (§2b).

**Userinfo:**
- Takes a bearer access token in the header, or `access_token` in a POST body.
- Returns `sub` plus the same email/profile claims, limited by the token's scope.
- On an invalid token: `401` with `WWW-Authenticate: Bearer error="invalid_token"`.

**Logout (end session):**
1. Verify `id_token_hint` if present. An expired one is accepted for this purpose, but the signature and `iss` must be valid.
2. Call `Hanko.Logout`, which forwards the browser cookie to public `POST /logout`. Hanko deletes the session row and returns a cookie-clearing `Set-Cookie`, which we pass through.
3. If there's no cookie but the hint has a `sid`, delete it via admin `DELETE /users/{sub}/sessions/{sid}`.
4. Redirect to `post_logout_redirect_uri` if it exactly matches the client's list, appending `state`. Otherwise show a "signed out" page.

## 5. Package layout

```
oidc/
  PLAN.md
  config.go      // Config, Client, Load from top-level oidc + env, Validate
  keys.go        // signing key load/generate, JWKS, kid thumbprint
  code.go        // seal/open authorization codes (aes_gcm), replay set
  provider.go    // Handler(cfg, Hanko) http.Handler; discovery, authorize, token, userinfo, logout
  hanko.go       // Hanko interface + adapter over frontend.Auth and the admin/public proxies
  errors.go      // RFC 6749 error helpers
  provider_test.go
  e2e_test.go
```

- **JWT signing and verification:** use `github.com/lestrrat-go/jwx/v2`, which Hanko already depends on, so no new module tree.
- **Tests and dev:** `github.com/coreos/go-oidc/v3` + `golang.org/x/oauth2`.

**`frontend` changes:**
- **Dependency direction:** `oidc` imports `frontend` (for `Session` and `AccessRule`), and `frontend` must not import `oidc`. So `frontend.LoadConfig` reads `server.*` only, `oidc.LoadConfig` reads the top-level `oidc` key, and `cmd/hankoid` wires them together: it builds the frontend handler and mounts `oidc.Handler` at `/oidc/` through an `Extra map[string]http.Handler` option on `frontend.Options`.
- `ServerConfig` gains `PublicURL` and `AdminAccess AccessRule` (merged with the legacy `admins`).
- New `access.go` with `AccessRule`; `Auth.IsAdmin` delegates to it.
- `Session` gains `SessionID` and `Organizations` (from `/sessions/validate`).
- Admin-API helpers move out of the proxy closure into small methods: `getJSON(path)` and `delete(path)` with the bearer token.
- The default sign-in page stays generic. When `next` is an `/oidc/authorize` URL, add the client name ("Sign in to continue to My App", from the client's `name`) by reading the client ID from `next`.

**`hankoid`:** no new flags. `serve frontend` and `serve all` pick up the top-level `oidc` key automatically.

**Local dev:** a real client setup for manual testing lives outside this plan (e.g. `.local/LISTMONK.md`).

## 6. Build order

1. **Shared access rule and admin access.** `frontend.AccessRule`, `server.frontend.admin_access` with the `admins` alias, and `Session.Organizations`, which `/admin` now needs too. Done first because it's useful on its own and `oidc` builds on it.
2. **Config.** `server.frontend.public_url` (with default and env override) in `frontend.LoadConfig` (renamed from `LoadServerConfig`). Then `oidc.LoadConfig` with env overrides and validation, wired up in `cmd/hankoid`. Unit tests for validation.
3. **Keys and discovery.** Signing key load/generate, `/oidc/jwks.json`, `/oidc/.well-known/openid-configuration`. Check that `oidc.NewProvider(ctx, issuer)` from go-oidc initializes against it.
4. **Hanko adapter.**
   - Add `SessionID` to `frontend.Session`.
   - Implement `User` (admin `GET /users/{id}`), `SessionAlive` (admin `GET /users/{id}/sessions`) and `Logout` (public `POST /logout`).
   - Test against the fake Hanko in `frontend_test.go`, extended.
5. **Authorize.** Request validation, the redirect to `/signin`, `prompt`/`max_age`, the `access` check (via `AccessRule`), and sealed codes. Show the client name on the sign-in page.
6. **Token.** Client auth, code open, PKCE, session-alive check, replay set, ID and access token signing, rate limit, RFC 6749 errors.
7. **Userinfo.** Include the minimal roles claim here and in the ID token.
8. **Logout.**
9. **Tests:**
   - Table tests: unknown client, bad redirect (no redirect issued), missing `openid`, PKCE mismatch or missing when required, expired code, replayed code, code whose session was deleted, wrong client secret, nonce passthrough, `prompt=none`, a user admitted by `users` only, by organization only, rejected by both, an organization member lacking a required role, and a membership revoked between authorize and token.
   - Roles claim: only the client's organization's roles appear, `[]` for `users`-only admits, omitted when `roles_claim` is off or neither `roles` nor `profile` is requested, and present in both the ID token and userinfo.
   - `/admin` with `admin_access`: admitted via `users`, via organization role, denied for a member without the role; the `admins` alias still works; empty means deny.
   - End-to-end: a real go-oidc + `oauth2` client (the libraries typical Go clients use) against `httptest` servers for the fake Hanko and the frontend. It follows redirects with a cookie jar through authorize → `/signin` → (fake session) → authorize → callback → token, then verifies the ID token with go-oidc and calls userinfo.
10. **Manual check with a real client** (see `.local/LISTMONK.md`).
11. **Docs:** README "OIDC provider" section with a config example and the cookie `same_site: lax` requirement. Update "Admin access" for `admin_access`, including the bootstrap steps.

## Implementation notes

- **Sign-in label:** the client name reaches `/signin` as a server-set `?to=` parameter.
  - `frontend.Options.Labelers` lets `oidc` name an `/oidc/authorize` destination.
  - `/signin` redirects to set or correct `to`, so a link can't spoof it.
  - For `/admin` destinations, the page shows "Hanko Admin".
- **Callback `iss`:** authorize also adds `iss` to the callback (RFC 9207, mix-up protection). Clients that don't know it ignore it.
- **Roles source:** the roles claim and organization access at token and userinfo time come from the admin API user record, which includes organizations and role slugs. At authorize time they come from `/sessions/validate`.
- **Rate limit:** 10-request burst, refilling at 1/s, per peer IP and per client, in memory.
- **`oidc genkey`:** a new CLI command. `.local/dev` uses it to create `.local/oidc-signing.pem` on first run.
- **Config loading:** `frontend.Config` carries the raw file and its directory. `oidc.LoadConfig(raw, publicURL, dir)` reads the top-level `oidc` key, and relative key paths resolve against the config file's directory.
- **Upgrade guard:** `TestHankoConfigHasNoOIDCKey` fails if Hanko's config struct gains a top-level `oidc` key.

## Decisions

- **Deployment:** single instance by default: codes use sealed blobs plus an in-memory replay set. `oidc.store: postgres` keeps codes in the `hankoid` schema for restarts and replicas (added later; see §3).
- **Signing key:** provider-owned (rationale in §3). Configure it with `oidc.signing_key_file` or `OIDC_SIGNING_KEY`; it's generated on startup only for dev.
- **Config location:** a top-level `oidc` key in the Hanko config file. `server.frontend` keeps `address` and `public_url`.
- **Access:** per-client `access` with a static `users` list and/or an organization rule (`organization` + `roles`). Either rule admits the user. `access` is required; `any_user: true` opens a client to every Hanko user (changed in the security review).
- **Public URL:** a new `server.frontend.public_url`; the issuer is `{public_url}/oidc`.
- **Admin access:** `/admin` uses the same rule shape, as `server.frontend.admin_access`. The static `users` list bootstraps, organization and roles are optional, and `admins` stays as an alias. An empty rule denies.
- **Roles claim:** minimal version, a per-client `roles_claim: true` that emits `roles` with slugs from `access.organization`. Name mapping, value mapping and static roles are deferred.

## Open questions

- None blocking. Revisit the deferred roles-claim options when a client that maps roles is added.

## Security hardening (second review)

Changes made after a security review of this repo's code:

- **Scripts are vendored.** hanko-elements and Mithril are served from `/assets/` (embedded, hash-checked by a test) instead of a CDN. The CSPs allow only `'self'` scripts, so a compromised CDN can't steal sessions on `/signin` or `/admin`.
- **The Hanko admin API stays on loopback.** It has no authentication; `deploy/config.yaml` binds it to `127.0.0.1:8001`, the image no longer exposes 8001, and the frontend warns at startup when it isn't loopback.
- **Logout CSRF.** `GET /oidc/logout` signs out only with a valid `id_token_hint`. Without one it shows a confirmation page; the sign-out is a `POST` that must be same-origin (`Origin` or `Sec-Fetch-Site`) and carry a double-submit token (`hankoid_logout` cookie, SameSite=Strict).
- **`id_token_hint` validation.** It must be one of our ID tokens: valid signature and issuer, not an access token (`typ: at+jwt`), a single audience that is a configured client (matching `client_id` if given), and issued within 30 days. Expired hints are accepted, per the spec.
- **No sign-out on `prompt=login` / `max_age`.** Instead of logging out on a GET, authorize sends the user to `/signin?fresh=1` and appends `min_auth_time=<now>` to the URL it returns to. Back at authorize, a session whose `auth_time` is older is rejected with `login_required`, so a stale session can't satisfy a forced re-login.
- **Token typing.** Access tokens carry `typ: at+jwt`; userinfo rejects anything else, so an ID token can't be used as a bearer token.
- **Access is required per client** (see §2a), with `any_user: true` as the explicit open option. Organization names match exactly (IDs case-insensitively), so a similarly named org can't grant access.
- **Config checks** for non-localhost issuers: client secrets ≥16 characters, `secrets.keys` ≥32 characters and not a `change-me` placeholder, redirect URIs `https` (or `http` on loopback) without userinfo.
- **Code key separation.** Codes are sealed with a key derived by HKDF-SHA256 from `secrets.keys` (label `hankoid oidc authorization code v1`), not the raw keys Hanko uses elsewhere.
- **Rate limiter.** Buckets are keyed per IP and per client; idle buckets are evicted, and when the table is full new keys share an overflow bucket rather than growing memory. `server.frontend.trusted_proxies` (IPs/CIDRs, shared with the rest of the frontend) makes `X-Forwarded-For` count, using the right-most untrusted address.
- **Cookie warnings.** Startup warns when `public_url` is https but `session.cookie.secure` is false, or when `same_site` is `none`.
- **Not done:** serving Hanko's public API on the frontend's origin (a "shared origin"), which would let the session cookie be host-only.
