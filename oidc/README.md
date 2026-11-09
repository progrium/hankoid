# OIDC provider: operator notes

Reference for running the OIDC provider. Configuration, setup steps and the production checklist are in the [main README](../README.md#oidc-provider); this page covers how the provider behaves and how to troubleshoot it. The design rationale is in [PLAN.md](./PLAN.md).

## How it uses Hanko

The provider runs inside the frontend and uses Hanko unmodified. By default it has no database access and no tables of its own; with `oidc.store: postgres` it keeps authorization codes in its own `hankoid` schema (see [State and restarts](#state-and-restarts)). Everything else comes from Hanko's APIs:

| Need | Source |
|---|---|
| Is the browser signed in? | the session cookie forwarded to the public API's `/sessions/validate` |
| Email, username, name, organizations and roles | admin API `GET /users/{id}` |
| Is the session still alive? (token, userinfo) | admin API `GET /users/{id}/sessions` |
| Sign out | public API `POST /logout` with the browser's cookie; or admin API `DELETE /users/{id}/sessions/{sid}` when only the hint is available |

So the frontend must reach both the public and the admin API (sending `HANKO_ADMIN_TOKEN` as a bearer token, if set). If the admin API is down, token and userinfo requests fail; sign-in to Hanko itself still works.

## Session cookie requirements

- `session.cookie.same_site: lax`. A `strict` cookie isn't sent on the top-level navigation from a client to `/oidc/authorize`, so users always look signed out.
- Cookie mode. `session.enable_auth_token_header` doesn't help: a browser redirect only carries cookies.
- `session.cookie.domain` can stay unset. `/signin`, `/oidc/*` and the proxied Hanko API are all on the frontend's origin.

## Who may sign in

Each client's `access` rule is required. A user is allowed if any part matches:

- `users`: user IDs, usernames or **verified** emails, case-insensitive. Changes need a config edit and restart.
- `organization` (+ optional `roles`): membership of a Hanko organization, by ID or exact (case-sensitive) name, holding one of `roles` if set. Managed in the admin UI; no restart needed.
- `any_user: true`: every Hanko user, including self-registered ones if `account.allow_signup` is on. It can't be combined with the others.
- An `access` block that is present but empty admits nobody.

The rule is checked at authorize (`error=access_denied`) and again at the token endpoint, so a membership removed in between makes the code fail. Userinfo also re-reads the user. What a user may do *inside* the client is the client's business, unless it maps the roles claim.

## Roles claim

With `roles_claim: true` (which requires `access.organization`), ID tokens and userinfo include `roles`: the role slugs the user holds **in that organization only**, e.g. `["editor"]`.

- It's sent when the client asks for the `roles` or `profile` scope.
- Users admitted only through `access.users` get `roles: []`.
- The ID token value is a snapshot from sign-in; userinfo is always current. Clients that sync roles on each sign-in pick up changes at the next sign-in.
- Point the client's role mapping at the `roles` claim (e.g. Grafana `role_attribute_path`, listmonk `security.oidc.roles`). Clients that can't map claims ignore it.
- A roles claim grants privileges in the client, so the client must check `iss` and `aud` (standard OIDC libraries do).

## Protocol details

**Discovery** (`{issuer}/.well-known/openid-configuration`) advertises:

- `response_types_supported: [code]`, `grant_types_supported: [authorization_code]`
- `id_token_signing_alg_values_supported: [RS256]`, `subject_types_supported: [public]`
- `code_challenge_methods_supported: [S256]`
- `token_endpoint_auth_methods_supported: [client_secret_basic, client_secret_post]`
- `scopes_supported: [openid, email, profile]`, plus `roles` when a client enables it

Discovery, JWKS and userinfo allow any origin (CORS, no credentials). Authorize, token and logout don't.

**Authorize:**

- An unknown `client_id` or a `redirect_uri` that isn't an exact match shows an error page and never redirects. Later errors redirect to `redirect_uri?error=…&state=…`.
- `scope` must contain `openid`. If `code_challenge` is sent, the method must be `S256`. With `require_pkce`, a challenge is required.
- The callback includes `iss` (RFC 9207). Clients that don't know it ignore it.
- `prompt=none` without a session returns `error=login_required`.

**Token endpoint:**

- `grant_type=authorization_code` only; no refresh tokens. Clients sign in again when their own session ends.
- Errors are RFC 6749 JSON (`invalid_client` with 401 and `WWW-Authenticate`, `invalid_grant`, `invalid_request`, `unsupported_grant_type`). Responses are `Cache-Control: no-store`.
- A verifier sent for a code issued without a challenge is refused as a PKCE downgrade.
- Rate limit: a burst of 10 refilling at 1 per second, per client IP and per client, in memory. Up to 10,000 buckets; idle ones (10 minutes) are evicted, and beyond that new keys share one bucket.

**ID token claims:** `iss`, `sub` (the Hanko user ID), `aud` (the client ID), `azp`, `exp`, `iat`, `auth_time`, `nonce`, `sid`, `email`, `email_verified` (from the primary email). The `profile` scope adds `name`, `given_name`, `family_name`, `preferred_username` (the username) and `picture` when set.

- `auth_time` is the Hanko session token's `iat`, or the session's creation time.
- `sub` is stable; clients that match users by email rely on `email_verified` being accurate, which it is.

**Access tokens** are JWTs (`typ: at+jwt`) with `aud = {issuer}/userinfo`, the client's `client_id`, `scope`, `sid` and a 5-minute default lifetime. They're only meant for userinfo, which takes them as a bearer header or an `access_token` POST field and returns 401 with `WWW-Authenticate: Bearer error="invalid_token"` when they fail. Userinfo also checks the session is still alive.

**Logout** (`end_session_endpoint`):

1. With an `id_token_hint`: the hint must be our ID token, for a configured client, issued within 30 days (expired is fine). `client_id`, if sent, must match its audience.
2. The Hanko session is ended via the browser's cookie; if there's no cookie, the hint's `sid` is deleted through the admin API.
3. The user is redirected (303) to `post_logout_redirect_uri` with `state` if it exactly matches the client's list; otherwise a "Signed out" page is shown.
4. Without a hint, a confirmation page is shown; only its same-origin POST signs out.

## State and restarts

`oidc.store` (or `OIDC_STORE`) decides where authorization codes live.

| | `memory` (default) | `postgres` |
|---|---|---|
| Code | sealed blob, encrypted with a key derived from `secrets.keys` | 32 random bytes; the row is keyed by its SHA-256 |
| Replay protection | in-memory set of used codes | `UPDATE … SET used_at … WHERE used_at IS NULL`, atomic across replicas |
| Restart within a code's 60s | used codes are forgotten; a replay would still need the client secret, the PKCE verifier and a live session | nothing lost |
| Replicas | not supported: each replica has its own used set | supported |
| Needs | nothing | Hanko's `database` section (Postgres only) |

**With `postgres`:**

- The frontend reads Hanko's `database` section (and `DATABASE_*` variables) and connects with a pool of up to 4 connections. A non-Postgres dialect is a startup error.
- At startup it creates the `hankoid` schema and applies any pending migrations under an advisory lock, so replicas can start together. `hankoid oidc migrate --config …` does the same as a separate step. `hankoid migrate up` only migrates Hanko's own tables and never touches `hankoid`.
- Rows are deleted an hour after their code expires, by every instance, every 10 minutes.
- If the database is down, authorize redirects with `error=temporarily_unavailable` and the token endpoint answers 500 `server_error`.
- Switching stores invalidates only the codes issued in the last 60 seconds. `DROP SCHEMA hankoid CASCADE` removes everything the provider stored without affecting Hanko.

**Either way:**

- **Signing key:** without `signing_key_file` / `OIDC_SIGNING_KEY`, a new key is generated at each start and every outstanding token stops verifying. Replicas must share one key.
- **Rate limits** are in memory, per instance, so N replicas allow N times the burst.
- Changing `secrets.keys` invalidates in-flight `memory` codes (and Hanko's own sealed data, so don't).

## Signing keys

- `kid` is the key's RFC 7638 thumbprint; the public keys are at `{issuer}/jwks.json`.
- The key is separate from Hanko's session-signing keys, so an ID token can never be mistaken for a Hanko session token (or the reverse), and rotating one doesn't affect the other.
- **Rotation:**
  1. `hankoid oidc genkey -o oidc-new.pem`.
  2. Set `signing_key_file: oidc-new.pem` and `previous_signing_key_file: <old key>`; restart. Both keys are published, only the new one signs.
  3. After the longest token lifetime plus the clients' JWKS cache time (an hour is plenty with the defaults), remove `previous_signing_key_file`.
- If a key leaks, rotate without keeping the old one as previous; tokens it signed stop verifying immediately.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Users always land on `/signin` from a client, even when signed in | `session.cookie.same_site` is `strict` (startup warns), or the cookie is `secure` on plain http |
| Client says the issuer doesn't match | the client's provider URL isn't exactly `{public_url}/oidc`; check `public_url` against what users see (scheme, host, port) |
| Error page "Invalid redirect" or "Unknown application" (no redirect) | the client's callback URL isn't listed exactly in `redirect_uris` |
| `error=access_denied` | the user doesn't match the client's `access`; organization names are case-sensitive, emails must be verified |
| `invalid_grant` at the token endpoint | code older than `code_ttl`, used twice, the session ended, access revoked in between, a PKCE mismatch, or (with the `memory` store and several replicas) the code was issued by another instance |
| `server_error` from the token endpoint, `temporarily_unavailable` from authorize | with `oidc.store: postgres`, the database is unreachable |
| `invalid_client` | wrong secret, or `OIDC_CLIENTS_<ID>_SECRET` not set in the frontend's environment |
| Tokens stop verifying after a restart | no persistent signing key configured |
| Passkeys fail on `/signin` | `public_url`'s origin isn't in `webauthn.relying_party.origins` (startup warns) |
| `429 slow_down` from the token endpoint | rate limit; behind a proxy, set `server.frontend.trusted_proxies` so clients aren't all seen as the proxy's IP |
| Startup refuses the config | secrets too short, a `change-me` placeholder key, or non-https redirect URIs on a non-localhost `public_url` |
