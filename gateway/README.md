# Built-in 9P gateway

The gateway puts device sign-in in front of any 9P server. Clients connect to a route on hankoid's frontend with 9P over WebSocket and an access token from `hankoid login`, and the gateway connects each one to the backend 9P server as the user the token names. The backend needs to know nothing about OIDC. It's also a reference for the resource contract described in [oidc/README.md](../oidc/README.md#protected-resources): a 9P server that does its own authentication can use introspection and the revocations feed instead.

## Configuration

Each route needs a resource in `oidc.resources` and the Postgres store:

```yaml
oidc:
  store: postgres
  clients:
    - id: hankfs
      token_endpoint_auth_method: none
      grant_types: [device_code]
      resources: [files]
      access: {organization: staff}
  resources:
    - id: files
      audience: wss://files.example.com/9p/files
      secret: ""                              # OIDC_RESOURCES_FILES_SECRET
gateway:
  routes:
    - resource: files                         # path defaults to the audience's: /9p/files
      backend: tcp!zerofs.internal!5564       # or unix!/run/fs.sock, ws://…, wss://…
      versions: [9P2000.L.Z, 9P2000.L, 9P2000.u, 9P2000]   # the default
      identity:
        uname: "{username}"                   # the default; {user_id} also works
        uid: 1000                             # n_uname for .u and .L, and the 9P-Uid header
        aname: "/users/{username}"            # optional: forces the attach root
      access: {organization: staff}           # optional, checked at every connection
      # allow_rebind: false, max_msize: 1048576, max_conns_per_user: 16, origins: []
```

The route's host is the frontend's, so the audience's host should be `public_url`'s. Then hankoid also serves the resource's metadata, and `hankoid login wss://files.example.com/9p/files` finds everything by itself.

## Connecting

- **Handshake:** `GET {path}` with `Upgrade: websocket`, subprotocol `9p`, and `Authorization: Bearer <access token>`. Without a valid token the answer is 401 with `WWW-Authenticate: Bearer resource_metadata="…"`. A user the route's `access` refuses gets 403, and one over `max_conns_per_user` gets 429.
- **Browsers** can't send headers with a WebSocket handshake. They `POST {path}/ticket` (with a bearer token, or with their hankoid session cookie and `X-Gateway-UI: 1`) and connect to `{path}?ticket=…`. A ticket works once, within 30 seconds. Other origins need `origins`.
- **The `101` response** names the identity: `9P-User` (the expanded `uname`) and `9P-Uid` when `uid` is set, which h9 uses to name files.
- Each client gets its own backend connection, so tags and fids never mix between users.

With h9 and the credential helper:

```sh
hankoid login wss://files.example.com/9p/files
h9 --cred 'files.example.com=hankoid cred' --root wss://files.example.com/9p/files rc
```

## What the gateway does to 9P

It reads 9P's framing (`size[4] type[1] tag[2]`), handles a few messages, and passes everything else through unchanged, one WebSocket message per 9P message:

| Message | What happens |
| --- | --- |
| `Tversion` | Passes only if the client's version, or a dialect it extends, is in `versions` (a `9P2000.L.Z` client on a `.L`-only route is offered `9P2000.L`). `msize` is capped at `max_msize`. If the backend answers a version that wasn't offered or isn't allowed, the client gets `unknown`. Any other version is answered `unknown` without reaching the backend |
| `Tauth` | Refused with the dialect's error. Authentication happened at the handshake |
| `Tattach` | `uname`, `n_uname` (.u and .L) and `aname` (when `identity.aname` is set) come from the route; `afid` is forced to `NOFID` |
| `Trebind` (.L.Z) | Refused with `EPERM` on routes with an `aname`, unless `allow_rebind` is set |
| anything before a version is agreed | closes the connection (1008) |

Messages larger than the negotiated `msize` close the connection (1009).

**Why `Trebind` is refused:** it binds a fid by inode number, not by walking from the attach root, so on a backend shared by several users a client could reach any inode the server serves. Turn on `allow_rebind` only when the backend checks that rebinds stay under the attach root. Without it, h9's dotl translator can't rebind fids after a reconnect, so open files fail instead of surviving it.

## Revocation and liveness

- Removing a device (from `/account/devices`, by an admin, by refresh token replay, or with `hankoid logout`) closes its open connections with close code **4401**, immediately on the instance that removed it, and within 10 seconds on other instances, which poll the revocations list.
- A connection isn't closed when its access token expires; the token is only checked at the handshake, and the device is what's tracked afterwards. Reconnects (such as h9's dotl reconnect) run the helper again and present a fresh token.
- The gateway pings each client every 30 seconds and hangs up if a ping goes unanswered for 30 seconds, which also keeps proxies and load balancers from closing idle connections.

## Backends

- `tcp!host!port`: plain TCP, without encryption, so for a private network only.
- `unix!path`: a unix socket on the same machine.
- `ws://…` or `wss://…`: 9P over WebSocket, subprotocol `9p`.

The backend should accept connections only from the gateway: anything that can reach it directly can attach as any user.
