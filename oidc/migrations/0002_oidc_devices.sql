-- Device authorization (RFC 8628), devices, and rotating refresh tokens. Secrets are stored only
-- as hashes; user_id and session ids are Hanko IDs with no foreign keys into Hanko's tables.

-- Pending and decided device authorizations. Rows live minutes.
CREATE TABLE hankoid.oidc_device_grants (
  device_code_hash bytea PRIMARY KEY,            -- sha256(device_code)
  user_code_hash   bytea NOT NULL UNIQUE,        -- HMAC-SHA256(normalized user_code), key from secrets.keys
  client_id        text NOT NULL,
  scope            text NOT NULL,
  resource         text,                         -- RFC 8707 resource asked for at device_authorization
  status           text NOT NULL DEFAULT 'pending', -- pending | approved | denied | consumed
  requester_ip     text NOT NULL,
  requester_geo    text,
  requester_ua     text,
  device_name      text,
  user_id          text,                         -- set on approve
  approved_session text,                         -- Hanko session that approved it, for audit
  approver_ip      text,
  auth_time        timestamptz,
  interval_s       integer NOT NULL,             -- grows by 5 on each slow_down
  last_polled_at   timestamptz,
  created_at       timestamptz NOT NULL,
  expires_at       timestamptz NOT NULL,
  decided_at       timestamptz
);
CREATE INDEX oidc_device_grants_expires_at ON hankoid.oidc_device_grants (expires_at);

-- One row per approved device. This is what the user sees and revokes.
CREATE TABLE hankoid.oidc_devices (
  id            uuid PRIMARY KEY,
  user_id       text NOT NULL,
  client_id     text NOT NULL,
  name          text NOT NULL,
  scope         text NOT NULL,
  auth_time     timestamptz NOT NULL,
  created_at    timestamptz NOT NULL,
  created_ip    text NOT NULL,
  last_used_at  timestamptz NOT NULL,
  last_used_ip  text,
  expires_at    timestamptz,                     -- absolute lifetime, if configured
  revoked_at    timestamptz,
  revoked_by    text                             -- user | admin | reuse | access | logout
);
CREATE INDEX oidc_devices_user ON hankoid.oidc_devices (user_id) WHERE revoked_at IS NULL;
CREATE INDEX oidc_devices_revoked_at ON hankoid.oidc_devices (revoked_at) WHERE revoked_at IS NOT NULL;

-- Rotating refresh tokens. A device's current token is its row with rotated_at IS NULL.
CREATE TABLE hankoid.oidc_refresh_tokens (
  token_hash  bytea PRIMARY KEY,                 -- sha256(token)
  device_id   uuid NOT NULL REFERENCES hankoid.oidc_devices(id) ON DELETE CASCADE,
  issued_at   timestamptz NOT NULL,
  expires_at  timestamptz NOT NULL,              -- idle lifetime from issue
  rotated_at  timestamptz                        -- set when exchanged
);
CREATE INDEX oidc_refresh_tokens_device ON hankoid.oidc_refresh_tokens (device_id);

-- Single-use WebSocket tickets for browser clients, which can't send an Authorization header.
CREATE TABLE hankoid.gateway_tickets (
  ticket_hash bytea PRIMARY KEY,                 -- sha256(ticket)
  resource    text NOT NULL,                     -- the audience it was issued for
  user_id     text NOT NULL,
  device_id   uuid,
  client_id   text NOT NULL,
  username    text,
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz
);
CREATE INDEX gateway_tickets_expires_at ON hankoid.gateway_tickets (expires_at);
