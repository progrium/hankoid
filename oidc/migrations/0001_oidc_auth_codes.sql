-- Single-use authorization codes. The code itself is never stored, only its SHA-256.
-- user_id and session_id are Hanko IDs; there are no foreign keys into Hanko's tables on purpose.
CREATE TABLE hankoid.oidc_auth_codes (
  code_hash      bytea PRIMARY KEY,
  client_id      text NOT NULL,
  user_id        text NOT NULL,
  session_id     text,
  redirect_uri   text NOT NULL,
  scope          text NOT NULL,
  nonce          text,
  code_challenge text,
  auth_time      timestamptz NOT NULL,
  expires_at     timestamptz NOT NULL,
  used_at        timestamptz
);
CREATE INDEX oidc_auth_codes_expires_at ON hankoid.oidc_auth_codes (expires_at);
