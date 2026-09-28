-- 0008_password_reset_tokens.sql
-- Self-service password reset tokens (GH-151).
-- A reset request (admino.password_reset.request_reset) upserts one row per
-- user and emails the raw token in a link; confirming the link
-- (admino.password_reset.confirm_reset) deletes the row as it sets the new
-- password, so a token works once.
--
-- Only the SHA-256 hash of the emailed token is stored, so a leaked table can't
-- be replayed as reset links. There is no column for the raw token, the email
-- address, the link or any other content.
--
-- user_id is the primary key: a user has at most one live token, and a newer
-- request replaces (invalidates) the older one.
--
-- CHECK constraints mirror the Python bounds (the 32-byte digest, and
-- RESET_TOKEN_LIFETIME = 30 minutes in password_reset.py) so the schema stays
-- safe even against a direct-DB write that bypasses the app.

CREATE TABLE password_reset_tokens (
    -- CASCADE: purging a user removes their token.
    user_id    UUID        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 of the emailed token, never the token itself.
    token_hash BYTEA       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The app sets it to now() + 30 minutes, on the same clock as created_at.
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT password_reset_tokens_expiry_check
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 minutes')
);
