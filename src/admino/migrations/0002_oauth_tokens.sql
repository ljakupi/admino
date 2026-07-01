-- 0002_oauth_tokens.sql
-- OAuth refresh token storage for admino (GH-86).
-- Refresh tokens are moved out of encrypted files and into PostgreSQL.
-- Only the Fernet ciphertext is stored here; the encryption key lives in
-- the OAUTH_ENCRYPTION_KEY environment variable and is never persisted.

-- Column CHECK constraints mirror the OAuthToken Pydantic bounds so the
-- schema stays safe even against a direct-DB write that bypasses the app.
CREATE TABLE oauth_tokens (
    provider                TEXT        PRIMARY KEY
        CHECK (provider IN ('google', 'microsoft')),
    encrypted_refresh_token TEXT        NOT NULL
        CHECK (length(encrypted_refresh_token) BETWEEN 1 AND 4096),
    email                   TEXT
        CHECK (email IS NULL OR length(email) <= 254),
    scopes                  JSONB       NOT NULL,
    healthy                 BOOLEAN     NOT NULL DEFAULT true,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_refreshed_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
