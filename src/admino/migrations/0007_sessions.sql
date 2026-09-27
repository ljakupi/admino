-- 0007_sessions.sql
-- Server-side login sessions (GH-149).
-- A login (admino.auth.login) inserts one row through
-- admino.sessions.create_session(); every request resolves the admino_session
-- cookie back to its row and re-reads the user (admino.sessions.resolve_session).
--
-- Only the SHA-256 hash of the cookie token is stored, so a leaked table can't
-- be replayed as cookies. There is no column for the raw token or any other
-- content: the IP and a truncated user agent are the only client details.
--
-- CHECK constraints mirror the Python bounds (hash_session_token's 32-byte
-- digest, USER_AGENT_MAX_LENGTH in sessions.py) so the schema stays safe even
-- against a direct-DB write that bypasses the app.
--
-- The old auth modes (vpn / token) are gone, so the obsolete 'auth' settings
-- row is deleted; nothing else is changed.

CREATE TABLE sessions (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- SHA-256 of the cookie token, never the token itself.
    token_hash   BYTEA       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    -- CASCADE: purging a user removes their sessions.
    user_id      UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Set at login; #152 adds its throttled updates (idle timeout).
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The app always sets the lifetime (12 hours until #152).
    expires_at   TIMESTAMPTZ NOT NULL,
    ip           INET,
    user_agent   TEXT        CHECK (char_length(user_agent) <= 256),
    revoked_at   TIMESTAMPTZ,
    CONSTRAINT sessions_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT sessions_revocation_check CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

-- The users foreign key cascade, and revoking every session of a user.
CREATE INDEX sessions_user_id_idx ON sessions (user_id);

-- The obsolete auth-mode row (auth.mode / AUTH_TOKEN were removed).
DELETE FROM settings WHERE key = 'auth';
