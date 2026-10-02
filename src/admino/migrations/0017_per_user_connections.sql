-- GH-162: per-user OAuth connections and memory notes.
--
-- oauth_tokens held one install-wide Google and Microsoft connection, and
-- memory one install-wide set of notes. Both are recreated per user: each
-- user connects their own accounts (primary key (user_id, provider)) and
-- keeps their own notes (primary key (user_id, key)), and every row names
-- the user's org.
--
-- The existing rows are dropped, not carried over (tracker #139 §4.2): the
-- single-install tokens and notes belong to no user, and a token one person
-- granted must never become another person's connection. Users reconnect
-- their accounts from the Tools page after the upgrade. So this migration
-- writes no row.
--
-- Both foreign keys cascade, so deleting a user and the org purge remove the
-- user's tokens and notes with them. user_id and org_id have no default:
-- every row names its owner, nothing is shared by omission.
--
-- The CHECKs mirror the Pydantic bounds: oauth_tokens follows
-- admino.oauth.OAuthToken (the OAuthProvider literal, a 1 to 4096 character
-- ciphertext, an email of at most 254 characters, at most 50 scopes) and
-- memory follows admino.models.MemoryStoreArgs (its key rule, 1 to 200
-- characters, and a value of at most 2000 characters), so the database
-- refuses what the models refuse.
--
-- No audit catalog change: #146's catalog has no OAuth or memory actions.

DROP TABLE oauth_tokens;

CREATE TABLE oauth_tokens (
    -- CASCADE: deleting the user or purging the org removes the connection.
    user_id                 UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    org_id                  UUID        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    provider                TEXT        NOT NULL CHECK (provider IN ('google', 'microsoft')),
    -- Fernet ciphertext only; the key lives in OAUTH_ENCRYPTION_KEY.
    encrypted_refresh_token TEXT        NOT NULL
        CHECK (length(encrypted_refresh_token) BETWEEN 1 AND 4096),
    email                   TEXT        CHECK (email IS NULL OR length(email) <= 254),
    scopes                  JSONB       NOT NULL
        CHECK (jsonb_typeof(scopes) = 'array' AND jsonb_array_length(scopes) <= 50),
    healthy                 BOOLEAN     NOT NULL DEFAULT true,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_refreshed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, provider)
);

DROP TABLE memory;

CREATE TABLE memory (
    -- CASCADE: deleting the user or purging the org removes the notes.
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    org_id     UUID        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    key        TEXT        NOT NULL CHECK (key ~ '^[a-zA-Z0-9_. -]{1,200}$'),
    value      TEXT        NOT NULL CHECK (char_length(value) <= 2000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key)
);
