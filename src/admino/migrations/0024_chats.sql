-- 0024_chats.sql
-- Persisted, tenant-scoped chats and their messages (GH-176).
--
-- chats holds one row per conversation: its org, its owner (chats are private
-- to their owner in V1), the title (auto or user-set, #179 fills auto titles),
-- the activity timestamp the chat list sorts by, and deleted_at (the trash: a
-- trashed chat is invisible; restore and purge are #194). chat_messages holds
-- the conversation in order (seq, assigned by the server): user, assistant and
-- tool rows only. System prompts and org or personal instructions are never
-- stored, they are rebuilt for every run.
--
-- The CHECKs mirror the Pydantic bounds (admino.models ChatSummary,
-- ChatMessageView, LLMMessage, MessageStatus and ChatRequest.session_id), so
-- the database refuses what the models refuse.
--
-- Every foreign key cascades: deleting a user removes their chats, and the org
-- purge removes the org's chats and messages. The composite foreign key
-- (chat_id, org_id) -> chats (id, org_id) makes a message whose org differs
-- from its chat's impossible.
--
-- legacy_session_id is a bridge for the legacy session_id API and #177 drops
-- it; one live chat per (owner, legacy session id). external_content is
-- GH-243's sticky flag: set once a stored tool result held wrapped external
-- content, never reset.
--
-- Grants: the runtime role gets SELECT, INSERT, UPDATE on chats (trash is a
-- timestamp, no DELETE) and SELECT, INSERT on chat_messages, which is
-- append-only for the app (no UPDATE or DELETE). No audit catalog change:
-- chat.delete is already in the catalog.

CREATE TABLE chats (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    owner_user_id     UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title             TEXT        NOT NULL DEFAULT ''
        CONSTRAINT chats_title_check CHECK (char_length(title) <= 200),
    title_source      TEXT        NOT NULL DEFAULT 'auto'
        CONSTRAINT chats_title_source_check CHECK (title_source IN ('auto', 'user')),
    legacy_session_id TEXT
        CONSTRAINT chats_legacy_session_id_check
        CHECK (legacy_session_id IS NULL OR legacy_session_id ~ '^[a-zA-Z0-9_-]{1,64}$'),
    external_content  BOOLEAN     NOT NULL DEFAULT false,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at        TIMESTAMPTZ,
    CONSTRAINT chats_id_org_key UNIQUE (id, org_id)
);
CREATE INDEX chats_owner_activity_idx
    ON chats (org_id, owner_user_id, last_activity_at DESC, id DESC) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX chats_legacy_session_key
    ON chats (owner_user_id, legacy_session_id)
    WHERE legacy_session_id IS NOT NULL AND deleted_at IS NULL;

CREATE TABLE chat_messages (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    seq             BIGINT      GENERATED ALWAYS AS IDENTITY
        CONSTRAINT chat_messages_seq_key UNIQUE,
    chat_id         UUID        NOT NULL,
    org_id          UUID        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    role            TEXT        NOT NULL
        CONSTRAINT chat_messages_role_check CHECK (role IN ('user', 'assistant', 'tool')),
    content         TEXT        NOT NULL
        CONSTRAINT chat_messages_content_check CHECK (char_length(content) <= 65536),
    tool_use_blocks JSONB
        CONSTRAINT chat_messages_tool_use_blocks_check
        CHECK (tool_use_blocks IS NULL OR jsonb_typeof(tool_use_blocks) = 'array'),
    tool_call_id    TEXT
        CONSTRAINT chat_messages_tool_call_id_check
        CHECK (tool_call_id IS NULL OR tool_call_id ~ '^[a-zA-Z0-9_-]{1,128}$'),
    tool_calls      JSONB
        CONSTRAINT chat_messages_tool_calls_check
        CHECK (tool_calls IS NULL
               OR (jsonb_typeof(tool_calls) = 'array' AND jsonb_array_length(tool_calls) <= 50)),
    status          TEXT        NOT NULL DEFAULT 'complete'
        CONSTRAINT chat_messages_status_check CHECK (status IN
            ('complete', 'stopped', 'error', 'awaiting_confirmation', 'limit_reached')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chat_messages_chat_fkey FOREIGN KEY (chat_id, org_id)
        REFERENCES chats (id, org_id) ON DELETE CASCADE
);
CREATE INDEX chat_messages_chat_seq_idx ON chat_messages (chat_id, seq DESC);

GRANT SELECT, INSERT, UPDATE ON chats TO admino_app;
GRANT SELECT, INSERT ON chat_messages TO admino_app;
