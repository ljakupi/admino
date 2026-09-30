-- GH-159: split the key/value settings table into three scopes.
--
-- platform_settings: one row, owned by the Super Admin: the LLM provider, one
--   model per provider and the limits. Startup seeds it from config.yaml, so
--   this migration inserts no platform row.
-- org_settings: one row per organization, owned by its Org Admin: the enabled
--   tool services.
-- user_settings: one row per user: theme and notifications. The UI and
--   response languages stay on users.
--
-- Existing values are not carried over: the old table is dropped and every
-- org and user starts from the column defaults, which equal the Pydantic
-- defaults (SettingsAppearance, SettingsNotifications, ToolsSettings). The
-- CHECKs mirror the Pydantic bounds (LLMConfig.provider, SettingsPatchLLM's
-- model-name rule, LimitsConfig, SettingsAppearance.theme). Both foreign keys
-- cascade, so the org purge removes an org's and its users' rows with them.

DROP TABLE settings;

CREATE TABLE platform_settings (
    -- A single row: the primary key can only be true.
    id                          BOOLEAN     PRIMARY KEY DEFAULT true CHECK (id),
    llm_provider                TEXT        NOT NULL
        CHECK (llm_provider IN ('infomaniak', 'vllm', 'anthropic', 'openai')),
    infomaniak_model            TEXT CHECK (infomaniak_model ~ '^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}$'),
    vllm_model                  TEXT CHECK (vllm_model       ~ '^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}$'),
    anthropic_model             TEXT CHECK (anthropic_model  ~ '^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}$'),
    openai_model                TEXT CHECK (openai_model     ~ '^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}$'),
    max_tool_calls_per_message  INTEGER     NOT NULL CHECK (max_tool_calls_per_message BETWEEN 1 AND 100),
    max_pending_confirmations   INTEGER     NOT NULL CHECK (max_pending_confirmations BETWEEN 1 AND 50),
    confirmation_timeout_s      INTEGER     NOT NULL CHECK (confirmation_timeout_s BETWEEN 10 AND 3600),
    max_message_length          INTEGER     NOT NULL CHECK (max_message_length BETWEEN 1 AND 100000),
    max_context_messages        INTEGER     NOT NULL CHECK (max_context_messages BETWEEN 1 AND 200),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE org_settings (
    org_id                    UUID        PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    gmail_enabled             BOOLEAN     NOT NULL DEFAULT true,
    google_calendar_enabled   BOOLEAN     NOT NULL DEFAULT true,
    google_drive_enabled      BOOLEAN     NOT NULL DEFAULT true,
    outlook_enabled           BOOLEAN     NOT NULL DEFAULT true,
    outlook_calendar_enabled  BOOLEAN     NOT NULL DEFAULT true,
    onedrive_enabled          BOOLEAN     NOT NULL DEFAULT true,
    memory_enabled            BOOLEAN     NOT NULL DEFAULT true,
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_settings (
    user_id                UUID        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    theme                  TEXT        NOT NULL DEFAULT 'light' CHECK (theme IN ('light', 'dark', 'system')),
    notifications_enabled  BOOLEAN     NOT NULL DEFAULT true,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Each existing org and user starts from the defaults (nothing is carried over).
INSERT INTO org_settings (org_id) SELECT id FROM organizations;
INSERT INTO user_settings (user_id) SELECT id FROM users;
