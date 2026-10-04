-- 0022_platform_model_policy.sql
-- The V1 model policy (GH-242).
--
-- platform_settings (one row, the Super Admin) gains the active model's
-- capabilities and the LLM retry limit, each read through
-- admino.scoped_settings' in-process cache:
-- - max_input_tokens: the most input tokens the active model takes;
-- - image_input: whether the active model accepts images;
-- - llm_max_retries: how often a retryable LLM failure (provider unavailable,
--   rate limited, timeout) is retried with the same provider and model.
-- config.yaml's llm.max_input_tokens and llm.image_input are stored on every
-- start, like the provider and the models; llm_max_retries is only ever
-- changed by the Super Admin (PATCH /api/platform/settings).
--
-- Each column is NOT NULL with a default, so the existing row takes the
-- defaults (which satisfy every CHECK) and no row is written here. The
-- defaults and CHECKs mirror the Pydantic models (LLMConfig,
-- StoredPlatformLLM, SettingsLLM, SettingsPatchLLM and
-- AgentConfig.llm_max_retries), so the database refuses what the API refuses.
-- No grant is needed: 0018's table-level grants on platform_settings cover
-- the new columns. platform.settings_change is already in the audit catalog
-- (0013).

ALTER TABLE platform_settings
    ADD COLUMN max_input_tokens INTEGER NOT NULL DEFAULT 200000
        CHECK (max_input_tokens BETWEEN 1000 AND 2000000),
    ADD COLUMN image_input      BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN llm_max_retries  INTEGER NOT NULL DEFAULT 2
        CHECK (llm_max_retries BETWEEN 0 AND 5);
