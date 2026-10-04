-- 0023_org_settings_policies.sql
-- The organization's policies and instructions (GH-169).
--
-- org_settings (one row per organization, its Org Admin) gains, next to the
-- tool switches of 0013, what the Organization -> Settings page edits through
-- GET / PATCH /api/org/settings (admino.scoped_settings):
-- - instructions: the organization instructions, at most 8000 characters
--   (#170 puts them into slot 2 of the prompt);
-- - session_idle_timeout_minutes and session_max_lifetime_hours: the session
--   policy a member's new session takes (admino.sessions' bounds, 15 to 480
--   minutes and 1 to 72 hours, the CHECKs of 0009); a change re-times the
--   org's live sessions in the same transaction;
-- - trash_retention_days: how long the org's trash is kept, 0 to 90 days; the
--   service also keeps a changed value within the platform's trash bounds.
--
-- Each column is NOT NULL with a default, so the existing rows take the
-- defaults (which satisfy every CHECK) and no row is written here. The
-- defaults and CHECKs mirror the Pydantic models (OrgSecurityPatch,
-- OrgRetentionPatch, OrgSettingsPatch, OrgSettingsResponse and
-- sessions.SessionPolicy), so the database refuses what the API refuses.
-- organizations is unchanged: the display name and the default response
-- language are its existing name and default_response_language columns.
-- No grant is needed: 0018's table-level grants on org_settings cover the new
-- columns. org.settings_change is already in the audit catalog.

ALTER TABLE org_settings
    ADD COLUMN instructions TEXT NOT NULL DEFAULT ''
        CONSTRAINT org_settings_instructions_check CHECK (char_length(instructions) <= 8000),
    ADD COLUMN session_idle_timeout_minutes INTEGER NOT NULL DEFAULT 60
        CONSTRAINT org_settings_session_idle_timeout_check
        CHECK (session_idle_timeout_minutes BETWEEN 15 AND 480),
    ADD COLUMN session_max_lifetime_hours INTEGER NOT NULL DEFAULT 12
        CONSTRAINT org_settings_session_lifetime_check
        CHECK (session_max_lifetime_hours BETWEEN 1 AND 72),
    ADD COLUMN trash_retention_days INTEGER NOT NULL DEFAULT 30
        CONSTRAINT org_settings_trash_retention_check
        CHECK (trash_retention_days BETWEEN 0 AND 90);
