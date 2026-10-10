-- 0033_account_preferences.sql
-- Account preferences for the new UI (GH-307).
--
-- user_settings gains the display density and the two notification types the
-- new Settings page shows, read and changed through GET/PATCH /api/me/settings
-- (appearance.density, notifications.approvals, notifications.completed) and
-- reset with the rest of the row by POST /api/me/settings/reset:
-- - density: comfortable (default) or compact.
-- - notifications_approvals: actions waiting for a decision in the
--   notification center (default on).
-- - notifications_completed: finished tasks and routine runs in the
--   notification center (default on).
-- The defaults mirror the Pydantic defaults (SettingsAppearance.density,
-- SettingsNotifications.approvals and .completed).
--
-- They replace notifications_enabled and notifications_task_done: every
-- existing row first takes notifications_completed = notifications_task_done
-- (the user's own choice is kept), then both old columns are dropped.
-- notifications_enabled is not mapped: notifications_approvals starts at its
-- default for every row. theme and updated_at are not touched.
--
-- users gains password_changed_at: when the password was last changed (by the
-- user or by a completed reset), NULL until the first change. No default and no
-- backfill: every existing account starts NULL.
--
-- No grant changes: 0018's table-level grants on both tables cover the new
-- columns. The user scope is not audited, so the audit catalog is unchanged.

ALTER TABLE user_settings
    ADD COLUMN density TEXT NOT NULL DEFAULT 'comfortable'
        CHECK (density IN ('comfortable', 'compact')),
    ADD COLUMN notifications_approvals BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN notifications_completed BOOLEAN NOT NULL DEFAULT true;

UPDATE user_settings SET notifications_completed = notifications_task_done;

ALTER TABLE user_settings
    DROP COLUMN notifications_enabled,
    DROP COLUMN notifications_task_done;

ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMPTZ;
