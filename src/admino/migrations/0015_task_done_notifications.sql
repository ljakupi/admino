-- GH-35: the task-done pings, a user setting next to the tool-approval pings.
--
-- user_settings gains notifications_task_done, read and changed through
-- GET/PATCH /api/me/settings (notifications.task_done) and reset with the rest
-- of the row by POST /api/me/settings/reset. The PWA notifications (#28) ask
-- the browser for permission when it is switched on, so it defaults to off.
--
-- The column is NOT NULL with a default, so the existing rows take the default
-- and no row is written here. The default mirrors the Pydantic default
-- (SettingsNotifications.task_done). The user scope is not audited, so the
-- audit catalog is unchanged.

ALTER TABLE user_settings ADD COLUMN notifications_task_done BOOLEAN NOT NULL DEFAULT false;
