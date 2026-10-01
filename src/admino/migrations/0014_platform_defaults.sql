-- GH-160: the platform defaults, stored next to the LLM and the limits.
--
-- platform_settings (one row, the Super Admin) gains three groups of values,
-- each read through admino.scoped_settings' in-process cache:
-- - files: max file size, files per message, pages per file, render DPI;
-- - retention: the trash bounds, the audit retention, the org-deletion grace
--   period;
-- - security: the per-user rate limit, the login lockout thresholds and the
--   Super Admin session policy.
--
-- Each column is NOT NULL with a default, so the existing row takes the
-- defaults and no row is written here. The defaults and CHECKs mirror the
-- Pydantic models (PlatformFiles, PlatformRetention, PlatformSecurity and their
-- patch models), the session policy bounds of migration 0009 and the audit
-- retention bounds of admino.audit_events. The trash minimum can't exceed the
-- maximum, so an inverted retention window is impossible at rest.
-- platform.settings_change is already in the audit catalog (0013).

ALTER TABLE platform_settings
    ADD COLUMN max_file_size_mb             INTEGER NOT NULL DEFAULT 50
        CHECK (max_file_size_mb BETWEEN 1 AND 500),
    ADD COLUMN max_files_per_message        INTEGER NOT NULL DEFAULT 10
        CHECK (max_files_per_message BETWEEN 1 AND 50),
    ADD COLUMN max_pages_per_file           INTEGER NOT NULL DEFAULT 100
        CHECK (max_pages_per_file BETWEEN 1 AND 1000),
    ADD COLUMN render_dpi                   INTEGER NOT NULL DEFAULT 150
        CHECK (render_dpi BETWEEN 72 AND 300),
    ADD COLUMN trash_min_days               INTEGER NOT NULL DEFAULT 0
        CHECK (trash_min_days BETWEEN 0 AND 90),
    ADD COLUMN trash_max_days               INTEGER NOT NULL DEFAULT 90
        CHECK (trash_max_days BETWEEN 0 AND 90),
    ADD COLUMN audit_months                 INTEGER NOT NULL DEFAULT 12
        CHECK (audit_months BETWEEN 6 AND 84),
    ADD COLUMN org_deletion_grace_days      INTEGER NOT NULL DEFAULT 30
        CHECK (org_deletion_grace_days BETWEEN 7 AND 90),
    ADD COLUMN rate_limit_per_minute        INTEGER NOT NULL DEFAULT 20
        CHECK (rate_limit_per_minute BETWEEN 1 AND 600),
    ADD COLUMN lockout_after_failures       INTEGER NOT NULL DEFAULT 10
        CHECK (lockout_after_failures BETWEEN 3 AND 100),
    ADD COLUMN lockout_window_minutes       INTEGER NOT NULL DEFAULT 15
        CHECK (lockout_window_minutes BETWEEN 1 AND 1440),
    ADD COLUMN lockout_minutes              INTEGER NOT NULL DEFAULT 15
        CHECK (lockout_minutes BETWEEN 1 AND 1440),
    ADD COLUMN session_idle_timeout_minutes INTEGER NOT NULL DEFAULT 60
        CHECK (session_idle_timeout_minutes BETWEEN 15 AND 480),
    ADD COLUMN session_max_lifetime_hours   INTEGER NOT NULL DEFAULT 12
        CHECK (session_max_lifetime_hours BETWEEN 1 AND 72),
    ADD CONSTRAINT platform_settings_trash_order_check
        CHECK (trash_min_days <= trash_max_days);
