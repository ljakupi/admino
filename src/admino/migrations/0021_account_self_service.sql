-- 0021_account_self_service.sql
-- Account self-service (GH-166).
--
-- A user edits their own account from Settings -> My account (admino.my_account):
-- name, UI and response languages, timezone and personal instructions, and
-- changes their password, which ends every one of their sessions.
--
-- users gains two columns next to ui_language and response_language:
-- - timezone: an IANA zone name, NULL until the PWA presets it from the
--   browser after the next login (consumers read NULL as Europe/Zurich). The
--   CHECK bounds its length and refuses anything but zone-name characters
--   (no dots, spaces, empty segments or non-ASCII), so no path-like value is
--   ever handed to a zone loader.
-- - personal_instructions: the user's own instructions for the assistant, at
--   most 1500 characters ('' = none).
-- No row is written: existing users get timezone NULL and personal_instructions
-- '' from the column defaults.
--
-- The audit action catalog grows by password.change (a user changing their own
-- password, which ends their sessions; self-service profile edits are not
-- audited): audit_events_action_check is replaced. No audit event is changed.
--
-- No table or grant is created: 0018's table-level grants on users cover the
-- new columns, so the runtime role gains nothing. Nothing else changes.

ALTER TABLE users
    ADD COLUMN timezone TEXT
        CONSTRAINT users_timezone_check
        CHECK (char_length(timezone) <= 64 AND timezone ~ '^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$'),
    ADD COLUMN personal_instructions TEXT NOT NULL DEFAULT ''
        CONSTRAINT users_personal_instructions_check
        CHECK (char_length(personal_instructions) <= 1500);

ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check;

ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK (action IN (
    'login.success', 'login.failure', 'login.lockout',
    'password_reset.request', 'password_reset.complete', 'password.change',
    'session.revoke', 'session.force_logout',
    'invitation.create', 'invitation.revoke', 'invitation.accept', 'invitation.resend',
    'invitation.refuse',
    'user.role_change', 'user.activate', 'user.deactivate', 'user.delete',
    'user.profile_change',
    'project.share', 'project.unshare', 'project.member_role_change', 'project.transfer',
    'project.delete', 'project.restore', 'chat.delete', 'chat.restore',
    'file.delete', 'file.restore', 'project.admin_access', 'export.create',
    'org.settings_change', 'org.create', 'org.limits_change', 'org.deactivate',
    'org.reactivate', 'org.deletion_schedule', 'org.deletion_cancel', 'org.purge',
    'org.residency_change', 'platform.settings_change', 'model.registry_change',
    'breakglass.start', 'breakglass.end', 'tool.call', 'audit.purge',
    'org.permission_change', 'org.permission_promote', 'org.permission_promote_cancel',
    'org.permission_demote'
));
