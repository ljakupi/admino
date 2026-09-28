-- 0009_session_policies.sql
-- Session policies and session management (GH-152).
-- A session now ends after an idle timeout (15 to 480 minutes) or at the end of
-- its lifetime (1 to 72 hours), whichever comes first. Each row stores its own
-- idle timeout, set at login from the member's org policy or the Super Admin's
-- platform policy (admino.sessions.session_policy_for), next to its expiry.
--
-- Ending a session deletes its row: logout, a user ending one of their
-- sessions, an Org Admin's forced logout, a password reset. So revoked_at goes,
-- together with the rows that were already revoked (they could never be used
-- again) and its sessions_revocation_check. Expired and idle rows are deleted
-- by admino.sessions.run_session_purge_job.
--
-- idle_timeout_minutes is added with DEFAULT 60 (the old fixed behavior) only
-- to backfill the rows that exist; the default is dropped afterwards, so the
-- app always sets it from the session's policy.
--
-- CHECK constraints mirror the Python bounds (MIN/MAX_IDLE_TIMEOUT_MINUTES and
-- MAX_LIFETIME_HOURS in sessions.py) so the schema stays safe even against a
-- direct-DB write that bypasses the app. The app computes expires_at on the
-- database clock, like created_at, so the 72-hour cap holds exactly.
--
-- The audit action catalog grows by session.revoke (a user ending one of their
-- sessions) and session.force_logout (an Org Admin logging a user of their org
-- out): audit_events_action_check is replaced. No audit event is changed.

DELETE FROM sessions WHERE revoked_at IS NOT NULL;

ALTER TABLE sessions
    DROP CONSTRAINT sessions_revocation_check,
    DROP COLUMN revoked_at,
    ADD COLUMN idle_timeout_minutes INTEGER NOT NULL DEFAULT 60
        CONSTRAINT sessions_idle_timeout_check CHECK (idle_timeout_minutes BETWEEN 15 AND 480),
    ADD CONSTRAINT sessions_lifetime_check
        CHECK (expires_at <= created_at + interval '72 hours');

ALTER TABLE sessions ALTER COLUMN idle_timeout_minutes DROP DEFAULT;

ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check;

ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK (action IN (
    'login.success', 'login.failure', 'login.lockout',
    'password_reset.request', 'password_reset.complete',
    'session.revoke', 'session.force_logout',
    'invitation.create', 'invitation.revoke', 'invitation.accept',
    'user.role_change', 'user.activate', 'user.deactivate', 'user.delete',
    'project.share', 'project.unshare', 'project.member_role_change', 'project.transfer',
    'project.delete', 'project.restore', 'chat.delete', 'chat.restore',
    'file.delete', 'file.restore', 'project.admin_access', 'export.create',
    'org.settings_change', 'org.create', 'org.limits_change', 'org.deactivate',
    'org.reactivate', 'org.deletion_schedule', 'org.deletion_cancel', 'org.purge',
    'org.residency_change', 'platform.settings_change', 'model.registry_change',
    'breakglass.start', 'breakglass.end', 'tool.call', 'audit.purge'
));
