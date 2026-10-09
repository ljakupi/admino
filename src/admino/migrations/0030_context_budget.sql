-- 0030_context_budget.sql
-- Attachment exclusion and the token-based context budget (GH-190).
--
-- - attachments.active: whether the file is sent with its chat's turns. A
--   member excludes (false) or includes (true) one of their own files with
--   PATCH /api/attachments/{id}; an excluded file stays linked to its message
--   and listed, but no turn, budget check or tool.call row counts it. Every
--   existing file takes the default true, so nothing changes for them.
-- - max_context_messages (platform_settings) becomes an optional secondary
--   cap: 0 means no cap and the token budget alone decides what each LLM call
--   sends. platform_settings_max_context_messages_check (0013's inline CHECK)
--   is replaced under the same name, from 1 to 200 to 0 to 200. A stored value
--   is kept: every value 0013 allowed is still allowed.
-- - The audit action catalog grows by file.exclude and file.include (a toggle
--   of the flag; the attachment's id is the target, never a name or content):
--   audit_events_action_check is replaced with 0027's list plus the two, right
--   after file.restore. No audit event is changed.
--
-- Grants: the runtime role (admino_app) may UPDATE the new active column; no
-- other privilege changes.

ALTER TABLE attachments ADD COLUMN active BOOLEAN NOT NULL DEFAULT true;

GRANT UPDATE (active) ON attachments TO admino_app;

-- No IF EXISTS: a missing 0013 constraint fails the migration loudly.
ALTER TABLE platform_settings DROP CONSTRAINT platform_settings_max_context_messages_check;

ALTER TABLE platform_settings ADD CONSTRAINT platform_settings_max_context_messages_check
    CHECK (max_context_messages BETWEEN 0 AND 200);

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
    'file.upload', 'file.delete', 'file.restore', 'file.exclude', 'file.include',
    'project.admin_access', 'export.create',
    'org.settings_change', 'org.create', 'org.limits_change', 'org.deactivate',
    'org.reactivate', 'org.deletion_schedule', 'org.deletion_cancel', 'org.purge',
    'org.residency_change', 'platform.settings_change', 'model.registry_change',
    'breakglass.start', 'breakglass.end', 'tool.call', 'audit.purge',
    'org.permission_change', 'org.permission_promote', 'org.permission_promote_cancel',
    'org.permission_demote'
));
