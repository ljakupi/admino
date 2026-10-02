-- 0020_user_management.sql
-- Org Admin user management (GH-164).
--
-- An Org Admin lists the org's users and changes their role, name or email,
-- deactivates, reactivates or deletes them, and sends them a password reset
-- link (admino.org_users). Every action is an audit event with IDs only.
--
-- The audit action catalog grows by user.profile_change (an Org Admin changing
-- a user's name or email, or a change refused because the email is taken, so
-- probing for existing emails shows in the org's audit log):
-- audit_events_action_check is replaced. No audit event is changed.
--
-- The email template catalog grows by email_changed: the content-free notice
-- (the org's display name only, no address and no link) that goes to a user's
-- old address when an Org Admin changes it. email_outbox_template_key_check is
-- replaced. No outbox row is changed.
--
-- No table, column or grant is created: the runtime role gains nothing.

ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check;

ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK (action IN (
    'login.success', 'login.failure', 'login.lockout',
    'password_reset.request', 'password_reset.complete',
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

ALTER TABLE email_outbox DROP CONSTRAINT email_outbox_template_key_check;

ALTER TABLE email_outbox ADD CONSTRAINT email_outbox_template_key_check CHECK (template_key IN (
    'invitation', 'password_reset', 'account_activated', 'account_deactivated',
    'budget_alert', 'model_deprecation', 'org_deletion_scheduled', 'email_changed'
));
