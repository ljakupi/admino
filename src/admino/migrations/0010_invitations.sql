-- 0010_invitations.sql
-- Invitations (GH-153).
-- An Org Admin invites an email into their org (a Super Admin the first Org
-- Admin of an empty org). Sending inserts the invitee's users row (status
-- 'invited', no name, no password) and one invitations row, and emails the raw
-- token in a link; accepting the link (admino.invitations.accept_invitation)
-- sets accepted_at as it activates the user, so a link works once. Resending
-- rotates the token and resets sent_at and expires_at.
--
-- Only the SHA-256 hash of the emailed token is stored, so a leaked table can't
-- be replayed as invitation links. There is no column for the raw token, the
-- email address, the name, the link or any other content.
--
-- user_id is UNIQUE (one invitation per invited user) and cascades: revoking
-- an invitation deletes the invited users row, and the invitation goes with it.
--
-- CHECK constraints mirror the Python bounds (the 32-byte digest, and
-- INVITATION_LIFETIME = 72 hours in invitations.py) so the schema stays safe
-- even against a direct-DB write that bypasses the app. The app computes
-- expires_at on the database clock, like sent_at, so the 72-hour cap holds
-- exactly.
--
-- The audit action catalog grows by invitation.resend (an Org Admin sending a
-- pending invitation again with a new link) and invitation.refuse (a send refused
-- because the email is taken or the org has no free seat, so probing for
-- existing emails shows in the org's audit log): audit_events_action_check is
-- replaced. No audit event is changed.

CREATE TABLE invitations (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- CASCADE: revoking (deleting the invited users row) removes the invitation.
    user_id     UUID        NOT NULL UNIQUE REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 of the emailed token, never the token itself.
    token_hash  BYTEA       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Reset to now() by a resend.
    sent_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The app sets it to now() + 72 hours, on the same clock as sent_at.
    expires_at  TIMESTAMPTZ NOT NULL,
    -- NULL while the invitation is pending.
    accepted_at TIMESTAMPTZ,
    CONSTRAINT invitations_sent_check CHECK (sent_at >= created_at),
    CONSTRAINT invitations_expiry_check
        CHECK (expires_at > sent_at AND expires_at <= sent_at + interval '72 hours')
);

ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check;

ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK (action IN (
    'login.success', 'login.failure', 'login.lockout',
    'password_reset.request', 'password_reset.complete',
    'session.revoke', 'session.force_logout',
    'invitation.create', 'invitation.revoke', 'invitation.accept', 'invitation.resend',
    'invitation.refuse',
    'user.role_change', 'user.activate', 'user.deactivate', 'user.delete',
    'project.share', 'project.unshare', 'project.member_role_change', 'project.transfer',
    'project.delete', 'project.restore', 'chat.delete', 'chat.restore',
    'file.delete', 'file.restore', 'project.admin_access', 'export.create',
    'org.settings_change', 'org.create', 'org.limits_change', 'org.deactivate',
    'org.reactivate', 'org.deletion_schedule', 'org.deletion_cancel', 'org.purge',
    'org.residency_change', 'platform.settings_change', 'model.registry_change',
    'breakglass.start', 'breakglass.end', 'tool.call', 'audit.purge'
));
