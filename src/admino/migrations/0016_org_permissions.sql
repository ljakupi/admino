-- GH-161: tool permissions per organization.
--
-- The permissions table held one global (tool, action) matrix that every org
-- shared. It is recreated org-scoped: each organization's Org Admin manages
-- its own matrix (and its critical tier-2 promotions, stored 'confirm'), and
-- every chat run loads the policy of its own org.
--
-- Existing rows are not carried over (tracker #139 §4.2): the old table is
-- dropped, and startup seeds DEFAULT_PERMISSIONS (admino.permissions) for
-- every org without rows (admino.org_permissions.seed_missing_orgs); a new org
-- is seeded inside organizations.create_org's transaction. So this migration
-- writes no row.
--
-- The CHECKs mirror the Pydantic bounds: tool and action follow the permission
-- engine's identifier rule (permissions._VALID_IDENTIFIER, the PermissionPatch
-- and PermissionEntry pattern), and permission is one of the engine's states
-- (PermissionState). No column but updated_at has a default: a row always
-- names its org and its state, so nothing is granted by omission. The org
-- foreign key cascades, so the org purge removes an org's rows with it.
--
-- The audit action catalog grows by org.permission_change,
-- org.permission_promote, org.permission_promote_cancel and
-- org.permission_demote (an Org Admin changing the matrix, requesting,
-- cancelling or reverting a critical promotion): audit_events_action_check is
-- replaced. No audit event is changed.

DROP TABLE permissions;

CREATE TABLE permissions (
    -- CASCADE: the org purge removes the org's matrix.
    org_id      UUID        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    tool        TEXT        NOT NULL CHECK (tool ~ '^[a-z][a-z0-9_]{0,62}$'),
    action      TEXT        NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]{0,62}$'),
    permission  TEXT        NOT NULL CHECK (permission IN ('allow', 'confirm', 'deny')),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- org_id leading: every read is one org's rows.
    PRIMARY KEY (org_id, tool, action)
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
    'breakglass.start', 'breakglass.end', 'tool.call', 'audit.purge',
    'org.permission_change', 'org.permission_promote', 'org.permission_promote_cancel',
    'org.permission_demote'
));
