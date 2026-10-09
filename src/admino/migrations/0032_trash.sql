-- 0032_trash.sql
-- The trash: restore, delete forever and the retention purge (GH-194).
--
-- 0024 and 0027 made the trash a timestamp (deleted_at) on chats and
-- attachments; this migration adds what restore and purge need.
--
-- - trash_group_id (chats and attachments): the id of the item whose
--   deletion moved this row to the trash, set together with deleted_at and
--   cleared together with it (the CHECKs). A trashed chat is its own group
--   (trash_group_id = id) and so is a file deleted on its own; the files a
--   chat's deletion moved with it carry the chat's id. Restoring a chat
--   restores exactly its group: a file deleted on its own before the chat
--   stays in the trash as its own item. An item of the trash is a row whose
--   trash_group_id is its own id.
-- - Existing trashed rows are backfilled: every trashed chat is its own
--   group; a trashed file whose chat is trashed joined its chat (0027's
--   cascade was the only way into the trash), any other trashed file is its
--   own group.
-- - Indexes: the owner's trash and the purge read the trashed rows of an
--   org (and owner) by deletion time; both partial on deleted_at IS NOT
--   NULL, so they hold only the trash.
-- - The audit action catalog grows by chat.purge and file.purge (an item
--   removed for good, by its owner or by the retention purge):
--   audit_events_action_check is replaced with 0030's list plus the two,
--   chat.purge after chat.restore and file.purge after file.restore. No
--   audit event is changed.
--
-- Grants: the runtime role (admino_app) may DELETE chats (delete forever and
-- the purge; the cascade to chat_messages and attachments runs as their
-- owner, so chat_messages stays append-only for the app) and UPDATE the new
-- trash_group_id columns. No other privilege changes.

ALTER TABLE chats ADD COLUMN trash_group_id UUID;
ALTER TABLE attachments ADD COLUMN trash_group_id UUID;

UPDATE chats SET trash_group_id = id WHERE deleted_at IS NOT NULL;

UPDATE attachments a
SET trash_group_id = CASE
    WHEN EXISTS (
        SELECT 1 FROM chats c
        WHERE c.id = a.chat_id AND c.org_id = a.org_id AND c.deleted_at IS NOT NULL
    ) THEN a.chat_id
    ELSE a.id
END
WHERE a.deleted_at IS NOT NULL;

ALTER TABLE chats ADD CONSTRAINT chats_trash_group_check
    CHECK ((deleted_at IS NULL) = (trash_group_id IS NULL));
ALTER TABLE attachments ADD CONSTRAINT attachments_trash_group_check
    CHECK ((deleted_at IS NULL) = (trash_group_id IS NULL));

CREATE INDEX chats_trash_idx
    ON chats (org_id, owner_user_id, deleted_at, id) WHERE deleted_at IS NOT NULL;
CREATE INDEX attachments_trash_idx
    ON attachments (org_id, owner_user_id, deleted_at, id) WHERE deleted_at IS NOT NULL;

GRANT DELETE ON chats TO admino_app;
GRANT UPDATE (trash_group_id) ON chats TO admino_app;
GRANT UPDATE (trash_group_id) ON attachments TO admino_app;

-- No IF EXISTS: a missing 0030 constraint fails the migration loudly.
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
    'project.delete', 'project.restore', 'chat.delete', 'chat.restore', 'chat.purge',
    'file.upload', 'file.delete', 'file.restore', 'file.purge', 'file.exclude',
    'file.include',
    'project.admin_access', 'export.create',
    'org.settings_change', 'org.create', 'org.limits_change', 'org.deactivate',
    'org.reactivate', 'org.deletion_schedule', 'org.deletion_cancel', 'org.purge',
    'org.residency_change', 'platform.settings_change', 'model.registry_change',
    'breakglass.start', 'breakglass.end', 'tool.call', 'audit.purge',
    'org.permission_change', 'org.permission_promote', 'org.permission_promote_cancel',
    'org.permission_demote'
));
