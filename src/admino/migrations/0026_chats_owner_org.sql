-- 0026_chats_owner_org.sql
-- A chat's owner belongs to the chat's org, and the user-deletion chat locks
-- get an index (GH-271).
--
-- 0024 tied chats.owner_user_id to users (id) only, so the database would
-- store a chat of one org owned by a user of another org: only the
-- application's binds (every chat write binds the caller's own org and user)
-- kept that from happening. users gains UNIQUE (id, org_id) and the
-- single-column owner foreign key is replaced, in the same ALTER TABLE, by
-- the composite (owner_user_id, org_id) -> users (id, org_id). Both chat
-- columns are NOT NULL, so the key is always checked: an owner of another
-- org, an unknown user and a Super Admin (no org, and NULL never matches)
-- are all refused. It keeps ON DELETE CASCADE and is the only foreign key
-- from chats to users, so there is exactly one cascade path from a user to
-- their chats (org_id -> organizations stays the org purge's).
--
-- Existing rows aren't rewritten: the key is checked against them (no NOT
-- VALID). If a chat whose owner belongs to another org already exists, the
-- migration fails and, being one transaction, changes nothing.
--
-- The index serves GH-265's ordered chat locks of the user deletions
-- (org_users and invitations: a user's chats in the org, by id, FOR UPDATE)
-- and the cascade's lookup by owner. They read trashed chats too, so the
-- partial chat-list index (chats_owner_activity_idx, WHERE deleted_at IS
-- NULL) can't serve them and each deletion scanned chats. The new index is
-- non-partial, keyed (org_id, owner_user_id, id) so the locks read their
-- rows already in id order. Not CONCURRENTLY: migrations run in a
-- transaction. No index is dropped.
--
-- No grant, no data write, no function or trigger change.

ALTER TABLE users ADD CONSTRAINT users_id_org_key UNIQUE (id, org_id);

ALTER TABLE chats
    DROP CONSTRAINT chats_owner_user_id_fkey,
    ADD CONSTRAINT chats_owner_org_fkey FOREIGN KEY (owner_user_id, org_id)
        REFERENCES users (id, org_id) ON DELETE CASCADE;

CREATE INDEX chats_org_owner_id_idx ON chats (org_id, owner_user_id, id);
