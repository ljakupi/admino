-- 0034_retire_viewer_role.sql
-- Retire the Viewer role (GH-306).
--
-- The platform has three roles: the Super Admin, Org Admins and Editors. No
-- account may keep the Viewer role, and none is promoted.
--
-- Lock first: the old agent can keep serving while the one-shot migrate step
-- runs, so users, invitations and sessions are locked in EXCLUSIVE mode for
-- the transaction. Reads continue; writes (an invitation accepted, a login)
-- wait for the commit. That keeps every audit row and session count below
-- true to what the statements after it change.
--
-- Then, in this order:
--
-- - Every pending Viewer invitation (accepted_at IS NULL, expired or not,
--   whose account has role viewer and status invited) is revoked as
--   DELETE /api/org/invitations/{id} does: an invitation.revoke event, then
--   its invited account is deleted (the foreign keys cascade to the
--   invitation and its queued email).
-- - Every other Viewer account (active, deactivated, or anything a direct
--   write left behind) is deactivated as POST /api/org/users/{id}/deactivate
--   does: a user.deactivate event, then its sessions are deleted (so they end
--   on their next request), and the account is stored with role editor and
--   status deactivated. It stays deactivated until an Org Admin or the Super
--   Admin reactivates it; reactivation restores the stored role, so it is an
--   explicit grant of Editor.
-- - users_role_check (0004's inline CHECK) is replaced under the same name
--   with org_admin and editor only. An invitation has no role column of its
--   own (it is its invited account's role), so this one CHECK covers both.
--
-- Audit: each event is in the account's org with the system actor (no actor
-- user, no IP), its target an id only, and its metadata holds no email, name
-- or other content.
-- - user.deactivate: target the user; metadata reason viewer_retired and
--   sessions_revoked, the number of sessions deleted (the route's count).
-- - invitation.revoke: target the invitation; metadata the invited user's id
--   (the route's metadata) and reason viewer_retired.
-- Only this migration writes viewer_retired. Both actions are already in the
-- catalog: audit_events_action_check doesn't change.
--
-- No email is queued. Every write selects Viewer rows only, so no other
-- account, invitation, session or audit event changes, and an install without
-- Viewer rows writes no audit row.
--
-- Grants: none change.

LOCK TABLE users, invitations, sessions IN EXCLUSIVE MODE;

INSERT INTO audit_events (org_id, actor_kind, action, target_type, target_ids, metadata)
SELECT u.org_id, 'system', 'invitation.revoke', 'invitation',
       jsonb_build_array(i.id),
       jsonb_build_object('user_id', u.id, 'reason', 'viewer_retired')
FROM users u
JOIN invitations i ON i.user_id = u.id
WHERE u.role = 'viewer' AND u.status = 'invited' AND i.accepted_at IS NULL;

DELETE FROM users u
USING invitations i
WHERE i.user_id = u.id
  AND u.role = 'viewer'
  AND u.status = 'invited'
  AND i.accepted_at IS NULL;

INSERT INTO audit_events (org_id, actor_kind, action, target_type, target_ids, metadata)
SELECT u.org_id, 'system', 'user.deactivate', 'user',
       jsonb_build_array(u.id),
       jsonb_build_object(
           'reason', 'viewer_retired',
           'sessions_revoked', (SELECT count(*) FROM sessions s WHERE s.user_id = u.id)
       )
FROM users u
WHERE u.role = 'viewer';

DELETE FROM sessions s
USING users u
WHERE s.user_id = u.id AND u.role = 'viewer';

UPDATE users SET role = 'editor', status = 'deactivated'
WHERE role = 'viewer';

ALTER TABLE users DROP CONSTRAINT users_role_check;

ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('org_admin', 'editor'));
