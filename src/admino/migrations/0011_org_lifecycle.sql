-- 0011_org_lifecycle.sql
-- The organization purge path of the audit log (GH-154).
-- A Super Admin schedules an organization for deletion (status
-- 'pending_deletion', purge_after = now() + 30 days); once purge_after has
-- passed, the purge job (admino.organizations.purge_due_orgs) removes the
-- org's audit events, its users (the foreign keys cascade to their sessions,
-- invitations, queued email and reset tokens), the org row and its files, and
-- records one platform org.purge event (no org, counts only).
--
-- 1. purge_org_audit_events(uuid) deletes one org's audit events and returns
--    how many. It refuses unless the org is pending deletion and past its
--    purge_after, so it can't erase the log of a live org. Static SQL, no
--    EXECUTE. The DELETE stays on one line: the trigger compares its text
--    with the call stack.
-- 2. audit_events_append_only() is replaced in place (the existing triggers
--    call it): everything 0005 allows stays exactly as it was (the retention
--    purge, its frame literal and the 6-month floor), and one path is added: a
--    DELETE issued by purge_org_audit_events(uuid) for a row whose org is
--    pending deletion and due. UPDATE and TRUNCATE are still always refused.
-- 3. #147's default organization (the fixed id below) is scheduled for
--    immediate purge, so the purge job removes it and its tool.call audit
--    events at the next startup and an upgraded install ends with no
--    organization, like a fresh one. A no-op on installs that never had it.
--
-- Nothing else changes: no table, column or constraint (the audit action
-- catalog of 0010 already holds every org.* action), and no row is deleted
-- here: the default organization goes through the regular purge path.

-- Deletes the audit events of an organization that is pending deletion and
-- past its purge date, and returns how many. Errors carry no row data or
-- input: the RAISE is a plain literal.
CREATE FUNCTION purge_org_audit_events(target_org uuid) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
    purged bigint;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM organizations
        WHERE id = target_org AND status = 'pending_deletion' AND purge_after <= now()
    ) THEN
        RAISE EXCEPTION 'audit events can only be purged for an organization due for deletion'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    DELETE FROM audit_events WHERE org_id = target_org;
    GET DIAGNOSTICS purged = ROW_COUNT;
    RETURN purged;
END;
$$;

-- Refuses UPDATE and TRUNCATE outright, and DELETE unless it comes from one of
-- the two purge functions:
-- - purge_audit_events(integer) (the retention purge, 0005), for a row past
--   the 6-month floor;
-- - purge_org_audit_events(uuid), for a row whose organization is pending
--   deletion and past its purge_after.
--
-- PG_CONTEXT is the call stack, one frame per line: frame 1 is this trigger
-- function, frame 2 the statement that fired it, frame 3 the function that ran
-- that statement. Frames are pinned by position, exactly like 0005, so a
-- lookalike statement (or a DO block whose DELETE carries a comment with a
-- newline and a fake frame) can't pass; starts_with, not LIKE ('_' is a LIKE
-- wildcard). The frame-2 literal of the new path is the purge function's
-- DELETE text, byte for byte.
--
-- Errors carry no row data: every RAISE is a plain literal.
CREATE OR REPLACE FUNCTION audit_events_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    call_stack text;
    frames text[];
BEGIN
    IF TG_OP = 'DELETE' THEN
        GET DIAGNOSTICS call_stack = PG_CONTEXT;
        frames := string_to_array(call_stack, E'\n');
        IF frames[2] = 'SQL statement "DELETE FROM audit_events WHERE occurred_at < now() - make_interval(months => retention_months)"'
            AND starts_with(frames[3], 'PL/pgSQL function purge_audit_events(integer) line ')
            AND OLD.occurred_at < now() - interval '6 months' THEN
            RETURN OLD;
        END IF;
        IF frames[2] = 'SQL statement "DELETE FROM audit_events WHERE org_id = target_org"'
            AND starts_with(frames[3], 'PL/pgSQL function purge_org_audit_events(uuid) line ')
            AND EXISTS (
                SELECT 1 FROM organizations o
                WHERE o.id = OLD.org_id
                  AND o.status = 'pending_deletion'
                  AND o.purge_after <= now()
            ) THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'audit_events is append-only'
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

-- #147's default organization: due for the regular purge right away.
UPDATE organizations
SET status = 'pending_deletion',
    deletion_requested_at = now(),
    purge_after = now(),
    updated_at = now()
WHERE id = '00000000-0000-4000-8000-000000000001';
