-- GH-220: the database-enforced deletion window and the owner-run org purge.
--
-- The finding (High): admino_app has UPDATE on organizations, and
-- purge_org_audit_events(uuid) trusted the row's status and purge_after. A
-- role with UPDATE on organizations could mark a live org as pending deletion
-- and due right now, erase its audit log through the purge function, and make
-- the org active again.
--
-- 1. The deletion window, enforced by a BEFORE trigger for every role, the
--    owner included. Entering pending_deletion (an INSERT, or an UPDATE from
--    another status) stamps deletion_requested_at with the database clock,
--    whatever the statement says, and refuses a purge_after that is NULL or
--    less than 7 days away (the floor of retention.org_deletion_grace_days).
--    While an org is pending deletion, both dates are frozen. Leaving
--    pending_deletion is always allowed: a cancel still works until the purge
--    has run (GH-154). The app's scheduling (deletion_requested_at = now(),
--    purge_after = now() + the grace period) always passes.
-- 2. purge_org_audit_events(uuid) keeps its name, argument, return type,
--    precondition and its one-line audit DELETE (the append-only trigger of
--    0011 compares that text with the call stack), and now deletes the org row
--    together with its audit events, in one owner-run call: the audit events
--    first (the append-only trigger checks the org row while they go), then
--    the org row. The org's users must be gone first (users.org_id is ON
--    DELETE RESTRICT), else the call fails and changes nothing. It is
--    re-declared SECURITY DEFINER with a pinned search_path, because CREATE OR
--    REPLACE resets the attributes it doesn't repeat; owner and grants stay.
-- 3. admino_app loses DELETE on organizations: only the purge function
--    removes an organization, and only once its window is over.
--
-- Errors carry no row data or input: every RAISE is a plain literal. Nothing
-- is granted here, no table is created and no row is written.

-- 1. The deletion window, enforced by the database for every role.
CREATE FUNCTION organizations_deletion_window() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status = 'pending_deletion' THEN
        IF TG_OP = 'UPDATE' AND OLD.status = 'pending_deletion' THEN
            IF NEW.deletion_requested_at IS DISTINCT FROM OLD.deletion_requested_at
                OR NEW.purge_after IS DISTINCT FROM OLD.purge_after THEN
                RAISE EXCEPTION 'a pending deletion keeps its dates'
                    USING ERRCODE = 'check_violation';
            END IF;
        ELSE
            NEW.deletion_requested_at := now();
            IF NEW.purge_after IS NULL OR NEW.purge_after < now() + interval '7 days' THEN
                RAISE EXCEPTION 'an organization''s deletion grace period is at least 7 days'
                    USING ERRCODE = 'check_violation';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER organizations_deletion_window
    BEFORE INSERT OR UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION organizations_deletion_window();

-- 2. The org purge: the audit events, then the org row, in one owner-run call.
CREATE OR REPLACE FUNCTION purge_org_audit_events(target_org uuid) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public, pg_temp
AS $$
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
    DELETE FROM organizations WHERE id = target_org;
    RETURN purged;
END;
$$;

-- 3. Only the purge function deletes organizations.
REVOKE DELETE ON organizations FROM admino_app;
