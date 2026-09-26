-- 0005_audit_events.sql
-- Content-free, append-only audit event store (GH-146).
-- Every security-relevant action (logins, invitations, role changes, sharing,
-- deletions and restores, exports, org and platform settings, Super Admin
-- actions, break-glass sessions, agent tool calls) becomes one row here,
-- written by admino.audit_events.record(). Rows hold IDs, counts, sizes and
-- statuses only: never titles, names, file names, emails or message text.
--
-- CHECK constraints mirror the Pydantic rules of AuditEvent (audit_events.py):
-- the enumerations, the actor rules, UUID-only targets and the flat metadata
-- whose string values are tokens or UUIDs, so the schema stays content-free
-- even against a direct-DB write that bypasses the app.
--
-- Append-only: a trigger refuses every UPDATE and TRUNCATE, and every DELETE
-- except those issued by purge_audit_events(integer) for rows past the
-- 6-month retention floor. This stops application-level rewrites and erasure
-- (bugs, injected DML). It is not a barrier against a role that can run
-- arbitrary SQL with elevated rights: a superuser can switch triggers off
-- (SET session_replication_role = replica) or drop them, and a table owner can
-- drop them too. The app still connects as the image's superuser; #220 moves
-- it to a non-superuser role with INSERT and SELECT only on this table. Direct
-- database access goes through break-glass (#172), and PostgreSQL stays on the
-- internal network.

CREATE TABLE audit_events (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL for platform events. RESTRICT: an org with audit rows can't be
    -- deleted; an org purge (#154) removes its audit rows on purpose first.
    -- CASCADE would fight the append-only trigger.
    org_id        UUID        REFERENCES organizations (id) ON DELETE RESTRICT,
    -- No foreign key: the audit history outlives deleted accounts.
    actor_user_id UUID,
    actor_kind    TEXT        NOT NULL
        CHECK (actor_kind IN ('member', 'super_admin', 'system', 'operator')),
    action        TEXT        NOT NULL,
    target_type   TEXT
        CHECK (target_type IN ('organization', 'user', 'invitation', 'project', 'chat',
                               'file', 'model')),
    target_ids    JSONB       NOT NULL DEFAULT '[]',
    ip            INET,
    metadata      JSONB       NOT NULL DEFAULT '{}',
    -- The action catalog (AuditAction). Named so a later migration can
    -- replace it when the catalog grows.
    CONSTRAINT audit_events_action_check CHECK (action IN (
        'login.success', 'login.failure', 'login.lockout',
        'password_reset.request', 'password_reset.complete',
        'invitation.create', 'invitation.revoke', 'invitation.accept',
        'user.role_change', 'user.activate', 'user.deactivate', 'user.delete',
        'project.share', 'project.unshare', 'project.member_role_change', 'project.transfer',
        'project.delete', 'project.restore', 'chat.delete', 'chat.restore',
        'file.delete', 'file.restore', 'project.admin_access', 'export.create',
        'org.settings_change', 'org.create', 'org.limits_change', 'org.deactivate',
        'org.reactivate', 'org.deletion_schedule', 'org.deletion_cancel', 'org.purge',
        'org.residency_change', 'platform.settings_change', 'model.registry_change',
        'breakglass.start', 'breakglass.end', 'tool.call', 'audit.purge'
    )),
    -- A system or operator actor names no user account; a member or Super
    -- Admin always does.
    CONSTRAINT audit_events_actor_user_check
        CHECK ((actor_kind IN ('system', 'operator')) = (actor_user_id IS NULL)),
    -- A member always acts inside their org.
    CONSTRAINT audit_events_member_org_check
        CHECK (actor_kind <> 'member' OR org_id IS NOT NULL),
    -- A target type comes with at least one target id, and ids with a type.
    CONSTRAINT audit_events_target_pair_check
        CHECK ((target_type IS NULL) = (target_ids = '[]'::jsonb)),
    -- An array of at most 100 canonical lowercase UUID strings. A non-string
    -- element (a number, an object) is refused explicitly: like_regex on a
    -- non-string is unknown, which the filter would otherwise skip. CASE keeps
    -- jsonb_array_length from erroring on a non-array.
    CONSTRAINT audit_events_target_ids_check CHECK (
        CASE WHEN jsonb_typeof(target_ids) = 'array' THEN
            jsonb_array_length(target_ids) <= 100
            AND NOT jsonb_path_exists(
                target_ids,
                'strict $[*] ? (@.type() != "string" || !(@ like_regex "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))'
            )
        ELSE false
        END
    ),
    -- A flat object of at most 4096 bytes and 16 keys: short snake_case keys,
    -- scalar values, and strings that are tokens or UUIDs (no spaces, '@' or
    -- '.', so no free text, emails or file names). strict mode, so an array
    -- value is seen as an array instead of being unwrapped. The keys are
    -- counted through jsonb_path_query_array: a CHECK can't hold a subquery.
    CONSTRAINT audit_events_metadata_check CHECK (
        CASE WHEN jsonb_typeof(metadata) = 'object' THEN
            octet_length(metadata::text) <= 4096
            AND jsonb_array_length(jsonb_path_query_array(metadata, 'strict $.keyvalue()')) <= 16
            AND NOT jsonb_path_exists(
                metadata,
                'strict $.keyvalue() ? (!(@.key like_regex "^[a-z][a-z0-9_]{0,39}$"))'
            )
            AND NOT jsonb_path_exists(
                metadata,
                'strict $.* ? (@.type() == "object" || @.type() == "array" || (@.type() == "string" && !(@ like_regex "^[a-z0-9_-]{1,64}$")))'
            )
        ELSE false
        END
    )
);

-- An org's audit log, newest first.
CREATE INDEX audit_events_org_id_occurred_at_idx ON audit_events (org_id, occurred_at);
-- The retention purge and the platform audit log.
CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at);

-- Deletes the events older than the retention and returns how many. The
-- retention is bounded to 6..84 months (MIN/MAX_RETENTION_MONTHS in
-- audit_events.py); the append-only trigger lets these DELETEs through only
-- for rows past the 6-month floor. Static SQL, no EXECUTE. The DELETE stays on
-- one line: the trigger compares its text with the call stack.
CREATE FUNCTION purge_audit_events(retention_months integer) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
    purged bigint;
BEGIN
    IF retention_months IS NULL OR retention_months NOT BETWEEN 6 AND 84 THEN
        RAISE EXCEPTION 'audit retention must be between 6 and 84 months'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    DELETE FROM audit_events WHERE occurred_at < now() - make_interval(months => retention_months);
    GET DIAGNOSTICS purged = ROW_COUNT;
    RETURN purged;
END;
$$;

-- Refuses UPDATE and TRUNCATE outright, and DELETE unless it comes from
-- purge_audit_events(integer) and the row is past the 6-month floor.
--
-- PG_CONTEXT is the call stack, one frame per line: frame 1 is this trigger
-- function, frame 2 the statement that fired it, frame 3 the function that ran
-- that statement. A DELETE is let through only when frame 2 is the purge
-- function's own DELETE and frame 3 is purge_audit_events(integer). Pinning
-- the positions matters: a statement's text can span lines, so a DO block
-- whose DELETE carries a comment with a newline and a lookalike frame would
-- satisfy an "any line matches" test. A top-level DELETE has no frame 2.
-- starts_with, not LIKE: '_' is a LIKE wildcard. Whatever the frames say, a
-- row younger than the 6-month floor never leaves.
--
-- Errors carry no row data: every RAISE is a plain literal.
CREATE FUNCTION audit_events_append_only() RETURNS trigger
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
    END IF;
    RAISE EXCEPTION 'audit_events is append-only'
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

-- No column list, so no UPDATE form skips the row trigger.
CREATE TRIGGER audit_events_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();

CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();
