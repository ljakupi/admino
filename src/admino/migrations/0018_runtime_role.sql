-- GH-220: the least-privilege runtime role admino_app.
--
-- Two database roles from here on:
-- - The owner: the postgres image's superuser admino (POSTGRES_USER). It owns
--   every table and function and runs the migrations, through the one-shot
--   migrate step (python -m admino.migrate) and nothing else.
-- - The runtime role admino_app: the server, its startup and the admin CLI
--   connect as it. A login role that owns nothing, with no superuser-class
--   attribute and only the table privileges the app's SQL needs.
--
-- Why: a superuser session can switch off the append-only trigger of the
-- audit store (SET session_replication_role = replica), drop that trigger, or
-- run COPY ... TO PROGRAM on the database host. As admino_app the app can do
-- none of these: audit_events is SELECT and INSERT only, and the two audit
-- purges run as the owner (SECURITY DEFINER with a pinned search_path).
--
-- No password is set here: the migrate step sets admino_app's password as a
-- SCRAM-SHA-256 verifier after the migrations ran. Creating the role is
-- idempotent (roles are cluster-wide), and an existing role keeps its
-- password.
--
-- A later migration that creates a table grants it to admino_app in the same
-- file (tests/test_migration_0018.py guards it). New functions are not
-- executable by PUBLIC by default.

-- The role: idempotent; an existing role keeps its password.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'admino_app') THEN
        CREATE ROLE admino_app;
    END IF;
END
$$;
ALTER ROLE admino_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- The database: only CONNECT, no TEMPORARY, nothing for PUBLIC.
DO $$
BEGIN
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO admino_app', current_database());
END
$$;

-- The schema: use it, never create in it.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO admino_app;

-- The tables: exactly what the app's SQL needs. audit_events is append-only.
GRANT SELECT ON _migrations TO admino_app;
GRANT SELECT, INSERT ON audit_events TO admino_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations, users, sessions, email_outbox,
    password_reset_tokens, login_throttle, user_settings, oauth_tokens TO admino_app;
GRANT SELECT, INSERT, UPDATE ON invitations, platform_settings, org_settings,
    permissions, memory TO admino_app;

-- The functions: no EXECUTE for PUBLIC, now and for future functions (the
-- global default: a per-schema default can't revoke it). The two purges run
-- as the owner with a pinned search_path, and only they are executable by
-- the app.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER FUNCTION purge_audit_events(integer) SECURITY DEFINER SET search_path = public, pg_temp;
ALTER FUNCTION purge_org_audit_events(uuid) SECURITY DEFINER SET search_path = public, pg_temp;
GRANT EXECUTE ON FUNCTION purge_audit_events(integer), purge_org_audit_events(uuid) TO admino_app;
