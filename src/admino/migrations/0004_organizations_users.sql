-- 0004_organizations_users.sql
-- Organizations and users for multi-tenant admino (GH-145).
-- Adds the account tables the role matrix (#139 §2.1) runs on: organizations
-- with their plan limits and lifecycle, and users that are either a Super
-- Admin (no org, no role) or a member of exactly one org with one role.
--
-- CHECK constraints mirror the Pydantic bounds (Principal's kind/org/role
-- validator in access.py) so the schema stays safe even against a direct-DB
-- write that bypasses the app.
--
-- Existing single-tenant rows (settings, permissions, memory, oauth_tokens)
-- are left alone here; the migrations that re-scope them to an org drop them
-- (#159, #161, #162).

CREATE TABLE organizations (
    id                        UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    name                      TEXT          NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    status                    TEXT          NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'deactivated', 'pending_deletion')),
    seats                     INTEGER       NOT NULL CHECK (seats BETWEEN 1 AND 100000),
    monthly_budget_chf        NUMERIC(12,2) NOT NULL CHECK (monthly_budget_chf >= 0),
    storage_quota_bytes       BIGINT        NOT NULL CHECK (storage_quota_bytes >= 0),
    data_residency            BOOLEAN       NOT NULL DEFAULT true,
    default_response_language TEXT          NOT NULL DEFAULT 'en'
        CHECK (default_response_language IN ('de', 'fr', 'it', 'en')),
    deletion_requested_at     TIMESTAMPTZ,
    purge_after               TIMESTAMPTZ,
    created_at                TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ   NOT NULL DEFAULT now(),
    -- An org is pending deletion exactly when its purge is scheduled.
    CONSTRAINT organizations_pending_deletion_check
        CHECK ((status = 'pending_deletion') = (purge_after IS NOT NULL)),
    -- The deletion request and the purge date are set and cleared together.
    CONSTRAINT organizations_deletion_dates_check
        CHECK ((deletion_requested_at IS NULL) = (purge_after IS NULL))
);

CREATE TABLE users (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email             TEXT        NOT NULL CHECK (char_length(email) BETWEEN 3 AND 254),
    -- name and password_hash stay NULL while the user is invited; they are
    -- set when the invitation is accepted (see users_active_credentials_check).
    name              TEXT        CHECK (char_length(name) BETWEEN 1 AND 120),
    password_hash     TEXT        CHECK (char_length(password_hash) BETWEEN 1 AND 512),
    kind              TEXT        NOT NULL CHECK (kind IN ('super_admin', 'member')),
    -- RESTRICT: an org can't be deleted while it has users; the purge (#154)
    -- removes them on purpose first.
    org_id            UUID        REFERENCES organizations (id) ON DELETE RESTRICT,
    role              TEXT        CHECK (role IN ('org_admin', 'editor', 'viewer')),
    status            TEXT        NOT NULL DEFAULT 'invited'
        CHECK (status IN ('invited', 'active', 'deactivated')),
    ui_language       TEXT        NOT NULL DEFAULT 'en' CHECK (ui_language IN ('de', 'fr', 'en')),
    -- NULL means the org's default_response_language applies.
    response_language TEXT        CHECK (response_language IN ('de', 'fr', 'it', 'en')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at     TIMESTAMPTZ,
    deleted_at        TIMESTAMPTZ,
    -- A Super Admin has no org and no role; a member has both.
    CONSTRAINT users_super_admin_org_check CHECK ((kind = 'super_admin') = (org_id IS NULL)),
    CONSTRAINT users_super_admin_role_check CHECK ((kind = 'super_admin') = (role IS NULL)),
    CONSTRAINT users_active_credentials_check
        CHECK (status <> 'active' OR (name IS NOT NULL AND password_hash IS NOT NULL)),
    -- No whitespace anywhere, so ' a@x.ch' can't slip past the lower(email)
    -- unique index as a second spelling of 'a@x.ch'; an '@' after a local part.
    CONSTRAINT users_email_format_check
        CHECK (email !~ '[[:space:]]' AND position('@' in email) > 1)
);

-- kind and org_id never change after insert: no UPDATE, buggy or injected, can
-- turn a member into a Super Admin, strip a member's org, or move a user into
-- another org. BEFORE UPDATE with no column list, so no UPDATE form skips it.
-- The error message carries no row data.
CREATE FUNCTION users_identity_is_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.kind IS DISTINCT FROM OLD.kind OR NEW.org_id IS DISTINCT FROM OLD.org_id THEN
        RAISE EXCEPTION 'users.kind and users.org_id can''t change'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER users_identity_is_immutable
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION users_identity_is_immutable();

-- Email uniqueness is case-insensitive and platform-wide (across all orgs and
-- Super Admins): Alice@Example.com and alice@example.com can't both exist.
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));
CREATE INDEX users_org_id_idx ON users (org_id);
