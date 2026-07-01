-- 0001_initial_schema.sql
-- Initial PostgreSQL schema for admino: settings, permissions, memory.

CREATE TABLE settings (
    key         TEXT        PRIMARY KEY,
    value       JSONB       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE permissions (
    tool        TEXT NOT NULL,
    action      TEXT NOT NULL,
    permission  TEXT NOT NULL CHECK (permission IN ('allow', 'confirm', 'deny')),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tool, action)
);

CREATE TABLE memory (
    key         TEXT        PRIMARY KEY,
    value       TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
