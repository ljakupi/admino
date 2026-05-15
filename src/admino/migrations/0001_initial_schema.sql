-- 0001_initial_schema.sql
-- Initial PostgreSQL schema for admino: settings, permissions, memory, documents.

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

CREATE TABLE documents (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    doc_type            TEXT        NOT NULL,
    sender              TEXT,
    doc_date            DATE,
    summary             TEXT,
    category            TEXT,
    amount_cents        BIGINT,
    currency            TEXT,
    metadata            JSONB,
    source              TEXT        NOT NULL,
    source_ref          TEXT,
    file_path           TEXT,
    raw_llm_extraction  JSONB
);

CREATE INDEX idx_documents_doc_type  ON documents (doc_type);
CREATE INDEX idx_documents_category  ON documents (category);
CREATE INDEX idx_documents_doc_date  ON documents (doc_date);
CREATE INDEX idx_documents_source    ON documents (source);
