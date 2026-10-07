-- 0028_attachment_token_estimate.sql
-- The estimated token count and the derived files' size of each converted
-- attachment (GH-188).
--
-- - token_estimate: set by processing together with status 'ready' (the
--   estimate of the file's converted text and images, admino.tokens), NULL
--   until then. The context budgeting (#190) reads it. The CHECK mirrors the
--   Pydantic bound (admino.models AttachmentSummary.token_estimate, ge=0).
-- - derived_bytes: set by processing together with status 'ready' (the bytes
--   of the file's derived files in <id>.d/), NULL until then. The org's
--   storage quota counts it beside size_bytes, so a conversion's output can't
--   fill the shared volume outside the quota.
--
-- Grants: the runtime role may UPDATE the two new columns (processing writes
-- them); no other privilege changes.
--
-- Files that were 'ready' before this release were only verified, never
-- converted: they have no derived files (<id>.d/) and no estimate. They go
-- back to 'uploaded', so the startup recovery queues and converts them.

ALTER TABLE attachments ADD COLUMN token_estimate INTEGER
    CONSTRAINT attachments_token_estimate_check
    CHECK (token_estimate IS NULL OR token_estimate >= 0);

ALTER TABLE attachments ADD COLUMN derived_bytes BIGINT
    CONSTRAINT attachments_derived_bytes_check
    CHECK (derived_bytes IS NULL OR derived_bytes >= 0);

GRANT UPDATE (token_estimate, derived_bytes) ON attachments TO admino_app;

UPDATE attachments SET status = 'uploaded', updated_at = now() WHERE status = 'ready';
