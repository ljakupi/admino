-- 0028_attachment_token_estimate.sql
-- The estimated token count of each converted attachment (GH-188).
--
-- - token_estimate: set by processing together with status 'ready' (the
--   estimate of the file's converted text and images, admino.tokens), NULL
--   until then. The context budgeting (#190) reads it. The CHECK mirrors the
--   Pydantic bound (admino.models AttachmentSummary.token_estimate, ge=0).
--
-- Grants: the runtime role may UPDATE the new column (processing writes it);
-- no other privilege changes.
--
-- Files that were 'ready' before this release were only verified, never
-- converted: they have no derived files (<id>.d/) and no estimate. They go
-- back to 'uploaded', so the startup recovery queues and converts them.

ALTER TABLE attachments ADD COLUMN token_estimate INTEGER
    CONSTRAINT attachments_token_estimate_check
    CHECK (token_estimate IS NULL OR token_estimate >= 0);

GRANT UPDATE (token_estimate) ON attachments TO admino_app;

UPDATE attachments SET status = 'uploaded', updated_at = now() WHERE status = 'ready';
