-- 0029_chat_message_attachments.sql
-- The attachments an assistant message was answered with (GH-189).
--
-- - included_attachment_ids: the ids of the chat's active attachments that
--   slot 4 of the prompt held when the run stored this assistant message, in
--   slot order. NULL for every other message: user and tool messages, and
--   assistant messages of a run without attachments. Ids only: never a file
--   name, kind, size or content. No route returns the column yet (#190 and
--   #191 shape the message API).
--
-- The CHECK allows NULL, or a one-dimensional array of at least one non-NULL
-- id on an assistant row.
--
-- Grants: none change. chat_messages stays append-only for the runtime role
-- (SELECT, INSERT), which writes the column with the row.

ALTER TABLE chat_messages ADD COLUMN included_attachment_ids UUID[]
    CONSTRAINT chat_messages_included_attachment_ids_check
    CHECK (included_attachment_ids IS NULL OR (
        role = 'assistant'
        AND array_ndims(included_attachment_ids) = 1
        AND cardinality(included_attachment_ids) >= 1
        AND array_position(included_attachment_ids, NULL) IS NULL));
