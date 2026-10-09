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
-- - audit_events_metadata_check is replaced (dropped and re-added under the
--   same name). Why: 0005's CHECK refused every array value and capped the
--   metadata at 4096 bytes, so the database refused every tool.call row that
--   carries attachment_ids (the ids of the attachments the run's prompt
--   held), after its tool had already run. What changes: attachment_ids, when
--   present, may be an array of 1 to 100 canonical lowercase UUID strings;
--   every other value stays a scalar or a short token (no object, array or
--   free text), the 16-key limit and the key rule stay as they were, and the
--   cap is 8192 bytes, so 100 ids, their count and the six tool.call keys
--   fit. What stays: the action catalog (audit_events_action_check) and every
--   other audit_events rule are untouched; the metadata stays content-free.
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

-- No IF EXISTS: a missing 0005 constraint fails the migration loudly.
ALTER TABLE audit_events DROP CONSTRAINT audit_events_metadata_check;

-- 0005's rules, with the value rule exempting attachment_ids only, and the
-- attachment_ids rule added. strict mode, so an array value is seen as an
-- array instead of being unwrapped. Validated against every existing row.
ALTER TABLE audit_events ADD CONSTRAINT audit_events_metadata_check CHECK (
    CASE WHEN jsonb_typeof(metadata) = 'object' THEN
        octet_length(metadata::text) <= 8192
        AND jsonb_array_length(jsonb_path_query_array(metadata, 'strict $.keyvalue()')) <= 16
        AND NOT jsonb_path_exists(
            metadata,
            'strict $.keyvalue() ? (!(@.key like_regex "^[a-z][a-z0-9_]{0,39}$"))'
        )
        AND NOT jsonb_path_exists(
            metadata,
            'strict $.keyvalue() ? (@.key != "attachment_ids") ? (@.value.type() == "object" || @.value.type() == "array" || (@.value.type() == "string" && !(@.value like_regex "^[a-z0-9_-]{1,64}$")))'
        )
        AND CASE WHEN metadata ? 'attachment_ids' THEN
            CASE WHEN jsonb_typeof(metadata -> 'attachment_ids') = 'array' THEN
                jsonb_array_length(metadata -> 'attachment_ids') BETWEEN 1 AND 100
                AND NOT jsonb_path_exists(
                    metadata -> 'attachment_ids',
                    'strict $[*] ? (@.type() != "string" || !(@ like_regex "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))'
                )
            ELSE false
            END
        ELSE true
        END
    ELSE false
    END
);
