-- 0025_chats_column_grants.sql
-- Column-level UPDATE on chats and a sticky external-content mark (GH-266).
--
-- 0024 granted admino_app a table-wide UPDATE on chats, so the runtime role
-- could rewrite a chat's id, org, owner, creation time or legacy session id
-- although the application never does (security audit of #176, core L-4).
-- The table-wide privilege is replaced by UPDATE on exactly the columns the
-- application writes: title and title_source (rename, automatic title),
-- last_activity_at and external_content (a stored turn) and deleted_at (the
-- trash). REVOKE comes first: revoking the table-level UPDATE also drops the
-- column privileges, so the column GRANT must follow it. SELECT ... FOR UPDATE
-- (the org notice's lock) needs UPDATE on one column only and still works.
--
-- external_content is GH-243's sticky flag: once a stored tool result held
-- wrapped external content the chat keeps the mark, "never reset". The
-- trigger makes that hold in the database too: a BEFORE UPDATE row trigger
-- without a column list (no UPDATE form skips it, like 0004's
-- users_identity_is_immutable) refuses true -> false with check_violation.
-- Its message carries no row data. Setting the flag, keeping it and updating
-- other columns of a flagged chat pass.
--
-- No table, column or index change and no data write; chat_messages keeps
-- SELECT, INSERT.

REVOKE UPDATE ON chats FROM admino_app;
GRANT UPDATE (title, title_source, last_activity_at, external_content, deleted_at)
    ON chats TO admino_app;

CREATE FUNCTION chats_external_content_is_sticky() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.external_content AND NOT NEW.external_content THEN
        RAISE EXCEPTION 'chats.external_content can''t be reset'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER chats_external_content_is_sticky
    BEFORE UPDATE ON chats
    FOR EACH ROW EXECUTE FUNCTION chats_external_content_is_sticky();
