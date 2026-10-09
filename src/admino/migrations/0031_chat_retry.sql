-- 0031_chat_retry.sql
-- Retrying a failed answer (GH-245): delete_failed_turn().
--
-- POST /api/chats/{id}/retry re-runs a chat's latest user message when its
-- last answer ended as error or stopped, and replaces the failed turn: V1
-- keeps no versions (#182 adds them in V2 and replaces this function).
--
-- chat_messages stays append-only for the runtime role (SELECT, INSERT; no
-- UPDATE or DELETE). The one delete the app needs runs through this function,
-- as the owner (SECURITY DEFINER with a pinned search_path), and only for a
-- failed last turn of a live chat of the given owner and org:
-- - the row at through_seq ended as error or stopped;
-- - no assistant or tool row comes after it (an org notice, a user row, may);
-- - the turn starts at the chat's latest user row at or before through_seq.
-- The turn's files are unlinked from its user row first (message_id = NULL,
-- the app's own A9 link puts them on the re-stored row in the same
-- transaction), so the delete never cascades to an attachment. Then the
-- turn's rows, its user row through through_seq, are deleted. Anything else
-- is refused with insufficient_privilege and a fixed text (no row data).
--
-- Grants: EXECUTE on the function to admino_app only (none to PUBLIC). No
-- table privilege changes; no table, column or index change.

CREATE FUNCTION delete_failed_turn(
    target_chat uuid, target_org uuid, target_owner uuid, through_seq bigint
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    turn_id uuid;
    turn_seq bigint;
    deleted bigint;
BEGIN
    PERFORM 1 FROM chats
    WHERE id = target_chat AND org_id = target_org AND owner_user_id = target_owner
        AND deleted_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'only a failed turn of a live chat can be deleted'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    PERFORM 1 FROM chat_messages
    WHERE chat_id = target_chat AND org_id = target_org AND seq = through_seq
        AND status IN ('error', 'stopped');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'only a failed turn of a live chat can be deleted'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    PERFORM 1 FROM chat_messages
    WHERE chat_id = target_chat AND org_id = target_org AND seq > through_seq
        AND role <> 'user';
    IF FOUND THEN
        RAISE EXCEPTION 'only a failed turn of a live chat can be deleted'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT id, seq INTO turn_id, turn_seq FROM chat_messages
    WHERE chat_id = target_chat AND org_id = target_org AND role = 'user'
        AND seq <= through_seq
    ORDER BY seq DESC
    LIMIT 1;
    IF turn_id IS NULL THEN
        RAISE EXCEPTION 'only a failed turn of a live chat can be deleted'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    UPDATE attachments SET message_id = NULL, updated_at = now()
    WHERE message_id = turn_id AND chat_id = target_chat AND org_id = target_org;
    DELETE FROM chat_messages
    WHERE chat_id = target_chat AND org_id = target_org
        AND seq >= turn_seq AND seq <= through_seq;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$;

REVOKE ALL ON FUNCTION delete_failed_turn(uuid, uuid, uuid, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION delete_failed_turn(uuid, uuid, uuid, bigint) TO admino_app;
