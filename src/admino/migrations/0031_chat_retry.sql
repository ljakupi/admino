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
-- - the turn starts at the chat's latest user row at or before through_seq;
-- - the turn's shape (security audit M-1): a compromised admino_app can
--   insert rows (and un-trash a chat), so a forged error row would satisfy
--   the checks above. The function accepts only what a real failed turn
--   holds between its user row and its last row: tool calls (assistant rows
--   with tool_use blocks) and their results, complete or awaiting
--   confirmation, and assistant error rows (a timed-out reply's partial
--   text, see the backfill). A completed turn ends with an answer without
--   tool_use blocks (or a limit_reached notice), stored complete, which
--   admino_app can't update: a forged row after it is refused.
-- Residual (documented): a compromised runtime role can still remove a turn
-- whose tail is a still-awaiting confirmation (pending or expired), an
-- already failed last turn, rows it inserted itself, and the org notices
-- after the chat's last answer (they are user rows). Only if it was already
-- compromised before this migration ran and planted rows then, the backfill
-- below can set completed answers to error, which it can then remove too.
-- A completed turn can't be removed otherwise.
-- The turn's files are unlinked from its user row first (message_id = NULL,
-- the app's own A9 link puts them on the re-stored row in the same
-- transaction), so the delete never cascades to an attachment. Then the
-- turn's rows, its user row through through_seq, are deleted. Anything else
-- is refused with insufficient_privilege and a fixed text (no row data).
--
-- The last statement is a one-off backfill (GH-25 D9): a streamed reply that
-- timed out after showing text stores that text right before its error
-- reply, now as error; one stored before (complete, no tool_use blocks, its
-- chat's next row an assistant error row) is set to error here, so its turn
-- can be retried. It is the migration's only data write.
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
    PERFORM 1 FROM chat_messages
    WHERE chat_id = target_chat AND org_id = target_org
        AND seq > turn_seq AND seq < through_seq
        AND NOT ((status IN ('complete', 'awaiting_confirmation')
                AND (role = 'tool'
                    OR (role = 'assistant' AND coalesce(jsonb_array_length(tool_use_blocks), 0) > 0)))
            OR (role = 'assistant' AND status = 'error'));
    IF FOUND THEN
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

UPDATE chat_messages m SET status = 'error'
WHERE m.role = 'assistant' AND m.status = 'complete'
    AND coalesce(jsonb_array_length(m.tool_use_blocks), 0) = 0
    AND EXISTS (
        SELECT 1 FROM chat_messages n
        WHERE n.chat_id = m.chat_id AND n.org_id = m.org_id
            AND n.seq = (
                SELECT min(x.seq) FROM chat_messages x
                WHERE x.chat_id = m.chat_id AND x.org_id = m.org_id AND x.seq > m.seq
            )
            AND n.role = 'assistant' AND n.status = 'error'
    );
