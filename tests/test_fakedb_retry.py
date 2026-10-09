"""The FakeDb reproduces what PostgreSQL does for retrying a failed answer (GH-245).

Contract C5 (RUN_DIR/contract.md): ``tests/db_fakes.py`` runs the retry's SQL as
the real database answers it, so the service and HTTP tests of GH-245 prove what
production does. Pinned here, each against a real-PostgreSQL fact of contract C1
and C2 (checked on postgres:16 as admino_app during preflight):

- ``SELECT delete_failed_turn($1, $2, $3, $4)`` (migration 0031) on the tree's
  shipped migrations: a failed turn ``U2 A(tool_use) T A(error)`` returns 4 and
  leaves U2's files unlinked (``message_id`` NULL, a new ``updated_at``, trashed
  and excluded ones too), never deleted; a stop on the user row itself returns 1;
  an org notice after the failed answer is kept (2); every refusal (a trashed
  chat, another owner, another org, an unknown chat, a ``complete`` /
  ``awaiting_confirmation`` / ``limit_reached`` row, a row an assistant or tool
  row follows, another chat's row, no row at that seq, no user row before it, a
  NULL seq) is InsufficientPrivilegeError "only a failed turn of a live chat can
  be deleted" with nothing changed; inside ``conn.transaction()`` it commits and
  rolls back with the transaction; fetchval / fetchrow / fetch / execute answer
  like asyncpg; the binds are checked like a chat statement; only the
  four-argument signature resolves. These are RED until 0031 ships.
- The turn's shape (C1', security audit M-1, Decision 7; the cases of
  RUN_DIR/audit-fix-pg-probe.sql, run on postgres:16 as admino_app): every
  row strictly between the turn's user row and through_seq must be a ``tool``
  row or an ``assistant`` row with at least one tool_use block, ``complete``
  or ``awaiting_confirmation``. The real failed shapes pass with their counts
  (a tool turn ending ``error`` 4, an approval continuation with its awaiting
  row ending ``error`` 4, a stop on the user row 1, a stopped ``tool`` row
  after an assistant row with two blocks 4, a stopped partial 2, GH-24's
  pending-limit turn ``U A(tool_use) T(denied) A(error)`` 4, two tool rounds
  ending ``error`` 6); a row admino_app forged after a completed answer,
  after a completed tool turn, after a ``limit_reached`` notice or after an
  answer whose tool_use_blocks is ``[]`` is refused with nothing changed (the
  turn's file stays linked), also when the function isn't SECURITY DEFINER
  (the check runs before the body's DELETE); every (middle row kind, status)
  cell is decided by that rule; the documented residual, a row forged after a
  still-awaiting tool call, deletes 3.
- GH-25 D9 partials (C1'b, Decision 7; RUN_DIR/audit-fix-pg-legacy.sql and
  audit-fix-pg-after.sql on postgres:16): a streamed run that timed out after
  text stores its partial reply (an ``assistant`` row without tool_use
  blocks) right before the error reply, now with status ``error``, and the
  shape check also admits ``assistant`` rows with status ``error``. The new
  D9 turn ``U A(partial, error) A(error)`` deletes 3 (also with ``[]``
  blocks), a tool turn ending in a D9 partial deletes 5; the grid admits an
  ``assistant`` ``error`` row of every block kind in the middle (a ``tool``
  ``error`` row stays refused). A legacy D9 turn whose partial is still
  ``complete`` (stored before C1'b; on PostgreSQL 0031's backfill UPDATE turns
  it into ``error``, the fake runs no migration data statement) is refused
  like the forged row it can't be told from, nothing changed.
- Before a migration creates the function (0030's migrations,
  ``monkeypatch.setattr(db_fakes, "shipped_functions", ...)``) the call is
  UndefinedFunctionError; a 0031 without the GRANT is "permission denied for
  function", one without SECURITY DEFINER fails at the DELETE, nothing changed.
- ``read_shipped_functions`` reads what the migrations leave (0030's: only the
  two purges are executable and owner-run; the contract's 0031 adds
  ``delete_failed_turn``; a comment-only 0031 adds nothing; 0031 leaves
  ``shipped_schema`` as it is), and the tree's own migrations give 0031's
  functions (RED until 0031 ships).
- admino_app still may not DELETE or UPDATE chat_messages directly.
- R1 (``chats.read_retry_target``'s statement) and T2b (``load_turn(...,
  before_seq=...)``) run on the reader with PostgreSQL's results. These pass
  today: they are fake infrastructure the other GH-245 tests build on.
"""

from __future__ import annotations

import re
import shutil
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import asyncpg
import pytest

from tests import db_fakes
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, ShippedFunctions

REFUSAL = "only a failed turn of a live chat can be deleted"
DELETE_SQL = "SELECT delete_failed_turn($1, $2, $3, $4)"

# Contract C1 (with C1', security audit M-1, and C1'b, GH-25 D9 partials): migration
# 0031, the statements exactly as the contract states them.
MIGRATION_0031 = """\
-- GH-245: retry a failed chat answer. chat_messages stays append-only for
-- admino_app (no UPDATE or DELETE). delete_failed_turn runs as the owner
-- (SECURITY DEFINER, pinned search_path) and deletes only a live chat's failed
-- last turn (the shape check: only tool calls, their results, an approval's
-- awaiting row and the failed answer's error rows between its user row and
-- the failed row: security audit M-1; the residual is a turn ending in a
-- still-awaiting call), after unlinking the turn's files (never cascaded); it
-- refuses anything else. #182 (versions) replaces it. EXECUTE to admino_app
-- only. The backfill marks GH-25 D9 timeout partials stored before as error.
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
                    OR (role = 'assistant'
                        AND coalesce(jsonb_array_length(tool_use_blocks), 0) > 0)))
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
"""
_GRANT_LINE = (
    "GRANT EXECUTE ON FUNCTION delete_failed_turn(uuid, uuid, uuid, bigint) TO admino_app;\n"
)
MIGRATION_0031_WITHOUT_GRANT = MIGRATION_0031.replace(_GRANT_LINE, "")
MIGRATION_0031_INVOKER = MIGRATION_0031.replace(
    "SECURITY DEFINER SET search_path", "SET search_path"
)
MIGRATION_0031_COMMENTS_ONLY = "".join(f"-- {line}\n" for line in MIGRATION_0031.splitlines())
PURGES = frozenset({"purge_audit_events", "purge_org_audit_events"})

# Contract C2: R1, read_retry_target's one statement, exactly.
R1_SQL = """
SELECT c.id,
       latest.seq AS through_seq, latest.status,
       turn.seq AS user_seq, turn.content,
       ARRAY(
           SELECT a.id FROM attachments a
           WHERE a.message_id = turn.id AND a.chat_id = c.id AND a.org_id = c.org_id
             AND a.owner_user_id = c.owner_user_id AND a.deleted_at IS NULL
           ORDER BY a.created_at, a.id
       ) AS attachment_ids
FROM chats c
LEFT JOIN LATERAL (
    SELECT seq, status FROM chat_messages
    WHERE chat_id = c.id AND org_id = c.org_id
    ORDER BY seq DESC
    LIMIT 1
) latest ON true
LEFT JOIN LATERAL (
    SELECT id, seq, content FROM chat_messages
    WHERE chat_id = c.id AND org_id = c.org_id AND role = 'user'
    ORDER BY seq DESC
    LIMIT 1
) turn ON true
WHERE c.id = $1 AND c.org_id = $2 AND c.owner_user_id = $3 AND c.deleted_at IS NULL
"""

# Contract C2: T2'' (load_turn's statement since GH-190), and T2b, the same with the
# lateral's WHERE bounded by ``seq < $5``.
_T2_HEAD = """
    SELECT c.id, c.org_id, c.owner_user_id, c.title, c.title_source, c.external_content,
           c.created_at, c.last_activity_at,
           ARRAY(
               SELECT ARRAY[a.id::text, a.filename, a.kind, a.page_count::text,
                            a.token_estimate::text, a.derived_bytes::text]
               FROM attachments a
               JOIN chat_messages am ON am.id = a.message_id AND am.org_id = a.org_id
               WHERE a.chat_id = c.id AND a.org_id = c.org_id
                 AND a.owner_user_id = c.owner_user_id
                 AND a.status = 'ready' AND a.active AND a.deleted_at IS NULL
               ORDER BY am.seq, a.created_at, a.id
           ) AS attachment_rows,
           m.role, m.content, m.tool_use_blocks, m.tool_call_id
    FROM chats c
    LEFT JOIN LATERAL (
        SELECT seq, role, content, tool_use_blocks, tool_call_id
        FROM chat_messages
"""
_T2_TAIL = """
        ORDER BY seq DESC
        LIMIT $4
    ) m ON true
    WHERE c.id = $1 AND c.org_id = $2 AND c.owner_user_id = $3 AND c.deleted_at IS NULL
    ORDER BY m.seq DESC
"""
T2_SQL = _T2_HEAD + "        WHERE chat_id = c.id AND org_id = c.org_id" + _T2_TAIL
T2B_SQL = _T2_HEAD + "        WHERE chat_id = c.id AND org_id = c.org_id AND seq < $5" + _T2_TAIL

_TOOL_USE = [{"type": "tool_use", "id": "toolu_1", "name": "memory_read", "input": {}}]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@dataclass
class World:
    """One org with the chat owner and a colleague, and a member of another org."""

    db: FakeDb
    owner: uuid.UUID
    colleague: uuid.UUID
    stranger: uuid.UUID


@dataclass
class FailedTurn:
    """A chat ``U1 A1 | U2 A(tool_use) T A(error)`` with U2's files (contract C1's fact)."""

    chat: uuid.UUID
    kept: list[uuid.UUID]  # U1, A1
    turn: list[uuid.UUID]  # U2, A(tool_use), T, A(error)
    through_seq: int
    turn_files: list[uuid.UUID]  # U2's: a live, a trashed and an excluded file
    other_files: list[uuid.UUID]  # U1's file and an unsent one


@pytest.fixture()
def world() -> World:
    db = FakeDb()
    return World(
        db=db,
        owner=db.add_account(org_id=ORG_ID),
        colleague=db.add_account(org_id=ORG_ID),
        stranger=db.add_account(org_id=OTHER_ORG_ID),
    )


def _seq(db: FakeDb, message_id: uuid.UUID) -> int:
    return int(db.chat_messages[message_id]["seq"])


def _ids(db: FakeDb, chat: uuid.UUID) -> list[uuid.UUID]:
    return [row["id"] for row in db.messages_of(chat)]


def _plain(values: Any) -> list[uuid.UUID]:
    return [uuid.UUID(int=value.int) for value in values]


def _failed_tool_turn(db: FakeDb, owner: uuid.UUID) -> FailedTurn:
    """``U1 A1 U2 A(tool_use) T A(error)``; U1 with a file, U2 with three, one unsent."""
    hour_ago = datetime.now(UTC) - timedelta(hours=1)
    chat = db.add_chat(owner)
    u1 = db.add_chat_message(chat, "user", "first question")
    a1 = db.add_chat_message(chat, "assistant", "first answer")
    u2 = db.add_chat_message(chat, "user", "second question")
    tool_use = db.add_chat_message(chat, "assistant", "", tool_use_blocks=_TOOL_USE)
    result = db.add_chat_message(chat, "tool", "result", tool_call_id="toolu_1")
    error = db.add_chat_message(chat, "assistant", "", status="error")
    turn_files = [
        db.add_attachment(chat, message_id=u2, created_at=hour_ago, status="ready"),
        db.add_attachment(chat, message_id=u2, created_at=hour_ago, deleted_at=hour_ago),
        db.add_attachment(chat, message_id=u2, created_at=hour_ago, active=False),
    ]
    other_files = [
        db.add_attachment(chat, message_id=u1, created_at=hour_ago),
        db.add_attachment(chat, created_at=hour_ago),
    ]
    return FailedTurn(
        chat=chat,
        kept=[u1, a1],
        turn=[u2, tool_use, result, error],
        through_seq=_seq(db, error),
        turn_files=turn_files,
        other_files=other_files,
    )


def _migrations_copy(target: Path, extra: str | None) -> Path:
    """0001 to 0030 of the tree's migrations in ``target``, plus ``extra`` as 0031."""
    from admino import database

    source = Path(database.__file__).parent / "migrations"
    target.mkdir()
    for path in sorted(source.glob("*.sql")):
        match = re.match(r"(\d{4})_", path.name)
        if match is not None and int(match.group(1)) <= 30:
            shutil.copyfile(path, target / path.name)
    if extra is not None:
        (target / "0031_chat_retry.sql").write_text(extra, encoding="utf-8")
    return target


@pytest.fixture()
def functions_0030(tmp_path: Path) -> ShippedFunctions:
    """What 0001 to 0030 leave in place."""
    return db_fakes.read_shipped_functions(_migrations_copy(tmp_path / "m0030", None))


@pytest.fixture()
def functions_0031(tmp_path: Path) -> ShippedFunctions:
    """What 0001 to 0030 plus the contract's 0031 leave in place."""
    return db_fakes.read_shipped_functions(_migrations_copy(tmp_path / "m0031", MIGRATION_0031))


def _use(monkeypatch: pytest.MonkeyPatch, functions: ShippedFunctions) -> None:
    monkeypatch.setattr(db_fakes, "shipped_functions", lambda: functions)


async def _refused(db: FakeDb, *args: Any) -> str:
    """Call the function expecting its refusal; return the error text."""
    with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError) as caught:
        await db.pool.fetchval(DELETE_SQL, *args)
    return str(caught.value)


# ---------------------------------------------------------------------------
# 1. delete_failed_turn on the tree's shipped migrations (RED until 0031 ships)
# ---------------------------------------------------------------------------


class TestDeleteFailedTurn:
    """C1's real-PostgreSQL facts, on the fake with the tree's migrations."""

    async def test_fakedb_delete_failed_turn_tool_turn_returns_four_and_keeps_the_rest(
        self, world: World
    ) -> None:
        """U2 A(tool_use) T A(error): 4 rows deleted, U1 and A1 kept."""
        db = world.db
        turn = _failed_tool_turn(db, world.owner)

        deleted = await db.pool.fetchval(
            DELETE_SQL, turn.chat, ORG_ID, world.owner, turn.through_seq
        )

        assert (deleted, _ids(db, turn.chat)) == (4, turn.kept)

    async def test_fakedb_delete_failed_turn_unlinks_the_turn_files_never_deletes(
        self, world: World
    ) -> None:
        """Every file of U2 (live, trashed, excluded) stays, unlinked with a new
        updated_at; U1's file and the unsent one are untouched."""
        db = world.db
        turn = _failed_tool_turn(db, world.owner)
        before = {row["id"]: row for row in db.attachments_of(turn.chat)}
        started = datetime.now(UTC)

        await db.pool.fetchval(DELETE_SQL, turn.chat, ORG_ID, world.owner, turn.through_seq)

        after = {row["id"]: row for row in db.attachments_of(turn.chat)}
        assert set(after) == set(before)
        assert [
            (after[file]["message_id"], after[file]["updated_at"] >= started)
            for file in turn.turn_files
        ] == [(None, True)] * 3
        assert [after[file] for file in turn.other_files] == [
            before[file] for file in turn.other_files
        ]

    async def test_fakedb_delete_failed_turn_stop_on_the_user_row_deletes_it_alone(
        self, world: World
    ) -> None:
        """A stop before any output stores ``stopped`` on the user row: 1 row."""
        db = world.db
        chat = db.add_chat(world.owner)
        kept = [
            db.add_chat_message(chat, "user", "first"),
            db.add_chat_message(chat, "assistant", "answer"),
        ]
        stopped = db.add_chat_message(chat, "user", "second", status="stopped")

        deleted = await db.pool.fetchval(DELETE_SQL, chat, ORG_ID, world.owner, _seq(db, stopped))

        assert (deleted, _ids(db, chat)) == (1, kept)

    async def test_fakedb_delete_failed_turn_keeps_a_notice_after_the_failed_answer(
        self, world: World
    ) -> None:
        """U A(error) N(org notice, a user row): U and A go (2), the notice stays."""
        db = world.db
        chat = db.add_chat(world.owner)
        db.add_chat_message(chat, "user", "question")
        error = db.add_chat_message(chat, "assistant", "", status="error")
        notice = db.add_chat_message(chat, "user", "Your administrator changed a permission.")

        deleted = await db.pool.fetchval(DELETE_SQL, chat, ORG_ID, world.owner, _seq(db, error))

        assert (deleted, _ids(db, chat)) == (2, [notice])

    async def test_fakedb_delete_failed_turn_deletes_a_stopped_answer_turn(
        self, world: World
    ) -> None:
        """A stopped partial answer: its user row and the answer go (2)."""
        db = world.db
        chat = db.add_chat(world.owner)
        first = db.add_chat_message(chat, "user", "first")
        db.add_chat_message(chat, "user", "second")
        stopped = db.add_chat_message(chat, "assistant", "partial", status="stopped")

        deleted = await db.pool.fetchval(DELETE_SQL, chat, ORG_ID, world.owner, _seq(db, stopped))

        assert (deleted, _ids(db, chat)) == (2, [first])

    @pytest.mark.parametrize(
        "case",
        [
            "trashed_chat",
            "colleague_as_owner",
            "colleague_chat",
            "other_org",
            "unknown_chat",
            "complete_row",
            "awaiting_confirmation_row",
            "limit_reached_row",
            "assistant_row_after",
            "tool_row_after",
            "other_chat_seq",
            "no_row_at_seq",
            "no_user_row_before",
            "null_seq",
            "null_owner",
        ],
    )
    async def test_fakedb_delete_failed_turn_refusal_changes_nothing(
        self, world: World, case: str
    ) -> None:
        """Each refusal: InsufficientPrivilegeError with C1's text, no row data,
        and every table as it was."""
        db = world.db
        turn = _failed_tool_turn(db, world.owner)
        chat, org, owner, seq = turn.chat, ORG_ID, world.owner, turn.through_seq
        if case == "trashed_chat":
            db.chats[chat]["deleted_at"] = datetime.now(UTC)
        elif case == "colleague_as_owner":
            owner = world.colleague
        elif case == "colleague_chat":
            chat = _failed_tool_turn(db, world.colleague).chat
            seq = _seq(db, _ids(db, chat)[-1])
        elif case == "other_org":
            org = OTHER_ORG_ID
        elif case == "unknown_chat":
            chat = uuid.uuid4()
        elif case.endswith("_row") and case != "complete_row":
            status = case.removesuffix("_row")
            seq = _seq(db, db.add_chat_message(chat, "assistant", "", status=status))
        elif case == "complete_row":
            seq = _seq(db, db.add_chat_message(chat, "assistant", "fine"))
        elif case == "assistant_row_after":
            db.add_chat_message(chat, "user", "third")
            db.add_chat_message(chat, "assistant", "third answer")
        elif case == "tool_row_after":
            seq = _seq(
                db,
                db.add_chat_message(
                    chat, "assistant", "", tool_use_blocks=_TOOL_USE, status="stopped"
                ),
            )
            db.add_chat_message(chat, "tool", "result", tool_call_id="toolu_1")
        elif case == "other_chat_seq":
            other = _failed_tool_turn(db, world.owner)
            seq = other.through_seq
        elif case == "no_row_at_seq":
            seq = max(row["seq"] for row in db.chat_messages.values()) + 100
        elif case == "no_user_row_before":
            chat = db.add_chat(world.owner)
            seq = _seq(db, db.add_chat_message(chat, "assistant", "", status="error"))
            db.add_chat_message(chat, "user", "a later notice")
        elif case == "null_seq":
            seq = None
        else:
            owner = None
        before = db.snapshot()

        text = await _refused(db, chat, org, owner, seq)

        assert (text, db.snapshot() == before) == (REFUSAL, True)

    async def test_fakedb_delete_failed_turn_commits_with_its_transaction(
        self, world: World
    ) -> None:
        """On a connection inside ``conn.transaction()``: recorded in that
        transaction, the deletion stays after the commit."""
        db = world.db
        turn = _failed_tool_turn(db, world.owner)

        async with db.pool.acquire() as conn, conn.transaction():
            deleted = await conn.fetchval(
                DELETE_SQL, turn.chat, ORG_ID, world.owner, turn.through_seq
            )
        (call,) = db.matching(r"delete_failed_turn")

        assert (deleted, call.tx is not None, db.transactions[-1][1], _ids(db, turn.chat)) == (
            4,
            True,
            "commit",
            turn.kept,
        )

    async def test_fakedb_delete_failed_turn_rolls_back_with_its_transaction(
        self, world: World
    ) -> None:
        """A failure later in the transaction undoes the delete and the unlink."""
        db = world.db
        turn = _failed_tool_turn(db, world.owner)
        before = db.snapshot()

        class _LaterError(Exception):
            pass

        with pytest.raises(_LaterError):
            async with db.pool.acquire() as conn, conn.transaction():
                deleted = await conn.fetchval(
                    DELETE_SQL, turn.chat, ORG_ID, world.owner, turn.through_seq
                )
                assert deleted == 4
                raise _LaterError

        assert (db.snapshot() == before, db.transactions[-1][1]) == (True, "rollback:_LaterError")

    @pytest.mark.parametrize(
        ("method", "expected"),
        [
            ("fetchval", 2),
            ("fetchrow", {"delete_failed_turn": 2}),
            ("fetch", [{"delete_failed_turn": 2}]),
            ("execute", "SELECT 1"),
        ],
        ids=["fetchval", "fetchrow", "fetch", "execute"],
    )
    async def test_fakedb_delete_failed_turn_answers_like_asyncpg(
        self, world: World, method: str, expected: Any
    ) -> None:
        """fetchval: the count; fetchrow / fetch: a row named after the function;
        execute: the SELECT status. The rows go whichever way it is called."""
        db = world.db
        chat = db.add_chat(world.owner)
        db.add_chat_message(chat, "user", "question")
        error = db.add_chat_message(chat, "assistant", "", status="error")

        answer = await getattr(db.pool, method)(
            DELETE_SQL, chat, ORG_ID, world.owner, _seq(db, error)
        )

        assert (answer, _ids(db, chat)) == (expected, [])

    async def test_fakedb_delete_failed_turn_alias_names_the_row(self, world: World) -> None:
        """``SELECT delete_failed_turn(...) AS deleted`` names the column."""
        db = world.db
        chat = db.add_chat(world.owner)
        stopped = db.add_chat_message(chat, "user", "question", status="stopped")

        row = await db.pool.fetchrow(
            "SELECT delete_failed_turn($1, $2, $3, $4) AS deleted",
            chat,
            ORG_ID,
            world.owner,
            _seq(db, stopped),
        )

        assert row == {"deleted": 1}

    @pytest.mark.parametrize(
        ("args", "error"),
        [
            pytest.param(3, asyncpg.exceptions.InterfaceError, id="three_arguments"),
            pytest.param("chat", asyncpg.exceptions.DataError, id="chat_not_a_uuid"),
            pytest.param("org", asyncpg.exceptions.DataError, id="org_an_int"),
            pytest.param("seq_text", asyncpg.exceptions.DataError, id="seq_a_str"),
            pytest.param("seq_big", asyncpg.exceptions.DataError, id="seq_beyond_int64"),
        ],
    )
    async def test_fakedb_delete_failed_turn_checks_the_binds_first(
        self, world: World, args: Any, error: type[Exception]
    ) -> None:
        """asyncpg's checks: the argument count and the uuid / bigint encoders,
        before anything runs."""
        db = world.db
        chat = db.add_chat(world.owner)
        error_row = db.add_chat_message(chat, "assistant", "", status="error")
        values: list[Any] = [chat, ORG_ID, world.owner, _seq(db, error_row)]
        if args == 3:
            values = values[:3]
        elif args == "chat":
            values[0] = "not-a-uuid"
        elif args == "org":
            values[1] = 7
        elif args == "seq_text":
            values[3] = str(values[3])
        else:
            values[3] = 2**63
        before = db.snapshot()

        with pytest.raises(error):
            await db.pool.fetchval(DELETE_SQL, *values)

        assert db.snapshot() == before

    async def test_fakedb_delete_failed_turn_resolves_only_the_four_argument_signature(
        self, world: World
    ) -> None:
        """Another arity or a text argument doesn't resolve (UndefinedFunctionError);
        the shipped signature does."""
        db = world.db
        chat = db.add_chat(world.owner)
        stopped = db.add_chat_message(chat, "user", "question", status="stopped")
        seq = _seq(db, stopped)
        refused = []
        for sql, args in (
            ("SELECT delete_failed_turn($1, $2, $3)", (chat, ORG_ID, world.owner)),
            (
                "SELECT delete_failed_turn($1::text, $2, $3, $4)",
                (str(chat), ORG_ID, world.owner, seq),
            ),
        ):
            with pytest.raises(asyncpg.exceptions.UndefinedFunctionError):
                await db.pool.fetchval(sql, *args)
            refused.append(sql)

        deleted = await db.pool.fetchval(
            "SELECT public.delete_failed_turn($1::uuid, $2::uuid, $3::uuid, $4::bigint)",
            chat,
            ORG_ID,
            world.owner,
            seq,
        )

        assert (len(refused), deleted) == (2, 1)


# ---------------------------------------------------------------------------
# 1b. The turn's shape (C1', security audit M-1; RED until 0031 ships)
# ---------------------------------------------------------------------------

# A row of a seeded turn: (role, content, status, extra add_chat_message keywords).
_Row = tuple[str, str, str, dict[str, Any]]

_TWO_BLOCKS = [
    {"type": "tool_use", "id": "toolu_1", "name": "memory_read", "input": {}},
    {"type": "tool_use", "id": "toolu_2", "name": "memory_read", "input": {}},
]
_SECOND_CALL = [{"type": "tool_use", "id": "toolu_2", "name": "memory_list", "input": {}}]
_CREATE_CALL = [
    {"type": "tool_use", "id": "toolu_c", "name": "google_calendar_create", "input": {}}
]
# GH-24: the closing tool result of a confirmation refused at the pending limit.
_PENDING_LIMIT_RESULT = "Tool call denied: too many confirmations are pending."

_U: _Row = ("user", "question", "complete", {})
_CALL: _Row = ("assistant", "", "complete", {"tool_use_blocks": _TOOL_USE})
_RESULT: _Row = ("tool", "result", "complete", {"tool_call_id": "toolu_1"})
_ERROR: _Row = ("assistant", "The provider failed.", "error", {})
_FINAL: _Row = ("assistant", "final answer", "complete", {})
_FORGED_ERROR: _Row = ("assistant", "forged", "error", {})
# GH-25 D9 (C1'b): a streamed run's text shown before it timed out, stored ``error``
# (no tool_use blocks) right before the error reply.
_D9_PARTIAL: _Row = ("assistant", "Day one: Zurich ", "error", {})
_TIMEOUT_ERROR: _Row = ("assistant", "The request timed out.", "error", {})

# The real failed turns (what the server stores) and how many rows each deletes.
_REAL_TURNS: dict[str, tuple[tuple[_Row, ...], int]] = {
    "tool-turn-error": ((_U, _CALL, _RESULT, _ERROR), 4),
    "approval-continuation-error": (
        (
            _U,
            ("assistant", "", "awaiting_confirmation", {"tool_use_blocks": _TOOL_USE}),
            _RESULT,
            _ERROR,
        ),
        4,
    ),
    "stopped-user-row": ((("user", "question", "stopped", {}),), 1),
    "stopped-tool-row-after-two-blocks": (
        (
            _U,
            ("assistant", "partial text", "complete", {"tool_use_blocks": _TWO_BLOCKS}),
            _RESULT,
            ("tool", "cut", "stopped", {"tool_call_id": "toolu_2"}),
        ),
        4,
    ),
    "stopped-partial": ((_U, ("assistant", "part", "stopped", {})), 2),
    "pending-limit-turn": (
        (
            _U,
            ("assistant", "I'll add it.", "complete", {"tool_use_blocks": _CREATE_CALL}),
            ("tool", _PENDING_LIMIT_RESULT, "complete", {"tool_call_id": "toolu_c"}),
            ("assistant", "Action google_calendar.create was not run.", "error", {}),
        ),
        4,
    ),
    "two-tool-rounds-error": (
        (
            _U,
            _CALL,
            _RESULT,
            ("assistant", "", "complete", {"tool_use_blocks": _SECOND_CALL}),
            ("tool", "second result", "complete", {"tool_call_id": "toolu_2"}),
            _ERROR,
        ),
        6,
    ),
    # C1'b: GH-25 D9, a streamed timeout after text (the partial stored ``error``).
    "d9-timeout-partial": ((_U, _D9_PARTIAL, _TIMEOUT_ERROR), 3),
    "d9-timeout-partial-with-empty-blocks": (
        (_U, ("assistant", "Day one: ", "error", {"tool_use_blocks": []}), _TIMEOUT_ERROR),
        3,
    ),
    "tool-turn-ending-in-a-d9-partial": ((_U, _CALL, _RESULT, _D9_PARTIAL, _TIMEOUT_ERROR), 5),
}

# A completed turn, then a row admino_app forged after it (INSERT is all it needs).
_FORGED_TURNS: dict[str, tuple[_Row, ...]] = {
    "error-after-a-complete-answer": (_U, _FINAL, _FORGED_ERROR),
    "stopped-tool-after-a-completed-tool-turn": (
        _U,
        _CALL,
        _RESULT,
        _FINAL,
        ("tool", "forged", "stopped", {"tool_call_id": "toolu_9"}),
    ),
    "error-after-limit-reached": (
        _U,
        ("assistant", "The tool-call limit was reached.", "limit_reached", {}),
        _FORGED_ERROR,
    ),
    "error-after-an-answer-with-empty-blocks": (
        _U,
        ("assistant", "final answer", "complete", {"tool_use_blocks": []}),
        _FORGED_ERROR,
    ),
    # Every row between is checked, not only the one before the forged row.
    "error-after-a-forged-tool-call-after-a-complete-answer": (
        _U,
        _FINAL,
        ("assistant", "", "complete", {"tool_use_blocks": _TOOL_USE}),
        _FORGED_ERROR,
    ),
}

# The (middle row kind, status) grid: one row between the user row and an error row.
_MIDDLE_KINDS: dict[str, tuple[str, str, dict[str, Any]]] = {
    "tool": ("tool", "result", {"tool_call_id": "toolu_1"}),
    "assistant-tool-use": ("assistant", "", {"tool_use_blocks": _TOOL_USE}),
    "assistant-null-blocks": ("assistant", "an answer", {}),
    "assistant-empty-blocks": ("assistant", "an answer", {"tool_use_blocks": []}),
}
_STATUSES = ("complete", "awaiting_confirmation", "stopped", "error", "limit_reached")
_ADMITTED = {
    (kind, status)
    for kind in ("tool", "assistant-tool-use")
    for status in ("complete", "awaiting_confirmation")
} | {
    # C1'b: an assistant error row (GH-25 D9's partial), whatever its blocks.
    (kind, "error")
    for kind in ("assistant-tool-use", "assistant-null-blocks", "assistant-empty-blocks")
}


@dataclass
class _Turn:
    """A chat ``U0 A0 | <rows>``: the kept rows, the turn's rows, its last seq, U's file."""

    chat: uuid.UUID
    kept: list[uuid.UUID]
    turn: list[uuid.UUID]
    through_seq: int
    file: uuid.UUID


def _turn_chat(db: FakeDb, owner: uuid.UUID, rows: tuple[_Row, ...]) -> _Turn:
    """A completed exchange, then ``rows`` stored in order (the first one the turn's user
    row, carrying a file), as the server or a forger with INSERT stores them."""
    chat = db.add_chat(owner)
    kept = [
        db.add_chat_message(chat, "user", "earlier question"),
        db.add_chat_message(chat, "assistant", "earlier answer"),
    ]
    turn = [
        db.add_chat_message(chat, role, content, status=status, **extra)
        for role, content, status, extra in rows
    ]
    file = db.add_attachment(
        chat, message_id=turn[0], created_at=datetime.now(UTC) - timedelta(hours=1)
    )
    return _Turn(chat=chat, kept=kept, turn=turn, through_seq=_seq(db, turn[-1]), file=file)


class TestDeleteFailedTurnShape:
    """C1': the rows between the turn's user row and through_seq must be a real failed
    turn's (tool calls, their results, an approval's awaiting row)."""

    @pytest.mark.parametrize("shape", list(_REAL_TURNS))
    async def test_fakedb_delete_failed_turn_real_failed_turn_is_deleted(
        self, world: World, shape: str
    ) -> None:
        """What the server stores for a failed run: the turn goes (its count), the
        completed exchange before it stays, the turn's file is unlinked."""
        rows, count = _REAL_TURNS[shape]
        db = world.db
        turn = _turn_chat(db, world.owner, rows)

        deleted = await db.pool.fetchval(
            DELETE_SQL, turn.chat, ORG_ID, world.owner, turn.through_seq
        )

        file = db.attachment_row(turn.file)
        assert file is not None
        assert (deleted, _ids(db, turn.chat), file["message_id"]) == (count, turn.kept, None)

    @pytest.mark.parametrize("shape", list(_FORGED_TURNS))
    async def test_fakedb_delete_failed_turn_forged_row_after_a_completed_turn_is_refused(
        self, world: World, shape: str
    ) -> None:
        """M-1: a failed-looking last row admino_app inserted after a completed turn:
        refused with C1's text, every table as it was (the turn's file still linked)."""
        db = world.db
        turn = _turn_chat(db, world.owner, _FORGED_TURNS[shape])
        before = db.snapshot()

        text = await _refused(db, turn.chat, ORG_ID, world.owner, turn.through_seq)

        assert (text, db.snapshot() == before) == (REFUSAL, True)

    async def test_fakedb_delete_failed_turn_forged_row_is_refused_before_the_delete(
        self, world: World, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The shape is checked in the body's checks, before its UPDATE and DELETE: on a
        0031 without SECURITY DEFINER a forged turn is C1's refusal, not "permission
        denied for table chat_messages"."""
        directory = _migrations_copy(tmp_path / "invoker", MIGRATION_0031_INVOKER)
        _use(monkeypatch, db_fakes.read_shipped_functions(directory))
        db = world.db
        turn = _turn_chat(db, world.owner, _FORGED_TURNS["error-after-a-complete-answer"])
        before = db.snapshot()

        text = await _refused(db, turn.chat, ORG_ID, world.owner, turn.through_seq)

        assert (text, db.snapshot() == before) == (REFUSAL, True)

    @pytest.mark.parametrize("status", _STATUSES)
    @pytest.mark.parametrize("kind", list(_MIDDLE_KINDS))
    async def test_fakedb_delete_failed_turn_middle_row_kind_and_status_decide(
        self, world: World, kind: str, status: str
    ) -> None:
        """``U <one row> A(error)``: deleted (3) exactly when the row between is a tool row
        or an assistant row with tool_use blocks, complete or awaiting_confirmation, or
        (C1'b) an assistant row with status error; refused with nothing changed
        otherwise."""
        role, content, extra = _MIDDLE_KINDS[kind]
        db = world.db
        turn = _turn_chat(db, world.owner, (_U, (role, content, status, extra), _ERROR))
        before = db.snapshot()

        try:
            outcome: object = await db.pool.fetchval(
                DELETE_SQL, turn.chat, ORG_ID, world.owner, turn.through_seq
            )
        except asyncpg.exceptions.InsufficientPrivilegeError as exc:
            outcome = (str(exc), db.snapshot() == before)

        assert outcome == (3 if (kind, status) in _ADMITTED else (REFUSAL, True))

    async def test_fakedb_delete_failed_turn_legacy_d9_partial_not_backfilled_is_refused(
        self, world: World
    ) -> None:
        """C1'b: a D9 turn stored before the append rule, its partial still ``complete``
        (``U A(partial, complete, no blocks) A(error)``), is the very shape of a forged
        error after a completed answer: refused, nothing changed. On PostgreSQL 0031's
        backfill UPDATE marks such a partial ``error`` first (the fake runs no migration
        data statement), and then the turn deletes 3 (``d9-timeout-partial``)."""
        db = world.db
        legacy = (_U, ("assistant", "Day one: Zurich ", "complete", {}), _TIMEOUT_ERROR)
        turn = _turn_chat(db, world.owner, legacy)
        before = db.snapshot()

        text = await _refused(db, turn.chat, ORG_ID, world.owner, turn.through_seq)

        assert (text, db.snapshot() == before) == (REFUSAL, True)

    async def test_fakedb_delete_failed_turn_forged_row_after_an_awaiting_call_is_the_residual(
        self, world: World
    ) -> None:
        """The documented residual (Low, C1'): a row forged after a still-awaiting tool
        call (pending or expired) passes the shape check; U, the awaiting row and the
        forged row go (3)."""
        db = world.db
        turn = _turn_chat(
            db,
            world.owner,
            (
                _U,
                ("assistant", "", "awaiting_confirmation", {"tool_use_blocks": _TOOL_USE}),
                _FORGED_ERROR,
            ),
        )

        deleted = await db.pool.fetchval(
            DELETE_SQL, turn.chat, ORG_ID, world.owner, turn.through_seq
        )

        assert (deleted, _ids(db, turn.chat)) == (3, turn.kept)


# ---------------------------------------------------------------------------
# 2. What the migrations ship (the gate of the emulation)
# ---------------------------------------------------------------------------


class TestShippedFunctions:
    """``read_shipped_functions`` and the emulation's gate."""

    def test_fakedb_functions_of_0001_to_0030_lack_delete_failed_turn(
        self, functions_0030: ShippedFunctions
    ) -> None:
        """0030's migrations: only the two purges are executable and owner-run."""
        assert (
            "delete_failed_turn" in functions_0030.created,
            functions_0030.executable,
            functions_0030.security_definer,
        ) == (False, PURGES, PURGES)

    def test_fakedb_functions_with_the_contract_0031_add_delete_failed_turn(
        self, functions_0030: ShippedFunctions, functions_0031: ShippedFunctions
    ) -> None:
        """The contract's 0031: created, executable by admino_app, SECURITY DEFINER."""
        assert functions_0031 == ShippedFunctions(
            created=functions_0030.created | {"delete_failed_turn"},
            executable=PURGES | {"delete_failed_turn"},
            security_definer=PURGES | {"delete_failed_turn"},
        )

    def test_fakedb_functions_ignore_a_0031_in_comments(
        self, tmp_path: Path, functions_0030: ShippedFunctions
    ) -> None:
        """A 0031 that only describes the statements in comments creates nothing."""
        directory = _migrations_copy(tmp_path / "comments", MIGRATION_0031_COMMENTS_ONLY)

        assert db_fakes.read_shipped_functions(directory) == functions_0030

    def test_fakedb_0031_leaves_the_shipped_schema_as_it_is(self, tmp_path: Path) -> None:
        """0031 changes nothing ``read_shipped_schema`` reads (no column, grant,
        CHECK or catalog), so the GH-190 schema pins hold with it."""
        without = db_fakes.read_shipped_schema(_migrations_copy(tmp_path / "a", None))
        with_0031 = db_fakes.read_shipped_schema(_migrations_copy(tmp_path / "b", MIGRATION_0031))

        assert with_0031 == without

    def test_fakedb_shipped_migrations_give_the_0031_functions(
        self, functions_0031: ShippedFunctions
    ) -> None:
        """The tree's own migrations (what the fake uses unpatched) leave 0031's
        functions (RED until 0031 ships)."""
        assert db_fakes.shipped_functions() == functions_0031

    async def test_fakedb_delete_failed_turn_is_undefined_before_0031(
        self, world: World, monkeypatch: pytest.MonkeyPatch, functions_0030: ShippedFunctions
    ) -> None:
        """No migration creates it: UndefinedFunctionError, before the binds are
        checked, nothing changed."""
        _use(monkeypatch, functions_0030)
        db = world.db
        turn = _failed_tool_turn(db, world.owner)
        before = db.snapshot()

        with pytest.raises(asyncpg.exceptions.UndefinedFunctionError):
            await db.pool.fetchval(DELETE_SQL, turn.chat, ORG_ID)

        assert db.snapshot() == before

    async def test_fakedb_delete_failed_turn_without_the_grant_is_permission_denied(
        self, world: World, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A 0031 without ``GRANT EXECUTE ... TO admino_app`` (0018 revoked PUBLIC's
        default): permission denied for the function, nothing changed."""
        directory = _migrations_copy(tmp_path / "nogrant", MIGRATION_0031_WITHOUT_GRANT)
        _use(monkeypatch, db_fakes.read_shipped_functions(directory))
        db = world.db
        turn = _failed_tool_turn(db, world.owner)
        before = db.snapshot()

        with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError) as caught:
            await db.pool.fetchval(DELETE_SQL, turn.chat, ORG_ID, world.owner, turn.through_seq)

        assert (str(caught.value), db.snapshot() == before) == (
            "permission denied for function delete_failed_turn",
            True,
        )

    async def test_fakedb_delete_failed_turn_as_invoker_fails_at_the_delete(
        self, world: World, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Without SECURITY DEFINER the body runs as admino_app, which may not
        DELETE chat_messages: the statement fails and nothing changes."""
        directory = _migrations_copy(tmp_path / "invoker", MIGRATION_0031_INVOKER)
        _use(monkeypatch, db_fakes.read_shipped_functions(directory))
        db = world.db
        turn = _failed_tool_turn(db, world.owner)
        before = db.snapshot()

        with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError) as caught:
            await db.pool.fetchval(DELETE_SQL, turn.chat, ORG_ID, world.owner, turn.through_seq)

        assert (str(caught.value), db.snapshot() == before) == (
            "permission denied for table chat_messages",
            True,
        )

    async def test_fakedb_delete_failed_turn_with_the_0031_functions_runs_on_any_tree(
        self, world: World, monkeypatch: pytest.MonkeyPatch, functions_0031: ShippedFunctions
    ) -> None:
        """The documented switch: with 0031's functions patched in, the call runs
        (how a test on a tree without 0031 reaches the emulation)."""
        _use(monkeypatch, functions_0031)
        db = world.db
        turn = _failed_tool_turn(db, world.owner)

        deleted = await db.pool.fetchval(
            DELETE_SQL, turn.chat, ORG_ID, world.owner, turn.through_seq
        )

        assert (deleted, _ids(db, turn.chat)) == (4, turn.kept)


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM chat_messages WHERE chat_id = $1 AND org_id = $2",
        "UPDATE chat_messages SET status = 'complete' WHERE chat_id = $1 AND org_id = $2",
    ],
    ids=["delete", "update"],
)
async def test_fakedb_admino_app_still_may_not_delete_or_update_chat_messages(
    world: World, sql: str
) -> None:
    """chat_messages stays append-only for admino_app (Decision 7)."""
    db = world.db
    turn = _failed_tool_turn(db, world.owner)
    before = db.snapshot()

    with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError) as caught:
        await db.pool.execute(sql, turn.chat, ORG_ID)

    assert (str(caught.value), db.snapshot() == before) == (
        "permission denied for table chat_messages",
        True,
    )


# ---------------------------------------------------------------------------
# 3. R1 and T2b on the reader (fake infrastructure: pass today)
# ---------------------------------------------------------------------------


class TestRetryTargetStatement:
    """R1 answers as PostgreSQL does."""

    async def test_fakedb_r1_failed_turn_row(self, world: World) -> None:
        """The latest row's seq and status, the latest user row's seq and content,
        and its live files (excluded ones too, not trashed) in created_at, id order."""
        db = world.db
        turn = _failed_tool_turn(db, world.owner)
        u2 = turn.turn[0]
        now = datetime.now(UTC)
        newer = db.add_attachment(turn.chat, message_id=u2, created_at=now)
        tied = sorted(
            db.add_attachment(turn.chat, message_id=u2, created_at=now - timedelta(minutes=1))
            for _ in range(2)
        )
        live, _trashed, excluded = turn.turn_files

        row = await db.pool.fetchrow(R1_SQL, turn.chat, ORG_ID, world.owner)

        assert row is not None
        assert {
            **row,
            "id": uuid.UUID(int=row["id"].int),
            "attachment_ids": _plain(row["attachment_ids"]),
        } == {
            "id": turn.chat,
            "through_seq": turn.through_seq,
            "status": "error",
            "user_seq": _seq(db, u2),
            "content": "second question",
            "attachment_ids": sorted([live, excluded]) + tied + [newer],
        }

    async def test_fakedb_r1_chat_without_messages_has_null_columns(self, world: World) -> None:
        """No message: one row, the latest and turn columns NULL, no files."""
        db = world.db
        chat = db.add_chat(world.owner)

        row = await db.pool.fetchrow(R1_SQL, chat, ORG_ID, world.owner)

        assert row is not None
        assert {key: value for key, value in row.items() if key != "id"} == {
            "through_seq": None,
            "status": None,
            "user_seq": None,
            "content": None,
            "attachment_ids": [],
        }

    async def test_fakedb_r1_latest_row_of_any_role(self, world: World) -> None:
        """A notice (user row) after the failed answer is the latest row; a stop
        on the user row makes it both the latest and the turn row."""
        db = world.db
        noticed = db.add_chat(world.owner)
        db.add_chat_message(noticed, "user", "question")
        db.add_chat_message(noticed, "assistant", "", status="error")
        notice = db.add_chat_message(noticed, "user", "notice")
        stopped_chat = db.add_chat(world.owner)
        stopped = db.add_chat_message(stopped_chat, "user", "asked", status="stopped")

        rows = [
            await db.pool.fetchrow(R1_SQL, chat, ORG_ID, world.owner)
            for chat in (noticed, stopped_chat)
        ]

        assert [
            (row["through_seq"], row["status"], row["user_seq"], row["content"]) for row in rows
        ] == [
            (_seq(db, notice), "complete", _seq(db, notice), "notice"),
            (_seq(db, stopped), "stopped", _seq(db, stopped), "asked"),
        ]

    @pytest.mark.parametrize("case", ["colleague", "other_org", "trashed", "unknown"])
    async def test_fakedb_r1_no_row_outside_the_callers_live_chats(
        self, world: World, case: str
    ) -> None:
        """Another owner's, another org's, a trashed or an unknown chat: no row."""
        db = world.db
        chat = _failed_tool_turn(db, world.owner).chat
        org, owner = ORG_ID, world.owner
        if case == "colleague":
            owner = world.colleague
        elif case == "other_org":
            chat = _failed_tool_turn(db, world.stranger).chat
            org = OTHER_ORG_ID
        elif case == "trashed":
            db.chats[chat]["deleted_at"] = datetime.now(UTC)
        else:
            chat = uuid.uuid4()

        assert await db.pool.fetchrow(R1_SQL, chat, org, owner) is None


class TestTurnBeforeStatement:
    """T2b answers as PostgreSQL does; T2'' is unchanged."""

    async def test_fakedb_t2b_loads_the_messages_before_the_bound(self, world: World) -> None:
        """The latest ``limit`` messages before ``$5``, newest first; T2'' all of them."""
        db = world.db
        turn = _failed_tool_turn(db, world.owner)
        bound = _seq(db, turn.turn[0])
        args = (turn.chat, ORG_ID, world.owner)

        before_all = await db.pool.fetch(T2B_SQL, *args, 200, bound)
        before_one = await db.pool.fetch(T2B_SQL, *args, 1, bound)
        unbounded = await db.pool.fetch(T2_SQL, *args, 200)

        assert [
            [row["content"] for row in rows] for rows in (before_all, before_one, unbounded)
        ] == [
            ["first answer", "first question"],
            ["first answer"],
            ["", "result", "", "second question", "first answer", "first question"],
        ]

    async def test_fakedb_t2b_keeps_the_chats_active_attachments(self, world: World) -> None:
        """The active files don't depend on the bound: U2's ready, live, included
        file is there although U2 is past it."""
        db = world.db
        turn = _failed_tool_turn(db, world.owner)
        live = turn.turn_files[0]

        rows = await db.pool.fetch(
            T2B_SQL, turn.chat, ORG_ID, world.owner, 200, _seq(db, turn.turn[0])
        )

        assert [entry[0] for entry in rows[0]["attachment_rows"]] == [str(live)]

    async def test_fakedb_t2b_no_row_for_another_owner(self, world: World) -> None:
        """The owner filters on the chat still decide."""
        db = world.db
        turn = _failed_tool_turn(db, world.owner)

        rows = await db.pool.fetch(T2B_SQL, turn.chat, ORG_ID, world.colleague, 200, 10**6)

        assert rows == []

    async def test_fakedb_t2b_bound_is_typed_as_the_bigint_seq(self, world: World) -> None:
        """``seq < $5`` types the bound: a str is asyncpg's DataError."""
        db = world.db
        turn = _failed_tool_turn(db, world.owner)

        with pytest.raises(asyncpg.exceptions.DataError):
            await db.pool.fetch(T2B_SQL, turn.chat, ORG_ID, world.owner, 200, "5")
