"""Spec for the attachment ids of a ``tool.call`` audit row (GH-189, contract C10 and
C11, issue Decision 10).

What is pinned here:

- ``audit_events`` metadata accepts, as a value, a list or tuple of 1 to 100 UUID
  objects. Each is canonicalized like a target id (rebuilt from its 128 bits, so an
  asyncpg ``UUID`` or any other subclass loses its behavior) and the value is stored
  as a JSON array of canonical UUID strings, in order. Anything else in a list is
  refused with ``AuditRecordError`` before anything is written: an empty list, 101
  items, a UUID-shaped str (any spelling), bytes, nested lists, a mix of UUIDs and
  other values (the last of 100 too), None, a set, a dict, an iterator, vocabulary
  tokens, ints, floats and bools. The error carries no input and is raised from None.
- ``record_tool_call(..., escalated, attachment_ids=())``: keyword-only, default empty.
  Empty (default, ``()`` or ``[]``): exactly the six metadata keys of today. Non-empty:
  plus ``attachment_ids`` (the first 100, canonical, order kept) and
  ``attachment_count`` (the total, so 150 ids store 100 and a count of 150). The row is
  still the member's ``tool.call`` on the chat (the ids are metadata, never targets).
  Nothing else about a file is recorded: no name, kind or size parameter, no other
  key; a file name passed as ids is refused and not echoed. A failed write logs no id.
- ``main._build_tool_call_recorder()``'s recorder takes a keyword-only
  ``attachment_ids`` (default empty) and forwards it to ``record_tool_call``; without
  ids (default or empty) it calls ``record_tool_call`` exactly as today, with no
  ``attachment_ids`` keyword. End to end through the real ``record_tool_call``, asyncpg
  ids reach the bound metadata canonical.
- Contract Amendment A1 (C10, security audit F1), the Python mirror of the database's
  ``audit_events_metadata_check``: a list value is allowed under the key
  ``attachment_ids`` only; under any other key (``ids``, ``attachments``, ``tool``,
  ``target_ids``) it is refused with ``AuditRecordError`` and nothing is written. The
  metadata JSON text stays within 8192 bytes: the largest metadata the other rules let
  through (16 keys: 100 ids plus 15 forty-character keys holding UUIDs, about 5.3 KB,
  over 0005's 4096) is accepted, and through tests/db_fakes.py's enforced CHECK
  ``record_tool_call`` with 1, 100, 101 and 150 ids is stored (the first 100 and the
  total). Over 8192 bytes can't be built within the key, value and 16-key rules, so the
  refusal at 8193 bytes is pinned on the database side (tests/test_migration_0029.py).

The unit tests mock asyncpg; the Amendment A1 tests write through tests/db_fakes.py
(which enforces the CHECK the shipped migrations define). No real PostgreSQL, LLM or
network is used.

Security notes: the audit log stays content-free (tracker #139 section 5): IDs and
counts only, never a file name, kind, size or content; validation and write errors
never echo the ids or the rejected values.
"""

from __future__ import annotations

import inspect
import json
import re
import uuid
from typing import Any, Final
from unittest.mock import AsyncMock, MagicMock

import asyncpg
import pytest
from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811

import admino.main as main_module
from admino import audit_events
from admino.access import Principal
from admino.audit_events import AuditAction, AuditEvent, AuditRecordError, TargetType, record
from tests.db_fakes import FakeDb
from tests.log_capture import configured_logging

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ORG: Final = uuid.UUID("5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d")
_USER: Final = uuid.UUID("6b7c8d9e-0f1a-4b2c-9d3e-4f5a6b7c8d9e")
_CHAT: Final = uuid.UUID("7c8d9e0f-1a2b-4c3d-8e4f-5a6b7c8d9e0f")
_MEMBER: Final = Principal(user_id=_USER, kind="member", org_id=_ORG, role="editor")
_SESSION: Final = str(_CHAT)

# 150 distinct ids in descending order, so a sorted copy differs from the input.
_IDS: Final[tuple[uuid.UUID, ...]] = tuple(
    uuid.UUID(f"{0xE0000000 - n:08x}-{n:04x}-4189-8000-{0x189000000000 + n:012x}")
    for n in range(150)
)
_ID: Final = _IDS[0]
_OTHER_ID: Final = _IDS[1]

_LEAK: Final = "report-ZZ189.pdf"
_FILE_NAME: Final = "Quarterly-ZZ189-report.pdf"
_TODAYS_SIX: Final = frozenset(
    {"tool", "action", "decision", "success", "duration_ms", "escalated"}
)
_WITH_IDS: Final = _TODAYS_SIX | {"attachment_ids", "attachment_count"}

_INSERT_RE: Final = re.compile(r"^insert into audit_events\s*\(([^)]*)\)\s*values\s*\((.*)\)$")
_PLACEHOLDER_RE: Final = re.compile(r"\$(\d+)(?:\s*::\s*[a-z_]+(?:\[\])?)?")


class _TextUUID(uuid.UUID):
    """A UUID subclass whose str() is text: only a rebuild from the bits is canonical."""

    def __str__(self) -> str:
        return _LEAK


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def conn() -> MagicMock:
    """A mocked asyncpg connection whose execute succeeds."""
    connection = MagicMock(spec=asyncpg.Connection)
    connection.execute = AsyncMock(return_value="INSERT 0 1")
    return connection


def _canonical(ids: Any) -> list[str]:
    return [str(uuid.UUID(int=item.int)) for item in ids]


def _row(conn: MagicMock) -> dict[str, Any]:
    """Map each INSERT column of the one execute call to its bind argument."""
    assert conn.execute.await_count == 1, "exactly one execute"
    call = conn.execute.await_args
    sql = re.sub(r"\s+", " ", call.args[0]).strip().rstrip(";").strip().lower()
    match = _INSERT_RE.match(sql)
    assert match is not None, f"unexpected statement: {sql}"
    columns = [column.strip().strip('"') for column in match.group(1).split(",")]
    values = [value.strip() for value in match.group(2).split(",")]
    row: dict[str, Any] = {"__sql__": sql}
    for column, value in zip(columns, values, strict=True):
        placeholder = _PLACEHOLDER_RE.fullmatch(value)
        assert placeholder is not None, f"{column} is not a bind parameter: {value}"
        row[column] = call.args[int(placeholder.group(1))]
    return row


def _metadata(conn: MagicMock) -> dict[str, Any]:
    metadata: dict[str, Any] = json.loads(_row(conn)["metadata"])
    return metadata


async def _record_list(executor: Any, value: object) -> None:
    """record() a member's tool.call on the chat whose metadata holds ``value``."""
    await record(
        executor,
        action=AuditAction.TOOL_CALL,
        actor_kind="member",
        actor_user_id=_USER,
        org_id=_ORG,
        target_type=TargetType.CHAT,
        target_ids=(_CHAT,),
        metadata={"decision": "allow", "attachment_ids": value},  # type: ignore[dict-item]
    )


def _tool_call_kwargs(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "org_id": _ORG,
        "actor_user_id": _USER,
        "chat_id": _CHAT,
        "tool": "gmail",
        "action": "read",
        "decision": "allow",
        "success": True,
        "duration_ms": 42,
        "escalated": True,
    }
    kwargs.update(overrides)
    return kwargs


def _todays_metadata() -> dict[str, Any]:
    return {
        "tool": "gmail",
        "action": "read",
        "decision": "allow",
        "success": True,
        "duration_ms": 42,
        "escalated": True,
    }


def _recorder_kwargs(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "principal": _MEMBER,
        "session_id": _SESSION,
        "tool": "memory",
        "action": "store",
        "decision": "confirm",
        "success": False,
        "duration_ms": 3,
        "escalated": True,
    }
    kwargs.update(overrides)
    return kwargs


def _todays_record_call() -> dict[str, Any]:
    """The keywords main's recorder passes record_tool_call today (GH-243)."""
    return {
        "org_id": _ORG,
        "actor_user_id": _USER,
        "chat_id": _CHAT,
        "tool": "memory",
        "action": "store",
        "decision": "confirm",
        "success": False,
        "duration_ms": 3,
        "escalated": True,
    }


def _markers(value: object) -> list[str]:
    """Every text a value could leak: UUIDs in canonical and hex form, strs, bytes' hex."""
    if isinstance(value, uuid.UUID):
        return [str(uuid.UUID(int=value.int)), value.hex]
    if isinstance(value, str):
        return [value] if len(value) >= 4 else []
    if isinstance(value, bytes | bytearray):
        return [bytes(value).hex()]
    if isinstance(value, dict):
        return [m for key, item in value.items() for m in (*_markers(key), *_markers(item))]
    if isinstance(value, list | tuple | set | frozenset):
        return [m for item in value for m in _markers(item)]
    return []


def _assert_refused_cleanly(exc: AuditRecordError, value: object) -> None:
    """No input in the error, nothing chained to it."""
    text = str(exc) + repr(exc.args)
    leaked = [marker for marker in _markers(value) if marker.lower() in text.lower()]
    assert leaked == []
    assert exc.__cause__ is None
    assert exc.__suppress_context__ is True


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

_ACCEPTED_LISTS: list[Any] = [
    pytest.param(container(_IDS[:size]), id=f"{container.__name__}-{size}")
    for container in (list, tuple)
    for size in (1, 2, 100)
] + [
    pytest.param(
        container(PgUUID(str(item)) for item in _IDS[:size]),
        id=f"asyncpg-{container.__name__}-{size}",
    )
    for container in (list, tuple)
    for size in (1, 2, 100)
]


def _refused_lists() -> list[Any]:
    """Every metadata list value Decision 10 refuses (fresh objects per call)."""
    hundred = list(_IDS[:100])
    return [
        pytest.param([], id="empty-list"),
        pytest.param((), id="empty-tuple"),
        pytest.param(list(_IDS[:101]), id="list-of-101"),
        pytest.param(tuple(_IDS[:101]), id="tuple-of-101"),
        pytest.param([str(_ID)], id="uuid-shaped-str"),
        pytest.param([str(_ID).upper()], id="uuid-shaped-str-upper"),
        pytest.param([_ID.hex], id="uuid-hex-str"),
        pytest.param([f"{{{_ID}}}"], id="uuid-braced-str"),
        pytest.param([f"urn:uuid:{_ID}"], id="uuid-urn-str"),
        pytest.param([_ID.bytes], id="uuid-bytes"),
        pytest.param([bytearray(_ID.bytes)], id="uuid-bytearray"),
        pytest.param([_FILE_NAME], id="file-name"),
        pytest.param([[_ID]], id="nested-list"),
        pytest.param([(_ID,)], id="nested-tuple"),
        pytest.param(([_ID, _OTHER_ID],), id="tuple-of-list"),
        pytest.param([_ID, str(_OTHER_ID)], id="mixed-uuid-and-str"),
        pytest.param([*hundred[:99], str(hundred[99])], id="mixed-str-at-the-hundredth"),
        pytest.param([_ID, None], id="uuid-and-none"),
        pytest.param([None], id="none-inside"),
        pytest.param({_ID}, id="set"),
        pytest.param(frozenset({_ID}), id="frozenset"),
        pytest.param({"attachment": _ID}, id="dict-of-uuid"),
        pytest.param({_ID: True}, id="dict-keyed-by-uuid"),
        pytest.param(["editor"], id="vocabulary-role"),
        pytest.param(["gmail", "read"], id="vocabulary-tool-action"),
        pytest.param(["allow", "deny"], id="vocabulary-decisions"),
        pytest.param([1, 2], id="ints"),
        pytest.param([0], id="zero"),
        pytest.param([_ID.int], id="uuid-as-int"),
        pytest.param([True], id="bool"),
        pytest.param([False, True], id="bools"),
        pytest.param([1.0], id="float"),
        pytest.param([AuditAction.TOOL_CALL], id="enum-member"),
    ]


def _refused_iterators() -> list[Any]:
    return [
        pytest.param(lambda: iter([_ID]), id="iterator"),
        pytest.param(lambda: (item for item in (_ID, _OTHER_ID)), id="generator"),
        pytest.param(lambda: map(uuid.UUID, [str(_ID)]), id="map"),
    ]


# ===========================================================================
# 1. Metadata list values: accepted
# ===========================================================================


class TestMetadataUuidListAccepted:
    """A list or tuple of 1 to 100 UUID objects is stored as a JSON array of strings."""

    @pytest.mark.parametrize("value", _ACCEPTED_LISTS)
    async def test_audit_events_uuid_list_is_stored_as_canonical_strings_in_order(
        self, conn: MagicMock, value: Any
    ) -> None:
        await _record_list(conn, value)

        assert _metadata(conn)["attachment_ids"] == _canonical(value)

    async def test_audit_events_uuid_subclass_in_a_list_is_rebuilt_from_its_bits(
        self, conn: MagicMock
    ) -> None:
        """A subclass whose str() is text: the stored value is the canonical UUID, the
        subclass's text appears nowhere in the row."""
        value = [_TextUUID(str(_ID)), PgUUID(str(_OTHER_ID))]

        await _record_list(conn, value)

        raw = _row(conn)["metadata"]
        assert json.loads(raw)["attachment_ids"] == [str(_ID), str(_OTHER_ID)]
        assert _LEAK not in raw

    def test_audit_events_event_metadata_holds_a_list_of_plain_strings(self) -> None:
        """The validated event's value is a list[str] (MetadataValue), not UUID objects."""
        event = AuditEvent.model_validate(
            {
                "org_id": _ORG,
                "actor_kind": "member",
                "actor_user_id": _USER,
                "action": AuditAction.TOOL_CALL,
                "target_type": TargetType.CHAT,
                "target_ids": (_CHAT,),
                "metadata": {"attachment_ids": (PgUUID(str(_ID)), _OTHER_ID)},
            }
        )

        stored = event.metadata["attachment_ids"]
        assert type(stored) is list
        assert [type(item) for item in stored] == [str, str]
        assert stored == [str(_ID), str(_OTHER_ID)]

    async def test_audit_events_uuid_list_binds_only_as_a_parameter(self, conn: MagicMock) -> None:
        """The ids travel in the metadata bind parameter, never in the SQL text."""
        await _record_list(conn, list(_IDS[:3]))

        sql = _row(conn)["__sql__"]
        assert [item for item in _IDS[:3] if str(item) in sql or item.hex in sql] == []


# ===========================================================================
# 2. Metadata list values: refused
# ===========================================================================


class TestMetadataUuidListRefused:
    """Anything but 1 to 100 UUID objects in a list or tuple is refused; nothing written."""

    @pytest.mark.parametrize("value", _refused_lists())
    async def test_audit_events_invalid_list_value_raises_and_writes_nothing(
        self, conn: MagicMock, value: Any
    ) -> None:
        """The same key takes a valid list, and refuses this one before any write."""
        await _record_list(conn, [_ID])
        conn.execute.reset_mock()

        with pytest.raises(AuditRecordError) as caught:
            await _record_list(conn, value)

        conn.execute.assert_not_awaited()
        _assert_refused_cleanly(caught.value, value)

    @pytest.mark.parametrize("make", _refused_iterators())
    async def test_audit_events_iterator_of_uuids_is_refused(
        self, conn: MagicMock, make: Any
    ) -> None:
        """Only a list or tuple: a one-shot iterable is no metadata value."""
        await _record_list(conn, [_ID])
        conn.execute.reset_mock()

        with pytest.raises(AuditRecordError):
            await _record_list(conn, make())

        conn.execute.assert_not_awaited()

    def test_audit_events_invalid_list_on_the_event_model_is_a_validation_error(self) -> None:
        """The model refuses it too, and its error doesn't show the ids."""
        from pydantic import ValidationError

        accepted = AuditEvent.model_validate(
            {
                "org_id": _ORG,
                "actor_kind": "member",
                "actor_user_id": _USER,
                "action": AuditAction.TOOL_CALL,
                "metadata": {"attachment_ids": [_ID]},
            }
        )
        assert accepted.metadata["attachment_ids"] == [str(_ID)]
        with pytest.raises(ValidationError) as caught:
            AuditEvent.model_validate(
                {
                    "org_id": _ORG,
                    "actor_kind": "member",
                    "actor_user_id": _USER,
                    "action": AuditAction.TOOL_CALL,
                    "metadata": {"attachment_ids": [_ID, str(_OTHER_ID)]},
                }
            )

        assert str(_OTHER_ID) not in str(caught.value)
        assert str(_ID) not in str(caught.value)


# ===========================================================================
# 3. record_tool_call(attachment_ids=)
# ===========================================================================


class TestRecordToolCallAttachmentIds:
    """The tool.call row of a run whose slot 4 holds attachments carries their ids."""

    def test_audit_events_record_tool_call_attachment_ids_is_keyword_only_and_empty_by_default(
        self,
    ) -> None:
        params = inspect.signature(audit_events.record_tool_call).parameters

        assert "attachment_ids" in params
        assert params["attachment_ids"].kind is inspect.Parameter.KEYWORD_ONLY
        assert params["attachment_ids"].default == ()

    def test_audit_events_record_tool_call_takes_no_file_details(self) -> None:
        """Ids only: no name, kind, size or content parameter."""
        params = inspect.signature(audit_events.record_tool_call).parameters

        assert set(params) == {
            "executor",
            "org_id",
            "actor_user_id",
            "chat_id",
            "tool",
            "action",
            "decision",
            "success",
            "duration_ms",
            "escalated",
            "attachment_ids",
        }

    @pytest.mark.parametrize("empty", [(), []], ids=["tuple", "list"])
    async def test_audit_events_record_tool_call_empty_ids_write_todays_six_keys(
        self, conn: MagicMock, empty: Any
    ) -> None:
        await audit_events.record_tool_call(conn, **_tool_call_kwargs(), attachment_ids=empty)

        assert _metadata(conn) == _todays_metadata()

    @pytest.mark.parametrize("size", [1, 2, 3, 100])
    @pytest.mark.parametrize("container", [tuple, list])
    async def test_audit_events_record_tool_call_stores_the_ids_in_order_and_their_count(
        self, conn: MagicMock, size: int, container: type
    ) -> None:
        ids = container(_IDS[:size])

        await audit_events.record_tool_call(conn, **_tool_call_kwargs(), attachment_ids=ids)

        assert _metadata(conn) == {
            **_todays_metadata(),
            "attachment_ids": _canonical(ids),
            "attachment_count": size,
        }

    @pytest.mark.parametrize("size", [101, 150])
    async def test_audit_events_record_tool_call_stores_the_first_100_and_the_total(
        self, conn: MagicMock, size: int
    ) -> None:
        await audit_events.record_tool_call(conn, **_tool_call_kwargs(), attachment_ids=_IDS[:size])

        metadata = _metadata(conn)
        assert metadata["attachment_ids"] == _canonical(_IDS[:100])
        assert metadata["attachment_count"] == size
        assert type(metadata["attachment_count"]) is int

    async def test_audit_events_record_tool_call_canonicalizes_asyncpg_and_subclass_ids(
        self, conn: MagicMock
    ) -> None:
        ids = (PgUUID(str(_ID)), _TextUUID(str(_OTHER_ID)))

        await audit_events.record_tool_call(conn, **_tool_call_kwargs(), attachment_ids=ids)

        raw = _row(conn)["metadata"]
        assert json.loads(raw)["attachment_ids"] == [str(_ID), str(_OTHER_ID)]
        assert _LEAK not in raw

    async def test_audit_events_record_tool_call_with_ids_is_still_a_member_tool_call_on_the_chat(
        self, conn: MagicMock
    ) -> None:
        """The ids are metadata: the target stays the chat alone."""
        await audit_events.record_tool_call(conn, **_tool_call_kwargs(), attachment_ids=_IDS[:3])

        row = _row(conn)
        assert (row["action"], row["actor_kind"], row["target_type"]) == (
            "tool.call",
            "member",
            "chat",
        )
        assert (row["org_id"], row["actor_user_id"], row["ip"]) == (_ORG, _USER, None)
        assert json.loads(row["target_ids"]) == [str(_CHAT)]

    @pytest.mark.parametrize("size", [1, 150])
    async def test_audit_events_record_tool_call_with_ids_adds_exactly_two_keys(
        self, conn: MagicMock, size: int
    ) -> None:
        """No file name, kind, size or any other key: the six of today plus the two."""
        await audit_events.record_tool_call(conn, **_tool_call_kwargs(), attachment_ids=_IDS[:size])

        assert set(_metadata(conn)) == _WITH_IDS

    @pytest.mark.parametrize(
        "ids",
        [
            pytest.param(_FILE_NAME, id="file-name-as-str"),
            pytest.param([_FILE_NAME], id="file-name-in-list"),
            pytest.param([_ID, _FILE_NAME], id="uuid-then-file-name"),
            pytest.param([str(_ID)], id="uuid-shaped-str"),
            pytest.param([_ID.bytes], id="bytes"),
            pytest.param([None], id="none"),
            pytest.param([[_ID]], id="nested"),
            pytest.param([1], id="int"),
            pytest.param([True], id="bool"),
            pytest.param(["gmail"], id="vocabulary-token"),
        ],
    )
    async def test_audit_events_record_tool_call_invalid_ids_raise_and_write_nothing(
        self, conn: MagicMock, ids: Any
    ) -> None:
        await audit_events.record_tool_call(conn, **_tool_call_kwargs(), attachment_ids=[_ID])
        conn.execute.reset_mock()

        with pytest.raises(AuditRecordError) as caught:
            await audit_events.record_tool_call(conn, **_tool_call_kwargs(), attachment_ids=ids)

        conn.execute.assert_not_awaited()
        _assert_refused_cleanly(caught.value, ids)

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({"decision": "disabled"}, id="bad-decision"),
            pytest.param({"escalated": 1}, id="non-bool-escalated"),
        ],
    )
    async def test_audit_events_record_tool_call_with_ids_still_checks_its_other_fields(
        self, conn: MagicMock, overrides: dict[str, Any]
    ) -> None:
        await audit_events.record_tool_call(conn, **_tool_call_kwargs(), attachment_ids=[_ID])
        conn.execute.reset_mock()

        with pytest.raises(AuditRecordError):
            await audit_events.record_tool_call(
                conn, **_tool_call_kwargs(**overrides), attachment_ids=[_ID]
            )

        conn.execute.assert_not_awaited()

    async def test_audit_events_record_tool_call_with_ids_binds_them_as_parameters_only(
        self, conn: MagicMock
    ) -> None:
        await audit_events.record_tool_call(conn, **_tool_call_kwargs(), attachment_ids=_IDS[:5])

        sql = _row(conn)["__sql__"]
        assert [item for item in _IDS[:5] if str(item) in sql or item.hex in sql] == []

    async def test_audit_events_record_tool_call_failed_write_logs_no_attachment_id(
        self, conn: MagicMock
    ) -> None:
        """The driver's error echoes the row; the log line names the class only."""
        ids = _IDS[:3]
        conn.execute.side_effect = asyncpg.exceptions.CheckViolationError(
            f"Failing row contains ({_ORG}, {ids[0]}, {ids[1]}, {ids[2]}, {_FILE_NAME})"
        )

        with (
            configured_logging(level="DEBUG", log_format="json") as captured,
            pytest.raises(AuditRecordError) as caught,
        ):
            await audit_events.record_tool_call(conn, **_tool_call_kwargs(), attachment_ids=ids)

        text = captured.text.lower()
        assert conn.execute.await_count == 1
        assert [m for m in [*_markers(list(ids)), _FILE_NAME.lower()] if m.lower() in text] == []
        assert caught.value.__cause__ is None


# ===========================================================================
# 4. main's recorder forwards attachment_ids
# ===========================================================================


class TestMainRecorderForwardsAttachmentIds:
    """The recorder main() injects into the Agent forwards the run's attachment ids."""

    def test_main_recorder_takes_a_keyword_only_attachment_ids_defaulting_to_empty(
        self,
    ) -> None:
        params = inspect.signature(main_module._build_tool_call_recorder()).parameters

        assert "attachment_ids" in params
        assert params["attachment_ids"].kind is inspect.Parameter.KEYWORD_ONLY
        assert params["attachment_ids"].default == ()

    async def test_main_recorder_forwards_attachment_ids_to_record_tool_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pool = MagicMock(name="runtime-pool")
        record_tool_call = AsyncMock()
        monkeypatch.setattr("admino.database.get_pool", MagicMock(return_value=pool))
        monkeypatch.setattr("admino.audit_events.record_tool_call", record_tool_call)
        ids = (_OTHER_ID, _ID)

        await main_module._build_tool_call_recorder()(**_recorder_kwargs(), attachment_ids=ids)

        record_tool_call.assert_awaited_once()
        call = record_tool_call.await_args
        forwarded = dict(call.kwargs)
        assert tuple(forwarded.pop("attachment_ids")) == ids
        assert (call.args, forwarded) == ((pool,), _todays_record_call())

    async def test_main_recorder_with_empty_ids_calls_record_tool_call_exactly_as_today(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A run without attachments: no attachment_ids keyword at all."""
        pool = MagicMock(name="runtime-pool")
        record_tool_call = AsyncMock()
        monkeypatch.setattr("admino.database.get_pool", MagicMock(return_value=pool))
        monkeypatch.setattr("admino.audit_events.record_tool_call", record_tool_call)

        await main_module._build_tool_call_recorder()(**_recorder_kwargs(), attachment_ids=())

        record_tool_call.assert_awaited_once_with(pool, **_todays_record_call())

    async def test_main_recorder_writes_canonical_ids_through_the_real_record_tool_call(
        self, monkeypatch: pytest.MonkeyPatch, conn: MagicMock
    ) -> None:
        """End to end: asyncpg ids (what the turn read returns) reach the bound metadata
        canonical, with their count, on a member tool.call targeting the run's chat."""
        monkeypatch.setattr("admino.database.get_pool", MagicMock(return_value=conn))
        ids = (PgUUID(str(_ID)), PgUUID(str(_OTHER_ID)))

        await main_module._build_tool_call_recorder()(**_recorder_kwargs(), attachment_ids=ids)

        row = _row(conn)
        metadata = json.loads(row["metadata"])
        assert (metadata["attachment_ids"], metadata["attachment_count"]) == (
            [str(_ID), str(_OTHER_ID)],
            2,
        )
        assert (metadata["escalated"], json.loads(row["target_ids"])) == (True, [str(_CHAT)])


# ===========================================================================
# 5. The database's metadata rule, mirrored (Amendment A1, security audit F1)
# ===========================================================================

# Keys a list must not hide under: only attachment_ids may hold one.
_OTHER_LIST_KEYS: Final = ("ids", "attachments", "tool", "target_ids")


def _largest_metadata() -> dict[str, Any]:
    """The largest metadata the key, value and count rules allow: 100 ids under
    attachment_ids plus 15 forty-character keys holding a UUID each (16 keys)."""
    metadata: dict[str, Any] = {f"k{n:02d}".ljust(40, "x"): _IDS[100 + n] for n in range(15)}
    metadata["attachment_ids"] = list(_IDS[:100])
    return metadata


@pytest.fixture()
def fake_db() -> FakeDb:
    """The shared FakeDb with the run's org: its INSERT INTO audit_events applies the
    metadata CHECK the shipped migrations define."""
    db = FakeDb()
    db.add_org(_ORG)
    return db


class TestMetadataRuleSharedWithTheDatabase:
    """C10: Python refuses what the database's metadata CHECK refuses, and nothing it
    accepts; the rows record_tool_call builds pass that CHECK."""

    @pytest.mark.parametrize("key", _OTHER_LIST_KEYS)
    async def test_audit_events_list_under_another_key_raises_and_writes_nothing(
        self, conn: MagicMock, key: str
    ) -> None:
        """The same list is accepted under attachment_ids; under any other key it is
        refused before any write, and the error carries no id."""
        await _record_list(conn, [_ID])
        conn.execute.reset_mock()

        with pytest.raises(AuditRecordError) as caught:
            await record(
                conn,
                action=AuditAction.TOOL_CALL,
                actor_kind="member",
                actor_user_id=_USER,
                org_id=_ORG,
                target_type=TargetType.CHAT,
                target_ids=(_CHAT,),
                metadata={"decision": "allow", key: [_ID]},
            )

        conn.execute.assert_not_awaited()
        _assert_refused_cleanly(caught.value, [_ID])

    async def test_audit_events_largest_allowed_metadata_passes_the_database_check(
        self, fake_db: FakeDb
    ) -> None:
        """16 keys with 100 ids: over 0005's 4096 bytes, within 8192; stored as bound."""
        metadata = _largest_metadata()

        await record(
            fake_db.pool,
            action=AuditAction.TOOL_CALL,
            actor_kind="member",
            actor_user_id=_USER,
            org_id=_ORG,
            target_type=TargetType.CHAT,
            target_ids=(_CHAT,),
            metadata=metadata,
        )

        stored = [row["metadata"] for row in fake_db.audit]
        assert stored == [
            {
                **{key: str(value) for key, value in metadata.items() if key != "attachment_ids"},
                "attachment_ids": _canonical(_IDS[:100]),
            }
        ]
        assert 4096 < len(json.dumps(stored[0]).encode()) <= 8192

    @pytest.mark.parametrize("size", [1, 100, 101, 150])
    async def test_audit_events_record_tool_call_with_ids_passes_the_database_check(
        self, fake_db: FakeDb, size: int
    ) -> None:
        """1 and 100 ids are stored with their count; 101 and 150 store the first 100
        and the total."""
        await audit_events.record_tool_call(
            fake_db.pool, **_tool_call_kwargs(), attachment_ids=_IDS[:size]
        )

        assert [row["metadata"] for row in fake_db.audit] == [
            {
                **_todays_metadata(),
                "attachment_ids": _canonical(_IDS[: min(size, 100)]),
                "attachment_count": size,
            }
        ]
