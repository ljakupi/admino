"""Tests for the memory tool (admino.tools.memory): each user's own notes (GH-162).

The handlers ``memory_store`` / ``memory_recall`` / ``memory_list`` take the
validated args plus a required keyword-only ``tenant`` (``TenantContext``, built
server-side from the logged-in principal) and run against the shared
in-memory ``FakeDb`` (``tests/db_fakes.py``), which models migration 0017's
``memory`` table: ``user_id`` and ``org_id`` (FKs, NOT NULL), ``key`` (CHECK
``^[a-zA-Z0-9_. -]{1,200}$``), ``value`` (at most 2000 characters), primary key
``(user_id, key)``.

Covers:
- ``tenant`` is required: calling a handler without it is a TypeError.
- Isolation: a user only stores, recalls and lists their own notes; another
  user of the same org, or a user of another org, with the same key is
  separate, and a row under the user's id but another org is invisible.
- Store is an upsert on ``(user_id, key)``: the second value replaces the
  first, still one row.
- Outputs: "Stored memory: <key>"; a found note as one wrapped untrusted block
  (GH-243: kind "memory", label "memory note <key>", the value inside) or "No
  memory found for key: <key>"; the newline-joined sorted keys as one wrapped
  block (label "memory keys") or "No memories stored.".
- Every memory statement is parameterized and carries both the tenant's
  user_id and org_id as bind args; no key, value or id is interpolated.
- Registration is unchanged (store / recall / list, no delete handler) and
  ``memory.delete`` stays a hardcoded denial.
- The args models still reject bad keys and oversized values.

Security notes:
- Tenant isolation: content queries filter by the caller's org_id AND user_id
  from the TenantContext, never from a request or LLM value.
- No content in logs: memory keys and values never appear in log lines.
- No real PostgreSQL: ``admino.tools.memory.get_pool`` returns ``FakeDb.pool``.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import re
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import patch

import pytest
from pydantic import BaseModel, ValidationError

from admino.access import Principal
from admino.models import MemoryListArgs, MemoryRecallArgs, MemoryStoreArgs, ToolCall
from admino.permissions import PermissionsConfig, ToolPermissions, check_permission
from admino.tenancy import TenantContext
from admino.tools.registry import clear_registry, get_registered_tools, get_tool_entry
from tests.db_fakes import OTHER_ORG_ID, FakeDb

if TYPE_CHECKING:
    import uuid
    from collections.abc import Generator


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def db() -> Generator[FakeDb, None, None]:
    """A fresh FakeDb behind ``admino.tools.memory.get_pool``."""
    fake = FakeDb()
    with patch("admino.tools.memory.get_pool", return_value=fake.pool):
        yield fake


def _tenant(db: FakeDb, user_id: uuid.UUID) -> TenantContext:
    """The TenantContext of a FakeDb member, built the way the server builds it."""
    user = db.users[user_id]
    principal = Principal(user_id=user_id, kind="member", org_id=user["org_id"], role=user["role"])
    return TenantContext.from_principal(principal)


@pytest.fixture()
def alice(db: FakeDb) -> TenantContext:
    """An editor of ORG_ID."""
    return _tenant(db, db.add_account(role="editor"))


@pytest.fixture()
def bob(db: FakeDb) -> TenantContext:
    """Another member (an Org Admin) of alice's org."""
    return _tenant(db, db.add_account(role="org_admin"))


@pytest.fixture()
def carol(db: FakeDb) -> TenantContext:
    """An editor of another organization (OTHER_ORG_ID)."""
    return _tenant(db, db.add_account(role="editor", org_id=OTHER_ORG_ID))


async def _store(key: str, value: str, tenant: TenantContext) -> str:
    from admino.tools.memory import memory_store

    return await memory_store(MemoryStoreArgs(key=key, value=value), tenant=tenant)


async def _recall(key: str, tenant: TenantContext) -> str:
    from admino.tools.memory import memory_recall

    return await memory_recall(MemoryRecallArgs(key=key), tenant=tenant)


async def _list(tenant: TenantContext) -> str:
    from admino.tools.memory import memory_list

    return await memory_list(MemoryListArgs(), tenant=tenant)


def _memory_calls(db: FakeDb) -> list[Any]:
    """Every recorded statement on the memory table."""
    return db.matching(r"\bmemory\b")


def _rows_of(db: FakeDb, tenant: TenantContext) -> list[dict[str, Any]]:
    return [row for (owner, _), row in db.memory.items() if owner == tenant.user_id]


# GH-243: a found note and a non-empty key list come back as ONE wrapped untrusted block,
# <untrusted_content_B kind="memory" label="...">\n<text>\n</untrusted_content_B>.
_WRAPPED: Final = re.compile(
    r'<untrusted_content_(?P<b>[0-9a-f]{16}) kind="(?P<kind>[^"]*)" label="(?P<label>[^"<>]*)">\n'
    r"(?P<text>.*)\n</untrusted_content_(?P=b)>",
    re.DOTALL,
)


def _fed(result: str) -> str | tuple[str, str, str]:
    """What the LLM is fed: a wrapped result as (kind, label, text), a plain one as is."""
    match = _WRAPPED.fullmatch(result)
    return (match["kind"], match["label"], match["text"]) if match else result


def _note(key: str, value: str) -> tuple[str, str, str]:
    """A found note as wrapped by memory.recall (GH-243)."""
    return ("memory", f"memory note {key}", value)


def _keys(*keys: str) -> tuple[str, str, str]:
    """A non-empty key list as wrapped by memory.list (GH-243)."""
    return ("memory", "memory keys", "\n".join(keys))


_HANDLER_ARGS: list[Any] = [
    pytest.param("memory_store", MemoryStoreArgs(key="greeting", value="hello"), id="store"),
    pytest.param("memory_recall", MemoryRecallArgs(key="greeting"), id="recall"),
    pytest.param("memory_list", MemoryListArgs(), id="list"),
]


# ---------------------------------------------------------------------------
# 1. The tool context is required
# ---------------------------------------------------------------------------


class TestMemoryHandlersRequireTenant:
    """Every handler takes a required keyword-only tenant; without one, nothing runs."""

    @pytest.mark.parametrize(("name", "args"), _HANDLER_ARGS)
    def test_memory_handler_tenant_is_keyword_only_without_default(
        self, name: str, args: BaseModel
    ) -> None:
        """tenant is keyword-only with no default."""
        import admino.tools.memory as memory_module

        param = inspect.signature(getattr(memory_module, name)).parameters.get("tenant")

        assert param is not None, f"{name} must take a tenant"
        assert param.kind is inspect.Parameter.KEYWORD_ONLY
        assert param.default is inspect.Parameter.empty

    @pytest.mark.parametrize(("name", "args"), _HANDLER_ARGS)
    async def test_memory_handler_without_tenant_raises_type_error(
        self, db: FakeDb, name: str, args: BaseModel
    ) -> None:
        """A call without the tenant is a TypeError and runs no statement."""
        import admino.tools.memory as memory_module

        handler: Any = getattr(memory_module, name)

        with pytest.raises(TypeError):
            await handler(args)
        assert _memory_calls(db) == []


# ---------------------------------------------------------------------------
# 2. Store and recall: each user's own notes
# ---------------------------------------------------------------------------


class TestMemoryStoreAndRecall:
    """A user stores and recalls only their own notes."""

    async def test_memory_store_then_recall_returns_the_value(
        self, db: FakeDb, alice: TenantContext
    ) -> None:
        """Store confirms with the key; recall returns the stored value."""
        stored = await _store("greeting", "hello world", alice)
        recalled = await _recall("greeting", alice)

        assert stored == "Stored memory: greeting"
        assert _fed(recalled) == _note("greeting", "hello world")

    async def test_memory_store_writes_the_tenants_user_and_org(
        self, db: FakeDb, alice: TenantContext
    ) -> None:
        """The row belongs to the caller: their user_id and their org_id."""
        await _store("greeting", "hello world", alice)

        assert db.memories_of(alice.user_id) == {"greeting": "hello world"}
        [row] = _rows_of(db, alice)
        assert (row["user_id"], row["org_id"], row["key"]) == (
            alice.user_id,
            alice.org_id,
            "greeting",
        )

    async def test_memory_other_user_cannot_recall_a_users_key(
        self, db: FakeDb, alice: TenantContext, bob: TenantContext
    ) -> None:
        """Bob (same org) asking for Alice's key gets the not-found message."""
        await _store("pin-hint", "alice-only-value", alice)

        assert await _recall("pin-hint", bob) == "No memory found for key: pin-hint"

    async def test_memory_same_key_for_two_users_keeps_both_values(
        self, db: FakeDb, alice: TenantContext, bob: TenantContext
    ) -> None:
        """Alice and Bob store the same key with different values; each recalls their own."""
        await _store("project", "alice-value", alice)
        await _store("project", "bob-value", bob)

        assert _fed(await _recall("project", alice)) == _note("project", "alice-value")
        assert _fed(await _recall("project", bob)) == _note("project", "bob-value")
        assert db.memories_of(alice.user_id) == {"project": "alice-value"}
        assert db.memories_of(bob.user_id) == {"project": "bob-value"}

    async def test_memory_store_by_another_user_never_overwrites(
        self, db: FakeDb, alice: TenantContext, bob: TenantContext
    ) -> None:
        """Bob storing Alice's key creates Bob's note; Alice's value is untouched."""
        db.add_memory(alice.user_id, "project", "alice-value")

        await _store("project", "bob-value", bob)

        assert db.memories_of(alice.user_id) == {"project": "alice-value"}
        assert _fed(await _recall("project", alice)) == _note("project", "alice-value")

    async def test_memory_user_of_another_org_is_isolated(
        self, db: FakeDb, alice: TenantContext, carol: TenantContext
    ) -> None:
        """Carol (another org) with the same key: neither sees the other's value."""
        await _store("project", "alice-value", alice)
        await _store("project", "carol-value", carol)
        await _store("carol-only", "carol-secret", carol)

        assert _fed(await _recall("project", alice)) == _note("project", "alice-value")
        assert _fed(await _recall("project", carol)) == _note("project", "carol-value")
        assert await _recall("carol-only", alice) == "No memory found for key: carol-only"
        assert _rows_of(db, carol)[0]["org_id"] == OTHER_ORG_ID

    async def test_memory_row_under_another_org_is_invisible(
        self, db: FakeDb, alice: TenantContext
    ) -> None:
        """A row with the caller's user_id but another org_id is neither recalled nor
        listed: every read filters by the org too, not by the user alone."""
        db.add_org(OTHER_ORG_ID)
        db.add_memory(alice.user_id, "stray", "stray-value", org_id=OTHER_ORG_ID)

        assert await _recall("stray", alice) == "No memory found for key: stray"
        assert await _list(alice) == "No memories stored."

    async def test_memory_recall_missing_key_returns_not_found(
        self, db: FakeDb, alice: TenantContext
    ) -> None:
        """A key the caller never stored gets the fixed not-found message, from one
        lookup bound to the caller's ids and the key."""
        db.add_memory(alice.user_id, "other-key", "other-value")

        result = await _recall("nonexistent", alice)

        assert result == "No memory found for key: nonexistent"
        [call] = _memory_calls(db)
        assert {str(alice.user_id), str(alice.org_id), "nonexistent"} <= {
            str(arg) for arg in call.args
        }

    async def test_memory_store_is_an_upsert(self, db: FakeDb, alice: TenantContext) -> None:
        """Storing a key twice replaces the value and keeps exactly one row."""
        first = await _store("mood", "first value", alice)
        second = await _store("mood", "second value", alice)

        assert (first, second) == ("Stored memory: mood", "Stored memory: mood")
        assert _fed(await _recall("mood", alice)) == _note("mood", "second value")
        assert db.memories_of(alice.user_id) == {"mood": "second value"}
        assert len(_rows_of(db, alice)) == 1


# ---------------------------------------------------------------------------
# 3. List: only the caller's keys, sorted
# ---------------------------------------------------------------------------


class TestMemoryList:
    """memory_list lists the caller's keys only."""

    async def test_memory_list_returns_only_the_callers_keys_sorted(
        self, db: FakeDb, alice: TenantContext, bob: TenantContext, carol: TenantContext
    ) -> None:
        """Alice's keys, sorted and newline-joined; Bob's and Carol's never appear."""
        for key in ("zebra", "alpha", "middle"):
            await _store(key, f"value of {key}", alice)
        db.add_memory(bob.user_id, "beta", "bob-value")
        db.add_memory(carol.user_id, "aardvark", "carol-value")

        assert _fed(await _list(alice)) == _keys("alpha", "middle", "zebra")

    async def test_memory_list_of_each_user_is_their_own(
        self, db: FakeDb, alice: TenantContext, bob: TenantContext
    ) -> None:
        """Two users with overlapping keys each list exactly their own set."""
        db.add_memory(alice.user_id, "shared", "a")
        db.add_memory(alice.user_id, "alice-only", "a")
        db.add_memory(bob.user_id, "shared", "b")
        db.add_memory(bob.user_id, "bob-only", "b")

        assert _fed(await _list(alice)) == _keys("alice-only", "shared")
        assert _fed(await _list(bob)) == _keys("bob-only", "shared")

    async def test_memory_list_without_notes_says_none_stored(
        self, db: FakeDb, alice: TenantContext, bob: TenantContext
    ) -> None:
        """A user with no notes gets "No memories stored." even when others have some."""
        db.add_memory(bob.user_id, "bob-note", "b")

        assert await _list(alice) == "No memories stored."


# ---------------------------------------------------------------------------
# 4. The SQL: parameterized and scoped to the tenant
# ---------------------------------------------------------------------------


class TestMemorySqlIsScoped:
    """Every memory statement binds the tenant's user_id and org_id; nothing is
    interpolated into the SQL text."""

    async def test_memory_every_statement_binds_user_and_org(
        self, db: FakeDb, alice: TenantContext
    ) -> None:
        """Store, recall and list each run statements carrying both ids as bind args."""
        await _store("greeting", "hello", alice)
        await _recall("greeting", alice)
        await _list(alice)

        calls = _memory_calls(db)
        assert len(calls) >= 3
        for call in calls:
            bound = {str(arg) for arg in call.args}
            assert str(alice.user_id) in bound, call.sql
            assert str(alice.org_id) in bound, call.sql
            assert re.search(r"\$\d", call.sql), call.sql

    @pytest.mark.parametrize(
        "value",
        ["'; DROP TABLE memory; --", "x' OR '1'='1", "Robert'); DELETE FROM memory; --"],
    )
    async def test_memory_values_are_bind_args_never_sql_text(
        self, db: FakeDb, alice: TenantContext, value: str
    ) -> None:
        """An injection-shaped value is stored and recalled verbatim, and neither it, the
        key nor an id ever appears in the SQL text."""
        key = "marker-key-7f3a"

        await _store(key, value, alice)
        recalled = await _recall(key, alice)

        assert _fed(recalled) == _note(key, value)
        store_calls = [call for call in _memory_calls(db) if value in call.args]
        assert len(store_calls) == 1
        assert key in store_calls[0].args
        for call in _memory_calls(db):
            for literal in (value, key, str(alice.user_id), str(alice.org_id)):
                assert literal not in call.sql

    async def test_memory_max_length_value_is_stored_whole(
        self, db: FakeDb, alice: TenantContext
    ) -> None:
        """A value at the 2000-character limit is stored and recalled whole."""
        long_value = "x" * 2000

        await _store("long-val", long_value, alice)

        assert _fed(await _recall("long-val", alice)) == _note("long-val", long_value)

    async def test_memory_logs_no_keys_or_values(
        self, db: FakeDb, alice: TenantContext, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No content in logs: neither the key nor the value reaches any log line."""
        key = "log-marker-key-5d1e"
        value = "LOG-MARKER-VALUE-91bc"

        with caplog.at_level(logging.DEBUG):
            await _store(key, value, alice)
            await _recall(key, alice)
            await _list(alice)

        assert db.memories_of(alice.user_id) == {key: value}
        assert key not in caplog.text
        assert value not in caplog.text


# ---------------------------------------------------------------------------
# 5. Registration and the memory.delete denial
# ---------------------------------------------------------------------------


@pytest.fixture()
def memory_registry(db: FakeDb) -> Generator[None, None, None]:
    """Re-run the memory module's registrations into a clean registry.

    The reload re-binds the module's ``get_pool``, so it is patched to the FakeDb
    pool again afterwards.
    """
    import admino.tools.memory as memory_module

    clear_registry()
    importlib.reload(memory_module)
    with patch("admino.tools.memory.get_pool", return_value=db.pool):
        yield
    clear_registry()


class TestMemoryRegistration:
    """store / recall / list stay the only memory tools; delete stays denied."""

    async def test_memory_registered_actions_dispatch_with_the_tenant(
        self, db: FakeDb, alice: TenantContext, memory_registry: None
    ) -> None:
        """Exactly store, recall and list are registered (no delete handler), and a
        registry dispatch of memory.store lands in the dispatching tenant's notes."""
        from admino.permissions import build_default_permissions_config
        from admino.tools.registry import dispatch_tool_call

        registered = {(t.tool, t.action) for t in get_registered_tools() if t.tool == "memory"}

        result = await dispatch_tool_call(
            ToolCall(tool="memory", action="store", args={"key": "via-registry", "value": "v"}),
            build_default_permissions_config(),
            session_id="sess-1",
            tenant=alice,
        )

        assert registered == {("memory", "store"), ("memory", "recall"), ("memory", "list")}
        assert get_tool_entry("memory", "delete") is None
        assert (result.success, result.result) == (True, "Stored memory: via-registry")
        assert db.memories_of(alice.user_id) == {"via-registry": "v"}

    async def test_memory_delete_stays_denied_even_when_config_allows(
        self, db: FakeDb, alice: TenantContext, memory_registry: None
    ) -> None:
        """memory.delete is a hardcoded denial: the engine says deny over a config that
        allows it, and a dispatch is refused without touching the memory table."""
        from admino.tools.registry import dispatch_tool_call

        db.add_memory(alice.user_id, "keep-me", "kept")
        config = PermissionsConfig(
            tools={"memory": ToolPermissions(actions={"delete": "allow", "store": "allow"})}
        )

        decision = check_permission("memory", "delete", config)
        result = await dispatch_tool_call(
            ToolCall(tool="memory", action="delete", args={"key": "keep-me"}),
            config,
            session_id="sess-1",
            tenant=alice,
        )

        assert decision.allowed == "deny"
        assert (result.success, result.permission.allowed) == (False, "deny")
        assert _memory_calls(db) == []
        assert db.memories_of(alice.user_id) == {"keep-me": "kept"}


# ---------------------------------------------------------------------------
# 6. Pydantic model validation
# ---------------------------------------------------------------------------


class TestMemoryModelValidation:
    """Tests for Pydantic model constraints on memory arg models."""

    @pytest.mark.parametrize(
        "invalid_key",
        [
            "key\x00null",
            "key;DROP TABLE",
            "key' OR '1'='1",
            "key<script>",
            "key\ninjection",
            "",
        ],
    )
    def test_store_args_rejects_special_chars(self, invalid_key: str) -> None:
        """MemoryStoreArgs rejects keys with special characters."""
        with pytest.raises(ValidationError):
            MemoryStoreArgs(key=invalid_key, value="test")

    @pytest.mark.parametrize(
        "invalid_key",
        [
            "key\x00null",
            "key;DROP TABLE",
            "key' OR '1'='1",
            "",
        ],
    )
    def test_recall_args_rejects_special_chars(self, invalid_key: str) -> None:
        """MemoryRecallArgs rejects keys with special characters."""
        with pytest.raises(ValidationError):
            MemoryRecallArgs(key=invalid_key)

    def test_store_args_max_key_length(self) -> None:
        """MemoryStoreArgs rejects keys exceeding max_length."""
        with pytest.raises(ValidationError):
            MemoryStoreArgs(key="a" * 201, value="test")

    def test_store_args_max_value_length(self) -> None:
        """MemoryStoreArgs rejects values exceeding max_length."""
        with pytest.raises(ValidationError):
            MemoryStoreArgs(key="mykey", value="x" * 2001)

    def test_store_args_valid_key(self) -> None:
        """MemoryStoreArgs accepts valid keys."""
        args = MemoryStoreArgs(key="my-key_v2.0", value="test value")
        assert args.key == "my-key_v2.0"

    def test_recall_args_valid_key(self) -> None:
        """MemoryRecallArgs accepts valid keys."""
        args = MemoryRecallArgs(key="my-key_v2.0")
        assert args.key == "my-key_v2.0"

    def test_store_args_key_with_spaces(self) -> None:
        """MemoryStoreArgs accepts keys with spaces."""
        args = MemoryStoreArgs(key="my key", value="val")
        assert args.key == "my key"

    def test_recall_sql_injection_key_rejected_by_pydantic(self) -> None:
        """SQL injection in recall key is rejected by Pydantic validation."""
        with pytest.raises(ValidationError):
            MemoryRecallArgs(key="'; DROP TABLE memory; --")
