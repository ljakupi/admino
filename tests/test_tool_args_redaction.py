"""Tool arguments are redacted at every depth; no key reaches a log, audit row or error (GH-270).

Issue #270 contract sections 5 and 6 (decision 5). ``ToolCallRecord.args`` and
``PendingConfirmationSummary.args`` are shown to users (the chat reply, a stored
message, the confirmation card). Until now only their top-level string values were
redacted, so a key nested in a list or a dict, or used as a dict key, was shown in
full (audit finding I-4). What this file pins, for both models:

- Every string at every depth goes through the credential rules
  (``models._strip_credentials``): dict values, list items and str dict keys. Only
  the credential rules apply, not the display cleanup: an invisible character in an
  argument is kept. When two keys redact to the same text, the later one wins.
  Non-str keys inside nested dicts are kept.
- A tuple becomes a list. bool, int, float and None are kept as they are. Any other
  type (a set, bytes, an object) becomes ``"[SANITIZED]"``
  (``models._SANITIZED_PLACEHOLDER``).
- Depth: ``args[k]`` is at depth 1 and the items of a container at depth d are at
  depth d + 1. A string at depth 8 is redacted and kept; any value at depth 9 (a
  string, a number, a dict or a list) becomes ``"[SANITIZED]"`` and nothing below it
  is read. A dict at depth 8 keeps its str keys (redacted) and its values become the
  placeholder. A 10,000-deep nesting raises nothing (no RecursionError).
- An argument value that is not a dict (a list, a string) is redacted first and then
  refused by Pydantic: a ``ValidationError`` (not an ``AttributeError``) whose text
  and ``errors()`` (input included) hold no part of the key.
- A stored record reloaded into ``ChatMessageView.tool_calls`` (the server's
  ``model_validate(record, from_attributes=True)`` path) is redacted the same way,
  and so is the record the agent builds for a real tool call.
- Section 6: no key, and no 8-character chunk of one, appears in a captured log
  record while the sanitizers, the titles, the argument models and an agent run
  process texts holding keys, nor in the agent's ``tool.call`` audit row (content
  free by design: these are regression guards).

No route takes tool arguments as input and both 422 handlers in ``server.py`` drop
the error input, so there is no route 422 body to check here.

Keys are built at runtime by tests/credential_keys.py (a fixed prefix and a seeded
random body); no key literal is written in this file.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import BaseModel, Field, ValidationError

import admino.main as main_module
from admino import chat_titles, chats, models
from admino.access import Principal
from admino.agent import Agent
from admino.llm import LLMResponse
from admino.models import (
    AgentConfig,
    ChatMessageView,
    PendingConfirmationSummary,
    ToolCall,
    ToolCallRecord,
    ToolPolicy,
)
from admino.permissions import PermissionsConfig, ToolPermissions
from admino.tenancy import TenantContext
from admino.tools.registry import clear_registry, register_tool
from tests.credential_keys import (
    anthropic_api03_key,
    api_key,
    openai_project_key,
    surviving_chunks,
)
from tests.log_capture import configured_logging

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from admino.models import AgentResult, LLMMessage
    from tests.log_capture import CapturedLogs

REDACTED: Final = models._REDACTED
# Decision 5 names the placeholder literally; models._SANITIZED_PLACEHOLDER holds it.
PLACEHOLDER: Final = "[SANITIZED]"
DEPTH_BOUND: Final = 8

_PROJECT_KEY: Final = openai_project_key()
_ANTHROPIC_KEY: Final = anthropic_api03_key()
_SERVICE_KEY: Final = api_key("sk-" + "svcacct-", 120, seed=2701)
_ALL_KEYS: Final = (_PROJECT_KEY, _ANTHROPIC_KEY, _SERVICE_KEY)
_KEY: Final = _PROJECT_KEY.text

_ZWSP: Final = chr(0x200B)  # zero-width space
_SHY: Final = chr(0x00AD)  # soft hyphen
_DEL: Final = chr(0x007F)
_EXPIRES: Final = datetime(2026, 10, 6, 12, tzinfo=UTC)
_CREATED: Final = datetime(2026, 10, 5, 12, tzinfo=UTC)


def _leaks(text: str) -> list[str]:
    """Every full test key, and every 8-character chunk of one, found in ``text``."""
    found = [key.text for key in _ALL_KEYS if key.text in text]
    for key in _ALL_KEYS:
        found.extend(surviving_chunks(text, key))
    return found


def _record_args(args: Any) -> dict[str, Any]:
    """The args a ``ToolCallRecord`` keeps after its sanitizer ran."""
    record = ToolCallRecord(
        tool="gmail", action="search", args=args, permission="allow", success=True
    )
    return record.args


def _summary_args(args: Any) -> dict[str, Any]:
    """The args a ``PendingConfirmationSummary`` keeps after its sanitizer ran."""
    summary = PendingConfirmationSummary(
        confirmation_id="c1", tool="gmail", action="send", args=args, expires_at=_EXPIRES
    )
    return summary.args


_SITES = pytest.mark.parametrize(
    "site",
    [_record_args, _summary_args],
    ids=["tool-call-record", "pending-confirmation-summary"],
)


def _in_lists(value: Any, depth: int) -> dict[str, Any]:
    """Tool args holding ``value`` at ``depth`` inside one-item lists (built iteratively).

    ``args["k"]`` is depth 1; each list around the value adds one level.
    """
    node = value
    for _ in range(depth - 1):
        node = [node]
    return {"k": node}


def _in_dicts(value: Any, depth: int) -> dict[str, Any]:
    """Tool args holding ``value`` at ``depth`` inside one-key dicts ``{"k": ...}``."""
    node = value
    for _ in range(depth - 1):
        node = {"k": node}
    return {"k": node}


def _at_depth(args: dict[str, Any], depth: int) -> Any:
    """The value at ``depth`` along a chain built by ``_in_lists`` or ``_in_dicts``.

    Returns a ``<no container ...>`` text when the chain stops early, so a value
    replaced too shallow (or a container kept too deep) never compares equal.
    """
    node: Any = args["k"]
    for level in range(1, depth):
        if isinstance(node, list) and len(node) == 1:
            node = node[0]
        elif isinstance(node, dict) and list(node) == ["k"]:
            node = node["k"]
        else:
            return f"<no container at depth {level}: {type(node).__name__}>"
    return node


# ===========================================================================
# 1. Every string at every depth is redacted (contract section 5)
# ===========================================================================


class TestNestedKeys:
    """Keys nested in lists, in dicts and in dict keys are redacted (criterion 6, I-4)."""

    @_SITES
    @pytest.mark.parametrize(
        ("args", "expected"),
        [
            pytest.param(
                {"labels": ["inbox", f"token {_KEY}"]},
                {"labels": ["inbox", f"token {REDACTED}"]},
                id="in-a-list",
            ),
            pytest.param(
                {"filters": {"note": f"Rotate {_KEY} today"}},
                {"filters": {"note": f"Rotate {REDACTED} today"}},
                id="in-a-nested-dict",
            ),
            pytest.param({_KEY: "v"}, {REDACTED: "v"}, id="as-a-dict-key"),
            pytest.param(
                {"headers": {f"x-{_KEY}": "v"}},
                {"headers": {f"x-{REDACTED}": "v"}},
                id="as-a-nested-dict-key",
            ),
            pytest.param({"a": [{"b": [_KEY]}]}, {"a": [{"b": [REDACTED]}]}, id="mixed"),
            pytest.param({"pair": ("x", _KEY)}, {"pair": ["x", REDACTED]}, id="tuple-to-list"),
            pytest.param(
                {"by_id": {1: _KEY, 2.5: "x"}},
                {"by_id": {1: REDACTED, 2.5: "x"}},
                id="non-str-keys-kept",
            ),
        ],
    )
    def test_models_nested_key_is_redacted(
        self,
        site: Callable[[Any], dict[str, Any]],
        args: dict[str, Any],
        expected: dict[str, Any],
    ) -> None:
        result = site(args)
        assert result == expected
        assert _leaks(repr(result)) == []

    @_SITES
    def test_models_keys_colliding_after_redaction_keep_the_later_value(
        self, site: Callable[[Any], dict[str, Any]]
    ) -> None:
        args = {f"id {_KEY}": "first", f"id {_SERVICE_KEY.text}": "later"}
        assert site(args) == {f"id {REDACTED}": "later"}


class TestValueTypes:
    """Scalars are kept, a tuple becomes a list, any other type becomes the placeholder."""

    @_SITES
    def test_models_scalars_are_kept_at_every_depth(
        self, site: Callable[[Any], dict[str, Any]]
    ) -> None:
        """bool, int, float and None pass through unchanged (a bool stays a bool)."""
        args = {
            "count": 5,
            "flag": True,
            "ratio": 0.5,
            "none": None,
            "nested": [7, False, 2.25, None, {"n": 3}],
        }
        result = site(args)
        assert result == args
        assert type(result["flag"]) is bool
        assert type(result["nested"][1]) is bool

    @_SITES
    def test_models_other_types_become_the_placeholder(
        self, site: Callable[[Any], dict[str, Any]]
    ) -> None:
        """A set, bytes or an object is never shown, whatever it holds, at any depth."""
        args = {
            "a_set": {_KEY},
            "raw": _KEY.encode(),
            "thing": object(),
            "nested": ["kept", _KEY.encode()],
        }
        assert site(args) == {
            "a_set": PLACEHOLDER,
            "raw": PLACEHOLDER,
            "thing": PLACEHOLDER,
            "nested": ["kept", PLACEHOLDER],
        }

    @_SITES
    def test_models_invisible_characters_in_args_are_kept(
        self, site: Callable[[Any], dict[str, Any]]
    ) -> None:
        """Only the credential rules apply to arguments, not the display cleanup."""
        args = {
            "q": f"x{_ZWSP}y",
            "nested": [f"a{_SHY}b", {f"k{_ZWSP}": f"c{_DEL}d"}],
        }
        assert site(args) == args


# ===========================================================================
# 2. The depth bound: 8 kept, 9 replaced (contract section 5)
# ===========================================================================


class TestDepthBound:
    """A value deeper than the bound is replaced by the placeholder, never shown."""

    @_SITES
    @pytest.mark.parametrize("chain", [_in_lists, _in_dicts], ids=["lists", "dicts"])
    def test_models_string_at_depth_eight_is_redacted_and_kept(
        self,
        site: Callable[[Any], dict[str, Any]],
        chain: Callable[[Any, int], dict[str, Any]],
    ) -> None:
        result = site(chain(f"Rotate {_KEY} today", DEPTH_BOUND))
        assert result == chain(f"Rotate {REDACTED} today", DEPTH_BOUND)

    @_SITES
    @pytest.mark.parametrize(
        "value",
        [_KEY, 42, {"inner": "x"}, ["x"]],
        ids=["string", "number", "dict", "list"],
    )
    def test_models_any_value_at_depth_nine_becomes_the_placeholder(
        self, site: Callable[[Any], dict[str, Any]], value: Any
    ) -> None:
        result = site(_in_lists(value, DEPTH_BOUND + 1))
        assert result == _in_lists(PLACEHOLDER, DEPTH_BOUND + 1)

    @_SITES
    @pytest.mark.parametrize("chain", [_in_lists, _in_dicts], ids=["lists", "dicts"])
    def test_models_dict_at_depth_eight_redacts_its_keys_and_replaces_its_values(
        self,
        site: Callable[[Any], dict[str, Any]],
        chain: Callable[[Any, int], dict[str, Any]],
    ) -> None:
        """A dict's str keys sit at its own depth (8: redacted), its values one deeper (9)."""
        at_the_bound = {f"id {_ANTHROPIC_KEY.text}": "v", "n": 3}
        result = site(chain(at_the_bound, DEPTH_BOUND))
        assert result == chain({f"id {REDACTED}": PLACEHOLDER, "n": PLACEHOLDER}, DEPTH_BOUND)
        assert _leaks(repr(result)) == []

    @_SITES
    def test_models_key_at_depth_nine_in_dicts_becomes_the_placeholder(
        self, site: Callable[[Any], dict[str, Any]]
    ) -> None:
        result = site(_in_dicts(_KEY, DEPTH_BOUND + 1))
        assert result == _in_dicts(PLACEHOLDER, DEPTH_BOUND + 1)

    @_SITES
    @pytest.mark.parametrize("chain", [_in_lists, _in_dicts], ids=["lists", "dicts"])
    def test_models_ten_thousand_deep_nesting_is_cut_at_depth_nine(
        self,
        site: Callable[[Any], dict[str, Any]],
        chain: Callable[[Any, int], dict[str, Any]],
    ) -> None:
        """No RecursionError: the container at depth 9 is replaced, nothing below is read."""
        result = site(chain(_KEY, 10_000))
        assert _at_depth(result, DEPTH_BOUND + 1) == PLACEHOLDER


# ===========================================================================
# 3. A non-dict is redacted before Pydantic refuses it (contract sections 5 and 6)
# ===========================================================================


class TestNonDictArgs:
    """A refused non-dict leaves no part of a key in the ValidationError."""

    @_SITES
    @pytest.mark.parametrize(
        "value",
        [[f"Rotate {_KEY} today", {"note": _KEY}], f"Rotate {_KEY} today"],
        ids=["list", "str"],
    )
    def test_models_non_dict_args_are_refused_without_any_part_of_the_key(
        self, site: Callable[[Any], dict[str, Any]], value: Any
    ) -> None:
        with pytest.raises(ValidationError) as caught:
            site(value)
        exc = caught.value
        refused = [(error["loc"], error["type"]) for error in exc.errors(include_input=False)]
        assert refused == [(("args",), "dict_type")]
        assert _leaks(str(exc)) == []
        assert _leaks(repr(exc.errors())) == []


# ===========================================================================
# 4. A stored record reloaded into the message view (contract section 5)
# ===========================================================================


class TestStoredRecords:
    """``ChatMessageView.tool_calls`` (records reloaded from stored JSON) is redacted."""

    def test_models_stored_record_with_nested_keys_is_redacted_in_the_view(self) -> None:
        stored = json.loads(
            json.dumps(
                [
                    {
                        "tool": "gmail",
                        "action": "search",
                        "args": {
                            "filters": {"from": [f"token {_KEY}"]},
                            _ANTHROPIC_KEY.text: "label",
                        },
                        "permission": "allow",
                        "success": True,
                        "duration_ms": 4,
                    }
                ]
            )
        )
        message = chats.MessageRecord(
            id=uuid.uuid4(),
            seq=3,
            role="assistant",
            content="Done.",
            tool_use_blocks=None,
            tool_call_id=None,
            tool_calls=stored,
            status="complete",
            created_at=_CREATED,
        )

        view = ChatMessageView.model_validate(message, from_attributes=True)

        assert view.tool_calls is not None
        assert view.tool_calls[0].args == {
            "filters": {"from": [f"token {REDACTED}"]},
            REDACTED: "label",
        }


# ===========================================================================
# 5. No key in any log line, audit row or error payload (contract section 6)
# ===========================================================================


@pytest.fixture()
def debug_logs(caplog: pytest.LogCaptureFixture) -> None:
    """The ``admino`` loggers at DEBUG (caplog restores the level after the test).

    The records themselves are captured inside the test body by
    ``log_capture.configured_logging`` (the real handler, plus every raw record).
    """
    caplog.set_level(logging.DEBUG, logger="admino")


def _log_leaks(logs: CapturedLogs) -> list[str]:
    """Key parts in what the configured handler wrote, and in every raw record
    (message and ``vars(record)``, at every level)."""
    dump = [logs.text]
    for record in logs.records:
        dump.append(record.getMessage())
        dump.append(repr(vars(record)))
    return _leaks("\n".join(dump))


# Texts holding keys the way this issue's cases do: plain, mid-sentence, after a run
# of removed characters, split inside the body.
_TEXTS_WITH_KEYS: Final = (
    f"Rotate {_KEY} today",
    f"a{_ZWSP}{_KEY}",
    f"key{_SHY}{_DEL}{_ANTHROPIC_KEY.text} ok",
    f"Bearer {_SERVICE_KEY.text}",
    _KEY[:48] + _SHY + _KEY[48:],
)


@pytest.mark.usefixtures("debug_logs")
class TestNoKeyInLogs:
    """Regression guards: the redaction paths log nothing that holds a key."""

    def test_models_sanitizers_titles_and_arg_models_log_no_part_of_a_key(self) -> None:
        nested = {
            "a": [{"b": [_KEY]}],
            _ANTHROPIC_KEY.text: {"c": (_SERVICE_KEY.text,)},
            "deep": _in_lists(_KEY, 12),
        }

        with configured_logging("DEBUG", "text") as logs:
            for text in _TEXTS_WITH_KEYS:
                models.sanitize_display_text(text)
                chat_titles.sanitize_title(text)
                chat_titles.fallback_title(text)
                _record_args({"note": text, "nested": [text]})
                _summary_args({"note": text, "nested": {"k": text}})
            _record_args(nested)
            _summary_args(nested)
            ChatMessageView(
                id=uuid.uuid4(),
                role="assistant",
                content=_TEXTS_WITH_KEYS[0],
                tool_calls=[
                    {
                        "tool": "gmail",
                        "action": "search",
                        "args": nested,
                        "permission": "allow",
                        "success": True,
                    }
                ],
                status="complete",
                created_at=_CREATED,
            )

        assert _log_leaks(logs) == []

    async def test_chat_titles_failed_title_logs_no_part_of_a_key(self) -> None:
        """The title task's failure line names the error type only, never the row."""
        pool = MagicMock(name="pool")
        pool.fetchval = AsyncMock(side_effect=RuntimeError(f"Failing row contains ({_KEY})"))
        tenant = TenantContext(org_id=uuid.uuid4(), user_id=uuid.uuid4(), role="editor")

        with configured_logging("DEBUG", "text") as logs:
            await chat_titles.title_chat(
                pool,
                tenant,
                uuid.uuid4(),
                get_client=MagicMock(side_effect=AssertionError("no client on a failed run")),
                user_message=f"Rotate {_KEY} and {_ANTHROPIC_KEY.text}",
                assistant_message=f"Done with {_SERVICE_KEY.text}",
                run_failed=True,
                external_content=False,
                data_residency=False,
                max_retries=0,
            )

        assert pool.fetchval.await_count == 1
        assert len(logs.records) >= 1
        assert _log_leaks(logs) == []


# --- A real agent run whose tool call holds nested keys ----------------------------

_CHAT_ID: Final = uuid.UUID("7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d")
_MEMBER: Final = Principal(
    user_id=uuid.UUID("8b9c0d1e-2f3a-4b4c-9d5e-6f7a8b9c0d1e"),
    kind="member",
    org_id=uuid.UUID("9c0d1e2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f"),
    role="editor",
)


class _FiltersArgs(BaseModel):
    """A tool whose arguments hold arbitrary nested JSON."""

    filters: dict[str, Any] = Field(default_factory=dict)


async def _filters_handler(args: _FiltersArgs, *, session_id: str, **_: object) -> str:
    return "1 note found"


async def _failing_handler(args: _FiltersArgs, *, session_id: str, **_: object) -> str:
    """A tool that fails with its arguments (and so the keys) in the error text."""
    raise RuntimeError(f"upstream refused {args.filters!r}")


class _ScriptedLLM:
    """Returns the scripted responses in order."""

    provider = "infomaniak"

    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = list(responses)

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        return self._responses.pop(0)


def _nested_key_args() -> dict[str, Any]:
    """Tool arguments with a key in a list item, a dict value and a dict key."""
    return {
        "filters": {
            "labels": [{"note": f"token {_KEY}"}],
            _ANTHROPIC_KEY.text: "label",
            "since": {"after": [_SERVICE_KEY.text]},
        }
    }


@pytest.fixture()
def nested_tool() -> Iterator[None]:
    """A registry holding ``memory.read`` (succeeds) and ``memory.search`` (raises),
    both with nested-JSON arguments."""
    clear_registry()
    register_tool("memory", "read", "Read a note", _FiltersArgs, side_effect=False)(
        _filters_handler
    )
    register_tool("memory", "search", "Search notes", _FiltersArgs, side_effect=False)(
        _failing_handler
    )
    yield
    clear_registry()


@pytest.fixture()
def audit_pool(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """The runtime pool the real tool-call recorder writes the audit row through."""
    pool = MagicMock(name="runtime-pool")
    pool.execute = AsyncMock(return_value="INSERT 0 1")
    monkeypatch.setattr("admino.database.get_pool", MagicMock(return_value=pool))
    return pool


async def _run_nested_tool_call(action: str = "read") -> AgentResult:
    """One agent run: a ``memory.<action>`` call with nested keys, then a final reply."""
    call = ToolCall(tool="memory", action=action, args=_nested_key_args(), tool_call_id="call-1")
    agent = Agent(
        llm_client=_ScriptedLLM(
            [LLMResponse(content="", tool_calls=[call]), LLMResponse(content="Done.")]
        ),
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
    )
    actions = ToolPermissions(actions={"read": "allow", "search": "allow"})
    policy = ToolPolicy(permissions=PermissionsConfig(tools={"memory": actions}))
    return await agent.run(
        "go", session_id=str(_CHAT_ID), history=[], principal=_MEMBER, tool_policy=policy
    )


@pytest.mark.usefixtures("nested_tool")
class TestAgentToolCall:
    """The agent's tool-call record is redacted; its audit row and logs hold no key."""

    async def test_agent_tool_call_record_redacts_nested_keys(self, audit_pool: MagicMock) -> None:
        result = await _run_nested_tool_call()

        assert result.status == "final"
        assert [record.args for record in result.tool_calls] == [
            {
                "filters": {
                    "labels": [{"note": f"token {REDACTED}"}],
                    REDACTED: "label",
                    "since": {"after": [REDACTED]},
                }
            }
        ]

    async def test_agent_tool_call_audit_row_holds_no_part_of_a_key(
        self, audit_pool: MagicMock
    ) -> None:
        """The ``tool.call`` row is content-free by design: pinned here for nested keys."""
        await _run_nested_tool_call()

        assert audit_pool.execute.await_count == 1
        params = audit_pool.execute.await_args.args
        assert params[4] == "tool.call"
        assert _leaks(" ".join(str(value) for value in params)) == []

    @pytest.mark.usefixtures("debug_logs")
    async def test_agent_failing_tool_call_logs_no_part_of_a_key(
        self, audit_pool: MagicMock
    ) -> None:
        """A tool that fails with the keys in its error text: the run's log lines
        (the registry's failure line included) hold none of them."""
        with configured_logging("DEBUG", "text") as logs:
            result = await _run_nested_tool_call("search")

        assert [record.success for record in result.tool_calls] == [False]
        assert audit_pool.execute.await_count == 1
        assert len(logs.records) >= 1
        assert _log_leaks(logs) == []
