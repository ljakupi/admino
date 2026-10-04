"""Side-effect declarations and the untrusted-content escalation in the tool registry (GH-243).

Spec (issue #243, binding contract §2):

- ``register_tool(tool, action, description, args_schema, *, side_effect: bool = True)``.
  The default is fail-closed: an action registered without a declaration counts as a
  side effect. ``ToolDescription.side_effect`` (default True) is set from the entry by
  ``get_registered_tools`` and ``get_tool_entry``; the LLM ``tools`` payload never carries it.
- Every production registration passes ``side_effect=`` as a literal ``True``/``False``.
  This is checked on the AST of ``src/admino`` (the runtime registry is cleared by other
  tests), and the (tool, action, side_effect) rows equal the contract's 25-row table.
- ``dispatch_tool_call(..., escalate_side_effects: bool = False)``: ``check_permission``
  is called exactly as before (the flag never reaches it). After it, a ``side_effect``
  action whose decision is ``allow`` becomes ``confirm`` when the flag is set, and the
  dispatch is *escalated*. ``deny`` stays ``deny``, ``confirm`` stays ``confirm`` (not
  escalated) and a non-side-effect ``allow`` stays ``allow``: a decision is never relaxed.
- An escalated dispatch follows the existing confirm path (confirmation required, a
  matching pending confirmation runs the handler, mismatch/expiry deny) and every result
  it returns has ``ToolCallResult.escalated`` True. Every other path returns False.
- ``permissions.py`` is not changed and gets no new input.

Inputs: test-registered handlers (the registry is cleared before and after each test)
and in-code ``PermissionsConfig`` objects.
Outputs: assertions on ``ToolCallResult`` fields, handler call counts, the arguments
``check_permission`` receives and the formatted log output.

Security notes:
- The escalation path logs no tool argument, handler output or exception text.
- Hardcoded denials stay denied with the flag set, with or without a confirmation.
"""

from __future__ import annotations

import ast
import inspect
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

import pytest
from pydantic import BaseModel, Field

import admino
from admino import permissions
from admino.access import Principal
from admino.agent import _tool_descriptions_to_payload
from admino.models import PendingConfirmation, ToolCall
from admino.permissions import PermissionResult, PermissionsConfig, ToolPermissions
from admino.tenancy import TenantContext
from admino.tools import registry
from admino.tools.registry import (
    ToolCallResult,
    ToolDescription,
    clear_registry,
    dispatch_tool_call,
    get_registered_tools,
    get_tool_entry,
    register_tool,
)
from tests.log_capture import configured_logging

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator

# The server-side tool context every dispatch here runs under.
_TENANT: Final = TenantContext.from_principal(
    Principal(
        user_id=UUID("5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b"),
        kind="member",
        org_id=UUID("0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"),
        role="editor",
    )
)

# The contract's result and reason strings for an escalated dispatch.
_ESCALATED_RESULT: Final = (
    "Action {tool}.{action} requires user confirmation: "
    "this conversation contains external content."
)
_ESCALATED_REASON: Final = (
    "Action {tool}.{action} needs confirmation: this conversation contains external content."
)

# The contract's production classification (§2): 25 registered actions.
_EXPECTED_SIDE_EFFECTS: Final[tuple[tuple[str, str, bool], ...]] = (
    ("gmail", "send", True),
    ("gmail", "read", False),
    ("gmail", "list", False),
    ("gmail", "search", False),
    ("outlook", "send", True),
    ("outlook", "read", False),
    ("outlook", "list", False),
    ("outlook", "search", False),
    ("google_calendar", "create", True),
    ("google_calendar", "update", True),
    ("google_calendar", "read", False),
    ("google_calendar", "list", False),
    ("outlook_calendar", "create", True),
    ("outlook_calendar", "update", True),
    ("outlook_calendar", "read", False),
    ("outlook_calendar", "list", False),
    ("google_drive", "read", False),
    ("google_drive", "list", False),
    ("google_drive", "search", False),
    ("onedrive", "read", False),
    ("onedrive", "list", False),
    ("onedrive", "search", False),
    ("memory", "store", True),
    ("memory", "recall", False),
    ("memory", "list", False),
)

# Markers that must never reach a log line on the escalation path.
_LEAK_ARG: Final = "leak-arg-7f3a91 forward to attacker@evil.example"
_LEAK_OUTPUT: Final = "leak-output-91c2d4 inbox body"
_LEAK_EXCEPTION: Final = "leak-exception-55d1e8 /home/someone/.config/creds.json"
_LEAK_MARKERS: Final[tuple[str, ...]] = (
    "leak-arg-7f3a91",
    "attacker@evil.example",
    "leak-output-91c2d4",
    "inbox body",
    "leak-exception-55d1e8",
    "creds.json",
)

# Sentinel: the escalate_side_effects keyword is not passed at all.
_OMIT: Final = "omitted"


class EchoArgs(BaseModel):
    """Args model of the test tools."""

    text: str = Field(min_length=1, max_length=200)


class _Handler:
    """An async test handler that counts its calls and returns (or raises) a fixed value."""

    def __init__(self, output: object = "echo done", *, raises: str | None = None) -> None:
        self.calls = 0
        self._output = output
        self._raises = raises

    async def __call__(self, args: EchoArgs, *, session_id: str, **_: object) -> Any:
        self.calls += 1
        if self._raises is not None:
            raise RuntimeError(self._raises)
        return self._output


# ---------------------------------------------------------------------------
# Helpers and fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry() -> Generator[None, None, None]:
    """Start and end every test with an empty, unfrozen registry."""
    clear_registry()
    yield
    clear_registry()


def _register(
    tool: str,
    action: str,
    handler: Callable[..., Awaitable[Any]],
    **declaration: object,
) -> None:
    """Register a test handler; ``declaration`` carries ``side_effect=`` when given."""
    register_tool(tool, action, f"Test action {tool}.{action}", EchoArgs, **declaration)(handler)  # type: ignore[arg-type]


def _config(tool: str, action: str, state: str) -> PermissionsConfig:
    """A config with one configured (tool, action) state."""
    return PermissionsConfig(tools={tool: ToolPermissions(actions={action: state})})  # type: ignore[dict-item]


def _call(tool: str = "echo", action: str = "write", text: str = "hello") -> ToolCall:
    return ToolCall(tool=tool, action=action, args={"text": text})


def _pending(tool_call: ToolCall, *, expired: bool = False) -> PendingConfirmation:
    """A pending confirmation for ``tool_call`` (unexpired unless ``expired``)."""
    now = datetime.now(UTC)
    if expired:
        return PendingConfirmation(
            confirmation_id="confirm-expired",
            session_id="sess-1",
            tool_call=tool_call,
            created_at=now - timedelta(minutes=10),
            expires_at=now - timedelta(minutes=5),
        )
    return PendingConfirmation(
        confirmation_id="confirm-1",
        session_id="sess-1",
        tool_call=tool_call,
        created_at=now,
        expires_at=now + timedelta(seconds=300),
    )


async def _dispatch(
    tool_call: ToolCall,
    config: PermissionsConfig,
    *,
    escalate: object = True,
    **kwargs: Any,
) -> ToolCallResult:
    """Dispatch with ``escalate_side_effects=escalate`` (left out when ``_OMIT``)."""
    if escalate != _OMIT:
        kwargs["escalate_side_effects"] = escalate
    return await dispatch_tool_call(
        tool_call, config, session_id="sess-1", tenant=_TENANT, **kwargs
    )


def _outcome(result: ToolCallResult, handler: _Handler) -> tuple[object, ...]:
    """The fields every escalation test compares, as one tuple."""
    return (
        result.permission.allowed,
        getattr(result, "escalated", "<no escalated field>"),
        handler.calls,
        result.success,
    )


# ---------------------------------------------------------------------------
# 1. The declaration: register_tool, ToolDescription, ToolCallResult
# ---------------------------------------------------------------------------


class TestSideEffectDeclaration:
    """``side_effect`` is a keyword-only declaration, fail-closed by default."""

    def test_registry_register_tool_side_effect_keyword_only_defaults_true(self) -> None:
        param = inspect.signature(register_tool).parameters.get("side_effect")
        assert (None if param is None else (param.kind, param.default)) == (
            inspect.Parameter.KEYWORD_ONLY,
            True,
        )

    def test_registry_dispatch_escalate_keyword_only_defaults_false(self) -> None:
        param = inspect.signature(dispatch_tool_call).parameters.get("escalate_side_effects")
        assert (None if param is None else (param.kind, param.default)) == (
            inspect.Parameter.KEYWORD_ONLY,
            False,
        )

    @pytest.mark.parametrize(
        ("declaration", "expected"),
        [
            ({"side_effect": True}, True),
            ({"side_effect": False}, False),
            ({}, True),
        ],
        ids=["declared-true", "declared-false", "undeclared-defaults-true"],
    )
    def test_registry_get_tool_entry_reports_declared_side_effect(
        self, declaration: dict[str, object], expected: bool
    ) -> None:
        _register("echo", "write", _Handler(), **declaration)
        entry = get_tool_entry("echo", "write")
        assert getattr(entry, "side_effect", "<missing>") is expected

    def test_registry_get_registered_tools_reports_each_side_effect(self) -> None:
        _register("echo", "write", _Handler(), side_effect=True)
        _register("echo", "read", _Handler(), side_effect=False)
        _register("echo", "note", _Handler())
        listed = [
            (d.tool, d.action, getattr(d, "side_effect", "<missing>"))
            for d in get_registered_tools()
        ]
        assert listed == [
            ("echo", "note", True),
            ("echo", "read", False),
            ("echo", "write", True),
        ]

    def test_registry_permission_aware_listing_reports_side_effect(self) -> None:
        """The permission-filtered listing carries the declaration too."""
        _register("echo", "write", _Handler(), side_effect=True)
        _register("echo", "read", _Handler(), side_effect=False)
        config = PermissionsConfig(
            tools={"echo": ToolPermissions(actions={"write": "confirm", "read": "allow"})}
        )
        listed = [
            (d.action, getattr(d, "side_effect", "<missing>"))
            for d in get_registered_tools(permissions_config=config)
        ]
        assert listed == [("read", False), ("write", True)]

    def test_registry_tool_description_side_effect_defaults_true(self) -> None:
        def build(**extra: object) -> ToolDescription:
            return ToolDescription(
                tool="echo",
                action="write",
                description="Write",
                parameters_schema={},
                **extra,  # type: ignore[arg-type]
            )

        assert (
            getattr(build(), "side_effect", "<missing>"),
            getattr(build(side_effect=False), "side_effect", "<missing>"),
        ) == (True, False)

    def test_registry_tool_call_result_escalated_defaults_false(self) -> None:
        result = ToolCallResult(
            success=True, permission=PermissionResult(allowed="allow", reason="ok")
        )
        assert getattr(result, "escalated", "<missing>") is False

    def test_registry_side_effect_never_reaches_llm_tools_payload(self) -> None:
        """The declaration is registry metadata; the LLM's tools array never shows it."""
        _register("echo", "write", _Handler(), side_effect=True)
        _register("echo", "read", _Handler(), side_effect=False)
        descriptions = get_registered_tools()
        payload = _tool_descriptions_to_payload(descriptions)
        assert (
            [d.side_effect for d in descriptions],
            [sorted(item["function"]) for item in payload],  # type: ignore[call-overload]
            "side_effect" in json.dumps(payload),
        ) == (
            [False, True],
            [["description", "name", "parameters"]] * 2,
            False,
        )


# ---------------------------------------------------------------------------
# 2. Every production action declares it (AST scan of src/admino)
# ---------------------------------------------------------------------------


def _callee_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _argument(call: ast.Call, name: str, position: int | None) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    if position is not None and len(call.args) > position:
        return call.args[position]
    return None


def _literal(node: ast.expr | None, kind: type) -> object:
    """The constant's value when ``node`` is a literal of ``kind``, else None."""
    if isinstance(node, ast.Constant) and type(node.value) is kind:
        return node.value
    return None


def _production_register_calls() -> list[tuple[str, int, ast.Call]]:
    """Every ``register_tool(...)`` call in the imported admino package's sources."""
    root = Path(inspect.getfile(admino)).parent
    found: list[tuple[str, int, ast.Call]] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _callee_name(node.func) == "register_tool":
                found.append((path.relative_to(root).as_posix(), node.lineno, node))
    return found


class TestEveryActionDeclaresSideEffect:
    """The issue's test: every registered action declares ``side_effect`` explicitly."""

    def test_registry_every_production_registration_declares_literal_side_effect(
        self,
    ) -> None:
        calls = _production_register_calls()
        undeclared = [
            f"{file}:{line}"
            for file, line, call in calls
            if _literal(_argument(call, "side_effect", None), bool) is None
        ]
        assert (calls != [], undeclared) == (True, [])

    def test_registry_production_side_effect_table_matches_contract(self) -> None:
        rows = sorted(
            (
                _literal(_argument(call, "tool", 0), str),
                _literal(_argument(call, "action", 1), str),
                _literal(_argument(call, "side_effect", None), bool),
            )
            for _file, _line, call in _production_register_calls()
        )
        assert rows == sorted(_EXPECTED_SIDE_EFFECTS)


# ---------------------------------------------------------------------------
# 3. Escalation matrix: side_effect x configured decision x flag
# ---------------------------------------------------------------------------

# (side_effect, configured decision, escalate flag,
#  expected decision, expected escalated, expected handler runs)
_MATRIX: Final[list[tuple[bool, str, object, str, bool, bool]]] = [
    (True, "allow", True, "confirm", True, False),
    (True, "allow", False, "allow", False, True),
    (True, "allow", _OMIT, "allow", False, True),
    (True, "confirm", True, "confirm", False, False),
    (True, "confirm", False, "confirm", False, False),
    (True, "confirm", _OMIT, "confirm", False, False),
    (True, "deny", True, "deny", False, False),
    (True, "deny", False, "deny", False, False),
    (True, "deny", _OMIT, "deny", False, False),
    (False, "allow", True, "allow", False, True),
    (False, "allow", False, "allow", False, True),
    (False, "allow", _OMIT, "allow", False, True),
    (False, "confirm", True, "confirm", False, False),
    (False, "confirm", False, "confirm", False, False),
    (False, "confirm", _OMIT, "confirm", False, False),
    (False, "deny", True, "deny", False, False),
    (False, "deny", False, "deny", False, False),
    (False, "deny", _OMIT, "deny", False, False),
]


def _matrix_id(row: tuple[bool, str, object, str, bool, bool]) -> str:
    side_effect, decision, escalate = row[0], row[1], row[2]
    kind = "side-effect" if side_effect else "read-only"
    return f"{kind}-{decision}-escalate-{escalate}"


class TestEscalationMatrix:
    """Only a side-effect action configured ``allow`` with the flag set becomes confirm."""

    @pytest.mark.parametrize(
        ("side_effect", "decision", "escalate", "want_decision", "want_escalated", "runs"),
        _MATRIX,
        ids=[_matrix_id(row) for row in _MATRIX],
    )
    async def test_registry_escalation_matrix_matches_rule(
        self,
        side_effect: bool,
        decision: str,
        escalate: object,
        want_decision: str,
        want_escalated: bool,
        runs: bool,
    ) -> None:
        handler = _Handler()
        _register("echo", "write", handler, side_effect=side_effect)
        result = await _dispatch(_call(), _config("echo", "write", decision), escalate=escalate)
        assert _outcome(result, handler) == (
            want_decision,
            want_escalated,
            1 if runs else 0,
            runs,
        )

    async def test_registry_undeclared_side_effect_escalates_fail_closed(self) -> None:
        """An action registered without a declaration is treated as a side effect."""
        handler = _Handler()
        _register("echo", "write", handler)
        result = await _dispatch(_call(), _config("echo", "write", "allow"), escalate=True)
        assert _outcome(result, handler) == ("confirm", True, 0, False)

    async def test_registry_escalation_is_per_call_not_sticky(self) -> None:
        """The registry keeps no escalation state: the next call without the flag is allow."""
        handler = _Handler()
        _register("echo", "write", handler, side_effect=True)
        config = _config("echo", "write", "allow")
        first = await _dispatch(_call(), config, escalate=True)
        second = await _dispatch(_call(), config, escalate=False)
        assert (_outcome(first, handler)[:2], _outcome(second, handler)) == (
            ("confirm", True),
            ("allow", False, 1, True),
        )


# ---------------------------------------------------------------------------
# 4. The escalated dispatch follows the confirm path
# ---------------------------------------------------------------------------


class TestEscalatedConfirmPath:
    """An escalated call asks for confirmation and runs only on a matching confirmation."""

    async def test_registry_escalated_without_pending_requires_confirmation(self) -> None:
        handler = _Handler()
        _register("echo", "write", handler, side_effect=True)
        result = await _dispatch(_call(), _config("echo", "write", "allow"))
        assert (
            result.success,
            result.permission.allowed,
            result.pending_confirmation,
            result.result,
            handler.calls,
            getattr(result, "escalated", "<missing>"),
        ) == (
            False,
            "confirm",
            None,
            _ESCALATED_RESULT.format(tool="echo", action="write"),
            0,
            True,
        )

    async def test_registry_escalated_reason_mentions_external_content(self) -> None:
        _register("echo", "write", _Handler(), side_effect=True)
        result = await _dispatch(_call(), _config("echo", "write", "allow"))
        assert result.permission.reason == _ESCALATED_REASON.format(tool="echo", action="write")

    async def test_registry_escalated_with_matching_pending_runs_handler_once(self) -> None:
        handler = _Handler("echo done")
        _register("echo", "write", handler, side_effect=True)
        call = _call()
        result = await _dispatch(
            call, _config("echo", "write", "allow"), pending_confirmation=_pending(call)
        )
        assert (_outcome(result, handler), result.result) == (
            ("confirm", True, 1, True),
            "echo done",
        )

    @pytest.mark.parametrize(
        "pending_call",
        [
            ToolCall(tool="echo", action="write", args={"text": "something else"}),
            ToolCall(tool="echo", action="edit", args={"text": "hello"}),
        ],
        ids=["other-args", "other-action"],
    )
    async def test_registry_escalated_with_mismatched_pending_denies(
        self, pending_call: ToolCall
    ) -> None:
        handler = _Handler()
        _register("echo", "write", handler, side_effect=True)
        _register("echo", "edit", _Handler(), side_effect=True)
        result = await _dispatch(
            _call(),
            PermissionsConfig(
                tools={"echo": ToolPermissions(actions={"write": "allow", "edit": "allow"})}
            ),
            pending_confirmation=_pending(pending_call),
        )
        assert (_outcome(result, handler), result.result) == (
            ("deny", True, 0, False),
            "Pending confirmation does not match this tool call.",
        )

    async def test_registry_escalated_with_expired_pending_denies(self) -> None:
        handler = _Handler()
        _register("echo", "write", handler, side_effect=True)
        call = _call()
        result = await _dispatch(
            call,
            _config("echo", "write", "allow"),
            pending_confirmation=_pending(call, expired=True),
        )
        assert (_outcome(result, handler), result.result) == (
            ("deny", True, 0, False),
            "Pending confirmation has expired.",
        )

    @pytest.mark.parametrize(
        ("args", "behaviour", "want_result_prefix", "want_calls"),
        [
            (
                {"text": "hello", "user_id": "u-1"},
                "returns",
                "Argument validation failed: unexpected fields are not permitted.",
                0,
            ),
            ({"text": ""}, "returns", "Argument validation failed:", 0),
            ({"text": "hello"}, "raises", "Tool execution failed: RuntimeError", 1),
            (
                {"text": "hello"},
                "returns-none",
                "Tool execution failed: handler returned non-string result.",
                1,
            ),
        ],
        ids=["unexpected-field", "invalid-value", "handler-raises", "non-string-result"],
    )
    async def test_registry_escalated_failure_after_confirmation_is_flagged(
        self,
        args: dict[str, object],
        behaviour: str,
        want_result_prefix: str,
        want_calls: int,
    ) -> None:
        """Validation failures and handler errors of an escalated call keep escalated=True."""
        handler = {
            "returns": _Handler(),
            "raises": _Handler(raises="boom"),
            "returns-none": _Handler(None),
        }[behaviour]
        _register("echo", "write", handler, side_effect=True)
        call = ToolCall(tool="echo", action="write", args=args)
        result = await _dispatch(
            call, _config("echo", "write", "allow"), pending_confirmation=_pending(call)
        )
        assert (_outcome(result, handler), result.result.startswith(want_result_prefix)) == (
            ("confirm", True, want_calls, False),
            True,
        )


# ---------------------------------------------------------------------------
# 5. A decision is never relaxed; non-dispatch paths are never escalated
# ---------------------------------------------------------------------------


class TestNeverRelaxed:
    """The flag only ever tightens ``allow``; hardcoded denials stay global."""

    @pytest.mark.parametrize("with_pending", [False, True], ids=["no-pending", "pending"])
    async def test_registry_immutable_denial_stays_denied_under_escalation(
        self, with_pending: bool
    ) -> None:
        handler = _Handler()
        _register("memory", "delete", handler, side_effect=True)
        call = _call("memory", "delete")
        extra = {"pending_confirmation": _pending(call)} if with_pending else {}
        result = await _dispatch(call, _config("memory", "delete", "allow"), **extra)
        assert _outcome(result, handler) == ("deny", False, 0, False)

    @pytest.mark.parametrize("with_pending", [False, True], ids=["no-pending", "pending"])
    async def test_registry_unpromoted_gmail_send_stays_denied_under_escalation(
        self, with_pending: bool
    ) -> None:
        handler = _Handler()
        _register("gmail", "send", handler, side_effect=True)
        call = _call("gmail", "send")
        extra = {"pending_confirmation": _pending(call)} if with_pending else {}
        result = await _dispatch(call, _config("gmail", "send", "allow"), **extra)
        assert _outcome(result, handler) == ("deny", False, 0, False)

    async def test_registry_promoted_gmail_send_confirm_is_not_escalated(self) -> None:
        handler = _Handler()
        _register("gmail", "send", handler, side_effect=True)
        result = await _dispatch(
            _call("gmail", "send"),
            PermissionsConfig(),
            promoted=frozenset({("gmail", "send")}),
        )
        assert (_outcome(result, handler), result.result) == (
            ("confirm", False, 0, False),
            "Action gmail.send requires user confirmation.",
        )

    async def test_registry_promoted_gmail_send_confirmed_runs_not_escalated(self) -> None:
        handler = _Handler("sent")
        _register("gmail", "send", handler, side_effect=True)
        call = _call("gmail", "send")
        result = await _dispatch(
            call,
            PermissionsConfig(),
            promoted=frozenset({("gmail", "send")}),
            pending_confirmation=_pending(call),
        )
        assert _outcome(result, handler) == ("confirm", False, 1, True)

    async def test_registry_configured_confirm_with_pending_runs_not_escalated(self) -> None:
        handler = _Handler("written")
        _register("echo", "write", handler, side_effect=True)
        call = _call()
        result = await _dispatch(
            call, _config("echo", "write", "confirm"), pending_confirmation=_pending(call)
        )
        assert _outcome(result, handler) == ("confirm", False, 1, True)

    @pytest.mark.parametrize("path", ["unknown", "disabled", "malformed"])
    async def test_registry_rejected_before_engine_is_not_escalated(self, path: str) -> None:
        handler = _Handler()
        extra: dict[str, object] = {}
        if path == "unknown":
            _register("echo", "other", handler, side_effect=True)
            call = _call()
        elif path == "disabled":
            _register("echo", "write", handler, side_effect=True)
            extra["enabled_tools"] = {"echo": False}
            call = _call()
        else:
            _register("echo", "write", handler, side_effect=True)
            call = ToolCall.model_construct(tool="ECHO", action="write", args={"text": "hello"})
        result = await _dispatch(call, _config("echo", "write", "allow"), **extra)
        assert _outcome(result, handler) == ("deny", False, 0, False)


# ---------------------------------------------------------------------------
# 6. The permission engine is untouched
# ---------------------------------------------------------------------------


class TestPermissionEngineUntouched:
    """``check_permission`` is called exactly as before and ``permissions.py`` is unchanged."""

    @pytest.mark.parametrize("escalate", [True, False])
    async def test_registry_check_permission_call_unchanged_under_escalation(
        self, escalate: bool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real_check = registry.check_permission
        calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

        def spy(*args: Any, **kwargs: Any) -> PermissionResult:
            calls.append((args, kwargs))
            return real_check(*args, **kwargs)

        monkeypatch.setattr(registry, "check_permission", spy)
        _register("echo", "write", _Handler(), side_effect=True)
        config = _config("echo", "write", "allow")
        promoted = frozenset({("gmail", "send")})
        await _dispatch(_call(text=_LEAK_ARG), config, escalate=escalate, promoted=promoted)
        assert [
            (args[:2], args[2] is config, len(args), sorted(kwargs), kwargs["promoted"] is promoted)
            for args, kwargs in calls
        ] == [(("echo", "write"), True, 3, ["promoted"], True)]

    async def test_registry_escalation_follows_engine_decision(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The escalation rewrites the engine's own answer: an engine deny is final."""

        def deny_all(*_args: Any, **_kwargs: Any) -> PermissionResult:
            return PermissionResult(allowed="deny", reason="Engine says no.")

        monkeypatch.setattr(registry, "check_permission", deny_all)
        handler = _Handler()
        _register("echo", "write", handler, side_effect=True)
        result = await _dispatch(_call(), _config("echo", "write", "allow"))
        assert (_outcome(result, handler), result.result) == (
            ("deny", False, 0, False),
            "Engine says no.",
        )

    def test_registry_check_permission_signature_unchanged(self) -> None:
        """Regression guard: the engine gains no input for the escalation."""
        params = inspect.signature(permissions.check_permission).parameters.values()
        assert [(p.name, p.kind) for p in params] == [
            ("tool", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            ("action", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            ("config", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            ("promoted", inspect.Parameter.KEYWORD_ONLY),
        ]

    def test_registry_permissions_module_never_mentions_escalation(self) -> None:
        """Regression guard: the escalation lives in dispatch, not in ``permissions.py``."""
        source = Path(inspect.getfile(permissions)).read_text(encoding="utf-8").casefold()
        assert [term for term in ("untrusted", "side_effect", "escalat") if term in source] == []


# ---------------------------------------------------------------------------
# 7. No content in logs on the escalation path
# ---------------------------------------------------------------------------


class TestEscalationLogsNoContent:
    """Escalated dispatches log identifiers at most: no args, output or exception text."""

    @pytest.mark.parametrize("log_format", ["json", "text"])
    async def test_registry_escalation_path_logs_no_content(self, log_format: str) -> None:
        writer = _Handler(_LEAK_OUTPUT)
        failing = _Handler(raises=_LEAK_EXCEPTION)
        _register("echo", "write", writer, side_effect=True)
        _register("echo", "edit", failing, side_effect=True)
        config = PermissionsConfig(
            tools={"echo": ToolPermissions(actions={"write": "allow", "edit": "allow"})}
        )
        write_call = _call(text=_LEAK_ARG)
        edit_call = _call(action="edit", text=_LEAK_ARG)
        with configured_logging("DEBUG", log_format) as captured:
            asked = await _dispatch(write_call, config)
            ran = await _dispatch(write_call, config, pending_confirmation=_pending(write_call))
            failed = await _dispatch(edit_call, config, pending_confirmation=_pending(edit_call))
            mismatched = await _dispatch(
                write_call, config, pending_confirmation=_pending(edit_call)
            )
        record_text = " ".join(
            f"{record.getMessage()} {record.args!r} {record.exc_info!r}"
            for record in captured.records
        ).casefold()
        output = f"{captured.text.casefold()} {record_text}"
        assert (
            [getattr(r, "escalated", None) for r in (asked, ran, failed, mismatched)],
            "echo.edit raised runtimeerror" in output,
            [marker for marker in _LEAK_MARKERS if marker.casefold() in output],
        ) == ([True, True, True, True], True, [])
