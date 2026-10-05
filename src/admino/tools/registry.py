"""Tool registration and dispatch for admino.

Provides the ``@register_tool`` decorator for registering async tool handler
functions, a dispatch function that enforces permission checks before execution,
and a listing function that returns tool metadata for the LLM's ``tools`` array.

Architecture:
- The registry is a module-level dict mapping ``(tool_name, action_name)`` to
  handler metadata.  It is populated at import time via ``@register_tool`` and
  should be treated as immutable after startup.
- ``dispatch_tool_call`` is the **only** entry point for executing tools.
  Unregistered (tool, action) pairs are rejected as unknown tools right after
  the identifier and enabled checks; the permission check (via
  ``permissions.check_permission``) then runs **before** any confirmation
  request, argument validation or handler execution.
- Argument validation uses each tool's declared Pydantic ``args_schema``.
- Dispatch does not audit.  The agent records every dispatch outcome (tool,
  action, final decision, success, duration — never args or output) through
  its injected tool-call recorder, so there is a single recording point.

Security notes:
- An unknown (unregistered) tool is denied before the permission engine runs,
  so a call with no handler never produces a confirmation request (GH-143).
- For registered tools the permission check runs before confirmation handling,
  argument validation and execution.
- Tool/action identifiers are validated against the same ``[a-z][a-z0-9_]{0,62}``
  pattern used by the permission engine.
- Argument validation errors never leak raw input values; only field-level
  constraint descriptions are surfaced.
- Side-effect escalation (GH-243): every registration declares
  ``side_effect`` (default True, fail-closed). Once the agent's run has
  received external content it dispatches with ``escalate_side_effects``,
  and a side-effect action the engine allows becomes ``confirm``
  (``ToolCallResult.escalated``). This happens after ``check_permission``,
  which is called exactly as without it and never sees the flag; ``deny`` and
  ``confirm`` are kept, so a decision is never relaxed.
- Tool context (GH-162): ``dispatch_tool_call`` requires the run's
  ``TenantContext`` and hands it to the handler as ``tenant=``; handlers
  scope every content query by its user_id and org_id. The context only
  comes from the server side: unknown argument keys (``user_id``, ``org_id``,
  ``tenant``, ``session_id``) are rejected before validation, so an LLM can't
  supply or override it. The permission engine never sees it.
- No ``eval``, ``exec``, ``compile``, ``importlib``, or ``shell=True``.
- This module does NOT import from ``agent.py``, ``llm.py``, or ``server.py``.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, Field, ValidationError

from admino.logs import safe_log
from admino.models import (
    _CONTROL_CHAR_TABLE,
    PendingConfirmation,
    ToolCall,
)
from admino.permissions import PermissionResult, PermissionsConfig, check_permission

if TYPE_CHECKING:
    from admino.tenancy import TenantContext

logger = logging.getLogger(__name__)

# Cached at import time so a later env change cannot re-enable the test-only
# clear_registry() in production.
_IS_PRODUCTION: Final[bool] = os.environ.get("ADMINO_ENV", "").lower() == "production"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VALID_IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_MAX_RESULT_LENGTH: Final[int] = 65_536

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

# Async tool handler: receives validated Pydantic args model instance, returns
# a result string.  The dispatch function passes the keyword arguments
# ``session_id`` and ``tenant`` (the run's TenantContext, GH-162); handlers
# take ``**_`` for the ones they don't use.
#
# NOTE: ``Callable[..., Awaitable[str]]`` cannot enforce the return type at
# registration time — Python's type system does not narrow ``...`` parameter
# specs.  The str return is enforced at runtime in ``dispatch_tool_call`` via
# an explicit ``isinstance(result, str)`` check after handler execution.
ToolHandler = Callable[..., Awaitable[str]]

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ToolDescription(BaseModel):
    """Metadata describing a registered tool for LLM tool-calling.

    Serialised into the ``tools`` array of the LLM chat request
    so the LLM knows which tools are available and their argument schemas.
    """

    tool: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="Tool name (e.g. 'gmail', 'calendar').",
    )
    action: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="Action name (e.g. 'read', 'search').",
    )
    description: str = Field(
        min_length=1,
        max_length=1024,
        description="Human-readable description of what this tool action does.",
    )
    parameters_schema: dict[str, object] = Field(
        description="JSON Schema derived from the tool's Pydantic args model.",
    )
    side_effect: bool = Field(
        default=True,
        description=(
            "Whether the action changes something (registry metadata; never sent to the LLM)."
        ),
    )


class ToolCallResult(BaseModel):
    """Result of a tool dispatch operation.

    Returned by ``dispatch_tool_call`` for every code path: permission denied,
    pending confirmation, validation failure, execution success, or execution
    error.
    """

    success: bool = Field(
        description="Whether the tool executed successfully.",
    )
    result: str = Field(
        default="",
        max_length=65536,
        description="Tool output on success, or error description on failure.",
    )
    permission: PermissionResult = Field(
        description="The permission engine's decision for this tool call.",
    )
    pending_confirmation: PendingConfirmation | None = Field(
        default=None,
        description=(
            "Set when the permission decision is 'confirm' and the call is pending user approval."
        ),
    )
    escalated: bool = Field(
        default=False,
        description=(
            "Whether dispatch tightened an 'allow' to 'confirm' because the run holds "
            "external content (GH-243)."
        ),
    )


# ---------------------------------------------------------------------------
# Registry data structure
# ---------------------------------------------------------------------------


class _ToolEntry(BaseModel):
    """Internal registry entry for a registered tool handler.

    Not exported — callers interact via ``register_tool``, ``dispatch_tool_call``,
    and ``get_registered_tools``.
    """

    tool: str = Field(max_length=63, pattern=r"^[a-z][a-z0-9_]{0,62}$")
    action: str = Field(max_length=63, pattern=r"^[a-z][a-z0-9_]{0,62}$")
    description: str = Field(min_length=1, max_length=1024)
    args_schema: type[BaseModel] = Field(
        description="Pydantic model class used to validate tool arguments.",
    )
    side_effect: bool = Field(description="Whether the action changes something.")
    # Stored separately because Pydantic cannot serialise bare callables
    # and we do not need to serialise entries.
    handler: ToolHandler = Field(
        description="The async handler function to invoke.",
        exclude=True,
    )

    model_config = {"arbitrary_types_allowed": True}


# Module-level registry.  Populated at import time by @register_tool.
# After startup, treat as read-only — tool handlers must never mutate it.
_REGISTRY: dict[tuple[str, str], _ToolEntry] = {}

# Once frozen, ``register_tool`` refuses further registrations.  Production
# entry points (main.py / server startup) should call ``freeze_registry()``
# after all tool modules have been imported.  Direct mutation of ``_REGISTRY``
# bypasses this flag — the underscore prefix and this comment are the only
# line of defence for that path.
_FROZEN: bool = False


# ---------------------------------------------------------------------------
# Registration decorator
# ---------------------------------------------------------------------------


def register_tool(
    tool: str,
    action: str,
    description: str,
    args_schema: type[BaseModel],
    *,
    side_effect: bool = True,
) -> Callable[[ToolHandler], ToolHandler]:
    """Decorator that registers an async tool handler in the global registry.

    Args:
        tool: Tool name — must match ``[a-z][a-z0-9_]{0,62}``.
        action: Action name — must match ``[a-z][a-z0-9_]{0,62}``.
        description: Human-readable description (1-1024 chars).
        args_schema: Pydantic BaseModel subclass for argument validation.
        side_effect: Whether the action changes something (sends, creates,
            updates, stores). Fail-closed default: an undeclared action counts
            as a side effect, so it is escalated once a run holds external
            content. Production registrations declare it explicitly.

    Returns:
        A decorator that registers the wrapped function and returns it unchanged.

    Raises:
        ValueError: If tool/action identifiers are invalid or already registered.
    """
    if _FROZEN:
        msg = "Tool registry is frozen; register_tool() is not allowed after startup"
        raise RuntimeError(msg)
    if not _VALID_IDENTIFIER.fullmatch(tool):
        msg = f"Invalid tool name: {tool!r:.64}"
        raise ValueError(msg)
    if not _VALID_IDENTIFIER.fullmatch(action):
        msg = f"Invalid action name: {action!r:.64}"
        raise ValueError(msg)

    key = (tool, action)
    if key in _REGISTRY:
        msg = f"Tool {tool}.{action} is already registered"
        raise ValueError(msg)

    def decorator(func: ToolHandler) -> ToolHandler:
        entry = _ToolEntry(
            tool=tool,
            action=action,
            description=description,
            args_schema=args_schema,
            side_effect=side_effect,
            handler=func,
        )
        _REGISTRY[key] = entry
        logger.debug("Registered tool %s.%s", tool, action)
        return func

    return decorator


# ---------------------------------------------------------------------------
# Dispatch function
# ---------------------------------------------------------------------------


async def dispatch_tool_call(
    tool_call: ToolCall,
    permissions_config: PermissionsConfig,
    *,
    session_id: str,
    tenant: TenantContext,
    pending_confirmation: PendingConfirmation | None = None,
    promoted: frozenset[tuple[str, str]] = frozenset(),
    enabled_tools: dict[str, bool] | None = None,
    escalate_side_effects: bool = False,
) -> ToolCallResult:
    """Dispatch a tool call: check enabled state, registry, permissions, validate, execute.

    This is the single entry point for tool execution.  The sequence is:
    0. Reject malformed identifiers.
    1. Check enabled state — disabled tools are rejected before anything else.
    2. Look up the tool in the registry — an unregistered (tool, action),
       e.g. a hallucinated or removed tool, is rejected as an unknown tool
       with a ``deny`` decision.  The permission engine never evaluates it
       and no confirmation is ever requested for it.
    3. Check permission via the isolated permission engine; if denied, return
       immediately with the denial reason.  With ``escalate_side_effects``, a
       side-effect action the engine allows becomes ``confirm`` (escalated).
    4. If ``confirm`` and no pending_confirmation supplied, return a result
       indicating that user confirmation is required.  If pending_confirmation
       IS supplied, verify its tool/action identity and expiry.
    5. Reject unknown args keys, then validate against the Pydantic schema.
    6. Execute the async handler with ``session_id`` and ``tenant``.

    Dispatch writes no audit record itself: the agent records every returned
    outcome (``result.permission.allowed`` and ``result.success``) through its
    injected tool-call recorder, so a disabled or unknown tool surfaces here
    as a ``deny`` decision.

    Args:
        tool_call: The LLM-requested tool call (tool, action, raw args).
        permissions_config: The validated permissions configuration.
        session_id: Current session identifier (passed to the handler).
        tenant: The run's tool context (GH-162): the logged-in user's
            ``TenantContext``, built server-side from the principal and passed
            to the handler as ``tenant=`` unchanged. Never taken from the
            LLM's arguments: an argument key the schema doesn't declare (e.g.
            ``user_id``, ``org_id``, ``tenant``) is rejected before the handler.
        pending_confirmation: If present, the user has already confirmed this
            call.  Dispatch verifies that ``pending_confirmation.tool_call.tool``,
            ``.action``, AND ``.args`` match the incoming ``tool_call`` and that
            the confirmation has not expired.  Mismatches (including args
            differences) and expiries are rejected — the caller is no longer
            the sole line of defence.
        enabled_tools: Per-tool enabled state from settings.  When provided,
            tools whose name maps to ``False`` are rejected before the
            registry lookup and permission check.  Missing keys default to
            enabled.
        escalate_side_effects: The run has received external content
            (GH-243): a ``side_effect`` action the engine allows needs the
            user's confirmation instead, and every result of that dispatch
            has ``escalated=True``.  ``deny`` and ``confirm`` are kept as they
            are, so a decision is only ever tightened.

    Returns:
        A ``ToolCallResult`` with the outcome of the dispatch.
    """
    raw_tool = tool_call.tool
    raw_action = tool_call.action

    # 0. Defensive identifier validation — reject malformed identifiers before
    #    any permission check or registry lookup.
    if not _VALID_IDENTIFIER.fullmatch(raw_tool) or not _VALID_IDENTIFIER.fullmatch(raw_action):
        permission = PermissionResult(allowed="deny", reason="Malformed identifier.")
        return ToolCallResult(
            success=False,
            result="Invalid tool or action identifier.",
            permission=permission,
        )

    # 1. Enabled check — reject disabled tools before the registry lookup and
    #    the permission engine run.
    if enabled_tools is not None and enabled_tools.get(raw_tool) is False:
        disabled_permission = PermissionResult(allowed="deny", reason="Tool is disabled.")
        return ToolCallResult(
            success=False,
            result=f"Tool '{raw_tool}' is disabled.",
            permission=disabled_permission,
        )

    # 2. Unknown-tool check — an unregistered (tool, action) has no handler, so
    #    it is denied before the permission engine runs.  This way a call to a
    #    hallucinated or removed tool can never trigger a confirmation request,
    #    whatever its configured permission state.
    entry = _REGISTRY.get((raw_tool, raw_action))
    if entry is None:
        logger.warning(
            "Rejected unknown tool %s.%s (not in registry)",
            safe_log(raw_tool),
            safe_log(raw_action),
        )
        unknown = PermissionResult(allowed="deny", reason="Tool is not registered.")
        return ToolCallResult(
            success=False,
            # defence-in-depth truncation on [:63] slices
            result=f"Unknown tool: {raw_tool[:63]}.{raw_action[:63]}",
            permission=unknown,
        )

    # 3. Permission check — before any confirmation, arg parsing or execution.
    #    SECURITY: check_permission receives ONLY (tool, action, config, promoted).
    #    It must never see LLM-supplied args, session state, or conversation.
    permission = check_permission(raw_tool, raw_action, permissions_config, promoted=promoted)

    # 3a. Escalation (GH-243) — after the engine, never inside it: external
    #     content in the run may have planted the call, so an allowed side
    #     effect waits for the user.  Only ``allow`` is rewritten.
    escalated = escalate_side_effects and entry.side_effect and permission.allowed == "allow"
    if escalated:
        permission = PermissionResult(
            allowed="confirm",
            reason=(
                f"Action {raw_tool}.{raw_action} needs confirmation: "
                "this conversation contains external content."
            ),
        )

    # 3b. Denied — return immediately (never escalated).
    if permission.allowed == "deny":
        return ToolCallResult(
            success=False,
            result=permission.reason,
            permission=permission,
        )

    # 4. Confirm required.
    if permission.allowed == "confirm":
        # 4a. No confirmation supplied — ask the user.
        if pending_confirmation is None:
            # defence-in-depth truncation on [:63] slices
            required = f"Action {raw_tool[:63]}.{raw_action[:63]} requires user confirmation"
            if escalated:
                required += ": this conversation contains external content"
            return ToolCallResult(
                success=False,
                result=f"{required}.",
                permission=permission,
                escalated=escalated,
            )

        # 4b. Confirmation supplied — enforce identity match.  The caller MUST
        #     NOT be the sole line of defence: a stale or mismatched
        #     confirmation must not unlock a different action.
        #     M3 fix: also verify args deep equality to prevent a caller from
        #     confirming a safe version then dispatching a destructive one.
        if (
            pending_confirmation.tool_call.tool != raw_tool
            or pending_confirmation.tool_call.action != raw_action
            or pending_confirmation.tool_call.args != tool_call.args
        ):
            logger.warning(
                "Rejected mismatched pending_confirmation for %s.%s",
                safe_log(raw_tool),
                safe_log(raw_action),
            )
            mismatched = PermissionResult(
                allowed="deny",
                reason="Pending confirmation does not match tool call.",
            )
            return ToolCallResult(
                success=False,
                result="Pending confirmation does not match this tool call.",
                permission=mismatched,
                escalated=escalated,
            )

        # 4c. Confirmation supplied — enforce expiry.
        if datetime.now(UTC) >= pending_confirmation.expires_at:
            logger.warning(
                "Rejected expired pending_confirmation for %s.%s",
                safe_log(raw_tool),
                safe_log(raw_action),
            )
            expired = PermissionResult(
                allowed="deny",
                reason="Pending confirmation has expired.",
            )
            return ToolCallResult(
                success=False,
                result="Pending confirmation has expired.",
                permission=expired,
                escalated=escalated,
            )

    # 5a. Reject args containing fields not declared on the schema.  Pydantic's
    #     default ``extra='ignore'`` would silently discard them, giving the
    #     LLM a covert channel to smuggle data past argument validation.
    schema_fields = set(entry.args_schema.model_fields.keys())
    extra_keys = [k for k in tool_call.args if k not in schema_fields]
    if extra_keys:
        return ToolCallResult(
            success=False,
            result="Argument validation failed: unexpected fields are not permitted.",
            permission=permission,
            escalated=escalated,
        )

    # 5b. Validate arguments against the tool's Pydantic schema.
    try:
        validated_args = entry.args_schema.model_validate(tool_call.args)
    except ValidationError as exc:
        # Never leak raw input values — use include_input=False.
        error_details = exc.errors(include_input=False)
        error_summary = "; ".join(
            f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}" for e in error_details
        )
        return ToolCallResult(
            success=False,
            result=f"Argument validation failed: {error_summary[:512]}",
            permission=permission,
            escalated=escalated,
        )

    # 6. Execute the async handler.
    try:
        result = await entry.handler(validated_args, session_id=session_id, tenant=tenant)
    except (MemoryError, RecursionError):
        raise
    except Exception as exc:
        # Catch handler errors — never expose raw exception details that
        # might contain user data or internal paths.  exc_info is deliberately
        # NOT passed: the exception message could include credentials or
        # filesystem paths from arbitrary tool handlers.
        error_type = type(exc).__name__
        logger.error(
            "Tool %s.%s raised %s during execution",
            safe_log(raw_tool),
            safe_log(raw_action),
            error_type,
        )
        return ToolCallResult(
            success=False,
            result=f"Tool execution failed: {error_type}",
            permission=permission,
            escalated=escalated,
        )

    # Guard against handlers that return a non-string type (e.g. None, dict).
    if not isinstance(result, str):
        logger.error(
            "Tool %s.%s returned non-string type %s",
            safe_log(raw_tool),
            safe_log(raw_action),
            type(result).__name__,
        )
        return ToolCallResult(
            success=False,
            result="Tool execution failed: handler returned non-string result.",
            permission=permission,
            escalated=escalated,
        )

    # Sanitize handler output: strip control characters that could spoof
    # log viewers, confirmation dialogs, or downstream consumers.
    sanitized_result = result.translate(_CONTROL_CHAR_TABLE)

    # Truncate to prevent oversized results from blowing up downstream
    # consumers or exceeding the ToolCallResult.result field constraint.
    if len(sanitized_result) > _MAX_RESULT_LENGTH:
        sanitized_result = sanitized_result[:_MAX_RESULT_LENGTH]

    return ToolCallResult(
        success=True,
        result=sanitized_result,
        permission=permission,
        escalated=escalated,
    )


# ---------------------------------------------------------------------------
# Tool listing
# ---------------------------------------------------------------------------


def get_registered_tools(
    *,
    enabled_tools: dict[str, bool] | None = None,
    permissions_config: PermissionsConfig | None = None,
    promoted: frozenset[tuple[str, str]] = frozenset(),
) -> list[ToolDescription]:
    """Return metadata for registered tools, optionally filtered by enabled state.

    Used to build the ``tools`` array in the LLM ``/api/chat`` request so
    the LLM knows which tools are available and their parameter schemas.

    Security (GH-77): when ``permissions_config`` is supplied, any (tool, action)
    the permission engine would ``deny`` is EXCLUDED from the advertised list.
    This makes tool exposure permission-aware so the LLM never sees — and thus
    cannot substitute — an action that is hardcoded-denied or a tier-2
    promotable action that has not yet been promoted.  ``allow`` and ``confirm``
    actions remain advertised.  When ``permissions_config`` is None the result
    is unchanged (module-enablement filtering only), preserving prior callers.

    Args:
        enabled_tools: When provided, tools whose name maps to ``False``
            are excluded.  Missing keys default to enabled for backward
            compatibility.
        permissions_config: When provided, tools whose (tool, action) the
            permission engine denies are excluded.  ``promoted`` is forwarded
            to the engine so promoted tier-2 actions surface as ``confirm``.
        promoted: Set of (tool, action) pairs promoted from tier-2 deny to
            confirm via the Critical Permissions API.  Only consulted when
            ``permissions_config`` is supplied.

    Returns:
        A list of ``ToolDescription`` models sorted by (tool, action).
    """
    descriptions: list[ToolDescription] = []
    for _key, entry in sorted(_REGISTRY.items()):
        if enabled_tools is not None and enabled_tools.get(entry.tool) is False:
            continue
        if permissions_config is not None:
            decision = check_permission(
                entry.tool, entry.action, permissions_config, promoted=promoted
            )
            if decision.allowed == "deny":
                continue
        schema = entry.args_schema.model_json_schema()
        descriptions.append(
            ToolDescription(
                tool=entry.tool,
                action=entry.action,
                description=entry.description,
                parameters_schema=schema,
                side_effect=entry.side_effect,
            )
        )
    return descriptions


def get_tool_entry(tool: str, action: str) -> ToolDescription | None:
    """Look up a registered tool's description by name and action.

    Returns a safe ``ToolDescription`` projection (no handler reference).
    Returns None if the tool is not registered.

    Args:
        tool: Tool name.
        action: Action name.

    Returns:
        A ``ToolDescription`` or None if not found.
    """
    entry = _REGISTRY.get((tool, action))
    if entry is None:
        return None
    return ToolDescription(
        tool=entry.tool,
        action=entry.action,
        description=entry.description,
        parameters_schema=entry.args_schema.model_json_schema(),
        side_effect=entry.side_effect,
    )


def freeze_registry() -> None:
    """Mark the registry as frozen.

    After freezing, any call to ``register_tool`` raises ``RuntimeError``.
    Production entry points should call this once all tool modules have
    been imported so that late/dynamic registration cannot silently alter
    the enforcement surface.

    Note: this flag does not protect against direct mutation of the
    private ``_REGISTRY`` dict — that is deliberately left to the
    underscore-prefix convention and CI scans.
    """
    global _FROZEN
    _FROZEN = True


def clear_registry() -> None:
    """Remove all entries from the tool registry and unfreeze.

    **Testing only** — this function exists solely for test fixture teardown.
    In production (``ADMINO_ENV=production``) it raises ``RuntimeError`` at
    call time, regardless of where it is called from.  A CI scan test
    (``test_no_production_clear_registry_calls``) additionally verifies that
    no non-test module references it.
    """
    if _IS_PRODUCTION:
        msg = "clear_registry() is forbidden in production (ADMINO_ENV=production)"
        raise RuntimeError(msg)
    global _FROZEN
    _REGISTRY.clear()
    _FROZEN = False
