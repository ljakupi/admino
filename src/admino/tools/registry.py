"""Tool registration and dispatch for admino.

Provides the ``@register_tool`` decorator for registering async tool handler
functions, a dispatch function that enforces permission checks before execution,
and a listing function that returns tool metadata for the LLM's ``tools`` array.

Architecture:
- The registry is a module-level dict mapping ``(tool_name, action_name)`` to
  handler metadata.  It is populated at import time via ``@register_tool`` and
  should be treated as immutable after startup.
- ``dispatch_tool_call`` is the **only** entry point for executing tools.
  Permission checks (via ``permissions.check_permission``) always run **before**
  argument validation or handler execution.
- Argument validation uses each tool's declared Pydantic ``args_schema``.

Security notes:
- Permission check is the FIRST operation in dispatch — before arg validation.
- Tool/action identifiers are validated against the same ``[a-z][a-z0-9_]{0,62}``
  pattern used by the permission engine.
- Argument validation errors never leak raw input values; only field-level
  constraint descriptions are surfaced.
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

from admino.models import (
    _CONTROL_CHAR_TABLE,
    PendingConfirmation,
    ToolCall,
    ToolCallAuditEntry,
)
from admino.permissions import PermissionResult, PermissionsConfig, check_permission

if TYPE_CHECKING:
    from admino.audit import AuditLogger

logger = logging.getLogger(__name__)

# Cached at import time so it cannot be mutated between import and dispatch.
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
# a result string.  Additional keyword arguments (e.g. session_id) may be
# passed by the dispatch function.
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

    Serialised into the ``tools`` array of the Ollama ``/api/chat`` request
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
) -> Callable[[ToolHandler], ToolHandler]:
    """Decorator that registers an async tool handler in the global registry.

    Args:
        tool: Tool name — must match ``[a-z][a-z0-9_]{0,62}``.
        action: Action name — must match ``[a-z][a-z0-9_]{0,62}``.
        description: Human-readable description (1-1024 chars).
        args_schema: Pydantic BaseModel subclass for argument validation.

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
            handler=func,
        )
        _REGISTRY[key] = entry
        logger.debug("Registered tool %s.%s", tool, action)
        return func

    return decorator


# ---------------------------------------------------------------------------
# Dispatch function
# ---------------------------------------------------------------------------


def _write_audit(
    audit_logger: AuditLogger | None,
    *,
    session_id: str,
    tool: str,
    action: str,
    permission: PermissionResult,
    args_keys: list[str],
    success: bool,
    error: str | None,
) -> None:
    """Write a ToolCallAuditEntry for a dispatch outcome, if a logger is set.

    The audit entry records only argument *key names*, never values, to
    avoid credential leakage.  Malformed tool/action identifiers are
    replaced with fixed placeholders so the Pydantic model validates.
    """
    if audit_logger is None:
        return
    safe_tool = tool if _VALID_IDENTIFIER.fullmatch(tool) else "invalid"
    safe_action = action if _VALID_IDENTIFIER.fullmatch(action) else "rejected"
    # Sort for determinism; truncate to the audit-entry field limit.
    args_summary = ",".join(sorted(args_keys))[:512] if args_keys else "[no args]"
    entry = ToolCallAuditEntry(
        session_id=session_id,
        tool=safe_tool,
        action=safe_action,
        permission=permission.allowed,
        args_summary=args_summary,
        success=success,
        error=error,
    )
    audit_logger.log_tool_call(entry)


async def dispatch_tool_call(
    tool_call: ToolCall,
    permissions_config: PermissionsConfig,
    *,
    session_id: str,
    pending_confirmation: PendingConfirmation | None = None,
    audit_logger: AuditLogger | None = None,
) -> ToolCallResult:
    """Dispatch a tool call: check permissions, validate args, execute handler.

    This is the single entry point for tool execution.  The sequence is:
    1. Check permission via the isolated permission engine.
    2. If denied, return immediately with the denial reason.
    3. If ``confirm`` and no pending_confirmation supplied, return a result
       indicating that user confirmation is required.  If pending_confirmation
       IS supplied, verify its tool/action identity and expiry.
    4. Look up the tool in the registry (reject hallucinated tool names).
    5. Reject unknown args keys, then validate against the Pydantic schema.
    6. Execute the async handler.

    Every terminal path writes a ``ToolCallAuditEntry`` via ``audit_logger``
    if one is supplied.  In production (``ADMINO_ENV=production``), an audit
    logger is REQUIRED — passing ``None`` raises ``ValueError``.

    Args:
        tool_call: The LLM-requested tool call (tool, action, raw args).
        permissions_config: The validated permissions configuration.
        session_id: Current session identifier (passed to the handler).
        pending_confirmation: If present, the user has already confirmed this
            call.  Dispatch verifies that ``pending_confirmation.tool_call.tool``,
            ``.action``, AND ``.args`` match the incoming ``tool_call`` and that
            the confirmation has not expired.  Mismatches (including args
            differences) and expiries are rejected — the caller is no longer
            the sole line of defence.
        audit_logger: Sink for ``ToolCallAuditEntry`` records.  Required in
            production; optional in dev/tests for ergonomic reasons.

    Returns:
        A ``ToolCallResult`` with the outcome of the dispatch.

    Raises:
        ValueError: If ``audit_logger`` is None and ``ADMINO_ENV=production``.
    """
    # Production enforcement: audit logger MUST be present.  This mirrors the
    # pattern in audit.py (base_dir=None disallowed in production) and ensures
    # the audit trail cannot be silently skipped.
    if audit_logger is None and _IS_PRODUCTION:
        msg = (
            "audit_logger is required in production (ADMINO_ENV=production). "
            "Pass a non-None AuditLogger to dispatch_tool_call."
        )
        raise ValueError(msg)

    raw_tool = tool_call.tool
    raw_action = tool_call.action
    args_keys = list(tool_call.args.keys())

    # 0. Defensive identifier validation — reject malformed identifiers before
    #    any permission check or registry lookup.
    if not _VALID_IDENTIFIER.fullmatch(raw_tool) or not _VALID_IDENTIFIER.fullmatch(raw_action):
        permission = PermissionResult(allowed="deny", reason="Malformed identifier.")
        _write_audit(
            audit_logger,
            session_id=session_id,
            tool=raw_tool,
            action=raw_action,
            permission=permission,
            args_keys=args_keys,
            success=False,
            error="Malformed identifier.",
        )
        return ToolCallResult(
            success=False,
            result="Invalid tool or action identifier.",
            permission=permission,
        )

    # 1. Permission check — ALWAYS first, before any arg parsing or execution.
    #    SECURITY: check_permission receives ONLY (tool, action, config).
    #    It must never see LLM-supplied args, session state, or conversation.
    permission = check_permission(raw_tool, raw_action, permissions_config)

    # 2. Denied — return immediately.
    if permission.allowed == "deny":
        _write_audit(
            audit_logger,
            session_id=session_id,
            tool=raw_tool,
            action=raw_action,
            permission=permission,
            args_keys=args_keys,
            success=False,
            error=permission.reason,
        )
        return ToolCallResult(
            success=False,
            result=permission.reason,
            permission=permission,
        )

    # 3. Confirm required.
    if permission.allowed == "confirm":
        # 3a. No confirmation supplied — ask the user.
        if pending_confirmation is None:
            _write_audit(
                audit_logger,
                session_id=session_id,
                tool=raw_tool,
                action=raw_action,
                permission=permission,
                args_keys=args_keys,
                success=False,
                error="Confirmation required.",
            )
            return ToolCallResult(
                success=False,
                result=(
                    # defence-in-depth truncation on [:63] slices
                    f"Action {raw_tool[:63]}.{raw_action[:63]} requires user confirmation."
                ),
                permission=permission,
            )

        # 3b. Confirmation supplied — enforce identity match.  The caller MUST
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
                raw_tool[:64],
                raw_action[:64],
            )
            mismatched = PermissionResult(
                allowed="deny",
                reason="Pending confirmation does not match tool call.",
            )
            _write_audit(
                audit_logger,
                session_id=session_id,
                tool=raw_tool,
                action=raw_action,
                permission=mismatched,
                args_keys=args_keys,
                success=False,
                error="Pending confirmation mismatch.",
            )
            return ToolCallResult(
                success=False,
                result="Pending confirmation does not match this tool call.",
                permission=mismatched,
            )

        # 3c. Confirmation supplied — enforce expiry.
        if datetime.now(UTC) >= pending_confirmation.expires_at:
            logger.warning(
                "Rejected expired pending_confirmation for %s.%s",
                raw_tool[:64],
                raw_action[:64],
            )
            expired = PermissionResult(
                allowed="deny",
                reason="Pending confirmation has expired.",
            )
            _write_audit(
                audit_logger,
                session_id=session_id,
                tool=raw_tool,
                action=raw_action,
                permission=expired,
                args_keys=args_keys,
                success=False,
                error="Pending confirmation expired.",
            )
            return ToolCallResult(
                success=False,
                result="Pending confirmation has expired.",
                permission=expired,
            )

    # 4. Look up tool in the registry.
    key = (raw_tool, raw_action)
    entry = _REGISTRY.get(key)
    if entry is None:
        logger.warning(
            "Rejected unknown tool %s.%s (not in registry)",
            raw_tool[:64],
            raw_action[:64],
        )
        _write_audit(
            audit_logger,
            session_id=session_id,
            tool=raw_tool,
            action=raw_action,
            permission=permission,
            args_keys=args_keys,
            success=False,
            error="Unknown tool.",
        )
        return ToolCallResult(
            success=False,
            # defence-in-depth truncation on [:63] slices
            result=f"Unknown tool: {raw_tool[:63]}.{raw_action[:63]}",
            permission=permission,
        )

    # 5a. Reject args containing fields not declared on the schema.  Pydantic's
    #     default ``extra='ignore'`` would silently discard them, giving the
    #     LLM a covert channel to smuggle data past argument validation.
    schema_fields = set(entry.args_schema.model_fields.keys())
    extra_keys = [k for k in tool_call.args if k not in schema_fields]
    if extra_keys:
        _write_audit(
            audit_logger,
            session_id=session_id,
            tool=raw_tool,
            action=raw_action,
            permission=permission,
            args_keys=args_keys,
            success=False,
            error="Unexpected argument fields.",
        )
        return ToolCallResult(
            success=False,
            result="Argument validation failed: unexpected fields are not permitted.",
            permission=permission,
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
        _write_audit(
            audit_logger,
            session_id=session_id,
            tool=raw_tool,
            action=raw_action,
            permission=permission,
            args_keys=args_keys,
            success=False,
            error="Argument validation failed.",
        )
        return ToolCallResult(
            success=False,
            result=f"Argument validation failed: {error_summary[:512]}",
            permission=permission,
        )

    # 6. Execute the async handler.
    try:
        result = await entry.handler(validated_args, session_id=session_id)
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
            raw_tool[:64],
            raw_action[:64],
            error_type,
        )
        _write_audit(
            audit_logger,
            session_id=session_id,
            tool=raw_tool,
            action=raw_action,
            permission=permission,
            args_keys=args_keys,
            success=False,
            error=f"Handler raised {error_type}",
        )
        return ToolCallResult(
            success=False,
            result=f"Tool execution failed: {error_type}",
            permission=permission,
        )

    # Guard against handlers that return a non-string type (e.g. None, dict).
    if not isinstance(result, str):
        logger.error(
            "Tool %s.%s returned non-string type %s",
            raw_tool[:64],
            raw_action[:64],
            type(result).__name__,
        )
        _write_audit(
            audit_logger,
            session_id=session_id,
            tool=raw_tool,
            action=raw_action,
            permission=permission,
            args_keys=args_keys,
            success=False,
            error="Handler returned non-string.",
        )
        return ToolCallResult(
            success=False,
            result="Tool execution failed: handler returned non-string result.",
            permission=permission,
        )

    # Sanitize handler output: strip control characters that could spoof
    # log viewers, confirmation dialogs, or downstream consumers.
    sanitized_result = result.translate(_CONTROL_CHAR_TABLE)

    # Truncate to prevent oversized results from blowing up downstream
    # consumers or exceeding the ToolCallResult.result field constraint.
    if len(sanitized_result) > _MAX_RESULT_LENGTH:
        sanitized_result = sanitized_result[:_MAX_RESULT_LENGTH]

    _write_audit(
        audit_logger,
        session_id=session_id,
        tool=raw_tool,
        action=raw_action,
        permission=permission,
        args_keys=args_keys,
        success=True,
        error=None,
    )
    return ToolCallResult(
        success=True,
        result=sanitized_result,
        permission=permission,
    )


# ---------------------------------------------------------------------------
# Tool listing
# ---------------------------------------------------------------------------


def get_registered_tools() -> list[ToolDescription]:
    """Return metadata for all registered tools.

    Used to build the ``tools`` array in the Ollama ``/api/chat`` request so
    the LLM knows which tools are available and their parameter schemas.

    Returns:
        A list of ``ToolDescription`` models sorted by (tool, action).
    """
    descriptions: list[ToolDescription] = []
    for (_tool, _action), entry in sorted(_REGISTRY.items()):
        schema = entry.args_schema.model_json_schema()
        descriptions.append(
            ToolDescription(
                tool=entry.tool,
                action=entry.action,
                description=entry.description,
                parameters_schema=schema,
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
