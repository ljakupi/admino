"""Permission engine for admino — pure function, architecturally isolated.

Evaluates whether a (tool, action) pair is allowed, requires confirmation,
or is denied. The engine receives ONLY the tool name and action string;
it never sees LLM context, conversation history, user messages, or tool arguments.

Security notes:
- This module must NEVER import from agent.py, llm.py, or server.py.
- Hardcoded denials cannot be overridden by YAML configuration.
- Default-deny: any unlisted tool/action combination is denied.
- check_permission is a pure function: no logging, no network calls, no state mutation.
- validate_permissions_config logs warnings when YAML attempts to override hardcoded denials.
"""

from __future__ import annotations

import logging
from typing import Literal, cast

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

PermissionState = Literal["allow", "confirm", "deny"]

# ---------------------------------------------------------------------------
# Hardcoded denials — cannot be overridden by YAML config
# ---------------------------------------------------------------------------

HARDCODED_DENIALS: frozenset[tuple[str, str]] = frozenset(
    {
        ("gmail", "send"),
        ("gmail", "delete"),
        ("calendar", "delete"),
        ("calendar", "update"),
        ("documents", "delete"),
        ("files", "delete"),
        ("memory", "delete"),
    }
)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class PermissionResult(BaseModel):
    """Result of a permission check."""

    allowed: PermissionState = Field(
        description="The permission decision: allow, confirm, or deny."
    )
    reason: str = Field(
        max_length=500,
        description="Human-readable explanation for the decision.",
    )


class ToolPermissions(BaseModel):
    """Permission map for a single tool's actions.

    Keys are action names, values are permission states.
    Unlisted actions default to deny.
    """

    actions: dict[str, PermissionState] = Field(
        default_factory=dict,
        description="Mapping of action name to permission state.",
    )


class PermissionsConfig(BaseModel):
    """Top-level permissions configuration, validated from permissions.yaml.

    Structure:
        tools:
          gmail:
            read: allow
            send: deny
          calendar:
            list: allow
            ...
    """

    tools: dict[str, ToolPermissions] = Field(
        default_factory=dict,
        description="Mapping of tool name to its action permissions.",
    )


# ---------------------------------------------------------------------------
# Config construction helpers
# ---------------------------------------------------------------------------


def validate_permissions_config(raw: dict[str, dict[str, str]]) -> PermissionsConfig:
    """Build a PermissionsConfig from a raw dict (e.g. parsed YAML 'tools' block).

    Logs warnings if YAML attempts to override hardcoded denials, but the
    hardcoded values are NOT stored — check_permission enforces them at
    call time regardless.

    Args:
        raw: Mapping of tool name -> {action: state} from the YAML file.

    Returns:
        A validated PermissionsConfig instance.
    """
    tools: dict[str, ToolPermissions] = {}
    for tool_name, actions in raw.items():
        cleaned_actions: dict[str, PermissionState] = {}
        for action_name, state in actions.items():
            if (tool_name, action_name) in HARDCODED_DENIALS:
                if state != "deny":
                    logger.warning(
                        "permissions.yaml sets %s.%s to '%s', "
                        "but this is a hardcoded denial — enforcing 'deny'.",
                        tool_name,
                        action_name,
                        state,
                    )
                # Always store 'deny' for hardcoded denials so the config
                # never contains misleading values.
                cleaned_actions[action_name] = "deny"
            else:
                if state not in ("allow", "confirm", "deny"):
                    msg = (
                        f"Invalid permission state '{state}' for {tool_name}.{action_name}. "
                        "Must be 'allow', 'confirm', or 'deny'."
                    )
                    raise ValueError(msg)
                cleaned_actions[action_name] = cast("PermissionState", state)
        tools[tool_name] = ToolPermissions(actions=cleaned_actions)
    return PermissionsConfig(tools=tools)


# ---------------------------------------------------------------------------
# Pure permission check
# ---------------------------------------------------------------------------


def check_permission(
    tool: str,
    action: str,
    config: PermissionsConfig,
) -> PermissionResult:
    """Determine whether a tool action is allowed, requires confirmation, or is denied.

    Decision rules (evaluated in order):
    1. Hardcoded denials — always deny, config cannot override.
    2. Config lookup — return the configured state if found.
    3. Default deny — unlisted tool/action combinations are denied.

    This is a **pure function**: no side effects, no logging, no network calls,
    no state mutation. It receives only (tool, action, config) and returns a result.

    Args:
        tool: The tool name (e.g. "gmail", "calendar").
        action: The action name (e.g. "read", "send", "delete").
        config: The validated permissions configuration.

    Returns:
        A PermissionResult with the decision and a human-readable reason.
    """
    # 1. Hardcoded denials — checked first, cannot be overridden
    if (tool, action) in HARDCODED_DENIALS:
        return PermissionResult(
            allowed="deny",
            reason=f"Action {tool}.{action} is permanently denied (hardcoded).",
        )

    # 2. Config lookup
    tool_perms = config.tools.get(tool)
    if tool_perms is None:
        return PermissionResult(
            allowed="deny",
            reason=f"Tool '{tool}' is not listed in permission config (default deny).",
        )

    state = tool_perms.actions.get(action)
    if state is None:
        return PermissionResult(
            allowed="deny",
            reason=f"Action {tool}.{action} is not listed in permission config (default deny).",
        )

    # 3. Return configured state
    return PermissionResult(
        allowed=state,
        reason=f"Action {tool}.{action} is configured as '{state}'.",
    )
