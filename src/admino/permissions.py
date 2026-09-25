"""Permission engine for admino — architecturally isolated.

Evaluates whether a (tool, action) pair is allowed, requires confirmation,
or is denied. The engine receives ONLY the tool name, action string, and
the immutable PermissionsConfig; it never sees LLM context, conversation
history, user messages, or tool arguments.

Security notes:
- This module must NEVER import from agent.py, llm.py, or server.py.
- Hardcoded denials cannot be overridden by configuration.
- Default-deny: any unlisted tool/action combination is denied.
- check_permission is a pure function: no logging, no network calls, no
  state mutation. (The module-level logger is used only by
  validate_permissions_config, not by check_permission itself.)
- Write-mutating actions cannot be configured as 'allow' — only 'confirm'
  or 'deny' are accepted. This prevents unconstrained writes via operator
  misconfiguration.
- validate_permissions_config logs warnings when the config attempts to
  override hardcoded denials.
- Input validation: tool and action identifiers must match [a-z][a-z0-9_]{0,62}.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from typing import Final, Literal

from pydantic import BaseModel, Field, model_validator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

_VALID_IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,62}$")

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

PermissionState = Literal["allow", "confirm", "deny"]

# ---------------------------------------------------------------------------
# Hardcoded denials — cannot be overridden by YAML config
# ---------------------------------------------------------------------------

# Tier-1: immutable denials — truly permanent, never promotable.
IMMUTABLE_DENIALS: frozenset[tuple[str, str]] = frozenset(
    {
        ("gmail", "delete"),
        ("google_calendar", "delete"),
        ("google_drive", "delete"),
        ("outlook", "delete"),
        ("outlook_calendar", "delete"),
        ("onedrive", "delete"),
        ("documents", "delete"),
        ("memory", "delete"),
    }
)

# Tier-2: promotable denials — can be promoted from ``deny`` to ``confirm``
# by the user via the Critical Permissions API, with re-authentication and
# a 5-minute cooldown. When promoted, the permission engine returns
# ``confirm`` (agent proposes, user approves) instead of ``deny``.
PROMOTABLE_DENIALS: frozenset[tuple[str, str]] = frozenset(
    {
        ("gmail", "send"),
        ("outlook", "send"),
        ("google_calendar", "update"),
        ("outlook_calendar", "update"),
    }
)

# Union of both tiers — backward-compatible alias used by config validation,
# the _CONFIRM_ONLY_ACTIONS invariant check, and the PATCH /api/permissions
# guard that blocks overriding any hardcoded denial via YAML/API.
HARDCODED_DENIALS: frozenset[tuple[str, str]] = IMMUTABLE_DENIALS | PROMOTABLE_DENIALS

# Write-mutating actions that must never be set to 'allow' via YAML config.
# These are downgraded to 'confirm' if an operator sets them to 'allow',
# ensuring human confirmation before any state-changing external action.
_CONFIRM_ONLY_ACTIONS: frozenset[tuple[str, str]] = frozenset(
    {
        # Google
        ("gmail", "send"),
        ("gmail", "delete"),
        ("google_calendar", "create"),
        ("google_calendar", "delete"),
        ("google_calendar", "update"),
        ("google_drive", "delete"),
        ("google_drive", "download"),
        # Microsoft
        ("outlook", "send"),
        ("outlook", "delete"),
        ("outlook_calendar", "create"),
        ("outlook_calendar", "delete"),
        ("outlook_calendar", "update"),
        ("onedrive", "delete"),
        ("onedrive", "download"),
        # Local (admino's own stores)
        ("documents", "delete"),
        ("memory", "delete"),
        ("memory", "write"),
    }
)

# Invariant: every hardcoded denial must also be a confirm-only action
# to prevent accidental promotion if removed from HARDCODED_DENIALS.
if not HARDCODED_DENIALS <= _CONFIRM_ONLY_ACTIONS:
    raise RuntimeError(
        "Every hardcoded denial must also be in _CONFIRM_ONLY_ACTIONS "
        "to prevent accidental promotion if removed from HARDCODED_DENIALS."
    )

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_log(s: str, max_len: int = 64) -> str:
    """Sanitize a string for safe log output."""
    return "".join(
        c if c.isprintable() and unicodedata.category(c) != "Cf" else f"\\u{ord(c):04x}"
        for c in s[:max_len]
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

    Security note: model_construct() bypasses all validators including
    action key validation. Production code must use the normal constructor.
    """

    actions: dict[str, PermissionState] = Field(
        default_factory=dict,
        description="Mapping of action name to permission state.",
    )

    @model_validator(mode="after")
    def validate_action_keys(self) -> ToolPermissions:
        """Ensure all action keys match the identifier pattern."""
        for key in self.actions:
            if not _VALID_IDENTIFIER.fullmatch(key):
                raise ValueError(f"Invalid action key: {key!r:.64}")
        return self


class PermissionsConfig(BaseModel):
    """Top-level permissions configuration.

    Built by ``validate_permissions_config`` from either the in-code
    ``DEFAULT_PERMISSIONS`` (initial DB seed) or the rows loaded from the
    database at runtime. Structure (tool -> action -> state)::

        tools:
          gmail:
            read: allow
            send: deny
          calendar:
            list: allow
            ...

    Security note: model_construct() bypasses all validators including
    tool key validation. Production code must use the normal constructor.
    """

    tools: dict[str, ToolPermissions] = Field(
        default_factory=dict,
        description="Mapping of tool name to its action permissions.",
    )

    @model_validator(mode="after")
    def validate_tool_keys(self) -> PermissionsConfig:
        """Ensure all tool name keys match the identifier pattern."""
        for key in self.tools:
            if not _VALID_IDENTIFIER.fullmatch(key):
                raise ValueError(f"Invalid tool key: {key!r:.64}")
        return self


# ---------------------------------------------------------------------------
# Config construction helpers
# ---------------------------------------------------------------------------


def validate_permissions_config(raw: dict[str, dict[str, str]]) -> PermissionsConfig:
    """Build a PermissionsConfig from a raw tool -> {action: state} mapping.

    The input comes from either ``DEFAULT_PERMISSIONS`` (initial DB seed) or the
    rows loaded from the database at runtime. Logs warnings if the config tries
    to override a hardcoded denial, but the hardcoded values are NOT stored —
    check_permission enforces them at call time regardless.

    Args:
        raw: Mapping of tool name -> {action: state}.

    Returns:
        A validated PermissionsConfig instance.
    """
    tools: dict[str, ToolPermissions] = {}
    for tool_name, actions in raw.items():
        if not _VALID_IDENTIFIER.fullmatch(tool_name):
            msg = f"Invalid tool name in permissions config: {_safe_log(repr(tool_name))}"
            raise ValueError(msg)
        cleaned_actions: dict[str, PermissionState] = {}
        for action_name, state in actions.items():
            if not _VALID_IDENTIFIER.fullmatch(action_name):
                msg = f"Invalid action name in permissions config: {_safe_log(repr(action_name))}"
                raise ValueError(msg)
            if (tool_name, action_name) in HARDCODED_DENIALS:
                if state != "deny":
                    logger.warning(
                        "permission config sets %s.%s to '%s', "
                        "but this is a hardcoded denial — enforcing 'deny'.",
                        _safe_log(tool_name),
                        _safe_log(action_name),
                        _safe_log(state),
                    )
                # Always store 'deny' for hardcoded denials so the config
                # never contains misleading values.
                cleaned_actions[action_name] = "deny"
            else:
                if state not in ("allow", "confirm", "deny"):
                    msg = (
                        f"Invalid permission state {_safe_log(repr(state))} for "
                        f"{_safe_log(tool_name)}.{_safe_log(action_name)}. "
                        "Must be 'allow', 'confirm', or 'deny'."
                    )
                    raise ValueError(msg)
                # Downgrade 'allow' to 'confirm' for write-mutating actions
                if state == "allow" and (tool_name, action_name) in _CONFIRM_ONLY_ACTIONS:
                    logger.warning(
                        "permission config sets %s.%s to 'allow', but this is a "
                        "write-mutating action — downgrading to 'confirm'.",
                        _safe_log(tool_name),
                        _safe_log(action_name),
                    )
                    cleaned_actions[action_name] = "confirm"
                else:
                    # state is valid ("allow"/"confirm"/"deny") per the guard above
                    cleaned_actions[action_name] = state  # type: ignore[assignment]
        if not cleaned_actions:
            logger.warning(
                "permission config tool %s has no actions configured.",
                _safe_log(tool_name),
            )
        tools[tool_name] = ToolPermissions(actions=cleaned_actions)
    return PermissionsConfig(tools=tools)


# ---------------------------------------------------------------------------
# Default permission ruleset (seed source)
# ---------------------------------------------------------------------------

# The default tool/action rules seeded into an empty ``permissions`` table on
# first run. This constant is the single version-controlled source of truth —
# it replaces the retired ``config/permissions.yaml`` seed file (GH-85). Nothing
# here is needed before the database exists, so it lives in code rather than in
# a shipped YAML file; the database is authoritative once seeded.
#
# Every listed action is one of allow / confirm / deny. Unlisted tool/action
# combinations default to deny (see ``check_permission``). Hardcoded denials are
# enforced by ``check_permission`` regardless of what appears here; this ruleset
# still passes through ``validate_permissions_config`` when built, so the same
# hardcoded-denial and write-mutating-action guarantees apply as with the YAML.
#
# The google_drive / onedrive ``download`` rows stay at ``confirm`` although no
# handler is registered for them (GH-143): #192 restores download as chat
# attachments, and until then dispatch rejects the calls as unknown tools.
DEFAULT_PERMISSIONS: Final[dict[str, dict[str, str]]] = {
    # --- Google ---
    "gmail": {
        "read": "allow",
        "list": "allow",
        "search": "allow",
        "send": "deny",
        "delete": "deny",
    },
    "google_calendar": {
        "read": "allow",
        "list": "allow",
        "create": "confirm",
        "update": "deny",
        "delete": "deny",
    },
    "google_drive": {
        "read": "allow",
        "list": "allow",
        "search": "allow",
        "download": "confirm",
        "delete": "deny",
    },
    # --- Microsoft ---
    "outlook": {
        "read": "allow",
        "list": "allow",
        "search": "allow",
        "send": "deny",
        "delete": "deny",
    },
    "outlook_calendar": {
        "read": "allow",
        "list": "allow",
        "create": "confirm",
        "update": "deny",
        "delete": "deny",
    },
    "onedrive": {
        "read": "allow",
        "list": "allow",
        "search": "allow",
        "download": "confirm",
        "delete": "deny",
    },
    # --- Other ---
    "memory": {"store": "allow", "recall": "allow", "list": "allow", "delete": "deny"},
}


def build_default_permissions_config() -> PermissionsConfig:
    """Build the seed ``PermissionsConfig`` from ``DEFAULT_PERMISSIONS``.

    Used at startup to seed an empty ``permissions`` table. The defaults are run
    through ``validate_permissions_config`` so the identical hardcoded-denial and
    write-mutating-action normalisation applies as when they were loaded from
    ``permissions.yaml``.

    Returns:
        A validated PermissionsConfig holding the default ruleset.
    """
    return validate_permissions_config(DEFAULT_PERMISSIONS)


# ---------------------------------------------------------------------------
# Pure permission check
# ---------------------------------------------------------------------------


def check_permission(
    tool: str,
    action: str,
    config: PermissionsConfig,
    *,
    promoted: frozenset[tuple[str, str]] = frozenset(),
) -> PermissionResult:
    """Determine whether a tool action is allowed, requires confirmation, or is denied.

    Decision rules (evaluated in order):
    0. Input validation — reject malformed identifiers.
    1. Hardcoded denials:
       a. Immutable denials — always deny, cannot be overridden.
       b. Promotable denials — deny by default, but return ``confirm`` if the
          (tool, action) pair appears in the ``promoted`` set.
    2. Config lookup — return the configured state if found.
    3. Default deny — unlisted tool/action combinations are denied.

    This is a **pure function**: no side effects, no logging, no network calls,
    no state mutation. It receives (tool, action, config, promoted) and returns
    a result.

    Args:
        tool: The tool name (e.g. "gmail", "calendar").
        action: The action name (e.g. "read", "send", "delete").
        config: The validated permissions configuration.
        promoted: Set of (tool, action) pairs that have been promoted from
            tier-2 deny to confirm via the Critical Permissions API.

    Returns:
        A PermissionResult with the decision and a human-readable reason.
    """
    # 0. Input validation
    if not _VALID_IDENTIFIER.fullmatch(tool) or not _VALID_IDENTIFIER.fullmatch(action):
        return PermissionResult(
            allowed="deny",
            reason="Invalid tool or action identifier.",
        )

    # 1a. Immutable denials — checked first, cannot be overridden
    if (tool, action) in IMMUTABLE_DENIALS:
        return PermissionResult(
            allowed="deny",
            reason=f"Action {tool[:64]}.{action[:64]} is permanently denied (hardcoded).",
        )

    # 1b. Promotable denials — deny unless promoted to confirm
    if (tool, action) in PROMOTABLE_DENIALS:
        if (tool, action) in promoted:
            return PermissionResult(
                allowed="confirm",
                reason=f"Action {tool[:64]}.{action[:64]} promoted from deny to confirm.",
            )
        return PermissionResult(
            allowed="deny",
            reason=f"Action {tool[:64]}.{action[:64]} is permanently denied (hardcoded).",
        )

    # 2. Config lookup
    tool_perms = config.tools.get(tool)
    if tool_perms is None:
        return PermissionResult(
            allowed="deny",
            reason=f"Tool '{tool[:64]}' is not listed in permission config (default deny).",
        )

    state = tool_perms.actions.get(action)
    if state is None:
        return PermissionResult(
            allowed="deny",
            reason=(
                f"Action {tool[:64]}.{action[:64]} is not listed in "
                "permission config (default deny)."
            ),
        )

    # 3. Return configured state
    return PermissionResult(
        allowed=state,
        reason=f"Action {tool[:64]}.{action[:64]} is configured as '{state}'.",
    )
