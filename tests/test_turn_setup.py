"""Tests for admino.turn_setup: the send path's one-statement turn setup (GH-244, contract C3 T1).

``turn_setup.load_turn_setup(executor, tenant, chat_id)`` replaces the send
path's separate reads of the org's permission rows, tool switches, residency
flag, the caller's prompt inputs and the chat's owner check with ONE
statement, so ``POST /api/chats/{chat_id}/messages`` makes at most 3 database
queries before the LLM call (session, turn setup, the chat with its history).
It runs against tests/db_fakes.py, which evaluates the contract's T1
statement as PostgreSQL does (LEFT JOINs, the correlated ``ARRAY(SELECT
ARRAY[...])``, no row for an unknown org).

What these tests pin down (contract C3 T1, issue "Decisions (pipeline)" 3):
- Surface: ``TurnSetup`` is a frozen dataclass of exactly ``policy``,
  ``prompt_context`` and ``chat_found``.
- One statement: a fetch/fetchrow SELECT naming organizations, org_settings,
  users, chats and permissions, bound to ``(tenant.org_id, tenant.user_id,
  chat_id)`` in that order, in every state (the fail-closed one included); it
  writes nothing and opens no transaction.
- Equivalence (the spec): for every database state, ``policy`` equals
  ``org_permissions.load_tool_policy`` and ``prompt_context`` equals
  ``scoped_settings.load_prompt_context`` on the same database, and each state
  also holds its literal expectation (so a shared helper broken in both paths
  can't pass): the default org; no org_settings row (every service on); tool
  switches off; residency on (every ``RESIDENCY_BLOCKED_TOOLS`` tool off,
  ``data_residency`` True), with and without a settings row; a promoted tier-2
  pair (in ``promoted``, the config keeps the hardcoded 'deny'; a tier-1 pair
  stored 'confirm' is never promoted); an empty matrix; org and personal
  instructions, response languages and timezone set, and the user's unset; a
  deleted user and a user of another org (``PromptContext()``, the tenant
  org's policy, never the user's org's).
- Fail closed: a tenant org without a row reads residency on, the blocked
  tools off, an empty matrix, ``PromptContext()`` and ``chat_found`` False.
- Tenant isolation (§5): ``chat_found`` is True only for the caller's own live
  chat; a colleague's, another org's (with the caller's tenant, with a forged
  tenant org, and a foreign user's own chat under the caller's org), a trashed
  and an unknown chat read False, exactly as ``chats.get_chat`` refuses them.
  The chat argument never changes ``policy`` or ``prompt_context``. Org B (the
  other org) differs from org A in residency, switches, instructions, language
  and matrix, so any cross-org read shows.
- No content in logs: the instructions, title and message canaries reach no
  log record.

``admino.turn_setup`` is imported in a fixture, so this file collects before
the module exists and every test fails on its own.
"""

from __future__ import annotations

import dataclasses
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import chats, org_permissions, scoped_settings
from admino.models import RESIDENCY_BLOCKED_TOOLS, PromptContext, ToolPolicy, ToolsSettings
from admino.permissions import build_default_permissions_config, validate_permissions_config
from admino.tenancy import TenantContext
from tests.db_fakes import FakeDb
from tests.log_capture import configured_logging
from tests.tenancy_world import World, build_world, seed_chat

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

    from tests.db_fakes import Call

ORG_CANARY: Final = "ORG-CANARY-7f3a always quote the Q3 figures"
PERSONAL_CANARY: Final = "PERSONAL-CANARY-91bc address me as Dr. Muster"
COLLEAGUE_CANARY: Final = "COLLEAGUE-CANARY-2d4e answer in haiku"
FOREIGN_CANARY: Final = "FOREIGN-CANARY-5c8a org B secrets"
OTHER_ORG_CANARY: Final = "OTHER-ORG-CANARY-0e1f org B instructions"
TITLE_CANARY: Final = "TITLE-CANARY-66aa merger plans"
MESSAGE_CANARY: Final = "MESSAGE-CANARY-3b9d the acquisition target is ACME"
CANARIES: Final = (
    ORG_CANARY,
    PERSONAL_CANARY,
    COLLEAGUE_CANARY,
    FOREIGN_CANARY,
    OTHER_ORG_CANARY,
    TITLE_CANARY,
    MESSAGE_CANARY,
)
TABLES: Final = ("organizations", "org_settings", "users", "chats", "permissions")
ALL_ON: Final[dict[str, bool]] = ToolsSettings().model_dump()
UNKNOWN_CHAT: Final = uuid.UUID("0b5e4c1d-8a7f-4e2b-9c3d-1f0a2b3c4d5e")


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def turn_setup() -> ModuleType:
    """admino.turn_setup, imported per test so each test fails on its own until it exists."""
    from admino import turn_setup as module

    return module


@dataclass(frozen=True)
class _Chats:
    """The chats every test may ask for (ids)."""

    own: uuid.UUID  # org A editor's live chat
    colleague: uuid.UUID  # org A viewer's live chat
    other_org: uuid.UUID  # org B editor's live chat
    trashed: uuid.UUID  # org A editor's trashed chat


@pytest.fixture()
def world() -> World:
    """Orgs A and B (tenancy_world), org B different from A in every policy input.

    Org B: residency on, gmail off, its own instructions, Italian default
    language and google_calendar.read stored 'confirm'; org A keeps the
    defaults (residency off, every service on, the default matrix, English).
    """
    db = FakeDb()
    built = build_world(db)
    db.add_org(built.org_b, data_residency=True, default_response_language="it")
    _replace_org_settings(db, built.org_b, instructions=OTHER_ORG_CANARY, gmail=False)
    db.add_permissions(built.org_b, {"google_calendar": {"read": "confirm"}})
    db.users[built.b["editor"].user_id]["personal_instructions"] = FOREIGN_CANARY
    db.users[built.b["editor"].user_id]["response_language"] = "it"
    db.users[built.a["viewer"].user_id]["personal_instructions"] = COLLEAGUE_CANARY
    db.users[built.a["viewer"].user_id]["response_language"] = "de"
    db.users[built.a["viewer"].user_id]["timezone"] = "America/New_York"
    return built


@pytest.fixture()
def seeded(world: World) -> _Chats:
    """One live chat of the org A editor, its colleague and the org B editor, plus a
    trashed chat of the org A editor."""
    db = world.db
    own = seed_chat(db, world.a["editor"], title=TITLE_CANARY, messages=[("user", MESSAGE_CANARY)])
    colleague = seed_chat(db, world.a["viewer"], title=TITLE_CANARY)
    other_org = seed_chat(db, world.b["editor"], title=TITLE_CANARY)
    trashed = db.add_chat(
        world.a["editor"].user_id, title=TITLE_CANARY, deleted_at=datetime.now(UTC)
    )
    return _Chats(own=own, colleague=colleague, other_org=other_org, trashed=trashed)


def _tenant(org_id: uuid.UUID, user_id: uuid.UUID) -> TenantContext:
    return TenantContext(org_id=org_id, user_id=user_id, role="editor")


def _editor(world: World) -> TenantContext:
    """The org A editor's own tenant."""
    return _tenant(world.org_a, world.a["editor"].user_id)


def _same_uuid(left: object, right: uuid.UUID) -> bool:
    """A bind argument equal to a UUID (a plain or an asyncpg UUID)."""
    return isinstance(left, uuid.UUID) and uuid.UUID(int=left.int) == right


async def _load(
    turn_setup: ModuleType, db: FakeDb, tenant: TenantContext, chat_id: uuid.UUID
) -> tuple[Any, list[Call]]:
    """Run load_turn_setup on the pool; return its result and the statements it ran."""
    before = len(db.calls)
    setup = await turn_setup.load_turn_setup(db.pool, tenant, chat_id)
    return setup, db.calls[before:]


async def _oracle(db: FakeDb, tenant: TenantContext) -> tuple[ToolPolicy, PromptContext]:
    """What the old loaders (unchanged) read for the tenant on the same database."""
    policy = await org_permissions.load_tool_policy(db.pool, tenant)
    prompt = await scoped_settings.load_prompt_context(db.pool, tenant)
    return policy, prompt


async def _found_by_get_chat(db: FakeDb, tenant: TenantContext, chat_id: uuid.UUID) -> bool:
    """Whether chats.get_chat returns the chat for the tenant (the chat_found oracle)."""
    try:
        await chats.get_chat(db.pool, tenant, chat_id)
    except chats.ChatNotFoundError:
        return False
    return True


def _drop_org_settings(db: FakeDb, org_id: uuid.UUID) -> None:
    db.org_settings = {
        key: row for key, row in db.org_settings.items() if uuid.UUID(str(key)) != org_id
    }


def _replace_org_settings(db: FakeDb, org_id: uuid.UUID, **columns: Any) -> None:
    """Store a new org_settings row for the org (every tool not given enabled)."""
    _drop_org_settings(db, org_id)
    db.add_org_settings(org_id, **columns)


def _drop_permissions(db: FakeDb, org_id: uuid.UUID) -> None:
    db.permissions = {
        key: row for key, row in db.permissions.items() if uuid.UUID(str(key[0])) != org_id
    }


def _blocked_off(stored: dict[str, bool]) -> dict[str, bool]:
    """The stored switches with every residency-blocked tool off."""
    return {tool: on and tool not in RESIDENCY_BLOCKED_TOOLS for tool, on in stored.items()}


# ---------------------------------------------------------------------------
# The equivalence states: each builds a database state and names the caller,
# and states what the result must literally be (besides the old loaders' value).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _State:
    build: Callable[[World, _Chats], tuple[TenantContext, uuid.UUID]]
    holds: Callable[[ToolPolicy, PromptContext], bool]


def _default(world: World, chats_: _Chats) -> tuple[TenantContext, uuid.UUID]:
    return _editor(world), chats_.own


def _no_org_settings_row(world: World, chats_: _Chats) -> tuple[TenantContext, uuid.UUID]:
    _drop_org_settings(world.db, world.org_a)
    world.db.users[world.a["editor"].user_id]["personal_instructions"] = PERSONAL_CANARY
    return _editor(world), chats_.own


def _switches_off(world: World, chats_: _Chats) -> tuple[TenantContext, uuid.UUID]:
    _replace_org_settings(world.db, world.org_a, gmail=False, outlook_calendar=False, memory=False)
    return _editor(world), chats_.own


def _residency_on(world: World, chats_: _Chats) -> tuple[TenantContext, uuid.UUID]:
    world.db.add_org(world.org_a, data_residency=True)
    _replace_org_settings(world.db, world.org_a, google_drive=False)
    return _editor(world), chats_.own


def _residency_on_no_settings_row(world: World, chats_: _Chats) -> tuple[TenantContext, uuid.UUID]:
    world.db.add_org(world.org_a, data_residency=True)
    _drop_org_settings(world.db, world.org_a)
    return _editor(world), chats_.own


def _promoted_pair(world: World, chats_: _Chats) -> tuple[TenantContext, uuid.UUID]:
    world.db.add_permissions(
        world.org_a,
        {
            "gmail": {"send": "confirm", "delete": "confirm"},
            "outlook_calendar": {"update": "confirm"},
            "outlook": {"send": "allow"},
        },
    )
    return _editor(world), chats_.own


def _empty_matrix(world: World, chats_: _Chats) -> tuple[TenantContext, uuid.UUID]:
    _drop_permissions(world.db, world.org_a)
    return _editor(world), chats_.own


def _prompt_inputs_set(world: World, chats_: _Chats) -> tuple[TenantContext, uuid.UUID]:
    db = world.db
    db.add_org(world.org_a, default_response_language="de")
    _replace_org_settings(db, world.org_a, instructions=ORG_CANARY)
    user = db.users[world.a["editor"].user_id]
    user.update(
        response_language="fr", timezone="Europe/Zurich", personal_instructions=PERSONAL_CANARY
    )
    return _editor(world), chats_.own


def _prompt_user_inputs_unset(world: World, chats_: _Chats) -> tuple[TenantContext, uuid.UUID]:
    world.db.add_org(world.org_a, default_response_language="de")
    _replace_org_settings(world.db, world.org_a, instructions=ORG_CANARY)
    return _editor(world), chats_.own


def _deleted_user(world: World, chats_: _Chats) -> tuple[TenantContext, uuid.UUID]:
    gone = world.db.add_account(
        org_id=world.org_a,
        role="editor",
        email="gone-editor@example.ch",
        deleted_at=datetime.now(UTC),
        response_language="fr",
        timezone="Europe/Zurich",
        personal_instructions=PERSONAL_CANARY,
    )
    return _tenant(world.org_a, gone), chats_.own


def _user_of_other_org(world: World, chats_: _Chats) -> tuple[TenantContext, uuid.UUID]:
    return _tenant(world.org_a, world.b["editor"].user_id), chats_.other_org


def _unknown_org(world: World, chats_: _Chats) -> tuple[TenantContext, uuid.UUID]:
    return _tenant(uuid.uuid4(), world.a["editor"].user_id), chats_.own


_DEFAULT_PROMPT: Final = PromptContext(default_response_language="en")
_FAIL_CLOSED_POLICY: Final = ToolPolicy(
    permissions=validate_permissions_config({}),
    promoted=frozenset(),
    enabled_tools=_blocked_off(ALL_ON),
    data_residency=True,
)


def _is_org_a_default_policy(policy: ToolPolicy) -> bool:
    return (
        policy.permissions == build_default_permissions_config()
        and policy.promoted == frozenset()
        and policy.enabled_tools == ALL_ON
        and policy.data_residency is False
    )


def _promoted_holds(policy: ToolPolicy, prompt: PromptContext) -> bool:
    gmail = policy.permissions.tools["gmail"].actions
    return (
        policy.promoted == frozenset({("gmail", "send"), ("outlook_calendar", "update")})
        and gmail["send"] == "deny"
        and gmail["delete"] == "deny"
        and policy.permissions.tools["outlook_calendar"].actions["update"] == "deny"
        and policy.permissions.tools["outlook"].actions["send"] == "deny"
        and prompt == _DEFAULT_PROMPT
    )


_STATES: Final[dict[str, _State]] = {
    "default-org": _State(
        _default,
        lambda policy, prompt: _is_org_a_default_policy(policy) and prompt == _DEFAULT_PROMPT,
    ),
    "no-org-settings-row": _State(
        _no_org_settings_row,
        lambda policy, prompt: (
            _is_org_a_default_policy(policy)
            and prompt
            == PromptContext(personal_instructions=PERSONAL_CANARY, default_response_language="en")
        ),
    ),
    "tool-switches-off": _State(
        _switches_off,
        lambda policy, _: (
            policy.enabled_tools
            == {**ALL_ON, "gmail": False, "outlook_calendar": False, "memory": False}
            and policy.data_residency is False
        ),
    ),
    "residency-on": _State(
        _residency_on,
        lambda policy, _: (
            policy.data_residency is True
            and policy.enabled_tools == _blocked_off(ALL_ON)
            and policy.enabled_tools["memory"] is True
            and policy.permissions == build_default_permissions_config()
        ),
    ),
    "residency-on-no-settings-row": _State(
        _residency_on_no_settings_row,
        lambda policy, _: (
            policy.data_residency is True and policy.enabled_tools == _blocked_off(ALL_ON)
        ),
    ),
    "promoted-tier2-pair": _State(_promoted_pair, _promoted_holds),
    "empty-matrix": _State(
        _empty_matrix,
        lambda policy, _: (
            policy.permissions.tools == {}
            and policy.promoted == frozenset()
            and policy.enabled_tools == ALL_ON
        ),
    ),
    "prompt-inputs-set": _State(
        _prompt_inputs_set,
        lambda _, prompt: (
            prompt
            == PromptContext(
                org_instructions=ORG_CANARY,
                personal_instructions=PERSONAL_CANARY,
                response_language="fr",
                default_response_language="de",
                timezone="Europe/Zurich",
            )
        ),
    ),
    "prompt-user-inputs-unset": _State(
        _prompt_user_inputs_unset,
        lambda _, prompt: (
            prompt == PromptContext(org_instructions=ORG_CANARY, default_response_language="de")
        ),
    ),
    "deleted-user": _State(
        _deleted_user,
        lambda policy, prompt: _is_org_a_default_policy(policy) and prompt == PromptContext(),
    ),
    "user-of-another-org": _State(
        _user_of_other_org,
        lambda policy, prompt: _is_org_a_default_policy(policy) and prompt == PromptContext(),
    ),
    "unknown-org": _State(
        _unknown_org,
        lambda policy, prompt: policy == _FAIL_CLOSED_POLICY and prompt == PromptContext(),
    ),
}


# ---------------------------------------------------------------------------
# 1. Surface
# ---------------------------------------------------------------------------


def test_turn_setup_result_is_a_frozen_dataclass_of_policy_prompt_and_chat_found(
    turn_setup: ModuleType,
) -> None:
    cls = turn_setup.TurnSetup

    assert dataclasses.is_dataclass(cls)
    assert {field.name for field in dataclasses.fields(cls)} == {
        "policy",
        "prompt_context",
        "chat_found",
    }
    assert cls.__dataclass_params__.frozen is True


async def test_turn_setup_load_returns_a_turn_setup(
    turn_setup: ModuleType, world: World, seeded: _Chats
) -> None:
    setup, _ = await _load(turn_setup, world.db, _editor(world), seeded.own)

    assert isinstance(setup, turn_setup.TurnSetup)
    assert isinstance(setup.policy, ToolPolicy)
    assert isinstance(setup.prompt_context, PromptContext)


# ---------------------------------------------------------------------------
# 2. One statement, bound to the tenant and the chat, no writes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "state", ["default-org", "unknown-org", "deleted-user", "user-of-another-org"]
)
async def test_turn_setup_load_runs_exactly_one_select_over_the_five_tables(
    turn_setup: ModuleType, world: World, seeded: _Chats, state: str
) -> None:
    """One statement in every state (the fail-closed one included): no follow-up reads."""
    tenant, chat_id = _STATES[state].build(world, seeded)

    _, calls = await _load(turn_setup, world.db, tenant, chat_id)

    assert len(calls) == 1, [call.normalized for call in calls]
    call = calls[0]
    assert call.method in {"fetch", "fetchrow"}
    assert call.normalized.startswith("select ")
    missing = [table for table in TABLES if not re.search(rf"\b{table}\b", call.normalized)]
    assert missing == []


@pytest.mark.parametrize("state", ["default-org", "unknown-org", "user-of-another-org"])
async def test_turn_setup_load_binds_org_user_and_chat_in_that_order(
    turn_setup: ModuleType, world: World, seeded: _Chats, state: str
) -> None:
    tenant, chat_id = _STATES[state].build(world, seeded)

    _, calls = await _load(turn_setup, world.db, tenant, chat_id)

    assert len(calls) == 1
    args = calls[0].args
    assert len(args) == 3, args
    assert _same_uuid(args[0], tenant.org_id)
    assert _same_uuid(args[1], tenant.user_id)
    assert _same_uuid(args[2], chat_id)


async def test_turn_setup_load_writes_nothing(
    turn_setup: ModuleType, world: World, seeded: _Chats
) -> None:
    db = world.db
    _prompt_inputs_set(world, seeded)
    before = db.snapshot()
    transactions = list(db.transactions)

    _, calls = await _load(turn_setup, db, _editor(world), seeded.own)

    assert calls != []
    assert all(call.normalized.startswith("select ") for call in calls)
    assert db.snapshot() == before
    assert db.transactions == transactions
    assert db.open_transactions == 0


# ---------------------------------------------------------------------------
# 3. Equivalence with the old loaders, state by state
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", list(_STATES))
async def test_turn_setup_policy_and_prompt_equal_the_old_loaders(
    turn_setup: ModuleType, world: World, seeded: _Chats, state: str
) -> None:
    tenant, chat_id = _STATES[state].build(world, seeded)

    setup, _ = await _load(turn_setup, world.db, tenant, chat_id)

    assert (setup.policy, setup.prompt_context) == await _oracle(world.db, tenant)
    assert _STATES[state].holds(setup.policy, setup.prompt_context), (
        setup.policy,
        setup.prompt_context,
    )


async def test_turn_setup_unknown_org_fails_closed(
    turn_setup: ModuleType, world: World, seeded: _Chats
) -> None:
    """No organizations row: residency on, the Google and Microsoft tools off, an empty
    matrix (default-deny), no prompt inputs and no chat."""
    tenant = _tenant(uuid.uuid4(), world.a["editor"].user_id)

    setup, _ = await _load(turn_setup, world.db, tenant, seeded.own)

    assert setup.policy == _FAIL_CLOSED_POLICY
    assert setup.policy.data_residency is True
    assert all(setup.policy.enabled_tools[tool] is False for tool in RESIDENCY_BLOCKED_TOOLS)
    assert setup.prompt_context == PromptContext()
    assert setup.chat_found is False


# ---------------------------------------------------------------------------
# 4. chat_found: the caller's own live chat only
# ---------------------------------------------------------------------------


def _chat_case(world: World, chats_: _Chats, case: str) -> tuple[TenantContext, uuid.UUID]:
    editor = world.a["editor"].user_id
    foreign = world.b["editor"].user_id
    return {
        "own-live-chat": (_editor(world), chats_.own),
        "colleague-chat": (_editor(world), chats_.colleague),
        "other-org-chat": (_editor(world), chats_.other_org),
        "trashed-own-chat": (_editor(world), chats_.trashed),
        "unknown-chat": (_editor(world), UNKNOWN_CHAT),
        "forged-org-own-chat": (_tenant(world.org_b, editor), chats_.own),
        "forged-org-other-org-chat": (_tenant(world.org_b, editor), chats_.other_org),
        "foreign-user-own-chat": (_tenant(world.org_a, foreign), chats_.other_org),
    }[case]


_CHAT_CASES: Final[dict[str, bool]] = {
    "own-live-chat": True,
    "colleague-chat": False,
    "other-org-chat": False,
    "trashed-own-chat": False,
    "unknown-chat": False,
    "forged-org-own-chat": False,
    "forged-org-other-org-chat": False,
    "foreign-user-own-chat": False,
}


@pytest.mark.parametrize(("case", "expected"), list(_CHAT_CASES.items()))
async def test_turn_setup_chat_found_only_for_the_callers_own_live_chat(
    turn_setup: ModuleType, world: World, seeded: _Chats, case: str, expected: bool
) -> None:
    tenant, chat_id = _chat_case(world, seeded, case)

    setup, _ = await _load(turn_setup, world.db, tenant, chat_id)

    assert setup.chat_found is expected
    assert await _found_by_get_chat(world.db, tenant, chat_id) is expected


@pytest.mark.parametrize("case", list(_CHAT_CASES))
async def test_turn_setup_chat_argument_doesnt_change_policy_or_prompt(
    turn_setup: ModuleType, world: World, seeded: _Chats, case: str
) -> None:
    """Whatever chat is named (found or not), the policy and prompt context are the
    tenant's own, as the old loaders read them."""
    _prompt_inputs_set(world, seeded)
    world.db.add_permissions(world.org_a, {"gmail": {"send": "confirm"}})
    tenant, chat_id = _chat_case(world, seeded, case)

    setup, _ = await _load(turn_setup, world.db, tenant, chat_id)

    assert (setup.policy, setup.prompt_context) == await _oracle(world.db, tenant)


# ---------------------------------------------------------------------------
# 5. No content in logs
# ---------------------------------------------------------------------------


async def test_turn_setup_load_logs_no_content(
    turn_setup: ModuleType, world: World, seeded: _Chats
) -> None:
    """The instructions, title and message canaries reach no log line (DEBUG, text)."""
    _prompt_inputs_set(world, seeded)

    with configured_logging("DEBUG", "text") as logs:
        for case in _CHAT_CASES:
            tenant, chat_id = _chat_case(world, seeded, case)
            await turn_setup.load_turn_setup(world.db.pool, tenant, chat_id)
        logged = logs.text + "\n".join(record.getMessage() for record in logs.records)

    assert [canary for canary in CANARIES if canary in logged] == []
