"""Spec: ``scoped_settings.load_prompt_context``, a member's prompt inputs (GH-170).

Every chat run's system prompt is assembled per request from the caller's
own rows: the org's instructions (``org_settings.instructions``) and default
response language (``organizations.default_response_language``), and the
user's response language, timezone and personal instructions (``users``).
``load_prompt_context(executor, tenant)`` reads them in ONE ``fetchrow``
(contract section 4) and returns an ``admino.models.PromptContext``.

These tests drive the loader against the in-memory database of
tests/db_fakes.py, which executes the contract's join (users JOIN
organizations LEFT JOIN org_settings, filtered by the user id, the tenant's
org id and ``deleted_at IS NULL``).

Inputs: a FakeDb with orgs A (``ORG_ID``) and B (``OTHER_ORG_ID``), their
org_settings rows and members; a ``TenantContext``.
Outputs (asserted):
- every column lands in its field; the user's own language stays None
  without a preference while the org default is carried beside it (the
  loader never resolves the fallback); unset columns read as the defaults;
- no org_settings row -> ``org_instructions == ""``;
- a tenant whose org isn't the user's org, a deleted or unknown user, or a
  Super Admin's id -> ``PromptContext()``: one org's instructions never come
  back for another org's tenant;
- every member role gets its context (no capability check);
- exactly one statement, a ``fetchrow`` binding ``(user_id, org_id)``, no
  identifier in the SQL text, nothing written, on the pool or a connection;
- no instruction text in any log record.

Security notes:
- Tenant isolation: the org is always the tenant's, bound as a parameter.
- The instruction texts are content: never logged.
- All values here are fixed fake values.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

import pytest

from admino.access import Principal
from admino.models import PromptContext
from admino.scoped_settings import load_prompt_context
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, plain

if TYPE_CHECKING:
    from tests.db_fakes import Call

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ORG_A_TEXT: Final = "OrgA-canary-170: answer formally and sign as Team Kestrel."
_ORG_B_TEXT: Final = "OrgB-canary-170: always mention the Basel office."
_PERSONAL_TEXT: Final = "Personal-canary-170: keep it under five sentences."
# A third org without an org_settings row.
_BARE_ORG_ID: Final = uuid.UUID("f6a7b8c9-d0e1-4f2a-8b3c-4d5e6f7a8b92")

_LANGUAGES: Final = ("de", "fr", "it", "en")
_MEMBER_ROLES: Final = ("org_admin", "editor", "viewer")

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def db() -> FakeDb:
    """Orgs A (default language fr) and B (default language it), each with instructions."""
    fake = FakeDb()
    fake.add_org(ORG_ID, data_residency=False, default_response_language="fr")
    fake.add_org_settings(ORG_ID, instructions=_ORG_A_TEXT)
    fake.add_org(OTHER_ORG_ID, data_residency=False, default_response_language="it")
    fake.add_org_settings(OTHER_ORG_ID, instructions=_ORG_B_TEXT)
    return fake


def _tenant(user_id: uuid.UUID, org_id: uuid.UUID, role: str = "editor") -> TenantContext:
    """The tenant of a member principal (built the way the server builds it)."""
    principal = Principal(user_id=user_id, kind="member", org_id=org_id, role=role)
    return TenantContext.from_principal(principal)


def _member(
    db: FakeDb,
    *,
    org_id: uuid.UUID = ORG_ID,
    role: str = "editor",
    response_language: str | None = None,
    timezone: str | None = None,
    personal_instructions: str = "",
) -> uuid.UUID:
    return db.add_account(
        role=role,
        org_id=org_id,
        response_language=response_language,
        timezone=timezone,
        personal_instructions=personal_instructions,
    )


def _calls_since(db: FakeDb, mark: int) -> list[Call]:
    return db.calls[mark:]


# ---------------------------------------------------------------------------
# 1. Every column lands in its field
# ---------------------------------------------------------------------------


class TestMapping:
    """The row of the caller's user, org and org_settings becomes the PromptContext."""

    async def test_prompt_context_loader_maps_every_column_to_its_field(self, db: FakeDb) -> None:
        user_id = _member(
            db,
            response_language="de",
            timezone="Asia/Kolkata",
            personal_instructions=_PERSONAL_TEXT,
        )

        context = await load_prompt_context(db.pool, _tenant(user_id, ORG_ID))

        assert type(context) is PromptContext
        assert context == PromptContext(
            org_instructions=_ORG_A_TEXT,
            personal_instructions=_PERSONAL_TEXT,
            response_language="de",
            default_response_language="fr",
            timezone="Asia/Kolkata",
        )

    @pytest.mark.parametrize("org_default", _LANGUAGES)
    async def test_prompt_context_loader_without_user_preference_carries_the_org_default(
        self, db: FakeDb, org_default: str
    ) -> None:
        """No preference: response_language stays None (the loader never resolves the
        fallback), the org default is carried in its own field."""
        db.add_org(ORG_ID, default_response_language=org_default)
        user_id = _member(db, response_language=None, timezone="Europe/Zurich")

        context = await load_prompt_context(db.pool, _tenant(user_id, ORG_ID))

        assert (context.response_language, context.default_response_language) == (
            None,
            org_default,
        )

    @pytest.mark.parametrize(
        ("preference", "org_default"),
        [("it", "en"), ("en", "de"), ("de", "fr"), ("fr", "it")],
    )
    async def test_prompt_context_loader_keeps_the_user_preference_beside_the_org_default(
        self, db: FakeDb, preference: str, org_default: str
    ) -> None:
        db.add_org(ORG_ID, default_response_language=org_default)
        user_id = _member(db, response_language=preference)

        context = await load_prompt_context(db.pool, _tenant(user_id, ORG_ID))

        assert (context.response_language, context.default_response_language) == (
            preference,
            org_default,
        )

    async def test_prompt_context_loader_unset_account_columns_read_as_defaults(
        self, db: FakeDb
    ) -> None:
        """timezone NULL -> None, personal_instructions '' -> ''; the org part still loads."""
        user_id = _member(db)

        context = await load_prompt_context(db.pool, _tenant(user_id, ORG_ID))

        assert context == PromptContext(
            org_instructions=_ORG_A_TEXT,
            personal_instructions="",
            response_language=None,
            default_response_language="fr",
            timezone=None,
        )

    async def test_prompt_context_loader_without_org_settings_row_has_empty_org_instructions(
        self, db: FakeDb
    ) -> None:
        """An org without an org_settings row (LEFT JOIN: NULL) reads as no instructions."""
        db.add_org(_BARE_ORG_ID, data_residency=False, default_response_language="de")
        user_id = _member(
            db,
            org_id=_BARE_ORG_ID,
            response_language="en",
            timezone="Europe/Zurich",
            personal_instructions=_PERSONAL_TEXT,
        )

        context = await load_prompt_context(db.pool, _tenant(user_id, _BARE_ORG_ID))

        assert context == PromptContext(
            org_instructions="",
            personal_instructions=_PERSONAL_TEXT,
            response_language="en",
            default_response_language="de",
            timezone="Europe/Zurich",
        )

    async def test_prompt_context_loader_empty_org_instructions_read_as_empty(
        self, db: FakeDb
    ) -> None:
        db.org_settings[ORG_ID]["instructions"] = ""
        user_id = _member(db, personal_instructions=_PERSONAL_TEXT)

        context = await load_prompt_context(db.pool, _tenant(user_id, ORG_ID))

        assert (context.org_instructions, context.personal_instructions) == ("", _PERSONAL_TEXT)

    async def test_prompt_context_loader_keeps_multiline_text_verbatim(self, db: FakeDb) -> None:
        """Instructions are returned as stored: lines, umlauts and quotes kept."""
        org_text = "Zeile 1: Bitte förmlich.\n- Antworten Sie kurz.\n« Merci » et à bientôt."
        personal = "Line one.\n\tIndented line two — with a dash."
        db.org_settings[ORG_ID]["instructions"] = org_text
        user_id = _member(db, personal_instructions=personal)

        context = await load_prompt_context(db.pool, _tenant(user_id, ORG_ID))

        assert (context.org_instructions, context.personal_instructions) == (org_text, personal)

    async def test_prompt_context_loader_loads_texts_at_their_column_limits(
        self, db: FakeDb
    ) -> None:
        """8000-char org instructions, 1500-char personal instructions and a 64-char
        timezone (the columns' CHECK limits) load without a validation error."""
        org_text = "o" * 8000
        personal = "p" * 1500
        timezone = "America/" + "x" * 56
        db.org_settings[ORG_ID]["instructions"] = org_text
        user_id = _member(db, timezone=timezone, personal_instructions=personal)

        context = await load_prompt_context(db.pool, _tenant(user_id, ORG_ID))

        assert (context.org_instructions, context.personal_instructions, context.timezone) == (
            org_text,
            personal,
            timezone,
        )

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    async def test_prompt_context_loader_every_member_role_gets_its_context(
        self, db: FakeDb, role: str
    ) -> None:
        """No capability check: an Org Admin, an Editor and a Viewer all get their rows."""
        user_id = _member(db, role=role, response_language="it", timezone="Europe/Zurich")

        context = await load_prompt_context(db.pool, _tenant(user_id, ORG_ID, role))

        assert context == PromptContext(
            org_instructions=_ORG_A_TEXT,
            response_language="it",
            default_response_language="fr",
            timezone="Europe/Zurich",
        )


# ---------------------------------------------------------------------------
# 2. Only the tenant's own org and user
# ---------------------------------------------------------------------------


class TestTenantScope:
    """A row is returned only for a live user of the tenant's org."""

    @pytest.mark.parametrize(
        ("user_org", "tenant_org", "foreign_text"),
        [
            pytest.param(ORG_ID, OTHER_ORG_ID, _ORG_B_TEXT, id="org-a-user-org-b-tenant"),
            pytest.param(OTHER_ORG_ID, ORG_ID, _ORG_A_TEXT, id="org-b-user-org-a-tenant"),
        ],
    )
    async def test_prompt_context_loader_tenant_of_another_org_reads_empty_context(
        self, db: FakeDb, user_org: uuid.UUID, tenant_org: uuid.UUID, foreign_text: str
    ) -> None:
        """A tenant naming an org the user isn't in gets PromptContext(): neither org's
        instructions, nor the user's own values."""
        user_id = _member(
            db,
            org_id=user_org,
            response_language="de",
            timezone="Asia/Kolkata",
            personal_instructions=_PERSONAL_TEXT,
        )

        context = await load_prompt_context(db.pool, _tenant(user_id, tenant_org))

        assert context == PromptContext()
        assert foreign_text not in context.model_dump_json()

    async def test_prompt_context_loader_org_a_tenant_never_gets_org_b_instructions(
        self, db: FakeDb
    ) -> None:
        """Both orgs have instructions: each tenant gets exactly its own org's text."""
        user_a = _member(db, org_id=ORG_ID)
        user_b = _member(db, org_id=OTHER_ORG_ID)

        context_a = await load_prompt_context(db.pool, _tenant(user_a, ORG_ID))
        context_b = await load_prompt_context(db.pool, _tenant(user_b, OTHER_ORG_ID))

        assert (context_a.org_instructions, context_a.default_response_language) == (
            _ORG_A_TEXT,
            "fr",
        )
        assert (context_b.org_instructions, context_b.default_response_language) == (
            _ORG_B_TEXT,
            "it",
        )
        assert _ORG_B_TEXT not in context_a.model_dump_json()
        assert _ORG_A_TEXT not in context_b.model_dump_json()

    async def test_prompt_context_loader_deleted_user_reads_empty_context(self, db: FakeDb) -> None:
        user_id = db.add_account(
            role="editor",
            org_id=ORG_ID,
            deleted_at=datetime(2026, 9, 1, tzinfo=UTC),
            response_language="de",
            timezone="Asia/Kolkata",
            personal_instructions=_PERSONAL_TEXT,
        )

        context = await load_prompt_context(db.pool, _tenant(user_id, ORG_ID))

        assert context == PromptContext()

    async def test_prompt_context_loader_unknown_user_reads_empty_context(self, db: FakeDb) -> None:
        _member(db, response_language="de", personal_instructions=_PERSONAL_TEXT)

        context = await load_prompt_context(db.pool, _tenant(uuid.uuid4(), ORG_ID))

        assert context == PromptContext()

    async def test_prompt_context_loader_super_admin_id_reads_empty_context(
        self, db: FakeDb
    ) -> None:
        """A Super Admin belongs to no org: a tenant forged from their id finds no row."""
        operator = db.add_account(kind="super_admin", role=None)

        context = await load_prompt_context(db.pool, _tenant(operator, ORG_ID))

        assert context == PromptContext()


# ---------------------------------------------------------------------------
# 3. One parameterized read, nothing written
# ---------------------------------------------------------------------------


class TestStatement:
    """Exactly one fetchrow binding the tenant's user id and org id; no write."""

    async def test_prompt_context_loader_runs_one_fetchrow_binding_user_and_org(
        self, db: FakeDb
    ) -> None:
        user_id = _member(db, personal_instructions=_PERSONAL_TEXT)
        mark = len(db.calls)

        await load_prompt_context(db.pool, _tenant(user_id, ORG_ID))

        calls = _calls_since(db, mark)
        assert [call.method for call in calls] == ["fetchrow"]
        assert tuple(plain(arg) for arg in calls[0].args) == (user_id, ORG_ID)

    async def test_prompt_context_loader_sql_is_a_constant_select(self, db: FakeDb) -> None:
        """The statement is a SELECT whose text carries no id: every value is a bind."""
        user_id = _member(db)
        mark = len(db.calls)

        await load_prompt_context(db.pool, _tenant(user_id, ORG_ID))

        (call,) = _calls_since(db, mark)
        assert call.normalized.startswith("select ")
        for value in (str(user_id), user_id.hex, str(ORG_ID), ORG_ID.hex):
            assert value not in call.normalized

    async def test_prompt_context_loader_writes_nothing(self, db: FakeDb) -> None:
        user_id = _member(db, personal_instructions=_PERSONAL_TEXT)
        before = db.snapshot()

        await load_prompt_context(db.pool, _tenant(user_id, ORG_ID))
        await load_prompt_context(db.pool, _tenant(user_id, OTHER_ORG_ID))
        await load_prompt_context(db.pool, _tenant(uuid.uuid4(), ORG_ID))

        assert db.snapshot() == before
        assert db.transactions == []

    async def test_prompt_context_loader_reads_through_a_connection_too(self, db: FakeDb) -> None:
        """The executor may be a connection: the read runs on it, same result."""
        user_id = _member(db, response_language="en", timezone="Europe/Zurich")
        connection = db.new_connection()
        mark = len(db.calls)

        context = await load_prompt_context(connection, _tenant(user_id, ORG_ID))

        assert context == PromptContext(
            org_instructions=_ORG_A_TEXT,
            response_language="en",
            default_response_language="fr",
            timezone="Europe/Zurich",
        )
        assert [(call.method, call.via) for call in _calls_since(db, mark)] == [
            ("fetchrow", "conn-1")
        ]


# ---------------------------------------------------------------------------
# 4. No instruction text in the logs
# ---------------------------------------------------------------------------


class TestLogs:
    """The loader logs no value it reads."""

    async def test_prompt_context_loader_logs_no_instruction_text(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        user_id = _member(
            db,
            response_language="de",
            timezone="Asia/Kolkata",
            personal_instructions=_PERSONAL_TEXT,
        )

        context = await load_prompt_context(db.pool, _tenant(user_id, ORG_ID))
        await load_prompt_context(db.pool, _tenant(user_id, OTHER_ORG_ID))

        # Non-vacuous: the texts were really read.
        assert (context.org_instructions, context.personal_instructions) == (
            _ORG_A_TEXT,
            _PERSONAL_TEXT,
        )
        logged = "\n".join(
            f"{record.getMessage()} {record.args!r}" for record in caplog.records
        ).casefold()
        for marker in (
            _ORG_A_TEXT,
            _ORG_B_TEXT,
            _PERSONAL_TEXT,
            "canary-170",
            "kestrel",
            "asia/kolkata",
        ):
            assert marker.casefold() not in logged, marker
