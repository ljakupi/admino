"""Tests for migration 0031_chat_retry.sql (GH-245, contract C1, issue Decision 7): the
owner-run ``delete_failed_turn`` function a retry uses to replace a chat's failed last
turn, while chat_messages stays append-only for admino_app.

There is no real PostgreSQL in the suite, so the shipped SQL file is the spec (the
pipeline ran the contract's SQL on a throwaway postgres:16 as admino_app). The SQL is
read with tests/test_migration_0018.py's lexer (comments blanked, '...' literals and
dollar-quoted bodies kept whole, nested DO / function bodies and EXECUTE literals
searched too) and tests/test_migration_0019.py's CREATE FUNCTION reader; the GRANT /
REVOKE statements of every shipped migration are replayed into the privileges each role
ends up with, on the tables (tests/test_migration_0027.py's replay) and on the functions
(this file: PUBLIC's default EXECUTE on a new function, 0018's REVOKE ON ALL FUNCTIONS
and ALTER DEFAULT PRIVILEGES, every GRANT / REVOKE ON FUNCTION).

What is pinned:
- ``0031_chat_retry.sql`` ships as the only version 31, right after the versions 1 to
  30; run_migrations applies it after 0030 (once). It opens with a header comment that
  names delete_failed_turn, says chat_messages stays append-only for admino_app (no
  UPDATE or DELETE), that the function is SECURITY DEFINER with a pinned search_path,
  that the turn's files are unlinked first, that #182 replaces it, and the grants.
- Exactly three top-level statements, in this order: ``CREATE FUNCTION
  delete_failed_turn(target_chat uuid, target_org uuid, target_owner uuid, through_seq
  bigint) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = public,
  pg_temp`` (not OR REPLACE, no other option); ``REVOKE ALL ON FUNCTION
  delete_failed_turn(uuid, uuid, uuid, bigint) FROM PUBLIC``; ``GRANT EXECUTE ON FUNCTION
  delete_failed_turn(uuid, uuid, uuid, bigint) TO admino_app`` (no grant option).
- The function body equals the contract's statement for statement (comments blanked,
  whitespace collapsed, keywords case-insensitive, '...' literals byte for byte). Every
  RAISE is ``RAISE EXCEPTION 'only a failed turn of a live chat can be deleted' USING
  ERRCODE = 'insufficient_privilege'`` (a plain literal: no row data), and the body runs
  static SQL only (no EXECUTE, format() or quoting helpers).
- Nothing else: no table, column, index, trigger, rule, policy, role or schema change,
  no table GRANT or REVOKE, no DO block, no data write outside the function body, no
  default privileges, no OWNER TO, no SET ROLE, also not nested in a body or a literal.
- After every shipped migration: admino_app holds exactly SELECT, INSERT on
  chat_messages (never UPDATE or DELETE), PUBLIC nothing; every table's privileges are
  what they were after 0030. admino_app may EXECUTE exactly purge_audit_events(integer),
  purge_org_audit_events(uuid) and delete_failed_turn(uuid, uuid, uuid, bigint), PUBLIC
  no function; 0031 adds EXECUTE on delete_failed_turn for admino_app and changes no
  other function's privileges. Every grant guard of tests/test_migration_0018.py passes
  with 0031 shipped.
- tests/db_fakes.py mirrors the refusal (contract C5): the fake's
  ``SELECT delete_failed_turn($1, $2, $3, $4)`` for an unknown chat raises
  InsufficientPrivilegeError with exactly the SQL's RAISE text.

Security notes:
- The runtime role still can't UPDATE or DELETE a chat message: the only delete path is
  the owner-run function, which checks the chat's org, owner and liveness and the turn's
  failed status itself, so a bug or injected SQL running as admino_app can delete at most
  the caller-named chat's failed last turn, never another org's or a colleague's rows.
- SECURITY DEFINER with ``search_path = public, pg_temp`` (two names, not one literal):
  the function can't be hijacked through objects in another schema.
- The refusal names no chat, org, user or row: the error carries no data.
"""

from __future__ import annotations

import re
import uuid
from typing import TYPE_CHECKING, Final, NamedTuple
from unittest.mock import AsyncMock

import asyncpg
import pytest

import admino.database as db_mod
from tests.db_fakes import ORG_ID, FakeDb
from tests.test_migration_0018 import (
    _GLOBAL_DEFAULT_REVOKE,
    _GUARDS,
    _executed,
    _fragments,
    _grantees,
    _load_migrations,
    _masked,
    _Migration,
    _normalize,
    _parse_grants,
    _privileges,
    _shipped,
    _signature,
    _split,
    _target,
)
from tests.test_migration_0019 import (
    _SET_RE,
    _canon,
    _Function,
    _function_of,
    _is_security_definer,
    _language,
    _settings,
    _Statement,
    _statements,
)
from tests.test_migration_0027 import _apply

if TYPE_CHECKING:
    from unittest.mock import MagicMock

_MIGRATION_NAME: Final = "0031_chat_retry.sql"
_PREVIOUS_MIGRATION: Final = "0030_context_budget.sql"
_VERSION: Final = 31
_ROLE: Final = "admino_app"
_FUNCTION: Final = "delete_failed_turn"
_SIGNATURE: Final = "delete_failed_turn(uuid,uuid,uuid,bigint)"
_ARGUMENTS: Final = (
    ("target_chat", "uuid"),
    ("target_org", "uuid"),
    ("target_owner", "uuid"),
    ("through_seq", "bigint"),
)
_SEARCH_PATH: Final = ("public", "pg_temp")
_REFUSAL: Final = "only a failed turn of a live chat can be deleted"
_ERRCODE: Final = "insufficient_privilege"
_RAISE_COUNT: Final = 4
_MESSAGES: Final = "chat_messages"
_PURGES: Final = ("purge_audit_events(integer)", "purge_org_audit_events(uuid)")
_EXECUTABLE: Final = frozenset({*_PURGES, _SIGNATURE})
_CALL: Final = "SELECT delete_failed_turn($1, $2, $3, $4)"

# The function body of contract C1, as validated on postgres:16 (between AS $$ and $$).
_CONTRACT_BODY: Final = """
DECLARE
    turn_id uuid;
    turn_seq bigint;
    deleted bigint;
BEGIN
    PERFORM 1 FROM chats
    WHERE id = target_chat AND org_id = target_org AND owner_user_id = target_owner
        AND deleted_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'only a failed turn of a live chat can be deleted'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    PERFORM 1 FROM chat_messages
    WHERE chat_id = target_chat AND org_id = target_org AND seq = through_seq
        AND status IN ('error', 'stopped');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'only a failed turn of a live chat can be deleted'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    PERFORM 1 FROM chat_messages
    WHERE chat_id = target_chat AND org_id = target_org AND seq > through_seq
        AND role <> 'user';
    IF FOUND THEN
        RAISE EXCEPTION 'only a failed turn of a live chat can be deleted'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT id, seq INTO turn_id, turn_seq FROM chat_messages
    WHERE chat_id = target_chat AND org_id = target_org AND role = 'user'
        AND seq <= through_seq
    ORDER BY seq DESC
    LIMIT 1;
    IF turn_id IS NULL THEN
        RAISE EXCEPTION 'only a failed turn of a live chat can be deleted'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    UPDATE attachments SET message_id = NULL, updated_at = now()
    WHERE message_id = turn_id AND chat_id = target_chat AND org_id = target_org;
    DELETE FROM chat_messages
    WHERE chat_id = target_chat AND org_id = target_org
        AND seq >= turn_seq AND seq <= through_seq;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
"""

# Argument / type spellings PostgreSQL treats as one type.
_TYPE_ALIASES: Final = {"int8": "bigint", "int4": "integer", "int": "integer"}
_ERRCODE_ALIASES: Final = {"42501": _ERRCODE}
_FUNCTION_KINDS: Final = frozenset({"function", "procedure", "routine"})
_BULK_FUNCTION_KINDS: Final = frozenset({"all functions", "all procedures", "all routines"})

_CREATE_FUNCTION_RE: Final = re.compile(
    r"create (?:or replace )?(?:function|procedure) (?P<name>[\w.\"$]+) ?"
    r"\((?P<arguments>[^)]*)\)"
)
_DROP_FUNCTION_RE: Final = re.compile(
    r"drop (?:function|procedure|routine) (?:if exists )?(?P<objects>.+?)"
    r"(?: (?:cascade|restrict))?"
)
_REVOKE_STATEMENT_RE: Final = re.compile(
    r"revoke (?P<option>grant option for )?(?P<privileges>.+?) on (?P<target>.+?)"
    r" from (?P<grantees>.+?)(?P<rest>(?: granted by \S+)?(?: (?:cascade|restrict))?)"
)
_RAISE_RE: Final = re.compile(
    r"(?:.*\bthen )?raise (?P<level>\w+) (?P<message>'(?:[^']|'')*')"
    r" using errcode ?= ?'(?P<code>[^']*)'"
)
_DYNAMIC_SQL_RE: Final = re.compile(
    r"\bexecute\b|\bformat ?\(|\bquote_(?:ident|literal|nullable)\b|\bdblink"
)
# Patterns never found in any fragment of 0031 (top level, function body, literals).
_FORBIDDEN: Final[dict[str, str]] = {
    "do block": r"^do\b",
    "table / index / view / type / schema / sequence": (
        r"\b(?:create|alter|drop) (?:(?:unique|temp|temporary|unlogged|global|local) )*"
        r"(?:table|index|view|materialized view|type|schema|sequence|domain|extension)\b"
    ),
    "trigger / rule / policy": (
        r"\b(?:create|alter|drop) (?:or replace )?(?:constraint )?"
        r"(?:trigger|event trigger|rule|policy)\b"
    ),
    "function change": r"\b(?:alter|drop) (?:function|procedure|routine)\b",
    "role": r"\b(?:create|alter|drop) (?:role|user|group)\b",
    "set role": r"\bset (?:(?:local|session) )?(?:role|session authorization)\b",
    "owner": r"\bowner to\b|\bauthorization\b|\breassign owned\b",
    "default privileges": r"\balter default privileges\b",
    "insert": r"\binsert into\b",
    "truncate": r"\btruncate\b",
    "copy": r"\bcopy\b",
    "merge": r"\bmerge into\b",
    "session_replication_role": r"\bsession_replication_role\b",
    "security invoker": r"\bsecurity invoker\b",
    "disable": r"\bdisable\b",
}
# Data writes that may only appear inside the function body.
_TOP_LEVEL_WRITES: Final[dict[str, str]] = {
    "update": r"\bupdate (?:only )?\S+ set\b",
    "delete": r"\bdelete from\b",
    "select": r"^select\b|\bperform\b",
}


# ---------------------------------------------------------------------------
# Helpers: the shipped SQL
# ---------------------------------------------------------------------------


def _raw_sql() -> str:
    path = db_mod._MIGRATIONS_DIR / _MIGRATION_NAME
    assert path.is_file(), f"{_MIGRATION_NAME} is not shipped"
    return path.read_text(encoding="utf-8")


def _top_statements() -> list[_Statement]:
    """0031's top-level statements (comments blanked; raw, normalized and masked)."""
    _raw_sql()
    return _statements(_MIGRATION_NAME)


def _header_lines() -> list[str]:
    """The non-empty ``--`` comment lines before the first statement."""
    lines: list[str] = []
    for line in _raw_sql().splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            lines.append(stripped[2:].strip())
        elif stripped:
            break
    return [line for line in lines if line]


def _alias_types(signature: str) -> str:
    """A ``name(type,...)`` signature with PostgreSQL's type aliases folded."""
    name, paren, rest = signature.partition("(")
    if not paren:
        return signature
    types = [_TYPE_ALIASES.get(item, item) for item in rest.removesuffix(")").split(",") if item]
    return f"{name}({','.join(types)})"


def _function() -> _Function:
    """The one CREATE FUNCTION of 0031 (tests/test_migration_0019.py's reader)."""
    found = [
        function
        for statement in _top_statements()
        if (function := _function_of(statement.raw)) is not None
    ]
    assert len(found) == 1, f"{_MIGRATION_NAME} must create exactly one function"
    return found[0]


def _arguments(text: str) -> tuple[tuple[str, str], ...]:
    """(name, type) per argument of a normalized argument list (an IN mode dropped)."""
    result: list[tuple[str, str]] = []
    for item in _split(text, ","):
        tokens = item.split()
        if tokens and tokens[0] == "in":
            tokens = tokens[1:]
        name = tokens[0] if tokens else ""
        type_name = " ".join(tokens[1:])
        result.append((name, _TYPE_ALIASES.get(type_name, type_name)))
    return tuple(result)


def _other_options(options: str) -> str:
    """The function's options without LANGUAGE plpgsql, SECURITY DEFINER, the SET
    clauses and VOLATILE (the default): whatever else 0031 declares."""
    rest = _SET_RE.sub(" ", options)
    rest = re.sub(r"\blanguage '?plpgsql'?", " ", rest)
    rest = re.sub(r"\b(?:external )?security definer\b", " ", rest)
    rest = re.sub(r"\bvolatile\b", " ", rest)
    return re.sub(r"\s+", " ", rest).strip()


def _body_statements(body: str) -> list[str]:
    """A PL/pgSQL body as its ``;``-separated pieces, comments blanked, whitespace
    collapsed (and dropped around punctuation), lowercased outside literals."""
    return [_canon(piece) for piece in _split(_normalize(body), ";")]


def _shipped_body() -> str:
    return _function().body


def _raises() -> list[tuple[str, str, str]]:
    """(level, message, errcode) of every RAISE in the shipped body, in order; an
    unreadable RAISE is reported whole."""
    found: list[tuple[str, str, str]] = []
    for piece in _split(_normalize(_shipped_body()), ";"):
        if re.search(r"\braise\b", _masked(piece)) is None:
            continue
        match = _RAISE_RE.fullmatch(piece)
        if match is None:
            found.append(("unreadable", piece, ""))
            continue
        message = match.group("message")[1:-1].replace("''", "'")
        code = _ERRCODE_ALIASES.get(match.group("code").lower(), match.group("code").lower())
        found.append((match.group("level"), message, code))
    return found


def _kind(statement: _Statement) -> str:
    """create function / revoke / grant, else the statement itself."""
    if _function_of(statement.raw) is not None:
        return "create function"
    if re.match(r"revoke\b", statement.masked):
        return "revoke"
    if re.match(r"grant\b", statement.masked):
        return "grant"
    return statement.norm


class _Revoke(NamedTuple):
    privileges: frozenset[str]
    kind: str
    objects: tuple[str, ...]
    grantees: frozenset[str]
    option_only: bool
    rest: str


def _function_privileges(kind: str, privileges: frozenset[str]) -> frozenset[str]:
    """ALL on a function is EXECUTE (its only privilege)."""
    if kind in _FUNCTION_KINDS and "all" in privileges:
        return (privileges - {"all"}) | {"execute"}
    return privileges


_FileGrant = tuple[frozenset[str], str, tuple[str, ...], frozenset[str], bool]


def _file_grants() -> tuple[list[_FileGrant], int]:
    """(privileges, kind, objects, grantees, grant option) of every GRANT in 0031, nested
    bodies and literals included, and how many role memberships it grants."""
    grants, memberships = _parse_grants(_fragments(_normalize(_raw_sql())))
    return [
        (
            _function_privileges(grant.kind, grant.privileges),
            grant.kind,
            tuple(_alias_types(item) for item in grant.objects),
            grant.grantees,
            grant.grant_option,
        )
        for grant in grants
    ], len(memberships)


def _file_revokes() -> list[_Revoke]:
    """Every REVOKE in 0031, nested bodies and literals included."""
    revokes: list[_Revoke] = []
    for fragment in _fragments(_normalize(_raw_sql())):
        masked = _masked(fragment)
        if re.match(r"revoke\b", masked) is None:
            continue
        match = _REVOKE_STATEMENT_RE.fullmatch(masked)
        assert match is not None, f"the test can't read the REVOKE {fragment!r}"
        kind, objects = _target(match.group("target"))
        revokes.append(
            _Revoke(
                _function_privileges(kind, _privileges(match.group("privileges"))),
                kind,
                tuple(_alias_types(item) for item in objects),
                _grantees(match.group("grantees")),
                match.group("option") is not None,
                match.group("rest").strip(),
            )
        )
    return revokes


# ---------------------------------------------------------------------------
# Helpers: privileges after every shipped migration
# ---------------------------------------------------------------------------


def _shipped_migrations() -> list[_Migration]:
    """The shipped migrations; fails the calling test while version 31 isn't shipped."""
    shipped = _load_migrations(db_mod._MIGRATIONS_DIR)
    assert _VERSION in [m.version for m in shipped], f"{_MIGRATION_NAME} is not shipped"
    return shipped


def _table_acl(up_to: int | None = None) -> dict[tuple[str, str], frozenset[str]]:
    """(table, grantee) -> ACL entries after every shipped migration (up to a version)."""
    acl: dict[tuple[str, str], set[str]] = {}
    for migration in _shipped_migrations():
        if up_to is not None and migration.version > up_to:
            continue
        for statement in _executed(_normalize(migration.sql)):
            _apply(acl, statement)
    return {key: frozenset(value) for key, value in acl.items() if value}


def _covers_execute(privileges: frozenset[str]) -> bool:
    return bool(privileges & {"execute", "all"})


def _function_targets(acl: dict[str, set[str]], kind: str, objects: tuple[str, ...]) -> list[str]:
    """The known functions a GRANT / REVOKE target names (a bare name: every overload)."""
    if kind in _BULK_FUNCTION_KINDS:
        return list(acl) if "public" in objects else []
    if kind not in _FUNCTION_KINDS:
        return []
    targets: list[str] = []
    for item in objects:
        if "(" in item:
            targets.append(_alias_types(item))
        else:
            targets.extend(signature for signature in acl if signature.split("(")[0] == item)
    return targets


def _apply_to_functions(acl: dict[str, set[str]], statement: str, public_default: bool) -> bool:
    """Apply one statement to the functions' ACL (grantee, ``grantee*`` for a grant
    option; the owner left out) as PostgreSQL does; returns whether a function created
    from now on gives PUBLIC EXECUTE (PostgreSQL's default until 0018's global ALTER
    DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC)."""
    masked = _masked(statement)
    if (created := _CREATE_FUNCTION_RE.match(masked)) is not None:
        raw = f"{created.group('name')}({created.group('arguments')})"
        acl.setdefault(_alias_types(_signature(raw)), {"public"} if public_default else set())
        return public_default
    if (dropped := _DROP_FUNCTION_RE.fullmatch(masked)) is not None:
        objects = tuple(_signature(item) for item in _split(dropped.group("objects"), ","))
        for signature in _function_targets(acl, "function", objects):
            acl.pop(signature, None)
        return public_default
    if _GLOBAL_DEFAULT_REVOKE.fullmatch(masked):
        return False
    if re.match(r"grant\b", masked):
        for grant in _parse_grants([statement])[0]:
            if not _covers_execute(grant.privileges):
                continue
            for signature in _function_targets(acl, grant.kind, grant.objects):
                held = acl.setdefault(signature, set())
                held.update(grant.grantees)
                if grant.grant_option:
                    held.update(f"{grantee}*" for grantee in grant.grantees)
        return public_default
    if (revoke := _REVOKE_STATEMENT_RE.fullmatch(masked)) is not None:
        if not _covers_execute(_privileges(revoke.group("privileges"))):
            return public_default
        kind, objects = _target(revoke.group("target"))
        for signature in _function_targets(acl, kind, objects):
            held = acl.setdefault(signature, set())
            for grantee in _grantees(revoke.group("grantees")):
                held.discard(f"{grantee}*")
                if revoke.group("option") is None:
                    held.discard(grantee)
    return public_default


def _function_acl(up_to: int | None = None) -> dict[str, frozenset[str]]:
    """signature -> who may EXECUTE it after every shipped migration (up to a version)."""
    acl: dict[str, set[str]] = {}
    public_default = True
    for migration in _shipped_migrations():
        if up_to is not None and migration.version > up_to:
            continue
        for statement in _executed(_normalize(migration.sql)):
            public_default = _apply_to_functions(acl, statement, public_default)
    return {signature: frozenset(held) for signature, held in acl.items()}


def _executable_by(grantee: str) -> frozenset[str]:
    return frozenset(signature for signature, held in _function_acl().items() if grantee in held)


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0031File:
    """The migration ships as version 31, right after 0030, and is applied once."""

    def test_migration_0031_file_is_the_only_version_31_after_versions_1_to_30(self) -> None:
        shipped = [
            (int(m.group(1)), path.name)
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name))
        ]

        assert [name for version, name in shipped if version == _VERSION] == [_MIGRATION_NAME]
        assert sorted(version for version, _ in shipped if version < _VERSION) == list(
            range(1, _VERSION)
        )

    async def test_migration_0031_run_migrations_applies_and_records_it(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0030 applied, run_migrations executes the file and records 31."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)
        assert (_VERSION, _MIGRATION_NAME) in recorded

    async def test_migration_0031_runs_after_0030(self, mock_pool: MagicMock) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION - 1)])
        previous = (db_mod._MIGRATIONS_DIR / _PREVIOUS_MIGRATION).read_text(encoding="utf-8")
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert previous in executed
        assert shipped in executed
        assert executed.index(previous) < executed.index(shipped)

    async def test_migration_0031_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0031_opens_with_a_header_comment_naming_what_it_adds(self) -> None:
        """What, why and grants, before any statement: the function, chat_messages staying
        append-only for admino_app (no UPDATE or DELETE), SECURITY DEFINER with a pinned
        search_path, the files unlinked first, #182, and what is granted."""
        lines = _header_lines()
        header = " ".join(lines)

        checks = {
            "names the function": _FUNCTION in header,
            "names chat_messages": _MESSAGES in header,
            "says append-only": re.search(r"append[- ]only", header, re.IGNORECASE) is not None,
            "names admino_app": _ROLE in header,
            "says no UPDATE": re.search(r"\bupdate\b", header, re.IGNORECASE) is not None,
            "says no DELETE": re.search(r"\bdelete\b", header, re.IGNORECASE) is not None,
            "says SECURITY DEFINER": re.search(r"security definer", header, re.IGNORECASE)
            is not None,
            "says search_path": "search_path" in header,
            "says the files are unlinked": re.search(r"\bunlink", header, re.IGNORECASE)
            is not None,
            "names #182": "#182" in header,
            "says what is granted": re.search(r"\bgrant", header, re.IGNORECASE) is not None,
        }

        assert len(lines) >= 3
        assert checks == dict.fromkeys(checks, True)


# ---------------------------------------------------------------------------
# 2. The statements, in order
# ---------------------------------------------------------------------------


class TestMigration0031Statements:
    """CREATE FUNCTION, REVOKE ALL FROM PUBLIC, GRANT EXECUTE TO admino_app; nothing else."""

    def test_migration_0031_runs_exactly_the_three_statements_in_the_contract_order(
        self,
    ) -> None:
        """The function first (a privilege on a missing function fails), then the REVOKE
        from PUBLIC, then the GRANT: no other top-level statement (so no data write, DO
        block or table change outside the function body)."""
        assert [_kind(statement) for statement in _top_statements()] == [
            "create function",
            "revoke",
            "grant",
        ]

    def test_migration_0031_revokes_all_on_the_function_from_public_only(self) -> None:
        """The file's only REVOKE (nested ones included): ALL (EXECUTE, a function's only
        privilege) ON FUNCTION delete_failed_turn(uuid, uuid, uuid, bigint) FROM PUBLIC."""
        assert _file_revokes() == [
            _Revoke(
                frozenset({"execute"}),
                "function",
                (_SIGNATURE,),
                frozenset({"public"}),
                False,
                "",
            )
        ]

    def test_migration_0031_grants_execute_on_the_function_to_admino_app_only(self) -> None:
        """The file's only GRANT (nested ones included): EXECUTE ON FUNCTION
        delete_failed_turn(uuid, uuid, uuid, bigint) TO admino_app, without grant option;
        no role membership."""
        assert _file_grants() == (
            [(frozenset({"execute"}), "function", (_SIGNATURE,), frozenset({_ROLE}), False)],
            0,
        )

    def test_migration_0031_changes_nothing_else(self) -> None:
        """No DO block, table / index / view / type / schema / trigger / rule / policy /
        role change, no other function altered or dropped, no default privileges, OWNER TO,
        SET ROLE, INSERT, TRUNCATE, COPY or MERGE, also not nested in the function body or
        a literal."""
        fragments = _fragments(_normalize(_raw_sql()))
        offenders = [
            (kind, fragment)
            for fragment in fragments
            for kind, pattern in _FORBIDDEN.items()
            if re.search(pattern, _masked(fragment))
        ]

        assert fragments, f"{_MIGRATION_NAME} runs nothing"
        assert offenders == []

    def test_migration_0031_writes_no_data_outside_the_function_body(self) -> None:
        """No UPDATE, DELETE, SELECT or PERFORM at the top level (the body's DML runs only
        when admino_app calls the function)."""
        offenders = [
            (kind, statement.masked)
            for statement in _top_statements()
            for kind, pattern in _TOP_LEVEL_WRITES.items()
            if re.search(pattern, statement.masked)
        ]

        assert offenders == []


# ---------------------------------------------------------------------------
# 3. The function's declaration
# ---------------------------------------------------------------------------


class TestMigration0031FunctionDeclaration:
    """delete_failed_turn(target_chat uuid, target_org uuid, target_owner uuid,
    through_seq bigint) RETURNS bigint, plpgsql, SECURITY DEFINER, search_path pinned."""

    def test_migration_0031_creates_delete_failed_turn_with_the_contract_signature(
        self,
    ) -> None:
        """A plain CREATE FUNCTION (not OR REPLACE: a function already there fails the
        migration instead of keeping its owner and grants), the four named arguments in
        order, RETURNS bigint (the deleted row count), LANGUAGE plpgsql."""
        function = _function()

        assert {
            "name": function.name,
            "or replace": function.or_replace,
            "arguments": _arguments(function.arguments),
            "returns": _TYPE_ALIASES.get(function.returns, function.returns),
            "language": _language(function),
        } == {
            "name": _FUNCTION,
            "or replace": False,
            "arguments": _ARGUMENTS,
            "returns": "bigint",
            "language": "plpgsql",
        }

    def test_migration_0031_function_is_security_definer(self) -> None:
        """It runs as the owner, so admino_app needs no DELETE or UPDATE on
        chat_messages; never SECURITY INVOKER."""
        function = _function()

        assert _is_security_definer(function), function.options
        assert re.search(r"\bsecurity invoker\b", function.options) is None

    def test_migration_0031_function_pins_its_search_path(self) -> None:
        """SET search_path = public, pg_temp, as two names (not one 'public, pg_temp'
        literal, which PostgreSQL reads as a single schema) and as its only setting."""
        assert _settings(_function().options) == {"search_path": _SEARCH_PATH}

    def test_migration_0031_function_declares_no_other_option(self) -> None:
        """Only LANGUAGE plpgsql, SECURITY DEFINER and the SET clause (VOLATILE, the
        default, tolerated): no STRICT (a NULL argument would return NULL instead of the
        refusal), STABLE / IMMUTABLE, LEAKPROOF, PARALLEL, COST or ROWS."""
        assert _other_options(_function().options) == ""


# ---------------------------------------------------------------------------
# 4. The function's body
# ---------------------------------------------------------------------------


class TestMigration0031FunctionBody:
    """The validated body: the checks, the refusals, the unlink, the delete, the count."""

    def test_migration_0031_body_is_the_contract_body_statement_for_statement(self) -> None:
        """The live, owned chat; the row at through_seq ended as error or stopped; no
        assistant or tool row after it; the turn's start (the latest user message at or
        before it); the files unlinked; the turn deleted; the deleted count returned.
        Comments, layout and keyword case aside, statement for statement."""
        assert _body_statements(_shipped_body()) == _body_statements(_CONTRACT_BODY)

    def test_migration_0031_every_raise_is_the_plain_refusal_with_insufficient_privilege(
        self,
    ) -> None:
        """Four RAISE EXCEPTION 'only a failed turn of a live chat can be deleted' USING
        ERRCODE = 'insufficient_privilege' (42501): a plain literal, so the error carries
        no chat, org, user or row data; no other RAISE (NOTICE, a format placeholder)."""
        assert _raises() == [("exception", _REFUSAL, _ERRCODE)] * _RAISE_COUNT

    def test_migration_0031_body_runs_static_sql_only(self) -> None:
        """No EXECUTE, format(), quote_ident / quote_literal / quote_nullable or dblink:
        the ids reach the statements as typed arguments, never as SQL text."""
        body = _masked(_normalize(_shipped_body()))

        assert body.strip(), "the function has an empty body"
        assert _DYNAMIC_SQL_RE.search(body) is None, body


# ---------------------------------------------------------------------------
# 5. Privileges after every shipped migration
# ---------------------------------------------------------------------------


class TestMigration0031Privileges:
    """chat_messages stays append-only for admino_app; it may execute the new function."""

    def test_migration_0031_admino_app_holds_select_insert_on_chat_messages_only(
        self,
    ) -> None:
        """After every shipped migration: SELECT, INSERT (never UPDATE or DELETE, no grant
        option) for admino_app on chat_messages; PUBLIC nothing."""
        acl = _table_acl()

        assert {
            _ROLE: acl.get((_MESSAGES, _ROLE), frozenset()),
            "public": acl.get((_MESSAGES, "public"), frozenset()),
        } == {_ROLE: frozenset({"select", "insert"}), "public": frozenset()}

    def test_migration_0031_changes_no_table_privilege(self) -> None:
        """Every (table, grantee) holds after 0031 exactly what it held after 0030."""
        assert _table_acl(_VERSION) == _table_acl(_VERSION - 1)

    def test_migration_0031_admino_app_may_execute_exactly_the_purges_and_the_new_function(
        self,
    ) -> None:
        """After every shipped migration: purge_audit_events(integer),
        purge_org_audit_events(uuid) and delete_failed_turn(uuid, uuid, uuid, bigint);
        no trigger function or anything else."""
        assert _executable_by(_ROLE) == _EXECUTABLE

    def test_migration_0031_public_may_execute_no_function(self) -> None:
        """After every shipped migration PUBLIC (every role) may execute no function, the
        new one included."""
        assert _executable_by("public") == frozenset()

    def test_migration_0031_adds_execute_on_the_new_function_and_nothing_else(self) -> None:
        """Every function's privileges after 0031 are those after 0030, plus
        delete_failed_turn executable by admino_app alone (no grant option)."""
        before = _function_acl(_VERSION - 1)

        assert _function_acl(_VERSION) == {**before, _SIGNATURE: frozenset({_ROLE})}

    def test_migration_0031_passes_the_0018_grant_guards(self) -> None:
        """With 0031 shipped, every grant guard of tests/test_migration_0018.py
        (section 7) still passes over all shipped migrations."""
        migrations = _shipped()
        violations = {guard_id: guard(migrations) for guard_id, guard in _GUARDS}

        assert _MIGRATION_NAME in [migration.name for migration in migrations]
        assert violations == {guard_id: [] for guard_id, _ in _GUARDS}


# ---------------------------------------------------------------------------
# 6. tests/db_fakes.py mirrors the refusal
# ---------------------------------------------------------------------------


class TestMigration0031FakeDb:
    """The FakeDb's delete_failed_turn refuses with the SQL's own text (contract C5)."""

    async def test_migration_0031_fake_refusal_is_the_sql_raise_text(self) -> None:
        """An unknown chat: InsufficientPrivilegeError with exactly the shipped RAISE
        literal, as PostgreSQL would answer."""
        literals = {message for _, message, _ in _raises()}
        db = FakeDb()

        with pytest.raises(asyncpg.InsufficientPrivilegeError) as refused:
            await db.pool.fetchval(_CALL, uuid.uuid4(), ORG_ID, uuid.uuid4(), 1)

        assert literals == {_REFUSAL}
        assert str(refused.value) == _REFUSAL
