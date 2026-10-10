"""Tests for migration 0033_retire_viewer_role.sql (GH-306, issue Decisions 1 to 5): the
Viewer role leaves the schema. Pending Viewer invitations are revoked, every other
Viewer account is deactivated and stored as an Editor, each change is audited with the
system actor, and ``users_role_check`` then allows the two member roles only.

There is no real PostgreSQL in the suite, so the shipped SQL file is the spec (the
pipeline ran the statements on a throwaway postgres:16 with active, deactivated and
invited Viewers, expired and accepted invitations and other orgs' rows; the PR records
the result). The SQL is read with tests/test_migration_0018.py's lexer (comments
blanked, '...' literals and dollar-quoted bodies kept whole, nested DO / function bodies
and EXECUTE literals searched too). Each statement is read into what PostgreSQL does
with it: the table it writes, the columns and the values it writes (a literal, a column
of a source table, a function call, a scalar sub-select), its sources (FROM / JOIN /
USING, with the join kind) and its conditions (WHERE and inner-join ON, AND-ed, every
column reference resolved to its table through the aliases, the sides of ``=``
sorted). So an alias, a reordered condition or ``JOIN ... ON`` written as a WHERE
condition reads the same, and a dropped, added or changed condition, value or source
does not. The CHECK's IN-list is read with tests/test_migration_0021.py's reader, and
the GRANT / REVOKE statements of every shipped migration are replayed with
tests/test_migration_0027.py's table replay and tests/test_migration_0031.py's
function replay.

What is pinned:
- ``0033_retire_viewer_role.sql`` ships as the only version 33, right after the
  versions 1 to 32; run_migrations applies and records it after 0032, and not again once
  applied. It opens with a header comment naming the retired Viewer role, the two
  system-actor events (``user.deactivate``, ``invitation.revoke``) and
  ``users_role_check``.
- Its statements, in this order (Decision 1):
  1. ``INSERT INTO audit_events (org_id, actor_kind, action, target_type, target_ids,
     metadata) SELECT u.org_id, 'system', 'invitation.revoke', 'invitation',
     jsonb_build_array(i.id), jsonb_build_object('user_id', u.id, 'reason',
     'viewer_retired') FROM users u JOIN invitations i ON i.user_id = u.id WHERE
     u.role = 'viewer' AND u.status = 'invited' AND i.accepted_at IS NULL``: one row per
     pending Viewer invitation, expired or not (Decision 2), before the delete it
     describes;
  2. ``DELETE FROM users u USING invitations i WHERE i.user_id = u.id AND u.role =
     'viewer' AND u.status = 'invited' AND i.accepted_at IS NULL``: the invited accounts
     go (the foreign keys cascade to the invitation and its queued email, as ``DELETE
     /api/org/invitations/{id}`` does);
  3. ``INSERT INTO audit_events (...) SELECT u.org_id, 'system', 'user.deactivate',
     'user', jsonb_build_array(u.id), jsonb_build_object('reason', 'viewer_retired',
     'sessions_revoked', (SELECT count(*) FROM sessions s WHERE s.user_id = u.id)) FROM
     users u WHERE u.role = 'viewer'``: every remaining Viewer (active, deactivated or
     anything a direct write left), its sessions counted before they are deleted;
  4. ``DELETE FROM sessions s USING users u WHERE s.user_id = u.id AND u.role =
     'viewer'``;
  5. ``UPDATE users SET role = 'editor', status = 'deactivated' WHERE role =
     'viewer'``;
  6. ``ALTER TABLE users DROP CONSTRAINT users_role_check`` (no IF EXISTS, no CASCADE),
     then ``ADD CONSTRAINT users_role_check CHECK (role IN ('org_admin', 'editor'))``
     (validated: no NOT VALID), after the UPDATE.
  Every write selects Viewer rows only, so nothing else changes and an install without
  Viewers writes no audit row.
- The audit rows fit the shipped audit_events CHECKs and the Python catalog (Decision
  3): actor_kind ``system`` (an ActorKind) with no actor user and no IP; both actions in
  the shipped action catalog and in AuditAction, their scope admits the account's org;
  target types ``user`` / ``invitation`` (TargetType); metadata keys and string values
  that pass ``audit_events_metadata_check``. ``viewer_retired`` is written by the
  migration only: the Python metadata vocabulary doesn't gain it.
- The new CHECK's IN-list equals ``typing.get_args(admino.access.MemberRole)``.
- Nothing else: no other statement, no DO block, function, trigger, role, GRANT,
  REVOKE, CREATE, DROP TABLE / INDEX / COLUMN, TRUNCATE, COPY, MERGE, SET, NOT VALID,
  owner change or email (Decision 4), also not nested in a body or an EXECUTE literal;
  every table and function privilege after 0033 is what it was after 0032;
  ``audit_events_action_check`` is not touched.
- tests/db_fakes.py mirrors the narrowed CHECK: ``add_account``, the org-user role
  change UPDATE (``org_users._UPDATE_SQL``) and the invited account's INSERT
  (``invitations._INSERT_USER_SQL``) store exactly the shipped roles; any other role,
  ``viewer`` included, is a CheckViolationError that stores nothing.

Security notes:
- A retired Viewer is deactivated, never promoted: it keeps no session and stays out
  until an Org Admin reactivates it (an explicit grant of Editor).
- The audit rows are content-free: ids, a count and the fixed token ``viewer_retired``.
"""

from __future__ import annotations

import re
import uuid
from typing import TYPE_CHECKING, Any, Final, NamedTuple, get_args
from unittest.mock import AsyncMock

import asyncpg
import pytest

import admino.database as db_mod
from admino import access, audit_events, invitations, org_users
from tests.db_fakes import ORG_ID, FakeDb
from tests.test_migration_0018 import (
    _executed,
    _fragments,
    _load_migrations,
    _masked,
    _normalize,
    _split,
)
from tests.test_migration_0021 import _check_values
from tests.test_migration_0027 import _ALTER_RE, _apply, _unwrap
from tests.test_migration_0031 import _function_acl
from tests.test_migration_0032 import (
    _ADD_CHECK_RE,
    _DROP_RE,
    _REFERENCE_RE,
    _UPDATE_HEAD_RE,
    _and_parts,
    _canon,
    _closing,
    _top_level,
)

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME: Final = "0033_retire_viewer_role.sql"
_PREVIOUS_MIGRATION: Final = "0032_trash.sql"
_VERSION: Final = 33
_ROLE_CHECK: Final = "users_role_check"
_ACTION_CHECK: Final = "audit_events_action_check"
_METADATA_CHECK: Final = "audit_events_metadata_check"
_REASON: Final = "viewer_retired"
_RETIRED_ROLE: Final = "viewer"
_MEMBER_ROLES: Final = ("org_admin", "editor")
# The rules of audit_events_metadata_check (0005, kept by 0029's re-add): a key, and
# a string value.
_KEY_RULE: Final = "^[a-z][a-z0-9_]{0,39}$"
_STRING_RULE: Final = "^[a-z0-9_-]{1,64}$"

# The columns of the tables the statements read (migrations 0004, 0007, 0009, 0010,
# 0021): a bare column belongs to the one source table that has it.
_COLUMNS: Final[dict[str, frozenset[str]]] = {
    "users": frozenset(
        {
            "id",
            "email",
            "name",
            "password_hash",
            "kind",
            "org_id",
            "role",
            "status",
            "ui_language",
            "response_language",
            "timezone",
            "personal_instructions",
            "created_at",
            "last_login_at",
            "deleted_at",
        }
    ),
    "invitations": frozenset(
        {"id", "user_id", "token_hash", "created_at", "sent_at", "expires_at", "accepted_at"}
    ),
    "sessions": frozenset(
        {
            "id",
            "token_hash",
            "user_id",
            "created_at",
            "last_seen_at",
            "expires_at",
            "ip",
            "user_agent",
            "idle_timeout_minutes",
        }
    ),
    "audit_events": frozenset(
        {
            "id",
            "occurred_at",
            "org_id",
            "actor_user_id",
            "actor_kind",
            "action",
            "target_type",
            "target_ids",
            "ip",
            "metadata",
        }
    ),
}

# A SQL value that is one token: a '...' literal or a (resolved) name.
_ATOM: Final = r"(?:'(?:[^']|'')*'|[\w.?*]+)"
_EQUALITY_RE: Final = re.compile(rf"(?P<left>{_ATOM}) = (?P<right>{_ATOM})")
_INSERT_RE: Final = re.compile(
    r'insert into (?:"?public"?\.)?"?(?P<table>\w+)"? ?\((?P<columns>[^()]*)\) ?(?P<query>.+)'
)
_DELETE_RE: Final = re.compile(
    r'delete from (?:only )?(?:"?public"?\.)?"?(?P<table>\w+)"?'
    r'(?: (?:as )?"?(?P<alias>(?!using\b|where\b|returning\b)\w+)"?)?(?P<rest>(?: .*)?)'
)
# One FROM / USING item: a table with an optional alias and an optional ON condition.
_SOURCE_RE: Final = re.compile(
    r'(?:only )?(?:"?public"?\.)?"?(?P<table>\w+)"?'
    r'(?: (?:as )?"?(?P<alias>(?!on\b)\w+)"?)?(?: on (?P<on>.+))?'
)
_JOIN_WORDS: Final = (
    r"natural (?:inner |left (?:outer )?|right (?:outer )?|full (?:outer )?)?join"
    r"|(?:inner |cross |left (?:outer )?|right (?:outer )?|full (?:outer )?)?join"
)
_QUERY_CLAUSES: Final = (
    "from|where|group by|having|order by|limit|offset|union|intersect|except|window"
    "|fetch|for|returning|on conflict"
)

# Fragments 0033 must not start with (top level, DO / function bodies, literals).
_FORBIDDEN: Final[dict[str, str]] = {
    "do": r"do\b",
    "grant": r"grant\b",
    "revoke": r"revoke\b",
    "truncate": r"truncate\b",
    "copy": r"copy\b",
    "merge": r"merge into\b",
    "create": r"create\b",
    "drop": r"drop\b",
    "set": r"(?:set|reset)\b",
    "function": r"(?:alter|drop) (?:function|procedure|routine)\b",
    "role": r"alter (?:role|user|group)\b",
    "default privileges": r"alter default privileges\b",
    "call": r"call\b",
}
# Fragments 0033 must not contain anywhere.
_FORBIDDEN_ANYWHERE: Final[dict[str, str]] = {
    "security definer": r"\bsecurity definer\b",
    "owner change": r"\bowner to\b",
    "trigger switch": r"\b(?:disable|enable) (?:always |replica )?trigger\b",
    "replication role": r"\bsession_replication_role\b",
    "not valid": r"\bnot valid\b",
    "email": r"\bemail_outbox\b",
    "drop column": r"\bdrop column\b",
}


class _Query(NamedTuple):
    """A SELECT read: its items, sources, conditions and anything unexpected."""

    items: tuple[Any, ...]
    sources: frozenset[tuple[str, str]]
    conditions: frozenset[str]
    unexpected: tuple[str, ...]


class _Insert(NamedTuple):
    table: str
    values: dict[str, Any]
    sources: frozenset[tuple[str, str]]
    conditions: frozenset[str]
    unexpected: tuple[str, ...]


class _Delete(NamedTuple):
    table: str
    sources: frozenset[tuple[str, str]]
    conditions: frozenset[str]
    unexpected: tuple[str, ...]


class _Update(NamedTuple):
    table: str
    values: dict[str, Any]
    sources: frozenset[tuple[str, str]]
    conditions: frozenset[str]
    unexpected: tuple[str, ...]


class _Step(NamedTuple):
    label: str
    form: Any


# A scope level: the aliases (or table names) it names, and its tables.
_Frame = tuple[dict[str, str], tuple[str, ...]]

_VIEWER: Final = "'viewer' = users.role"
_PENDING_INVITATION: Final = frozenset(
    {
        "invitations.user_id = users.id",
        _VIEWER,
        "'invited' = users.status",
        "invitations.accepted_at is null",
    }
)
_USERS_AND_INVITATIONS: Final = frozenset({("users", "inner"), ("invitations", "inner")})

_CONTRACT_ORDER: Final = (
    "audit invitation.revoke",
    "delete users",
    "audit user.deactivate",
    "delete sessions",
    "update users",
    f"drop users.{_ROLE_CHECK}",
    f"check users.{_ROLE_CHECK}",
)
_REVOKE_AUDIT: Final = _Insert(
    table="audit_events",
    values={
        "org_id": "users.org_id",
        "actor_kind": "'system'",
        "action": "'invitation.revoke'",
        "target_type": "'invitation'",
        "target_ids": ("jsonb_build_array", ("invitations.id",)),
        "metadata": (
            "jsonb_build_object",
            (("'reason'", f"'{_REASON}'"), ("'user_id'", "users.id")),
        ),
    },
    sources=_USERS_AND_INVITATIONS,
    conditions=_PENDING_INVITATION,
    unexpected=(),
)
_INVITED_DELETE: Final = _Delete(
    table="users",
    sources=frozenset({("invitations", "inner")}),
    conditions=_PENDING_INVITATION,
    unexpected=(),
)
_DEACTIVATE_AUDIT: Final = _Insert(
    table="audit_events",
    values={
        "org_id": "users.org_id",
        "actor_kind": "'system'",
        "action": "'user.deactivate'",
        "target_type": "'user'",
        "target_ids": ("jsonb_build_array", ("users.id",)),
        "metadata": (
            "jsonb_build_object",
            (
                ("'reason'", f"'{_REASON}'"),
                (
                    "'sessions_revoked'",
                    _Query(
                        items=(("count", ("*",)),),
                        sources=frozenset({("sessions", "inner")}),
                        conditions=frozenset({"sessions.user_id = users.id"}),
                        unexpected=(),
                    ),
                ),
            ),
        ),
    },
    sources=frozenset({("users", "inner")}),
    conditions=frozenset({_VIEWER}),
    unexpected=(),
)
_SESSIONS_DELETE: Final = _Delete(
    table="sessions",
    sources=frozenset({("users", "inner")}),
    conditions=frozenset({"sessions.user_id = users.id", _VIEWER}),
    unexpected=(),
)
_ROLE_UPDATE: Final = _Update(
    table="users",
    values={"role": "'editor'", "status": "'deactivated'"},
    sources=frozenset(),
    conditions=frozenset({_VIEWER}),
    unexpected=(),
)

# Roles a write may name: the member roles, the retired one, and near misses.
_CANDIDATE_ROLES: Final = ("org_admin", "editor", "viewer", "super_admin", "Editor", "")


# ---------------------------------------------------------------------------
# Helpers: the shipped SQL
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _raw_sql() -> str:
    path = _migration_path()
    assert path.is_file(), f"{_MIGRATION_NAME} is not shipped"
    return path.read_text(encoding="utf-8")


def _statements() -> list[str]:
    """The statements 0033 runs (top level and DO blocks), normalized."""
    return _executed(_normalize(_raw_sql()))


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


def _role_check_values() -> list[str]:
    """The literals of 0033's ``users_role_check`` IN-list, in written order."""
    _raw_sql()
    return _check_values(_MIGRATION_NAME, _ROLE_CHECK, "role")


def _resolved(text: str, frames: list[_Frame]) -> str:
    """``text`` with every column reference written as ``<table>.<column>``.

    A qualifier is looked up from the innermost scope outwards (an alias hides its
    table's name, as in PostgreSQL); a bare column belongs to the one table of the
    innermost scope that has it (``?name`` when two do). An unknown qualifier stays
    visible as ``?<qualifier>``.
    """

    def replace(match: re.Match[str]) -> str:
        qualifier, name = match.group("qualifier"), match.group("name")
        if qualifier is not None:
            for aliases, _ in frames:
                if qualifier in aliases:
                    return f"{aliases[qualifier]}.{name}"
            return f"?{qualifier}.{name}"
        for _, tables in frames:
            owners = [table for table in tables if name in _COLUMNS.get(table, ())]
            if len(owners) == 1:
                return f"{owners[0]}.{name}"
            if owners:
                return f"?{name}"
        return match.group(0)

    masked = _masked(text)
    out: list[str] = []
    position = 0
    for match in _REFERENCE_RE.finditer(masked):
        out.append(text[position : match.start()])
        out.append(replace(match))
        position = match.end()
    out.append(text[position:])
    return _canon("".join(out))


def _condition(text: str, frames: list[_Frame]) -> str:
    """One condition, its references resolved; ``a = b`` with its sides sorted."""
    resolved = _resolved(_unwrap(text), frames)
    sides = _EQUALITY_RE.fullmatch(resolved)
    if sides is not None:
        return " = ".join(sorted((sides.group("left"), sides.group("right"))))
    return resolved


def _value(text: str, frames: list[_Frame]) -> Any:
    """A written value: a scalar sub-select as a _Query, a function call as (name,
    arguments) (``jsonb_build_object`` as its sorted key/value pairs), else the
    resolved expression."""
    text = _unwrap(text)
    masked = _masked(text)
    if re.match(r"select\b", masked):
        return _query(text, frames)
    call = re.match(r"(?P<name>[a-z_]\w*) ?\(", masked)
    if call is not None and _closing(masked, call.end() - 1) == len(masked) - 1:
        name = call.group("name")
        arguments = [_value(item, frames) for item in _split(text[call.end() : -1], ",")]
        if name != "jsonb_build_object":
            return (name, tuple(arguments))
        if len(arguments) % 2:
            return (name, ("odd argument count", *arguments))
        pairs = zip(arguments[::2], arguments[1::2], strict=True)
        return (name, tuple(sorted(pairs, key=lambda pair: repr(pair[0]))))
    return _resolved(text, frames)


def _sources(
    text: str, outer: list[_Frame]
) -> tuple[_Frame, frozenset[tuple[str, str]], list[str], list[str]]:
    """(scope, {(table, join kind)}, ON conditions, unexpected) of a FROM / USING list.

    A comma, JOIN, INNER JOIN or CROSS JOIN is an inner join (its ON conditions count
    as WHERE conditions); any other join keeps its keyword as its kind.
    """
    aliases: dict[str, str] = {}
    tables: list[str] = []
    sources: set[tuple[str, str]] = set()
    on_conditions: list[str] = []
    unexpected: list[str] = []
    for item in _split(text, ","):
        masked = _masked(item)
        joins = _top_level(masked, _JOIN_WORDS)
        starts = [0, *[join.end() for join in joins]]
        ends = [*[join.start() for join in joins], len(item)]
        kinds = ["inner", *[join.group(0) for join in joins]]
        for start, end, kind in zip(starts, ends, kinds, strict=True):
            piece = item[start:end].strip()
            match = _SOURCE_RE.fullmatch(_masked(piece))
            if match is None:
                unexpected.append(f"source {piece}")
                continue
            table = match.group("table")
            aliases[match.group("alias") or table] = table
            tables.append(table)
            normal = "inner" if kind in ("inner", "join", "inner join", "cross join") else kind
            sources.add((table, normal))
            if match.group("on") is not None:
                on = piece[match.start("on") : match.end("on")]
                if normal == "inner":
                    on_conditions.extend(_and_parts(on))
                else:
                    unexpected.append(f"{kind} on {on}")
    del outer
    return (aliases, tuple(tables)), frozenset(sources), on_conditions, unexpected


def _clause_text(text: str, clauses: list[re.Match[str]], word: str) -> str | None:
    """The text after the top-level keyword ``word`` up to the next clause."""
    for index, token in enumerate(clauses):
        if token.group(0) == word:
            end = clauses[index + 1].start() if index + 1 < len(clauses) else len(text)
            return text[token.end() : end]
    return None


def _query(text: str, outer: list[_Frame]) -> _Query:
    """``SELECT items FROM sources [WHERE conditions]`` read."""
    masked = _masked(text)
    head = re.match(r"select (?P<distinct>(?:distinct|all)\b ?)?", masked)
    if head is None:
        return _Query((), frozenset(), frozenset(), (f"unreadable {text}",))
    clauses = _top_level(masked, _QUERY_CLAUSES)
    unexpected = [token.group(0) for token in clauses if token.group(0) not in ("from", "where")]
    if head.group("distinct"):
        unexpected.append(head.group("distinct").strip())
    if [token.group(0) for token in clauses].count("from") != 1:
        unexpected.append("from count")
    items_end = clauses[0].start() if clauses else len(text)
    from_text = _clause_text(text, clauses, "from") or ""
    frame, sources, on_conditions, more = _sources(from_text, outer)
    unexpected.extend(more)
    frames = [frame, *outer]
    where = _clause_text(text, clauses, "where")
    parts = [*on_conditions, *(_and_parts(where) if where else [])]
    items = tuple(_value(item, frames) for item in _split(text[head.end() : items_end], ","))
    return _Query(
        items=items,
        sources=sources,
        conditions=frozenset(_condition(part, frames) for part in parts),
        unexpected=tuple(unexpected),
    )


def _insert(statement: str) -> _Insert:
    """``INSERT INTO t (columns) SELECT ...`` read: each column with its value."""
    match = _INSERT_RE.fullmatch(_masked(statement))
    assert match is not None, f"the test can't read the INSERT {statement!r}"
    columns = [
        name.strip().strip('"')
        for name in _split(statement[match.start("columns") : match.end("columns")], ",")
    ]
    query_text = statement[match.start("query") :]
    if not re.match(r"select\b", _masked(query_text)):
        return _Insert(match.group("table"), {}, frozenset(), frozenset(), (query_text,))
    query = _query(query_text, [])
    unexpected = list(query.unexpected)
    if len(columns) != len(set(columns)) or len(columns) != len(query.items):
        unexpected.append(f"{len(columns)} columns for {len(query.items)} values")
    return _Insert(
        table=match.group("table"),
        values=dict(zip(columns, query.items, strict=False)),
        sources=query.sources,
        conditions=query.conditions,
        unexpected=tuple(unexpected),
    )


def _delete(statement: str) -> _Delete:
    """``DELETE FROM t [alias] [USING ...] [WHERE ...]`` read."""
    masked = _masked(statement)
    match = _DELETE_RE.fullmatch(masked)
    assert match is not None, f"the test can't read the DELETE {statement!r}"
    table = match.group("table")
    rest = statement[match.start("rest") :]
    clauses = _top_level(_masked(rest), "using|where|returning")
    unexpected = [token.group(0) for token in clauses if token.group(0) not in ("using", "where")]
    using_text = _clause_text(rest, clauses, "using")
    (aliases, tables), sources, on_conditions, more = _sources(using_text or "", [])
    unexpected.extend(more)
    frame: _Frame = ({**aliases, match.group("alias") or table: table}, (table, *tables))
    where = _clause_text(rest, clauses, "where")
    parts = [*on_conditions, *(_and_parts(where) if where else [])]
    return _Delete(
        table=table,
        sources=sources,
        conditions=frozenset(_condition(part, [frame]) for part in parts),
        unexpected=tuple(unexpected),
    )


def _update(statement: str) -> _Update:
    """``UPDATE t [alias] SET ... [FROM ...] [WHERE ...]`` read."""
    head = _UPDATE_HEAD_RE.fullmatch(_masked(statement))
    assert head is not None, f"the test can't read the UPDATE {statement!r}"
    table = head.group("table")
    rest = statement[head.start("rest") :]
    clauses = _top_level(_masked(rest), "from|where|returning")
    unexpected = [token.group(0) for token in clauses if token.group(0) not in ("from", "where")]
    (aliases, tables), sources, on_conditions, more = _sources(
        _clause_text(rest, clauses, "from") or "", []
    )
    unexpected.extend(more)
    frame: _Frame = ({**aliases, head.group("alias") or table: table}, (table, *tables))
    set_end = clauses[0].start() if clauses else len(rest)
    values: dict[str, Any] = {}
    for item in _split(rest[:set_end], ","):
        assignment = re.fullmatch(r'"?(\w+)"? ?= ?(.+)', item.strip())
        if assignment is None:
            unexpected.append(f"assignment {item}")
            continue
        values[assignment.group(1)] = _value(assignment.group(2), [frame])
    where = _clause_text(rest, clauses, "where")
    parts = [*on_conditions, *(_and_parts(where) if where else [])]
    return _Update(
        table=table,
        values=values,
        sources=sources,
        conditions=frozenset(_condition(part, [frame]) for part in parts),
        unexpected=tuple(unexpected),
    )


def _literal(value: Any) -> str | None:
    """The text of a '...' literal value, else None."""
    if isinstance(value, str) and re.fullmatch(r"'(?:[^']|'')*'", value):
        return value[1:-1].replace("''", "'")
    return None


def _alter_steps(statement: str) -> list[_Step] | None:
    """One step per ALTER TABLE action (a plain DROP CONSTRAINT, a validated ADD
    CONSTRAINT ... CHECK); None if the statement isn't an ALTER TABLE."""
    alter = _ALTER_RE.fullmatch(_masked(statement))
    if alter is None:
        return None
    table = alter.group("table")
    steps: list[_Step] = []
    for action in _split(statement[alter.start("actions") :], ","):
        masked = _masked(action)
        if (drop := _DROP_RE.fullmatch(masked)) is not None:
            steps.append(_Step(f"drop {table}.{drop.group('name')}", action))
        elif (added := _ADD_CHECK_RE.fullmatch(masked)) is not None:
            steps.append(_Step(f"check {table}.{added.group('name')}", action))
        else:
            steps.append(_Step(f"other: alter table {table} {action}", action))
    return steps


def _steps() -> list[_Step]:
    """What 0033 does, in order: each write read into its form, each ALTER TABLE
    action one by one; anything else as ``other: ...``."""
    steps: list[_Step] = []
    for statement in _statements():
        masked = _masked(statement)
        if re.match(r"insert into\b", masked):
            form = _insert(statement)
            action = _literal(form.values.get("action"))
            is_audit = form.table == "audit_events" and action is not None
            steps.append(_Step(f"audit {action}" if is_audit else f"insert {form.table}", form))
        elif re.match(r"delete from\b", masked):
            deleted = _delete(statement)
            steps.append(_Step(f"delete {deleted.table}", deleted))
        elif re.match(r"update\b", masked):
            updated = _update(statement)
            steps.append(_Step(f"update {updated.table}", updated))
        elif (alters := _alter_steps(statement)) is not None:
            steps.extend(alters)
        else:
            steps.append(_Step(f"other: {statement}", statement))
    return steps


def _forms(label: str) -> list[Any]:
    """The read forms of every step with this label."""
    steps = _steps()
    assert steps, f"{_MIGRATION_NAME} runs nothing"
    return [step.form for step in steps if step.label == label]


def _acl(up_to: int) -> dict[tuple[str, str], frozenset[str]]:
    """(table, grantee) -> ACL entries after every shipped migration up to a version."""
    acl: dict[tuple[str, str], set[str]] = {}
    for migration in _load_migrations(db_mod._MIGRATIONS_DIR):
        if migration.version > up_to:
            continue
        for statement in _executed(_normalize(migration.sql)):
            _apply(acl, statement)
    return {key: frozenset(value) for key, value in acl.items() if value}


def _latest_adding(constraint: str) -> str:
    """The last shipped migration that (re-)adds ``constraint``, normalized."""
    found = [
        migration
        for migration in _load_migrations(db_mod._MIGRATIONS_DIR)
        if re.search(rf"\badd constraint {constraint}\b", _normalize(migration.sql))
    ]
    assert found, f"no shipped migration adds {constraint}"
    return found[-1].name


def _shipped_action_catalog() -> frozenset[str]:
    """The literals of the action catalog in force after every shipped migration."""
    return frozenset(_check_values(_latest_adding(_ACTION_CHECK), _ACTION_CHECK, "action"))


def _metadata_check_text() -> str:
    """The SQL of the last shipped migration that re-adds the metadata CHECK."""
    name = _latest_adding(_METADATA_CHECK)
    return _normalize((db_mod._MIGRATIONS_DIR / name).read_text(encoding="utf-8"))


def _fullmatch_rule(rule: str, value: str) -> bool:
    """A like_regex rule anchored with ^...$, applied as PostgreSQL does (its ``$`` is
    the end of the text, never before a final newline)."""
    assert rule.startswith("^") and rule.endswith("$"), rule
    return re.fullmatch(rule[1:-1], value) is not None


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0033File:
    """The migration ships as version 33, right after 0032, and is applied once."""

    def test_migration_0033_file_is_the_only_version_33_after_versions_1_to_32(self) -> None:
        shipped = [
            (int(m.group(1)), path.name)
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name))
        ]

        assert [name for version, name in shipped if version == _VERSION] == [_MIGRATION_NAME]
        assert sorted(version for version, _ in shipped if version < _VERSION) == list(
            range(1, _VERSION)
        )

    async def test_migration_0033_run_migrations_applies_and_records_it(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0032 applied, run_migrations executes the file and records 33."""
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

    async def test_migration_0033_runs_after_0032(self, mock_pool: MagicMock) -> None:
        """With 0001 to 0031 applied, 0032 (GH-194's trash) runs before 0033."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION - 1)])
        previous = (db_mod._MIGRATIONS_DIR / _PREVIOUS_MIGRATION).read_text(encoding="utf-8")
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert previous in executed
        assert shipped in executed
        assert executed.index(previous) < executed.index(shipped)

    async def test_migration_0033_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0033 applied, the file isn't executed."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0033_opens_with_a_header_comment_naming_what_it_changes(self) -> None:
        """What and why, before any statement: the retired Viewer role, the two events
        written with the system actor, and the narrowed users_role_check."""
        lines = _header_lines()
        header = " ".join(lines)

        assert len(lines) >= 3
        assert {
            "names the viewer role": re.search(r"\bviewers?\b", header, re.IGNORECASE) is not None,
            "names user.deactivate": "user.deactivate" in header,
            "names invitation.revoke": "invitation.revoke" in header,
            "names the system actor": re.search(r"\bsystem\b", header) is not None,
            "names the constraint": _ROLE_CHECK in header,
        } == dict.fromkeys(
            (
                "names the viewer role",
                "names user.deactivate",
                "names invitation.revoke",
                "names the system actor",
                "names the constraint",
            ),
            True,
        )


# ---------------------------------------------------------------------------
# 2. The statements and their order (Decisions 1 and 2)
# ---------------------------------------------------------------------------


class TestMigration0033Statements:
    """The six steps of Decision 1, each selecting the Viewer rows it is about."""

    def test_migration_0033_runs_the_decided_steps_in_order(self) -> None:
        """Every statement (top level and DO blocks), ALTER TABLE actions one by one:
        the invitation.revoke rows before the invited accounts are deleted, then the
        user.deactivate rows (sessions counted) before the sessions are deleted, then the
        role and status change, then the CHECK dropped and added again. Nothing else,
        nothing twice."""
        assert [step.label for step in _steps()] == list(_CONTRACT_ORDER)

    def test_migration_0033_records_invitation_revoke_for_each_pending_viewer_invitation(
        self,
    ) -> None:
        """One audit row per invitations row with accepted_at IS NULL (expired or not)
        whose account is an invited Viewer: in the account's org, system actor (no user,
        no IP), target the invitation, metadata the invited user id and the reason."""
        assert _forms("audit invitation.revoke") == [_REVOKE_AUDIT]

    def test_migration_0033_deletes_the_invited_viewer_accounts(self) -> None:
        """DELETE FROM users USING invitations with the same four conditions: the
        foreign keys cascade to the invitation and its queued email."""
        assert _forms("delete users") == [_INVITED_DELETE]

    def test_migration_0033_records_user_deactivate_for_each_remaining_viewer(self) -> None:
        """One audit row per remaining users row with role viewer, whatever its status:
        in its org, system actor, target the user, metadata the reason and the count of
        the user's sessions (all of them: the next step deletes all of them)."""
        assert _forms("audit user.deactivate") == [_DEACTIVATE_AUDIT]

    def test_migration_0033_deletes_every_viewer_session(self) -> None:
        """DELETE FROM sessions USING users WHERE the session is a Viewer's: every
        session ends, as with POST /api/org/users/{id}/deactivate."""
        assert _forms("delete sessions") == [_SESSIONS_DELETE]

    def test_migration_0033_stores_every_viewer_as_a_deactivated_editor(self) -> None:
        """UPDATE users SET role = 'editor', status = 'deactivated' WHERE role = 'viewer':
        nothing else is set, no other filter, no FROM or RETURNING."""
        assert _forms("update users") == [_ROLE_UPDATE]

    def test_migration_0033_every_write_selects_viewer_rows_only(self) -> None:
        """Each INSERT, DELETE and UPDATE has role = 'viewer' among its AND-ed
        conditions: no other account changes, and an install without Viewers writes no
        audit row."""
        writes = {
            step.label: _VIEWER in step.form.conditions
            for step in _steps()
            if isinstance(step.form, _Insert | _Delete | _Update)
        }

        assert writes == dict.fromkeys(_CONTRACT_ORDER[:5], True)


# ---------------------------------------------------------------------------
# 3. The narrowed users_role_check (Decision 1, step 6)
# ---------------------------------------------------------------------------


class TestMigration0033RoleCheck:
    """users_role_check allows org_admin and editor only, after the Viewers are gone."""

    def test_migration_0033_replaces_users_role_check_with_the_two_member_roles(self) -> None:
        """A plain DROP (no IF EXISTS, no CASCADE) and one validated ADD of the same name
        on users, exactly CHECK (role IN ('org_admin', 'editor')), each role once."""
        users_steps = [step.label for step in _steps() if step.label.startswith(("drop", "check"))]

        assert users_steps == [f"drop users.{_ROLE_CHECK}", f"check users.{_ROLE_CHECK}"]
        assert sorted(_role_check_values()) == sorted(_MEMBER_ROLES)

    def test_migration_0033_role_check_matches_member_role(self) -> None:
        """The SQL IN-list equals access.MemberRole's values (Decision 6): Principal,
        TenantContext and the database accept the same roles."""
        assert sorted(_role_check_values()) == sorted(get_args(access.MemberRole))


# ---------------------------------------------------------------------------
# 4. The audit rows fit the schema and the catalog (Decision 3)
# ---------------------------------------------------------------------------


class TestMigration0033AuditRows:
    """The rows the two INSERTs write pass audit_events' CHECKs and match the catalog."""

    def test_migration_0033_audit_rows_satisfy_the_shipped_checks_and_catalog(self) -> None:
        """For both INSERTs: actor_kind 'system' (an ActorKind; no actor_user_id or ip
        column, so both NULL as audit_events_actor_user_check wants); the action in the
        shipped action catalog and in AuditAction, scoped to an org (or any) and written
        with the account's org; the target type a TargetType; every metadata key and
        string value passing audit_events_metadata_check (a UUID string too). The
        reason token is the migration's alone: METADATA_VOCABULARY doesn't hold it."""
        metadata_sql = _metadata_check_text()
        catalog = _shipped_action_catalog()
        facts: dict[str, dict[str, Any]] = {}
        for step in _steps():
            if not isinstance(step.form, _Insert) or step.form.table != "audit_events":
                continue
            values = step.form.values
            action = _literal(values.get("action")) or ""
            target_type = _literal(values.get("target_type"))
            name, pairs = values.get("metadata", ("", ()))
            keys = [_literal(key) or "" for key, _ in pairs]
            strings = [text for _, value in pairs if (text := _literal(value)) is not None]
            facts[action] = {
                "actor_kind": _literal(values.get("actor_kind")),
                "actor is an ActorKind": _literal(values.get("actor_kind"))
                in get_args(audit_events.ActorKind),
                "names actor_user_id or ip": bool({"actor_user_id", "ip"} & set(values)),
                "in the shipped catalog": action in catalog,
                "an AuditAction": action in {member.value for member in audit_events.AuditAction},
                "org scope with the account's org": (
                    audit_events.ACTION_SCOPES.get(audit_events.AuditAction(action))
                    in ("org", "any")
                    if action in set(audit_events.AuditAction)
                    else False
                )
                and values.get("org_id") == "users.org_id",
                "a TargetType": target_type in {member.value for member in audit_events.TargetType},
                "metadata object": name == "jsonb_build_object",
                "keys pass": all(_fullmatch_rule(_KEY_RULE, key) for key in keys),
                "strings pass": bool(strings)
                and all(_fullmatch_rule(_STRING_RULE, text) for text in strings),
            }

        assert {
            "key rule shipped": f'like_regex "{_KEY_RULE}"' in metadata_sql,
            "string rule shipped": f'like_regex "{_STRING_RULE}"' in metadata_sql,
            "a uuid passes": _fullmatch_rule(_STRING_RULE, str(uuid.uuid4())),
            "reason not in the vocabulary": _REASON not in audit_events.METADATA_VOCABULARY,
        } == {
            "key rule shipped": True,
            "string rule shipped": True,
            "a uuid passes": True,
            "reason not in the vocabulary": True,
        }
        assert facts == {
            action: {
                "actor_kind": "system",
                "actor is an ActorKind": True,
                "names actor_user_id or ip": False,
                "in the shipped catalog": True,
                "an AuditAction": True,
                "org scope with the account's org": True,
                "a TargetType": True,
                "metadata object": True,
                "keys pass": True,
                "strings pass": True,
            }
            for action in ("invitation.revoke", "user.deactivate")
        }


# ---------------------------------------------------------------------------
# 5. Nothing else (Decisions 1 and 4)
# ---------------------------------------------------------------------------


class TestMigration0033Scope:
    """Only the writes and the CHECK: no code, no privilege, no catalog, no email."""

    def test_migration_0033_runs_no_code_privilege_or_schema_change(self) -> None:
        """No DO block, function, trigger, role, GRANT, REVOKE, CREATE, top-level DROP,
        TRUNCATE, COPY, MERGE, SET, CALL, SECURITY DEFINER, owner change, trigger switch,
        replication role, NOT VALID, DROP COLUMN or email_outbox, also not nested in a
        body or an EXECUTE literal."""
        fragments = _fragments(_normalize(_raw_sql()))
        offenders = [
            (kind, fragment)
            for fragment in fragments
            for kind, pattern in _FORBIDDEN.items()
            if re.match(pattern, _masked(fragment))
        ] + [
            (kind, fragment)
            for fragment in fragments
            for kind, pattern in _FORBIDDEN_ANYWHERE.items()
            if re.search(pattern, _masked(fragment))
        ]

        assert fragments, f"{_MIGRATION_NAME} runs nothing"
        assert offenders == []

    def test_migration_0033_changes_no_table_or_function_privilege(self) -> None:
        """Every (table, grantee) and every function's EXECUTE holds after 0033 what it
        held after 0032."""
        versions = [m.version for m in _load_migrations(db_mod._MIGRATIONS_DIR)]

        assert _VERSION in versions, f"{_MIGRATION_NAME} is not shipped"
        assert _acl(_VERSION) == _acl(_VERSION - 1)
        assert _function_acl(_VERSION) == _function_acl(_VERSION - 1)

    def test_migration_0033_leaves_the_action_catalog_alone(self) -> None:
        """audit_events_action_check isn't named (both actions are in it already): the
        catalog in force after 0033 is 0032's."""
        sql = _normalize(_raw_sql())

        assert re.search(rf"\b{_ACTION_CHECK}\b", sql) is None
        assert _latest_adding(_ACTION_CHECK) == _PREVIOUS_MIGRATION


# ---------------------------------------------------------------------------
# 6. tests/db_fakes.py mirrors the narrowed CHECK (Decision 5)
# ---------------------------------------------------------------------------


async def _write_role(db: FakeDb, entry: str, role: str) -> uuid.UUID:
    """Write ``role`` through one entry point; return the account written."""
    if entry == "add_account":
        return db.add_account(org_id=ORG_ID, role=role)
    if entry == "role_change_update":
        target = db.add_account(org_id=ORG_ID, role="org_admin" if role == "editor" else "editor")
        await db.pool.fetch(org_users._UPDATE_SQL, role, None, None, target, ORG_ID)
        return target
    assert entry == "invitation_insert", entry
    row = await db.pool.fetchrow(
        invitations._INSERT_USER_SQL, "invitee@example.test", ORG_ID, role, "de"
    )
    return uuid.UUID(str(row["id"]))


class TestMigration0033FakeDb:
    """The FakeDb's users table takes exactly the roles 0033's CHECK allows."""

    @pytest.mark.parametrize("entry", ["add_account", "role_change_update", "invitation_insert"])
    async def test_migration_0033_fake_stores_exactly_the_shipped_roles(self, entry: str) -> None:
        """The seed helper, the org-user role change's UPDATE (a forged value past the
        API) and the invited account's INSERT: a role in the shipped IN-list is stored;
        any other ('viewer' included) is a CheckViolationError and no users row holds
        it."""
        allowed = set(_role_check_values())
        outcomes: dict[str, str] = {}
        for role in _CANDIDATE_ROLES:
            db = FakeDb()
            db.add_org(ORG_ID)
            try:
                user_id = await _write_role(db, entry, role)
            except asyncpg.CheckViolationError:
                held = any(row["role"] == role for row in db.users.values())
                outcomes[role] = "refused, but stored" if held else "refused"
                continue
            outcomes[role] = "stored" if db.users[user_id]["role"] == role else "not stored"

        assert outcomes == {
            role: "stored" if role in allowed else "refused" for role in _CANDIDATE_ROLES
        }

    def test_migration_0033_fake_still_seeds_a_super_admin_without_a_role(self) -> None:
        """A Super Admin's role is NULL, which the CHECK passes: the seed works, with
        the role None, now that the fake follows the shipped IN-list."""
        allowed = set(_role_check_values())
        db = FakeDb()

        user_id = db.add_account(kind="super_admin", role=None)

        assert (allowed, db.users[user_id]["role"]) == (set(_MEMBER_ROLES), None)
