"""Tests for migration 0018_runtime_role.sql — the least-privilege runtime
database role (GH-220) — and the grant guard over every later migration.

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0017.py pattern): it must exist, be applied by
run_migrations as version 18, and make exactly the change GH-220 needs. The SQL
is read with ``--`` and ``/* */`` comments blanked; statements are split outside
parentheses, '...' literals and dollar-quoted bodies (a ``DO $$ ... $$`` block is
one statement); keywords are compared case-insensitively with whitespace
collapsed. Statements inside a dollar-quoted body, and dynamic SQL run from a
string literal (``EXECUTE format('...')``), are read as well, so nothing can hide
in a DO block.

What these tests pin down (0018):
- The role ``admino_app`` (``admino.database.RUNTIME_ROLE``) is created first,
  idempotently, in a DO block guarded by ``pg_roles`` / ``rolname =
  'admino_app'``; then ``ALTER ROLE admino_app WITH LOGIN NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS`` (exactly these six, any order). No
  PASSWORD anywhere (the migrate step sets a SCRAM verifier), no positive
  SUPERUSER / CREATEDB / CREATEROLE / REPLICATION / BYPASSRLS.
- Database: a DO block runs exactly ``REVOKE ALL ON DATABASE %I FROM PUBLIC`` and
  ``GRANT CONNECT ON DATABASE %I TO admino_app`` through ``format(...,
  current_database())``: CONNECT only, no TEMPORARY, nothing for PUBLIC.
- Schema: ``REVOKE CREATE ON SCHEMA public FROM PUBLIC`` and ``GRANT USAGE ON
  SCHEMA public TO admino_app``; never CREATE for the role.
- Tables: the (table -> privileges) map of every grant to admino_app equals the
  contract table exactly (``audit_events`` is SELECT, INSERT only), and covers
  every table that exists after 0001-0017 (CREATE / DROP TABLE replayed from the
  shipped files) plus ``_migrations``. No ALL, TRUNCATE, TRIGGER or REFERENCES,
  no bulk ``ON ALL TABLES``, no grant option, no grantee but admino_app.
- Functions: ``REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC``; the
  global ``ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`` (not
  the per-schema form, which cannot revoke a global default); both purge
  functions altered to SECURITY DEFINER with ``search_path = public, pg_temp``
  and nothing else; EXECUTE granted to admino_app on exactly those two.
- Nothing else: no OWNER TO, no role membership, no session_replication_role, no
  trigger change, no CREATE FUNCTION / TABLE, no data writes, no default table
  privileges, parameter-free. The header comment names both roles.

What the guard pins down (every shipped migration, now and later):
- A migration after 0018 that creates a table grants it to admino_app in the
  same file.
- No migration gives the app (admino_app, or PUBLIC, which every role is a
  member of) more than SELECT, INSERT on audit_events, nor ALL / TRUNCATE /
  TRIGGER / REFERENCES on anything.
- No migration makes admino_app an owner or a member of a role, gives it a
  superuser-class attribute, or lets it SET a superuser-only parameter.
- No migration grants anything through ALTER DEFAULT PRIVILEGES.
- Each guard is mutation-probed on a scratch copy of the migrations directory
  (tmp_path) holding a fake 0019, so a guard is shown to fail when violated and
  to accept a compliant migration.

Security notes:
- A superuser session can ``SET session_replication_role = replica`` (switching
  off the append-only trigger of audit_events), drop the trigger or ``COPY ... TO
  PROGRAM``. The app connects as admino_app, which owns nothing, so it can do
  none of these; the purges run as the owner through SECURITY DEFINER with a
  pinned search_path, so the trigger's call-stack check still lets them through.
- The guard reads grants hidden in DO blocks and EXECUTE strings too, and counts
  a grant to PUBLIC as a grant to the app.
"""

from __future__ import annotations

import re
import shutil
from typing import TYPE_CHECKING, NamedTuple
from unittest.mock import AsyncMock

import pytest

import admino.database as db_mod

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME = "0018_runtime_role.sql"
_VERSION = 18
_ROLE = "admino_app"
# admino_app as an SQL identifier (bare or quoted), not a prefix of a longer name.
_APP = r"(?:admino_app|\"admino_app\")(?![\w$])"
_AUDIT = "audit_events"
_APP_GRANTEES = frozenset({_ROLE, "public"})
_RUNTIME_ATTRIBUTES = (
    "login",
    "nosuperuser",
    "nocreatedb",
    "nocreaterole",
    "noreplication",
    "nobypassrls",
)
_POSITIVE_ATTRIBUTES = ("superuser", "createdb", "createrole", "replication", "bypassrls")
_FORBIDDEN_PRIVILEGES = ("all", "truncate", "trigger", "references")
_PURGE_FUNCTIONS = ("purge_audit_events(integer)", "purge_org_audit_events(uuid)")
_SEARCH_PATH = ("public", "pg_temp")
_FULL = frozenset({"select", "insert", "update", "delete"})
_NO_DELETE = frozenset({"select", "insert", "update"})
_EXPECTED_GRANTS: dict[str, frozenset[str]] = {
    "_migrations": frozenset({"select"}),
    _AUDIT: frozenset({"select", "insert"}),
    **dict.fromkeys(
        (
            "organizations",
            "users",
            "sessions",
            "email_outbox",
            "password_reset_tokens",
            "login_throttle",
            "user_settings",
            "oauth_tokens",
        ),
        _FULL,
    ),
    **dict.fromkeys(
        ("invitations", "platform_settings", "org_settings", "permissions", "memory"),
        _NO_DELETE,
    ),
}
_DATABASE_TEMPLATES = (
    "revoke all on database %i from public",
    "grant connect on database %i to admino_app",
)

# Top-level statement kinds of 0018 (see _kind).
_DO_ROLE = "do: create the role"
_ALTER_ROLE = "alter role"
_DO_DATABASE = "do: database privileges"
_REVOKE_SCHEMA_CREATE = "revoke create on schema public from public"
_GRANT_SCHEMA = "grant on schema"
_GRANT_TABLES = "grant on tables"
_REVOKE_FUNCTIONS = "revoke execute on all functions from public"
_DEFAULT_REVOKE = "default privileges: revoke execute from public"
_ALTER_FUNCTION = "alter function"
_GRANT_EXECUTE = "grant execute on functions"
_REQUIRED_KINDS = (
    _DO_ROLE,
    _ALTER_ROLE,
    _DO_DATABASE,
    _REVOKE_SCHEMA_CREATE,
    _GRANT_SCHEMA,
    _GRANT_TABLES,
    _REVOKE_FUNCTIONS,
    _DEFAULT_REVOKE,
    _ALTER_FUNCTION,
    _GRANT_EXECUTE,
)

_DOLLAR_TAG = re.compile(r"\$(?:[A-Za-z_]\w*)?\$")
_IDENT = r"(?:\"(?:[^\"]|\"\")+\"|[\w$]+)"
_QUALIFIED = rf"{_IDENT}(?:\s*\.\s*{_IDENT})?"
_CREATE_TABLE = re.compile(
    r"\bcreate\s+(?:(?:global|local)\s+)?(?P<temp>(?:temp|temporary)\s+)?(?:unlogged\s+)?"
    rf"table\s+(?:if\s+not\s+exists\s+)?(?P<name>{_QUALIFIED})"
)
_DROP_TABLE = re.compile(
    r"\bdrop\s+table\s+(?:if\s+exists\s+)?(?P<names>.+?)(?:\s+(?:cascade|restrict))?$"
)
_RENAME_TABLE = re.compile(
    rf"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?P<old>{_QUALIFIED})"
    rf"\s+rename\s+to\s+(?P<new>{_IDENT})$"
)
_GRANT_CLAUSE = re.compile(
    r"grant\s+(?P<what>.+?)\s+to\s+(?P<grantees>.+?)"
    r"(?P<option>\s+with\s+(?:grant|admin|inherit|set)\s+(?:option|true|false))?"
    r"(?:\s+granted\s+by\s+\S+)?"
)
_OBJECT_KINDS = (
    "schema",
    "database",
    "function",
    "procedure",
    "routine",
    "sequence",
    "parameter",
    "type",
    "domain",
    "language",
    "tablespace",
    "large object",
    "foreign data wrapper",
    "foreign server",
)
_ARG_MODES = frozenset({"in", "out", "inout", "variadic"})
_MULTIWORD_TYPE_STARTS = frozenset(
    {"double", "character", "timestamp", "time", "bit", "interval", "national"}
)
_TYPE_ALIASES = {"int": "integer", "int4": "integer"}
_FUNCTION_ACTION = re.compile(
    r"\s*(?:(?P<definer>(?:external\s+)?security\s+definer)"
    r"|set\s+search_path\s*(?:=|\bto\b)\s*(?P<path>[\w\"'$]+(?:\s*,\s*[\w\"'$]+)*))"
)
_ROLE_BLOCK = re.compile(
    r"begin\s+if\s+not\s+exists\s*\(\s*select\s+(?:(?:1|\*)\s+)?from\s+"
    r"(?:pg_catalog\s*\.\s*)?pg_roles\s+where\s+rolname\s*=\s*'admino_app'\s*\)\s*then\s+"
    r"create\s+role\s+admino_app\s*;\s*end\s+if\s*;\s*end\s*;?"
)
_EXECUTE_FORMAT = re.compile(
    r"execute\s+format\s*\(\s*'(?P<template>(?:[^']|'')*)'\s*,"
    r"\s*current_database\s*\(\s*\)\s*\)"
)
_GLOBAL_DEFAULT_REVOKE = re.compile(
    r"alter\s+default\s+privileges\s+revoke\s+execute\s+on\s+(?:functions|routines)"
    r"\s+from\s+public"
)

# (id, pattern) never found in 0018 outside comments; literals and DO bodies included.
_MUST_NOT: tuple[tuple[str, str], ...] = (
    ("password", r"\bpassword\b"),
    ("owner-to", r"\bowner\s+to\b"),
    ("reassign-owned", r"\breassign\s+owned\b"),
    ("session-replication-role", r"\bsession_replication_role\b"),
    ("trigger", r"\btrigger\b"),
    ("create-function", r"\bcreate\s+(?:or\s+replace\s+)?(?:function|procedure)\b"),
    (
        "create-table",
        r"\bcreate\s+(?:(?:global|local)\s+)?(?:(?:temp|temporary|unlogged)\s+)?table\b",
    ),
    ("drop", r"\bdrop\s+\w"),
    ("alter-table", r"\balter\s+table\b"),
    ("insert-into", r"\binsert\s+into\b"),
    ("update-set", r"\bupdate\s+(?:only\s+)?[\w.\"]+\s+set\b"),
    ("delete-from", r"\bdelete\s+from\b"),
    ("truncate", r"\btruncate\b"),
    ("copy", r"\bcopy\b"),
    # GRANT ALL [PRIVILEGES]; REVOKE ALL is fine.
    ("grant-all", r"\bgrant\s+all\b"),
    ("references", r"\breferences\b"),
    ("default-privileges-grant", r"\balter\s+default\s+privileges\b[^;]*\bgrant\b"),
    ("on-tables", r"\bon\s+tables\b"),
    ("on-all-tables", r"\bon\s+all\s+tables\b"),
    ("on-all-sequences", r"\bon\s+all\s+sequences\b"),
    ("in-role", r"\bin\s+(?:role|group)\b"),
    ("alter-group", r"\balter\s+group\b"),
    ("grant-option", r"\bwith\s+(?:grant|admin)\s+option\b"),
)


# ---------------------------------------------------------------------------
# Helpers: quote-aware reading of SQL (comments, literals, dollar quotes)
# ---------------------------------------------------------------------------


def _quote_end(text: str, start: int) -> int:
    """Index of the quote closing the one at start ('' and "" escape), or -1."""
    quote = text[start]
    position = start + 1
    while True:
        close = text.find(quote, position)
        if close < 0 or not text.startswith(quote, close + 1):
            return close
        position = close + 2


def _dollar_tag(text: str, start: int) -> str | None:
    """The $tag$ delimiter opening at start (never the tail of an identifier)."""
    if start > 0 and (text[start - 1].isalnum() or text[start - 1] in "_$"):
        return None
    match = _DOLLAR_TAG.match(text, start)
    return None if match is None else match.group(0)


def _normalize(sql: str) -> str:
    """SQL with comments blanked, whitespace collapsed, lowercased outside literals.

    '...' literals and "..." identifiers are kept byte for byte; a dollar-quoted
    body is normalized the same way (it is PL/pgSQL or SQL text).
    """
    out: list[str] = []
    index = 0
    while index < len(sql):
        char = sql[index]
        tag = _dollar_tag(sql, index) if char == "$" else None
        if char in "'\"":
            close = _quote_end(sql, index)
            stop = len(sql) if close < 0 else close + 1
            out.append(sql[index:stop])
            index = stop
        elif tag is not None:
            close = sql.find(tag, index + len(tag))
            stop = len(sql) if close < 0 else close
            body = _normalize(sql[index + len(tag) : stop])
            delimiter = tag.lower()
            out.append(f"{delimiter} {body} {delimiter}" if body else f"{delimiter} {delimiter}")
            index = len(sql) if close < 0 else close + len(tag)
        elif sql.startswith("--", index) or sql.startswith("/*", index):
            end_marker = "\n" if char == "-" else "*/"
            close = sql.find(end_marker, index + 2)
            index = len(sql) if close < 0 else close + len(end_marker)
            if out and out[-1] != " ":
                out.append(" ")
        elif char.isspace():
            if out and out[-1] != " ":
                out.append(" ")
            index += 1
        else:
            out.append(char.lower())
            index += 1
    return "".join(out).strip()


def _scan(text: str) -> tuple[str, list[str], list[str]]:
    """(masked text, literal contents, dollar-quoted bodies) of a normalized text.

    The masked text has the input's length, with the contents of '...' literals
    and of $tag$ bodies blanked; "..." identifiers are kept. Only the outermost
    literals and bodies are returned.
    """
    masked: list[str] = []
    literals: list[str] = []
    bodies: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        tag = _dollar_tag(text, index) if char == "$" else None
        if char in "'\"":
            close = _quote_end(text, index)
            stop = len(text) if close < 0 else close + 1
            if char == "'":
                inner_end = len(text) if close < 0 else close
                literals.append(text[index + 1 : inner_end].replace("''", "'"))
                masked.append("'" + " " * (inner_end - index - 1) + text[inner_end:stop])
            else:
                masked.append(text[index:stop])
            index = stop
        elif tag is not None:
            close = text.find(tag, index + len(tag))
            stop = len(text) if close < 0 else close
            end = len(text) if close < 0 else close + len(tag)
            bodies.append(text[index + len(tag) : stop])
            masked.append(tag + " " * (stop - index - len(tag)) + text[stop:end])
            index = end
        else:
            masked.append(char)
            index += 1
    return "".join(masked), literals, bodies


def _masked(text: str) -> str:
    return _scan(text)[0]


def _split(text: str, separator: str) -> list[str]:
    """Split text at a separator outside parentheses, literals and dollar quotes."""
    masked = _masked(text)
    items: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(masked):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == separator and depth == 0:
            items.append(text[start:index].strip())
            start = index + 1
    items.append(text[start:].strip())
    return [item for item in items if item]


def _fragments(text: str) -> list[str]:
    """Every statement of a normalized text, with those nested in it.

    Nested: the statements of each dollar-quoted body (DO blocks, function
    bodies) and of each '...' literal (dynamic SQL for EXECUTE), recursively.
    """
    result: list[str] = []
    for statement in _split(text, ";"):
        result.append(statement)
        _, literals, bodies = _scan(statement)
        for nested in [*bodies, *literals]:
            result.extend(_fragments(_normalize(nested)))
    return result


def _executed(text: str) -> list[str]:
    """The statements a migration runs: top-level ones and those of its DO blocks."""
    result: list[str] = []
    for statement in _split(text, ";"):
        result.append(statement)
        masked, _, bodies = _scan(statement)
        if re.match(r"do\b", masked):
            for body in bodies:
                result.extend(_executed(body))
    return result


# ---------------------------------------------------------------------------
# Helpers: names, tables and grants
# ---------------------------------------------------------------------------


def _name(raw: str) -> str:
    """An object name without quotes and without the public schema."""
    parts = [part.strip().strip('"') for part in raw.strip().split(".")]
    if len(parts) == 2 and parts[0] == "public":
        return parts[1]
    return ".".join(parts)


def _signature(raw: str) -> str:
    """A function as name(type, ...): argument modes and names dropped."""
    match = re.fullmatch(r"(?P<name>[^(\s]+)\s*\((?P<args>.*)\)", raw.strip())
    if match is None:
        return _name(raw)
    types: list[str] = []
    for argument in _split(match.group("args"), ","):
        tokens = argument.split()
        if tokens and tokens[0] in _ARG_MODES:
            tokens = tokens[1:]
        if len(tokens) >= 2 and tokens[0] not in _MULTIWORD_TYPE_STARTS:
            tokens = tokens[1:]
        type_name = " ".join(tokens)
        types.append(_TYPE_ALIASES.get(type_name, type_name))
    return f"{_name(match.group('name'))}({','.join(types)})"


def _replay(statements: Iterable[str], tables: set[str]) -> set[str]:
    """The tables after running CREATE / DROP / RENAME TABLE statements in order."""
    result = set(tables)
    for statement in statements:
        masked = _masked(statement)
        if (create := _CREATE_TABLE.search(masked)) is not None:
            if create.group("temp") is None:
                result.add(_name(create.group("name")))
        elif (drop := _DROP_TABLE.search(masked)) is not None:
            result.difference_update(_name(item) for item in _split(drop.group("names"), ","))
        elif (rename := _RENAME_TABLE.search(masked)) is not None:
            old = _name(rename.group("old"))
            if old in result:
                result.discard(old)
                result.add(_name(rename.group("new")))
    return result


class _Grant(NamedTuple):
    privileges: frozenset[str]
    kind: str
    objects: tuple[str, ...]
    grantees: frozenset[str]
    grant_option: bool


class _Membership(NamedTuple):
    roles: tuple[str, ...]
    grantees: frozenset[str]


def _privileges(raw: str) -> frozenset[str]:
    """Privilege names, column lists dropped; ALL PRIVILEGES is 'all'."""
    result: set[str] = set()
    for item in _split(raw, ","):
        privilege = re.sub(r"\s*\(.*\)$", "", item.strip())
        privilege = re.sub(r"\s+", " ", privilege)
        if privilege in ("all", "all privileges"):
            privilege = "all"
        elif privilege == "temp":
            privilege = "temporary"
        result.add(privilege)
    return frozenset(result)


def _grantees(raw: str) -> frozenset[str]:
    return frozenset(_name(re.sub(r"^group\s+", "", item.strip())) for item in _split(raw, ","))


def _target(text: str) -> tuple[str, tuple[str, ...]]:
    """(kind, objects) of a GRANT's ON clause; a bare name list is a table grant."""
    bulk = re.fullmatch(r"all\s+(\w+)\s+in\s+schema\s+(.+)", text)
    if bulk is not None:
        return f"all {bulk.group(1)}", tuple(_name(item) for item in _split(bulk.group(2), ","))
    for kind in _OBJECT_KINDS:
        match = re.fullmatch(r"\s+".join(kind.split()) + r"\s+(.+)", text)
        if match is not None:
            items = _split(match.group(1), ",")
            if kind in ("function", "procedure", "routine"):
                return kind, tuple(_signature(item) for item in items)
            return kind, tuple(_name(item) for item in items)
    names = re.sub(r"^table\s+", "", text)
    return "table", tuple(_name(item) for item in _split(names, ","))


def _grant_clauses(fragment: str) -> list[str]:
    """Each GRANT of a fragment, from the keyword to the fragment's end.

    ``WITH GRANT OPTION`` is not a GRANT; ALTER DEFAULT PRIVILEGES grants are
    read by their own guard.
    """
    masked = _masked(fragment)
    if re.search(r"\balter\s+default\s+privileges\b", masked):
        return []
    return [
        masked[match.start() :].strip()
        for match in re.finditer(r"\bgrant\b", masked)
        if re.search(r"\bwith\s+$", masked[: match.start()]) is None
    ]


def _parse_grants(fragments: Iterable[str]) -> tuple[list[_Grant], list[_Membership]]:
    """The privilege grants and the role-membership grants of the fragments."""
    grants: list[_Grant] = []
    memberships: list[_Membership] = []
    for fragment in fragments:
        for clause in _grant_clauses(fragment):
            match = _GRANT_CLAUSE.fullmatch(clause)
            if match is None:
                continue
            what = match.group("what")
            grantees = _grantees(match.group("grantees"))
            on = re.search(r"\s+on\s+", what)
            if on is None:
                roles = tuple(_name(item) for item in _split(what, ","))
                memberships.append(_Membership(roles, grantees))
                continue
            kind, objects = _target(what[on.end() :])
            grants.append(
                _Grant(
                    _privileges(what[: on.start()]),
                    kind,
                    objects,
                    grantees,
                    match.group("option") is not None,
                )
            )
    return grants, memberships


# ---------------------------------------------------------------------------
# Helpers: the shipped 0018
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _raw_sql() -> str:
    return _migration_path().read_text(encoding="utf-8")


def _normalized_sql() -> str:
    return _normalize(_raw_sql())


def _top_statements() -> list[str]:
    return _split(_normalized_sql(), ";")


def _all_fragments() -> list[str]:
    return _fragments(_normalized_sql())


def _full_text() -> str:
    """0018 without comments, literals and DO bodies included, all lowercase."""
    return _normalized_sql().lower()


def _header_comment() -> str:
    """The ``--`` comment lines before the first statement, joined."""
    lines: list[str] = []
    for line in _raw_sql().splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            lines.append(stripped[2:].strip())
        elif stripped:
            break
    return " ".join(lines)


def _kind(statement: str) -> str | None:
    """The contract kind of a top-level 0018 statement (None: not in the contract)."""
    masked = _masked(statement)
    if re.fullmatch(
        r"do\s+(?:language\s+plpgsql\s+)?(\$\w*\$).*\1(?:\s+language\s+plpgsql)?", masked
    ):
        body = _scan(statement)[2][0].lower()
        if re.search(r"\bcreate\s+role\b", body):
            return _DO_ROLE
        if re.search(r"\bon\s+database\b", body):
            return _DO_DATABASE
        return None
    if re.match(rf"alter\s+(?:role|user)\s+{_APP}", masked):
        return _ALTER_ROLE
    if masked == "revoke create on schema public from public":
        return _REVOKE_SCHEMA_CREATE
    if re.fullmatch(
        r"revoke\s+execute\s+on\s+all\s+(?:functions|routines)\s+in\s+schema\s+public"
        r"\s+from\s+public",
        masked,
    ):
        return _REVOKE_FUNCTIONS
    if _GLOBAL_DEFAULT_REVOKE.fullmatch(masked):
        return _DEFAULT_REVOKE
    if re.match(r"alter\s+function\s", masked):
        return _ALTER_FUNCTION
    if re.match(r"grant\s", masked):
        grants, memberships = _parse_grants([statement])
        if memberships or len(grants) != 1:
            return None
        grant = grants[0]
        if grant.grantees != frozenset({_ROLE}) or grant.grant_option:
            return None
        return {"table": _GRANT_TABLES, "schema": _GRANT_SCHEMA, "function": _GRANT_EXECUTE}.get(
            grant.kind
        )
    return None


def _kinds() -> list[str | None]:
    return [_kind(statement) for statement in _top_statements()]


def _do_body(kind: str) -> str:
    """The normalized body of the one DO block of a kind."""
    bodies = [_scan(s)[2][0].strip() for s in _top_statements() if _kind(s) == kind]
    assert len(bodies) == 1, f"expected exactly one '{kind}' block, found {len(bodies)}"
    return bodies[0]


def _database_templates() -> list[str]:
    """The format() templates the database DO block executes (verbatim)."""
    templates: list[str] = []
    for statement in _split(_do_body(_DO_DATABASE), ";"):
        statement = re.sub(r"^begin\s+", "", statement)
        if statement == "end":
            continue
        match = _EXECUTE_FORMAT.fullmatch(statement)
        assert match is not None, f"unexpected statement in the database block: {statement}"
        templates.append(match.group("template").replace("''", "'"))
    return templates


def _template_key(template: str) -> str:
    key = re.sub(r"\s+", " ", template.strip().lower())
    return key.replace("all privileges", "all")


def _alter_role_options() -> list[str]:
    statements = [s for s in _top_statements() if _kind(s) == _ALTER_ROLE]
    assert len(statements) == 1, f"expected one ALTER ROLE {_ROLE}, found {len(statements)}"
    match = re.fullmatch(
        rf"alter\s+(?:role|user)\s+{_APP}(?:\s+with)?(?P<options>(?:\s+\w+)*)",
        _masked(statements[0]),
    )
    assert match is not None, f"ALTER ROLE sets more than role attributes: {statements[0]}"
    return match.group("options").split()


def _grants() -> list[_Grant]:
    return _parse_grants(_all_fragments())[0]


def _table_grant_map() -> dict[str, frozenset[str]]:
    """table -> privileges granted to admino_app, over every grant of 0018."""
    result: dict[str, frozenset[str]] = {}
    for grant in _grants():
        if grant.kind == "table" and _ROLE in grant.grantees:
            for table in grant.objects:
                result[table] = result.get(table, frozenset()) | grant.privileges
    return result


class _FunctionChange(NamedTuple):
    security_definer: bool
    search_path: tuple[str, ...] | None
    other: tuple[str, ...]


def _function_changes() -> dict[str, _FunctionChange]:
    """signature -> what the ALTER FUNCTION statements of 0018 change."""
    result: dict[str, _FunctionChange] = {}
    for statement in _top_statements():
        if _kind(statement) != _ALTER_FUNCTION:
            continue
        match = re.fullmatch(
            r"alter\s+function\s+(?P<name>[\w.\"$]+)\s*(?P<args>\([^)]*\))?\s*(?P<actions>.*)",
            statement,
        )
        assert match is not None, statement
        signature = _signature(match.group("name") + (match.group("args") or ""))
        actions = match.group("actions")
        previous = result.get(signature, _FunctionChange(False, None, ()))
        definer = previous.security_definer
        path = previous.search_path
        position = 0
        while position < len(actions):
            step = _FUNCTION_ACTION.match(actions, position)
            if step is None:
                break
            if step.group("definer"):
                definer = True
            else:
                # 'public, pg_temp' as one literal is a single schema name in PostgreSQL.
                path = tuple(item.strip("'\"").lower() for item in _split(step.group("path"), ","))
            position = step.end()
        rest = re.sub(r"^restrict$", "", actions[position:].strip())
        other = (*previous.other, rest) if rest else previous.other
        result[signature] = _FunctionChange(definer, path, other)
    return result


# ---------------------------------------------------------------------------
# Helpers: the guard over every migration
# ---------------------------------------------------------------------------


class _Migration(NamedTuple):
    version: int
    name: str
    sql: str


class _Violation(NamedTuple):
    file: str
    detail: str


def _load_migrations(directory: Path) -> list[_Migration]:
    """The numbered migrations of a directory, in version order."""
    migrations: list[_Migration] = []
    for path in sorted(directory.iterdir()):
        match = db_mod._MIGRATION_FILE_RE.match(path.name)
        if match is not None:
            migrations.append(
                _Migration(int(match.group(1)), path.name, path.read_text(encoding="utf-8"))
            )
    return migrations


def _shipped() -> list[_Migration]:
    return _load_migrations(db_mod._MIGRATIONS_DIR)


def _tables_before_0018() -> set[str]:
    """The tables that exist after 0001-0017, plus run_migrations' _migrations."""
    tables: set[str] = set()
    for migration in _shipped():
        if migration.version < _VERSION:
            tables = _replay(_executed(_normalize(migration.sql)), tables)
    return tables | {"_migrations"}


def _migration_grants(migration: _Migration) -> tuple[list[_Grant], list[_Membership]]:
    return _parse_grants(_fragments(_normalize(migration.sql)))


def _guard_new_tables_are_granted(migrations: Sequence[_Migration]) -> list[_Violation]:
    """After 0018, a migration that creates a table grants it to admino_app."""
    violations: list[_Violation] = []
    for migration in migrations:
        if migration.version <= _VERSION:
            continue
        created = _replay(_executed(_normalize(migration.sql)), set())
        granted = {
            table
            for grant in _migration_grants(migration)[0]
            if grant.kind == "table" and _ROLE in grant.grantees
            for table in grant.objects
        }
        violations.extend(
            _Violation(migration.name, f"table {table} has no GRANT to {_ROLE}")
            for table in sorted(created - granted)
        )
    return violations


def _guard_audit_events_select_insert_only(
    migrations: Sequence[_Migration],
) -> list[_Violation]:
    """The app gets at most SELECT, INSERT on audit_events (bulk grants included)."""
    violations: list[_Violation] = []
    for migration in migrations:
        for grant in _migration_grants(migration)[0]:
            if not grant.grantees & _APP_GRANTEES:
                continue
            covers = (grant.kind == "table" and _AUDIT in grant.objects) or (
                grant.kind == "all tables" and "public" in grant.objects
            )
            extra = grant.privileges - {"select", "insert"}
            if covers and extra:
                violations.append(_Violation(migration.name, f"{sorted(extra)} on {_AUDIT}"))
    return violations


def _guard_no_forbidden_privileges(migrations: Sequence[_Migration]) -> list[_Violation]:
    """The app never gets ALL, TRUNCATE, TRIGGER or REFERENCES on anything."""
    violations: list[_Violation] = []
    for migration in migrations:
        for grant in _migration_grants(migration)[0]:
            forbidden = grant.privileges & frozenset(_FORBIDDEN_PRIVILEGES)
            if grant.grantees & _APP_GRANTEES and forbidden:
                violations.append(
                    _Violation(migration.name, f"{sorted(forbidden)} on {grant.objects}")
                )
    return violations


def _guard_no_role_escalation(migrations: Sequence[_Migration]) -> list[_Violation]:
    """admino_app never owns, joins a role, gets a superuser-class attribute or
    may SET a superuser-only parameter."""
    violations: list[_Violation] = []
    for migration in migrations:
        fragments = _fragments(_normalize(migration.sql))
        grants, memberships = _parse_grants(fragments)
        violations.extend(
            _Violation(migration.name, f"membership in {membership.roles}")
            for membership in memberships
            if membership.grantees & _APP_GRANTEES
        )
        violations.extend(
            _Violation(migration.name, f"parameter {grant.objects}")
            for grant in grants
            if grant.kind == "parameter" and grant.grantees & _APP_GRANTEES
        )
        for fragment in fragments:
            masked = _masked(fragment)
            if re.search(rf"\b(?:owner\s+to|authorization)\s+{_APP}", masked):
                violations.append(_Violation(migration.name, "ownership"))
            if re.search(rf"\breassign\s+owned\s+by\b.*\bto\s+{_APP}", masked):
                violations.append(_Violation(migration.name, "reassigned ownership"))
            if re.search(rf"\balter\s+group\b.*\badd\s+user\b.*{_APP}", masked):
                violations.append(_Violation(migration.name, "group membership"))
            for match in re.finditer(
                rf"\b(?:create|alter)\s+(?:role|user)\s+{_APP}(?P<options>.*)", masked
            ):
                options = match.group("options")
                violations.extend(
                    _Violation(migration.name, f"attribute {attribute}")
                    for attribute in _POSITIVE_ATTRIBUTES
                    if re.search(rf"\b{attribute}\b", options)
                )
                if re.search(r"\bin\s+(?:role|group)\b", options):
                    violations.append(_Violation(migration.name, "membership on creation"))
    return violations


def _guard_no_default_privilege_grants(migrations: Sequence[_Migration]) -> list[_Violation]:
    """No ALTER DEFAULT PRIVILEGES ... GRANT: every grant is explicit."""
    violations: list[_Violation] = []
    for migration in migrations:
        for fragment in _fragments(_normalize(migration.sql)):
            masked = _masked(fragment)
            if re.search(r"\balter\s+default\s+privileges\b", masked) and re.search(
                r"\bgrant\b(?!\s+option)", masked
            ):
                violations.append(_Violation(migration.name, "default privileges grant"))
    return violations


_GUARDS: tuple[tuple[str, Callable[[Sequence[_Migration]], list[_Violation]]], ...] = (
    ("new-tables-are-granted", _guard_new_tables_are_granted),
    ("audit-events-select-insert-only", _guard_audit_events_select_insert_only),
    ("no-forbidden-privileges", _guard_no_forbidden_privileges),
    ("no-role-escalation", _guard_no_role_escalation),
    ("no-default-privilege-grants", _guard_no_default_privilege_grants),
)

_PROBE_NAME = "0019_probe.sql"

# The 0018 statements of the contract, as a later migration: they must pass every guard.
_CONTRACT_0018_SQL = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'admino_app') THEN
        CREATE ROLE admino_app;
    END IF;
END
$$;
ALTER ROLE admino_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
DO $$
BEGIN
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO admino_app', current_database());
END
$$;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO admino_app;
GRANT SELECT ON _migrations TO admino_app;
GRANT SELECT, INSERT ON audit_events TO admino_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations, users, sessions, email_outbox,
    password_reset_tokens, login_throttle, user_settings, oauth_tokens TO admino_app;
GRANT SELECT, INSERT, UPDATE ON invitations, platform_settings, org_settings,
    permissions, memory TO admino_app;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER FUNCTION purge_audit_events(integer) SECURITY DEFINER SET search_path = public, pg_temp;
ALTER FUNCTION purge_org_audit_events(uuid) SECURITY DEFINER SET search_path = public, pg_temp;
GRANT EXECUTE ON FUNCTION purge_audit_events(integer), purge_org_audit_events(uuid) TO admino_app;
"""

_COMPLIANT_PROBES = (
    pytest.param(
        "CREATE TABLE widgets (id uuid PRIMARY KEY);\n"
        "GRANT SELECT, INSERT, UPDATE, DELETE ON widgets TO admino_app;",
        id="table-with-grant",
    ),
    pytest.param(
        "CREATE TABLE IF NOT EXISTS public.widgets (id uuid);\n"
        'grant select on table "widgets" to admino_app;',
        id="qualified-and-quoted-names",
    ),
    pytest.param(
        "CREATE TABLE widgets (id uuid);\nCREATE TABLE gadgets (id uuid);\n"
        "GRANT SELECT ON widgets, public.gadgets TO admino_app;",
        id="two-tables-one-grant",
    ),
    pytest.param(
        "CREATE TABLE widgets (id uuid);\nGRANT SELECT ON widgets TO admino_app;\n"
        "-- GRANT ALL ON widgets TO admino_app;\n/* GRANT pg_execute_server_program "
        "TO admino_app; */",
        id="violations-only-in-comments",
    ),
    pytest.param("CREATE TEMP TABLE scratch_rows AS SELECT 1 AS n;", id="temp-table"),
    pytest.param("GRANT SELECT, INSERT ON audit_events TO admino_app;", id="audit-select-insert"),
    pytest.param(
        "ALTER ROLE admino_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION "
        "NOBYPASSRLS;",
        id="alter-role-no-attributes",
    ),
    pytest.param(
        "ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;",
        id="default-privileges-revoke",
    ),
    pytest.param(_CONTRACT_0018_SQL, id="the-0018-contract-statements"),
)

_UNGRANTED_TABLE_PROBES = (
    pytest.param("CREATE TABLE widgets (id uuid PRIMARY KEY);", id="no-grant"),
    pytest.param("CREATE TABLE IF NOT EXISTS public.widgets (id uuid);", id="qualified"),
    pytest.param('CREATE UNLOGGED TABLE "widgets" (id uuid);', id="unlogged-quoted"),
    pytest.param(
        "CREATE TABLE widgets (id uuid);\nGRANT SELECT ON widgets TO PUBLIC;",
        id="granted-to-public-only",
    ),
    pytest.param(
        "CREATE TABLE widgets (id uuid);\nGRANT SELECT ON widgets TO reporting;",
        id="granted-to-another-role",
    ),
    pytest.param(
        "CREATE TABLE widgets (id uuid);\n-- GRANT SELECT ON widgets TO admino_app;",
        id="grant-only-in-a-comment",
    ),
    pytest.param(
        "CREATE TABLE gadgets (id uuid);\nCREATE TABLE widgets (id uuid);\n"
        "GRANT SELECT ON gadgets TO admino_app;",
        id="second-table-not-granted",
    ),
    pytest.param(
        "DO $$ BEGIN CREATE TABLE widgets (id uuid); END $$;",
        id="created-in-a-do-block",
    ),
)

_AUDIT_OVERGRANT_PROBES = (
    pytest.param("GRANT UPDATE ON audit_events TO admino_app;", id="update"),
    pytest.param("GRANT DELETE ON TABLE public.audit_events TO admino_app;", id="delete"),
    pytest.param("GRANT TRUNCATE ON audit_events TO admino_app;", id="truncate"),
    pytest.param("grant all on audit_events to admino_app;", id="all"),
    pytest.param("GRANT TRIGGER ON audit_events TO admino_app;", id="trigger"),
    pytest.param("GRANT UPDATE (actor_id) ON audit_events TO admino_app;", id="column-update"),
    pytest.param('GRANT UPDATE ON "audit_events" TO "admino_app";', id="quoted"),
    pytest.param(
        "GRANT SELECT, INSERT, DELETE ON users, audit_events TO admino_app;",
        id="in-a-table-list",
    ),
    pytest.param("GRANT DELETE ON audit_events TO PUBLIC;", id="to-public"),
    pytest.param(
        "GRANT UPDATE ON ALL TABLES IN SCHEMA public TO admino_app;",
        id="bulk-all-tables",
    ),
    pytest.param(
        "gRaNt\n  UPDATE\tON audit_events  TO admino_app;",
        id="mixed-case-whitespace",
    ),
    pytest.param(
        "DO $$ BEGIN EXECUTE 'GRANT DELETE ON audit_events TO admino_app'; END $$;",
        id="dynamic-sql-in-a-do-block",
    ),
)

_FORBIDDEN_PRIVILEGE_PROBES = (
    pytest.param("GRANT ALL ON memory TO admino_app;", id="grant-all"),
    pytest.param("GRANT ALL PRIVILEGES ON TABLE users TO admino_app;", id="all-privileges"),
    pytest.param("GRANT TRUNCATE ON sessions TO admino_app;", id="truncate"),
    pytest.param("GRANT TRIGGER ON users TO admino_app;", id="trigger"),
    pytest.param("GRANT REFERENCES ON organizations TO admino_app;", id="references"),
    pytest.param("GRANT SELECT, TRUNCATE ON email_outbox TO PUBLIC;", id="truncate-to-public"),
    pytest.param("GRANT ALL ON SCHEMA public TO admino_app;", id="all-on-schema"),
    pytest.param("GRANT ALL ON ALL TABLES IN SCHEMA public TO admino_app;", id="all-bulk"),
    pytest.param(
        "DO $$ BEGIN EXECUTE format('GRANT ALL ON DATABASE %I TO admino_app', "
        "current_database()); END $$;",
        id="all-on-database-dynamic",
    ),
)

_ESCALATION_PROBES = (
    pytest.param("ALTER TABLE memory OWNER TO admino_app;", id="table-owner"),
    pytest.param(
        "ALTER FUNCTION purge_audit_events(integer) OWNER TO admino_app;",
        id="function-owner",
    ),
    pytest.param('ALTER TABLE users OWNER TO "admino_app";', id="quoted-owner"),
    pytest.param("CREATE SCHEMA app AUTHORIZATION admino_app;", id="schema-authorization"),
    pytest.param("REASSIGN OWNED BY admino TO admino_app;", id="reassign-owned"),
    pytest.param("GRANT pg_execute_server_program TO admino_app;", id="execute-server-program"),
    pytest.param(
        "GRANT pg_write_server_files, pg_read_server_files TO admino_app;",
        id="server-files",
    ),
    pytest.param("GRANT admino TO admino_app;", id="owner-membership"),
    pytest.param(
        "ALTER GROUP pg_write_server_files ADD USER admino_app;",
        id="alter-group-add-user",
    ),
    pytest.param("ALTER ROLE admino_app SUPERUSER;", id="superuser"),
    pytest.param("ALTER ROLE admino_app CREATEDB;", id="createdb"),
    pytest.param("ALTER ROLE admino_app WITH CREATEROLE;", id="createrole"),
    pytest.param("ALTER ROLE admino_app REPLICATION;", id="replication"),
    pytest.param("ALTER USER admino_app BYPASSRLS;", id="bypassrls-alter-user"),
    pytest.param(
        "ALTER ROLE admino_app WITH NOSUPERUSER CREATEROLE;",
        id="mixed-no-and-positive",
    ),
    pytest.param(
        "DO $$ BEGIN CREATE ROLE admino_app LOGIN SUPERUSER; END $$;",
        id="superuser-on-creation",
    ),
    pytest.param(
        "CREATE ROLE admino_app IN ROLE pg_execute_server_program;",
        id="membership-on-creation",
    ),
    pytest.param(
        "GRANT SET ON PARAMETER session_replication_role TO admino_app;",
        id="set-session-replication-role",
    ),
)

_DEFAULT_GRANT_PROBES = (
    pytest.param(
        "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO admino_app;",
        id="global-tables",
    ),
    pytest.param(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE "
        "ON TABLES TO admino_app;",
        id="in-schema-tables",
    ),
    pytest.param(
        "ALTER DEFAULT PRIVILEGES FOR ROLE admino IN SCHEMA public GRANT ALL ON TABLES TO PUBLIC;",
        id="for-role-all-to-public",
    ),
    pytest.param(
        "alter default privileges grant execute on functions to admino_app;",
        id="functions",
    ),
)


@pytest.fixture
def scratch_migrations(tmp_path: Path) -> Path:
    """A scratch copy of the shipped migrations directory."""
    directory = tmp_path / "migrations"
    directory.mkdir()
    for path in db_mod._MIGRATIONS_DIR.iterdir():
        if db_mod._MIGRATION_FILE_RE.match(path.name):
            shutil.copyfile(path, directory / path.name)
    return directory


def _with_probe(directory: Path, sql: str, name: str = _PROBE_NAME) -> list[_Migration]:
    """Write a fake migration into the scratch directory and load the directory."""
    (directory / name).write_text(sql, encoding="utf-8")
    migrations = _load_migrations(directory)
    assert name in [migration.name for migration in migrations]
    return migrations


def _flags_probe(violations: list[_Violation], name: str = _PROBE_NAME) -> bool:
    return any(violation.file == name for violation in violations)


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0018File:
    """The migration ships as version 18 and is applied by run_migrations."""

    def test_migration_0018_file_is_shipped_as_version_18(self) -> None:
        """0018_runtime_role.sql exists and its number is version 18."""
        assert _migration_path().is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == _VERSION

    def test_migration_0018_is_the_only_version_18(self) -> None:
        """No other file claims version 18."""
        eighteens = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert eighteens == [_MIGRATION_NAME]

    async def test_migration_0018_run_migrations_applies_it_as_version_18(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0017 applied, run_migrations executes the file and records 18."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])

        await db_mod.run_migrations(mock_pool)

        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert (_VERSION, _MIGRATION_NAME) in recorded
        assert all(version >= _VERSION for version, _ in recorded)

    async def test_migration_0018_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        """The SQL run for version 18 is the shipped file, byte for byte."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    async def test_migration_0018_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0018 recorded, the shipped SQL is not executed a second time."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0018_is_parameter_free(self) -> None:
        """No $n placeholder anywhere (a $$ dollar quote is not one), no %s / %(."""
        for fragment in _all_fragments():
            assert re.search(r"\$\d", _masked(fragment)) is None, fragment
        masked = _masked(_normalized_sql())
        assert "%s" not in masked
        assert "%(" not in masked

    def test_migration_0018_header_comment_names_both_roles(self) -> None:
        """The header explains that the app connects as admino_app, not as the owner."""
        header = _header_comment().lower()

        assert _ROLE in header, header
        assert re.search(r"\bowners?\b", header), header

    def test_migration_0018_header_comment_explains_why(self) -> None:
        """The header says why: a superuser could bypass the append-only audit store."""
        header = _header_comment().lower()

        assert "superuser" in header, header
        assert "audit" in header, header

    def test_migration_0018_runtime_role_constant_is_admino_app(self) -> None:
        """admino.database.RUNTIME_ROLE names the runtime role."""
        assert db_mod.RUNTIME_ROLE == _ROLE

    def test_migration_0018_uses_the_runtime_role_constant(self) -> None:
        """The role the migration creates and alters is database.RUNTIME_ROLE."""
        masked = " ".join(_masked(fragment) for fragment in _all_fragments())
        names = re.findall(r"\b(?:create|alter)\s+(?:role|user)\s+\"?(\w+)", masked)

        assert names
        assert set(names) == {db_mod.RUNTIME_ROLE}


# ---------------------------------------------------------------------------
# 2. Exactly the contract's statements
# ---------------------------------------------------------------------------


class TestMigration0018Statements:
    """The role, the database, the schema, the tables and the functions; nothing else."""

    def test_migration_0018_every_statement_is_part_of_the_contract(self) -> None:
        """Each top-level statement is one of the contract's statement kinds."""
        unexpected = [s for s in _top_statements() if _kind(s) is None]

        assert unexpected == []

    @pytest.mark.parametrize("kind", _REQUIRED_KINDS)
    def test_migration_0018_contains_the_contract_statement(self, kind: str) -> None:
        """Every kind of statement the contract lists is present."""
        assert kind in _kinds()

    def test_migration_0018_creates_the_role_before_anything_else(self) -> None:
        """The role exists before any statement names it (grants to a missing role fail)."""
        kinds = _kinds()

        assert kinds
        assert kinds[0] == _DO_ROLE

    @pytest.mark.parametrize("pattern_id", [pattern_id for pattern_id, _ in _MUST_NOT])
    def test_migration_0018_does_not_contain_forbidden_sql(self, pattern_id: str) -> None:
        """No password, ownership change, trigger change, function or table creation,
        data write, bulk or default-privilege grant, membership or grant option."""
        pattern = dict(_MUST_NOT)[pattern_id]

        assert re.search(pattern, _full_text()) is None

    def test_migration_0018_grants_no_role_membership(self) -> None:
        """No GRANT <role> TO ... (pg_execute_server_program, pg_write_server_files, admino)."""
        assert _parse_grants(_all_fragments())[1] == []


# ---------------------------------------------------------------------------
# 3. The runtime role
# ---------------------------------------------------------------------------


class TestMigration0018Role:
    """admino_app: created idempotently, a login role with no superuser-class power."""

    def test_migration_0018_role_creation_is_guarded_by_pg_roles(self) -> None:
        """IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'admino_app') THEN
        CREATE ROLE admino_app; END IF; so a re-run keeps an existing role (and its
        password)."""
        body = _do_body(_DO_ROLE)

        assert _ROLE_BLOCK.fullmatch(body), body

    def test_migration_0018_role_is_created_only_inside_the_guarded_block(self) -> None:
        """One CREATE ROLE in the whole file, and never as a top-level statement."""
        creations = [
            fragment
            for fragment in _all_fragments()
            if re.search(r"\bcreate\s+(?:role|user|group)\b", _masked(fragment))
        ]

        assert len(creations) == 1, creations
        assert not any(
            re.match(r"create\s+(?:role|user|group)\b", _masked(s)) for s in _top_statements()
        )

    @pytest.mark.parametrize("attribute", _RUNTIME_ATTRIBUTES)
    def test_migration_0018_alter_role_sets_the_runtime_attribute(self, attribute: str) -> None:
        """ALTER ROLE admino_app sets LOGIN and every NO* attribute."""
        assert attribute in _alter_role_options()

    def test_migration_0018_alter_role_sets_exactly_the_six_attributes(self) -> None:
        """Nothing else: no PASSWORD, CONNECTION LIMIT, VALID UNTIL, INHERIT tweaks."""
        assert sorted(_alter_role_options()) == sorted(_RUNTIME_ATTRIBUTES)

    def test_migration_0018_alters_only_the_runtime_role(self) -> None:
        """One ALTER ROLE in the whole file, on admino_app (never the owner role)."""
        altered = [
            match.group(1)
            for fragment in _all_fragments()
            for match in re.finditer(r"\balter\s+(?:role|user)\s+(\"?[\w$]+\"?)", _masked(fragment))
        ]

        assert [name.strip('"') for name in altered] == [_ROLE]

    def test_migration_0018_sets_no_password(self) -> None:
        """No PASSWORD anywhere: the migrate step sets a SCRAM verifier, not the SQL file."""
        assert re.search(r"\bpassword\b", _full_text()) is None

    @pytest.mark.parametrize("attribute", _POSITIVE_ATTRIBUTES)
    def test_migration_0018_grants_no_superuser_class_attribute(self, attribute: str) -> None:
        """SUPERUSER, CREATEDB, CREATEROLE, REPLICATION, BYPASSRLS only with NO."""
        assert re.search(rf"\b{attribute}\b", _full_text()) is None


# ---------------------------------------------------------------------------
# 4. The database and the schema
# ---------------------------------------------------------------------------


class TestMigration0018DatabaseAndSchema:
    """CONNECT on the current database, USAGE on public; nothing for PUBLIC."""

    def test_migration_0018_database_block_revokes_all_from_public(self) -> None:
        """EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database())."""
        keys = [_template_key(template) for template in _database_templates()]

        assert "revoke all on database %i from public" in keys

    def test_migration_0018_database_block_grants_only_connect_to_the_role(self) -> None:
        """EXECUTE format('GRANT CONNECT ON DATABASE %I TO admino_app', current_database())."""
        keys = [_template_key(template) for template in _database_templates()]

        assert "grant connect on database %i to admino_app" in keys

    def test_migration_0018_database_block_runs_exactly_the_two_statements(self) -> None:
        """No TEMPORARY or CREATE on the database, no other dynamic statement."""
        keys = sorted(_template_key(template) for template in _database_templates())

        assert keys == sorted(_DATABASE_TEMPLATES)

    def test_migration_0018_database_name_is_quoted_with_format_identifier(self) -> None:
        """The database name goes through %I (identifier quoting), never %s or %L."""
        templates = _database_templates()

        assert templates
        for template in templates:
            assert "%I" in template, template
            assert "%s" not in template, template
            assert "%L" not in template, template

    def test_migration_0018_grants_on_the_database_are_connect_only(self) -> None:
        """Every database grant in the file is CONNECT to admino_app."""
        database_grants = [grant for grant in _grants() if grant.kind == "database"]

        assert database_grants
        for grant in database_grants:
            assert grant.privileges == frozenset({"connect"}), grant
            assert grant.grantees == frozenset({_ROLE}), grant

    def test_migration_0018_revokes_create_on_schema_public_from_public(self) -> None:
        """PUBLIC (hence admino_app) can no longer create objects in public."""
        assert _REVOKE_SCHEMA_CREATE in _kinds()

    def test_migration_0018_grants_only_usage_on_schema_public(self) -> None:
        """The one schema grant is USAGE on public to admino_app, never CREATE."""
        schema_grants = [grant for grant in _grants() if grant.kind == "schema"]

        assert schema_grants == [
            _Grant(frozenset({"usage"}), "schema", ("public",), frozenset({_ROLE}), False)
        ]


# ---------------------------------------------------------------------------
# 5. Table privileges
# ---------------------------------------------------------------------------


class TestMigration0018TableGrants:
    """Exactly what the app's SQL needs, per table; audit_events append-only."""

    def test_migration_0018_table_grants_equal_the_contract_map(self) -> None:
        """The (table -> privileges) map of all grants to admino_app is the contract's."""
        assert _table_grant_map() == _EXPECTED_GRANTS

    @pytest.mark.parametrize(("table", "privileges"), sorted(_EXPECTED_GRANTS.items()))
    def test_migration_0018_table_gets_exactly_its_privileges(
        self, table: str, privileges: frozenset[str]
    ) -> None:
        """Each table's privileges for admino_app, one table at a time."""
        assert _table_grant_map().get(table) == privileges

    def test_migration_0018_audit_events_is_select_and_insert_only(self) -> None:
        """No UPDATE, DELETE or TRUNCATE on the append-only audit store."""
        assert _table_grant_map().get(_AUDIT) == frozenset({"select", "insert"})

    def test_migration_0018_grants_only_to_the_runtime_role(self) -> None:
        """Every grant names admino_app alone: nothing for PUBLIC or any other role."""
        grants = _grants()

        assert grants
        for grant in grants:
            assert grant.grantees == frozenset({_ROLE}), grant

    @pytest.mark.parametrize("privilege", _FORBIDDEN_PRIVILEGES)
    def test_migration_0018_grants_no_forbidden_privilege(self, privilege: str) -> None:
        """No ALL [PRIVILEGES], TRUNCATE, TRIGGER or REFERENCES for anyone."""
        grants = _grants()

        assert grants
        assert not any(privilege in grant.privileges for grant in grants)

    def test_migration_0018_makes_no_bulk_grant(self) -> None:
        """No ON ALL TABLES / FUNCTIONS / SEQUENCES IN SCHEMA grant."""
        grants = _grants()

        assert grants
        assert [grant for grant in grants if grant.kind.startswith("all ")] == []

    def test_migration_0018_grants_without_grant_option(self) -> None:
        """admino_app can't pass a privilege on to anyone."""
        grants = _grants()

        assert grants
        assert not any(grant.grant_option for grant in grants)

    def test_migration_0018_grants_only_on_tables_schema_database_and_functions(self) -> None:
        """No sequence, type, language, parameter or other object grant."""
        kinds = {grant.kind for grant in _grants()}

        assert kinds == {"table", "schema", "database", "function"}

    def test_migration_0018_grants_every_table_that_exists_before_it(self) -> None:
        """Every table left by 0001-0017 (CREATE minus DROP, replayed) plus _migrations
        gets a grant, so no app query hits a permission error."""
        tables = _tables_before_0018()
        assert _AUDIT in tables
        assert "settings" not in tables  # dropped by 0013

        missing = tables - set(_table_grant_map())

        assert missing == set()

    def test_migration_0018_grants_no_table_that_does_not_exist(self) -> None:
        """A grant on a missing table would fail the migration on PostgreSQL."""
        extra = set(_table_grant_map()) - _tables_before_0018()

        assert extra == set()


# ---------------------------------------------------------------------------
# 6. Functions
# ---------------------------------------------------------------------------


class TestMigration0018Functions:
    """No EXECUTE for PUBLIC; the two purges run as the owner and only they run."""

    def test_migration_0018_revokes_execute_on_all_functions_from_public(self) -> None:
        """REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC."""
        assert _REVOKE_FUNCTIONS in _kinds()

    def test_migration_0018_revokes_execute_from_public_by_default(self) -> None:
        """ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC (global form)."""
        assert _DEFAULT_REVOKE in _kinds()

    def test_migration_0018_default_privileges_are_global_not_per_schema(self) -> None:
        """Every ALTER DEFAULT PRIVILEGES is the global revoke: no IN SCHEMA (it can't
        revoke a global default), no FOR ROLE, no GRANT."""
        statements = [
            _masked(fragment)
            for fragment in _all_fragments()
            if re.search(r"\balter\s+default\s+privileges\b", _masked(fragment))
        ]

        assert statements
        for statement in statements:
            assert _GLOBAL_DEFAULT_REVOKE.fullmatch(statement), statement

    def test_migration_0018_alters_only_the_two_purge_functions(self) -> None:
        """ALTER FUNCTION touches purge_audit_events(integer) and
        purge_org_audit_events(uuid), nothing else."""
        assert set(_function_changes()) == set(_PURGE_FUNCTIONS)

    @pytest.mark.parametrize("signature", _PURGE_FUNCTIONS)
    def test_migration_0018_purge_function_is_security_definer(self, signature: str) -> None:
        """The purge runs as the owner, so the app needs no DELETE on audit_events."""
        change = _function_changes().get(signature)

        assert change is not None
        assert change.security_definer

    @pytest.mark.parametrize("signature", _PURGE_FUNCTIONS)
    def test_migration_0018_purge_function_pins_search_path(self, signature: str) -> None:
        """SET search_path = public, pg_temp: a SECURITY DEFINER function can't be
        hijacked through objects in another schema."""
        change = _function_changes().get(signature)

        assert change is not None
        assert change.search_path == _SEARCH_PATH

    def test_migration_0018_alter_function_changes_nothing_else(self) -> None:
        """No OWNER TO, RENAME, SET SCHEMA or other setting on the functions."""
        changes = _function_changes()

        assert changes
        for signature, change in changes.items():
            assert change.other == (), (signature, change.other)

    def test_migration_0018_grants_execute_on_exactly_the_purge_functions(self) -> None:
        """admino_app may EXECUTE the two purges and no other function."""
        function_grants = [
            grant
            for grant in _grants()
            if grant.kind in ("function", "procedure", "routine") or grant.kind.startswith("all ")
        ]
        granted = {name for grant in function_grants for name in grant.objects}

        assert granted == set(_PURGE_FUNCTIONS)
        for grant in function_grants:
            assert grant.privileges == frozenset({"execute"}), grant
            assert grant.grantees == frozenset({_ROLE}), grant


# ---------------------------------------------------------------------------
# 7. The guard over every shipped migration
# ---------------------------------------------------------------------------


class TestMigrationGrantGuardShipped:
    """Every shipped migration passes every guard, and the guard sees 0018's grants."""

    @pytest.mark.parametrize(("guard_id", "guard"), _GUARDS, ids=[g for g, _ in _GUARDS])
    def test_migration_grants_shipped_migrations_pass_the_guard(
        self,
        guard_id: str,
        guard: Callable[[Sequence[_Migration]], list[_Violation]],
    ) -> None:
        """No shipped migration violates the guard."""
        assert guard(_shipped()) == [], guard_id

    def test_migration_grants_guard_reads_the_runtime_role_grants_of_the_shipped_files(
        self,
    ) -> None:
        """The guard's parser finds 0018's table grants, so its checks are not vacuous."""
        granted = {
            table
            for migration in _shipped()
            for grant in _migration_grants(migration)[0]
            if grant.kind == "table" and _ROLE in grant.grantees
            for table in grant.objects
        }

        assert {_AUDIT, "_migrations", "users"} <= granted


# ---------------------------------------------------------------------------
# 8. Mutation probes: each guard fails on a scratch copy holding a violation
# ---------------------------------------------------------------------------


class TestMigrationGrantGuardProbes:
    """A fake 0019 in a scratch copy of the migrations shows each guard works."""

    @pytest.mark.parametrize("sql", _COMPLIANT_PROBES)
    @pytest.mark.parametrize(("guard_id", "guard"), _GUARDS, ids=[g for g, _ in _GUARDS])
    def test_migration_grants_compliant_migration_passes_the_guard(
        self,
        scratch_migrations: Path,
        guard_id: str,
        guard: Callable[[Sequence[_Migration]], list[_Violation]],
        sql: str,
    ) -> None:
        """A later migration that grants its new table (and nothing more) is accepted."""
        violations = guard(_with_probe(scratch_migrations, sql))

        assert not _flags_probe(violations), (guard_id, violations)

    @pytest.mark.parametrize("sql", _UNGRANTED_TABLE_PROBES)
    def test_migration_grants_new_table_without_grant_is_flagged(
        self, scratch_migrations: Path, sql: str
    ) -> None:
        """CREATE TABLE in 0019 with no GRANT ... TO admino_app in the same file fails."""
        violations = _guard_new_tables_are_granted(_with_probe(scratch_migrations, sql))

        assert _flags_probe(violations), violations
        assert any("widgets" in violation.detail for violation in violations), violations

    def test_migration_grants_new_table_granted_in_a_later_file_is_flagged(
        self, scratch_migrations: Path
    ) -> None:
        """The grant must be in the file that creates the table, not in a later one."""
        _with_probe(scratch_migrations, "CREATE TABLE widgets (id uuid);")
        migrations = _with_probe(
            scratch_migrations, "GRANT SELECT ON widgets TO admino_app;", "0020_grant.sql"
        )

        violations = _guard_new_tables_are_granted(migrations)

        assert _flags_probe(violations), violations

    @pytest.mark.parametrize("sql", _AUDIT_OVERGRANT_PROBES)
    def test_migration_grants_more_than_select_insert_on_audit_events_is_flagged(
        self, scratch_migrations: Path, sql: str
    ) -> None:
        """UPDATE / DELETE / TRUNCATE / ALL on audit_events for the app fails."""
        violations = _guard_audit_events_select_insert_only(_with_probe(scratch_migrations, sql))

        assert _flags_probe(violations), violations

    @pytest.mark.parametrize("sql", _FORBIDDEN_PRIVILEGE_PROBES)
    def test_migration_grants_forbidden_privilege_is_flagged(
        self, scratch_migrations: Path, sql: str
    ) -> None:
        """ALL / TRUNCATE / TRIGGER / REFERENCES for the app fails."""
        violations = _guard_no_forbidden_privileges(_with_probe(scratch_migrations, sql))

        assert _flags_probe(violations), violations

    @pytest.mark.parametrize("sql", _ESCALATION_PROBES)
    def test_migration_grants_role_escalation_is_flagged(
        self, scratch_migrations: Path, sql: str
    ) -> None:
        """Ownership, role membership, superuser-class attributes or SET on a
        superuser-only parameter for admino_app fails."""
        violations = _guard_no_role_escalation(_with_probe(scratch_migrations, sql))

        assert _flags_probe(violations), violations

    @pytest.mark.parametrize("sql", _DEFAULT_GRANT_PROBES)
    def test_migration_grants_default_privilege_grant_is_flagged(
        self, scratch_migrations: Path, sql: str
    ) -> None:
        """ALTER DEFAULT PRIVILEGES ... GRANT ... fails: every grant is explicit."""
        violations = _guard_no_default_privilege_grants(_with_probe(scratch_migrations, sql))

        assert _flags_probe(violations), violations
