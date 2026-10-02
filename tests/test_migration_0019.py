"""Tests for migration 0019_org_purge_window.sql — the database-enforced org
deletion window and the owner-run org purge (GH-220, security finding High).

Finding: admino_app has UPDATE on organizations, and purge_org_audit_events(uuid)
trusted organizations.status / purge_after. The app could mark a live org as due
right now, purge its audit log, and make it active again. 0019 closes this in the
database, for every role.

There is no real PostgreSQL in the suite, so the shipped SQL file is the spec (the
test_migration_0011.py / test_migration_0018.py pattern). The SQL is read with
``--`` and ``/* */`` comments blanked and split into statements outside literals,
parentheses and dollar-quoted bodies. Keywords are compared case-insensitively with
whitespace collapsed, and '...' literals are kept byte for byte. The trigger
function is not matched against a text pattern: a small PL/pgSQL interpreter
(IF / ELSIF / ELSE, assignments to NEW, RAISE EXCEPTION, RETURN; SQL three-valued
logic, with OLD NULL for an INSERT) runs it over every combination of TG_OP, old and
new status and dates around the window. Any equivalent way of writing the body
passes; anything the interpreter can't read fails.

What these tests pin down:
- Exactly four top-level statements, each once: CREATE FUNCTION
  organizations_deletion_window() RETURNS trigger (plpgsql, not SECURITY DEFINER);
  CREATE TRIGGER organizations_deletion_window BEFORE INSERT OR UPDATE ON
  organizations FOR EACH ROW EXECUTE FUNCTION organizations_deletion_window(), with
  no WHEN clause and after its function; CREATE OR REPLACE FUNCTION
  purge_org_audit_events(target_org uuid) RETURNS bigint; REVOKE DELETE ON
  organizations FROM admino_app.
- The window: entering pending_deletion (an INSERT, or an UPDATE from another
  status) stamps deletion_requested_at with now() (whatever the statement says) and
  refuses a NULL purge_after or one earlier than now() + the floor (exactly the
  floor passes). While a row stays pending, both dates are frozen (IS DISTINCT FROM,
  so a NULL counts as a change). Leaving pending_deletion (#154's cancel until the
  purge) and rows outside it are never refused nor changed. The row returned is
  NEW. Every refusal is a plain-literal RAISE EXCEPTION with ERRCODE
  check_violation, and the body runs no SQL.
- The floor is one number: the trigger's interval, the platform setting minimum
  (admino.models._GraceDays and PlatformRetention.org_deletion_grace_days ``ge``)
  and the migrations' CHECK (org_deletion_grace_days BETWEEN <floor> AND ...) must
  agree, so changing one without the others fails here. The app's _SCHEDULE_SQL
  (deletion_requested_at = now(), purge_after = now() + $2::interval) passes the
  window for every allowed grace.
- The purge keeps 0011's name, uuid argument (target_org) and bigint return, so
  the frame-3 prefix of 0011's append-only trigger still names it. It is
  re-declared SECURITY DEFINER with SET search_path = public, pg_temp, because
  CREATE OR REPLACE resets attributes it doesn't repeat. Its body is 0011's
  precondition block unchanged, then the one-line DELETE FROM audit_events WHERE
  org_id = target_org (equal to the frame-2 literal of 0011's trigger, which is read
  from 0011), GET DIAGNOSTICS <n> = ROW_COUNT right after it, DELETE FROM
  organizations WHERE id = target_org, and RETURN <n>. Static SQL only.
- admino_app ends with exactly SELECT, INSERT, UPDATE on organizations (the grants
  and revokes of every shipped migration replayed). 0019 grants nothing, and the
  0018 grant guards still pass with 0019 shipped.
- Nothing else: no data write outside a function body, no table, nothing dropped
  or altered, the append-only trigger function and the retention purge untouched,
  no other trigger, no DO block, no default privileges, parameter-free. The header
  comment explains the window and names admino_app and the audit log.

Security notes:
- A BEFORE trigger enforces the window for every role, the owner included. Neither
  the app nor a compromised app process can make an org due early, back-date the
  request, or move a pending purge date, so the purge precondition can trust the
  row.
- Only the owner-run purge function deletes organizations. It deletes the audit
  events first (the append-only trigger checks the org row while they go), then
  the org row, in one call.
- Errors carry no row data or input: every RAISE is a plain literal.
"""

from __future__ import annotations

import operator
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, NamedTuple, get_args
from unittest.mock import AsyncMock

import pytest

import admino.database as db_mod
import admino.models as models_mod
import admino.organizations as organizations_mod

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME = "0019_org_purge_window.sql"
_VERSION = 19
_PURGE_SOURCE = "0011_org_lifecycle.sql"
_ROLE = "admino_app"
_PENDING = "pending_deletion"
_WINDOW = "organizations_deletion_window"  # the trigger function and the trigger
_PURGE = "purge_org_audit_events"
_APPEND_ONLY = "audit_events_append_only"
_AUDIT_DELETE = "DELETE FROM audit_events WHERE org_id = target_org"
_SEARCH_PATH = ("public", "pg_temp")
_CHECK_VIOLATION = "check_violation"
_DATES = ("deletion_requested_at", "purge_after")
_STATUSES = ("active", "deactivated", _PENDING)
_ALL_PRIVILEGES = frozenset(
    {"select", "insert", "update", "delete", "truncate", "references", "trigger"}
)

_NOW = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
_DAY = timedelta(days=1)
_TICK = timedelta(microseconds=1)  # the resolution of timestamptz

# Top-level statement kinds of 0019 (see _kind).
_WINDOW_FUNCTION_KIND = "create the window trigger function"
_WINDOW_TRIGGER_KIND = "create the window trigger"
_PURGE_KIND = "replace the org purge function"
_REVOKE_KIND = "revoke delete on organizations from admino_app"
_KINDS = (_WINDOW_FUNCTION_KIND, _WINDOW_TRIGGER_KIND, _PURGE_KIND, _REVOKE_KIND)

_LITERAL = r"'(?:[^']|'')*'"
_DOLLAR_TAG = re.compile(r"\$(?:[A-Za-z_]\w*)?\$")
_IDENTIFIER = r"(?:\"(?:[^\"]|\"\")+\"|[\w$]+)"
_QUALIFIED = rf"{_IDENTIFIER}(?:\s*\.\s*{_IDENTIFIER})?"


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


def _blank_comments(sql: str) -> str:
    """The SQL with every comment replaced by spaces (newlines kept), dollar-quoted
    bodies included; literals, identifiers, case and layout are kept."""
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
            out.append(tag + _blank_comments(sql[index + len(tag) : stop]))
            if close >= 0:
                out.append(tag)
            index = len(sql) if close < 0 else close + len(tag)
        elif sql.startswith("--", index) or sql.startswith("/*", index):
            end_marker = "\n" if char == "-" else "*/"
            close = sql.find(end_marker, index + 2)
            stop = len(sql) if close < 0 else close + (0 if char == "-" else 2)
            out.append(re.sub(r"[^\n]", " ", sql[index:stop]))
            index = stop
        else:
            out.append(char)
            index += 1
    return "".join(out)


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
    """(masked text, literal contents, dollar-quoted bodies) of a comment-free text.

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


_PUNCTUATION_RE = re.compile(r"\s*([()\[\],;=<>!+\-*/:|])\s*")


def _canon(text: str) -> str:
    """_normalize, then no spaces around punctuation outside literals, so formatting
    variants of one statement compare equal."""
    parts = re.split(f"({_LITERAL})", _normalize(text))
    return "".join(
        part if index % 2 else _PUNCTUATION_RE.sub(r"\1", part) for index, part in enumerate(parts)
    ).strip()


def _unliteral(literal: str) -> str:
    """The value of a '...' literal."""
    return literal[1:-1].replace("''", "'")


def _name(raw: str) -> str:
    """An object name: unquoted parts lowercased, quotes and the public schema dropped."""
    parts = [part.strip() for part in raw.strip().split(".")]
    names = [
        part[1:-1].replace('""', '"') if part.startswith('"') else part.lower() for part in parts
    ]
    if len(names) == 2 and names[0] == "public":
        return names[1]
    return ".".join(names)


# ---------------------------------------------------------------------------
# Helpers: the shipped migrations and their top-level statements
# ---------------------------------------------------------------------------


def _path(name: str = _MIGRATION_NAME) -> Path:
    return db_mod._MIGRATIONS_DIR / name


def _raw(name: str = _MIGRATION_NAME) -> str:
    """A shipped migration, exactly as it is on disk."""
    path = _path(name)
    if not path.is_file():
        pytest.fail(f"{name} is not shipped in {db_mod._MIGRATIONS_DIR}")
    return path.read_text(encoding="utf-8")


def _shipped_names() -> list[str]:
    """Every shipped migration file name, in version order."""
    versions: list[tuple[int, str]] = []
    for path in db_mod._MIGRATIONS_DIR.iterdir():
        match = db_mod._MIGRATION_FILE_RE.match(path.name)
        if match is not None:
            versions.append((int(match.group(1)), path.name))
    return [name for _, name in sorted(versions)]


class _Statement(NamedTuple):
    """One top-level statement of a migration."""

    raw: str  # comments blanked, case and layout kept
    norm: str  # _normalize-d
    masked: str  # norm with literal contents and dollar-quoted bodies blanked


def _statements(name: str = _MIGRATION_NAME) -> list[_Statement]:
    result: list[_Statement] = []
    for raw in _split(_blank_comments(_raw(name)), ";"):
        norm = _normalize(raw)
        result.append(_Statement(raw, norm, _masked(norm)))
    return result


def _top_level() -> str:
    """0019 without comments, literal contents and dollar-quoted bodies, lowercased."""
    return " ; ".join(statement.masked for statement in _statements())


def _header_comment() -> str:
    """The ``--`` comment lines before the first statement, joined."""
    lines: list[str] = []
    for line in _raw().splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            lines.append(stripped[2:].strip())
        elif stripped:
            break
    return " ".join(lines)


# ---------------------------------------------------------------------------
# Helpers: CREATE FUNCTION, CREATE TRIGGER, GRANT / REVOKE
# ---------------------------------------------------------------------------


class _Function(NamedTuple):
    """One CREATE [OR REPLACE] FUNCTION statement."""

    name: str
    or_replace: bool
    arguments: str  # normalized
    returns: str
    options: str  # normalized, the body left out
    body: str  # comments blanked, case and layout kept (PL/pgSQL sees this text)


_FUNCTION_HEAD_RE = re.compile(
    rf"create\s+(?P<replace>or\s+replace\s+)?function\s+(?P<name>{_QUALIFIED})\s*"
    r"\((?P<arguments>[^)]*)\)\s*returns\s+(?P<returns>[\w.]+)(?P<rest>.*)",
    re.IGNORECASE | re.DOTALL,
)
_BODY_START_RE = re.compile(r"\bas\s+(\$(?:[A-Za-z_]\w*)?\$)", re.IGNORECASE)
_VALUE = rf"(?:{_LITERAL}|\"(?:[^\"]|\"\")*\"|[\w$]+)"
_SET_RE = re.compile(
    rf"\bset\s+(?P<parameter>\w+)\s*(?:=|\bto\b)\s*(?P<value>{_VALUE}(?:\s*,\s*{_VALUE})*)"
)


def _function_of(raw: str) -> _Function | None:
    """The function a statement creates, or None when it isn't a CREATE FUNCTION."""
    head = _FUNCTION_HEAD_RE.fullmatch(raw.strip())
    if head is None:
        return None
    rest = head.group("rest")
    masked = _masked(rest)
    start = _BODY_START_RE.search(masked)
    if start is None:
        pytest.fail(f"function {head.group('name')} has no dollar-quoted body")
    tag = start.group(1)
    close = masked.find(tag, start.end())
    if close < 0:
        pytest.fail(f"function {head.group('name')} has an unterminated body")
    return _Function(
        name=_name(head.group("name")),
        or_replace=head.group("replace") is not None,
        arguments=_normalize(head.group("arguments")),
        returns=head.group("returns").lower(),
        options=_normalize(f"{rest[: start.start()]} {rest[close + len(tag) :]}"),
        body=rest[start.end() : close],
    )


def _function(function_name: str, name: str = _MIGRATION_NAME) -> _Function:
    """The one function of that name a migration creates."""
    found = [
        function
        for statement in _statements(name)
        if (function := _function_of(statement.raw)) is not None and function.name == function_name
    ]
    if len(found) != 1:
        pytest.fail(f"{name} creates {function_name} {len(found)} times, expected once")
    return found[0]


def _settings(options: str) -> dict[str, tuple[str, ...]]:
    """parameter -> values of the SET clauses of a function ('a, b' as one literal is
    ONE value: PostgreSQL reads it as a single schema name)."""
    result: dict[str, tuple[str, ...]] = {}
    for match in _SET_RE.finditer(options):
        values = []
        for item in _split(match.group("value"), ","):
            values.append(item[1:-1] if item[:1] in "'\"" else item)
        result[match.group("parameter")] = tuple(values)
    return result


def _language(function: _Function) -> str | None:
    match = re.search(r"\blanguage\s+'?(\w+)'?", function.options)
    return None if match is None else match.group(1).lower()


def _is_security_definer(function: _Function) -> bool:
    return re.search(r"\bsecurity\s+definer\b", function.options) is not None


class _Trigger(NamedTuple):
    """One CREATE TRIGGER statement."""

    name: str
    constraint: bool
    timing: str
    events: frozenset[str]
    table: str
    function: str | None  # None: more than FOR EACH ROW EXECUTE FUNCTION f()


_TRIGGER_RE = re.compile(
    rf"create\s+(?:or\s+replace\s+)?(?P<constraint>constraint\s+)?trigger\s+"
    rf"(?P<name>{_IDENTIFIER})\s+(?P<timing>before|after|instead\s+of)\s+(?P<events>.+?)"
    rf"\s+on\s+(?P<table>{_QUALIFIED})(?P<rest>.*)"
)
_TRIGGER_REST_RE = re.compile(
    rf"\s+for\s+(?:each\s+)?row\s+execute\s+(?:function|procedure)\s+(?P<function>{_QUALIFIED})"
    r"\s*\(\s*\)"
)


def _trigger_of(statement: _Statement) -> _Trigger | None:
    match = _TRIGGER_RE.fullmatch(statement.masked)
    if match is None:
        return None
    rest = _TRIGGER_REST_RE.fullmatch(match.group("rest"))
    return _Trigger(
        name=_name(match.group("name")),
        constraint=match.group("constraint") is not None,
        timing=re.sub(r"\s+", " ", match.group("timing")),
        events=frozenset(
            re.sub(r"\s+", " ", event.strip())
            for event in re.split(r"\s+or\s+", match.group("events"))
        ),
        table=_name(match.group("table")),
        function=None if rest is None else _name(rest.group("function")),
    )


class _Privileges(NamedTuple):
    """One GRANT or REVOKE of table privileges."""

    verb: str
    privileges: frozenset[str]
    tables: frozenset[str]
    grantees: frozenset[str]


_PRIVILEGE_STATEMENT_RE = re.compile(
    r"(?P<verb>grant|revoke)\s+(?P<privileges>[a-z]+(?:\s+privileges)?(?:\s*,\s*[a-z]+)*)"
    rf"\s+on\s+(?:table\s+)?(?P<tables>{_QUALIFIED}(?:\s*,\s*{_QUALIFIED})*)"
    rf"\s+(?:to|from)\s+(?P<grantees>{_IDENTIFIER}(?:\s*,\s*{_IDENTIFIER})*)"
    r"(?:\s+(?:cascade|restrict))?"
)


def _table_privileges(statement: _Statement) -> _Privileges | None:
    """The table privileges a statement grants or revokes (None: not such a statement)."""
    match = _PRIVILEGE_STATEMENT_RE.fullmatch(statement.masked)
    if match is None:
        return None
    privileges: set[str] = set()
    for item in match.group("privileges").split(","):
        privilege = re.sub(r"\s+", " ", item.strip())
        privileges |= _ALL_PRIVILEGES if privilege in ("all", "all privileges") else {privilege}
    return _Privileges(
        verb=match.group("verb"),
        privileges=frozenset(privileges),
        tables=frozenset(_name(item) for item in _split(match.group("tables"), ",")),
        grantees=frozenset(_name(item) for item in _split(match.group("grantees"), ",")),
    )


def _runtime_privileges_on(table: str) -> frozenset[str]:
    """The privileges admino_app holds on a table after every shipped migration
    (their table GRANTs and REVOKEs replayed in order)."""
    held: set[str] = set()
    for name in _shipped_names():
        for statement in _statements(name):
            change = _table_privileges(statement)
            if change is None or table not in change.tables or _ROLE not in change.grantees:
                continue
            if change.verb == "grant":
                held |= change.privileges
            else:
                held -= change.privileges
    return frozenset(held)


def _kind(statement: _Statement) -> str | None:
    """The contract kind of a top-level 0019 statement (None: not in the contract)."""
    function = _function_of(statement.raw)
    if function is not None:
        return {_WINDOW: _WINDOW_FUNCTION_KIND, _PURGE: _PURGE_KIND}.get(function.name)
    trigger = _trigger_of(statement)
    if trigger is not None:
        return _WINDOW_TRIGGER_KIND if trigger.name == _WINDOW else None
    change = _table_privileges(statement)
    if change is not None and change == _Privileges(
        "revoke", frozenset({"delete"}), frozenset({"organizations"}), frozenset({_ROLE})
    ):
        return _REVOKE_KIND
    return None


def _kinds() -> list[str | None]:
    return [_kind(statement) for statement in _statements()]


def _window_trigger() -> _Trigger:
    triggers = [t for s in _statements() if (t := _trigger_of(s)) is not None]
    assert len(triggers) == 1, triggers
    return triggers[0]


# ---------------------------------------------------------------------------
# Helpers: PL/pgSQL bodies as a tree of IF branches and statements
# ---------------------------------------------------------------------------


class _Leaf(NamedTuple):
    """One PL/pgSQL statement that isn't an IF (comments blanked, layout kept)."""

    raw: str


class _If(NamedTuple):
    """An IF: its (raw condition, statements) branches and its ELSE (None: no ELSE)."""

    branches: tuple[tuple[str, tuple[_Leaf | _If, ...]], ...]
    orelse: tuple[_Leaf | _If, ...] | None


_BLOCK_RE = re.compile(
    r"\s*(?:declare\b(?P<declare>.*?))?\bbegin\b(?P<code>.*)\bend\s*;?\s*",
    re.IGNORECASE | re.DOTALL,
)
_BRANCH_END = frozenset({"elsif", "else", "endif"})


def _block(body: str) -> tuple[str, str]:
    """(DECLARE section, statements) of a function body ``[DECLARE ...] BEGIN ... END``."""
    match = _BLOCK_RE.fullmatch(_masked(body))
    if match is None:
        pytest.fail("the function body is not [DECLARE ...] BEGIN ... END")
    declare = (
        ""
        if match.group("declare") is None
        else body[match.start("declare") : match.end("declare")]
    )
    return declare, body[match.start("code") : match.end("code")]


def _block_tokens(code: str) -> list[tuple[str, str]]:
    """The IF / ELSIF / ELSE / END IF markers and the statements of PL/pgSQL code, in
    order: (kind, raw text) with kind if, elsif, else, endif or stmt."""
    tokens: list[tuple[str, str]] = []
    for piece in _split(code, ";"):
        rest = piece
        while rest:
            masked = _masked(rest)
            opener = re.match(r"(?:if|elsif|elseif)\b", masked, re.IGNORECASE)
            if opener is not None:
                then = re.search(r"\bthen\b", masked[opener.end() :], re.IGNORECASE)
                if then is None:
                    pytest.fail(f"IF without THEN: {rest!r}")
                kind = "if" if opener.group(0).lower() == "if" else "elsif"
                tokens.append((kind, rest[opener.end() : opener.end() + then.start()].strip()))
                rest = rest[opener.end() + then.end() :].strip()
            elif re.fullmatch(r"end\s+if", masked, re.IGNORECASE):
                tokens.append(("endif", ""))
                rest = ""
            elif re.match(r"else\b", masked, re.IGNORECASE):
                tokens.append(("else", ""))
                rest = rest[4:].strip()
            else:
                tokens.append(("stmt", rest))
                rest = ""
    return tokens


def _parse_nodes(
    tokens: list[tuple[str, str]], index: int, stop: frozenset[str]
) -> tuple[tuple[_Leaf | _If, ...], int]:
    nodes: list[_Leaf | _If] = []
    while index < len(tokens) and tokens[index][0] not in stop:
        kind, text = tokens[index]
        index += 1
        if kind == "stmt":
            nodes.append(_Leaf(text))
            continue
        if kind != "if":
            pytest.fail(f"unexpected {kind.upper()} in a PL/pgSQL body")
        branches: list[tuple[str, tuple[_Leaf | _If, ...]]] = []
        orelse: tuple[_Leaf | _If, ...] | None = None
        condition = text
        while True:
            body, index = _parse_nodes(tokens, index, _BRANCH_END)
            branches.append((condition, body))
            if index >= len(tokens):
                pytest.fail("IF without END IF in a PL/pgSQL body")
            marker, condition = tokens[index]
            index += 1
            if marker == "elsif":
                continue
            if marker == "else":
                orelse, index = _parse_nodes(tokens, index, frozenset({"endif"}))
                if index >= len(tokens):
                    pytest.fail("ELSE without END IF in a PL/pgSQL body")
                index += 1
            break
        nodes.append(_If(tuple(branches), orelse))
    return tuple(nodes), index


def _tree(code: str) -> tuple[_Leaf | _If, ...]:
    tokens = _block_tokens(code)
    nodes, index = _parse_nodes(tokens, 0, frozenset())
    if index != len(tokens):
        pytest.fail(f"unexpected {tokens[index][0].upper()} in a PL/pgSQL body")
    return nodes


def _canon_node(node: _Leaf | _If) -> object:
    """A node with every statement and condition in _canon form."""
    if isinstance(node, _Leaf):
        return _canon(node.raw)
    return (
        tuple(
            (_canon(condition), tuple(_canon_node(n) for n in body))
            for condition, body in node.branches
        ),
        None if node.orelse is None else tuple(_canon_node(n) for n in node.orelse),
    )


def _leaves(nodes: Iterable[_Leaf | _If]) -> Iterator[_Leaf]:
    for node in nodes:
        if isinstance(node, _Leaf):
            yield node
            continue
        for _, body in node.branches:
            yield from _leaves(body)
        yield from _leaves(node.orelse or ())


# ---------------------------------------------------------------------------
# Helpers: the purge function and 0011's append-only trigger
# ---------------------------------------------------------------------------


def _purge_body(name: str = _MIGRATION_NAME) -> tuple[str, tuple[_Leaf | _If, ...]]:
    """(DECLARE section, top-level nodes) of purge_org_audit_events in a migration."""
    declare, code = _block(_function(_PURGE, name).body)
    return declare, _tree(code)


def _audit_deletes() -> list[_Leaf]:
    """Every DELETE FROM audit_events of the 0019 purge function, at any depth."""
    _, nodes = _purge_body()
    return [
        leaf
        for leaf in _leaves(nodes)
        if re.match(
            r"delete\s+from\s+(?:only\s+)?(?:public\s*\.\s*)?audit_events\b", _normalize(leaf.raw)
        )
    ]


def _frame_3_prefix(function: _Function) -> str:
    """What PG_CONTEXT reports as frame 3 for a statement run by this function."""
    types = [argument.split()[-1] for argument in _split(function.arguments, ",")]
    return f"PL/pgSQL function {function.name}({','.join(types)}) line "


def _frames_0011() -> list[tuple[str, str]]:
    """(frame-2 literal, frame-3 prefix) of each allow path of 0011's
    audit_events_append_only(), read from the shipped 0011."""
    _, code = _block(_function(_APPEND_ONLY, _PURGE_SOURCE).body)
    pairs: list[tuple[str, str]] = []
    for kind, text in _block_tokens(code):
        if kind not in ("if", "elsif"):
            continue
        frame_2 = re.search(rf"frames\s*\[\s*2\s*\]\s*=\s*({_LITERAL})", text)
        frame_3 = re.search(
            rf"starts_with\s*\(\s*frames\s*\[\s*3\s*\]\s*,\s*({_LITERAL})\s*\)", text, re.IGNORECASE
        )
        if frame_2 is not None and frame_3 is not None:
            pairs.append((_unliteral(frame_2.group(1)), _unliteral(frame_3.group(1))))
    assert pairs, "no frame checks found in 0011's audit_events_append_only()"
    return pairs


# ---------------------------------------------------------------------------
# Helpers: a PL/pgSQL interpreter for the trigger function
# ---------------------------------------------------------------------------

_Ast = tuple[object, ...]
_Row = dict[str, object]

_EXPRESSION_TOKEN_RE = re.compile(
    rf"\s*(?:(?P<literal>{_LITERAL})|(?P<number>\d+)"
    r"|(?P<symbol><=|>=|<>|!=|=>|::|[=<>+\-(),])"
    r"|(?P<word>[a-z_]\w*(?:\.[a-z_]\w*)?))"
)
_COMPARISONS: dict[str, Callable[[object, object], object]] = {
    "=": operator.eq,
    "<>": operator.ne,
    "!=": operator.ne,
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
}
_INTERVAL_RE = re.compile(r"\s*(\d+)\s*(days?|weeks?)\s*", re.IGNORECASE)


def _interval(text: str) -> timedelta:
    """An interval literal in days or weeks ('7 days', '1 week')."""
    match = _INTERVAL_RE.fullmatch(text)
    if match is None:
        pytest.fail(f"unsupported interval {text!r}")
    count = int(match.group(1))
    return (
        timedelta(weeks=count)
        if match.group(2).lower().startswith("week")
        else timedelta(days=count)
    )


class _ExpressionParser:
    """Recursive descent over the SQL expression subset a trigger condition may use:
    OR / AND / NOT, comparisons, IS [NOT] NULL, IS [NOT] DISTINCT FROM, + and -,
    casts, literals, interval literals, now() and its equivalents, make_interval(days
    => n), TG_OP and NEW / OLD fields. Anything else fails the test."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.tokens: list[str] = []
        position = 0
        stripped = text.strip()
        while position < len(stripped):
            match = _EXPRESSION_TOKEN_RE.match(stripped, position)
            if match is None or match.lastgroup is None:
                pytest.fail(f"unsupported expression: {text!r}")
            self.tokens.append(match.group(match.lastgroup))
            position = match.end()
        self.index = 0

    def parse(self) -> _Ast:
        node = self._or()
        if self.index != len(self.tokens):
            pytest.fail(f"unsupported expression: {self.text!r}")
        return node

    def _peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _take(self, expected: str | None = None) -> str:
        token = self._peek()
        if token is None or (expected is not None and token != expected):
            pytest.fail(f"unsupported expression: {self.text!r}")
        self.index += 1
        return token

    def _or(self) -> _Ast:
        node = self._and()
        while self._peek() == "or":
            self._take()
            node = ("or", node, self._and())
        return node

    def _and(self) -> _Ast:
        node = self._not()
        while self._peek() == "and":
            self._take()
            node = ("and", node, self._not())
        return node

    def _not(self) -> _Ast:
        if self._peek() == "not":
            self._take()
            return ("not", self._not())
        return self._comparison()

    def _comparison(self) -> _Ast:
        left = self._sum()
        token = self._peek()
        if token in _COMPARISONS:
            self._take()
            return ("compare", token, left, self._sum())
        if token != "is":
            return left
        self._take()
        negated = self._peek() == "not"
        if negated:
            self._take()
        if self._peek() == "null":
            self._take()
            node: _Ast = ("is null", left)
        else:
            self._take("distinct")
            self._take("from")
            node = ("distinct", left, self._sum())
        return ("not", node) if negated else node

    def _sum(self) -> _Ast:
        node = self._cast()
        while self._peek() in ("+", "-"):
            symbol = self._take()
            node = ("arithmetic", symbol, node, self._cast())
        return node

    def _cast(self) -> _Ast:
        node = self._term()
        while self._peek() == "::":
            self._take()
            node = ("cast", self._take(), node)
        return node

    def _term(self) -> _Ast:
        token = self._take()
        if token == "(":
            node = self._or()
            self._take(")")
            return node
        if token.startswith("'"):
            return ("const", _unliteral(token))
        if token == "interval" and (self._peek() or "").startswith("'"):
            return ("const", _interval(_unliteral(self._take())))
        if token in ("null", "true", "false"):
            return ("const", {"null": None, "true": True, "false": False}[token])
        if token in ("now", "transaction_timestamp") and self._peek() == "(":
            self._take("(")
            self._take(")")
            return ("now",)
        if token == "current_timestamp":
            return ("now",)
        if token == "make_interval":
            self._take("(")
            self._take("days")
            self._take("=>")
            days = self._take()
            self._take(")")
            if not days.isdigit():
                pytest.fail(f"unsupported expression: {self.text!r}")
            return ("const", timedelta(days=int(days)))
        if token == "tg_op":
            return ("tg_op",)
        field = re.fullmatch(r"(new|old)\.(\w+)", token)
        if field is not None:
            return ("field", field.group(1), field.group(2))
        pytest.fail(f"unsupported term {token!r} in {self.text!r}")


class _Env(NamedTuple):
    """A trigger call: TG_OP, OLD (None for an INSERT) and NEW (mutable)."""

    op: str
    old: _Row | None
    new: _Row


def _evaluate(node: _Ast, env: _Env) -> object:
    """The value of an expression, with SQL's NULL (None) semantics."""
    kind = node[0]
    if kind == "const":
        return node[1]
    if kind == "now":
        return _NOW
    if kind == "tg_op":
        return env.op
    if kind == "field":
        record = env.new if node[1] == "new" else env.old
        if record is None:
            return None
        if node[2] not in record:
            pytest.fail(f"the trigger reads an unknown column {node[1]}.{node[2]}")
        return record[str(node[2])]
    if kind == "cast":
        value = _evaluate(node[2], env)
        if node[1] == "interval" and isinstance(value, str):
            return _interval(value)
        if node[1] in ("interval", "timestamptz", "text"):
            return value
        pytest.fail(f"unsupported cast to {node[1]}")
    if kind == "not":
        value = _evaluate(node[1], env)
        return None if value is None else not value
    if kind in ("and", "or"):
        values = (_evaluate(node[1], env), _evaluate(node[2], env))
        if any(value not in (True, False, None) for value in values):
            pytest.fail(f"non-boolean operand of {kind.upper()}: {values!r}")
        decisive = kind == "or"  # TRUE decides an OR, FALSE decides an AND
        if decisive in values:
            return decisive
        return None if None in values else not decisive
    left = _evaluate(node[2] if kind in ("compare", "arithmetic") else node[1], env)
    if kind == "is null":
        return left is None
    right = _evaluate(node[3] if kind in ("compare", "arithmetic") else node[2], env)
    if kind == "distinct":
        if left is None or right is None:
            return (left is None) != (right is None)
        return left != right
    if left is None or right is None:
        return None
    if kind == "compare":
        return _COMPARISONS[str(node[1])](left, right)
    if isinstance(right, str):
        right = _interval(right)  # an untyped literal next to a timestamp is an interval
    return left + right if node[1] == "+" else left - right


class _Raise(NamedTuple):
    message: str
    errcode: str


class _Return(NamedTuple):
    record: str  # new, old or null


class _Assign(NamedTuple):
    column: str
    expression: _Ast


class _Choice(NamedTuple):
    branches: tuple[tuple[_Ast, tuple[_Raise | _Return | _Assign | _Choice, ...]], ...]
    orelse: tuple[_Raise | _Return | _Assign | _Choice, ...]


_Op = _Raise | _Return | _Assign | _Choice

_RAISE_RE = re.compile(
    rf"raise\s+exception\s+(?P<message>{_LITERAL})"
    r"(?:\s+using\s+errcode\s*=\s*'(?P<errcode>\w+)')?"
)
_ASSIGN_RE = re.compile(r"new\.(?P<column>\w+)\s*:?=\s*(?P<expression>.+)", re.DOTALL)
_RETURN_RE = re.compile(r"return\s+(?P<record>new|old|null)")
_ERRCODES = {
    "23514": _CHECK_VIOLATION,
    "42501": "insufficient_privilege",
    "P0001": "raise_exception",
}


def _compile_leaf(raw: str) -> _Op | None:
    """A trigger statement: RETURN, a plain-literal RAISE EXCEPTION, an assignment to
    NEW, or NULL (a no-op, None). Anything else fails the test."""
    text = _normalize(raw)
    if (returned := _RETURN_RE.fullmatch(text)) is not None:
        return _Return(returned.group("record"))
    if (raised := _RAISE_RE.fullmatch(text)) is not None:
        code = raised.group("errcode") or "P0001"
        return _Raise(
            _unliteral(raised.group("message")), _ERRCODES.get(code.upper(), code.lower())
        )
    if (assigned := _ASSIGN_RE.fullmatch(text)) is not None:
        expression = _ExpressionParser(assigned.group("expression")).parse()
        return _Assign(assigned.group("column"), expression)
    if text == "null":
        return None
    pytest.fail(f"unsupported statement in the trigger function: {text!r}")


def _compile(nodes: Iterable[_Leaf | _If]) -> tuple[_Op, ...]:
    ops: list[_Op] = []
    for node in nodes:
        if isinstance(node, _If):
            branches = tuple(
                (_ExpressionParser(_normalize(condition)).parse(), _compile(body))
                for condition, body in node.branches
            )
            ops.append(_Choice(branches, _compile(node.orelse or ())))
        elif (op := _compile_leaf(node.raw)) is not None:
            ops.append(op)
    return tuple(ops)


def _window_program() -> tuple[_Op, ...]:
    """The 0019 trigger function, compiled for _run."""
    declare, code = _block(_function(_WINDOW).body)
    if declare.strip():
        pytest.fail("the trigger function declares variables; it should read NEW, OLD and TG_OP")
    return _compile(_tree(code))


def _walk(ops: Iterable[_Op]) -> Iterator[_Op]:
    for op in ops:
        yield op
        if isinstance(op, _Choice):
            for _, body in op.branches:
                yield from _walk(body)
            yield from _walk(op.orelse)


class _Outcome(NamedTuple):
    """What a BEFORE row trigger did with a row."""

    action: str  # "return" (the row written), "raise", "skip" (RETURN NULL), "end" (no RETURN)
    row: tuple[tuple[str, object], ...] | None
    errcode: str | None


_REFUSED = _Outcome("raise", None, _CHECK_VIOLATION)


def _frozen(row: _Row) -> tuple[tuple[str, object], ...]:
    return tuple(sorted(row.items()))


def _accepted(row: _Row) -> _Outcome:
    return _Outcome("return", _frozen(row), None)


def _execute(ops: Iterable[_Op], env: _Env) -> _Outcome | None:
    for op in ops:
        if isinstance(op, _Choice):
            chosen = op.orelse
            for condition, body in op.branches:
                value = _evaluate(condition, env)
                if value not in (True, False, None):
                    pytest.fail(f"non-boolean IF condition: {value!r}")
                if value is True:
                    chosen = body
                    break
            result = _execute(chosen, env)
            if result is not None:
                return result
        elif isinstance(op, _Assign):
            if op.column not in env.new:
                pytest.fail(f"the trigger assigns an unknown column NEW.{op.column}")
            env.new[op.column] = _evaluate(op.expression, env)
        elif isinstance(op, _Raise):
            return _Outcome("raise", None, op.errcode)
        elif op.record == "new":
            return _Outcome("return", _frozen(env.new), None)
        elif op.record == "old" and env.old is not None:
            return _Outcome("return", _frozen(env.old), None)
        else:
            return _Outcome("skip", None, None)
    return None


def _run(program: tuple[_Op, ...], op: str, old: _Row | None, new: _Row) -> _Outcome:
    """Fire the trigger function for one row."""
    env = _Env(op, None if old is None else dict(old), dict(new))
    result = _execute(program, env)
    return _Outcome("end", None, None) if result is None else result


def _fire(op: str, old: _Row | None, new: _Row) -> _Outcome:
    return _run(_window_program(), op, old, new)


def _row(
    status: str,
    requested: datetime | None = None,
    purge_after: datetime | None = None,
    name: str = "Acme",
) -> _Row:
    """An organizations row, reduced to the columns the window is about (and a name)."""
    return {
        "status": status,
        "deletion_requested_at": requested,
        "purge_after": purge_after,
        "name": name,
    }


def _expected(op: str, old: _Row | None, new: _Row, floor: int) -> _Outcome:
    """The contract: what the trigger does with a row."""
    if new["status"] != _PENDING:
        return _accepted(new)
    if op == "UPDATE" and old is not None and old["status"] == _PENDING:
        frozen = all(new[column] == old[column] for column in _DATES)
        return _accepted(new) if frozen else _REFUSED
    purge_after = new["purge_after"]
    if not isinstance(purge_after, datetime) or purge_after < _NOW + timedelta(days=floor):
        return _REFUSED
    return _accepted({**new, "deletion_requested_at": _NOW})


def _dates(floor: int) -> tuple[datetime | None, ...]:
    window = _NOW + timedelta(days=floor)
    return (None, _NOW - _DAY, _NOW, window - _TICK, window, window + timedelta(days=53))


def _scenarios(floor: int) -> Iterator[tuple[str, _Row | None, _Row]]:
    """Every (TG_OP, OLD, NEW) over the statuses and the dates around the window."""
    dates = _dates(floor)
    for new_status in _STATUSES:
        for requested in dates:
            for purge_after in dates:
                new = _row(new_status, requested, purge_after, "New name")
                yield "INSERT", None, new
                for old_status in _STATUSES:
                    for old_requested in dates:
                        for old_purge_after in dates:
                            old = _row(old_status, old_requested, old_purge_after, "Old name")
                            yield "UPDATE", old, new


# ---------------------------------------------------------------------------
# Helpers: the floor of the deletion grace period
# ---------------------------------------------------------------------------

_GRACE_CHECK_RE = re.compile(
    r"check\s*\(\s*org_deletion_grace_days\s+between\s+(\d+)\s+and\s+\d+\s*\)"
)
_INTERVAL_TEXT_RE = re.compile(
    rf"interval\s*(?P<a>{_LITERAL})|(?P<b>{_LITERAL})\s*::\s*interval"
    r"|make_interval\s*\(\s*days\s*=>\s*(?P<c>\d+)\s*\)"
    rf"|(?:now\s*\(\s*\)|current_timestamp)\s*\+\s*(?P<d>{_LITERAL})"
)


def _ge_values(metadata: Iterable[object]) -> list[int]:
    values: list[int] = []
    for item in metadata:
        value = getattr(item, "ge", None)
        if isinstance(value, int):
            values.append(value)
    return values


def _setting_floor() -> int:
    """The minimum of the platform setting retention.org_deletion_grace_days."""
    field = models_mod.PlatformRetention.model_fields["org_deletion_grace_days"]
    (floor,) = _ge_values(field.metadata)
    return floor


def _alias_floor() -> int:
    """The minimum of admino.models._GraceDays."""
    _, *annotations = get_args(models_mod._GraceDays)
    (floor,) = [
        value
        for annotation in annotations
        for value in _ge_values(getattr(annotation, "metadata", [annotation]))
    ]
    return floor


def _check_floor() -> int:
    """The lower bound of the latest CHECK (org_deletion_grace_days BETWEEN ...)."""
    floors = [
        int(floor)
        for name in _shipped_names()
        for floor in _GRACE_CHECK_RE.findall(_normalize(_raw(name)))
    ]
    assert floors, "no CHECK (org_deletion_grace_days BETWEEN ...) in the shipped migrations"
    return floors[-1]


def _window_intervals() -> set[int]:
    """The day counts of every interval in the trigger function's body."""
    body = _normalize(_function(_WINDOW).body)
    days: set[int] = set()
    for match in _INTERVAL_TEXT_RE.finditer(body):
        if match.group("c") is not None:
            days.add(int(match.group("c")))
        else:
            literal = match.group("a") or match.group("b") or match.group("d")
            days.add(_interval(_unliteral(literal)).days)
    return days


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0019File:
    """The migration ships as version 19 and is applied by run_migrations."""

    def test_migration_0019_file_is_shipped_as_version_19(self) -> None:
        """0019_org_purge_window.sql exists and its number is version 19."""
        assert _path().is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == _VERSION

    def test_migration_0019_is_the_only_version_19(self) -> None:
        """No other file claims version 19."""
        nineteens = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert nineteens == [_MIGRATION_NAME]

    async def test_migration_0019_run_migrations_applies_it_as_version_19(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0018 applied, run_migrations executes the file and records 19."""
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

    async def test_migration_0019_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        """The SQL run for version 19 is the shipped file, byte for byte."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _raw()

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    async def test_migration_0019_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0019 recorded, the shipped SQL is not executed a second time."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _raw()

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0019_is_parameter_free(self) -> None:
        """No $n placeholder anywhere, function bodies included ($$ is a dollar quote,
        not a parameter), and no %s / %( either."""
        texts: list[str] = []
        for statement in _statements():
            masked, _, bodies = _scan(statement.norm)
            texts.append(masked)
            texts.extend(_masked(body) for body in bodies)
        joined = " ".join(texts)

        assert re.search(r"\$\d", joined) is None
        assert "%s" not in joined
        assert "%(" not in joined

    def test_migration_0019_header_comment_explains_the_window(self) -> None:
        """The header names the runtime role, the audit log and the floor in days."""
        header = _header_comment().lower()

        assert _ROLE in header, header
        assert "audit" in header, header
        assert re.search(rf"\b{_setting_floor()}\s+days\b", header), header


# ---------------------------------------------------------------------------
# 2. Exactly the contract's statements
# ---------------------------------------------------------------------------


class TestMigration0019Statements:
    """The window function and trigger, the replaced purge, the revoke; nothing else."""

    def test_migration_0019_every_statement_is_part_of_the_contract(self) -> None:
        """Each top-level statement is one of the four contract statements."""
        unexpected = [s.norm[:120] for s in _statements() if _kind(s) is None]

        assert unexpected == []

    def test_migration_0019_has_each_contract_statement_once(self) -> None:
        """The window function, the trigger, the purge function and the revoke appear
        exactly once each."""
        assert Counter(_kinds()) == Counter(_KINDS)

    def test_migration_0019_creates_the_window_function_before_its_trigger(self) -> None:
        """CREATE TRIGGER needs its function: the function comes first."""
        kinds = _kinds()

        assert kinds.index(_WINDOW_FUNCTION_KIND) < kinds.index(_WINDOW_TRIGGER_KIND)

    def test_migration_0019_window_function_is_a_plpgsql_trigger_function(self) -> None:
        """organizations_deletion_window() takes no argument, RETURNS trigger, plpgsql."""
        function = _function(_WINDOW)

        assert function.arguments == ""
        assert function.returns == "trigger"
        assert _language(function) == "plpgsql"

    def test_migration_0019_window_function_runs_with_the_callers_rights(self) -> None:
        """Not SECURITY DEFINER: it only reads NEW, OLD and the clock, so it needs no
        privilege of its own."""
        assert not _is_security_definer(_function(_WINDOW))

    def test_migration_0019_trigger_fires_before_insert_or_update_on_organizations(
        self,
    ) -> None:
        """BEFORE (it rewrites NEW) INSERT OR UPDATE (every column) ON organizations; a
        plain trigger, not a constraint trigger."""
        trigger = _window_trigger()

        assert trigger.name == _WINDOW
        assert trigger.timing == "before"
        assert trigger.events == frozenset({"insert", "update"})
        assert trigger.table == "organizations"
        assert not trigger.constraint

    def test_migration_0019_trigger_runs_the_window_function_for_each_row(self) -> None:
        """FOR EACH ROW EXECUTE FUNCTION organizations_deletion_window(), and nothing
        more: no WHEN clause that could exempt a row."""
        assert _window_trigger().function == _WINDOW

    def test_migration_0019_creates_only_the_two_functions(self) -> None:
        """The window trigger function and the org purge; no other function."""
        created = sorted(f.name for s in _statements() if (f := _function_of(s.raw)) is not None)

        assert created == sorted([_WINDOW, _PURGE])


# ---------------------------------------------------------------------------
# 3. The deletion window, run through the trigger function
# ---------------------------------------------------------------------------

_ENTRY_PATHS = (
    pytest.param("INSERT", None, id="insert"),
    pytest.param("UPDATE", "active", id="from-active"),
    pytest.param("UPDATE", "deactivated", id="from-deactivated"),
)


def _old(status: str | None) -> _Row | None:
    return None if status is None else _row(status, None, None, "Old name")


class TestMigration0019DeletionWindow:
    """Entering pending_deletion is stamped and needs the floor; pending dates are
    frozen; leaving it, or never being in it, is free."""

    @pytest.mark.parametrize(("op", "old_status"), _ENTRY_PATHS)
    def test_migration_0019_entering_pending_at_the_floor_is_accepted(
        self, op: str, old_status: str | None
    ) -> None:
        """purge_after = now() + the floor exactly (the shortest grace the app can
        schedule) is accepted."""
        new = _row(_PENDING, _NOW, _NOW + timedelta(days=_setting_floor()))

        assert _fire(op, _old(old_status), new) == _accepted(new)

    @pytest.mark.parametrize("short", ["null", "in-the-past", "now", "one-microsecond-short"])
    @pytest.mark.parametrize(("op", "old_status"), _ENTRY_PATHS)
    def test_migration_0019_entering_pending_short_of_the_floor_is_refused(
        self, op: str, old_status: str | None, short: str
    ) -> None:
        """A NULL purge_after, or one earlier than now() + the floor, is refused with
        check_violation: no role can make an org due early."""
        window = _NOW + timedelta(days=_setting_floor())
        purge_after = {
            "null": None,
            "in-the-past": _NOW - _DAY,
            "now": _NOW,
            "one-microsecond-short": window - _TICK,
        }[short]

        assert _fire(op, _old(old_status), _row(_PENDING, _NOW, purge_after)) == _REFUSED

    @pytest.mark.parametrize(
        "requested",
        [None, _NOW - timedelta(days=30), _NOW + timedelta(days=30)],
        ids=["null", "back-dated", "future"],
    )
    @pytest.mark.parametrize(("op", "old_status"), _ENTRY_PATHS)
    def test_migration_0019_entering_pending_stamps_the_request_with_now(
        self, op: str, old_status: str | None, requested: datetime | None
    ) -> None:
        """deletion_requested_at becomes now() (the database clock), whatever the
        statement says; the rest of the row is written as given."""
        new = _row(_PENDING, requested, _NOW + timedelta(days=200))

        assert _fire(op, _old(old_status), new) == _accepted({**new, "deletion_requested_at": _NOW})

    @pytest.mark.parametrize(
        "change",
        [
            pytest.param({"deletion_requested_at": _NOW}, id="request-restamped"),
            pytest.param({"deletion_requested_at": _NOW - 60 * _DAY}, id="request-back-dated"),
            pytest.param({"deletion_requested_at": None}, id="request-cleared"),
            pytest.param({"purge_after": _NOW}, id="purge-made-due"),
            pytest.param({"purge_after": _NOW - _DAY}, id="purge-moved-to-the-past"),
            pytest.param({"purge_after": _NOW + 200 * _DAY}, id="purge-postponed"),
            pytest.param({"purge_after": None}, id="purge-cleared"),
            pytest.param(
                {"deletion_requested_at": _NOW, "purge_after": _NOW + 300 * _DAY},
                id="both-moved-past-the-floor",
            ),
        ],
    )
    def test_migration_0019_pending_dates_are_frozen(self, change: _Row) -> None:
        """While a row stays pending_deletion, changing either date (NULL included) is
        refused with check_violation."""
        old = _row(_PENDING, _NOW - _DAY, _NOW + 100 * _DAY, "Old name")
        new = {**old, "name": "New name", **change}

        assert _fire("UPDATE", old, new) == _REFUSED

    @pytest.mark.parametrize(
        "old",
        [
            pytest.param(_row(_PENDING, _NOW - 40 * _DAY, _NOW - 10 * _DAY), id="due"),
            pytest.param(_row(_PENDING, _NOW - _DAY, _NOW + 100 * _DAY), id="not-yet-due"),
            pytest.param(_row(_PENDING, _NOW, _NOW), id="scheduled-for-now-before-0019"),
        ],
    )
    def test_migration_0019_pending_row_keeping_its_dates_is_accepted_unchanged(
        self, old: _Row
    ) -> None:
        """Other columns of a pending row may change; its dates are neither restamped
        nor checked against the floor again."""
        new = {**old, "name": "New name"}

        assert _fire("UPDATE", old, new) == _accepted(new)

    @pytest.mark.parametrize("new_status", ["deactivated", "active"])
    @pytest.mark.parametrize(
        "old_purge_after", [_NOW - _DAY, _NOW + 100 * _DAY], ids=["due", "not-yet-due"]
    )
    def test_migration_0019_cancelling_a_pending_deletion_is_accepted(
        self, new_status: str, old_purge_after: datetime
    ) -> None:
        """#154: a pending deletion can be cancelled until the purge (status leaves
        pending_deletion, both dates NULL); the row is written as given."""
        old = _row(_PENDING, _NOW - 40 * _DAY, old_purge_after)
        new = _row(new_status, None, None)

        assert _fire("UPDATE", old, new) == _accepted(new)

    def test_migration_0019_leaving_pending_is_never_refused_on_any_dates(self) -> None:
        """No branch refuses or rewrites a row leaving pending_deletion, whatever its
        old and new dates."""
        program = _window_program()
        dates = _dates(_setting_floor())
        changed = [
            (old, new)
            for new_status in ("active", "deactivated")
            for old in (_row(_PENDING, a, b) for a in dates for b in dates)
            for new in (_row(new_status, c, d, "New") for c in dates for d in dates)
            if _run(program, "UPDATE", old, new) != _accepted(new)
        ]

        assert changed == [], f"{len(changed)} cases, e.g. {changed[:2]}"

    @pytest.mark.parametrize(
        ("op", "old", "new"),
        [
            pytest.param("INSERT", None, _row("active"), id="insert-active"),
            pytest.param(
                "INSERT", None, _row("deactivated", _NOW, _NOW), id="insert-deactivated-with-dates"
            ),
            pytest.param("UPDATE", _row("active"), _row("deactivated"), id="deactivate"),
            pytest.param(
                "UPDATE", _row("deactivated"), _row("active", name="New name"), id="reactivate"
            ),
            pytest.param(
                "UPDATE",
                _row("active", _NOW - _DAY, _NOW),
                _row("active", _NOW - _DAY, _NOW - _DAY),
                id="active-with-dates",
            ),
        ],
    )
    def test_migration_0019_rows_outside_pending_are_untouched(
        self, op: str, old: _Row | None, new: _Row
    ) -> None:
        """A row that is not entering or staying in pending_deletion is written as given."""
        assert _fire(op, old, new) == _accepted(new)

    def test_migration_0019_window_matches_the_contract_on_every_combination(self) -> None:
        """INSERT and UPDATE, every old and new status, and NULL / past / now / just
        short of / exactly at / well past the floor for each date: the trigger does
        what the contract says, case by case."""
        program = _window_program()
        floor = _setting_floor()
        mismatches = []
        for op, old, new in _scenarios(floor):
            outcome = _run(program, op, old, new)
            expected = _expected(op, old, new, floor)
            if outcome != expected:
                mismatches.append((op, old, new, outcome, expected))

        assert mismatches == [], f"{len(mismatches)} cases differ, e.g. {mismatches[:2]}"

    def test_migration_0019_window_refusals_are_plain_literal_check_violations(self) -> None:
        """Every RAISE is RAISE EXCEPTION '<literal>' USING ERRCODE = 'check_violation':
        no format placeholder, no row data, no input."""
        raises = [op for op in _walk(_window_program()) if isinstance(op, _Raise)]

        assert raises
        for raised in raises:
            assert raised.errcode == _CHECK_VIOLATION, raised
            assert raised.message.strip(), raised
            assert "%" not in raised.message, raised

    def test_migration_0019_window_only_ever_returns_new(self) -> None:
        """RETURN NEW only: never OLD (which would undo the update) nor NULL (which
        would skip the row silently)."""
        returns = [op for op in _walk(_window_program()) if isinstance(op, _Return)]

        assert returns
        assert {op.record for op in returns} == {"new"}

    def test_migration_0019_window_function_runs_no_sql(self) -> None:
        """The body only compares and assigns: no query, DML or dynamic SQL."""
        body = _masked(_normalize(_function(_WINDOW).body))

        assert (
            re.search(
                r"\b(?:select|insert|update|delete|truncate|copy|merge|execute|perform)\b", body
            )
            is None
        ), body

    def test_migration_0019_window_floor_is_the_platform_minimum_grace(self) -> None:
        """The trigger's interval is the floor of org_deletion_grace_days: the
        PlatformRetention field and models._GraceDays (ge) and the migrations' CHECK
        (BETWEEN <floor> AND ...) all agree with it."""
        floor = _setting_floor()

        assert (_window_intervals(), _alias_floor(), _check_floor()) == ({floor}, floor, floor)

    def test_migration_0019_the_app_schedule_passes_the_window(self) -> None:
        """organizations._SCHEDULE_SQL sets deletion_requested_at = now() and
        purge_after = now() + $2::interval; with any allowed grace (floor to maximum)
        the trigger accepts the scheduled row."""
        schedule = _canon(organizations_mod._SCHEDULE_SQL)
        field = models_mod.PlatformRetention.model_fields["org_deletion_grace_days"]
        maximum = next(item.le for item in field.metadata if getattr(item, "le", None))
        program = _window_program()

        assert "deletion_requested_at=now()" in schedule
        assert "purge_after=now()+$2::interval" in schedule
        for grace_days in (_setting_floor(), 30, maximum):
            new = _row(_PENDING, _NOW, _NOW + timedelta(days=grace_days))
            assert _run(program, "UPDATE", _row("active"), new) == _accepted(new), grace_days


# ---------------------------------------------------------------------------
# 4. purge_org_audit_events(uuid): the audit events, then the org row
# ---------------------------------------------------------------------------


class TestMigration0019PurgeFunction:
    """The purge keeps 0011's contract with the append-only trigger and also deletes
    the org row, as the owner."""

    def test_migration_0019_purge_function_is_replaced_in_place(self) -> None:
        """CREATE OR REPLACE FUNCTION purge_org_audit_events(target_org uuid) RETURNS
        bigint: the same signature, so it keeps its owner, its grants and 0011's frame
        check; the argument name is part of the DELETE text the trigger compares."""
        function = _function(_PURGE)

        assert function.or_replace
        assert re.fullmatch(r"(?:in\s+)?target_org\s+uuid", function.arguments), function
        assert function.returns in {"bigint", "int8"}
        assert _language(function) == "plpgsql"

    def test_migration_0019_purge_function_is_security_definer(self) -> None:
        """Re-declared SECURITY DEFINER (CREATE OR REPLACE resets it otherwise): it runs
        as the owner, so the app needs no DELETE on audit_events or organizations."""
        function = _function(_PURGE)

        assert _is_security_definer(function), function.options
        assert re.search(r"\bsecurity\s+invoker\b", function.options) is None

    def test_migration_0019_purge_function_pins_its_search_path(self) -> None:
        """SET search_path = public, pg_temp, as two names (not one 'public, pg_temp'
        literal) and as its only setting: a SECURITY DEFINER function can't be hijacked
        through objects in another schema."""
        assert _settings(_function(_PURGE).options) == {"search_path": _SEARCH_PATH}

    def test_migration_0019_purge_function_still_matches_the_0011_frame_3_check(self) -> None:
        """0011's append-only trigger allows the org purge only from frame 3 'PL/pgSQL
        function purge_org_audit_events(uuid) line ': the replaced function still is
        that function."""
        prefixes = [frame_3 for _, frame_3 in _frames_0011()]

        assert _frame_3_prefix(_function(_PURGE)) in prefixes

    def test_migration_0019_purge_precondition_is_unchanged_from_0011(self) -> None:
        """The body starts with 0011's IF NOT EXISTS (... id = target_org AND status =
        'pending_deletion' AND purge_after <= now()) THEN RAISE ... END IF, unchanged."""
        _, nodes = _purge_body()
        _, original = _purge_body(_PURGE_SOURCE)

        assert isinstance(original[0], _If)
        assert nodes, "the purge function has no statements"
        assert _canon_node(nodes[0]) == _canon_node(original[0])

    def test_migration_0019_purge_deletes_the_audit_events_with_the_0011_text(self) -> None:
        """Exactly one DELETE FROM audit_events, written byte for byte 'DELETE FROM
        audit_events WHERE org_id = target_org' on one line: PG_CONTEXT reports this
        text and 0011's trigger compares it."""
        assert [leaf.raw for leaf in _audit_deletes()] == [_AUDIT_DELETE]

    def test_migration_0019_purge_audit_delete_is_the_0011_frame_2_literal(self) -> None:
        """The DELETE text and the function signature are exactly the frame-2 literal
        and the frame-3 prefix of one allow path of 0011's audit_events_append_only()."""
        (delete,) = _audit_deletes()
        frame_3 = _frame_3_prefix(_function(_PURGE))

        assert (f'SQL statement "{delete.raw}"', frame_3) in _frames_0011()

    def test_migration_0019_purge_counts_the_audit_rows_right_after_deleting_them(
        self,
    ) -> None:
        """GET DIAGNOSTICS <n> = ROW_COUNT is the statement right after the audit DELETE
        (not after the org DELETE, whose count is 1)."""
        _, nodes = _purge_body()
        canon = [_canon(n.raw) if isinstance(n, _Leaf) else None for n in nodes]
        index = canon.index(_canon(_AUDIT_DELETE))

        assert re.fullmatch(r"get diagnostics \w+:?=row_count", canon[index + 1] or ""), canon

    def test_migration_0019_purge_deletes_the_org_row_after_the_audit_events(self) -> None:
        """DELETE FROM organizations WHERE id = target_org, unconditional, after the
        audit DELETE (the append-only trigger checks the org row while they go)."""
        _, nodes = _purge_body()
        canon = [_canon(n.raw) if isinstance(n, _Leaf) else "" for n in nodes]
        org_deletes = [
            index
            for index, text in enumerate(canon)
            if re.fullmatch(
                r"delete from (?:public\.)?organizations where (?:id=target_org|target_org=id)",
                text,
            )
        ]

        assert len(org_deletes) == 1, canon
        assert org_deletes[0] > canon.index(_canon(_AUDIT_DELETE)), canon

    def test_migration_0019_purge_returns_the_audit_count(self) -> None:
        """RETURN <n> last, where <n> is the bigint the GET DIAGNOSTICS after the audit
        DELETE filled."""
        declare, nodes = _purge_body()
        canon = [_canon(n.raw) if isinstance(n, _Leaf) else "" for n in nodes]
        diagnostics = re.fullmatch(
            r"get diagnostics (\w+):?=row_count", canon[canon.index(_canon(_AUDIT_DELETE)) + 1]
        )

        assert diagnostics is not None, canon
        counter = diagnostics.group(1)
        assert canon[-1] == f"return {counter}", canon
        assert re.search(rf"\b{counter} (?:bigint|int8) ?;", _normalize(declare)), declare

    def test_migration_0019_purge_body_is_exactly_the_contract_sequence(self) -> None:
        """Precondition, audit DELETE, GET DIAGNOSTICS, org DELETE, RETURN: five
        top-level statements and no other DML."""
        _, nodes = _purge_body()
        leaves = [_canon(n.raw) for n in nodes[1:] if isinstance(n, _Leaf)]

        assert len(nodes) == 5, [_canon_node(n) for n in nodes]
        assert len(leaves) == 4, leaves
        assert leaves[0] == _canon(_AUDIT_DELETE)
        assert re.fullmatch(r"get diagnostics (\w+):?=row_count", leaves[1]), leaves
        assert re.fullmatch(
            r"delete from (?:public\.)?organizations where id=target_org", leaves[2]
        )
        assert re.fullmatch(r"return \w+", leaves[3]), leaves

    def test_migration_0019_purge_uses_no_dynamic_sql(self) -> None:
        """No EXECUTE, PERFORM or format(): static SQL with the org id as a typed argument."""
        body = _masked(_normalize(_function(_PURGE).body))

        assert re.search(r"\b(?:execute|perform)\b|\bformat\s*\(", body) is None, body


# ---------------------------------------------------------------------------
# 5. Privileges: admino_app can no longer delete organizations
# ---------------------------------------------------------------------------


class TestMigration0019Privileges:
    """Only the owner-run purge deletes organizations; 0019 grants nothing."""

    def test_migration_0019_revokes_delete_on_organizations_from_the_runtime_role(
        self,
    ) -> None:
        """REVOKE DELETE ON organizations FROM admino_app (database.RUNTIME_ROLE)."""
        assert db_mod.RUNTIME_ROLE == _ROLE
        assert _REVOKE_KIND in _kinds()

    def test_migration_0019_runtime_role_keeps_select_insert_update_on_organizations(
        self,
    ) -> None:
        """Replaying every shipped GRANT and REVOKE: admino_app ends with exactly
        SELECT, INSERT, UPDATE on organizations."""
        assert _runtime_privileges_on("organizations") == frozenset({"select", "insert", "update"})

    def test_migration_0019_grants_nothing(self) -> None:
        """No GRANT anywhere in 0019: top level and function bodies (literals aside)."""
        texts: list[str] = []
        for statement in _statements():
            masked, _, bodies = _scan(statement.norm)
            texts.append(masked)
            texts.extend(_masked(body) for body in bodies)

        assert re.search(r"\bgrant\b", " ".join(texts)) is None

    def test_migration_0019_passes_the_0018_grant_guards(self) -> None:
        """With 0019 shipped, every grant guard of tests/test_migration_0018.py
        (section 7) still passes over all shipped migrations."""
        from tests.test_migration_0018 import _GUARDS, _shipped

        migrations = _shipped()
        violations = {guard_id: guard(migrations) for guard_id, guard in _GUARDS}

        assert _MIGRATION_NAME in [migration.name for migration in migrations]
        assert violations == {guard_id: [] for guard_id, _ in _GUARDS}


# ---------------------------------------------------------------------------
# 6. Nothing else changes
# ---------------------------------------------------------------------------

# (id, pattern) never found at 0019's top level (comments, literals and bodies aside).
_MUST_NOT: tuple[tuple[str, str], ...] = (
    ("insert", r"\binsert\s+into\b"),
    ("update", r"\bupdate\s+(?:only\s+)?[\w.\"]+\s+set\b"),
    ("delete", r"\bdelete\s+from\b"),
    ("truncate", r"\btruncate\b"),
    ("copy", r"\bcopy\b"),
    ("merge", r"\bmerge\s+into\b"),
    (
        "create-table",
        r"\bcreate\s+(?:(?:global|local)\s+)?(?:(?:temp|temporary|unlogged)\s+)?table\b",
    ),
    ("drop", r"\bdrop\b"),
    ("alter", r"\balter\b"),
    ("grant", r"\bgrant\b"),
    ("default-privileges", r"\bdefault\s+privileges\b"),
    ("owner-to", r"\bowner\s+to\b"),
    ("create-role", r"\bcreate\s+(?:role|user|group)\b"),
    ("session-replication-role", r"\bsession_replication_role\b"),
    ("disable-trigger", r"\bdisable\b"),
    ("event-trigger", r"\bevent\s+trigger\b"),
    ("rule", r"\bcreate\s+(?:or\s+replace\s+)?rule\b"),
    ("append-only-trigger-function", r"\baudit_events_append_only\b"),
    ("retention-purge-function", r"\bpurge_audit_events\b"),
    ("set-role", r"\bset\s+(?:(?:local|session)\s+)?(?:role|session\s+authorization)\b"),
)


class TestMigration0019ChangesNothingElse:
    """No data, schema, privilege or trigger change beyond the contract."""

    @pytest.mark.parametrize(
        "pattern", [pattern for _, pattern in _MUST_NOT], ids=[i for i, _ in _MUST_NOT]
    )
    def test_migration_0019_top_level_does_not_contain(self, pattern: str) -> None:
        """Outside the function bodies: no data write, no table, nothing dropped or
        altered, no grant or default privilege, no role change, no trigger switched
        off, and neither audit_events_append_only() nor purge_audit_events(integer)
        touched."""
        assert re.search(pattern, _top_level()) is None, _top_level()

    def test_migration_0019_creates_exactly_one_trigger(self) -> None:
        """One CREATE TRIGGER (organizations_deletion_window) and no other trigger."""
        created = re.findall(
            r"\bcreate\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger\b", _top_level()
        )

        assert len(created) == 1
        assert _window_trigger().name == _WINDOW

    def test_migration_0019_runs_no_anonymous_block(self) -> None:
        """No DO block: its body would hide statements from these checks."""
        assert not any(re.match(r"do\b", statement.masked) for statement in _statements())
