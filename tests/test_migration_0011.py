"""Tests for migration 0011_org_lifecycle.sql — the org purge path of the audit log (GH-154).

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0005.py / test_migration_0010.py pattern): it must
exist, be applied by run_migrations as version 11, and make exactly the
changes GH-154 needs. The SQL is read with ``--`` comments blanked; statements
are split outside literals and dollar-quoted bodies; keywords are compared
case-insensitively with whitespace collapsed, while string literals are kept
byte for byte (PL/pgSQL compares them exactly). PL/pgSQL bodies are read by a
small IF/ELSIF/ELSE parser, so every ``RETURN OLD`` is known together with the
conditions that guard it, whether they are written as nested IFs, one IF with
AND, or alternatives with OR.

What these tests pin down:
- ``purge_org_audit_events(target_org uuid) RETURNS bigint`` (plpgsql) raises a
  plain-literal RAISE EXCEPTION unless ``EXISTS (SELECT 1 FROM organizations
  WHERE id = target_org AND status = 'pending_deletion' AND purge_after <=
  now())``; then runs the one-line ``DELETE FROM audit_events WHERE org_id =
  target_org`` (not inside any IF), ``GET DIAGNOSTICS ... = ROW_COUNT`` and
  returns it. Static SQL: no EXECUTE, no other DML.
- ``CREATE OR REPLACE FUNCTION audit_events_append_only()`` keeps 0005's
  retention path exactly (the same conditions, its frame literal byte for
  byte, the ``purge_audit_events(integer)`` frame check and the 6-month floor)
  and adds exactly one path: frame 2 is exactly ``SQL statement "DELETE FROM
  audit_events WHERE org_id = target_org"`` (the purge function's DELETE text),
  frame 3 starts with ``PL/pgSQL function purge_org_audit_events(uuid) line ``,
  and ``EXISTS`` finds OLD.org_id's org pending deletion and due. Every path
  needs ``TG_OP = 'DELETE'``, the only RETURN is ``RETURN OLD``, and the body
  ends in an unconditional plain-literal RAISE, so UPDATE and TRUNCATE are
  still always refused.
- #147's default organization is scheduled for immediate purge:
  ``UPDATE organizations SET status = 'pending_deletion',
  deletion_requested_at = now(), purge_after = now(), updated_at = now() WHERE
  id = '00000000-0000-4000-8000-000000000001'``.
- Nothing else: no table created, dropped or altered, no constraint change (the
  catalog already holds every org.* action), no DELETE / INSERT / TRUNCATE, no
  DO block, triggers neither dropped nor created, parameter-free.
- Python and SQL stay in sync: admino.organizations calls the function, and no
  Python module deletes from audit_events directly.

Security notes:
- The audit log stays append-only: the new path opens only for the purge
  function's own DELETE, only for rows of an org that is pending deletion and
  past its purge date, and only for DELETE.
- Frames are pinned by position (frame 2 = the statement, frame 3 = the
  function), exactly like 0005, so a lookalike statement or a DO block can't
  pass; starts_with, not LIKE ('_' is a LIKE wildcard).
- Errors carry no row data or input: every RAISE is a plain literal.
- The default-org cleanup goes through the same purge path as any org, so no
  audit row is deleted by the migration itself.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple
from unittest.mock import AsyncMock

import pytest

import admino.database as db_mod

if TYPE_CHECKING:
    from unittest.mock import MagicMock

_MIGRATION_NAME = "0011_org_lifecycle.sql"
_BASE_MIGRATION = "0005_audit_events.sql"
_CATALOG_MIGRATION = "0010_invitations.sql"
_DEFAULT_ORG_ID = "00000000-0000-4000-8000-000000000001"
_ORG_DELETE = "DELETE FROM audit_events WHERE org_id = target_org"
_ORG_FRAME_2 = f'SQL statement "{_ORG_DELETE}"'
_ORG_FRAME_3_PREFIX = "PL/pgSQL function purge_org_audit_events(uuid) line "
_ORG_ACTIONS = frozenset(
    {
        "org.create",
        "org.limits_change",
        "org.deactivate",
        "org.reactivate",
        "org.deletion_schedule",
        "org.deletion_cancel",
        "org.purge",
        "org.residency_change",
        "invitation.create",
    }
)

_LITERAL = r"'(?:[^']|'')*'"
# A RAISE whose message is a plain literal with, at most, an ERRCODE: no format
# arguments, no concatenation, no DETAIL/HINT that could carry row data or input.
_LITERAL_RAISE_RE = re.compile(
    rf"raise\s+exception\s+{_LITERAL}(?:\s+using\s+errcode\s*=\s*'\w+')?\s*;"
)


# ---------------------------------------------------------------------------
# Helpers: reading the shipped SQL
# ---------------------------------------------------------------------------


def _raw(name: str = _MIGRATION_NAME) -> str:
    """A shipped migration, exactly as it is on disk."""
    return (db_mod._MIGRATIONS_DIR / name).read_text(encoding="utf-8")


def _blank_comments(text: str) -> str:
    """Replace every ``--`` comment outside '...' literals with spaces (same length,
    newlines kept), so positions in the result match the raw text."""
    out = list(text)
    in_literal = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_literal:
            if char == "'":
                in_literal = False
        elif char == "'":
            in_literal = True
        elif text.startswith("--", index):
            end = text.find("\n", index)
            end = len(text) if end < 0 else end
            for position in range(index, end):
                out[position] = " "
            index = end
            continue
        index += 1
    return "".join(out)


def _code(name: str = _MIGRATION_NAME) -> str:
    """A shipped migration with its comments blanked (case and layout kept)."""
    return _blank_comments(_raw(name))


def _mask_literals(text: str) -> str:
    """Blank out the contents of '...' and "..." literals (same length), so parentheses,
    semicolons and keywords inside literals don't count as SQL structure."""
    out: list[str] = []
    quote = ""
    for char in text:
        if quote:
            if char == quote:
                quote = ""
                out.append(char)
            else:
                out.append(" ")
        else:
            if char in "'\"":
                quote = char
            out.append(char)
    return "".join(out)


def _mask_bodies(text: str) -> str:
    """Blank out the contents of $tag$...$tag$ bodies (same length, delimiters kept)."""
    out = list(text)
    for match in re.finditer(r"\$(\w*)\$(.*?)\$\1\$", text, re.DOTALL):
        for position in range(match.start(2), match.end(2)):
            if out[position] != "\n":
                out[position] = " "
    return "".join(out)


def _norm(text: str) -> str:
    """Collapse whitespace and lowercase, outside '...' literals only."""
    parts = re.split(f"({_LITERAL})", text)
    return "".join(
        part if index % 2 else re.sub(r"\s+", " ", part.lower()) for index, part in enumerate(parts)
    ).strip()


_PUNCTUATION_SPACE_RE = re.compile(r"\s*([()\[\],=<>!+\-*/:|])\s*")
_NOW_EQUIVALENTS_RE = re.compile(r"\bcurrent_timestamp\b|\btransaction_timestamp\(\)")


def _canon(text: str) -> str:
    """_norm, then no spaces around punctuation and now() for its equivalents (outside
    literals), so formatting variants of one expression compare equal."""
    parts = re.split(f"({_LITERAL})", _norm(text))
    return "".join(
        part
        if index % 2
        else _NOW_EQUIVALENTS_RE.sub("now()", _PUNCTUATION_SPACE_RE.sub(r"\1", part))
        for index, part in enumerate(parts)
    ).strip()


def _balanced_end(masked: str, open_index: int) -> int:
    """Return the index of the parenthesis closing the one at open_index."""
    depth = 0
    for index in range(open_index, len(masked)):
        if masked[index] == "(":
            depth += 1
        elif masked[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    pytest.fail(f"unbalanced parentheses in {_MIGRATION_NAME}")


def _unwrap(expression: str) -> str:
    """Drop parentheses that wrap the whole expression."""
    expression = expression.strip()
    while (
        expression.startswith("(")
        and _balanced_end(_mask_literals(expression), 0) == len(expression) - 1
    ):
        expression = expression[1:-1].strip()
    return expression


def _split_top(text: str, keyword: str) -> list[str]:
    """Split at a keyword (or a one-character separator) outside parentheses and literals."""
    masked = _mask_literals(text)
    pattern = re.escape(keyword) if len(keyword) == 1 else rf"\b{keyword}\b"
    parts: list[str] = []
    depth = 0
    start = 0
    for match in re.finditer(rf"\(|\)|{pattern}", masked):
        token = match.group(0)
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
        elif depth == 0:
            parts.append(text[start : match.start()])
            start = match.end()
    parts.append(text[start:])
    return [part.strip() for part in parts if part.strip()]


_COMPARISON_RE = re.compile(r"<=|>=|<>|!=|=|<|>")


def _canon_atom(atom: str) -> str:
    """One condition in canonical form: _canon, outer parentheses dropped, and a top-level
    comparison written one way (operands of =/<> sorted, >= and > turned around)."""
    text = _unwrap(_canon(atom))
    masked = _mask_literals(text)
    depth = 0
    operators: list[re.Match[str]] = []
    index = 0
    while index < len(masked):
        char = masked[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and (match := _COMPARISON_RE.match(masked, index)) is not None:
            operators.append(match)
            index = match.end()
            continue
        index += 1
    if len(operators) != 1:
        return text
    operator = operators[0]
    left, symbol, right = text[: operator.start()], operator.group(0), text[operator.end() :]
    if symbol in {"=", "<>", "!="}:
        symbol = "<>" if symbol == "!=" else symbol
        left, right = sorted((left, right))
    elif symbol in {">=", ">"}:
        symbol = "<=" if symbol == ">=" else "<"
        left, right = right, left
    return f"{left}{symbol}{right}"


def _statements(name: str = _MIGRATION_NAME) -> list[str]:
    """The migration's top-level statements (split at semicolons outside literals and
    function bodies), each _norm-ed, bodies intact."""
    code = _code(name)
    masked = _mask_literals(_mask_bodies(code))
    statements: list[str] = []
    start = 0
    for index, char in enumerate(masked):
        if char == ";":
            statements.append(_norm(code[start:index]))
            start = index + 1
    statements.append(_norm(code[start:]))
    return [statement for statement in statements if statement]


def _top_level(name: str = _MIGRATION_NAME) -> str:
    """The migration's top-level SQL: function bodies and literals blanked, _norm-ed."""
    return _norm(_mask_literals(_mask_bodies(_code(name))))


# ---------------------------------------------------------------------------
# Helpers: functions and their PL/pgSQL bodies
# ---------------------------------------------------------------------------


class _Function(NamedTuple):
    """One CREATE [OR REPLACE] FUNCTION statement."""

    name: str
    or_replace: bool
    arguments: str
    returns: str
    options: str
    body: str  # comments blanked, case and layout kept (PL/pgSQL sees this text)


_FUNCTION_RE = re.compile(
    r"create\s+(or\s+replace\s+)?function\s+(?:public\.)?(\w+)\s*\(([^)]*)\)\s*"
    r"returns\s+(\w+)(.*?)\$(\w*)\$(.*?)\$\6\$([^;]*);",
    re.IGNORECASE | re.DOTALL,
)


def _functions(name: str = _MIGRATION_NAME) -> dict[str, _Function]:
    """Every function a migration creates, by lowercased name."""
    return {
        match.group(2).lower(): _Function(
            name=match.group(2).lower(),
            or_replace=match.group(1) is not None,
            arguments=_norm(match.group(3)),
            returns=match.group(4).lower(),
            options=_norm(f"{match.group(5)} {match.group(8)}"),
            body=match.group(7),
        )
        for match in _FUNCTION_RE.finditer(_code(name))
    }


def _function(function_name: str, name: str = _MIGRATION_NAME) -> _Function:
    function = _functions(name).get(function_name)
    if function is None:
        pytest.fail(f"no function {function_name} in {name}")
    return function


def _purge_function() -> _Function:
    return _function("purge_org_audit_events")


def _trigger_function(name: str = _MIGRATION_NAME) -> _Function:
    return _function("audit_events_append_only", name)


class _Statement(NamedTuple):
    """One PL/pgSQL statement and the IF branch conditions around it."""

    keyword: str  # return, raise, delete, update, insert, truncate, execute, perform, get
    text: str  # _norm-ed, with its semicolon
    raw: str  # exactly as in the body, without its semicolon
    conditions: tuple[str, ...]  # _norm-ed; "" for an ELSE branch
    position: int


_BODY_TOKEN_RE = re.compile(
    r"\bend\s+if\b|\belsif\b|\bif\b|\belse\b|\bthen\b"
    r"|\b(?:return|raise|delete|update|insert|truncate|execute|perform|get\s+diagnostics)\b"
)


def _body_statements(body: str) -> list[_Statement]:
    """The statements of a PL/pgSQL body that return, raise, run DML or read diagnostics,
    each with the conditions of the IF/ELSIF/ELSE branches it sits in."""
    lowered = _mask_literals(body).lower()
    stack: list[list[object]] = []  # [condition start, condition]
    statements: list[_Statement] = []
    resume = 0
    for match in _BODY_TOKEN_RE.finditer(lowered):
        if match.start() < resume:
            continue
        token = re.sub(r"\s+", " ", match.group(0))
        if token == "if":
            stack.append([match.end(), None])
        elif token == "elsif":
            stack[-1] = [match.end(), None]
        elif token == "then":
            start = stack[-1][0]
            assert isinstance(start, int)
            stack[-1][1] = _norm(body[start : match.start()])
        elif token == "else":
            stack[-1] = [match.end(), ""]
        elif token == "end if":
            stack.pop()
        else:
            end = lowered.find(";", match.start())
            end = len(lowered) if end < 0 else end
            raw = body[match.start() : end]
            statements.append(
                _Statement(
                    keyword=token.split(" ")[0],
                    text=_norm(raw + ";"),
                    raw=raw,
                    conditions=tuple(str(condition) for _, condition in stack),
                    position=match.start(),
                )
            )
            resume = end + 1
    return statements


def _alternatives(condition: str) -> list[frozenset[str]]:
    """The OR-alternatives of a condition, each a set of canonical AND-ed atoms."""
    if condition == "":
        return [frozenset()]
    return [
        frozenset(_canon_atom(atom) for atom in _split_top(_unwrap(alternative), "and"))
        for alternative in _split_top(_unwrap(condition), "or")
    ]


def _paths(conditions: tuple[str, ...]) -> list[frozenset[str]]:
    """Every conjunction of atoms under which a statement in these branches runs."""
    paths: list[frozenset[str]] = [frozenset()]
    for condition in conditions:
        paths = [path | alternative for path in paths for alternative in _alternatives(condition)]
    return paths


def _allow_paths(function: _Function) -> list[frozenset[str]]:
    """Every set of conditions under which the trigger function returns (lets a row go)."""
    return [
        path
        for statement in _body_statements(function.body)
        if statement.keyword == "return"
        for path in _paths(statement.conditions)
    ]


_TG_OP_DELETE = _canon_atom("TG_OP = 'DELETE'")
_ORG_FRAME_2_ATOM = _canon_atom(f"frames[2] = '{_ORG_FRAME_2}'")
_ORG_FRAME_3_ATOM = _canon_atom(f"starts_with(frames[3], '{_ORG_FRAME_3_PREFIX}')")

_EXISTS_RE = re.compile(
    r"(not )?exists\(select (?:1|\*|true) from (?:public\.)?organizations"
    r"(?: (?:as )?(?!where\b)(\w+))? where (.*)\)"
)


def _exists_conditions(atom: str, *, negated: bool) -> frozenset[str] | None:
    """The canonical WHERE atoms of '[NOT] EXISTS (SELECT 1 FROM organizations [o] WHERE
    ...)', table alias removed; None when the atom isn't such an EXISTS."""
    match = _EXISTS_RE.fullmatch(atom)
    if match is None or (match.group(1) is not None) != negated:
        return None
    qualifiers = ["organizations"] + ([match.group(2)] if match.group(2) else [])
    where = match.group(3)
    for qualifier in qualifiers:
        where = re.sub(rf"(?<![\w.]){qualifier}\.", "", where)
    return frozenset(_canon_atom(atom) for atom in _split_top(where, "and"))


_TRIGGER_EXISTS_WHERE = frozenset(
    {
        _canon_atom("id = OLD.org_id"),
        _canon_atom("status = 'pending_deletion'"),
        _canon_atom("purge_after <= now()"),
    }
)
_PURGE_GUARD_WHERE = frozenset(
    {
        _canon_atom("id = target_org"),
        _canon_atom("status = 'pending_deletion'"),
        _canon_atom("purge_after <= now()"),
    }
)


def _is_org_purge_path(path: frozenset[str]) -> bool:
    """frames[2] is the purge function's DELETE, frames[3] the purge function, and the
    row's org is pending deletion and due: exactly these three conditions."""
    rest = path - {_TG_OP_DELETE}
    if len(rest) != 3 or _ORG_FRAME_2_ATOM not in rest or _ORG_FRAME_3_ATOM not in rest:
        return False
    (exists,) = rest - {_ORG_FRAME_2_ATOM, _ORG_FRAME_3_ATOM}
    return _exists_conditions(exists, negated=False) == _TRIGGER_EXISTS_WHERE


def _retention_path() -> frozenset[str]:
    """0005's single allow path (the retention purge), without the TG_OP check."""
    paths = _allow_paths(_trigger_function(_BASE_MIGRATION))
    assert len(paths) == 1, paths
    return paths[0] - {_TG_OP_DELETE}


def _delete_statements(function: _Function) -> list[_Statement]:
    return [s for s in _body_statements(function.body) if s.keyword == "delete"]


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0011File:
    """The migration ships as version 11 and is applied by run_migrations."""

    def test_migration_0011_file_is_shipped_as_version_11(self) -> None:
        assert (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == 11

    def test_migration_0011_is_the_only_version_11(self) -> None:
        elevens = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == 11
        ]

        assert elevens == [_MIGRATION_NAME]

    async def test_migration_0011_run_migrations_applies_it_as_version_11(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0010 applied, run_migrations executes the file and records 11."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, 11)])

        await db_mod.run_migrations(mock_pool)

        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert (11, _MIGRATION_NAME) in recorded
        assert all(version >= 11 for version, _ in recorded)

    async def test_migration_0011_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, 11)])
        shipped = _raw()

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0011_is_parameter_free(self) -> None:
        sql = _norm(_code())

        assert re.search(r"\$\d", sql) is None
        assert "%s" not in sql
        assert "%(" not in sql


# ---------------------------------------------------------------------------
# 2. purge_org_audit_events(uuid): the only way an org's audit rows leave
# ---------------------------------------------------------------------------


class TestMigration0011PurgeOrgFunction:
    """purge_org_audit_events(target_org uuid) deletes a due org's audit events."""

    def test_migration_0011_purge_org_function_signature(self) -> None:
        """purge_org_audit_events(target_org uuid) RETURNS bigint LANGUAGE plpgsql.

        The argument name is part of the DELETE text the trigger compares."""
        function = _purge_function()

        assert re.fullmatch(r"(?:in\s+)?target_org\s+uuid", function.arguments), function
        assert function.returns in {"bigint", "int8"}
        assert "language plpgsql" in function.options

    def test_migration_0011_purge_org_raises_unless_the_org_is_pending_and_due(self) -> None:
        """A RAISE EXCEPTION guarded by exactly NOT EXISTS (SELECT 1 FROM organizations WHERE
        id = target_org AND status = 'pending_deletion' AND purge_after <= now())."""
        raises = [s for s in _body_statements(_purge_function().body) if s.keyword == "raise"]

        assert len(raises) == 1, raises
        (condition,) = raises[0].conditions
        (alternative,) = _alternatives(condition)
        (atom,) = alternative
        assert _exists_conditions(atom, negated=True) == _PURGE_GUARD_WHERE, atom

    def test_migration_0011_purge_org_checks_before_deleting(self) -> None:
        """The guard comes before the DELETE."""
        statements = _body_statements(_purge_function().body)
        raise_position = next(s.position for s in statements if s.keyword == "raise")
        delete_position = next(s.position for s in statements if s.keyword == "delete")

        assert raise_position < delete_position

    def test_migration_0011_purge_org_deletes_exactly_the_org_events_on_one_line(self) -> None:
        """One DELETE, written exactly 'DELETE FROM audit_events WHERE org_id = target_org'
        on one line: PG_CONTEXT reports this text, and the trigger compares it."""
        deletes = _delete_statements(_purge_function())

        assert [statement.raw for statement in deletes] == [_ORG_DELETE]

    def test_migration_0011_purge_org_delete_is_unconditional(self) -> None:
        """The DELETE sits in no IF branch: past the guard, it always runs."""
        (delete,) = _delete_statements(_purge_function())

        assert delete.conditions == ()

    def test_migration_0011_purge_org_returns_the_row_count(self) -> None:
        """GET DIAGNOSTICS <var> = ROW_COUNT after the DELETE; RETURN <var>."""
        statements = _body_statements(_purge_function().body)
        delete_position = next(s.position for s in statements if s.keyword == "delete")
        diagnostics = [
            match
            for s in statements
            if s.keyword == "get" and s.position > delete_position
            if (match := re.fullmatch(r"get diagnostics (\w+) ?:?= ?row_count ?;", s.text))
        ]
        returns = [s for s in statements if s.keyword == "return"]

        assert len(diagnostics) == 1
        assert [s.text for s in returns] == [f"return {diagnostics[0].group(1)};"]
        assert returns[0].conditions == ()

    def test_migration_0011_purge_org_uses_no_dynamic_sql(self) -> None:
        """No EXECUTE: the DELETE is static SQL with the org id as a typed argument."""
        assert re.search(r"\bexecute\b", _mask_literals(_purge_function().body).lower()) is None

    def test_migration_0011_purge_org_runs_no_other_dml(self) -> None:
        """No UPDATE, INSERT, TRUNCATE or PERFORM: the function only deletes the events."""
        keywords = [s.keyword for s in _body_statements(_purge_function().body)]

        assert set(keywords) <= {"raise", "delete", "get", "return"}
        assert keywords.count("delete") == 1

    def test_migration_0011_purge_org_errors_echo_no_input(self) -> None:
        """Every RAISE is a plain literal: the org id is never echoed."""
        raises = [s for s in _body_statements(_purge_function().body) if s.keyword == "raise"]

        assert raises
        assert all(_LITERAL_RAISE_RE.fullmatch(s.text) for s in raises), raises


# ---------------------------------------------------------------------------
# 3. audit_events_append_only(): 0005's rules plus the org purge path
# ---------------------------------------------------------------------------

_MONTHS = r"(?:months?|mons?)"
_FLOOR_RE = re.compile(
    rf"old\.occurred_at<now\(\)-(?:interval ?'(\d+) ?{_MONTHS}'"
    rf"|'(\d+) ?{_MONTHS}'::interval|make_interval\(months=>(\d+)\))"
)


class TestMigration0011AppendOnlyTrigger:
    """The trigger function is replaced; the table stays append-only."""

    def test_migration_0011_replaces_the_trigger_function_in_place(self) -> None:
        """CREATE OR REPLACE FUNCTION audit_events_append_only() RETURNS trigger, plpgsql:
        the existing triggers call the replaced function (no DROP, no CASCADE)."""
        function = _trigger_function()

        assert function.or_replace
        assert function.arguments == ""
        assert function.returns == "trigger"
        assert "language plpgsql" in function.options

    def test_migration_0011_trigger_reads_the_call_stack_like_0005(self) -> None:
        """The same GET DIAGNOSTICS ... = PG_CONTEXT and frames := string_to_array(...)
        statements as 0005."""
        base = _norm(_trigger_function(_BASE_MIGRATION).body)
        body = _norm(_trigger_function().body)
        diagnostics = re.search(r"get diagnostics \w+ ?:?= ?pg_context ?;", base)
        frames = re.search(r"frames ?:= ?[^;]*;", base)

        assert diagnostics is not None
        assert frames is not None
        assert diagnostics.group(0) in body
        assert frames.group(0) in body

    def test_migration_0011_trigger_keeps_the_retention_path_of_0005(self) -> None:
        """0005's retention conditions, unchanged: the frame literal byte for byte, the
        purge_audit_events(integer) frame check and the 6-month floor."""
        paths = [path - {_TG_OP_DELETE} for path in _allow_paths(_trigger_function())]

        assert _retention_path() in paths

    def test_migration_0011_trigger_keeps_the_six_month_floor(self) -> None:
        body = _canon(_trigger_function().body)
        floors = {int(next(g for g in groups if g)) for groups in _FLOOR_RE.findall(body)}

        assert floors == {6}

    def test_migration_0011_trigger_adds_the_org_purge_path(self) -> None:
        """frames[2] = 'SQL statement "DELETE FROM audit_events WHERE org_id =
        target_org"', starts_with(frames[3], 'PL/pgSQL function
        purge_org_audit_events(uuid) line ') and EXISTS (SELECT 1 FROM organizations o
        WHERE o.id = OLD.org_id AND o.status = 'pending_deletion' AND o.purge_after <=
        now())."""
        paths = _allow_paths(_trigger_function())

        assert any(_is_org_purge_path(path) for path in paths), paths

    def test_migration_0011_trigger_lets_rows_go_on_exactly_two_paths(self) -> None:
        """The retention path and the org purge path, nothing else."""
        paths = _allow_paths(_trigger_function())

        assert len(paths) == 2, paths
        without_tg_op = [path - {_TG_OP_DELETE} for path in paths]
        assert _retention_path() in without_tg_op
        assert sum(_is_org_purge_path(path) for path in paths) == 1

    def test_migration_0011_trigger_lets_only_deletes_through(self) -> None:
        """Every path requires TG_OP = 'DELETE' (the literal is upper case, as PL/pgSQL
        sets it): UPDATE and TRUNCATE never reach a RETURN."""
        paths = _allow_paths(_trigger_function())

        assert paths
        assert all(_TG_OP_DELETE in path for path in paths), paths

    def test_migration_0011_trigger_only_ever_returns_old(self) -> None:
        """No RETURN NEW (an UPDATE going through) and no RETURN NULL (which would let a
        TRUNCATE proceed and skip rows silently)."""
        returns = [s for s in _body_statements(_trigger_function().body) if s.keyword == "return"]

        assert returns
        assert {s.text for s in returns} == {"return old;"}

    def test_migration_0011_trigger_ends_with_an_unconditional_raise(self) -> None:
        """Whatever doesn't match a path falls through to RAISE EXCEPTION, outside every
        IF, as the last statement."""
        statements = _body_statements(_trigger_function().body)

        assert statements[-1].keyword == "raise"
        assert statements[-1].conditions == ()
        assert re.search(
            rf"raise exception {_LITERAL}(?: using errcode ?= ?'\w+')? ?; ?end ?;?$",
            _norm(_trigger_function().body),
        )

    def test_migration_0011_trigger_errors_carry_no_row_data(self) -> None:
        """Every RAISE is a plain literal (with at most an ERRCODE)."""
        raises = [s for s in _body_statements(_trigger_function().body) if s.keyword == "raise"]

        assert raises
        assert all(_LITERAL_RAISE_RE.fullmatch(s.text) for s in raises), raises

    def test_migration_0011_trigger_frame_literal_is_the_purge_delete_text(self) -> None:
        """The frame-2 literal is 'SQL statement "<the purge function's DELETE>"', byte for
        byte: a mismatch would make the purge fail (or a lookalike pass)."""
        (delete,) = _delete_statements(_purge_function())
        body = _trigger_function().body
        framed = re.findall(r"""frames\s*\[\s*2\s*\]\s*=\s*'SQL statement "([^"']*)"'""", body)

        assert delete.raw in framed

    def test_migration_0011_trigger_frame_3_names_the_purge_function_signature(self) -> None:
        """Frame 3 names purge_org_audit_events(uuid): the function the migration creates,
        with its one uuid argument."""
        function = _purge_function()

        assert f"'{_ORG_FRAME_3_PREFIX}'" in _trigger_function().body
        assert re.fullmatch(r"(?:in\s+)?\w+\s+uuid", function.arguments)

    def test_migration_0011_trigger_runs_no_dml(self) -> None:
        """The trigger only reads (the EXISTS); it deletes, updates or inserts nothing."""
        keywords = {s.keyword for s in _body_statements(_trigger_function().body)}

        assert keywords <= {"get", "return", "raise"}


# ---------------------------------------------------------------------------
# 4. #147's default organization is scheduled for immediate purge
# ---------------------------------------------------------------------------


def _updates() -> list[str]:
    return [s for s in _statements() if re.match(r"update\b", s)]


_UPDATE_RE = re.compile(r"update (?:only )?(?:public\.)?organizations set (.*) where (.*)")


def _default_org_update() -> tuple[set[str], list[str]]:
    """The canonical SET assignments and WHERE atoms of the one UPDATE."""
    updates = _updates()
    assert len(updates) == 1, updates
    match = _UPDATE_RE.fullmatch(updates[0])
    assert match is not None, updates[0]
    assignments = {_canon_atom(item) for item in _split_top(match.group(1), ",")}
    where = [
        _canon_atom(re.sub(r"::\s*(?:uuid|text)\b", "", atom))
        for atom in _split_top(match.group(2), "and")
    ]
    return assignments, where


class TestMigration0011DefaultOrgCleanup:
    """The default org goes through the regular purge path; the migration deletes nothing."""

    def test_migration_0011_updates_only_organizations_once(self) -> None:
        updates = _updates()

        assert len(updates) == 1
        assert _UPDATE_RE.fullmatch(updates[0]), updates[0]

    def test_migration_0011_marks_the_default_org_pending_and_due_now(self) -> None:
        """status 'pending_deletion', deletion_requested_at, purge_after and updated_at
        now() (the database clock): the next purge run takes it."""
        assignments, _ = _default_org_update()

        assert assignments == {
            _canon_atom("status = 'pending_deletion'"),
            _canon_atom("deletion_requested_at = now()"),
            _canon_atom("purge_after = now()"),
            _canon_atom("updated_at = now()"),
        }

    def test_migration_0011_targets_only_the_default_org(self) -> None:
        """WHERE id = '00000000-0000-4000-8000-000000000001' and nothing else: a no-op on
        installs that never had #147's default org."""
        _, where = _default_org_update()

        assert where == [_canon_atom(f"id = '{_DEFAULT_ORG_ID}'")]


# ---------------------------------------------------------------------------
# 5. Nothing else changes
# ---------------------------------------------------------------------------


def _action_catalog(name: str) -> set[str]:
    """The action list of ADD CONSTRAINT audit_events_action_check CHECK (action IN (...))
    in a shipped migration."""
    for statement in _statements(name):
        match = re.search(
            r"add constraint audit_events_action_check check ?\( ?action in ?\(([^)]*)\)",
            statement,
        )
        if match is not None:
            return set(re.findall(r"'([^']*)'", match.group(1)))
    pytest.fail(f"no ADD CONSTRAINT audit_events_action_check CHECK (action IN (...)) in {name}")


class TestMigration0011ChangesNothingElse:
    """Two functions and one UPDATE; no schema change, no data deleted."""

    def test_migration_0011_creates_exactly_the_two_functions(self) -> None:
        assert set(_functions()) == {"purge_org_audit_events", "audit_events_append_only"}
        created = re.findall(r"\bcreate (?:or replace )?function\b", _top_level())
        assert len(created) == 2

    def test_migration_0011_drops_nothing(self) -> None:
        assert re.search(r"\bdrop\b", _top_level()) is None

    def test_migration_0011_creates_or_alters_no_table(self) -> None:
        top = _top_level()

        assert re.search(r"\bcreate (?:\w+ )*table\b", top) is None
        assert re.search(r"\balter table\b", top) is None

    def test_migration_0011_changes_no_constraint_the_catalog_already_has_org_actions(
        self,
    ) -> None:
        """No constraint is added or dropped: 0010's action catalog already holds every
        action GH-154 records."""
        assert re.search(r"\bconstraint\b", _top_level()) is None
        assert _action_catalog(_CATALOG_MIGRATION) >= _ORG_ACTIONS

    def test_migration_0011_leaves_the_triggers_alone(self) -> None:
        """The existing triggers call the replaced function: none is created, altered,
        dropped or disabled, and triggers aren't switched off for the session."""
        top = _top_level()

        assert (
            re.search(r"\b(?:create|alter|drop) (?:or replace )?(?:constraint )?trigger\b", top)
            is None
        )
        assert re.search(r"\bdisable trigger\b", top) is None
        assert "session_replication_role" not in top

    def test_migration_0011_deletes_inserts_and_truncates_nothing(self) -> None:
        """Outside the function bodies: no DELETE, INSERT or TRUNCATE."""
        top = _top_level()

        assert re.search(r"\bdelete\s+from\b", top) is None
        assert re.search(r"\binsert\s+into\b", top) is None
        assert re.search(r"\btruncate\b", top) is None

    def test_migration_0011_runs_no_anonymous_block(self) -> None:
        """No DO block (its body would hide statements from these checks)."""
        assert not any(re.match(r"do\b", statement) for statement in _statements())


# ---------------------------------------------------------------------------
# 6. Python and SQL stay in sync
# ---------------------------------------------------------------------------

_SRC_DIR = Path(db_mod.__file__).resolve().parent


class TestMigration0011PythonSync:
    """The purge job calls the function; no Python code deletes audit rows directly."""

    def test_migration_0011_purge_function_is_what_the_org_purge_calls(self) -> None:
        """admino.organizations calls purge_org_audit_events(...), and no Python module
        under src/admino issues DELETE FROM audit_events itself."""
        import admino.organizations as organizations_mod

        source = re.sub(
            r"\s+",
            " ",
            Path(organizations_mod.__file__).read_text(encoding="utf-8"),
        ).lower()
        direct_deletes = [
            path.name
            for path in sorted(_SRC_DIR.rglob("*.py"))
            if re.search(
                r"delete\s+from\s+(?:only\s+)?audit_events\b",
                path.read_text(encoding="utf-8"),
                re.IGNORECASE,
            )
        ]

        assert "purge_org_audit_events(" in source
        assert _purge_function().name == "purge_org_audit_events"
        assert direct_deletes == []
