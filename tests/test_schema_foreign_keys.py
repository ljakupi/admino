"""Foreign-key guard: the org purge stays complete as tables are added (GH-154).

The org purge (``admino.organizations.purge_due_orgs``) deletes an org's audit
events through ``purge_org_audit_events``, then ``DELETE FROM users WHERE
org_id = $1``, then the organizations row. Everything else that belongs to the
org must go with those rows through ``ON DELETE CASCADE``. A new table that
references ``users`` or ``organizations`` without CASCADE would either block
the purge (RESTRICT / NO ACTION) or keep the org's data after it (SET NULL),
so this guard reads every shipped migration and pins the rule:

- Every ``REFERENCES organizations`` and every ``REFERENCES users`` has
  ``ON DELETE CASCADE``, except exactly ``users.org_id`` and
  ``audit_events.org_id``, which are ``ON DELETE RESTRICT`` (the purge deletes
  those rows explicitly, first; CASCADE on audit_events would fight the
  append-only trigger).
- Every column named ``org_id`` references ``organizations``. The allowlist of
  FK-less ``org_id`` columns is empty today; #178 adds its retained billing
  aggregate table (monthly cost per org, kept by law after the purge).
- GH-161: the per-org ``permissions`` table (migration 0016) has exactly one
  foreign key, ``org_id`` -> ``organizations`` ON DELETE CASCADE.

The parser reads the final schema across all migrations, in version order:
inline column FKs, table-level ``FOREIGN KEY`` constraints, ``ALTER TABLE ...
ADD [COLUMN | CONSTRAINT] ... REFERENCES``, and ``DROP TABLE`` / ``DROP
COLUMN`` / ``DROP CONSTRAINT`` (default FK names ``<table>_<columns>_fkey``).
Comments, literals and function bodies are ignored. The parser self-tests at
the end run it on synthetic SQL for the forms no migration uses yet.

This is a regression guard: it passes on today's migrations and must keep
passing as #154 and later issues add tables.

Security notes:
- A purge that leaves rows behind (a non-cascading FK, or an org_id without an
  FK) would keep an org's content after its "irreversible" deletion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import pytest

import admino.database as db_mod

_PURGE_TARGETS = frozenset({"organizations", "users"})
# Deleted explicitly by the purge, in order, so they must block an out-of-order delete.
_RESTRICTED: frozenset[tuple[str, tuple[str, ...]]] = frozenset(
    {("users", ("org_id",)), ("audit_events", ("org_id",))}
)
# org_id columns allowed without a foreign key to organizations. Empty: #178 adds
# the retained billing aggregate table here, with its reason.
_FKLESS_ORG_ID_COLUMNS: frozenset[str] = frozenset()


# ---------------------------------------------------------------------------
# The parser
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ForeignKey:
    """One foreign key of the final schema."""

    migration: str
    table: str
    columns: tuple[str, ...]
    referenced: str
    on_delete: str  # cascade, restrict, no action, set null, set default
    name: str


@dataclass
class _Schema:
    """The foreign keys and columns left after applying every statement."""

    foreign_keys: list[_ForeignKey] = field(default_factory=list)
    columns: set[tuple[str, str]] = field(default_factory=set)


def _blank_comments(text: str) -> str:
    """Replace -- comments outside '...' literals with spaces (newlines kept)."""
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


def _mask_literals(text: str) -> str:
    """Blank the contents of '...' literals (same length)."""
    out: list[str] = []
    in_literal = False
    for char in text:
        if in_literal:
            if char == "'":
                in_literal = False
                out.append(char)
            else:
                out.append(" ")
        else:
            if char == "'":
                in_literal = True
            out.append(char)
    return "".join(out)


def _mask_bodies(text: str) -> str:
    """Blank the contents of $tag$...$tag$ bodies (same length, delimiters kept)."""
    out = list(text)
    for match in re.finditer(r"\$(\w*)\$(.*?)\$\1\$", text, re.DOTALL):
        for position in range(match.start(2), match.end(2)):
            out[position] = " "
    return "".join(out)


def _split_top(text: str, separator: str) -> list[str]:
    """Split at a one-character separator outside parentheses (text is literal-masked)."""
    parts: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == separator and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    parts.append(text[start:].strip())
    return [part for part in parts if part]


def _balanced_end(text: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    pytest.fail("unbalanced parentheses in a migration")


def _statements(sql: str) -> list[str]:
    """Top-level statements, lowercased with whitespace collapsed; comments, literal
    contents and function bodies blanked (they are never schema)."""
    masked = _mask_literals(_mask_bodies(_blank_comments(sql)))
    return [
        re.sub(r"\s+", " ", statement).strip().lower()
        for statement in masked.split(";")
        if statement.strip()
    ]


_IDENT = r'(?:"?public"?\.)?"?(\w+)"?'
_CONSTRAINT_START = re.compile(
    r'(?:constraint\s+"?(\w+)"?\s+)?(check|unique|primary\s+key|foreign\s+key|exclude)\b'
)
_REFERENCES = re.compile(rf"\breferences\s+{_IDENT}\s*(?:\(([^)]*)\))?")
_ON_DELETE = re.compile(r"\bon\s+delete\s+(cascade|restrict|no\s+action|set\s+null|set\s+default)")


def _names(text: str) -> tuple[str, ...]:
    return tuple(name.strip().strip('"') for name in text.split(",") if name.strip())


def _on_delete(clause: str) -> str:
    match = _ON_DELETE.search(clause)
    return re.sub(r"\s+", " ", match.group(1)) if match else "no action"


def _default_name(table: str, columns: tuple[str, ...]) -> str:
    return f"{table}_{'_'.join(columns)}_fkey"


def _add_column(
    schema: _Schema, migration: str, table: str, definition: str
) -> tuple[str, _ForeignKey | None]:
    """Record a column definition ('name type ... [REFERENCES ...]')."""
    match = re.match(r'"?(\w+)"?\s', definition + " ")
    assert match is not None, definition
    column = match.group(1)
    schema.columns.add((table, column))
    references = _REFERENCES.search(definition)
    if references is None:
        return column, None
    named = re.search(r'\bconstraint\s+"?(\w+)"?\s+references\b', definition)
    foreign_key = _ForeignKey(
        migration=migration,
        table=table,
        columns=(column,),
        referenced=references.group(1),
        on_delete=_on_delete(definition[references.end() :]),
        name=named.group(1) if named else _default_name(table, (column,)),
    )
    schema.foreign_keys.append(foreign_key)
    return column, foreign_key


def _add_table_constraint(schema: _Schema, migration: str, table: str, constraint: str) -> None:
    """Record a table-level FOREIGN KEY constraint (other constraints don't matter)."""
    start = _CONSTRAINT_START.match(constraint)
    assert start is not None, constraint
    if not start.group(2).startswith("foreign"):
        return
    columns = re.match(r"\s*\(([^)]*)\)", constraint[start.end() :])
    references = _REFERENCES.search(constraint)
    assert columns is not None, constraint
    assert references is not None, constraint
    column_names = _names(columns.group(1))
    schema.foreign_keys.append(
        _ForeignKey(
            migration=migration,
            table=table,
            columns=column_names,
            referenced=references.group(1),
            on_delete=_on_delete(constraint[references.end() :]),
            name=start.group(1) or _default_name(table, column_names),
        )
    )


def _drop(
    schema: _Schema, table: str, *, column: str | None = None, name: str | None = None
) -> None:
    """Remove a table, a column (and the FKs on it) or a named constraint."""
    schema.foreign_keys = [
        fk
        for fk in schema.foreign_keys
        if not (
            fk.table == table
            and (
                (column is None and name is None)
                or (column is not None and column in fk.columns)
                or (name is not None and fk.name == name)
            )
        )
    ]
    if name is None:
        schema.columns = {
            (t, c) for t, c in schema.columns if not (t == table and column in {None, c})
        }


def _apply_create_table(schema: _Schema, migration: str, statement: str) -> None:
    match = re.match(
        rf"create\s+(?:(?:global\s+|local\s+)?(?:temp|temporary|unlogged)\s+)?table\s+"
        rf"(?:if\s+not\s+exists\s+)?{_IDENT}\s*\(",
        statement,
    )
    if match is None:
        return
    table = match.group(1)
    end = _balanced_end(statement, match.end() - 1)
    for element in _split_top(statement[match.end() : end], ","):
        if _CONSTRAINT_START.match(element) or element.startswith("like "):
            if _CONSTRAINT_START.match(element):
                _add_table_constraint(schema, migration, table, element)
        else:
            _add_column(schema, migration, table, element)


def _apply_alter_table(schema: _Schema, migration: str, statement: str) -> None:
    match = re.match(
        rf"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?{_IDENT}\s+(.*)", statement, re.DOTALL
    )
    if match is None:
        return
    table = match.group(1)
    for action in _split_top(match.group(2), ","):
        if add := re.match(r"add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?(.*)", action):
            rest = add.group(1)
            if re.match(r"column\b", action[4:]) is None and _CONSTRAINT_START.match(rest):
                _add_table_constraint(schema, migration, table, rest)
            else:
                _add_column(schema, migration, table, rest)
        elif drop := re.match(r'drop\s+column\s+(?:if\s+exists\s+)?"?(\w+)"?', action):
            _drop(schema, table, column=drop.group(1))
        elif drop := re.match(r'drop\s+constraint\s+(?:if\s+exists\s+)?"?(\w+)"?', action):
            _drop(schema, table, name=drop.group(1))
        elif rename := re.match(r'rename\s+to\s+"?(\w+)"?', action):
            new = rename.group(1)
            schema.foreign_keys = [
                _ForeignKey(fk.migration, new, fk.columns, fk.referenced, fk.on_delete, fk.name)
                if fk.table == table
                else fk
                for fk in schema.foreign_keys
            ]
            schema.columns = {(new if t == table else t, c) for t, c in schema.columns}


def _apply(schema: _Schema, migration: str, sql: str) -> None:
    for statement in _statements(sql):
        if statement.startswith("create"):
            _apply_create_table(schema, migration, statement)
        elif statement.startswith("alter table"):
            _apply_alter_table(schema, migration, statement)
        elif drop := re.match(r"drop\s+table\s+(?:if\s+exists\s+)?(.*)", statement):
            tables = re.sub(r"\s+(?:cascade|restrict)$", "", drop.group(1))
            for name in _names(tables):
                _drop(schema, name.split(".")[-1].strip('"'))


def _schema_of(migrations: list[tuple[str, str]]) -> _Schema:
    schema = _Schema()
    for name, sql in migrations:
        _apply(schema, name, sql)
    return schema


def _shipped() -> list[tuple[str, str]]:
    """Every shipped migration (name, SQL), in version order."""
    found: list[tuple[int, str, str]] = []
    for path in db_mod._MIGRATIONS_DIR.iterdir():
        match = db_mod._MIGRATION_FILE_RE.match(path.name)
        if match is not None:
            found.append((int(match.group(1)), path.name, path.read_text(encoding="utf-8")))
    return [(name, sql) for _, name, sql in sorted(found)]


def _shipped_schema() -> _Schema:
    return _schema_of(_shipped())


def _describe(fk: _ForeignKey) -> str:
    return (
        f"{fk.migration}: {fk.table}({', '.join(fk.columns)}) -> {fk.referenced} "
        f"ON DELETE {fk.on_delete.upper()}"
    )


# ---------------------------------------------------------------------------
# 1. The guard on the shipped migrations
# ---------------------------------------------------------------------------


class TestSchemaForeignKeyGuard:
    """Every reference to organizations or users cascades, except the two the purge
    deletes explicitly; every org_id column references organizations."""

    def test_schema_fk_parser_finds_the_known_foreign_keys(self) -> None:
        """The parser sees today's foreign keys (so the guard isn't vacuous)."""
        found = {
            (fk.table, fk.columns, fk.referenced, fk.on_delete)
            for fk in _shipped_schema().foreign_keys
        }

        assert found >= {
            ("users", ("org_id",), "organizations", "restrict"),
            ("audit_events", ("org_id",), "organizations", "restrict"),
            ("email_outbox", ("recipient_user_id",), "users", "cascade"),
            ("sessions", ("user_id",), "users", "cascade"),
            ("password_reset_tokens", ("user_id",), "users", "cascade"),
            ("invitations", ("user_id",), "users", "cascade"),
        }

    def test_schema_fk_permissions_org_id_cascades_from_organizations(self) -> None:
        """GH-161: tool permissions are per org; the org purge removes them through
        permissions.org_id -> organizations ON DELETE CASCADE (migration 0016)."""
        found = {
            (fk.table, fk.columns, fk.referenced, fk.on_delete)
            for fk in _shipped_schema().foreign_keys
            if fk.table == "permissions"
        }

        assert found == {("permissions", ("org_id",), "organizations", "cascade")}

    def test_schema_fk_references_to_orgs_and_users_cascade(self) -> None:
        """Apart from users.org_id and audit_events.org_id, every foreign key to
        organizations or users is ON DELETE CASCADE, so the purge removes the rows."""
        offenders = [
            _describe(fk)
            for fk in _shipped_schema().foreign_keys
            if fk.referenced in _PURGE_TARGETS
            and (fk.table, fk.columns) not in _RESTRICTED
            and fk.on_delete != "cascade"
        ]

        assert offenders == []

    def test_schema_fk_users_org_id_and_audit_events_org_id_restrict(self) -> None:
        """The two rows the purge deletes on purpose, first, are ON DELETE RESTRICT (a
        cascade on audit_events would fight the append-only trigger)."""
        found = {
            (fk.table, fk.columns): fk.on_delete
            for fk in _shipped_schema().foreign_keys
            if (fk.table, fk.columns) in _RESTRICTED and fk.referenced == "organizations"
        }

        assert found == dict.fromkeys(_RESTRICTED, "restrict")

    def test_schema_fk_only_the_purge_deleted_references_are_not_cascade(self) -> None:
        """The exceptions are exactly users.org_id and audit_events.org_id."""
        not_cascading = {
            (fk.table, fk.columns)
            for fk in _shipped_schema().foreign_keys
            if fk.referenced in _PURGE_TARGETS and fk.on_delete != "cascade"
        }

        assert not_cascading == _RESTRICTED

    def test_schema_fk_every_org_id_column_references_organizations(self) -> None:
        """An org_id column without a foreign key would survive the purge unnoticed."""
        schema = _shipped_schema()
        with_fk = {
            fk.table
            for fk in schema.foreign_keys
            if fk.referenced == "organizations" and "org_id" in fk.columns
        }
        org_id_tables = {table for table, column in schema.columns if column == "org_id"}

        assert {"users", "audit_events"} <= org_id_tables
        assert sorted(org_id_tables - with_fk - _FKLESS_ORG_ID_COLUMNS) == []


# ---------------------------------------------------------------------------
# 2. Parser self-tests on synthetic SQL
# ---------------------------------------------------------------------------


def _parse(sql: str) -> set[tuple[str, tuple[str, ...], str, str]]:
    return {
        (fk.table, fk.columns, fk.referenced, fk.on_delete)
        for fk in _schema_of([("x.sql", sql)]).foreign_keys
    }


class TestSchemaForeignKeyParser:
    """The parser understands every way a migration can declare a foreign key."""

    @pytest.mark.parametrize(
        ("sql", "expected"),
        [
            pytest.param(
                "CREATE TABLE t (id UUID PRIMARY KEY,\n"
                "  org_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE);",
                {("t", ("org_id",), "organizations", "cascade")},
                id="inline",
            ),
            pytest.param(
                "CREATE TABLE t (user_id UUID REFERENCES users);",
                {("t", ("user_id",), "users", "no action")},
                id="inline-default-no-action",
            ),
            pytest.param(
                "CREATE TABLE IF NOT EXISTS \"t\" (a UUID, b TEXT CHECK (b IN ('x, y', '(z')),\n"
                "  CONSTRAINT t_a_fk FOREIGN KEY (a) REFERENCES public.users (id)\n"
                "    ON UPDATE CASCADE ON DELETE RESTRICT);",
                {("t", ("a",), "users", "restrict")},
                id="table-level",
            ),
            pytest.param(
                "CREATE TABLE t (a UUID, b UUID, FOREIGN KEY (a, b) REFERENCES p (x, y) "
                "ON DELETE SET NULL);",
                {("t", ("a", "b"), "p", "set null")},
                id="table-level-multi-column",
            ),
            pytest.param(
                "ALTER TABLE t ADD COLUMN org_id UUID REFERENCES organizations ON DELETE SET NULL;",
                {("t", ("org_id",), "organizations", "set null")},
                id="alter-add-column",
            ),
            pytest.param(
                "ALTER TABLE ONLY t ADD org_id UUID CONSTRAINT t_org_fk REFERENCES "
                "organizations (id) ON DELETE CASCADE;",
                {("t", ("org_id",), "organizations", "cascade")},
                id="alter-add-without-column-keyword",
            ),
            pytest.param(
                "ALTER TABLE t ADD CONSTRAINT t_u_fkey FOREIGN KEY (user_id) "
                "REFERENCES users (id) ON DELETE CASCADE;",
                {("t", ("user_id",), "users", "cascade")},
                id="alter-add-constraint",
            ),
            pytest.param(
                "CREATE TABLE t (user_id UUID REFERENCES users ON DELETE CASCADE);\n"
                "ALTER TABLE t DROP CONSTRAINT t_user_id_fkey,\n"
                "  ADD CONSTRAINT t_user_fk FOREIGN KEY (user_id) REFERENCES users ON DELETE "
                "RESTRICT;",
                {("t", ("user_id",), "users", "restrict")},
                id="alter-replace-default-named",
            ),
            pytest.param(
                "CREATE TABLE t (org_id UUID REFERENCES organizations);\n"
                "ALTER TABLE t DROP COLUMN org_id;",
                set(),
                id="drop-column",
            ),
            pytest.param(
                "CREATE TABLE t (org_id UUID REFERENCES organizations);\nDROP TABLE IF EXISTS t;",
                set(),
                id="drop-table",
            ),
            pytest.param(
                "-- REFERENCES users ON DELETE SET NULL\n"
                "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$\n"
                "BEGIN CREATE TABLE z (a UUID REFERENCES users); END; $$;\n"
                "CREATE TABLE t (note TEXT DEFAULT 'REFERENCES users (id)');",
                set(),
                id="comments-bodies-and-literals-ignored",
            ),
        ],
    )
    def test_schema_fk_parser_reads_foreign_keys(
        self, sql: str, expected: set[tuple[str, tuple[str, ...], str, str]]
    ) -> None:
        assert _parse(sql) == expected

    def test_schema_fk_parser_records_org_id_columns(self) -> None:
        """Columns are tracked through CREATE TABLE, ADD COLUMN and DROP COLUMN."""
        schema = _schema_of(
            [
                (
                    "x.sql",
                    "CREATE TABLE a (org_id UUID, CONSTRAINT a_pk PRIMARY KEY (org_id));\n"
                    "ALTER TABLE b ADD COLUMN org_id UUID;\n"
                    "CREATE TABLE c (org_id UUID);\nALTER TABLE c DROP COLUMN org_id;",
                )
            ]
        )

        assert {table for table, column in schema.columns if column == "org_id"} == {"a", "b"}
