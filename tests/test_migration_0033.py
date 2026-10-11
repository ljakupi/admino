"""Tests for migration 0033_account_preferences.sql (GH-307, contract C1, issue Decision 1):
the display density and the two notification types on user_settings, which replace
notifications_enabled and notifications_task_done, and users.password_changed_at.

There is no real PostgreSQL in the suite, so the shipped SQL file is the spec (the
pipeline ran the contract's SQL on a throwaway postgres:16: old rows kept their theme and
updated_at, task_done true -> completed true and false -> false, density comfortable,
approvals true, password_changed_at NULL; density 'tiny' -> user_settings_density_check).
The SQL is read with tests/test_migration_0018.py's lexer (comments blanked, literals and
dollar-quoted bodies kept whole, nested DO / function bodies and EXECUTE literals searched
too) and every statement is read into steps: one per ALTER TABLE action (an added column
through tests/test_migration_0024.py's column parser, a dropped column with its IF EXISTS /
CASCADE), one per UPDATE (target, assignments with their table qualifiers removed, WHERE /
FROM / RETURNING), anything else as is. Whitespace around parentheses, commas and ``=`` is
not significant; literals are compared byte for byte.

What is pinned:
- ``0033_account_preferences.sql`` ships as the only version 33, right after the versions
  1 to 32; run_migrations applies it after 0032 and records it, and not again once applied.
  It is parameter-free.
- Exactly the contract's steps, in its order: ADD density TEXT NOT NULL DEFAULT
  'comfortable' CHECK (density IN ('comfortable', 'compact')) (an inline CHECK, so named
  user_settings_density_check), ADD notifications_approvals and notifications_completed,
  each BOOLEAN NOT NULL DEFAULT true; then ``UPDATE user_settings SET
  notifications_completed = notifications_task_done`` (every row: no WHERE, nothing else
  set); then DROP COLUMN notifications_enabled and notifications_task_done (no IF EXISTS,
  no CASCADE); then ``ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMPTZ``
  (nullable, no default, no backfill).
- theme and updated_at are not named by any statement (kept as they are).
- Nothing else, also not nested in a DO block, a function body or an EXECUTE literal: no
  INSERT / DELETE / TRUNCATE / COPY / MERGE, no other DROP or CASCADE, no RENAME or ALTER
  COLUMN, no GRANT / REVOKE, no CREATE (table, index, function, trigger, type, role), no
  audit catalog change.
- Privileges: every (table, grantee) holds after 0033 what it held after 0032, and
  admino_app's grants on users and user_settings are table-level, so they cover the new
  columns. tests/test_migration_0018.py's runtime-role guards hold with 0033 shipped.
- The SQL defaults equal the Pydantic defaults (``SettingsAppearance().density``,
  ``SettingsNotifications().approvals`` / ``.completed``), the density CHECK's values are
  the ``Literal`` of ``SettingsAppearance.density`` and of ``SettingsPatchAppearance``'s
  density, and ``SettingsNotifications`` has one plain-bool field per notifications_*
  column of the migrated table.
- tests/db_fakes.py mirrors the result: user_settings' columns (0013's and 0015's minus
  the dropped two, plus the added three), their types, NOT NULLs, defaults and the density
  CHECK; a statement naming a dropped column fails with UndefinedColumnError (also without
  a row); users has password_changed_at, NULL on a new account.

Security notes:
- No row of another user is read or written: the only data write maps each row's own
  task_done value onto its own completed column.
- No privilege changes: the runtime role's table-level grants already cover the columns.
- The CHECK mirrors the API's Literal, so a value the API accepts never makes the
  database refuse the write with a 500, and a write that bypasses the models is refused.
"""

from __future__ import annotations

import re
import typing
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock

import asyncpg

import admino.database as db_mod
import admino.models as models_module
from tests import db_fakes
from tests.test_migration_0018 import (
    _GUARDS,
    _executed,
    _fragments,
    _load_migrations,
    _masked,
    _normalize,
    _shipped,
    _split,
)
from tests.test_migration_0024 import _TYPE_CANON, _canonical_default, _parse_column
from tests.test_migration_0027 import _ALTER_RE, _apply, _unwrap

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME: Final = "0033_account_preferences.sql"
_PREVIOUS_MIGRATION: Final = "0032_trash.sql"
_VERSION: Final = 33
_ROLE: Final = "admino_app"
_USER_SETTINGS: Final = "user_settings"
_USERS: Final = "users"
# user_settings before 0033: migration 0013's columns plus 0015's notifications_task_done
# (pinned by tests/test_migration_0013.py and tests/test_migration_0015.py).
_USER_SETTINGS_BEFORE: Final = frozenset(
    {"user_id", "theme", "notifications_enabled", "notifications_task_done", "updated_at"}
)

# The contract's statements (contract C1), read with the same parser as the shipped file.
_CONTRACT_SQL: Final = """
ALTER TABLE user_settings
    ADD COLUMN density TEXT NOT NULL DEFAULT 'comfortable'
        CHECK (density IN ('comfortable', 'compact')),
    ADD COLUMN notifications_approvals BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN notifications_completed BOOLEAN NOT NULL DEFAULT true;

UPDATE user_settings SET notifications_completed = notifications_task_done;

ALTER TABLE user_settings
    DROP COLUMN notifications_enabled,
    DROP COLUMN notifications_task_done;

ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMPTZ;
"""

# An added column with no key, identity, unique, reference or unexpected clause.
_NOTHING_ELSE: Final = (False, None, (), (), ())
_DENSITY: Final[dict[str, Any]] = {
    "type": "text",
    "not_null": True,
    "default": "'comfortable'",
    "checks": (("user_settings_density_check", "density in('comfortable','compact')"),),
    "other": _NOTHING_ELSE,
}
_NOTIFICATION_TYPE: Final[dict[str, Any]] = {
    "type": "boolean",
    "not_null": True,
    "default": "true",
    "checks": (),
    "other": _NOTHING_ELSE,
}
_PASSWORD_CHANGED_AT: Final[dict[str, Any]] = {
    "type": "timestamptz",
    "not_null": False,
    "default": None,
    "checks": (),
    "other": _NOTHING_ELSE,
}
_PLAIN_DROP: Final[dict[str, Any]] = {"if_exists": False, "behaviour": ""}
_SQL_VALUES: Final[dict[str, Any]] = {"true": True, "false": False}
_FAKE_TYPES: Final[dict[str, str]] = {
    "text": "text",
    "boolean": "bool",
    "timestamptz": "timestamptz",
    "uuid": "uuid",
}
# A read of each dropped column, as code written before 0033 would run it.
_OLD_COLUMN_READS: Final[dict[str, str]] = {
    "notifications_enabled": "SELECT notifications_enabled FROM user_settings WHERE user_id = $1",
    "notifications_task_done": (
        "SELECT notifications_task_done FROM user_settings WHERE user_id = $1"
    ),
}

_ADD_COLUMN_RE: Final = re.compile(
    r"add (?:column )?(?:if not exists )?"
    r'(?!(?:constraint|check|unique|primary|foreign|exclude)\b)"?(?P<name>\w+)"? '
    r"(?P<definition>.+)"
)
_DROP_COLUMN_RE: Final = re.compile(
    r'drop (?:column )?(?!constraint\b)(?P<if_exists>if exists )?"?(?P<name>\w+)"?'
    r"(?P<rest>(?: \w+)?)"
)
# UPDATE <table> [[AS] alias] SET ... (the alias is never the keyword SET).
_UPDATE_RE: Final = re.compile(
    r'update (?:only )?(?:"?public"?\.)?"?(?P<table>\w+)"?'
    r'(?: (?:as )?"?(?P<alias>(?!set\b)\w+)"?)? set (?P<rest>.+)'
)
_LITERAL_RE: Final = re.compile(r"('(?:[^']|'')*')")
# Fragments 0033 must not contain (top level, DO / function bodies, EXECUTE literals).
_FORBIDDEN: Final[dict[str, str]] = {
    "row insert": r"\binsert\b",
    "row delete": r"\bdelete\b",
    "truncate": r"\btruncate\b",
    "copy": r"\bcopy\b",
    "merge": r"\bmerge\b",
    "grant": r"\bgrant\b",
    "revoke": r"\brevoke\b",
    "create": r"\bcreate\b",
    "do block": r"\bdo\b",
    "function or trigger": r"\b(?:function|procedure|trigger)\b",
    "index": r"\bindex\b",
    "cascade": r"\bcascade\b",
    "rename": r"\brename\b",
    "alter column": r"\balter (?:column )?(?!table\b)\w+ (?:set|drop|type)\b",
    "drop of anything but a column": (
        r"\bdrop (?:table|index|constraint|type|view|schema|function|procedure|trigger|role"
        r"|owned|default|not null|expression|identity)\b"
    ),
    "audit catalog": r"\baudit_events\b|\baction_check\b",
    "owner or default privileges": r"\bowner to\b|\bdefault privileges\b",
}


# ---------------------------------------------------------------------------
# Helpers: reading the shipped SQL into steps
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _raw_sql() -> str:
    return _migration_path().read_text(encoding="utf-8")


def _sql() -> str:
    """The shipped file, normalized: comments blanked, lowercased outside literals."""
    return _normalize(_raw_sql())


def _canon(text: str) -> str:
    """Whitespace collapsed, none around parentheses, commas and ``=``; literals kept."""
    parts = _LITERAL_RE.split(text)
    return "".join(
        part if index % 2 else re.sub(r"\s*([(),=])\s*", r"\1", re.sub(r"\s+", " ", part))
        for index, part in enumerate(parts)
    ).strip()


def _shape(table: str, name: str, definition: str) -> dict[str, Any]:
    """An added column's type, NOT NULL, default, CHECKs and any other clause.

    An inline CHECK without a name gets PostgreSQL's ``<table>_<column>_check``.
    """
    column = _parse_column(name, definition)
    return {
        "type": _TYPE_CANON.get(column.type_name, column.type_name),
        "not_null": column.not_null,
        "default": _canonical_default(column),
        "checks": tuple(
            (check_name or f"{table}_{name}_check", _canon(_unwrap(expression)))
            for check_name, expression in column.checks
        ),
        "other": (
            column.primary_key,
            column.identity,
            tuple(column.uniques),
            tuple(column.references),
            tuple(column.unexpected),
        ),
    }


def _action_step(table: str, action: str) -> tuple[Any, ...]:
    masked = _masked(action)
    if (add := _ADD_COLUMN_RE.fullmatch(masked)) is not None:
        name = add.group("name")
        return ("add", table, name, _shape(table, name, action[add.start("definition") :]))
    if (drop := _DROP_COLUMN_RE.fullmatch(masked)) is not None:
        behaviour = drop.group("rest").strip()
        return (
            "drop",
            table,
            drop.group("name"),
            {
                "if_exists": drop.group("if_exists") is not None,
                "behaviour": "" if behaviour == "restrict" else behaviour,
            },
        )
    return ("other", table, action)


def _top_level_clauses(text: str) -> dict[str, str]:
    """``SET ...`` and any WHERE / FROM / RETURNING outside parentheses and literals."""
    masked = _masked(text)
    cuts: list[tuple[int, int, str]] = [(0, 0, "set")]
    depth = 0
    for index, char in enumerate(masked):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and (word := re.match(r" (where|from|returning) ", masked[index:])):
            cuts.append((index, index + word.end(), word.group(1)))
    clauses: dict[str, str] = {}
    for (_, body_start, keyword), following in zip(
        cuts, [*cuts[1:], (len(text), len(text), "")], strict=True
    ):
        clauses[keyword] = text[body_start : following[0]].strip()
    return clauses


def _update_step(statement: str, match: re.Match[str]) -> tuple[Any, ...]:
    table = match.group("table")
    alias = match.group("alias") or table
    clauses = _top_level_clauses(statement[match.start("rest") :])
    qualifier = re.compile(rf'(?<![\w."])"?(?:{re.escape(alias)}|{re.escape(table)})"?\.')
    assignments = []
    for piece in _split(clauses.pop("set"), ","):
        assignment = re.fullmatch(r'(?:"?\w+"?\.)?"?(?P<column>\w+)"? ?= ?(?P<value>.+)', piece)
        if assignment is None:
            assignments.append((piece, None))
            continue
        value = qualifier.sub("", assignment.group("value"))
        assignments.append((assignment.group("column"), _canon(value)))
    return ("update", table, tuple(assignments), {k: _canon(v) for k, v in clauses.items()})


def _steps(sql: str) -> list[tuple[Any, ...]]:
    """Every statement of a migration as steps, in file order."""
    steps: list[tuple[Any, ...]] = []
    for statement in _split(_normalize(sql), ";"):
        masked = _masked(statement)
        if (alter := _ALTER_RE.fullmatch(masked)) is not None:
            actions = _split(statement[alter.start("actions") :], ",")
            steps.extend(_action_step(alter.group("table"), action) for action in actions)
        elif (update := _UPDATE_RE.fullmatch(masked)) is not None:
            steps.append(_update_step(statement, update))
        else:
            steps.append(("other", _canon(statement)))
    return steps


def _shipped_steps() -> list[tuple[Any, ...]]:
    return _steps(_raw_sql())


def _added(table: str) -> dict[str, dict[str, Any]]:
    """The columns 0033 adds to a table, with their shapes, in file order."""
    return {step[2]: step[3] for step in _shipped_steps() if step[0] == "add" and step[1] == table}


def _dropped(table: str) -> list[str]:
    return [step[2] for step in _shipped_steps() if step[0] == "drop" and step[1] == table]


def _user_settings_after() -> frozenset[str]:
    """user_settings' columns after 0033: the columns before it, minus drops, plus adds."""
    return (_USER_SETTINGS_BEFORE - set(_dropped(_USER_SETTINGS))) | set(_added(_USER_SETTINGS))


def _sql_value(default: str | None) -> Any:
    """The Python value of a canonical SQL default (a bool keyword or a text literal)."""
    assert default is not None, "no DEFAULT"
    if default in _SQL_VALUES:
        return _SQL_VALUES[default]
    literal = re.fullmatch(r"'((?:[^']|'')*)'", default)
    assert literal is not None, f"an unexpected DEFAULT: {default}"
    return literal.group(1).replace("''", "'")


def _check_values(column: str) -> frozenset[str]:
    """The literals of the added column's only CHECK, which must be ``<column> IN (...)``."""
    checks = _added(_USER_SETTINGS)[column]["checks"]
    assert len(checks) == 1, checks
    match = re.fullmatch(rf"{column} in\((?P<values>.*)\)", checks[0][1])
    assert match is not None, checks
    return frozenset(re.findall(r"'([^']*)'", match.group("values")))


def _literal_args(annotation: Any) -> frozenset[Any]:
    """The values of a ``Literal[...]`` (or ``Literal[...] | None``), None left out."""
    values: set[Any] = set()
    for arg in typing.get_args(annotation) or (annotation,):
        if typing.get_origin(arg) is typing.Literal:
            values.update(typing.get_args(arg))
        elif arg is not type(None):
            values.add(arg)
    return frozenset(value for value in values if isinstance(value, str))


def _acl(up_to: int) -> dict[tuple[str, str], frozenset[str]]:
    """(table, grantee) -> ACL entries after every shipped migration up to a version.

    Fails the calling test when version 33 isn't shipped."""
    shipped = _load_migrations(db_mod._MIGRATIONS_DIR)
    assert _VERSION in [m.version for m in shipped], f"{_MIGRATION_NAME} is not shipped"
    acl: dict[tuple[str, str], set[str]] = {}
    for migration in shipped:
        if migration.version > up_to:
            continue
        for statement in _executed(_normalize(migration.sql)):
            _apply(acl, statement)
    return {key: frozenset(value) for key, value in acl.items() if value}


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

    async def test_migration_0033_run_migrations_applies_it_after_0032_and_records_it(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0031 applied, 0032 runs, then 0033, and 33 is recorded."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION - 1)])
        previous = (db_mod._MIGRATIONS_DIR / _PREVIOUS_MIGRATION).read_text(encoding="utf-8")
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert previous in executed
        assert shipped in executed
        assert executed.index(previous) < executed.index(shipped)
        assert (_VERSION, _MIGRATION_NAME) in recorded

    async def test_migration_0033_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0033 recorded, the shipped SQL is not executed a second time."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0033_is_parameter_free(self) -> None:
        masked = _masked(_sql())

        assert re.search(r"\$\d", masked) is None
        assert "%s" not in masked
        assert "%(" not in masked


# ---------------------------------------------------------------------------
# 2. The statements (contract C1, Decision 1)
# ---------------------------------------------------------------------------


class TestMigration0033Statements:
    """Exactly the contract's steps, in its order, and nothing else."""

    def test_migration_0033_runs_exactly_the_contract_steps_in_order(self) -> None:
        """Add the three columns, map task_done, drop the old two, add the users column."""
        assert _shipped_steps() == _steps(_CONTRACT_SQL)

    def test_migration_0033_adds_density_text_not_null_default_comfortable_with_its_check(
        self,
    ) -> None:
        assert _added(_USER_SETTINGS).get("density") == _DENSITY

    def test_migration_0033_adds_the_two_notification_types_boolean_not_null_default_true(
        self,
    ) -> None:
        """Both start on: approvals is not mapped from notifications_enabled."""
        added = _added(_USER_SETTINGS)

        assert {
            column: added.get(column)
            for column in ("notifications_approvals", "notifications_completed")
        } == dict.fromkeys(
            ("notifications_approvals", "notifications_completed"), _NOTIFICATION_TYPE
        )

    def test_migration_0033_maps_task_done_onto_completed_on_every_row_before_the_drop(
        self,
    ) -> None:
        """One UPDATE: every row (no WHERE), only notifications_completed set, after the
        column exists and before notifications_task_done is dropped."""
        steps = _shipped_steps()
        updates = [step for step in steps if step[0] == "update"]
        update = (
            "update",
            _USER_SETTINGS,
            (("notifications_completed", "notifications_task_done"),),
            {},
        )

        assert updates == [update]
        assert (
            [step[:3] for step in steps].index(("add", _USER_SETTINGS, "notifications_completed"))
            < steps.index(update)
            < [step[:3] for step in steps].index(
                ("drop", _USER_SETTINGS, "notifications_task_done")
            )
        )

    def test_migration_0033_drops_exactly_the_two_old_columns_without_cascade(self) -> None:
        """No IF EXISTS (a missing column fails loudly), no CASCADE."""
        drops = [step[1:] for step in _shipped_steps() if step[0] == "drop"]

        assert drops == [
            (_USER_SETTINGS, "notifications_enabled", _PLAIN_DROP),
            (_USER_SETTINGS, "notifications_task_done", _PLAIN_DROP),
        ]

    def test_migration_0033_adds_users_password_changed_at_nullable_without_default(
        self,
    ) -> None:
        """NULL for every existing account: no default, no backfill."""
        users_steps = [step for step in _shipped_steps() if step[1] == _USERS]

        assert users_steps == [("add", _USERS, "password_changed_at", _PASSWORD_CHANGED_AT)]

    def test_migration_0033_never_names_theme_or_updated_at(self) -> None:
        """Both are kept as they are: not added, dropped, set or altered."""
        masked = _masked(_sql())

        assert masked
        assert re.search(r"\b(?:theme|updated_at)\b", masked) is None

    def test_migration_0033_changes_nothing_else(self) -> None:
        """No other data write, DROP, privilege, object or catalog change, also nested."""
        fragments = [_masked(fragment) for fragment in _fragments(_sql())]
        hits = {
            kind: [fragment for fragment in fragments if re.search(pattern, fragment)]
            for kind, pattern in _FORBIDDEN.items()
        }

        assert fragments
        assert {kind: found for kind, found in hits.items() if found} == {}
        assert len(re.findall(r"\bupdate\b", " ".join(fragments))) == 1


# ---------------------------------------------------------------------------
# 3. Privileges (Decision 1: the grants stay as they are)
# ---------------------------------------------------------------------------


class TestMigration0033Privileges:
    """No privilege changes; the table-level grants cover the new columns."""

    def test_migration_0033_changes_no_privilege_and_the_table_grants_cover_the_columns(
        self,
    ) -> None:
        after = _acl(_VERSION)

        assert after == _acl(_VERSION - 1)
        assert {
            table: after.get((table, _ROLE)) for table in (_USERS, _USER_SETTINGS)
        } == dict.fromkeys(
            (_USERS, _USER_SETTINGS), frozenset({"select", "insert", "update", "delete"})
        )

    def test_migration_0033_passes_the_runtime_role_grant_guards(self) -> None:
        """tests/test_migration_0018.py's guards over every shipped migration, 0033 included."""
        shipped = _shipped()

        assert _MIGRATION_NAME in [migration.name for migration in shipped]
        assert {guard_id: guard(shipped) for guard_id, guard in _GUARDS} == {
            guard_id: [] for guard_id, _ in _GUARDS
        }


# ---------------------------------------------------------------------------
# 4. SQL and Pydantic agree (contract C2)
# ---------------------------------------------------------------------------


class TestMigration0033MatchesPython:
    """The SQL defaults and CHECK equal the models' defaults and Literals."""

    def test_migration_0033_density_default_and_check_equal_the_pydantic_literal(
        self,
    ) -> None:
        """A density the API accepts is one the database accepts, and the defaults agree."""
        response_values = _literal_args(
            models_module.SettingsAppearance.model_fields["density"].annotation
        )
        patch_values = _literal_args(
            models_module.SettingsPatchAppearance.model_fields["density"].annotation
        )

        assert _sql_value(_added(_USER_SETTINGS)["density"]["default"]) == "comfortable"
        assert models_module.SettingsAppearance().density == "comfortable"
        assert _check_values("density") == response_values == patch_values
        assert response_values == frozenset({"comfortable", "compact"})

    def test_migration_0033_notification_columns_equal_the_pydantic_fields_and_defaults(
        self,
    ) -> None:
        """notifications_<field> <-> notifications.<field>: one plain bool per column of the
        migrated table, defaulting to the SQL default."""
        added = _added(_USER_SETTINGS)
        columns = sorted(c for c in _user_settings_after() if c.startswith("notifications_"))
        fields = models_module.SettingsNotifications.model_fields
        defaults = models_module.SettingsNotifications()

        assert columns == ["notifications_approvals", "notifications_completed"]
        assert sorted(fields) == [column.removeprefix("notifications_") for column in columns]
        assert {
            column: (
                fields[column.removeprefix("notifications_")].annotation,
                getattr(defaults, column.removeprefix("notifications_")),
            )
            for column in columns
        } == {column: (bool, _sql_value(added[column]["default"])) for column in columns}


# ---------------------------------------------------------------------------
# 5. The FakeDb mirrors the migrated schema (contract C6)
# ---------------------------------------------------------------------------


class TestMigration0033FakeDb:
    """tests/db_fakes.py's user_settings and users are the tables after 0033."""

    def test_migration_0033_fake_user_settings_has_the_migrated_columns_and_types(
        self,
    ) -> None:
        """0013's and 0015's columns minus the dropped two, plus the added three, typed
        like the SQL, NOT NULL where the SQL says so."""
        added = _added(_USER_SETTINGS)
        types = db_fakes._SETTINGS_TYPES[_USER_SETTINGS]
        nullable = db_fakes._SETTINGS_NULLABLE[_USER_SETTINGS]

        assert frozenset(db_fakes._USER_SETTINGS_COLUMNS) == _user_settings_after()
        assert frozenset(types) == _user_settings_after()
        assert {column: (types[column], column not in nullable) for column in added} == {
            column: (_FAKE_TYPES[shape["type"]], shape["not_null"])
            for column, shape in added.items()
        }

    def test_migration_0033_fake_new_row_takes_the_sql_defaults(self) -> None:
        """A FakeDb user_settings row without values (the ensure INSERT) reads the defaults."""
        added = _added(_USER_SETTINGS)
        row = db_fakes.FakeDb().settings_defaults(_USER_SETTINGS, {}, datetime.now(UTC))

        assert added
        assert {column: row[column] for column in added} == {
            column: _sql_value(shape["default"]) for column, shape in added.items()
        }

    def test_migration_0033_fake_density_check_is_the_sql_check(self) -> None:
        """Every CHECK value is stored; anything else is a CheckViolationError."""
        allowed = _check_values("density")
        db = db_fakes.FakeDb()
        outcomes: dict[str, str] = {}
        for value in sorted(allowed | {"spacious", "Compact"}):
            user_id = db.add_account()
            try:
                db.add_user_settings(user_id, density=value)
            except asyncpg.exceptions.CheckViolationError:
                outcomes[value] = "refused"
            else:
                outcomes[value] = "stored"

        assert outcomes == {
            value: "stored" if value in allowed else "refused"
            for value in allowed | {"spacious", "Compact"}
        }

    async def test_migration_0033_fake_refuses_a_statement_naming_a_dropped_column(
        self,
    ) -> None:
        """Like PostgreSQL after 0033: refused when planned, with or without a row."""
        dropped = _dropped(_USER_SETTINGS)
        db = db_fakes.FakeDb()
        without_row = db.add_account()
        with_row = db.add_account()
        db.add_user_settings(with_row)
        outcomes: dict[tuple[str, str], str] = {}
        for column in dropped:
            for label, user_id in (("no row", without_row), ("row", with_row)):
                try:
                    await db.pool.fetchrow(_OLD_COLUMN_READS[column], user_id)
                except asyncpg.exceptions.UndefinedColumnError:
                    outcomes[column, label] = "undefined column"
                else:
                    outcomes[column, label] = "answered"

        assert sorted(dropped) == sorted(_OLD_COLUMN_READS)
        assert outcomes == {
            (column, label): "undefined column" for column in dropped for label in ("no row", "row")
        }

    def test_migration_0033_fake_users_have_a_nullable_password_changed_at(self) -> None:
        """users gains the column the migration adds; a new account reads NULL."""
        added = _added(_USERS)
        db = db_fakes.FakeDb()
        user_id = db.add_account()

        assert set(added) <= db_fakes._USER_COLUMNS
        assert {column: db.users[user_id][column] for column in added} == {
            column: None for column, shape in added.items() if not shape["not_null"]
        }
        assert added == {"password_changed_at": _PASSWORD_CHANGED_AT}
