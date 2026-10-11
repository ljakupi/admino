"""Tests for migration 0013_settings_scopes.sql — settings split into three scopes (GH-159).

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0012.py pattern): it must exist, be applied by
run_migrations as version 13, and make exactly the schema change GH-159 needs.
The SQL is read with ``--`` comments blanked; statements are split outside
parentheses and literals; keywords are compared case-insensitively with
whitespace collapsed, while string literals are kept byte for byte (the theme
values, the defaults and the model-name regex are compared exactly). A
constraint may be written inline on its column or as a table constraint, and a
range may be written as ``BETWEEN`` or as two comparisons.

What these tests pin down:
- ``DROP TABLE settings``: the old key/value table goes, nothing is carried over.
- ``platform_settings``: a singleton (``id BOOLEAN PRIMARY KEY DEFAULT true
  CHECK (id)``); ``llm_provider TEXT NOT NULL`` limited to the providers of
  ``LLMConfig.provider``; the four nullable ``*_model`` columns, each with the
  model-name regex CHECK; the five ``LimitsConfig`` fields as ``INTEGER NOT
  NULL`` with exactly the ``LimitsConfig`` bounds; ``updated_at``. The
  migration inserts no platform row (startup seeds it from config.yaml).
  (GH-190: ``LimitsConfig.max_context_messages`` is 0 to 200 now, and migration
  0030 re-adds that CHECK with those bounds; 0013's own CHECK stays 1 to 200.)
- ``org_settings``: ``org_id UUID PRIMARY KEY REFERENCES organizations (id) ON
  DELETE CASCADE`` and one ``<tool>_enabled BOOLEAN NOT NULL DEFAULT true``
  per ``ToolsSettings`` field; ``updated_at``.
- ``user_settings``: ``user_id UUID PRIMARY KEY REFERENCES users (id) ON
  DELETE CASCADE``; ``theme TEXT NOT NULL DEFAULT 'light'`` limited to the
  ``SettingsAppearance.theme`` values; ``notifications_enabled BOOLEAN NOT NULL
  DEFAULT true``; ``updated_at``. (GH-307: migration 0033 drops
  notifications_enabled; its model field goes with it, and
  tests/test_migration_0033.py pins the columns that replace it.)
- Every existing org and user gets a row with the column defaults only
  (``INSERT INTO org_settings (org_id) SELECT id FROM organizations`` and the
  same for users), and the SQL defaults equal the Pydantic defaults.
- The model-name CHECK accepts and rejects exactly what the Python
  ``SettingsPatchLLM`` validator does (so a value the API accepts never makes
  the database refuse the write with a 500).
- Nothing else: no audit catalog change (``org.settings_change`` and
  ``platform.settings_change`` already exist), no other DROP, no ALTER, no
  UPDATE / DELETE / TRUNCATE, no index, function, trigger, view, type or DO
  block, no GRANT / REVOKE, parameter-free.

Security notes:
- Both foreign keys cascade, so the org purge (GH-154) removes an org's and
  its users' settings rows with them (tests/test_schema_foreign_keys.py).
- The CHECKs mirror the Pydantic bounds, so the database refuses what the API
  refuses even if a write bypasses the models.
- The singleton key means there is exactly one platform settings row.
"""

from __future__ import annotations

import re
import typing
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

import admino.database as db_mod
from admino.config import LimitsConfig, LLMConfig
from admino.models import (
    SettingsAppearance,
    SettingsNotifications,
    SettingsPatchLLM,
    ToolsSettings,
)
from tests.test_migration_0015 import _user_settings_changes_after

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME = "0013_settings_scopes.sql"
_VERSION = 13
_TABLES = ("platform_settings", "org_settings", "user_settings")
_PROVIDERS = frozenset({"infomaniak", "vllm", "anthropic", "openai"})
_MODEL_COLUMNS = ("infomaniak_model", "vllm_model", "anthropic_model", "openai_model")
_LIMIT_BOUNDS: dict[str, tuple[int, int]] = {
    "max_tool_calls_per_message": (1, 100),
    "max_pending_confirmations": (1, 50),
    "confirmation_timeout_s": (10, 3600),
    "max_message_length": (1, 100_000),
    "max_context_messages": (1, 200),
}
# LimitsConfig's bounds today: GH-190 (Decision 8) widened max_context_messages to 0 (no
# cap), and migration 0030 re-adds its CHECK with those bounds (the model sync for that
# column is pinned in tests/test_migration_0030.py). 0013's own CHECK stays 1 to 200.
_CONFIG_BOUNDS: dict[str, tuple[int, int]] = {**_LIMIT_BOUNDS, "max_context_messages": (0, 200)}
_TOOLS = (
    "gmail",
    "google_calendar",
    "google_drive",
    "outlook",
    "outlook_calendar",
    "onedrive",
    "memory",
)
_THEMES = frozenset({"light", "dark", "system"})
_TIMESTAMPTZ = r"(?:timestamptz|timestamp\s*(?:\(\s*\d\s*\)\s*)?with\s+time\s+zone)"
_NOW = r"(?:now\s*\(\s*\)|current_timestamp|transaction_timestamp\s*\(\s*\))"
_CONSTRAINT_START = (
    r"(?:constraint\s+\w+\s+)?(?:check|unique|primary\s+key|foreign\s+key|exclude)\b"
)
# (sample, accepted): the model-name rule of GH-159 (fullmatch of
# [a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}; a trailing newline is refused).
_MODEL_NAME_SAMPLES: tuple[tuple[str, bool], ...] = (
    ("Qwen/Qwen3.5-397B-A17B-FP8", True),
    ("gpt-4o", True),
    ("claude-sonnet-4-6", True),
    ("a", True),
    ("mistralai/Mistral-Small-3.2", True),
    ("llama3.1:8b", True),
    ("org_name/model_v2", True),
    ("a" * 200, True),
    ("", False),
    ("-x", False),
    ("_x", False),
    (".hidden", False),
    ("/abs", False),
    ("a b", False),
    ("a;rm", False),
    ("a|b", False),
    ("model$(id)", False),
    ("a\n", False),
    ("a\tb", False),
    ("a" + chr(0) + "b", False),
    ("mod" + chr(0xE9) + "le", False),
    ("x" * 201, False),
)


# ---------------------------------------------------------------------------
# Helpers: reading and quote-aware parsing of the shipped SQL
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _migration_sql() -> str:
    """The shipped migration, normalized outside literals only.

    ``--`` comments are blanked, whitespace is collapsed and keywords are
    lowercased; the contents of '...' and "..." are kept byte for byte.
    """
    raw = _migration_path().read_text(encoding="utf-8")
    out: list[str] = []
    quote = ""
    index = 0
    while index < len(raw):
        char = raw[index]
        if quote:
            out.append(char)
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
            out.append(char)
        elif raw.startswith("--", index):
            end = raw.find("\n", index)
            index = len(raw) if end < 0 else end
            if out and out[-1] != " ":
                out.append(" ")
            continue
        elif char.isspace():
            if out and out[-1] != " ":
                out.append(" ")
        else:
            out.append(char.lower())
        index += 1
    return "".join(out).strip()


def _masked(text: str) -> str:
    """Blank out the contents of '...' and "..." literals (same length)."""
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


def _balanced_end(masked: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(masked)):
        if masked[index] == "(":
            depth += 1
        elif masked[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    pytest.fail(f"unbalanced parentheses in {_MIGRATION_NAME}")


def _split(text: str, separator: str) -> list[str]:
    """Split text at a separator outside parentheses and literals."""
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


def _statements() -> list[str]:
    return _split(_migration_sql(), ";")


def _create_table_body(table: str) -> str:
    for statement in _statements():
        masked = _masked(statement)
        match = re.match(rf"create\s+table\s+(?:if\s+not\s+exists\s+)?{table}\s*\(", masked)
        if match is None:
            continue
        end = _balanced_end(masked, match.end() - 1)
        assert masked[end + 1 :].strip() == "", statement
        return statement[match.end() : end]
    pytest.fail(f"no CREATE TABLE {table} (...) in {_MIGRATION_NAME}")


def _elements(table: str) -> list[str]:
    return _split(_create_table_body(table), ",")


def _columns(table: str) -> dict[str, str]:
    columns: dict[str, str] = {}
    for element in _elements(table):
        if re.match(_CONSTRAINT_START, _masked(element)):
            continue
        match = re.fullmatch(r'"?(\w+)"?\s+(.*)', element)
        assert match is not None, element
        columns[match.group(1)] = match.group(2)
    return columns


def _column(table: str, name: str) -> str:
    columns = _columns(table)
    assert name in columns, f"no column {name} in CREATE TABLE {table}"
    return columns[name]


def _table_constraints(table: str) -> list[str]:
    return [element for element in _elements(table) if re.match(_CONSTRAINT_START, element)]


def _unwrap(expression: str) -> str:
    expression = expression.strip()
    while (
        expression.startswith("(") and _balanced_end(_masked(expression), 0) == len(expression) - 1
    ):
        expression = expression[1:-1].strip()
    return expression


def _checks_in(text: str) -> list[str]:
    masked = _masked(text)
    expressions: list[str] = []
    for match in re.finditer(r"\bcheck\s*\(", masked):
        end = _balanced_end(masked, match.end() - 1)
        expressions.append(_unwrap(text[match.end() : end]))
    return expressions


def _check_expressions(table: str, column: str) -> list[str]:
    """The CHECKs on a column: inline on it, or table-level ones naming it."""
    expressions = _checks_in(_column(table, column))
    for constraint in _table_constraints(table):
        for expression in _checks_in(constraint):
            if re.search(rf"\b{column}\b", _masked(expression)):
                expressions.append(expression)
    return expressions


def _and_atoms(expression: str) -> list[str]:
    """The top-level AND-ed conditions of an expression, each unwrapped."""
    masked = _masked(expression)
    atoms: list[str] = []
    depth = 0
    start = 0
    for match in re.finditer(r"\(|\)|\band\b", masked):
        token = match.group(0)
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
        elif depth == 0:
            atoms.append(_unwrap(expression[start : match.start()]))
            start = match.end()
    atoms.append(_unwrap(expression[start:]))
    return atoms


def _check_atoms(table: str, column: str) -> list[str]:
    """Every AND-ed condition on a column; BETWEEN is read as two comparisons."""
    atoms: list[str] = []
    for expression in _check_expressions(table, column):
        rewritten = re.sub(
            rf"\b{column}\s+between\s+(-?\d[\d_]*)\s+and\s+(-?\d[\d_]*)",
            rf"{column} >= \1 and {column} <= \2",
            expression,
        )
        atoms.extend(_and_atoms(rewritten))
    return atoms


def _bounds(table: str, column: str) -> tuple[int | None, int | None]:
    """The inclusive (low, high) range the CHECKs allow for an integer column."""
    low: int | None = None
    high: int | None = None
    for atom in _check_atoms(table, column):
        forward = re.fullmatch(rf"{column}\s*(>=|>|<=|<)\s*(-?\d[\d_]*)", atom)
        backward = re.fullmatch(rf"(-?\d[\d_]*)\s*(>=|>|<=|<)\s*{column}", atom)
        if forward is not None:
            operator, value = forward.group(1), int(forward.group(2))
        elif backward is not None:
            flipped = {">=": "<=", ">": "<", "<=": ">=", "<": ">"}
            operator, value = flipped[backward.group(2)], int(backward.group(1))
        else:
            pytest.fail(f"unexpected CHECK condition on {table}.{column}: {atom}")
        if operator == ">=":
            low = value
        elif operator == ">":
            low = value + 1
        elif operator == "<=":
            high = value
        else:
            high = value - 1
    return low, high


def _in_values(table: str, column: str) -> set[str] | None:
    """The literals of '<column> IN (...)' when a CHECK condition is exactly that."""
    for atom in _check_atoms(table, column):
        match = re.fullmatch(rf"{column}\s+in\s*\(([^)]*)\)", atom)
        if match is not None:
            return set(re.findall(r"'([^']*)'", match.group(1)))
    return None


def _default(definition: str) -> str | None:
    """The DEFAULT expression of a column definition (literals kept verbatim)."""
    masked = _masked(definition)
    match = re.search(r"\bdefault\s+", masked)
    if match is None:
        return None
    rest = definition[match.end() :]
    rest_masked = masked[match.end() :]
    if rest.startswith("'"):
        closing = rest_masked.index("'", 1)
        return rest[: closing + 1]
    token = re.match(r"\w+(?:\s*\(\s*\))?", rest_masked)
    assert token is not None, definition
    return rest[: token.end()]


def _primary_key(table: str) -> tuple[str, ...]:
    inline = tuple(
        name
        for name, definition in _columns(table).items()
        if re.search(r"\bprimary\s+key\b", _masked(definition))
    )
    table_level = tuple(
        column.strip()
        for constraint in _table_constraints(table)
        if (
            match := re.fullmatch(
                r"(?:constraint\s+\w+\s+)?primary\s+key\s*\(([^)]*)\)", _masked(constraint)
            )
        )
        for column in match.group(1).split(",")
    )
    return tuple(sorted(inline + table_level))


def _foreign_key(table: str, column: str) -> tuple[str, str, str]:
    """(referenced table, referenced column, rest after the reference) for a column's FK."""
    pattern = r"references\s+(\w+)\s*(?:\(\s*(\w+)\s*\))?(.*)"
    inline = re.search(rf"\b{pattern}", _masked(_column(table, column)))
    if inline is not None:
        return inline.group(1), inline.group(2) or "id", inline.group(3)
    for constraint in _table_constraints(table):
        match = re.fullmatch(
            rf"(?:constraint\s+\w+\s+)?foreign\s+key\s*\(\s*{column}\s*\)\s*{pattern}",
            _masked(constraint),
        )
        if match is not None:
            return match.group(1), match.group(2) or "id", match.group(3)
    pytest.fail(f"{table}.{column} has no foreign key")


def _model_rule(table: str, column: str) -> tuple[str, int | None]:
    """The model-name CHECK of a column: (regex literal, optional length cap)."""
    regexes: list[str] = []
    cap: int | None = None
    for atom in _check_atoms(table, column):
        regex = re.fullmatch(rf"{column}\s*~\s*'((?:[^']|'')*)'", atom)
        length = re.fullmatch(
            rf"(?:char_length|character_length|length)\s*\(\s*{column}\s*\)\s*<=\s*(\d+)", atom
        )
        if regex is not None:
            regexes.append(regex.group(1).replace("''", "'"))
        elif length is not None:
            cap = int(length.group(1))
        else:
            pytest.fail(f"unexpected CHECK condition on {table}.{column}: {atom}")
    assert len(regexes) == 1, f"{table}.{column} needs exactly one '~' regex CHECK"
    return regexes[0], cap


def _sql_accepts_model(column: str, sample: str) -> bool:
    """Emulate PostgreSQL's CHECK (column ~ '^...$') on a sample value."""
    pattern, cap = _model_rule("platform_settings", column)
    assert pattern.startswith("^"), pattern
    assert pattern.endswith("$"), pattern
    if cap is not None and len(sample) > cap:
        return False
    # PostgreSQL's '$' (not newline-sensitive) only matches at the very end, so
    # an anchored ~ is a full match of the inner pattern.
    return re.fullmatch(pattern[1:-1], sample) is not None


def _python_accepts_model(column: str, sample: str) -> bool:
    try:
        SettingsPatchLLM.model_validate({column: sample})
    except ValidationError:
        return False
    return True


def _is_required(definition: str) -> bool:
    return re.search(r"\bnot\s+null\b", _masked(definition)) is not None


def _literal_values(annotation: object) -> set[str]:
    values: set[str] = set()
    for arg in typing.get_args(annotation):
        if isinstance(arg, str):
            values.add(arg)
        else:
            values |= _literal_values(arg)
    return values


def _field_bounds(name: str) -> tuple[int, int]:
    metadata = LimitsConfig.model_fields[name].metadata
    low = next(item.ge for item in metadata if hasattr(item, "ge"))
    high = next(item.le for item in metadata if hasattr(item, "le"))
    return int(low), int(high)


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0013File:
    """The migration ships as version 13 and is applied by run_migrations."""

    def test_migration_0013_file_is_shipped_as_version_13(self) -> None:
        assert _migration_path().is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == _VERSION

    def test_migration_0013_is_the_only_version_13(self) -> None:
        thirteens = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert thirteens == [_MIGRATION_NAME]

    async def test_migration_0013_run_migrations_applies_it_as_version_13(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0012 applied, run_migrations executes the file and records 13."""
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

    async def test_migration_0013_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0013_is_parameter_free(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\$\d", masked) is None
        assert "%s" not in masked
        assert "%(" not in masked


# ---------------------------------------------------------------------------
# 2. Exactly the contract's statements
# ---------------------------------------------------------------------------

_STATEMENT_KINDS: tuple[tuple[str, str], ...] = (
    ("drop settings", r"drop\s+table\s+(?:if\s+exists\s+)?settings(?:\s+restrict)?"),
    *(
        (f"create {table}", rf"create\s+table\s+(?:if\s+not\s+exists\s+)?{table}\s*\(.*\)")
        for table in _TABLES
    ),
    (
        "seed org_settings",
        r"insert\s+into\s+org_settings\s*\(\s*org_id\s*\)\s*"
        r"select\s+(?:organizations\s*\.\s*)?id\s+from\s+organizations",
    ),
    (
        "seed user_settings",
        r"insert\s+into\s+user_settings\s*\(\s*user_id\s*\)\s*"
        r"select\s+(?:users\s*\.\s*)?id\s+from\s+users",
    ),
)


def _kind(statement: str) -> str | None:
    masked = _masked(statement)
    for kind, pattern in _STATEMENT_KINDS:
        if re.fullmatch(pattern, masked):
            return kind
    return None


class TestMigration0013Statements:
    """One drop, three tables, two seeds; nothing else."""

    def test_migration_0013_every_statement_is_part_of_the_contract(self) -> None:
        for statement in _statements():
            assert _kind(statement) is not None, statement

    def test_migration_0013_has_each_contract_statement_exactly_once(self) -> None:
        kinds = sorted(kind for statement in _statements() if (kind := _kind(statement)))

        assert kinds == sorted(kind for kind, _ in _STATEMENT_KINDS)

    def test_migration_0013_drops_the_old_settings_table(self) -> None:
        """Existing values are not carried over: the key/value table is dropped."""
        drops = [s for s in _statements() if re.match(r"drop\b", _masked(s))]

        assert len(drops) == 1
        assert _kind(drops[0]) == "drop settings", drops[0]

    def test_migration_0013_drop_does_not_cascade(self) -> None:
        """Nothing depends on settings; CASCADE could silently drop more."""
        drops = [s for s in _statements() if re.match(r"drop\b", _masked(s))]

        assert drops
        for statement in drops:
            assert re.search(r"\bcascade\b", _masked(statement)) is None, statement

    def test_migration_0013_seeds_come_after_their_tables(self) -> None:
        kinds = [_kind(statement) for statement in _statements()]

        assert kinds.index("seed org_settings") > kinds.index("create org_settings")
        assert kinds.index("seed user_settings") > kinds.index("create user_settings")

    def test_migration_0013_inserts_no_platform_row(self) -> None:
        """Startup seeds platform_settings from config.yaml; the migration does not."""
        masked = _masked(_migration_sql())

        assert re.search(r"\binsert\s+into\s+platform_settings\b", masked) is None

    def test_migration_0013_seeds_use_the_column_defaults_only(self) -> None:
        """Each org and user row gets only its key; every other value is the default."""
        inserts = [s for s in _statements() if re.match(r"insert\b", _masked(s))]

        assert sorted(_kind(s) or s for s in inserts) == ["seed org_settings", "seed user_settings"]


# ---------------------------------------------------------------------------
# 3. platform_settings
# ---------------------------------------------------------------------------


class TestMigration0013PlatformSettings:
    """The singleton platform row: llm provider, one model per provider, limits."""

    def test_migration_0013_platform_settings_has_exactly_the_contract_columns(self) -> None:
        expected = {"id", "llm_provider", *_MODEL_COLUMNS, *_LIMIT_BOUNDS, "updated_at"}

        assert set(_columns("platform_settings")) == expected

    def test_migration_0013_platform_settings_is_a_singleton(self) -> None:
        """id BOOLEAN PRIMARY KEY DEFAULT true CHECK (id): only one row can exist."""
        definition = _masked(_column("platform_settings", "id"))

        assert re.match(r"(?:boolean|bool)\b", definition), definition
        assert _primary_key("platform_settings") == ("id",)
        assert _default(_column("platform_settings", "id")) == "true"
        assert any(
            re.fullmatch(r"id(?:\s*=\s*true|\s+is\s+true)?", atom)
            for atom in _check_atoms("platform_settings", "id")
        ), _check_expressions("platform_settings", "id")

    def test_migration_0013_platform_provider_is_required_text(self) -> None:
        definition = _masked(_column("platform_settings", "llm_provider"))

        assert re.match(r"text\b", definition), definition
        assert _is_required(definition), definition

    def test_migration_0013_platform_provider_check_equals_llm_config_providers(self) -> None:
        config_providers = _literal_values(LLMConfig.model_fields["provider"].annotation)

        assert config_providers == _PROVIDERS
        assert _in_values("platform_settings", "llm_provider") == _PROVIDERS

    def test_migration_0013_platform_model_columns_mirror_the_patch_model(self) -> None:
        """One model column per provider, the same names as SettingsPatchLLM's."""
        patch_models = {name for name in SettingsPatchLLM.model_fields if name.endswith("_model")}
        sql_models = {name for name in _columns("platform_settings") if name.endswith("_model")}

        assert patch_models == set(_MODEL_COLUMNS)
        assert sql_models == patch_models

    @pytest.mark.parametrize("column", _MODEL_COLUMNS)
    def test_migration_0013_platform_model_column_is_nullable_text(self, column: str) -> None:
        """An empty or missing model in config.yaml is stored as NULL."""
        definition = _masked(_column("platform_settings", column))

        assert re.match(r"text\b", definition), definition
        assert not _is_required(definition), definition

    @pytest.mark.parametrize("column", _MODEL_COLUMNS)
    def test_migration_0013_platform_model_column_has_the_anchored_regex_check(
        self, column: str
    ) -> None:
        pattern, _ = _model_rule("platform_settings", column)

        assert pattern.startswith("^")
        assert pattern.endswith("$")

    @pytest.mark.parametrize("column", _MODEL_COLUMNS)
    @pytest.mark.parametrize(
        ("sample", "accepted"),
        _MODEL_NAME_SAMPLES,
        ids=[repr(s)[:40] for s, _ in _MODEL_NAME_SAMPLES],
    )
    def test_migration_0013_model_check_matches_the_python_validator(
        self, column: str, sample: str, accepted: bool
    ) -> None:
        """The DB CHECK and SettingsPatchLLM accept and refuse the same model names."""
        assert _sql_accepts_model(column, sample) is accepted
        assert _python_accepts_model(column, sample) is accepted

    def test_migration_0013_platform_limit_columns_equal_limits_config_fields(self) -> None:
        sql_limits = set(_columns("platform_settings")) - {
            "id",
            "llm_provider",
            "updated_at",
            *_MODEL_COLUMNS,
        }

        assert set(LimitsConfig.model_fields) == set(_LIMIT_BOUNDS)
        assert sql_limits == set(LimitsConfig.model_fields)

    @pytest.mark.parametrize("column", sorted(_LIMIT_BOUNDS))
    def test_migration_0013_platform_limit_is_a_required_integer(self, column: str) -> None:
        definition = _masked(_column("platform_settings", column))

        assert re.match(r"(?:integer|int|int4)\b", definition), definition
        assert _is_required(definition), definition

    @pytest.mark.parametrize("column", sorted(_LIMIT_BOUNDS))
    def test_migration_0013_platform_limit_bounds_equal_limits_config(self, column: str) -> None:
        """The CHECK range is the contract's, and LimitsConfig's ge/le are the bounds the
        shipped migrations leave (0013's, but max_context_messages 0 to 200 since GH-190's
        migration 0030)."""
        assert _field_bounds(column) == _CONFIG_BOUNDS[column]
        assert _bounds("platform_settings", column) == _LIMIT_BOUNDS[column]

    def test_migration_0013_platform_updated_at(self) -> None:
        definition = _masked(_column("platform_settings", "updated_at"))

        assert re.match(_TIMESTAMPTZ, definition), definition
        assert _is_required(definition), definition
        assert re.fullmatch(_NOW, _default(definition) or ""), definition

    def test_migration_0013_platform_settings_has_no_foreign_key(self) -> None:
        """Platform scope belongs to no org or user."""
        assert (
            re.search(r"\breferences\b", _masked(_create_table_body("platform_settings"))) is None
        )


# ---------------------------------------------------------------------------
# 4. org_settings
# ---------------------------------------------------------------------------


class TestMigration0013OrgSettings:
    """One row per org: the enabled tool services."""

    def test_migration_0013_org_settings_has_exactly_the_contract_columns(self) -> None:
        expected = {"org_id", *(f"{tool}_enabled" for tool in _TOOLS), "updated_at"}

        assert set(_columns("org_settings")) == expected

    def test_migration_0013_org_tool_columns_equal_tools_settings_fields(self) -> None:
        tool_columns = {name for name in _columns("org_settings") if name.endswith("_enabled")}

        assert set(ToolsSettings.model_fields) == set(_TOOLS)
        assert tool_columns == {f"{tool}_enabled" for tool in ToolsSettings.model_fields}

    def test_migration_0013_org_id_is_the_uuid_primary_key(self) -> None:
        definition = _masked(_column("org_settings", "org_id"))

        assert re.match(r"uuid\b", definition), definition
        assert _primary_key("org_settings") == ("org_id",)

    def test_migration_0013_org_id_references_organizations_on_delete_cascade(self) -> None:
        """The org purge removes the org's settings row with it."""
        referenced, column, rest = _foreign_key("org_settings", "org_id")

        assert (referenced, column) == ("organizations", "id")
        assert re.search(r"\bon\s+delete\s+cascade\b", rest), rest

    @pytest.mark.parametrize("tool", _TOOLS)
    def test_migration_0013_org_tool_is_required_boolean_default_true(self, tool: str) -> None:
        """Every service starts enabled, like ToolsSettings()."""
        definition = _column("org_settings", f"{tool}_enabled")

        assert re.match(r"(?:boolean|bool)\b", _masked(definition)), definition
        assert _is_required(definition), definition
        assert getattr(ToolsSettings(), tool) is True
        assert _default(definition) == "true", definition

    def test_migration_0013_org_updated_at(self) -> None:
        definition = _masked(_column("org_settings", "updated_at"))

        assert re.match(_TIMESTAMPTZ, definition), definition
        assert _is_required(definition), definition
        assert re.fullmatch(_NOW, _default(definition) or ""), definition


# ---------------------------------------------------------------------------
# 5. user_settings
# ---------------------------------------------------------------------------


class TestMigration0013UserSettings:
    """One row per user: theme and notifications (languages stay on users)."""

    def test_migration_0013_user_settings_has_exactly_the_contract_columns(self) -> None:
        """No language column: ui/response language stay on users (#145, #166)."""
        expected = {"user_id", "theme", "notifications_enabled", "updated_at"}

        assert set(_columns("user_settings")) == expected

    def test_migration_0013_user_id_is_the_uuid_primary_key(self) -> None:
        definition = _masked(_column("user_settings", "user_id"))

        assert re.match(r"uuid\b", definition), definition
        assert _primary_key("user_settings") == ("user_id",)

    def test_migration_0013_user_id_references_users_on_delete_cascade(self) -> None:
        """The org purge deletes the users, and their settings rows go with them."""
        referenced, column, rest = _foreign_key("user_settings", "user_id")

        assert (referenced, column) == ("users", "id")
        assert re.search(r"\bon\s+delete\s+cascade\b", rest), rest

    def test_migration_0013_theme_is_required_text(self) -> None:
        definition = _masked(_column("user_settings", "theme"))

        assert re.match(r"text\b", definition), definition
        assert _is_required(definition), definition

    def test_migration_0013_theme_default_equals_the_pydantic_default(self) -> None:
        assert SettingsAppearance().theme == "light"
        assert _default(_column("user_settings", "theme")) == f"'{SettingsAppearance().theme}'"

    def test_migration_0013_theme_check_equals_the_pydantic_literal(self) -> None:
        literal = _literal_values(SettingsAppearance.model_fields["theme"].annotation)

        assert literal == _THEMES
        assert _in_values("user_settings", "theme") == literal

    def test_migration_0013_notifications_enabled_is_required_boolean_default_true(self) -> None:
        """The SQL default is the model's while the column is shipped (GH-307: once a later
        migration drops it, the model field goes with it)."""
        definition = _column("user_settings", "notifications_enabled")

        assert re.match(r"(?:boolean|bool)\b", _masked(definition)), definition
        assert _is_required(definition), definition
        if "notifications_enabled" in _user_settings_changes_after(_VERSION)[1]:
            assert "enabled" not in SettingsNotifications.model_fields
        else:
            assert SettingsNotifications().enabled is True
        assert _default(definition) == "true", definition

    def test_migration_0013_user_updated_at(self) -> None:
        definition = _masked(_column("user_settings", "updated_at"))

        assert re.match(_TIMESTAMPTZ, definition), definition
        assert _is_required(definition), definition
        assert re.fullmatch(_NOW, _default(definition) or ""), definition


# ---------------------------------------------------------------------------
# 6. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0013NothingElse:
    """No other table, constraint, data, code or privilege changes."""

    def test_migration_0013_alters_nothing(self) -> None:
        assert re.search(r"\balter\b", _masked(_migration_sql())) is None

    def test_migration_0013_drops_nothing_else(self) -> None:
        assert len(re.findall(r"\bdrop\b", _masked(_migration_sql()))) == 1

    def test_migration_0013_changes_no_existing_rows(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\bupdate\s+(?:only\s+)?\w+\s+set\b", masked) is None
        assert re.search(r"\bdelete\s+from\b", masked) is None
        assert re.search(r"\btruncate\b", masked) is None
        assert re.search(r"\bmerge\s+into\b", masked) is None

    def test_migration_0013_defines_no_index_function_trigger_view_or_type(self) -> None:
        masked = _masked(_migration_sql())

        assert (
            re.search(
                r"\bcreate\s+(?:or\s+replace\s+)?(?:unique\s+)?"
                r"(?:index|function|procedure|trigger|view|type|rule|policy)\b",
                masked,
            )
            is None
        )
        assert re.search(r"\bdo\s+\$", masked) is None
        assert "$$" not in masked

    def test_migration_0013_grants_nothing(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\b(?:grant|revoke)\b", masked) is None

    def test_migration_0013_leaves_the_audit_catalog_alone(self) -> None:
        """org.settings_change and platform.settings_change are already in the catalog."""
        from admino.audit_events import AuditAction

        assert AuditAction.ORG_SETTINGS_CHANGE.value == "org.settings_change"
        assert AuditAction.PLATFORM_SETTINGS_CHANGE.value == "platform.settings_change"
        assert "audit" not in _migration_sql()
