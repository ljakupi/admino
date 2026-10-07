"""The developer tooling around ``make ttft`` and ``make test-proxy`` (GH-278, decisions 3 and 7).

Spec, checked against the tools under ``tests/`` and their docs:

``make ttft`` (``tests/perf/ttft.py``, decision 3):
- ``token_from_env_file(path)`` parses the repository's ``.env`` as text, never
  through a shell: only a line whose key is exactly ``INFOMANIAK_API_TOKEN``
  counts (optional ``export `` prefix, spaces around the key and the ``=``, one
  pair of matching quotes removed, `` #`` starts a comment in an unquoted value,
  the last matching line wins). Missing file, missing line or an empty/blank
  value give None.
- ``main()`` uses a non-blank ``INFOMANIAK_API_TOKEN`` from the environment;
  otherwise it reads ``_ENV_FILE`` (resolved from the module's own path, looked
  up at call time) and puts the token into its own ``os.environ``. No other key
  of ``.env`` is set. Without a token it exits with status 2 and a message that
  names ``.env`` and the variable, never a value; the token is never printed.
- The docs (configuration.md "Model latency", getting-started.md's ``make ttft``
  line) and the Makefile's comment no longer tell the operator to load ``.env``
  into the shell (``set -a; source .env``) and say the token comes from ``.env``.

``make test-proxy`` (``tests/test_proxy_profile.py``, decision 7):
- ``_require_docker()`` skips with the on-demand reason without
  ``ADMINO_DOCKER_TESTS=1`` (and doesn't probe Docker); with it, a missing
  ``docker`` CLI or a ``docker info`` that fails (non-zero exit or no answer)
  FAILS the test with a message saying ``make test-proxy`` needs Docker and
  naming what is missing. The ``proxy`` fixture calls it before any setup.
- The Makefile's ``test-proxy`` comment no longer says the test is skipped
  without Docker.

Security notes: every ``.env`` here is a tmp file with marker values; the real
``.env`` is never read (``_ENV_FILE`` is monkeypatched in every ``main()``
test). The measuring is stubbed, so no network is used, and ``os.environ`` is
restored by monkeypatch. Docker is never run: ``shutil.which`` and
``subprocess.run`` are replaced by recorders.
"""

from __future__ import annotations

import inspect
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from types import ModuleType

_ROOT = Path(__file__).resolve().parents[1]
_TOKEN_KEY = "INFOMANIAK_API_TOKEN"
_TOKEN = "tok-w4-file-0123456789abcdef"
_ENV_TOKEN = "tok-w4-env-fedcba9876543210"

# Other secrets an operator's .env holds next to the token (marker values).
_OTHER_KEYS = (
    "PG_APP_PASSWORD",
    "ADMINO_FERNET_KEY",
    "SMTP_PASSWORD",
    "INFOMANIAK_PRODUCT_ID",
    "INFOMANIAK_API_TOKEN_OLD",
    "OAUTH_ENCRYPTION_KEY",
)
_OTHER_VALUES = (
    "pg-app-secret-w4",
    "fernet-secret-w4",
    "smtp-secret-w4",
    "987654321",
    "old-token-secret-w4",
    "oauth-secret-w4",
)
_OTHER_LINES = (
    "# admino .env (marker values)\n"
    "PG_APP_PASSWORD=pg-app-secret-w4\n"
    'export ADMINO_FERNET_KEY="fernet-secret-w4"\n'
    "SMTP_PASSWORD='smtp-secret-w4'\n"
    "INFOMANIAK_PRODUCT_ID=987654321\n"
    "INFOMANIAK_API_TOKEN_OLD=old-token-secret-w4\n"
)
_TRAILING_LINES = "OAUTH_ENCRYPTION_KEY=oauth-secret-w4\n"


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def ttft() -> ModuleType:
    """``tests/perf/ttft.py``, imported lazily (the new names are looked up per test)."""
    from tests.perf import ttft as module

    return module


@pytest.fixture
def proxy_module() -> ModuleType:
    """``tests/test_proxy_profile.py``, imported lazily (never at this module's top level)."""
    from tests import test_proxy_profile as module

    return module


class _Measure:
    """Stands in for ``ttft.measure``: records each call and the environment it saw."""

    def __init__(self, ttft: ModuleType) -> None:
        self.ttft = ttft
        self.environs: list[dict[str, str]] = []

    async def __call__(self, runs: int) -> list[Any]:
        self.environs.append(dict(os.environ))
        return [
            self.ttft.Cell(
                model=model,
                prompt=prompt,
                runs=[self.ttft.Run(ttft_s=1.0, tokens_per_s=20.0)],
            )
            for model in self.ttft.MODELS
            for prompt in (self.ttft.SHORT_LABEL, self.ttft.DOCUMENT_LABEL)
        ]


def _prepare_main(
    ttft: ModuleType, monkeypatch: pytest.MonkeyPatch, env_file: Path, env_token: str | None
) -> _Measure:
    """Point ``_ENV_FILE`` at ``env_file``, clean the environment, stub measuring and logging."""
    monkeypatch.setattr(ttft, "_ENV_FILE", env_file)
    for key in (*_OTHER_KEYS, "TTFT_RUNS"):
        monkeypatch.delenv(key, raising=False)
    if env_token is None:
        monkeypatch.delenv(_TOKEN_KEY, raising=False)
    else:
        monkeypatch.setenv(_TOKEN_KEY, env_token)
    measure = _Measure(ttft)
    monkeypatch.setattr(ttft, "measure", measure)
    # The real one replaces the root handlers (basicConfig force=True).
    monkeypatch.setattr(ttft, "_configure_logging", lambda: None)
    return measure


def _run_main(ttft: ModuleType) -> int:
    """``ttft.main()``'s exit status, whether it returns it or raises ``SystemExit``."""
    try:
        return int(ttft.main())
    except SystemExit as exc:
        return int(exc.code or 0)
    except KeyboardInterrupt:
        pytest.fail("ttft.main() let a KeyboardInterrupt escape")


def _leaked(text: str, values: tuple[str, ...]) -> list[str]:
    return [value for value in values if value in text]


def _md_section(path: Path, heading: str) -> str:
    """The text of the Markdown section ``heading`` up to the next heading of its level or above.

    Lines inside fenced code blocks never end a section (a ``# comment`` in a
    bash block isn't a heading).
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    level = len(heading) - len(heading.lstrip("#"))
    start = lines.index(heading)
    body: list[str] = []
    fenced = False
    for line in lines[start + 1 :]:
        if line.lstrip().startswith("```"):
            fenced = not fenced
        elif not fenced:
            match = re.match(r"(#{1,6})\s", line)
            if match and len(match.group(1)) <= level:
                break
        body.append(line)
    return "\n".join(body)


def _makefile_comment_above(target: str) -> str:
    """The comment lines directly above the Makefile rule ``target:``."""
    lines = (_ROOT / "Makefile").read_text(encoding="utf-8").splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith(f"{target}:"))
    comment: list[str] = []
    for line in reversed(lines[:index]):
        if not line.startswith("#"):
            break
        comment.insert(0, line)
    assert comment, f"the Makefile has no comment above {target}:"
    return "\n".join(comment)


def _makefile_recipe(target: str) -> str:
    """The recipe lines (tab-indented) of the Makefile rule ``target:``."""
    lines = (_ROOT / "Makefile").read_text(encoding="utf-8").splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith(f"{target}:"))
    recipe: list[str] = []
    for line in lines[index + 1 :]:
        if not line.startswith("\t"):
            break
        recipe.append(line)
    return "\n".join(recipe)


class _DockerProbe:
    """Replaces ``shutil.which`` and ``subprocess.run``; records every probe, never runs Docker."""

    def __init__(self, which: str | None, info: int | BaseException) -> None:
        self._which = which
        self._info = info
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def which(self, name: str, *args: Any, **kwargs: Any) -> str | None:
        self.calls.append(("which", (name,)))
        return self._which

    def run(self, argv: Any, *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        command = tuple(str(part) for part in argv)
        self.calls.append(("run", command))
        if isinstance(self._info, BaseException):
            raise self._info
        return subprocess.CompletedProcess(
            list(command), self._info, b"", b"Cannot connect to the Docker daemon"
        )


def _install_probe(monkeypatch: pytest.MonkeyPatch, probe: _DockerProbe) -> None:
    # tests/test_proxy_profile.py looks both up through the modules (``import shutil``,
    # ``import subprocess``), so patching the module attributes reaches it.
    monkeypatch.setattr(shutil, "which", probe.which)
    monkeypatch.setattr(subprocess, "run", probe.run)


def _gate_outcome(proxy_module: ModuleType) -> tuple[str, str]:
    """Call ``_require_docker()``: ("skip" | "fail" | "none", its message).

    A skip or failure is caught and returned: left to propagate, a wrong
    ``pytest.skip`` would turn THIS test into a skip instead of a failure.
    """
    try:
        result = proxy_module._require_docker()
    except pytest.skip.Exception as exc:
        return "skip", str(exc)
    except pytest.fail.Exception as exc:
        return "fail", str(exc)
    return "none", repr(result)


# ---------------------------------------------------------------------------
# make ttft: parsing .env
# ---------------------------------------------------------------------------

_PARSE_CASES = [
    pytest.param(f"INFOMANIAK_API_TOKEN={_TOKEN}\n", _TOKEN, id="plain"),
    pytest.param(f"export INFOMANIAK_API_TOKEN={_TOKEN}\n", _TOKEN, id="export-prefix"),
    pytest.param(
        f"  INFOMANIAK_API_TOKEN  =  {_TOKEN}\n", _TOKEN, id="spaces-around-key-and-equals"
    ),
    pytest.param(f'INFOMANIAK_API_TOKEN="{_TOKEN}"\n', _TOKEN, id="double-quoted"),
    pytest.param(f"INFOMANIAK_API_TOKEN='{_TOKEN}'\n", _TOKEN, id="single-quoted"),
    pytest.param(
        f"INFOMANIAK_API_TOKEN=\"'{_TOKEN}'\"\n", f"'{_TOKEN}'", id="only-one-quote-pair-removed"
    ),
    pytest.param(
        f'INFOMANIAK_API_TOKEN="{_TOKEN} #kept"\n', f"{_TOKEN} #kept", id="quoted-hash-is-value"
    ),
    pytest.param(
        f"INFOMANIAK_API_TOKEN={_TOKEN} # the operator's token\n", _TOKEN, id="unquoted-comment"
    ),
    pytest.param(
        f"INFOMANIAK_API_TOKEN={_TOKEN}#part\n", f"{_TOKEN}#part", id="hash-without-space-is-value"
    ),
    pytest.param(
        f"INFOMANIAK_API_TOKEN=first-token-w4\nINFOMANIAK_API_TOKEN={_TOKEN}\n",
        _TOKEN,
        id="last-line-wins",
    ),
    pytest.param(
        f"INFOMANIAK_API_TOKEN={_TOKEN}\n"
        "INFOMANIAK_API_TOKEN_OLD=lookalike-old\n"
        "# INFOMANIAK_API_TOKEN=lookalike-comment\n"
        "#INFOMANIAK_API_TOKEN=lookalike-comment-2\n"
        "XINFOMANIAK_API_TOKEN=lookalike-prefixed\n",
        _TOKEN,
        id="lookalike-lines-never-count",
    ),
    pytest.param(_OTHER_LINES + _TRAILING_LINES, None, id="no-such-line"),
    pytest.param("INFOMANIAK_API_TOKEN=\n", None, id="empty-value"),
    pytest.param("INFOMANIAK_API_TOKEN=   \n", None, id="blank-value"),
    pytest.param('INFOMANIAK_API_TOKEN=""\n', None, id="empty-quoted-value"),
    pytest.param("INFOMANIAK_API_TOKEN='   '\n", None, id="blank-quoted-value"),
    pytest.param(
        f"INFOMANIAK_API_TOKEN={_TOKEN}\nINFOMANIAK_API_TOKEN=\n", None, id="last-line-empty"
    ),
    pytest.param(None, None, id="missing-file"),
]


@pytest.mark.parametrize(("content", "expected"), _PARSE_CASES)
def test_ttft_token_from_env_file_reads_only_the_exact_key(
    ttft: ModuleType, tmp_path: Path, content: str | None, expected: str | None
) -> None:
    """Only a line keyed exactly ``INFOMANIAK_API_TOKEN`` counts, parsed per decision 3."""
    path = tmp_path / ".env"
    if content is not None:
        path.write_text(content, encoding="utf-8")

    assert ttft.token_from_env_file(path) == expected


def test_ttft_token_from_env_file_parses_text_without_a_shell(
    ttft: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file is text: no expansion, no command run, nothing put into the environment."""
    marker = tmp_path / "shell-ran"
    value = f"tok-w4-$HOME-$(touch {marker})-`touch {marker}`"
    path = tmp_path / ".env"
    path.write_text(
        _OTHER_LINES + f"INFOMANIAK_API_TOKEN={value}\n" + _TRAILING_LINES, encoding="utf-8"
    )
    for key in (*_OTHER_KEYS, _TOKEN_KEY):
        monkeypatch.delenv(key, raising=False)
    before = dict(os.environ)

    result = ttft.token_from_env_file(path)

    assert (result, marker.exists(), dict(os.environ) == before) == (value, False, True)


# ---------------------------------------------------------------------------
# make ttft: main()
# ---------------------------------------------------------------------------


def test_ttft_env_file_resolves_from_the_module_path_not_the_cwd(
    ttft: ModuleType, tmp_path: Path
) -> None:
    """``_ENV_FILE`` is the repository's ``.env`` beside ``tests/``, whatever the cwd."""
    import admino

    expected = Path(ttft.__file__).resolve().parents[2] / ".env"
    in_process = ttft._ENV_FILE
    src = Path(admino.__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(expected.parent), str(src)])}
    child = subprocess.run(  # noqa: S603
        [sys.executable, "-c", "from tests.perf import ttft; print(ttft._ENV_FILE)"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert (isinstance(in_process, Path), in_process, child.returncode, child.stdout.strip()) == (
        True,
        expected,
        0,
        str(expected),
    )


@pytest.mark.parametrize("env_token", [None, "   "], ids=["env-unset", "env-blank"])
def test_ttft_main_takes_only_the_token_from_env_file(
    ttft: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    env_token: str | None,
) -> None:
    """Without a usable environment token, the file's token (and nothing else) is set."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        _OTHER_LINES + f"INFOMANIAK_API_TOKEN={_TOKEN}\n" + _TRAILING_LINES, encoding="utf-8"
    )
    measure = _prepare_main(ttft, monkeypatch, env_file, env_token)
    caplog.set_level(logging.DEBUG)
    before = dict(os.environ)

    status = _run_main(ttft)

    captured = capsys.readouterr()
    assert status == 0
    assert measure.environs == [{**before, _TOKEN_KEY: _TOKEN}]
    printed = captured.out + captured.err + caplog.text
    assert _leaked(printed, (_TOKEN, *_OTHER_VALUES)) == []


@pytest.mark.parametrize("file_state", ["missing", "other-token"])
def test_ttft_main_prefers_a_non_blank_environment_token(
    ttft: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    file_state: str,
) -> None:
    """A non-blank ``INFOMANIAK_API_TOKEN`` in the environment wins; ``.env`` isn't needed."""
    env_file = tmp_path / ".env"
    if file_state == "other-token":
        env_file.write_text(
            _OTHER_LINES + f"INFOMANIAK_API_TOKEN={_TOKEN}\n" + _TRAILING_LINES, encoding="utf-8"
        )
    measure = _prepare_main(ttft, monkeypatch, env_file, _ENV_TOKEN)
    caplog.set_level(logging.DEBUG)
    before = dict(os.environ)

    status = _run_main(ttft)

    captured = capsys.readouterr()
    assert status == 0
    assert measure.environs == [before]
    printed = captured.out + captured.err + caplog.text
    assert _leaked(printed, (_ENV_TOKEN, _TOKEN, *_OTHER_VALUES)) == []


@pytest.mark.parametrize(
    ("env_token", "content"),
    [
        pytest.param("  ", None, id="blank-env-missing-file"),
        pytest.param(None, _OTHER_LINES + _TRAILING_LINES, id="no-token-line"),
        pytest.param(
            None, _OTHER_LINES + "INFOMANIAK_API_TOKEN=\n" + _TRAILING_LINES, id="empty-value"
        ),
    ],
)
def test_ttft_main_without_a_token_exits_2_naming_env_file_and_variable(
    ttft: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    env_token: str | None,
    content: str | None,
) -> None:
    """No token: status 2, a message naming ``.env`` and the variable, no value, no measuring."""
    env_file = tmp_path / ".env"
    if content is not None:
        env_file.write_text(content, encoding="utf-8")
    measure = _prepare_main(ttft, monkeypatch, env_file, env_token)
    before = dict(os.environ)

    status = _run_main(ttft)

    captured = capsys.readouterr()
    assert (status, measure.environs, dict(os.environ) == before) == (2, [], True)
    assert ".env" in captured.err
    assert _TOKEN_KEY in captured.err
    # The tool reads the token itself: it no longer tells the operator to export .env.
    assert "source .env" not in captured.err
    assert "set -a" not in captured.err
    assert _leaked(captured.out + captured.err, _OTHER_VALUES) == []


# ---------------------------------------------------------------------------
# make test-proxy: the Docker gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("opt_in", [None, "0"], ids=["unset", "zero"])
def test_proxy_gate_without_opt_in_skips_without_probing_docker(
    proxy_module: ModuleType, monkeypatch: pytest.MonkeyPatch, opt_in: str | None
) -> None:
    """``make check`` and CI: the Docker tests skip with the on-demand reason."""
    if opt_in is None:
        monkeypatch.delenv("ADMINO_DOCKER_TESTS", raising=False)
    else:
        monkeypatch.setenv("ADMINO_DOCKER_TESTS", opt_in)
    probe = _DockerProbe(which="/usr/local/bin/docker", info=0)
    _install_probe(monkeypatch, probe)

    kind, message = _gate_outcome(proxy_module)

    assert (kind, "ADMINO_DOCKER_TESTS" in message, probe.calls) == ("skip", True, [])


def test_proxy_gate_opted_in_without_docker_cli_fails_clearly(
    proxy_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``make test-proxy`` without the docker CLI: a failure that says what is missing."""
    monkeypatch.setenv("ADMINO_DOCKER_TESTS", "1")
    probe = _DockerProbe(which=None, info=0)
    _install_probe(monkeypatch, probe)

    kind, message = _gate_outcome(proxy_module)

    assert (kind, "make test-proxy needs Docker" in message, "docker CLI" in message) == (
        "fail",
        True,
        True,
    )


@pytest.mark.parametrize(
    "info",
    [
        pytest.param(1, id="daemon-down"),
        pytest.param(subprocess.TimeoutExpired(["docker", "info"], 60), id="no-answer"),
    ],
)
def test_proxy_gate_opted_in_when_docker_info_fails_fails_clearly(
    proxy_module: ModuleType, monkeypatch: pytest.MonkeyPatch, info: int | BaseException
) -> None:
    """``make test-proxy`` with a daemon that doesn't answer ``docker info``: a clear failure."""
    monkeypatch.setenv("ADMINO_DOCKER_TESTS", "1")
    probe = _DockerProbe(which="/usr/local/bin/docker", info=info)
    _install_probe(monkeypatch, probe)

    kind, message = _gate_outcome(proxy_module)

    assert (kind, "make test-proxy needs Docker" in message, "docker info" in message) == (
        "fail",
        True,
        True,
    )


def test_proxy_gate_opted_in_with_docker_lets_the_tests_run(
    proxy_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the CLI and a daemon that answers, the gate neither skips nor fails."""
    monkeypatch.setenv("ADMINO_DOCKER_TESTS", "1")
    probe = _DockerProbe(which="/usr/local/bin/docker", info=0)
    _install_probe(monkeypatch, probe)

    assert _gate_outcome(proxy_module) == ("none", "None")


def test_proxy_fixture_checks_the_docker_gate_before_any_setup(
    proxy_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ``proxy`` fixture runs ``_require_docker`` first (its skip or failure decides)."""

    class _GateRanError(Exception):
        pass

    def gate() -> None:
        raise _GateRanError

    def no_docker(*args: Any, **kwargs: Any) -> bytes:
        raise AssertionError("the proxy fixture ran docker before checking the gate")

    class _NoTmp:
        def mktemp(self, *args: Any, **kwargs: Any) -> Path:
            raise AssertionError("the proxy fixture set up before checking the gate")

    # Without the opt-in, a fixture with its own inline gate would skip (caught below).
    monkeypatch.delenv("ADMINO_DOCKER_TESTS", raising=False)
    monkeypatch.setattr(proxy_module, "_require_docker", gate)
    monkeypatch.setattr(proxy_module, "_docker", no_docker)
    monkeypatch.setattr(proxy_module, "_docker_quiet", no_docker)
    fixture_function = inspect.unwrap(proxy_module.proxy)

    try:
        next(iter(fixture_function(_NoTmp())))
    except _GateRanError:
        outcome = "gate"
    except (pytest.skip.Exception, pytest.fail.Exception) as exc:
        outcome = f"{type(exc).__name__}: {exc}"
    else:
        outcome = "yielded"

    assert outcome == "gate"


# ---------------------------------------------------------------------------
# Docs and Makefile text
# ---------------------------------------------------------------------------

_SOURCING = ("set -a", "source .env", "in the shell")


def test_docs_model_latency_section_drops_sourcing_env_for_make_ttft() -> None:
    """configuration.md "Model latency": no ``set -a; source .env``; the token comes from .env."""
    section = _md_section(_ROOT / "docs" / "configuration.md", "### Model latency")

    assert [phrase for phrase in _SOURCING if phrase in section] == []
    assert (".env" in section, _TOKEN_KEY in section) == (True, True)


def test_docs_getting_started_make_ttft_line_reads_the_token_from_env_file() -> None:
    """getting-started.md's ``make ttft`` line: no shell instruction, the token comes from .env."""
    text = (_ROOT / "docs" / "getting-started.md").read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if "make ttft" in line]

    assert lines, "getting-started.md no longer mentions make ttft"
    assert [line for line in lines if any(phrase in line for phrase in _SOURCING)] == []
    assert any(".env" in line for line in lines)


def test_makefile_ttft_comment_drops_sourcing_env() -> None:
    """The comment above ``ttft:`` says the token comes from .env, not from a sourced shell."""
    comment = _makefile_comment_above("ttft")

    assert [phrase for phrase in _SOURCING if phrase in comment] == []
    assert ".env" in comment


def test_makefile_test_proxy_comment_no_longer_says_skipped_without_docker() -> None:
    """``make test-proxy`` sets the opt-in and its comment no longer promises a skip."""
    comment = _makefile_comment_above("test-proxy")

    assert re.search(r"skip\w*\s+without\s+docker", comment, re.IGNORECASE) is None
    assert "ADMINO_DOCKER_TESTS=1" in _makefile_recipe("test-proxy")
