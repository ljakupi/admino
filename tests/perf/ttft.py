"""``make ttft``: time to first token and tokens/s of the Infomaniak models (manual, GH-244).

Usage (the operator; the token comes from the repository's ``.env``)::

    python -m tests.perf.ttft      # what ``make ttft`` runs

The token: ``INFOMANIAK_API_TOKEN`` from the environment when it is set and not
blank; otherwise the tool reads that one line from the repository's ``.env``
(``_ENV_FILE``, resolved from this file's path, not the working directory). The
file is parsed as text, never run by a shell, and no other key of it is read
or set: the other secrets in ``.env`` never reach this process's environment.

Dev only, manual, needs the network and the operator's Infomaniak token. Not a
pytest file (no ``test_`` prefix, never collected); the pipeline's agents
never run it against Infomaniak.

For each model (``Qwen/Qwen3.5-397B-A17B-FP8`` and ``Qwen/Qwen3.5-122B-A10B-FP8``)
and each prompt it makes ``TTFT_RUNS`` measured requests (after one unmeasured
warm-up request per model, which also resolves the product ID, so neither the
product discovery nor the first TLS handshake counts):

- the short prompt: a one-line question;
- the 20-page document: a synthetic report of ``DOCUMENT_WORDS`` (10,000)
  words generated deterministically in code (``synthetic_document``), sent as
  the chat's one active attachment (a text file), plus a question about it.
  Each run's document differs from its first sentence on (its seed is the
  run), so the provider's prefix cache can't serve one run from another's.

Every request is shaped like a chat turn: admino's assembled context
(``prompt_assembly.assemble``: the system message with the base prompt and the
date line; the user message opened by slot 4, the document's attachment block,
since GH-189) and the tool definitions a default org advertises (every tool
module, the default permission matrix), sent through admino's own Infomaniak
client (``create_llm_client`` with an ``LLMConfig`` for
the model): ``chat_stream``, so ``reasoning_effort: none`` and the configured
output cap apply. No retries (the client alone, not ``llm_policy``).

Measures, per run:
- TTFT: seconds from the request's start to the first ``LLMStreamDelta``;
- tokens/s: the completion tokens (the final ``LLMResponse``'s ``usage`` when
  the provider reports it, else the answer's characters / 4, marked "est.")
  divided by the seconds from the first delta to the end of the stream.

Inputs (environment): ``INFOMANIAK_API_TOKEN`` (required, here or in ``.env``),
``INFOMANIAK_PRODUCT_ID`` (optional, environment only; discovered otherwise),
``TTFT_RUNS`` (default 5, 1 to 50).

Outputs: progress on stderr; on stdout the Markdown table for
docs/configuration.md (the p50 per model and prompt) and the outcome of the
default-model rule: "default: 397B", unless the 397B's short-prompt p50 TTFT is
above 3.0 s, then "default: 122B (397B stays available to the Super Admin)".
Exit status 0 when every run succeeded; 1 when a run failed or the rule can't
be decided; 2 when ``INFOMANIAK_API_TOKEN`` is missing (from the environment and
``.env``), ``.env`` can't be read or isn't valid UTF-8, or ``TTFT_RUNS`` is
invalid. Every exit-2 error is one line on stderr, without a traceback.

Security notes:
- The token reaches admino's client through this process's environment only
  (never the operator's shell); this module never prints, logs or writes it,
  and its error messages name the file and the variable, never a value. An
  unreadable or non-UTF-8 ``.env`` gets one fixed line: never the OS or codec
  error text, the path or anything from the file.
- No other key of ``.env`` is read or set: the file is parsed as text, never
  sourced by a shell, so its other secrets stay out of this process.
- No reply text is printed or kept: only its length is counted. A failed run
  is reported by its error code (admino's fixed catalogue) or exception type,
  never a message or a provider response.
- The third-party HTTP and SDK loggers stay at WARNING (they log request URLs
  at INFO and whole payloads at DEBUG); admino's formatter prints no traceback.
- ``_client_factory`` and ``_clock`` are module-level seams (looked up at call
  time) so the tool can be checked with a fake client, without the network.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import statistics
import sys
import time
from contextlib import aclosing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

from admino.llm import LLMError, LLMResponse, LLMStreamDelta

if TYPE_CHECKING:
    from collections.abc import Callable

    from admino.llm import LLMClient
    from admino.models import AttachmentContent, LLMMessage
    from admino.tools.registry import ToolDescription

MODELS: Final = ("Qwen/Qwen3.5-397B-A17B-FP8", "Qwen/Qwen3.5-122B-A10B-FP8")
# The rule: the 397B is the default unless its short-prompt p50 TTFT is above this.
TTFT_LIMIT_S: Final = 3.0
DOCUMENT_WORDS: Final = 10_000
DEFAULT_RUNS: Final = 5
MAX_RUNS: Final = 50

SHORT_LABEL: Final = "short prompt"
DOCUMENT_LABEL: Final = "20-page document"
_SHORT_PROMPT: Final = (
    "Suggest three ways to make a weekly team meeting shorter, in at most 120 words."
)
_DOCUMENT_QUESTION: Final = (
    "Using only the attached report, list the three decisions with the largest budget "
    "impact and the page each is on, in at most 120 words."
)
_RULE_397B: Final = "default: 397B"
_RULE_122B: Final = "default: 122B (397B stays available to the Super Admin)"
# The document's attachment: a fixed id (never part of the prompt) and file name.
_DOCUMENT_ID: Final = UUID("5d0c3b1e-7a2f-4e9d-8c6b-1f0e9d8c7b6a")
_DOCUMENT_NAME: Final = "report.txt"

_TOKEN_ENV: Final = "INFOMANIAK_API_TOKEN"
# The repository's .env (tests/perf/ttft.py -> the repository root), not the working
# directory's. Not Final: main() looks it up at call time, so a check can point it elsewhere.
_ENV_FILE: Path = Path(__file__).resolve().parents[2] / ".env"
# Fixed: never the OSError/UnicodeDecodeError text (path, bytes, position) or the content.
_ENV_UNREADABLE: Final = "the repository's .env can't be read or isn't valid UTF-8"
# The token's .env line (fullmatch): an optional "export ", spaces around the key and the
# "=". The key must be exact, so INFOMANIAK_API_TOKEN_OLD or a "#" comment never matches.
_TOKEN_LINE: Final = re.compile(rf"\s*(?:export\s+)?{re.escape(_TOKEN_ENV)}\s*=(.*)")
_RUNS_VALUE: Final = re.compile(r"[0-9]{1,3}")
_CODE: Final = re.compile(r"[a-z_]{1,40}")
_PINNED_LOGGERS: Final = ("httpx", "httpcore", "openai", "urllib3")

# Vocabulary of the synthetic report: plain business prose, about 5.5 characters
# per word with spaces and punctuation, so 10,000 words are about 55,000
# characters (the size the measurements have always used).
_SUBJECTS: Final = (
    "The team",
    "Our finance group",
    "The project office",
    "Each region",
    "The steering committee",
    "Customer support",
    "The operations unit",
    "The audit lead",
    "Our sales staff",
    "The board",
    "The works council",
    "The IT group",
)
_VERBS: Final = (
    "reviewed",
    "approved",
    "postponed",
    "expanded",
    "reduced",
    "documented",
    "compared",
    "measured",
    "rejected",
    "planned",
    "audited",
    "renewed",
)
_OBJECTS: Final = (
    "the quarterly budget",
    "the vendor contracts",
    "the hiring plan",
    "the travel policy",
    "the cloud costs",
    "the office lease",
    "the training program",
    "the support backlog",
    "the pricing model",
    "the security review",
    "the energy bill",
    "the fleet renewal",
)
_DETAILS: Final = (
    "after the March workshop",
    "for the Zurich office",
    "with two open questions",
    "ahead of the board meeting",
    "despite higher costs",
    "in close contact with legal",
    "as agreed in the last review",
    "for the second half of the year",
    "with a clear owner",
    "to cut waste",
    "without new staff",
    "on a tight timeline",
)


class SettingsError(ValueError):
    """``TTFT_RUNS`` is invalid, or ``.env`` can't be read or isn't valid UTF-8."""


@dataclass(frozen=True)
class Run:
    """One measured request: its numbers, or the reason it failed."""

    ttft_s: float | None = None
    tokens_per_s: float | None = None
    estimated: bool = False
    error: str | None = None


@dataclass
class Cell:
    """The runs of one model and one prompt."""

    model: str
    prompt: str
    runs: list[Run] = field(default_factory=list)

    def _ok(self) -> list[Run]:
        return [run for run in self.runs if run.error is None and run.ttft_s is not None]

    def ttft_p50(self) -> float | None:
        """The median TTFT of the successful runs (None without one)."""
        values = [run.ttft_s for run in self._ok() if run.ttft_s is not None]
        return statistics.median(values) if values else None

    def tokens_per_s_p50(self) -> float | None:
        """The median tokens/s of the successful runs that have one."""
        values = [run.tokens_per_s for run in self._ok() if run.tokens_per_s is not None]
        return statistics.median(values) if values else None

    def estimated(self) -> bool:
        """Whether a successful run's token count is the characters/4 estimate."""
        return any(run.estimated for run in self._ok())

    def failures(self) -> list[str]:
        """The failed runs' error codes."""
        return [run.error for run in self.runs if run.error is not None]


# ---------------------------------------------------------------------------
# Seams: the client factory and the clock (looked up at call time)
# ---------------------------------------------------------------------------


def _default_client(model: str) -> LLMClient:
    """Admino's own Infomaniak client for ``model`` (token and product ID from the env)."""
    from admino.config import LLMConfig
    from admino.llm import create_llm_client

    return create_llm_client(LLMConfig(provider="infomaniak", infomaniak_model=model))


_client_factory: Callable[[str], LLMClient] = _default_client
_clock: Callable[[], float] = time.perf_counter


# ---------------------------------------------------------------------------
# The requests
# ---------------------------------------------------------------------------


def _pick(options: tuple[str, ...], digest: bytes, index: int) -> str:
    return options[digest[index] % len(options)]


def synthetic_document(seed: int, words: int = DOCUMENT_WORDS) -> str:
    """A deterministic report: ``words`` words of prose in 20 pages, each with a heading.

    Sentences are drawn from fixed phrase lists by SHA-256 of ``seed`` and the
    sentence number, so the same seed gives the same text and two seeds differ
    from the first sentence on.
    """
    sentences: list[str] = []
    count = 0
    number = 0
    while count < words:
        digest = hashlib.sha256(f"admino-ttft:{seed}:{number}".encode()).digest()
        tokens = (
            f"{_pick(_SUBJECTS, digest, 0)} {_pick(_VERBS, digest, 1)} "
            f"{_pick(_OBJECTS, digest, 2)} {_pick(_DETAILS, digest, 3)} "
            f"and saved {digest[4] % 90 + 10} percent in week {digest[5] % 52 + 1}."
        ).split()[: words - count]
        sentences.append(" ".join(tokens))
        count += len(tokens)
        number += 1
    per_page = -(-len(sentences) // 20)
    pages = [sentences[start : start + per_page] for start in range(0, len(sentences), per_page)]
    return "\n\n".join(
        f"Page {page} of {len(pages)}\n" + " ".join(lines)
        for page, lines in enumerate(pages, start=1)
    )


def _tools() -> tuple[list[ToolDescription], list[dict[str, Any]]]:
    """The tool descriptions and payload a default org advertises (every tool module)."""
    from admino import main as admino_main
    from admino.agent import _tool_descriptions_to_payload
    from admino.permissions import build_default_permissions_config
    from admino.tools import registry

    admino_main._import_tool_modules()  # imports are cached: each module registers once
    descriptions = registry.get_registered_tools(
        permissions_config=build_default_permissions_config()
    )
    return descriptions, list(_tool_descriptions_to_payload(descriptions))


def _attachments(document: str) -> list[AttachmentContent]:
    """The document as the chat's one active attachment (none for an empty document)."""
    from admino.models import AttachmentContent, TextContent

    if not document:
        return []
    return [
        AttachmentContent(
            id=_DOCUMENT_ID,
            filename=_DOCUMENT_NAME,
            kind="txt",
            page_count=None,
            parts=(TextContent(text=document),),
        )
    ]


def build_request(
    user_message: str, document: str
) -> tuple[list[LLMMessage], list[dict[str, Any]]]:
    """A chat turn's messages (admino's system prompt, the document as attachment) and tools."""
    from admino import prompt_assembly
    from admino.models import PromptContext

    descriptions, payload = _tools()
    messages = prompt_assembly.assemble(
        PromptContext(default_response_language="en"),
        tools=descriptions,
        now=datetime.now(UTC),
        user_message=user_message,
        attachments=_attachments(document),
    )
    return messages, payload


def _error_code(exc: Exception) -> str:
    """A failed run's reason: the LLMError code, else the exception type (never a message)."""
    if isinstance(exc, LLMError):
        code = exc.code
        return code if isinstance(code, str) and _CODE.fullmatch(code) else "llm_error"
    return type(exc).__name__


async def measure_once(
    client: LLMClient, messages: list[LLMMessage], tools: list[dict[str, Any]]
) -> Run:
    """One streamed request: TTFT and tokens/s, or the error code. Reads the stream to its end."""
    started = _clock()
    first: float | None = None
    characters = 0
    completion_tokens: int | None = None
    try:
        async with aclosing(client.chat_stream(messages, tools)) as items:
            async for item in items:
                if isinstance(item, LLMStreamDelta):
                    if first is None:
                        first = _clock()
                    characters += len(item.content)
                elif isinstance(item, LLMResponse) and item.usage is not None:
                    completion_tokens = item.usage.completion_tokens
    except Exception as exc:  # any failure is one failed run, named by code or type
        return Run(error=_error_code(exc))
    ended = _clock()
    if first is None:
        return Run(error="no_answer_delta")
    estimated = completion_tokens is None
    tokens = characters / 4 if completion_tokens is None else float(completion_tokens)
    seconds = ended - first
    return Run(
        ttft_s=first - started,
        tokens_per_s=tokens / seconds if seconds > 0 else None,
        estimated=estimated,
    )


async def _warm_up(client: LLMClient) -> None:
    """Resolve the product ID and make one unmeasured short request (its result is dropped)."""
    from admino.llm_infomaniak import InfomaniakClient

    if isinstance(client, InfomaniakClient):
        try:
            await client.resolve_product_id()
        except LLMError:
            return  # every measured run reports the setup error by its code
    messages, tools = build_request(_SHORT_PROMPT, "")
    await measure_once(client, messages, tools)


async def measure(runs: int) -> list[Cell]:
    """Every model and prompt, ``runs`` measured requests each."""
    cells: list[Cell] = []
    for model_index, model in enumerate(MODELS):
        client = _client_factory(model)
        try:
            print(f"make ttft: {model}: warm-up", file=sys.stderr, flush=True)
            await _warm_up(client)
            for label, question in (
                (SHORT_LABEL, _SHORT_PROMPT),
                (DOCUMENT_LABEL, _DOCUMENT_QUESTION),
            ):
                cell = Cell(model=model, prompt=label)
                for run in range(runs):
                    print(
                        f"make ttft: {model}: {label}, run {run + 1} of {runs}",
                        file=sys.stderr,
                        flush=True,
                    )
                    document = (
                        synthetic_document(seed=model_index * 1000 + run)
                        if label == DOCUMENT_LABEL
                        else ""
                    )
                    messages, tools = build_request(question, document)
                    cell.runs.append(await measure_once(client, messages, tools))
                cells.append(cell)
        finally:
            await client.close()
    return cells


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def rule_outcome(cells: list[Cell]) -> str | None:
    """The default-model rule's outcome, or None without a successful 397B short-prompt run."""
    for cell in cells:
        if cell.model == MODELS[0] and cell.prompt == SHORT_LABEL:
            p50 = cell.ttft_p50()
            if p50 is None:
                return None
            return _RULE_122B if p50 > TTFT_LIMIT_S else _RULE_397B
    return None


def render(cells: list[Cell], runs: int, today: str) -> tuple[list[str], bool]:
    """The Markdown rows, the failures and the rule; and whether everything succeeded."""
    lines = [
        f"Measured {today} with admino's Infomaniak client (chat_stream, reasoning_effort none), "
        f"p50 of {runs} runs per row:",
        "",
        "| Model | Prompt | TTFT p50 | Tokens/s p50 | Runs |",
        "|---|---|---|---|---|",
    ]
    ok = True
    for cell in cells:
        ttft = cell.ttft_p50()
        rate = cell.tokens_per_s_p50()
        succeeded = len(cell.runs) - len(cell.failures())
        ttft_text = "failed" if ttft is None else f"{ttft:.2f} s"
        rate_text = "-" if rate is None else f"{rate:.1f}" + (" (est.)" if cell.estimated() else "")
        runs_text = f"{succeeded}/{len(cell.runs)}"
        lines.append(f"| {cell.model} | {cell.prompt} | {ttft_text} | {rate_text} | {runs_text} |")
    if any(cell.estimated() for cell in cells):
        lines.extend(
            ["", "(est.): no usage reported; completion tokens estimated as characters / 4."]
        )
    failed = [cell for cell in cells if cell.failures()]
    if failed:
        ok = False
        lines.append("")
        lines.extend(
            f"FAILED: {cell.model}, {cell.prompt}: {len(cell.failures())} of {len(cell.runs)} "
            f"runs ({', '.join(sorted(set(cell.failures())))})"
            for cell in failed
        )
    outcome = rule_outcome(cells)
    lines.append("")
    if outcome is None:
        ok = False
        lines.append(f"Rule outcome: undecided (no successful {MODELS[0]} short-prompt run)")
    else:
        short = next(c for c in cells if c.model == MODELS[0] and c.prompt == SHORT_LABEL)
        lines.append(
            f"Rule outcome: {outcome} ({MODELS[0]} short-prompt p50 TTFT "
            f"{short.ttft_p50():.2f} s; limit {TTFT_LIMIT_S:.1f} s)"
        )
    return lines, ok


def runs_from_env() -> int:
    """``TTFT_RUNS`` (default 5).

    Raises:
        SettingsError: Unless it is a whole number from 1 to 50.
    """
    raw = os.environ.get("TTFT_RUNS", "").strip()
    if not raw:
        return DEFAULT_RUNS
    if not _RUNS_VALUE.fullmatch(raw) or not 1 <= int(raw) <= MAX_RUNS:
        msg = f"TTFT_RUNS must be a whole number from 1 to {MAX_RUNS}"
        raise SettingsError(msg)
    return int(raw)


def _env_value(raw: str) -> str:
    """A .env value: one pair of matching quotes removed, else everything before `` #``.

    A quoted value is kept whole (a `` #`` inside it is part of the token);
    only an unquoted one has a comment, as in a shell or docker compose.
    """
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    comment = value.find(" #")
    return (value if comment == -1 else value[:comment]).strip()


def token_from_env_file(path: Path) -> str | None:
    """The ``INFOMANIAK_API_TOKEN`` value of the .env file at ``path``, or None.

    Only a line whose key is exactly ``INFOMANIAK_API_TOKEN`` counts (optional
    ``export `` prefix, spaces around the key and the ``=``); the last one wins.
    Its value loses one pair of matching quotes; unquoted, `` #`` starts a
    comment. Comment lines and every other key are ignored. The file is parsed
    as text, never run by a shell (no expansion), and nothing is set.

    Args:
        path: The .env file (``_ENV_FILE`` in ``main()``).

    Returns:
        The value, or None when the file is missing, has no such line, or the
        value is empty or blank.

    Raises:
        SettingsError: The file exists but can't be read (any other OSError,
            e.g. no permission or a directory) or isn't valid UTF-8; fixed text.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError):
        raise SettingsError(_ENV_UNREADABLE) from None
    value: str | None = None
    for line in text.splitlines():
        match = _TOKEN_LINE.fullmatch(line)
        if match is not None:
            value = _env_value(match.group(1))
    if value is None or not value.strip():
        return None
    return value


def _configure_logging() -> None:
    """Warnings and errors on stderr (admino's formatter); third-party loggers at WARNING."""
    from admino.logs import RequestIdFilter, TextFormatter

    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RequestIdFilter())
    handler.setFormatter(TextFormatter())
    logging.basicConfig(level=logging.WARNING, handlers=[handler], force=True)
    for name in _PINNED_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def main() -> int:
    """Measure and print; see the module docstring for the exit statuses."""
    if not os.environ.get(_TOKEN_ENV, "").strip():
        try:
            token = token_from_env_file(_ENV_FILE)
        except SettingsError as exc:
            print(f"make ttft: {exc}", file=sys.stderr)
            return 2
        if token is None:
            print(
                f"make ttft needs {_TOKEN_ENV}: set it in the repository's .env "
                "(or in the environment), then run it again.",
                file=sys.stderr,
            )
            return 2
        # This process only (admino's client reads it); no other .env key is set.
        os.environ[_TOKEN_ENV] = token
    try:
        runs = runs_from_env()
    except SettingsError as exc:
        print(f"make ttft: {exc}", file=sys.stderr)
        return 2
    _configure_logging()
    try:
        cells = asyncio.run(measure(runs))
    except KeyboardInterrupt:
        print("make ttft: interrupted", file=sys.stderr)
        return 130
    lines, ok = render(cells, runs, datetime.now(UTC).date().isoformat())
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
