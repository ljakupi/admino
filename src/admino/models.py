"""Shared Pydantic models for tool args, API types, and agent messages.

This module defines all structured data types shared across admino modules:
- API request/response models (used by server.py)
- Agent and LLM message models (used by agent.py and llm.py)

Tool-call audit events are not modelled here: they are content-free rows of
the ``audit_events`` table, validated by ``admino.audit_events``.

Security notes:
- No secrets, tokens, passwords, or credentials are stored in any model field,
  except ``LoginRequest.password``, ``PasswordResetConfirmRequest.token`` /
  ``new_password``, ``InvitationAcceptRequest.password``,
  ``CriticalPermissionPromote.password`` and ``PasswordChangeRequest``'s two
  passwords: ``SecretStr`` values (hidden from repr/str) that live only for
  their request and are never logged or echoed.
  Invitation models carry no token, hash or link.
- Organization models (GH-154) carry org metadata only: no content, and
  ``OrgCreateResponse`` no token or link. ``OrgCreateRequest`` and
  ``OrgLimitsPatch`` hide their input from validation errors (an org name or
  admin email never reaches a log or a 422 body); seats, quotas and the
  residency switch are strict ints and bools.
- Org user management (GH-164): ``OrgUserSummary`` carries account metadata
  only (no hash, token, org id or kind); ``OrgUserPatch`` refuses unknown keys
  (the org, the target, the status and the kind come from the session, the
  path and the dedicated routes) and hides its input from validation errors.
  ``OrgSeats`` (GH-165) carries two counts only: the org's used seats and its
  limit.
- LLM error codes (GH-242): ``LLMErrorCode`` is the closed set of stable
  codes a failed run carries (``AgentResult.error_code``,
  ``ChatResponse.error_code``); the UI translates them, so no provider text
  is ever shown. ``ChatResponse.error_code`` also admits ``rate_limit``
  (GH-24: too many pending confirmations), which no agent run carries.
- Super Admin user administration (GH-167): ``PlatformUserSummary`` carries
  account metadata only (no hash, token, org id or kind); ``OrgMetadata``
  counts and sizes only, never org content. ``PlatformReinviteRequest`` has
  one optional email (the invitation rules), refuses unknown keys (the org,
  the target, the role and the language come from the path, the contract and
  the session) and hides its input from validation errors.
- Account self-service (GH-166): ``MyAccountResponse`` carries the caller's
  own email, name, languages, timezone and personal instructions only (no id,
  hash, org, role or kind). ``MyAccountPatch`` and ``PasswordChangeRequest``
  refuse unknown keys (the account, its email, role and org come from the
  session) and hide their input from validation errors; the timezone must be
  a name of the runtime's tz database, and its error never repeats it. The
  two passwords are ``SecretStr``.
- Organization settings (GH-169): ``OrgSettingsResponse`` carries the
  caller's own org's profile, instructions, session policy, trash retention
  (with the platform's bounds) and tool services, and, read-only, its
  residency flag and plan (seats and storage quota; no budget).
  ``OrgSettingsPatch`` refuses those read-only fields and any unknown key at
  every level (an org id included), takes strict ints for the session policy
  and the trash retention, holds the display name to
  ``OrgCreateRequest.name``'s rule and the instructions (at most 8000 code
  points, kept verbatim; #170 puts them into the prompt) to the personal
  instructions' character rule, and hides its input from validation errors.
- Prompt context (GH-170): ``PromptContext`` holds exactly the five inputs of
  a run's system prompt (org and personal instructions, the user's and the
  org's response language, the timezone), never an account identifier; it
  is frozen, refuses unknown keys, bounds every text by its column's limit
  and hides its input from validation errors.
- Persisted chats (GH-176): ``ChatCreateRequest``, ``ChatUpdateRequest`` and
  ``ChatMessageCreate`` refuse unknown keys (the org, the owner, the chat and
  the title source come from the session, the path and the server) and hide
  their input from validation errors. A title is stripped, 1 to 200
  characters, and refuses control, format (bidi overrides included),
  surrogate and line/paragraph separator characters. ``ChatMessageView``
  sanitizes stored content like ``ChatResponse.response`` and exposes the
  sanitized ``ToolCallRecord``s only, never the raw tool inputs.
  ``ConfirmRequest`` names exactly one of ``chat_id`` and the legacy
  ``session_id``.
- Attachments (GH-187): ``AttachmentSummary`` carries a stored file's
  metadata only (never its org, owner or path); its bounds are migration
  0027's CHECKs. ``ChatMessageCreate.attachment_ids`` holds at most 50 ids,
  each once; the duplicate refusal names no id. ``ChatRequest`` (the legacy
  route) takes no attachments.
- Content parts (GH-189): ``LLMMessage.content`` is a str or, on a user
  message only, a non-empty list of ``TextContent`` (never blank) and
  ``ImageContent`` (JPEG or PNG, standard base64 without a ``data:`` prefix)
  parts. They and ``AttachmentContent`` (one active attachment for slot 4 of
  the prompt) exist only in the context built for one LLM call: never
  stored, logged or returned by an API. They are frozen, refuse unknown keys
  and hide their input from validation errors, and so does ``LLMMessage``.
  ``AgentConfig.image_input`` is the stored platform ``llm.image_input``.
- Context budget (GH-190): ``ContextUsage`` and ``ContextNotice`` carry
  token and message counts only. ``ContextReport`` (the send refusal's and an
  overflowing upload's report) names files by id with their stored token
  estimate and derived bytes, never by name. ``AttachmentUpdateRequest``
  takes a strict bool and nothing else and hides its input from validation
  errors. ``ChatMessageView.attachment_ids`` are ids only.
- Trash (GH-194): ``TrashItem`` carries an item's type, id, name (the chat
  title or the file name a client already showed), chat id and times only,
  never an org, an owner, a trash group or a path; ``TrashListResponse`` and
  ``TrashEmptyResponse`` are response models (no request body is added).
- Blank messages (GH-286): ``ChatMessageCreate.message`` and
  ``ChatRequest.message`` take at most 32768 characters and accept an empty
  or whitespace-only text, unstripped; the message routes refuse a blank one
  without files with ``message_empty``.
- Streamed chat turns (GH-8): ``AgentStatus`` gains ``stopped`` (a streamed
  run the user stopped; ``ChatResponse.status`` never carries it, a JSON run
  can't be stopped). The SSE event payloads (``RunStartedPayload`` to
  ``DonePayload``) and ``ChatStopResponse`` refuse unknown keys;
  ``StreamErrorCode`` is the closed set of ``error`` event codes. A delta's
  text arrives as display text (``admino.streaming.DisplayDeltas``) and is
  not cleaned again; the ``error`` message is cleaned like
  ``ChatResponse.response``. ``normalize_display_text`` is the cleanup of
  text shown to users without the credential rules: never shown itself.
- ``PlatformDiagnosticsResponse`` (GH-158) carries the LLM provider, model
  and statuses only, for the Super Admin; the public /health is status-only.
- Settings scopes (GH-159): ``UserSettingsPatch``, ``OrgSettingsPatch`` and
  ``PlatformSettingsPatch`` refuse unknown keys at every level (another
  scope's key, an org id, an LLM endpoint), take strict bools, need at least
  one value and hide their input from validation errors. Model names must
  fully match the model-name rule, the same as migration 0013's CHECK.
  ``SettingsLLM`` shows key presence flags only, never a key.
- Tool permissions per org (GH-161): ``PermissionPatch`` and
  ``CriticalPermissionPromote`` refuse unknown keys (an org id included: the
  org always comes from the session) and hide their input from validation
  errors. ``ToolPolicy`` (one org's permissions for one agent run) is frozen,
  so a loaded policy can't be changed. ``PermissionSummaryEntry`` carries a
  (tool, action) pair and its effective state only.
- Per-user connections (GH-162): ``PROVIDER_TOOLS`` (a read-only mapping)
  and ``RESIDENCY_BLOCKED_TOOLS`` (a frozenset) drive residency gating and
  can't be widened or emptied at runtime; memory is not residency-blocked.
  ``OAuthServiceStatus.tool`` is a closed Literal (``ConnectorTool``), and
  ``OAuthConnectionStatus`` / ``OrgSettingsResponse`` carry the org's
  residency flag only, never a token.
- Platform defaults (GH-160): the section patch models of
  ``PlatformSettingsPatch`` take strict ints only (a bool, float or numeric
  string is refused, never coerced) within bounds that mirror migration
  0014's CHECKs; the session and audit retention bounds are the
  ``admino.sessions`` and ``admino.audit_events`` constants.
- Models that surface free text to users (ChatResponse, ToolCallRecord,
  PendingConfirmationSummary) strip credential patterns (OAuth tokens, JWTs,
  Bearer headers, API keys) via field validators. Text shown to users
  (``sanitize_display_text``: the live reply and a stored message) also
  removes every control, format, surrogate and line/paragraph separator
  character but tab, LF and CR, the set a ``ChatTitle`` refuses (GH-270). Tool
  arguments (``ToolCallRecord.args``, ``PendingConfirmationSummary.args``) get
  the credential rules at every depth, dict keys included; a value nested
  deeper than ``_ARGS_MAX_DEPTH`` (8) becomes ``[SANITIZED]`` unread, so does
  any value or key that is not a string, None or an exact bool, int or float
  (a subclass, an ``IntEnum`` member included), and a non-dict is redacted
  before it is refused, so the validation error holds no key.
  ``SessionSummary`` strips control and direction-override characters
  from the stored user agent.
- All user-facing string fields have max_length constraints to prevent abuse.
- ToolCall.args uses dict[str, Any] because LLM output is untyped JSON;
  individual tools validate args via their own Pydantic models before execution.

Caller responsibility — ValidationError logging:
- When logging Pydantic ValidationErrors from these models, callers MUST use
  ``exc.errors(include_input=False)`` to avoid leaking raw input values.
- Never log ``str(exc)`` directly, as it embeds the offending input by default.
- This cannot be enforced inside models.py; it is a caller-side obligation.

Credential redaction limitations (defence-in-depth, not primary barrier):
- Generic ``password=`` / ``token=`` key-value pairs are not pattern-matched.
- Fernet keys (44-char base64) removed due to false-positive risk; defended by
  never formatting the key into loggable strings.
- JWT pattern only matches tokens whose first segment starts with ``ey``.
- Residual limits (GH-270), still not redacted:
  - Keys not redacted at all:
    - key formats with no rule, and a JWT whose header doesn't start with
      ``ey`` (the JWT rule needs that start): a header encoded from JSON
      that starts with ``{`` and a newline (``ewo...``) isn't caught by the
      JWT rule, or only from a later ``ey`` in it (a nested object), and the
      header's start then stays visible;
    - a key glued directly to an ASCII letter, digit or ``_`` (``ask-...``,
      ``xhf_...``, a key in ``_`` emphasis ``_<key>_``): not a token start,
      by design. Only a model title trims a ``_`` at its start before it
      redacts again, so there ``_<key>_`` and ``Title: _<key>_`` are
      redacted (decision 11 (a)); elsewhere in it (``Key: _<key>_``), in a
      message and in a fallback title the key stays visible;
    - a key whose ``sk`` prefix is split by a removed character with no
      removed character before it, glued to a preceding letter
      (``as<SHY>k-proj-...``): once the character is removed it reads
      ``ask-proj-...``, a key glued directly;
    - in a model title, a reasoning block removed between a word and a key
      (``a<think>...</think>sk-...``): it glues the two, a key glued
      directly.
  - Keys redacted only in part:
    - a key split by an invisible character outside the removal set (for
      example a combining grapheme joiner, a variation selector, a Hangul
      filler, U+2800, the Khmer vowels U+17B4 / U+17B5 or an unassigned
      default-ignorable code point such as U+2065): it isn't joined, so it
      isn't redacted whole, or not at all when the split falls within the
      rule's minimum length;
    - a key split by whitespace, a line break or any visible character its
      format doesn't allow (a key hard-wrapped in a pasted log; NBSP and
      U+3000 become spaces under NFKC): only the piece that starts with the
      prefix and reaches the rule's minimum is redacted;
    - a JWT with a key prefix at a token start inside any segment (after its
      dot, a ``-`` or a removed run): the key rules run first, so only the
      key is redacted, from the prefix to the end of that segment (or to the
      first character a narrower key format doesn't allow). The rest of the
      JWT stays visible: the header, the payload, and the signature too when
      the prefix is in the payload. The JWT can't be used without the
      redacted part;
    - a ``GOCSPX-`` or ``xox...`` credential whose body holds a key prefix
      right after a ``-`` (``GOCSPX-<4>-sk-<20>``): the key rules run first,
      so the characters before the prefix stay visible when they are shorter
      than their rule's minimum (``1//`` and ``ya29.`` run before the key
      rules and are redacted whole). When the inner key's format allows no
      ``-`` (``hf_``, ``gho_`` / ``ghu_`` / ``ghr_``, ``gsk_``, Stripe
      ``sk_live_`` / ``sk_test_``, ``github_pat_``), the characters after
      that key stay visible too (``GOCSPX-<4>-hf_<34>-<20>`` shows the last
      20);
    - a key of a rule without a token start (``GOCSPX-``, ``rk_live_`` /
      ``rk_test_``, ``ghp_`` / ``ghs_``, ``xox...``, ``1//``, ``ya29.``)
      split by a removed character right before a complete key inside its
      own body (``GOCSPX-ab<SHY>sk-<20 or more>``): the run is a separator,
      so the inner key is redacted, and the outer key's start stays visible
      when it alone is shorter than its rule's minimum;
    - a key split by a removed character right before another key inside
      its own body when the joined match wouldn't cover that inner key
      (``github_pat_<50><SHY>AIza<35>-<10>``: the ``github_pat_`` body has
      no ``-``), or when a word and a run come before the outer key
      (``x<SHY>sk-proj-ab<ZWSP>sk-...``): the run is a separator, so the
      inner key is redacted, and the outer key's start stays visible when it
      is shorter than its rule's minimum. That start can hold a complete key
      joined to it (``github_pat_<6><SHY>hf_<34><ZWSP>AIza<35>-<10>``: the
      joined ``hf_`` key is not a token start);
    - a credential of an older bounded rule longer than its bound: the part
      past the bound stays visible (``GOCSPX-`` and 100 body characters
      leave the last 20). The bounds, in body characters: ``GOCSPX-`` 80,
      ``1//`` and ``ya29.`` 512, ``ghp_`` / ``ghs_`` and ``xox<letter>-``
      255, ``rk_live_`` / ``rk_test_`` 200, ``AKIA`` exactly 16, a Bearer
      value 2048 and each JWT segment 2048. Only a JWT signature past its
      bound leaves a tail: a header or payload longer than 2048 fails the
      JWT rule, so the JWT may not be redacted at all (a later ``ey`` in a
      long header starts a match there, the header's start stays visible).
      This predates GH-270; only the token-start key rules
      (``_TOKEN_START_KEYS``) have no upper bound.
  - Elsewhere:
    - in tool arguments, a key split by any invisible character: arguments
      get the credential rules only, not the display cleanup;
    - automatic chat titles stored before #264.
- Primary defence is never placing raw credentials in loggable fields;
  ``_strip_credentials`` is a secondary safety net.
"""

from __future__ import annotations

import functools
import re
import sys
import unicodedata
import zoneinfo
from datetime import UTC, datetime
from decimal import Decimal
from types import MappingProxyType
from typing import Annotated, Any, Final, Literal, cast, get_args
from uuid import UUID  # noqa: TC003 — Pydantic resolves field annotations at runtime

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    SecretStr,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from admino import audit_events, sessions
from admino.access import (  # noqa: TC001 — Pydantic resolves field annotations at runtime
    MemberRole,
    PlainUUID,
    UserKind,
)
from admino.permissions import (  # noqa: TC001 — Pydantic resolves field annotations at runtime
    PermissionsConfig,
)

# Control characters to strip from SSE data (SSEEvent), from tool output sent
# to the model (tools/registry.py) and from a stored user agent
# (SessionSummary). Text shown to users removes a wider set (_REMOVED_RUN).
# Keeps tab (0x09), newline (0x0A), carriage return (0x0D) because they are
# legitimate in content.
# Strips Unicode direction-override and zero-width characters that could
# spoof displayed text in confirmation dialogs or log viewers.
_CONTROL_CHAR_TABLE: MappingProxyType[int, None] = MappingProxyType(
    dict.fromkeys(
        # C0 controls (0x00-0x1F) except tab (0x09), LF (0x0A), CR (0x0D).
        [i for i in range(32) if i not in (9, 10, 13)]
        # C1 controls (0x80-0x9F). Includes U+009B (CSI — Control Sequence
        # Introducer) which can trigger terminal escape sequences in log
        # viewers, and U+0085 (NEL) which is a Unicode line break.
        + list(range(0x80, 0xA0))
        + [
            0x200B,  # ZERO WIDTH SPACE
            0x200C,  # ZERO WIDTH NON-JOINER
            0x200D,  # ZERO WIDTH JOINER
            0x200E,  # LEFT-TO-RIGHT MARK
            0x200F,  # RIGHT-TO-LEFT MARK
            0x202A,  # LEFT-TO-RIGHT EMBEDDING
            0x202B,  # RIGHT-TO-LEFT EMBEDDING
            0x202C,  # POP DIRECTIONAL FORMATTING
            0x202D,  # LEFT-TO-RIGHT OVERRIDE
            0x202E,  # RIGHT-TO-LEFT OVERRIDE
            0x2028,  # LINE SEPARATOR
            0x2029,  # PARAGRAPH SEPARATOR
            0x2066,  # LEFT-TO-RIGHT ISOLATE
            0x2067,  # RIGHT-TO-LEFT ISOLATE
            0x2068,  # FIRST STRONG ISOLATE
            0x2069,  # POP DIRECTIONAL ISOLATE
            0xFEFF,  # BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE
        ]
    )
)

# The Unicode categories text shown to users removes (GH-270 decision 1):
# control (Cc), format (Cf), surrogate (Cs), line separator (Zl) and paragraph
# separator (Zp) characters, soft hyphens, word joiners and DEL included. Text
# shown to users keeps tab, LF and CR; a chat title refuses them too
# (CHAT_TITLE_BANNED_CATEGORIES is this set), so the message view and the
# titles remove the same characters.
_INVISIBLE_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_KEPT_CONTROLS: Final = frozenset("\t\n\r")


def _removed_class() -> str:
    """The regex class body of every removed code point, as ranges of ``\\U`` escapes.

    Read once at import from the runtime's Unicode data (about 0.1 s), so the
    set follows the Unicode version. Ranges (26 in Unicode 15), not 2,282
    single code points: re matches a short range list about six times faster.
    """
    ranges: list[list[int]] = []
    for code in range(sys.maxunicode + 1):
        char = chr(code)
        if char in _KEPT_CONTROLS or unicodedata.category(char) not in _INVISIBLE_CATEGORIES:
            continue
        if ranges and ranges[-1][1] == code - 1:
            ranges[-1][1] = code
        else:
            ranges.append([code, code])
    return "".join(f"\\U{first:08x}-\\U{last:08x}" for first, last in ranges)


# One run of removed characters. A character class never backtracks: each
# pass over the text is linear and runs in C.
_REMOVED_RUN: Final[re.Pattern[str]] = re.compile(f"[{_removed_class()}]+")

# API keys that start only at a token start: (prefix, body character class, the
# real format's minimum body length). OpenAI sk-proj-, sk-svcacct-, sk-admin- and
# plain sk- (about 164 characters, with "_" and "-") and Anthropic
# sk-ant-<version>- (GH-264); Stripe secret keys, Google API keys, GitHub
# fine-grained, OAuth, user-to-server and refresh tokens, Hugging Face and Groq
# keys (GH-270 decision 4). One table builds both the rule and the separator
# check below, so the two can't drift apart. The body classes nest
# ([A-Za-z0-9] inside [A-Za-z0-9_] inside [A-Za-z0-9_-]): _remove_runs relies on
# it to decide in one step whether a run inside a key joins.
_TOKEN_START_KEYS: Final[tuple[tuple[str, str, int], ...]] = (
    ("sk-", r"[A-Za-z0-9_\-]", 20),
    ("sk_(?:live|test)_", "[A-Za-z0-9]", 24),
    ("AIza", r"[A-Za-z0-9_\-]", 35),
    ("github_pat_", "[A-Za-z0-9_]", 82),
    ("gh[our]_", "[A-Za-z0-9]", 36),
    ("hf_", "[A-Za-z0-9]", 34),
    ("gsk_", "[A-Za-z0-9]", 52),
)
# A key starts only at a token start: not right after an ASCII letter, ASCII
# digit or "_" (risk-free-..., Ask-..., 2sk-..., xhf_... aren't keys), then at
# least the minimum body. ASCII on purpose, not \b: Python's \b counts CJK,
# kana and accented letters as word characters, so a key glued to Chinese,
# Japanese or accented text would not be redacted at all. No upper bound on
# purpose: an upper bound would leave the rest of a longer run as a visible
# tail, so the whole run is redacted whatever its length (fail closed). No
# trailing \b, so a key's final "-" goes too. Still linear: the lookbehind is
# fixed-width, each branch is a literal prefix and one greedy class with
# nothing after it (it never backtracks), and a failed branch reads fewer
# characters than its prefix and minimum. One pattern, not one per format: a
# leading lookbehind keeps re from scanning for a literal prefix, so each
# pattern costs a full pass, and the leftmost key wins whatever its format.
_KEY_RULE: Final[re.Pattern[str]] = re.compile(
    "(?<![A-Za-z0-9_])(?:"
    + "|".join(f"{prefix}{body}{{{minimum},}}" for prefix, body, minimum in _TOKEN_START_KEYS)
    + ")"
)
# Where a run of removed characters separates a word from a key (GH-270
# decision 2): right after an ASCII letter, digit or "_", a key prefix and its
# rule's minimum body. Exact counts, no open bound: one check reads at most
# 93 characters, so a text full of runs stays linear. One group per format, so
# a match's lastindex names the format of the key after the run.
_KEY_AFTER_WORD: Final[re.Pattern[str]] = re.compile(
    "(?<=[A-Za-z0-9_])(?:"
    + "|".join(f"({prefix}{body}{{{minimum}}})" for prefix, body, minimum in _TOKEN_START_KEYS)
    + ")"
)
# One body character of each format, in _KEY_AFTER_WORD's group order.
_KEY_BODY_CHAR: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(body) for _, body, _ in _TOKEN_START_KEYS
)
# Marks a separator while the credential rules run, then goes: NUL is in the
# removal set, so the cleaned text never holds one, and it isn't an ASCII word
# character, so the key after it starts at a token start.
_SEPARATOR: Final = "\x00"

# JWTs: three dot-separated base64url segments (header.payload.signature)
# Upper bound of 2048 per segment covers all real JWTs and caps worst-case scanning.
# Character class excludes = since RFC 7515 prohibits base64url padding in JWTs.
# Limitation: only matches tokens whose first segment starts with 'ey'.
# Named separately so _strip_credentials can skip it via a cheap pre-filter
# to avoid O(n^2) backtracking on long dot-free strings.
_JWT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"ey[A-Za-z0-9_\-]{16,2048}\.[A-Za-z0-9_\-]{16,2048}\.[A-Za-z0-9_\-]{16,2048}"
)

# Credential patterns redacted from free text shown to users.
# Immutable tuple prevents accidental mutation under concurrent access.
_CREDENTIAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"1//[A-Za-z0-9_\-]{20,512}"),  # Google OAuth refresh tokens
    re.compile(r"ya29\.[A-Za-z0-9_\-]{20,512}"),  # Google OAuth access tokens (bounded)
    # The token-start key rule runs before the JWT and Bearer rules (GH-270
    # decision 3): the Bearer rule stops after 2048 characters and the JWT rule
    # can start at an "ey" inside a key's body, so either would cut a key and
    # leave the rest visible. A key prefix at a token start inside a JWT
    # segment is redacted as a key, and the rest of that JWT stays visible (a
    # documented residual, see the module docstring).
    _KEY_RULE,
    _JWT_PATTERN,
    # NOTE: Fernet key pattern removed — regex-based redaction is unreliable for
    # 44-char base64 strings (false positives on UUIDs/hashes, false negatives when
    # embedded in longer base64 blobs). Defence: never format the key into any
    # loggable string; keep it exclusively in memory from the env var.
    re.compile(r"Bearer\s+\S{1,2048}"),  # Bearer token header values (bounded)
    re.compile(r"GOCSPX-[A-Za-z0-9_\-]{20,80}"),  # Google OAuth client secrets
    re.compile(r"rk_live_[A-Za-z0-9]{20,200}"),  # Stripe restricted keys (live)
    re.compile(r"rk_test_[A-Za-z0-9]{20,200}"),  # Stripe restricted keys (test)
    re.compile(r"gh[ps]_[A-Za-z0-9]{36,255}"),  # GitHub PATs and server tokens
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key IDs
    # NOTE: AWS secret access keys (40-char mixed alphanumeric) are intentionally
    # omitted — the character set overlaps too broadly with UUIDs, hashes, and
    # other benign strings, causing unacceptable false-positive rates.
    re.compile(r"xox[a-z]-[A-Za-z0-9\-]{10,255}"),  # Slack tokens (all types)
)
_REDACTED: Final[str] = "[CREDENTIAL_REDACTED]"
_SANITIZED_PLACEHOLDER: Final[str] = "[SANITIZED]"


def _strip_credentials(value: str) -> str:
    """Replace known credential patterns in a string with a redaction marker.

    Applies NFKC normalization first to collapse Unicode compatibility
    characters (e.g. fullwidth Latin letters). Note: NFKC does NOT collapse
    confusable characters across scripts (e.g. Cyrillic 'a' -> Latin 'a').
    Homoglyph attacks on credential prefixes are out of scope for this
    secondary safety net. Primary defence: never place raw credentials in
    loggable fields (see module docstring).
    """
    value = unicodedata.normalize("NFKC", value)
    for pattern in _CREDENTIAL_PATTERNS:
        # Skip JWT regex on strings that cannot possibly contain a JWT
        # (no "ey" prefix or fewer than 2 dots). This avoids O(n^2)
        # backtracking in CPython's re engine on long dot-free base64
        # and prevents slow linear scans on URL-bearing strings with
        # exactly two dots.
        if pattern is _JWT_PATTERN and ("ey" not in value or value.count(".") < 2):
            continue
        value = pattern.sub(_REDACTED, value)
    return value


def _remove_runs(text: str) -> str:
    """Remove every run of removed characters; one between a word and a key becomes ``_SEPARATOR``.

    Removed, a run between an ASCII letter, digit or ``_`` and a key
    (``a<SHY>sk-...``) would glue the two together, so the key would no longer
    start at a token start and would show in full (GH-270 decision 2). The key
    is looked up in the text with every run removed (the joined text), so
    removed characters inside its prefix or body (``a<SHY>s<SHY>k-...``) don't
    hide it. Any other run just goes, so a credential split by one is joined
    and redacted whole (GH-264 L-2).

    A run inside a key joins too (decision 9): criterion 2, a key split inside
    its body is redacted whole, wins over criterion 1. When a key match on the
    joined text starts before the run and reaches at least the end of the
    whole key after it, ``sk-proj-ab<SHY>sk-<20 or more>`` is one key, not
    ``sk-proj-ab`` and a key. When that match stops inside the key after the
    run (``hf_<34><SHY>sk-<20>``: an ``hf_`` body has no ``-``), joining would
    show the rest of that key, so the run separates.

    Linear: one split, one bounded check per run, and the key matches on the
    joined text read once, lazily, by a pointer that only moves forward.
    """
    pieces = _REMOVED_RUN.split(text)
    if len(pieces) == 1:
        return text
    cleaned = "".join(pieces)
    # finditer's matches don't overlap, and a key that starts inside one ends
    # inside it too: only a "-" in a body makes a token start there, only the
    # widest class holds one, and the key starting there has no wider class.
    # So the last match that starts before the run is the only one that can
    # span it. None starts at the run: a word character precedes it.
    keys = _KEY_RULE.finditer(cleaned)
    spanning: re.Match[str] | None = None
    following: re.Match[str] | None = None
    kept = [pieces[0]]
    position = len(pieces[0])
    for piece in pieces[1:]:
        inner = _KEY_AFTER_WORD.match(cleaned, position)
        if inner is not None:
            while (following := following or next(keys, None)) and following.start() < position:
                spanning, following = following, None
            # The key after the run ends within the spanning match (which then
            # spans the run) when its minimum fits and the character right after
            # the match doesn't continue it. That one character decides because
            # the body classes nest: a wider key class holds every body character
            # of the match, a narrower one can't hold the character the match
            # stopped at. One check, not a scan of the key's unbounded body, so
            # many runs inside one long key stay linear. Every alternative of
            # _KEY_AFTER_WORD is a group, so a match always sets lastindex.
            body_char = _KEY_BODY_CHAR[cast("int", inner.lastindex) - 1]
            joins = (
                spanning is not None
                and inner.end() <= spanning.end()
                and body_char.match(cleaned, spanning.end()) is None
            )
            if not joins:
                kept.append(_SEPARATOR)
        kept.append(piece)
        position += len(piece)
    return "".join(kept)


def sanitize_display_text(value: str) -> str:
    """Remove invisible characters and redact credentials in text shown to users.

    The live chat reply (``ChatResponse.response``) and a stored message
    (``ChatMessageView.content``) go through this same function, so a chat
    reads the same live and reloaded. Public because chat titles
    (``chat_titles``) are redacted and cleaned exactly like a stored message.

    NFKC first, so a fullwidth letter or a fullwidth ``sk-`` counts in the
    separator check; then every control, format, surrogate and
    line/paragraph separator character but tab, LF and CR is removed
    (``_remove_runs``), and the credential rules run. A run of them right
    before a key leaves nothing: ``a<ZWSP>sk-...`` gives
    ``a[CREDENTIAL_REDACTED]``.
    """
    text = _remove_runs(unicodedata.normalize("NFKC", value))
    return _strip_credentials(text).replace(_SEPARATOR, "")


def normalize_display_text(value: str) -> str:
    """Return ``value`` as text shown to users reads it before credential redaction.

    NFKC, then every removed character (``sanitize_display_text``'s set) taken
    out; no credential rule runs, so the result is NOT safe to show. Public
    because the live stream (``admino.streaming``) reads how a word displays to
    decide whether the ``Bearer`` rule could reach past it.
    """
    return _REMOVED_RUN.sub("", unicodedata.normalize("NFKC", value))


# The deepest tool-argument value kept (GH-270 decision 5): ``args[k]`` is at
# depth 1, and the items of a container at depth d are at depth d + 1.
_ARGS_MAX_DEPTH: Final = 8


def _redact_arg(value: object, depth: int) -> object:
    """Redact one tool-argument value found at ``depth`` (the args object itself is 0).

    Every string goes through the credential rules only (invisible characters
    are kept): dict keys, dict values and list items. A tuple becomes a list.
    A value deeper than ``_ARGS_MAX_DEPTH`` becomes ``_SANITIZED_PLACEHOLDER``
    unread, so the recursion stops at depth 9 whatever the nesting, on a cycle
    too (no ``RecursionError``). There is no visited set: a wide cyclic or
    shared structure would cost its width to the 8th power, but args are
    always decoded JSON, which is acyclic and shares nothing.
    """
    if depth > _ARGS_MAX_DEPTH:
        return _SANITIZED_PLACEHOLDER
    if isinstance(value, dict):
        # A dict's keys sit at its own depth. Two keys that redact to the same
        # text: the later one wins.
        return {_redact_leaf(key): _redact_arg(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_redact_arg(item, depth + 1) for item in value]
    return _redact_leaf(value)


def _redact_leaf(value: object) -> object:
    """A string redacted, None or an exact bool, int or float kept, else the placeholder.

    Any other type (bytes, a set, an object, a tuple used as a dict key) could
    hold a key that no rule reads, so it is never shown (fail closed). That
    includes every subclass of bool, int or float, an ``IntEnum`` member too
    (GH-270 decision 11 (b)): its own ``__str__`` or ``__repr__`` could print
    a key into a dump, and pydantic-core writes a non-str dict key with
    ``str()``.
    """
    if isinstance(value, str):
        return _strip_credentials(value)
    if value is None or type(value) in (bool, int, float):
        return value
    return _SANITIZED_PLACEHOLDER


# ---------------------------------------------------------------------------
# API request/response models (server.py imports these)
# ---------------------------------------------------------------------------


LLMErrorCode = Literal[
    "not_configured",
    "missing_model",
    "provider_unavailable",
    "rate_limited",
    "timeout",
    "residency_blocked",
    "context_too_long",
    "malformed_response",
]
"""Stable code of a user-facing LLM failure (GH-242); the UI shows its translation."""

LLM_ERROR_CODES: Final[frozenset[str]] = frozenset(get_args(LLMErrorCode))


class ChatMessage(BaseModel):
    """A single message in a conversation history.

    Note: content is NOT sanitised for control characters here. Sanitisation
    occurs at the display boundary (server.py SSE rendering). This model is used in conversation
    history and must preserve the original content for LLM context fidelity.
    """

    role: Literal["user", "assistant", "system"] = Field(
        description="The role of the message sender.",
    )
    content: str = Field(
        max_length=32768,
        description=(
            "The message content. Empty strings are allowed for"
            " assistant messages with tool-call-only responses."
        ),
    )

    @field_validator("content")
    @classmethod
    def strip_null_bytes(cls, v: str) -> str:
        """Remove null bytes which can cause silent truncation in C-based parsers."""
        return v.replace("\x00", "")


class ChatRequest(BaseModel):
    """Incoming POST /chat request body.

    Validated on receipt by the ASGI server before any processing. Unknown
    fields (e.g. a smuggled ``org_id`` or ``user_id``) are refused with a 422:
    whose chat it is comes from the session only (GH-163). A blank message
    is valid here and kept as given; the route refuses it (GH-286).
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    message: str = Field(
        max_length=32768,
        description="The user's message text.",
    )
    session_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Session identifier. Alphanumeric, hyphens, and underscores only.",
    )


class ToolCallRecord(BaseModel):
    """Summary of a tool call included in a chat response.

    The ``args`` dict is sanitized via ``_sanitize_args`` to strip known
    credential patterns from every string at every depth (dict keys
    included, ``_ARGS_MAX_DEPTH`` levels) before the record reaches the API
    layer or any log sink.
    """

    tool: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="The tool name.",
    )
    action: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="The action name.",
    )
    # Any is justified here: tool call arguments are arbitrary JSON objects
    # whose schema varies per tool. Values are sanitized by _sanitize_args.
    args: dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized tool call arguments for UI display.",
    )
    permission: Literal["allow", "confirm", "deny", "disabled"] = Field(
        description="The permission decision for this tool call.",
    )
    success: bool = Field(
        description="Whether the tool call executed successfully.",
    )
    duration_ms: int | None = Field(
        default=None,
        ge=0,
        description="Execution duration in milliseconds, if available.",
    )

    @field_validator("args", mode="before")
    @classmethod
    def _sanitize_args(cls, v: object) -> object:
        """Redact credentials at every depth; a non-dict is redacted, then refused."""
        return _redact_arg(v, 0)


class PendingConfirmationSummary(BaseModel):
    """Subset of ``PendingConfirmation`` safe to expose over the HTTP API.

    Excludes the internal session_id. Includes sanitized tool arguments so
    the PWA can display call details (e.g. ``query``, ``max_results``) in the
    confirmation card. The PWA also needs the confirmation ID (to POST
    /api/confirm), the tool/action being confirmed, and the expiry so it
    can show a countdown.
    """

    confirmation_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Pending confirmation identifier.",
    )
    tool: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="The tool name awaiting confirmation.",
    )
    action: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="The action name awaiting confirmation.",
    )
    # Any is justified here: tool call arguments are arbitrary JSON objects
    # whose schema varies per tool. Values are sanitized by _sanitize_args.
    args: dict[str, Any] = Field(
        default_factory=dict,
        description="Tool call arguments for display in the confirmation card.",
    )
    expires_at: datetime = Field(
        description="UTC timestamp after which this confirmation is auto-denied.",
    )

    @field_validator("args", mode="before")
    @classmethod
    def _sanitize_args(cls, v: object) -> object:
        """Redact credentials at every depth; a non-dict is redacted, then refused."""
        return _redact_arg(v, 0)


class ContextUsage(BaseModel):
    """How full the chat's context is as its next turn starts (GH-190): token counts only.

    ``used`` adds up the instructions, the chat's active attachments, the
    stored history the budget keeps and the reserved output; ``max`` is the
    token budget of one LLM call. ``percent`` goes above 100 only when the
    attachments alone don't fit.
    """

    model_config = ConfigDict(extra="forbid")

    used: int = Field(ge=0, description="Estimated tokens the chat's next turn starts with.")
    max: int = Field(
        ge=1,
        description="The token budget of one LLM call: the model's input limit minus the margin.",
    )
    percent: int = Field(ge=0, description="used * 100 // max, rounded down.")


class ContextNotice(BaseModel):
    """Earlier turns the run's last LLM call left out to fit the budget (GH-190): counts only."""

    model_config = ConfigDict(extra="forbid")

    dropped_turns: int = Field(ge=1, description="Earlier turns left out, oldest first.")
    dropped_messages: int = Field(ge=1, description="The messages of those turns.")


class ChatResponse(BaseModel):
    """Response body of a chat turn and of a confirmation (GH-176: names its chat).

    ``chat_id`` is the persisted chat the turn ran in. ``session_id`` is the
    legacy session id, echoed by the legacy routes only (None on the chat
    route) until #177.
    """

    chat_id: UUID = Field(description="The persisted chat this turn ran in.")
    session_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="The legacy session identifier, echoed by the legacy routes (until #177).",
    )

    @field_validator("session_id")
    @classmethod
    def redact_credentials_in_session_id(cls, v: str | None) -> str | None:
        """Defence-in-depth: strip credentials from session_id."""
        return None if v is None else _strip_credentials(v)

    response: str = Field(
        max_length=65536,
        description="The assistant's text response.",
    )

    @field_validator("response")
    @classmethod
    def sanitize_response(cls, v: str) -> str:
        """Strip control characters and credentials from assistant response.

        Prevents XSS via LLM output containing script tags or Unicode
        direction-override characters. This is defence-in-depth — the PWA
        must also use textContent (not innerHTML) when rendering responses.
        """
        return sanitize_display_text(v)

    tool_calls: list[ToolCallRecord] = Field(
        default_factory=list,
        max_length=50,
        description="Summary of tool calls made during this response.",
    )

    status: Literal["final", "awaiting_confirmation", "limit_reached", "error"] = Field(
        default="final",
        description=(
            "Terminal status of this agent run. When 'awaiting_confirmation', "
            "``pending_confirmation`` describes the action the user must "
            "approve or deny via POST /api/confirm/{confirmation_id}."
        ),
    )

    pending_confirmation: PendingConfirmationSummary | None = Field(
        default=None,
        description=(
            "Present only when ``status='awaiting_confirmation'``. Carries the "
            "information the PWA needs to render a confirmation card and call "
            "POST /api/confirm/{confirmation_id}. Deliberately excludes tool "
            "arguments — those may contain secrets or large content and are "
            "already summarised in ``tool_calls``."
        ),
    )

    # One flattened Literal (the same type as ``LLMErrorCode | Literal["rate_limit"]``):
    # a union of two Literals would report one validation error per member.
    error_code: Literal[LLMErrorCode, "rate_limit"] | None = Field(
        default=None,
        description=(
            "The error code when ``status='error'``: the PWA shows its"
            " translation. One of the run's LLM error codes (GH-242), or"
            " ``rate_limit`` (GH-24) when too many confirmations are pending,"
            " so the confirmation this run asked for was denied. None on"
            " success and for uncoded errors."
        ),
    )

    context_usage: ContextUsage = Field(
        description="How full the chat's context is as its next turn starts (GH-190).",
    )
    context_notice: ContextNotice | None = Field(
        default=None,
        description=(
            "Set when the run's last LLM call left earlier turns out to fit the"
            " token budget (GH-190); null otherwise."
        ),
    )


class ConfirmRequest(BaseModel):
    """Incoming POST /confirm request body.

    Used when the user approves or denies a pending confirmation. The chat is
    named by ``chat_id`` (GH-176) or by the legacy ``session_id`` (until
    #177): exactly one of the two. Unknown fields (e.g. a smuggled ``org_id``
    or ``user_id``) are refused with a 422: whose confirmation it is comes
    from the session only (GH-163).
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    chat_id: UUID | None = Field(default=None, description="The persisted chat (GH-176).")
    session_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Legacy session identifier (until #177).",
    )
    confirmation_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Pending confirmation identifier. Alphanumeric, hyphens, underscores only.",
    )
    approved: bool = Field(
        description="Whether the user approved (True) or denied (False) the action.",
    )

    @model_validator(mode="after")
    def _check_one_chat_reference(self) -> ConfirmRequest:
        """Refuse a body naming both a chat_id and a session_id, or neither."""
        if (self.chat_id is None) == (self.session_id is None):
            msg = "Give exactly one of chat_id and session_id."
            raise ValueError(msg)
        return self


class SSEEvent(BaseModel):
    """Server-sent event envelope for streaming responses."""

    event: str = Field(
        max_length=64,
        pattern=r"^[a-zA-Z0-9_.:-]+$",
        description="SSE event type. No newlines — prevents SSE frame injection.",
    )
    data: str = Field(
        max_length=65536,
        description="The JSON-encoded event payload.",
    )

    @field_validator("data")
    @classmethod
    def sanitize_sse_data(cls, v: str) -> str:
        """Encode bare newlines to prevent SSE frame injection.

        SSE uses '\\n\\n' as a frame delimiter. Literal newlines in data
        would inject synthetic SSE frames. This validator replaces them with
        the two-character literal sequence backslash-n.

        Contract: callers write ev.data directly into SSE 'data:' lines
        (one data: prefix per logical line). The sanitised value is safe for
        raw text insertion. If callers JSON-encode ev.data first, the backslash
        is further escaped by JSON serialisation -- consumers must decode JSON
        before interpreting newlines.

        Pre-existing literal backslash-n sequences in input are preserved
        unchanged (they are not real newlines and pose no injection risk).

        Control characters are stripped first via _CONTROL_CHAR_TABLE to prevent
        U+0085 NEL and U+2028/U+2029 line/paragraph separators from bypassing
        the newline sanitisation (they are removed before newline replacement).
        """
        v = v.translate(_CONTROL_CHAR_TABLE)
        return v.replace("\r\n", "\\n").replace("\r", "\\n").replace("\n", "\\n")


# ---------------------------------------------------------------------------
# Agent / LLM models (agent.py and llm.py import these)
# ---------------------------------------------------------------------------


class ToolCall(BaseModel):
    """A tool call requested by the LLM.

    The args field uses dict[str, Any] because LLM output is untyped JSON.
    Individual tool executors validate args against their own Pydantic schemas
    before execution, so type safety is enforced at the tool boundary.
    """

    tool: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="Tool name — lowercase alphanumeric and underscores only (e.g. 'gmail').",
    )
    action: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="Action name — lowercase alphanumeric and underscores only (e.g. 'read').",
    )
    # Any is justified here: LLM tool-call arguments are arbitrary JSON objects.
    # Each tool validates its own args via a dedicated Pydantic model before execution.
    args: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw arguments from the LLM. Validated by individual tool schemas.",
    )
    tool_call_id: str | None = Field(
        default=None,
        max_length=128,
        description=(
            "Provider-assigned ID linking this tool call to its result. "
            "Required by Anthropic (tool_use id) and OpenAI (tool_calls[].id) "
            "for multi-turn tool calling."
        ),
    )

    @field_validator("args")
    @classmethod
    def limit_args_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Reject args payloads exceeding 64 KiB to prevent memory abuse."""
        import json

        if len(json.dumps(v, default=str)) > 65536:
            msg = "args payload exceeds 64 KiB limit"
            raise ValueError(msg)
        return v


class TextContent(BaseModel):
    """A text part of a user message's content (GH-189).

    Never blank: a text whose ``text.strip() == ""`` is refused, so no
    provider is ever sent a whitespace-only text block. The text is kept
    verbatim and isn't capped (attachments go in full).
    """

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    type: Literal["text"] = "text"
    text: str

    @field_validator("text")
    @classmethod
    def _check_not_blank(cls, value: str) -> str:
        """Refuse a whitespace-only text (the error never repeats it)."""
        if not value.strip():
            msg = "Text content must not be blank."
            raise ValueError(msg)
        return value


class ImageContent(BaseModel):
    """An image part of a user message's content (GH-189).

    ``media_type`` is JPEG or PNG, the attachment converters' output types;
    ``data`` is the image's standard base64, without a ``data:`` prefix.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    type: Literal["image"] = "image"
    media_type: Literal["image/jpeg", "image/png"]
    data: str = Field(min_length=1, pattern=r"^[A-Za-z0-9+/]+={0,2}$")


ContentPart = Annotated[TextContent | ImageContent, Field(discriminator="type")]
"""One part of a user message's content list, told apart by its ``type``."""


class LLMMessage(BaseModel):
    """A message in the LLM context window.

    Represents messages sent to and received from the LLM provider's chat API.
    ``content`` is a str, or on a user message a non-empty list of content
    parts (GH-189: slot 4's attachment blocks and images, then the user's
    text). Content parts exist only in the context built for one LLM call:
    they are never stored, logged or returned by an API.

    Note: content is NOT sanitised for control characters at this layer.
    Sanitisation is applied at the LLM client boundary (llm.py
    _strip_control_chars). Raw content is preserved here for context-window fidelity.
    """

    # A content list carries file content: validation errors never repeat it.
    model_config = ConfigDict(hide_input_in_errors=True)

    role: Literal["user", "assistant", "system", "tool"] = Field(
        description="The role of the message in the LLM context.",
    )
    content: (
        Annotated[str, Field(max_length=65536)] | Annotated[list[ContentPart], Field(min_length=1)]
    ) = Field(
        description=(
            "The message content: a str (empty strings are valid for tool responses with "
            "empty results), or on a user message a non-empty list of content parts."
        ),
    )
    tool_call_id: str | None = Field(
        default=None,
        max_length=128,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Identifier linking a tool response to its originating call.",
    )
    tool_use_blocks: list[dict[str, Any]] | None = Field(
        default=None,
        description=(
            "Structured tool_use blocks for providers that require them in the assistant "
            "message (e.g. Anthropic). Each entry has type, id, name (dot notation), "
            "and input. The OpenAI-compatible serializer replays them as tool_calls."
        ),
    )

    @model_validator(mode="after")
    def _check_parts_on_user_only(self) -> LLMMessage:
        """Refuse a content list on a system, assistant or tool message.

        Every provider takes images in user messages only, and file content
        must never get the system message's authority.
        """
        if isinstance(self.content, list) and self.role != "user":
            msg = "Only user messages may carry content parts."
            raise ValueError(msg)
        return self


class AgentConfig(BaseModel):
    """Runtime configuration for the agent loop.

    Separate from AppConfig (which covers the full application). AgentConfig
    controls agent-specific behavior limits. Its bounds hold every stored
    platform limit (GH-160), so a run's config can be built from them.
    """

    max_tool_calls: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum tool calls the agent may make per user message.",
    )
    max_context_messages: int = Field(
        default=40,
        ge=0,
        le=200,
        description=(
            "Optional cap on the conversation messages sent as LLM context, applied"
            " before the token budget; 0 means no cap (GH-190). The system prompt"
            " and the current user message are always sent."
        ),
    )
    confirmation_timeout_s: float = Field(
        default=30.0,
        ge=1.0,
        le=3600.0,
        description="Seconds before an unconfirmed action is automatically denied.",
    )
    llm_max_retries: int = Field(
        default=0,
        ge=0,
        le=5,
        description=(
            "Retries of a transient LLM failure per call (GH-242: the stored"
            " platform llm.max_retries)."
        ),
    )
    image_input: bool = Field(
        default=True,
        description=(
            "Whether the run's model accepts image input (GH-189: the stored platform"
            " llm.image_input). False: no image part reaches the LLM."
        ),
    )
    max_input_tokens: int = Field(
        default=200_000,
        ge=1000,
        le=2_000_000,
        description=(
            "The most input tokens the run's model accepts (GH-190: the stored"
            " platform llm.max_input_tokens)."
        ),
    )
    reserved_output_tokens: int = Field(
        default=4096,
        ge=1,
        le=65536,
        description="Tokens every LLM call keeps free for the reply (llm.max_response_tokens).",
    )
    context_margin_percent: int = Field(
        default=10,
        ge=0,
        le=50,
        description=(
            "The share of max_input_tokens kept back as a safety margin, in percent"
            " (context.safety_margin_percent)."
        ),
    )
    max_tool_result_tokens: int = Field(
        default=8000,
        ge=256,
        le=100_000,
        description=(
            "A longer tool result is cut to this many tokens, with a marker"
            " (context.max_tool_result_tokens)."
        ),
    )


class PendingConfirmation(BaseModel):
    """A tool call awaiting user confirmation.

    Created when the permission engine returns 'confirm' for a tool call.
    The user must approve or deny before expires_at.
    """

    confirmation_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Unique identifier for this pending confirmation.",
    )
    session_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Session in which this confirmation was requested.",
    )
    tool_call: ToolCall = Field(
        description="The tool call awaiting confirmation.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of when the confirmation was created.",
    )
    expires_at: datetime = Field(
        description="UTC timestamp after which the confirmation is auto-denied.",
    )

    @model_validator(mode="after")
    def validate_expiry(self) -> PendingConfirmation:
        """Ensure expires_at is timezone-aware and after created_at."""
        if self.expires_at.tzinfo is None:
            msg = "expires_at must be timezone-aware"
            raise ValueError(msg)
        if self.expires_at <= self.created_at:
            msg = "expires_at must be after created_at"
            raise ValueError(msg)
        return self


AgentStatus = Literal["final", "awaiting_confirmation", "limit_reached", "error", "stopped"]
"""Terminal status of an agent run.

- ``final``: the LLM produced a plain text response; history contains it.
- ``awaiting_confirmation``: a tool call requires user confirmation; the caller
  must resume by calling ``Agent.run`` again with ``pending_confirmation`` set.
- ``limit_reached``: the agent exhausted ``AgentConfig.max_tool_calls`` without
  producing a final text response.
- ``error``: an upstream error (e.g. LLM client failure) prevented completion;
  ``response`` contains a safe human-readable message, never raw exception data.
- ``stopped`` (GH-8): the user stopped a streamed run; ``response`` is the text
  the interrupted LLM call had forwarded (empty when none).
"""


class AgentResult(BaseModel):
    """Result of a single ``Agent.run`` invocation.

    The caller owns conversation history: the agent returns the full updated
    ``history`` (user turn + any assistant/tool turns added during the run) so
    the caller can persist it. It never contains ``system`` messages — the
    agent adds its system prompt to each LLM call itself, so feeding the
    history back cannot duplicate it. ``tool_calls`` is a summary for the HTTP
    response layer; the authoritative, content-free record of each dispatch is
    its ``tool.call`` audit event.
    """

    status: AgentStatus = Field(
        description="Terminal status of the agent run.",
    )
    response: str = Field(
        default="",
        max_length=65536,
        description=(
            "Assistant text to surface to the user. Empty when the agent"
            " terminates without producing text (should not happen in"
            " practice — always populated with a terminal message)."
        ),
    )
    history: list[LLMMessage] = Field(
        default_factory=list,
        max_length=1000,
        description=(
            "Updated conversation history including this turn's additions."
            " User/assistant/tool messages only; excludes the system prompt."
        ),
    )
    tool_calls: list[ToolCallRecord] = Field(
        default_factory=list,
        max_length=50,
        description="Summary of tool calls dispatched during this run.",
    )
    pending_confirmation: PendingConfirmation | None = Field(
        default=None,
        description=(
            "Set when ``status == 'awaiting_confirmation'``. The caller must"
            " persist this and pass it back on the resumption call."
        ),
    )
    error_code: LLMErrorCode | None = Field(
        default=None,
        description=(
            "Set when ``status == 'error'`` and the failure is a coded LLM error"
            " (GH-242); None for any other outcome."
        ),
    )
    truncated: bool = Field(
        default=False,
        description=(
            "True when the run ends ``final`` with an answer the LLM output cap (or"
            " the 65536-character content cap) cut: ``response`` then ends at its"
            " last complete word (GH-25). False for every other outcome."
        ),
    )
    context_notice: ContextNotice | None = Field(
        default=None,
        description=(
            "The earlier turns the run's last LLM call (made or refused) left out to"
            " fit the token budget (GH-190); None when it dropped none."
        ),
    )
    external_content: bool = Field(
        default=False,
        description=(
            "True when the run received external content (GH-190): attachments in its"
            " slot, earlier_external_content, a wrapped tool result in its history, or"
            " a dispatch whose full result was wrapped, judged before any cut. The"
            " chat's sticky external_content flag is stored from it."
        ),
    )


# ---------------------------------------------------------------------------
# Tool argument models (individual tools import these)
# ---------------------------------------------------------------------------


class MemoryStoreArgs(BaseModel):
    """Arguments for the memory.store action (upsert a key-value note)."""

    key: str = Field(
        max_length=200,
        pattern=r"^[a-zA-Z0-9_.\- ]+$",
        description="Unique key for the memory entry. Alphanumeric, dots, hyphens, underscores.",
    )
    value: str = Field(
        max_length=2000,
        description="The value to store.",
    )


class MemoryRecallArgs(BaseModel):
    """Arguments for the memory.recall action (retrieve a value by key)."""

    key: str = Field(
        max_length=200,
        pattern=r"^[a-zA-Z0-9_.\- ]+$",
        description="The key to look up. Alphanumeric, dots, hyphens, underscores.",
    )


class MemoryListArgs(BaseModel):
    """Arguments for the memory.list action (list all stored keys)."""


# ---------------------------------------------------------------------------
# Shared email validation helpers (used by GmailSendArgs, OutlookSendArgs)
# ---------------------------------------------------------------------------

_EMAIL_ADDRESS_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)


def _validate_email_list(v: list[str]) -> list[str]:
    """Validate each email address in a list.

    Rejects addresses with control characters, newlines, or missing @.
    Intentionally strict to prevent header injection.
    """
    for addr in v:
        if not isinstance(addr, str) or not _EMAIL_ADDRESS_RE.match(addr):
            msg = f"Invalid email address: {addr!r}"
            raise ValueError(msg)
    return v


def _reject_control_chars(v: str, field_name: str) -> str:
    """Reject strings containing CR, LF, or null bytes.

    Defence-in-depth against header injection and log spoofing. The email
    transport layer (stdlib EmailMessage for Gmail, JSON for Graph) also
    prevents injection, but we reject at the model boundary.
    """
    if "\r" in v or "\n" in v or "\x00" in v:
        msg = f"{field_name} must not contain CR, LF, or null bytes"
        raise ValueError(msg)
    return v


# ---------------------------------------------------------------------------
# Gmail tool argument models (tools/gmail.py imports these)
# ---------------------------------------------------------------------------


class GmailSearchArgs(BaseModel):
    """Arguments for the gmail.search action."""

    query: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[\x20-\x7E]+$",
        description="Gmail search query (printable ASCII only).",
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of messages to return.",
    )


class GmailReadArgs(BaseModel):
    """Arguments for the gmail.read action."""

    message_id: str = Field(
        pattern=r"^[a-zA-Z0-9]+$",
        max_length=64,
        description="Gmail message ID.",
    )


class GmailListArgs(BaseModel):
    """Arguments for the gmail.list action."""

    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of messages to return.",
    )


class GmailSendArgs(BaseModel):
    """Arguments for the gmail.send action (requires promotion + confirm).

    Email addresses are validated with a basic pattern that rejects obvious
    injection attempts (newlines, control chars). The stdlib ``email`` module
    handles RFC 2822 encoding safely.
    """

    to: list[str] = Field(
        min_length=1,
        max_length=20,
        description="Recipient email addresses (1-20).",
    )
    subject: str = Field(
        default="",
        max_length=500,
        description="Email subject line.",
    )
    body: str = Field(
        max_length=50_000,
        description="Plain-text email body (max 50 000 chars).",
    )
    cc: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="CC recipients (optional, max 20).",
    )
    bcc: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="BCC recipients (optional, max 20).",
    )

    @field_validator("to", "cc", "bcc", mode="before")
    @classmethod
    def _validate_email_addresses(cls, v: list[str]) -> list[str]:
        return _validate_email_list(v)

    @field_validator("subject", mode="after")
    @classmethod
    def _validate_subject(cls, v: str) -> str:
        return _reject_control_chars(v, "subject")

    @field_validator("body", mode="after")
    @classmethod
    def _validate_body(cls, v: str) -> str:
        return _reject_control_chars(v, "body")


# ---------------------------------------------------------------------------
# Google Calendar tool argument models (tools/google_calendar.py imports these)
# ---------------------------------------------------------------------------


class GoogleCalendarListArgs(BaseModel):
    """Arguments for the google_calendar.list action."""

    time_min: datetime = Field(
        description="Start of the time range (ISO 8601 UTC).",
    )
    time_max: datetime = Field(
        description="End of the time range (ISO 8601 UTC).",
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of events to return.",
    )


class GoogleCalendarReadArgs(BaseModel):
    """Arguments for the google_calendar.read action."""

    event_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[a-zA-Z0-9_]+$",
        description="Google Calendar event ID.",
    )


class GoogleCalendarCreateArgs(BaseModel):
    """Arguments for the google_calendar.create action (requires confirm)."""

    summary: str = Field(
        max_length=200,
        description="Event title.",
    )
    start: datetime = Field(
        description="Event start time (ISO 8601 UTC).",
    )
    end: datetime = Field(
        description="Event end time (ISO 8601 UTC).",
    )
    description: str = Field(
        default="",
        max_length=1000,
        description="Event description.",
    )
    location: str = Field(
        default="",
        max_length=200,
        description="Event location.",
    )


class GoogleCalendarUpdateArgs(BaseModel):
    """Arguments for the google_calendar.update action (tier-2, requires promotion + confirm).

    All fields except ``event_id`` are optional; only the provided fields are
    sent in the partial (PATCH) update. ``event_id`` is constrained to safe
    characters to prevent path traversal in the Calendar API URL, and attendee
    addresses are validated to reject injection.
    """

    event_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[a-zA-Z0-9_]+$",
        description="Google Calendar event ID to update.",
    )
    summary: str | None = Field(
        default=None,
        max_length=200,
        description="New event title.",
    )
    description: str | None = Field(
        default=None,
        max_length=1000,
        description="New event description.",
    )
    start: datetime | None = Field(
        default=None,
        description="New event start time (ISO 8601 UTC).",
    )
    end: datetime | None = Field(
        default=None,
        description="New event end time (ISO 8601 UTC).",
    )
    location: str | None = Field(
        default=None,
        max_length=200,
        description="New event location.",
    )
    attendees: list[str] | None = Field(
        default=None,
        max_length=50,
        description="Replacement attendee email addresses (max 50).",
    )

    @field_validator("attendees", mode="before")
    @classmethod
    def _validate_attendees(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return _validate_email_list(v)


# ---------------------------------------------------------------------------
# Google Drive tool argument models (tools/google_drive.py imports these)
# ---------------------------------------------------------------------------


class GoogleDriveListArgs(BaseModel):
    """Arguments for the google_drive.list action."""

    # SECURITY: The pattern MUST exclude single quotes — folder_id is interpolated
    # into a Drive API q= query string in google_drive.py google_drive_list().
    folder_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        pattern=r"^[a-zA-Z0-9_\-]+$",
        description="Folder ID to list. None = root. Only alphanumeric, hyphens, underscores.",
    )
    max_results: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of files to return.",
    )


class GoogleDriveReadArgs(BaseModel):
    """Arguments for the google_drive.read action."""

    file_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[a-zA-Z0-9_\-]+$",
        description="Google Drive file ID.",
    )


class GoogleDriveSearchArgs(BaseModel):
    """Arguments for the google_drive.search action."""

    query: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[^'\\]+$",
        description="Search query for Google Drive files. No quotes or backslashes.",
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of results to return.",
    )


# ---------------------------------------------------------------------------
# Outlook (Microsoft Graph) tool argument models (tools/outlook.py imports these)
# ---------------------------------------------------------------------------


class OutlookSearchArgs(BaseModel):
    """Arguments for the outlook.search action."""

    query: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[a-zA-Z0-9 ._@\-]+$",
        description="Search query for Outlook messages. Alphanumeric, spaces, dots, @, hyphens.",
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of messages to return.",
    )


# ---------------------------------------------------------------------------
# Microsoft Graph resource ID validation
# ---------------------------------------------------------------------------
# Graph message/drive-item IDs are base64/base64url and contain '=', '+', '/';
# OneDrive *personal* item IDs may also contain '!'. These IDs are URL-encoded
# with quote(safe="") before being interpolated into the Graph request path
# (see outlook.py / onedrive.py), so the characters cannot alter the URL path.
# The bounded, anchored patterns below are defense-in-depth; the length cap
# matches the calendar event-ID cap since Graph IDs can exceed 200 chars. The
# first character is restricted to a non-slash so a value cannot begin with '/'
# (real Graph IDs never do); '.' is excluded entirely to block '..' sequences.
_GRAPH_ID_MAX_LEN: Final[int] = 512
_GRAPH_MESSAGE_ID_PATTERN: Final[str] = r"^[A-Za-z0-9_\-][A-Za-z0-9_\-=+/]*$"
_GRAPH_ITEM_ID_PATTERN: Final[str] = r"^[A-Za-z0-9_\-!][A-Za-z0-9_\-=+/!]*$"


class OutlookReadArgs(BaseModel):
    """Arguments for the outlook.read action."""

    message_id: str = Field(
        min_length=1,
        max_length=_GRAPH_ID_MAX_LEN,
        pattern=_GRAPH_MESSAGE_ID_PATTERN,
        description="Outlook message ID.",
    )


class OutlookListArgs(BaseModel):
    """Arguments for the outlook.list action."""

    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of messages to return.",
    )


class OutlookSendArgs(BaseModel):
    """Arguments for the outlook.send action (requires promotion + confirm).

    Email addresses are validated with a basic pattern that rejects obvious
    injection attempts (newlines, control chars). The JSON payload structure
    of Microsoft Graph prevents header injection by design.
    """

    to: list[str] = Field(
        min_length=1,
        max_length=20,
        description="Recipient email addresses (1-20).",
    )
    subject: str = Field(
        default="",
        max_length=500,
        description="Email subject line.",
    )
    body: str = Field(
        max_length=50_000,
        description="Plain-text email body (max 50 000 chars).",
    )
    cc: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="CC recipients (optional, max 20).",
    )
    bcc: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="BCC recipients (optional, max 20).",
    )

    @field_validator("to", "cc", "bcc", mode="before")
    @classmethod
    def _validate_email_addresses(cls, v: list[str]) -> list[str]:
        return _validate_email_list(v)

    @field_validator("subject", mode="after")
    @classmethod
    def _validate_subject(cls, v: str) -> str:
        return _reject_control_chars(v, "subject")

    @field_validator("body", mode="after")
    @classmethod
    def _validate_body(cls, v: str) -> str:
        return _reject_control_chars(v, "body")


# ---------------------------------------------------------------------------
# Outlook Calendar (Microsoft Graph) tool argument models
# ---------------------------------------------------------------------------


class OutlookCalendarListArgs(BaseModel):
    """Arguments for the outlook_calendar.list action."""

    time_min: datetime = Field(
        description="Start of the time range (ISO 8601 UTC).",
    )
    time_max: datetime = Field(
        description="End of the time range (ISO 8601 UTC).",
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of events to return.",
    )


# Microsoft Graph event IDs are base64 strings that legitimately contain
# '=', '/', and '+' (as well as '-' and '_'). They are interpolated into the
# Graph REST path, so the tool handlers URL-encode them (urllib.parse.quote,
# safe="") before use — that encoding, not this charset, is the path-traversal
# defence. This pattern is a permissive allow-list that still rejects
# whitespace, control characters, '.', and other unexpected input. The length
# cap is generous because recurring-instance / immutable IDs can be long.
_GRAPH_EVENT_ID_PATTERN: Final[str] = r"^[A-Za-z0-9_\-=+/]+$"
_GRAPH_EVENT_ID_MAX_LEN: Final[int] = 512


class OutlookCalendarReadArgs(BaseModel):
    """Arguments for the outlook_calendar.read action."""

    event_id: str = Field(
        min_length=1,
        max_length=_GRAPH_EVENT_ID_MAX_LEN,
        pattern=_GRAPH_EVENT_ID_PATTERN,
        description="Outlook Calendar event ID.",
    )


class OutlookCalendarCreateArgs(BaseModel):
    """Arguments for the outlook_calendar.create action (requires confirm)."""

    subject: str = Field(
        max_length=200,
        description="Event subject.",
    )
    start: datetime = Field(
        description="Event start time (ISO 8601 UTC).",
    )
    end: datetime = Field(
        description="Event end time (ISO 8601 UTC).",
    )
    body: str = Field(
        default="",
        max_length=1000,
        description="Event body/description.",
    )
    location: str = Field(
        default="",
        max_length=200,
        description="Event location.",
    )


class OutlookCalendarUpdateArgs(BaseModel):
    """Arguments for the outlook_calendar.update action (tier-2, requires promotion + confirm).

    All fields except ``event_id`` are optional; only the provided fields are
    sent in the partial (PATCH) update. ``event_id`` allows the Microsoft Graph
    base64 charset; the handler URL-encodes it to prevent path traversal in the
    Graph API URL, and attendee addresses are validated to reject injection.
    """

    event_id: str = Field(
        min_length=1,
        max_length=_GRAPH_EVENT_ID_MAX_LEN,
        pattern=_GRAPH_EVENT_ID_PATTERN,
        description="Outlook Calendar event ID to update.",
    )
    subject: str | None = Field(
        default=None,
        max_length=200,
        description="New event subject.",
    )
    body: str | None = Field(
        default=None,
        max_length=1000,
        description="New event body/description.",
    )
    start: datetime | None = Field(
        default=None,
        description="New event start time (ISO 8601 UTC).",
    )
    end: datetime | None = Field(
        default=None,
        description="New event end time (ISO 8601 UTC).",
    )
    location: str | None = Field(
        default=None,
        max_length=200,
        description="New event location.",
    )
    attendees: list[str] | None = Field(
        default=None,
        max_length=50,
        description="Replacement attendee email addresses (max 50).",
    )

    @field_validator("attendees", mode="before")
    @classmethod
    def _validate_attendees(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return _validate_email_list(v)


# ---------------------------------------------------------------------------
# OneDrive (Microsoft Graph) tool argument models (tools/onedrive.py imports these)
# ---------------------------------------------------------------------------


class OneDriveListArgs(BaseModel):
    """Arguments for the onedrive.list action."""

    folder_path: str | None = Field(
        default=None,
        min_length=1,
        max_length=500,
        pattern=r"^[a-zA-Z0-9 ._/\-]+$",
        description="Folder path to list. None = root. Only safe path chars allowed.",
    )
    max_results: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of items to return.",
    )


class OneDriveReadArgs(BaseModel):
    """Arguments for the onedrive.read action."""

    item_id: str = Field(
        min_length=1,
        max_length=_GRAPH_ID_MAX_LEN,
        pattern=_GRAPH_ITEM_ID_PATTERN,
        description="OneDrive item ID.",
    )


class OneDriveSearchArgs(BaseModel):
    """Arguments for the onedrive.search action."""

    query: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[^'\\]+$",
        description="Search query for OneDrive files. No quotes or backslashes.",
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of results to return.",
    )


# ---------------------------------------------------------------------------
# Settings API models: the user, org and platform scopes (GH-159)
# ---------------------------------------------------------------------------

# A model name: letters, digits, '_', '.', ':', '/' and '-', starting with a
# letter or digit, at most 200 characters. Always used with fullmatch (Python's
# '$' would accept a trailing newline). Migration 0013's CHECK on the
# platform_settings model columns is the same rule.
_MODEL_NAME_RE: Final[re.Pattern[str]] = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}")
_MODEL_NAME_ERROR: Final = "Model name contains invalid characters."
# GH-242: the platform model's max input tokens and the LLM retry limit (the
# CHECKs of migration 0022).
_MaxInputTokens = Annotated[int, Field(ge=1000, le=2_000_000)]
_LLMMaxRetries = Annotated[int, Field(ge=0, le=5)]


class SettingsLLM(BaseModel):
    """The platform LLM as GET/PATCH /api/platform/settings shows it (Super Admin).

    Credentials are never exposed: only ``*_configured`` boolean flags.
    """

    provider: Literal["infomaniak", "anthropic", "openai", "vllm"]
    anthropic_model: str = Field(max_length=200)
    openai_model: str = Field(max_length=200)
    infomaniak_model: str = Field(default="", max_length=200)
    # Model IDs the Infomaniak product lists (empty unless infomaniak is active
    # and reachable).
    infomaniak_available_models: list[str] = Field(default_factory=list)
    vllm_model: str = Field(default="", max_length=200)
    # Model IDs the local vLLM endpoint reports as served (empty if unreachable).
    vllm_available_models: list[str] = Field(default_factory=list)
    # GH-242: the active model's capabilities and the retry limit.
    max_input_tokens: _MaxInputTokens = 200_000
    image_input: bool = True
    max_retries: _LLMMaxRetries = 2
    # The number of orgs whose data residency is on: what a switch to a
    # non-Swiss provider affects (a count only).
    residency_orgs: int = Field(default=0, ge=0)
    # Boolean flags — never expose actual API key or token values.
    anthropic_key_configured: bool = False
    openai_key_configured: bool = False
    infomaniak_token_configured: bool = False

    @field_validator("anthropic_model", "openai_model", "infomaniak_model", "vllm_model")
    @classmethod
    def validate_model_name(cls, v: str) -> str:
        """Reject model names containing shell metacharacters or control chars.

        An empty string is allowed: a model that isn't set (NULL in
        ``platform_settings``) is shown blank.
        """
        if v and _MODEL_NAME_RE.fullmatch(v) is None:
            raise ValueError(_MODEL_NAME_ERROR)
        return v

    @field_validator("vllm_available_models", "infomaniak_available_models")
    @classmethod
    def filter_available_models(cls, v: list[str]) -> list[str]:
        """Drop served-model ids that are not well-formed model names.

        ``vllm_available_models`` is populated from the local vLLM server's
        ``/v1/models`` response and ``infomaniak_available_models`` from the
        Infomaniak models endpoint — input from outside admino's trust
        boundary. A rogue or compromised server (or a MITM on the non-TLS
        local vLLM connection) could return ids with unexpected characters.
        Keep only ids matching the same allowlist enforced on user-supplied
        model names, and bound the count, so a malicious server cannot spoof
        the settings response or smuggle characters past downstream sanitisers.
        """
        return [m for m in v if isinstance(m, str) and _MODEL_NAME_RE.fullmatch(m)][:64]


class SettingsAppearance(BaseModel):
    """Appearance settings (user scope)."""

    theme: Literal["light", "dark", "system"] = "light"


class SettingsNotifications(BaseModel):
    """Notification preferences (user scope).

    ``enabled``: the tool-approval pings (on by default). ``task_done``: the
    task-done pings (GH-35), off by default because switching them on asks the
    browser for notification permission. Neither is a master switch for the other.
    """

    enabled: bool = True
    task_done: bool = False


class OAuthAuthorizeResponse(BaseModel):
    """GET /api/oauth/google/authorize response — consent URL for the frontend."""

    url: str = Field(max_length=2048, pattern=r"^https://")


# The tools of the Google and Microsoft OAuth providers (their "services", GH-162).
ConnectorTool = Literal[
    "gmail", "google_calendar", "google_drive", "outlook", "outlook_calendar", "onedrive"
]

# Each OAuth provider's tools, in the order the connection status lists them.
PROVIDER_TOOLS: Final[MappingProxyType[str, tuple[ConnectorTool, ...]]] = MappingProxyType(
    {
        "google": ("gmail", "google_calendar", "google_drive"),
        "microsoft": ("outlook", "outlook_calendar", "onedrive"),
    }
)

# The tools an org's data residency policy switches off: every provider's tools
# (memory stays on: it never leaves the server).
RESIDENCY_BLOCKED_TOOLS: Final[frozenset[str]] = frozenset(
    tool for tools in PROVIDER_TOOLS.values() for tool in tools
)


class OAuthServiceStatus(BaseModel):
    """One service of an OAuth provider and the org's stored switch for it (GH-162)."""

    tool: ConnectorTool
    enabled: bool


class OAuthConnectionStatus(BaseModel):
    """The caller's own connection to an OAuth provider (GH-162: per user).

    ``connected`` means the caller has a token row for the provider.
    ``healthy`` means the stored refresh token is still believed valid (not
    flagged dead after a terminal refresh failure). The frontend treats
    ``connected and not healthy`` the same as "Not connected" — prompting a
    fresh Connect. ``data_residency`` is the caller's org's residency policy:
    connecting is refused and a stored connection is inactive. ``services``
    lists the provider's tools (``PROVIDER_TOOLS`` order), each with the
    org's stored switch.
    """

    connected: bool = False
    healthy: bool = False
    email: str | None = Field(
        default=None,
        max_length=254,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
    )
    data_residency: bool = False
    services: list[OAuthServiceStatus] = Field(default_factory=list)


class ToolsSettings(BaseModel):
    """Per-tool enabled/disabled state (the org scope's tool services).

    Each field corresponds to a registered tool name and maps to an
    ``org_settings.<tool>_enabled`` column. Default is True (enabled) for
    all tools, like the column defaults of migration 0013.

    strict=True: a non-boolean value (e.g. a ``"false"`` string) raises
    ``ValidationError`` instead of being silently coerced to ``True`` and
    re-enabling a service that was turned off (GH-80 security gate).

    Unknown keys are dropped, so a legacy ``files`` toggle (removed in
    GH-143) is never reported.
    """

    model_config = ConfigDict(strict=True)

    gmail: bool = True
    google_calendar: bool = True
    google_drive: bool = True
    outlook: bool = True
    outlook_calendar: bool = True
    onedrive: bool = True
    memory: bool = True


class SettingsPatchLLM(BaseModel):
    """Partial platform LLM settings for PATCH /api/platform/settings.

    Only the provider, the four model names and (GH-242) the active model's
    max input tokens, image input and the retry limit can be changed: every
    other key (an endpoint URL, a timeout, a key) is refused. A model name must
    fully match ``[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}``, the database CHECK of
    migration 0013 (so a trailing newline is refused here, not by the
    database). Validation errors never repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    provider: Literal["infomaniak", "anthropic", "openai", "vllm"] | None = None
    anthropic_model: str | None = Field(default=None, max_length=200)
    openai_model: str | None = Field(default=None, max_length=200)
    infomaniak_model: str | None = Field(default=None, max_length=200)
    vllm_model: str | None = Field(default=None, max_length=200)
    # GH-242: strict, so a bool, float or string is refused.
    max_input_tokens: Annotated[StrictInt, Field(ge=1000, le=2_000_000)] | None = None
    image_input: StrictBool | None = None
    max_retries: Annotated[StrictInt, Field(ge=0, le=5)] | None = None

    @field_validator("anthropic_model", "openai_model", "infomaniak_model", "vllm_model")
    @classmethod
    def validate_model_name(cls, v: str | None) -> str | None:
        """Refuse a model name that isn't a full match of the model-name rule.

        Runs after the type and length checks: a non-string or a name over 200
        characters is already a validation error. The message never includes
        the value.
        """
        if v is None:
            return v
        if not isinstance(v, str) or _MODEL_NAME_RE.fullmatch(v) is None:
            raise ValueError(_MODEL_NAME_ERROR)
        return v


class SettingsPatchAppearance(BaseModel):
    """Partial appearance settings for PATCH /api/me/settings."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    theme: Literal["light", "dark", "system"] | None = None


class SettingsPatchNotifications(BaseModel):
    """Partial notification settings for PATCH /api/me/settings (strict bools)."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    enabled: StrictBool | None = None
    task_done: StrictBool | None = None


class UserSettingsResponse(BaseModel):
    """GET/PATCH /api/me/settings response: the caller's own theme and notifications."""

    appearance: SettingsAppearance
    notifications: SettingsNotifications


class UserSettingsPatch(BaseModel):
    """PATCH /api/me/settings request body: the caller's theme and/or notifications.

    Another scope's key (llm, tools, limits), a language or a user id is
    refused, never ignored. A null counts as not given, and at least one value
    must be given. Validation errors never repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    appearance: SettingsPatchAppearance | None = None
    notifications: SettingsPatchNotifications | None = None

    @model_validator(mode="after")
    def _check_something_given(self) -> UserSettingsPatch:
        """Refuse a patch that changes nothing."""
        theme = None if self.appearance is None else self.appearance.theme
        notifications = self.notifications or SettingsPatchNotifications()
        if theme is None and notifications.enabled is None and notifications.task_done is None:
            msg = "Give at least one setting to change."
            raise ValueError(msg)
        return self


class OrgToolsPatch(BaseModel):
    """The tool services to switch on or off; a null (or a missing tool) is not given.

    The ``tools`` section of ``OrgSettingsPatch`` (GH-169). Strict bools only;
    an unknown tool (e.g. the removed ``files`` toggle) is refused, never
    ignored.
    """

    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    gmail: bool | None = None
    google_calendar: bool | None = None
    google_drive: bool | None = None
    outlook: bool | None = None
    outlook_calendar: bool | None = None
    onedrive: bool | None = None
    memory: bool | None = None


# The bounds of each platform default (GH-160), shared by its response and
# patch fields and mirrored by migration 0013's (limits) and 0014's CHECKs.
_ToolCallsPerMessage = Annotated[int, Field(ge=1, le=100)]
_PendingConfirmations = Annotated[int, Field(ge=1, le=50)]
_ConfirmationTimeoutS = Annotated[int, Field(ge=10, le=3600)]
_MessageLength = Annotated[int, Field(ge=1, le=100_000)]
# 0: no message cap, the token budget alone decides (GH-190, migration 0030).
_ContextMessages = Annotated[int, Field(ge=0, le=200)]
_FileSizeMb = Annotated[int, Field(ge=1, le=500)]
_FilesPerMessage = Annotated[int, Field(ge=1, le=50)]
_PagesPerFile = Annotated[int, Field(ge=1, le=1000)]
_RenderDpi = Annotated[int, Field(ge=72, le=300)]
_TrashDays = Annotated[int, Field(ge=0, le=90)]
_AuditMonths = Annotated[
    int,
    Field(ge=audit_events.MIN_RETENTION_MONTHS, le=audit_events.MAX_RETENTION_MONTHS),
]
_GraceDays = Annotated[int, Field(ge=7, le=90)]
_RequestsPerMinute = Annotated[int, Field(ge=1, le=600)]
_LockoutFailures = Annotated[int, Field(ge=3, le=100)]
_LockoutMinutes = Annotated[int, Field(ge=1, le=1440)]
_IdleTimeoutMinutes = Annotated[
    int,
    Field(ge=sessions.MIN_IDLE_TIMEOUT_MINUTES, le=sessions.MAX_IDLE_TIMEOUT_MINUTES),
]
_LifetimeHours = Annotated[
    int, Field(ge=sessions.MIN_LIFETIME_HOURS, le=sessions.MAX_LIFETIME_HOURS)
]
_TRASH_ORDER_ERROR: Final = "The trash retention minimum can't exceed the maximum."


class PlatformLimits(BaseModel):
    """The platform limits, with ``LimitsConfig``'s bounds (editable since GH-160)."""

    max_tool_calls_per_message: _ToolCallsPerMessage
    max_pending_confirmations: _PendingConfirmations
    confirmation_timeout_s: _ConfirmationTimeoutS
    max_message_length: _MessageLength
    max_context_messages: _ContextMessages


class PlatformFiles(BaseModel):
    """The platform file limits (GH-160): size in MB, files per message, pages, render DPI."""

    max_file_size_mb: _FileSizeMb = 50
    max_files_per_message: _FilesPerMessage = 10
    max_pages_per_file: _PagesPerFile = 100
    render_dpi: _RenderDpi = 150


class PlatformRetention(BaseModel):
    """The platform retention (GH-160): trash bounds in days, audit months, grace days.

    The trash minimum can't exceed the maximum; the message never repeats the
    values.
    """

    trash_min_days: _TrashDays = 0
    trash_max_days: _TrashDays = 90
    audit_months: _AuditMonths = audit_events.DEFAULT_RETENTION_MONTHS
    org_deletion_grace_days: _GraceDays = 30

    @model_validator(mode="after")
    def _check_trash_order(self) -> PlatformRetention:
        """Refuse a trash minimum above the trash maximum."""
        if self.trash_min_days > self.trash_max_days:
            raise ValueError(_TRASH_ORDER_ERROR)
        return self


class PlatformSecurity(BaseModel):
    """The platform security (GH-160): rate limit, login lockout, Super Admin sessions.

    The session bounds are ``admino.sessions``' (migration 0009's CHECKs).
    """

    rate_limit_per_minute: _RequestsPerMinute = 20
    lockout_after_failures: _LockoutFailures = 10
    lockout_window_minutes: _LockoutMinutes = 15
    lockout_minutes: _LockoutMinutes = 15
    session_idle_timeout_minutes: _IdleTimeoutMinutes = sessions.DEFAULT_IDLE_TIMEOUT_MINUTES
    session_max_lifetime_hours: _LifetimeHours = sessions.DEFAULT_LIFETIME_HOURS


class PlatformSettingsResponse(BaseModel):
    """GET/PATCH /api/platform/settings response (Super Admin): the five sections.

    No content and no secret: key presence flags only.
    """

    llm: SettingsLLM
    limits: PlatformLimits
    files: PlatformFiles
    retention: PlatformRetention
    security: PlatformSecurity


class PlatformLimitsPatch(BaseModel):
    """The platform limits to change: strict ints within the bounds, a null not given."""

    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    max_tool_calls_per_message: _ToolCallsPerMessage | None = None
    max_pending_confirmations: _PendingConfirmations | None = None
    confirmation_timeout_s: _ConfirmationTimeoutS | None = None
    max_message_length: _MessageLength | None = None
    max_context_messages: _ContextMessages | None = None


class PlatformFilesPatch(BaseModel):
    """The platform file limits to change: strict ints within the bounds, a null not given."""

    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    max_file_size_mb: _FileSizeMb | None = None
    max_files_per_message: _FilesPerMessage | None = None
    max_pages_per_file: _PagesPerFile | None = None
    render_dpi: _RenderDpi | None = None


class PlatformRetentionPatch(BaseModel):
    """The platform retention to change: strict ints within the bounds, a null not given.

    The trash order isn't checked here: the service checks the patch merged
    into the stored values.
    """

    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    trash_min_days: _TrashDays | None = None
    trash_max_days: _TrashDays | None = None
    audit_months: _AuditMonths | None = None
    org_deletion_grace_days: _GraceDays | None = None


class PlatformSecurityPatch(BaseModel):
    """The platform security to change: strict ints within the bounds, a null not given."""

    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    rate_limit_per_minute: _RequestsPerMinute | None = None
    lockout_after_failures: _LockoutFailures | None = None
    lockout_window_minutes: _LockoutMinutes | None = None
    lockout_minutes: _LockoutMinutes | None = None
    session_idle_timeout_minutes: _IdleTimeoutMinutes | None = None
    session_max_lifetime_hours: _LifetimeHours | None = None


class PlatformSettingsPatch(BaseModel):
    """PATCH /api/platform/settings request body: the platform defaults to change.

    Five optional sections (llm, limits, files, retention, security); any
    other key, top-level or nested, is refused. At least one value must be
    given: an empty section or a null counts as not given. Validation errors
    never repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    llm: SettingsPatchLLM | None = None
    limits: PlatformLimitsPatch | None = None
    files: PlatformFilesPatch | None = None
    retention: PlatformRetentionPatch | None = None
    security: PlatformSecurityPatch | None = None
    # GH-242: not a setting. A switch to a non-Swiss provider needs it equal to
    # the number of residency orgs (the route checks it).
    confirm_residency_orgs: Annotated[StrictInt, Field(ge=0, le=1_000_000)] | None = None

    @model_validator(mode="after")
    def _check_something_given(self) -> PlatformSettingsPatch:
        """Refuse a patch that gives no value in any section."""
        sections = (self.llm, self.limits, self.files, self.retention, self.security)
        if not any(section.model_dump(exclude_none=True) for section in sections if section):
            msg = "Give at least one setting to change."
            raise ValueError(msg)
        return self


# ---------------------------------------------------------------------------
# Permissions API models
# ---------------------------------------------------------------------------


class ToolPolicy(BaseModel):
    """One org's tool policy for one agent run (GH-161).

    Loaded per run by ``admino.org_permissions.load_tool_policy`` from the
    org's stored permission rows and tool switches, so concurrent runs of
    different orgs never share a policy. Frozen: a loaded policy can't be
    changed.
    """

    model_config = ConfigDict(frozen=True)

    permissions: PermissionsConfig
    # The tier-2 (tool, action) pairs the org promoted from deny to confirm.
    promoted: frozenset[tuple[str, str]] = frozenset()
    # Every tool name -> whether the org enabled the service.
    enabled_tools: dict[str, bool] = Field(default_factory=dict)
    # GH-242: the org's data residency policy. Under it, the run makes no LLM
    # call unless the running provider is Swiss (admino.llm_policy).
    data_residency: bool = False


class PermissionEntry(BaseModel):
    """A single permission row: (tool, action) → permission state."""

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    permission: Literal["allow", "confirm", "deny"]


class PermissionsResponse(BaseModel):
    """GET and PATCH /api/org/permissions response — the org's full permission matrix."""

    permissions: list[PermissionEntry]


class PermissionPatch(BaseModel):
    """PATCH /api/org/permissions request body — update one permission of the caller's org.

    Unknown keys (an org id included) are refused, and validation errors never
    repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    permission: Literal["allow", "confirm", "deny"]


class PermissionSummaryEntry(BaseModel):
    """One row of the read-only summary: a (tool, action) pair and its effective state.

    ``disabled`` when the org switched the tool's service off; otherwise the
    permission engine's decision for the org's policy.
    """

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    state: Literal["allow", "confirm", "deny", "disabled"]


class PermissionsSummaryResponse(BaseModel):
    """GET /api/permissions/summary response — the caller's org policy, read-only."""

    permissions: list[PermissionSummaryEntry]


# ---------------------------------------------------------------------------
# Critical permissions (tier-2 promotable denials)
# ---------------------------------------------------------------------------


class CriticalPermissionPromote(BaseModel):
    """PATCH /api/org/critical-permissions/{tool}/{action} body of a promotion.

    The Org Admin's own password, re-checked before the cooldown starts. A
    ``SecretStr``: ``repr()``/``str()`` never show it, validation errors never
    repeat it, and unknown fields are refused.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    password: SecretStr = Field(min_length=1, max_length=128)


class CriticalPermissionEntry(BaseModel):
    """A single promotable permission with current state and optional cooldown."""

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    state: Literal["deny", "confirm"]
    pending_at: datetime | None = Field(
        default=None,
        description="ISO 8601 timestamp when promotion cooldown started.",
    )


class CriticalPermissionsResponse(BaseModel):
    """GET /api/org/critical-permissions response."""

    permissions: list[CriticalPermissionEntry]


class CriticalPermissionState(BaseModel):
    """Response after PATCH /api/org/critical-permissions/{tool}/{action} or DELETE .../pending."""

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    state: Literal["deny", "confirm"]
    pending_at: datetime | None = None


# ---------------------------------------------------------------------------
# Authentication API models (GH-149)
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    """POST /api/auth/login request body.

    The email is matched case-insensitively by ``admino.auth``; its format is
    not validated here (an unknown address fails like a wrong password). The
    password is a ``SecretStr``: ``repr()``/``str()`` never show it, and the
    422 handler never echoes request input. Unknown fields are refused.
    """

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    password: SecretStr = Field(min_length=1, max_length=128)


class PasswordResetRequest(BaseModel):
    """POST /api/auth/password-reset request body.

    The email is matched case-insensitively by ``admino.password_reset``; its
    format is not validated here (an unknown address gets the same 202 as a
    known one). The 422 handler never echoes request input. Unknown fields are
    refused.
    """

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)


class PasswordResetConfirmRequest(BaseModel):
    """POST /api/auth/password-reset/confirm request body.

    The token (from the emailed link) and the new password are ``SecretStr``:
    ``repr()``/``str()`` never show them, and the 422 handler never echoes
    request input. The bounds only cap the body: ``admino.password_reset``
    decides whether the token can exist, and the password policy decides the
    password. Unknown fields are refused.
    """

    model_config = ConfigDict(extra="forbid")

    token: SecretStr = Field(min_length=1, max_length=128)
    new_password: SecretStr = Field(min_length=1, max_length=1024)


class MeResponse(BaseModel):
    """GET /api/auth/me response: the logged-in account, from the resolved session.

    Every value comes from the server-side session and users row, never from
    the request. A Super Admin has no ``org_id`` and no ``role``.
    """

    user_id: UUID
    kind: UserKind
    org_id: UUID | None
    role: MemberRole | None
    ui_language: Literal["de", "fr", "en"]
    response_language: Literal["de", "fr", "it", "en"] | None


# ---------------------------------------------------------------------------
# Session management API models (GH-152)
# ---------------------------------------------------------------------------


class SessionSummary(BaseModel):
    """One of the caller's live sessions (GET /api/me/sessions).

    No token or token hash: a session is identified by its id only. The IP and
    the user agent are what the browser sent when the session was opened; the
    user agent (client-supplied text) is stripped of control and
    direction-override characters. ``current`` marks the session of the
    request.
    """

    id: PlainUUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    ip: str | None = Field(max_length=45)
    user_agent: str | None = Field(max_length=256)
    current: bool

    @field_validator("user_agent")
    @classmethod
    def _strip_control_chars(cls, value: str | None) -> str | None:
        """Remove control and direction-override characters from the user agent."""
        return None if value is None else value.translate(_CONTROL_CHAR_TABLE)


class SessionListResponse(BaseModel):
    """GET /api/me/sessions response: the caller's live sessions, most recently active first."""

    sessions: list[SessionSummary]


# ---------------------------------------------------------------------------
# Invitation API models (GH-153)
# ---------------------------------------------------------------------------

# Characters a display name may not contain: control (Cc), format (Cf, e.g.
# direction overrides and zero-width characters) and line/paragraph separators.
_NAME_BANNED_CATEGORIES: Final = frozenset({"Cc", "Cf", "Zl", "Zp"})
# An invite email refuses the same, plus surrogates (Cs): it is shown on the
# acceptance page and in the org's invitation list.
_EMAIL_BANNED_CATEGORIES: Final = _NAME_BANNED_CATEGORIES | {"Cs"}


def _strip_if_str(value: object) -> object:
    """Strip surrounding whitespace from a string; leave anything else to the type check."""
    return value.strip() if isinstance(value, str) else value


def _check_invite_email(value: str) -> str:
    """Accept a plausible single invitee address; the messages never include it.

    No whitespace, control, format, separator or surrogate characters; exactly
    one '@' after a non-empty local part, and a '.' inside the domain (not its
    first or last character).
    """
    if any(
        char.isspace() or unicodedata.category(char) in _EMAIL_BANNED_CATEGORIES for char in value
    ):
        msg = "The email must not contain whitespace, control or invisible characters."
        raise ValueError(msg)
    local, at, domain = value.partition("@")
    if not at or not local or "@" in domain or "." not in domain[1:-1]:
        msg = "The email must look like name@example.com."
        raise ValueError(msg)
    return value


class InvitationCreateRequest(BaseModel):
    """POST /api/org/invitations request body: who to invite, with which role.

    The email is stripped, then must be 3 to 254 characters without
    whitespace, control, format (zero-width, direction override), separator or
    surrogate characters, with exactly one '@' after a non-empty
    local part and a '.' inside the domain (not its first or last character).
    Capitalization is kept (the unique index ignores it). The org is always the
    caller's and the language the caller's session language: unknown fields
    are refused. Validation messages never repeat the email.
    """

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    role: MemberRole

    @field_validator("email", mode="before")
    @classmethod
    def _strip_email(cls, value: object) -> object:
        """Strip surrounding whitespace before the length checks."""
        return _strip_if_str(value)

    @field_validator("email")
    @classmethod
    def _check_email(cls, value: str) -> str:
        """Accept a plausible single address; the messages never include it."""
        return _check_invite_email(value)


class InvitationSummary(BaseModel):
    """One pending invitation of the caller's org (list, create and resend responses).

    No token, token hash or link: an invitation is identified by its id only.
    ``expired`` is True once ``expires_at`` has passed; an expired invitation
    still holds its seat until it is revoked or sent again.
    """

    id: PlainUUID
    email: str = Field(max_length=254)
    role: MemberRole
    sent_at: datetime
    expires_at: datetime
    expired: bool


class InvitationListResponse(BaseModel):
    """GET /api/org/invitations response: the org's pending invitations, newest first."""

    invitations: list[InvitationSummary]


class InvitationDetails(BaseModel):
    """GET /api/auth/invitations/{token} response: what the acceptance page shows.

    The minimum: the org's display name, the offered role and the invited
    email. No ids, dates or token.
    """

    org_name: str = Field(max_length=120)
    role: MemberRole
    email: str = Field(max_length=254)


class InvitationAcceptRequest(BaseModel):
    """POST /api/auth/invitations/{token}/accept request body.

    The name is stripped, then must be 1 to 120 characters without control,
    format or line/paragraph separator characters. The password is a
    ``SecretStr``: ``repr()``/``str()`` never show it, and the 422 handler never
    echoes request input; its bounds only cap the body (the password policy
    decides the rest). Unknown fields are refused.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    password: SecretStr = Field(min_length=1, max_length=1024)

    @field_validator("name", mode="before")
    @classmethod
    def _strip_name(cls, value: object) -> object:
        """Strip surrounding whitespace before the length checks."""
        return _strip_if_str(value)

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        """Refuse control, format and line/paragraph separator characters."""
        if any(unicodedata.category(char) in _NAME_BANNED_CATEGORIES for char in value):
            msg = "The name must not contain control or formatting characters."
            raise ValueError(msg)
        return value


# ---------------------------------------------------------------------------
# Organization lifecycle API models (GH-154): org metadata only, no content
# ---------------------------------------------------------------------------

OrgStatus = Literal["active", "deactivated", "pending_deletion"]

# The plan limits, shared by the create request and the limits patch. The
# budget fits the organizations column NUMERIC(12,2): at most 10 digits before
# the point and 2 after; NaN and infinities are refused. The quota is in bytes
# and stays exact for a JSON reader (2**53 - 1).
Seats = Annotated[StrictInt, Field(ge=1, le=100_000)]
BudgetChf = Annotated[Decimal, Field(ge=0, max_digits=12, decimal_places=2, allow_inf_nan=False)]
StorageQuotaBytes = Annotated[StrictInt, Field(ge=0, le=2**53 - 1)]

# An org name reaches the invitation email's Subject header: the
# email_templates org-name rule refuses control, format, surrogate and
# line/paragraph separator characters.
_ORG_NAME_BANNED_CATEGORIES: Final = _NAME_BANNED_CATEGORIES | {"Cs"}


def _check_org_name(value: str) -> str:
    """Refuse an org name with a control, format, surrogate or line/paragraph separator.

    The message never includes the name.
    """
    if any(unicodedata.category(char) in _ORG_NAME_BANNED_CATEGORIES for char in value):
        msg = "The name must not contain control or formatting characters."
        raise ValueError(msg)
    return value


class OrgCreateRequest(BaseModel):
    """POST /api/platform/orgs request body (and the create-org CLI's input).

    The name is stripped, then must be 1 to 120 characters without control,
    format, surrogate or line/paragraph separator characters. The first Org
    Admin's email follows ``InvitationCreateRequest.email``'s rules exactly.
    Seats and the storage quota (bytes) are strict ints; the monthly budget in
    CHF is a JSON number or numeric string with at most 2 decimals. An org
    starts active or deactivated, never pending deletion. Residency keeps its
    default and the invitee's language is the caller's: unknown fields are
    refused. Validation errors never repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    name: str = Field(min_length=1, max_length=120)
    primary_admin_email: str = Field(min_length=3, max_length=254)
    seats: Seats
    monthly_budget_chf: BudgetChf
    storage_quota: StorageQuotaBytes
    status: Literal["active", "deactivated"] = "active"

    @field_validator("name", "primary_admin_email", mode="before")
    @classmethod
    def _strip(cls, value: object) -> object:
        """Strip surrounding whitespace before the length checks."""
        return _strip_if_str(value)

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        """Refuse control, format, surrogate and line/paragraph separator characters."""
        return _check_org_name(value)

    @field_validator("primary_admin_email")
    @classmethod
    def _check_email(cls, value: str) -> str:
        """The invitation email rules; the messages never include the address."""
        return _check_invite_email(value)


class OrgLimitsPatch(BaseModel):
    """PATCH /api/platform/orgs/{org_id}/limits request body.

    Any of the three plan limits, with the bounds of ``OrgCreateRequest``; a
    null counts as not given, and at least one must be given.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    seats: Seats | None = None
    monthly_budget_chf: BudgetChf | None = None
    storage_quota: StorageQuotaBytes | None = None

    @model_validator(mode="after")
    def _check_something_given(self) -> OrgLimitsPatch:
        """Refuse a patch that changes nothing."""
        if self.seats is None and self.monthly_budget_chf is None and self.storage_quota is None:
            msg = "Give at least one limit to change."
            raise ValueError(msg)
        return self


class OrgResidencyPatch(BaseModel):
    """PATCH /api/platform/orgs/{org_id}/residency request body: a strict bool."""

    # Validation errors never repeat the rejected input.
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    enabled: StrictBool


class OrgSummary(BaseModel):
    """One organization's metadata, as the Super Admin sees it (no content).

    ``storage_quota`` is in bytes; ``monthly_budget_chf`` is serialized as a
    decimal string. The deletion dates are set only while a deletion is
    pending.
    """

    id: PlainUUID
    name: str = Field(max_length=120)
    status: OrgStatus
    seats: int
    monthly_budget_chf: Decimal
    storage_quota: int
    data_residency: bool
    deletion_requested_at: datetime | None
    purge_after: datetime | None
    created_at: datetime
    updated_at: datetime


class OrgListResponse(BaseModel):
    """GET /api/platform/orgs response: every organization, oldest first."""

    organizations: list[OrgSummary]


class OrgCreateResponse(BaseModel):
    """POST /api/platform/orgs response: the new org and its first Org Admin's invitation.

    The invitation part carries no token and no link.
    """

    organization: OrgSummary
    invitation: InvitationSummary


# ---------------------------------------------------------------------------
# Org user management API models (GH-164): account metadata only, no credential
# ---------------------------------------------------------------------------

# A user's name is stored and shown in the org's user list: the display-name
# rule plus surrogates (Cs), which can't be stored as UTF-8.
_USER_NAME_BANNED_CATEGORIES: Final = _NAME_BANNED_CATEGORIES | {"Cs"}


class OrgUserSummary(BaseModel):
    """One user of the caller's org (list, change and status responses).

    No password hash, token, org id or account kind: a user is identified by
    its id only. An invited or deleted account is never a user here, so the
    status is ``active`` or ``deactivated``. ``name`` is None for an account
    created without one; ``last_login_at`` is None until the first login.
    """

    id: PlainUUID
    name: str | None = Field(max_length=120)
    email: str = Field(max_length=254)
    role: MemberRole
    status: Literal["active", "deactivated"]
    created_at: datetime
    last_login_at: datetime | None


class OrgSeats(BaseModel):
    """The read-only seat usage of the caller's org (GH-165).

    ``used`` counts the org's active and invited users (expired invitations
    included), the rule a new invitation is checked against; ``limit`` is the
    org's seats. ``used`` may exceed ``limit`` when the seats were lowered
    below the org's users, so there is no cross-field check.
    """

    used: int = Field(ge=0)
    limit: int = Field(ge=0)


class OrgUserListResponse(BaseModel):
    """GET /api/org/users response: the org's active and deactivated users, oldest first.

    ``seats`` is the org's seat usage (GH-165), shown next to the list.
    """

    users: list[OrgUserSummary]
    seats: OrgSeats


class OrgUserPatch(BaseModel):
    """PATCH /api/org/users/{user_id} request body: a new role, name or email.

    Any of the three; a null counts as not given, and at least one must be
    given. The name follows ``InvitationAcceptRequest.name``'s rules and also
    refuses surrogates; the email follows ``InvitationCreateRequest.email``'s
    rules exactly (capitalization kept). The org, the target user, the status
    and the account kind are never chosen by the body: unknown fields are
    refused. Validation errors never repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    role: MemberRole | None = None
    name: str | None = Field(default=None, min_length=1, max_length=120)
    email: str | None = Field(default=None, min_length=3, max_length=254)

    @field_validator("name", "email", mode="before")
    @classmethod
    def _strip(cls, value: object) -> object:
        """Strip surrounding whitespace before the length checks."""
        return _strip_if_str(value)

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str | None) -> str | None:
        """Refuse control, format, surrogate and line/paragraph separator characters."""
        if value is not None and any(
            unicodedata.category(char) in _USER_NAME_BANNED_CATEGORIES for char in value
        ):
            msg = "The name must not contain control or formatting characters."
            raise ValueError(msg)
        return value

    @field_validator("email")
    @classmethod
    def _check_email(cls, value: str | None) -> str | None:
        """The invitation email rules; the messages never include the address."""
        return None if value is None else _check_invite_email(value)

    @model_validator(mode="after")
    def _check_something_given(self) -> OrgUserPatch:
        """Refuse a patch that changes nothing."""
        if self.role is None and self.name is None and self.email is None:
            msg = "Give a role, a name or an email to change."
            raise ValueError(msg)
        return self


# ---------------------------------------------------------------------------
# Super Admin user administration API models (GH-167): account metadata and
# counts only, no credential and no org content
# ---------------------------------------------------------------------------


class PlatformUserSummary(BaseModel):
    """One account of an org as the Super Admin sees it (users list and status responses).

    Account metadata only: no password hash, token, org id or account kind.
    Unlike ``OrgUserSummary``, an invited account is listed too (status
    ``invited``, no name, never logged in), so the Super Admin can re-invite an
    org's first Org Admin. A deleted account is never listed.
    """

    id: PlainUUID
    name: str | None = Field(max_length=120)
    email: str = Field(max_length=254)
    role: MemberRole
    status: Literal["active", "deactivated", "invited"]
    created_at: datetime
    last_login_at: datetime | None


class PlatformUserListResponse(BaseModel):
    """GET /api/platform/orgs/{org_id}/users response: the org's accounts, oldest first."""

    users: list[PlatformUserSummary]


class OrgMetadata(BaseModel):
    """GET /api/platform/orgs/{org_id}/metadata response: counts and sizes only.

    ``seats`` follows the invitation seat rule (``OrgSeats``).
    ``chat_count`` is the org's chats that aren't trashed (GH-176);
    ``file_count`` and ``storage_used_bytes`` are the number of the org's
    attachments and the bytes they use, trashed ones included (GH-187).
    Never a title, a name or any other org content.
    """

    seats: OrgSeats
    storage_used_bytes: int = Field(ge=0)
    chat_count: int = Field(ge=0)
    file_count: int = Field(ge=0)


class PlatformReinviteRequest(BaseModel):
    """POST /api/platform/orgs/{org_id}/users/{user_id}/invitation request body.

    No email (absent or null) resends the invited Org Admin's invitation with a
    new link; an email replaces the invited account with a new invitation to
    that address. The email follows ``InvitationCreateRequest.email``'s rules
    exactly (stripped, capitalization kept); an empty or blank string is
    refused, not taken as "no email". The org, the target, the role (always
    org_admin) and the language come from the path, the contract and the
    session: unknown fields are refused. Validation errors never repeat the
    input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    email: str | None = Field(default=None, min_length=3, max_length=254)

    @field_validator("email", mode="before")
    @classmethod
    def _strip_email(cls, value: object) -> object:
        """Strip surrounding whitespace before the length checks."""
        return _strip_if_str(value)

    @field_validator("email")
    @classmethod
    def _check_email(cls, value: str | None) -> str | None:
        """The invitation email rules; the messages never include the address."""
        return None if value is None else _check_invite_email(value)


# ---------------------------------------------------------------------------
# Account self-service API models (GH-166): the caller's own account only
# ---------------------------------------------------------------------------

UiLanguage = Literal["de", "fr", "en"]
ResponseLanguage = Literal["de", "fr", "it", "en"]

# The bounds of migration 0021's users.timezone and users.personal_instructions.
_TIMEZONE_MAX_LENGTH: Final = 64
_PERSONAL_INSTRUCTIONS_MAX_LENGTH: Final = 1500
# Control characters personal instructions may keep: tab, newline, carriage return.
_INSTRUCTIONS_ALLOWED_CONTROLS: Final = frozenset("\t\n\r")
# Format characters they may keep: the zero-width non-joiner and joiner, which
# some scripts and emoji sequences need. Every other format character (bidi
# overrides and isolates, direction marks, zero-width space, BOM) is refused:
# the instructions reach the system prompt (#170).
_INSTRUCTIONS_ALLOWED_FORMATS: Final = frozenset("\u200c\u200d")
# Categories refused outright: surrogates and line/paragraph separators.
_INSTRUCTIONS_BANNED_CATEGORIES: Final = frozenset({"Cs", "Zl", "Zp"})
# The account fields a patch can't clear: a null for them is refused.
_NOT_NULLABLE_ACCOUNT_FIELDS: Final = ("name", "ui_language", "timezone", "personal_instructions")


def _has_refused_instruction_char(value: str) -> bool:
    """True when instructions hold a character they must not (personal and org alike).

    Refused: every control character but tab, newline and carriage return,
    every format character but the zero-width non-joiner and joiner,
    surrogates and line/paragraph separators.
    """
    return any(
        (category := unicodedata.category(char)) in _INSTRUCTIONS_BANNED_CATEGORIES
        or (category == "Cc" and char not in _INSTRUCTIONS_ALLOWED_CONTROLS)
        or (category == "Cf" and char not in _INSTRUCTIONS_ALLOWED_FORMATS)
        for char in value
    )


@functools.cache
def _available_timezones() -> frozenset[str]:
    """The IANA zone names of the runtime's tz database, read once."""
    return frozenset(zoneinfo.available_timezones())


class MyAccountResponse(BaseModel):
    """GET and PATCH /api/me response: the caller's own account (GH-166).

    Read from the caller's own users row. No id, hash, token, org, role or
    account kind. ``name`` is None only for a Super Admin created without
    one; ``response_language`` None means the org's default; ``timezone``
    None means not preset yet (consumers use Europe/Zurich);
    ``personal_instructions`` ``""`` means none.
    """

    email: str = Field(max_length=254)
    name: str | None = Field(max_length=120)
    ui_language: UiLanguage
    response_language: ResponseLanguage | None
    timezone: str | None = Field(max_length=_TIMEZONE_MAX_LENGTH)
    personal_instructions: str = Field(max_length=_PERSONAL_INSTRUCTIONS_MAX_LENGTH)


class MyAccountPatch(BaseModel):
    """PATCH /api/me request body: change the caller's own account (GH-166).

    Any of the five fields; presence is ``model_fields_set``, and at least one
    must be given. ``response_language`` given as null means "use the org
    default"; a null name, UI language, timezone or instructions is refused
    (``""`` clears the instructions). The name is stripped, then 1 to 120
    characters without control, format, surrogate or line/paragraph separator
    characters. The timezone is a name of the runtime's tz database, exactly
    as written. The instructions are kept verbatim (not stripped): at most
    1500 code points, no control character but tab, newline and carriage
    return, no format character but the zero-width non-joiner and joiner, no
    surrogate and no line/paragraph separator. The email, password, role, org
    and kind are never
    chosen here: unknown fields are refused. Validation errors never repeat
    the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    name: str | None = Field(default=None, min_length=1, max_length=120)
    ui_language: UiLanguage | None = None
    response_language: ResponseLanguage | None = None
    timezone: str | None = Field(default=None, min_length=1, max_length=_TIMEZONE_MAX_LENGTH)
    personal_instructions: str | None = Field(
        default=None, max_length=_PERSONAL_INSTRUCTIONS_MAX_LENGTH
    )

    @field_validator("name", mode="before")
    @classmethod
    def _strip_name(cls, value: object) -> object:
        """Strip surrounding whitespace from the name before the length checks."""
        return _strip_if_str(value)

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str | None) -> str | None:
        """Refuse control, format, surrogate and line/paragraph separator characters."""
        if value is not None and any(
            unicodedata.category(char) in _USER_NAME_BANNED_CATEGORIES for char in value
        ):
            msg = "The name must not contain control or formatting characters."
            raise ValueError(msg)
        return value

    @field_validator("timezone")
    @classmethod
    def _check_timezone(cls, value: str | None) -> str | None:
        """Accept a known IANA zone name only; the message never includes the value."""
        if value is not None and value not in _available_timezones():
            msg = "Unknown timezone."
            raise ValueError(msg)
        return value

    @field_validator("personal_instructions")
    @classmethod
    def _check_personal_instructions(cls, value: str | None) -> str | None:
        """Refuse control, format, surrogate and line/paragraph separator characters.

        Tab, newline and carriage return, and the zero-width non-joiner and
        joiner, are kept.
        """
        if value is not None and _has_refused_instruction_char(value):
            msg = "The personal instructions must not contain control or formatting characters."
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _check_given_fields(self) -> MyAccountPatch:
        """Refuse an empty patch, and a null for a field that can't be cleared."""
        given = self.model_fields_set
        if not given:
            msg = "Give at least one field to change."
            raise ValueError(msg)
        if any(
            field in given and getattr(self, field) is None
            for field in _NOT_NULLABLE_ACCOUNT_FIELDS
        ):
            msg = "Only response_language can be null."
            raise ValueError(msg)
        return self


class PasswordChangeRequest(BaseModel):
    """POST /api/me/password request body: the caller's current and new password (GH-166).

    Both are ``SecretStr`` (hidden from repr/str/JSON) and kept as typed. The
    bounds only cap the body: ``admino.auth.reauthenticate`` checks the
    current password and the password policy decides the new one. Unknown
    fields are refused; validation errors never repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    current_password: SecretStr = Field(min_length=1, max_length=1024)
    new_password: SecretStr = Field(min_length=1, max_length=1024)


# ---------------------------------------------------------------------------
# Organization settings API models (GH-169): the Org Admin's own org only
# ---------------------------------------------------------------------------

# The bound of migration 0023's org_settings.instructions.
_ORG_INSTRUCTIONS_MAX_LENGTH: Final = 8000


class OrgProfile(BaseModel):
    """The org's profile: its name (``organizations.name``) and default response language."""

    display_name: str = Field(max_length=120)
    default_response_language: ResponseLanguage


class OrgSecurity(BaseModel):
    """The session policy a member's new session takes (the ``admino.sessions`` bounds)."""

    session_idle_timeout_minutes: _IdleTimeoutMinutes
    session_max_lifetime_hours: _LifetimeHours


class OrgRetention(BaseModel):
    """The org's trash retention and the platform's trash bounds (read-only).

    ``trash_retention_days`` is the effective value: the stored one clamped
    into ``[trash_min_days, trash_max_days]``.
    """

    trash_retention_days: _TrashDays
    trash_min_days: _TrashDays
    trash_max_days: _TrashDays


class OrgPlan(BaseModel):
    """The org's plan limits, read-only: seats and the storage quota in bytes (no budget)."""

    seats: int
    storage_quota: int


class OrgSettingsResponse(BaseModel):
    """GET/PATCH /api/org/settings response: the Org Admin's own org's settings.

    The profile, the instructions, the session policy, the trash retention
    and the tool services are editable; ``data_residency`` (GH-162, when on
    the Google and Microsoft services are off for every run whatever their
    stored switch says) and the plan are the Super Admin's, read-only here.
    """

    profile: OrgProfile
    instructions: str = Field(max_length=_ORG_INSTRUCTIONS_MAX_LENGTH)
    security: OrgSecurity
    retention: OrgRetention
    tools: ToolsSettings
    data_residency: bool
    plan: OrgPlan


class OrgProfilePatch(BaseModel):
    """The profile to change; a null is not given.

    The display name follows ``OrgCreateRequest.name``'s rule exactly:
    stripped, then 1 to 120 characters without control, format, surrogate or
    line/paragraph separator characters.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    default_response_language: ResponseLanguage | None = None

    @field_validator("display_name", mode="before")
    @classmethod
    def _strip(cls, value: object) -> object:
        """Strip surrounding whitespace before the length checks."""
        return _strip_if_str(value)

    @field_validator("display_name")
    @classmethod
    def _check_display_name(cls, value: str | None) -> str | None:
        """Refuse control, format, surrogate and line/paragraph separator characters."""
        return None if value is None else _check_org_name(value)


class OrgSecurityPatch(BaseModel):
    """The session policy to change: strict ints within the bounds, a null not given."""

    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    session_idle_timeout_minutes: _IdleTimeoutMinutes | None = None
    session_max_lifetime_hours: _LifetimeHours | None = None


class OrgRetentionPatch(BaseModel):
    """The trash retention to change: a strict int of 0 to 90 days, a null not given.

    The platform's trash bounds are not checked here: the service checks a
    changed value against them.
    """

    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    trash_retention_days: _TrashDays | None = None


class OrgSettingsPatch(BaseModel):
    """PATCH /api/org/settings request body: the org settings to change (GH-169).

    Five optional sections: profile, instructions, security, retention and
    tools. A null anywhere counts as not given, and at least one value must be
    given (an empty section is none). The instructions are kept verbatim (not
    stripped; ``""`` clears them): at most 8000 code points under the personal
    instructions' character rule. The org is always the caller's own, and the
    residency, the plan and the platform's trash bounds are read-only: any
    other key, at any level, is refused. Validation errors never repeat the
    input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    profile: OrgProfilePatch | None = None
    instructions: str | None = Field(default=None, max_length=_ORG_INSTRUCTIONS_MAX_LENGTH)
    security: OrgSecurityPatch | None = None
    retention: OrgRetentionPatch | None = None
    tools: OrgToolsPatch | None = None

    @field_validator("instructions")
    @classmethod
    def _check_instructions(cls, value: str | None) -> str | None:
        """Refuse control, format, surrogate and line/paragraph separator characters.

        Tab, newline and carriage return, and the zero-width non-joiner and
        joiner, are kept.
        """
        if value is not None and _has_refused_instruction_char(value):
            msg = "The instructions must not contain control or formatting characters."
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _check_something_given(self) -> OrgSettingsPatch:
        """Refuse a patch that gives no value in any section."""
        sections = (self.profile, self.security, self.retention, self.tools)
        if self.instructions is None and not any(
            section.model_dump(exclude_none=True) for section in sections if section
        ):
            msg = "Give at least one setting to change."
            raise ValueError(msg)
        return self


# ---------------------------------------------------------------------------
# Prompt context (GH-170): the per-user, per-org inputs of a run's system prompt
# ---------------------------------------------------------------------------


class PromptContext(BaseModel):
    """The per-user, per-org inputs of one run's system prompt (GH-170).

    Read from the caller's own rows by ``scoped_settings.load_prompt_context``
    and assembled by ``admino.prompt_assembly``. ``response_language`` is the
    user's own preference and ``default_response_language`` the org's (the
    assembler resolves the fallback); ``timezone`` None means Europe/Zurich
    (an unknown name falls back the same way when the date line is built).
    ``PromptContext()`` is the empty context: no instructions, no language,
    the default timezone. No account identifier (id, email, name, org name,
    role) is a field, and unknown keys are refused, so none can reach a
    prompt. Frozen; validation errors never repeat the input.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    org_instructions: str = Field(default="", max_length=_ORG_INSTRUCTIONS_MAX_LENGTH)
    personal_instructions: str = Field(default="", max_length=_PERSONAL_INSTRUCTIONS_MAX_LENGTH)
    response_language: ResponseLanguage | None = None
    default_response_language: ResponseLanguage | None = None
    timezone: str | None = Field(default=None, max_length=_TIMEZONE_MAX_LENGTH)


# ---------------------------------------------------------------------------
# Platform diagnostics API model (GH-158): config metadata and statuses only
# ---------------------------------------------------------------------------


class PlatformDiagnosticsResponse(BaseModel):
    """GET /api/platform/diagnostics response (Super Admin): what public /health hides.

    ``status`` is the database check (``"ok"`` or ``"degraded"``), ``provider``
    and ``model`` the active LLM configuration (``model`` is None when no model
    is chosen), ``llm_reachable`` the provider probe. No content.
    """

    status: Literal["ok", "degraded"]
    provider: Literal["infomaniak", "anthropic", "openai", "vllm"]
    model: str | None = Field(max_length=200)
    llm_reachable: bool


# ---------------------------------------------------------------------------
# Persisted chats (GH-176): the /api/chats request and response models
# ---------------------------------------------------------------------------


MessageStatus = Literal["complete", "stopped", "error", "awaiting_confirmation", "limit_reached"]
"""Status of a stored chat message (migration 0024's CHECK); the run's ``final`` is ``complete``."""

TitleSource = Literal["auto", "user"]
"""Who set a chat's title: ``auto`` (untitled until #179 fills it) or the ``user``."""

_CHAT_TITLE_MAX_LENGTH: Final = 200
# A title is stored and shown in every chat list: the display-name rule plus
# surrogates (Cs), which can't be stored as UTF-8. The same object as the set
# text shown to users removes (sanitize_display_text keeps tab, LF and CR),
# so the two can't drift apart. Public because an automatic title
# (chat_titles) drops exactly the characters a ChatTitle refuses.
CHAT_TITLE_BANNED_CATEGORIES: Final = _INVISIBLE_CATEGORIES
_CURSOR_MAX_LENGTH: Final = 200


def _check_chat_title(value: str) -> str:
    """Refuse a title with a control, format, surrogate or line/paragraph separator.

    The message never includes the title.
    """
    if any(unicodedata.category(char) in CHAT_TITLE_BANNED_CATEGORIES for char in value):
        msg = "The title must not contain control or formatting characters."
        raise ValueError(msg)
    return value


ChatTitle = Annotated[
    str,
    BeforeValidator(_strip_if_str),
    Field(min_length=1, max_length=_CHAT_TITLE_MAX_LENGTH),
    AfterValidator(_check_chat_title),
]
"""A chat title from a request: stripped, 1 to 200 characters, no control or format character."""


class ChatCreateRequest(BaseModel):
    """POST /api/chats request body: an optional title (absent or null: untitled).

    The org, the owner and the title source come from the session and the
    server, never from the body; validation errors never repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    title: ChatTitle | None = None


class ChatUpdateRequest(BaseModel):
    """PATCH /api/chats/{chat_id} request body: the new title (required)."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    title: ChatTitle


AttachmentKind = Literal["pdf", "docx", "xlsx", "csv", "txt", "md", "png", "jpeg", "webp"]
"""An attachment's type, detected from its content (admino.attachment_types)."""

AttachmentStatus = Literal["uploaded", "processing", "ready", "failed"]
"""An attachment's processing state: uploaded -> processing -> ready | failed."""

# Migration 0027's CHECKs: the name length, 500 MiB (the platform maximum of
# max_file_size_mb) and the reason code.
_ATTACHMENT_FILENAME_MAX_LENGTH: Final = 255
_ATTACHMENT_MAX_BYTES: Final = 524_288_000
_ATTACHMENT_REASON_PATTERN: Final = r"^[a-z][a-z0-9_]{0,63}$"
_ATTACHMENTS_PER_MESSAGE_MAX: Final = 50

ContextRefusalReason = Literal["context_overflow", "attachment_bytes_exceeded"]
"""Why a turn's attachments alone don't fit (GH-190): too many tokens, or too many bytes."""


class ContextReportItem(BaseModel):
    """One file of a context report: its id and stored sizes, never its name (GH-190)."""

    model_config = ConfigDict(extra="forbid")

    attachment_id: UUID
    token_estimate: int = Field(ge=0, description="The file's stored token estimate (null as 0).")
    derived_bytes: int = Field(
        ge=0, description="The bytes of the file's converted text and images (null as 0)."
    )


class ContextReport(BaseModel):
    """The files a turn would send and how they compare with the limits (GH-190).

    ``attachments`` are in slot order; ``attachment_tokens`` and
    ``attachment_bytes`` are their sums, ``available_tokens`` the budget minus
    the reserved output (at least 0) and ``max_bytes`` the per-turn byte cap.
    """

    model_config = ConfigDict(extra="forbid")

    attachments: list[ContextReportItem]
    attachment_tokens: int = Field(ge=0)
    available_tokens: int = Field(ge=0)
    attachment_bytes: int = Field(ge=0)
    max_bytes: int = Field(ge=1)


class ContextRefusal(BaseModel):
    """The 422 body of a turn whose attachments alone don't fit (GH-190).

    ``reason`` is the stable code (tokens are checked before bytes) and
    ``report`` names the files by id only.
    """

    model_config = ConfigDict(extra="forbid")

    detail: str = Field(max_length=200)
    reason: ContextRefusalReason
    report: ContextReport


class AttachmentSummary(BaseModel):
    """One stored attachment as the API shows it: metadata only.

    ``filename`` is the sanitized name, ``kind`` the detected type,
    ``failure_reason`` a code (set when ``status`` is ``failed``),
    ``token_estimate`` the estimated tokens of the converted file (null until
    it is ``ready``) and ``active`` whether the file is sent with the chat's
    turns (GH-190: an excluded file stays listed). ``context_report`` is set
    only on a file that failed with ``context_overflow``.
    """

    id: UUID
    chat_id: UUID
    message_id: UUID | None
    filename: str = Field(min_length=1, max_length=_ATTACHMENT_FILENAME_MAX_LENGTH)
    kind: AttachmentKind
    size_bytes: int = Field(ge=1, le=_ATTACHMENT_MAX_BYTES)
    status: AttachmentStatus
    failure_reason: str | None = Field(pattern=_ATTACHMENT_REASON_PATTERN)
    page_count: int | None = Field(ge=0)
    token_estimate: int | None = Field(ge=0)
    active: bool
    context_report: ContextReport | None = None
    created_at: datetime


class AttachmentUpdateRequest(BaseModel):
    """PATCH /api/attachments/{attachment_id} request body: include or exclude the file.

    A strict bool and nothing else (GH-190); the attachment comes from the
    path, its owner and org from the session.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    active: StrictBool


class AttachmentListResponse(BaseModel):
    """GET /api/chats/{chat_id}/attachments response: one page of the chat's files, oldest first."""

    attachments: list[AttachmentSummary] = Field(max_length=100)
    next_cursor: str | None = Field(default=None, max_length=_CURSOR_MAX_LENGTH)


class AttachmentContent(BaseModel):
    """One active attachment of a chat, as slot 4 of the prompt needs it (GH-189).

    ``filename`` is the stored name (``prompt_assembly.prompt_filename`` makes
    the prompt name of it) and ``parts`` the converted parts in manifest
    order: an image part's label is the text part right before it.
    ``token_estimate`` is the row's stored estimate (NULL as 0), what the
    context budget counts for the file (GH-190). It has no default (GH-294,
    Decision 9), so no caller can leave it out and have the budget count
    the file as 0. Built for one run from the caller's own rows and derived
    files; never stored, logged or returned by an API.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    id: UUID
    filename: str = Field(min_length=1, max_length=_ATTACHMENT_FILENAME_MAX_LENGTH)
    kind: AttachmentKind
    page_count: int | None = Field(ge=0)
    parts: tuple[ContentPart, ...]
    token_estimate: int = Field(ge=0)

    @property
    def has_images(self) -> bool:
        """Whether any part is an image (the image-input gate refuses those)."""
        return any(isinstance(part, ImageContent) for part in self.parts)


class ChatMessageCreate(BaseModel):
    """POST /api/chats/{chat_id}/messages request body: one user message.

    The chat comes from the path, the org and the owner from the session.
    ``attachment_ids`` are the caller's unsent uploads in that chat, each
    at most once. A blank message is valid here and kept as given; the
    route refuses it when it sends no files (GH-286).
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    message: str = Field(max_length=32768)
    attachment_ids: list[UUID] = Field(
        default_factory=list, max_length=_ATTACHMENTS_PER_MESSAGE_MAX
    )

    @field_validator("attachment_ids")
    @classmethod
    def _refuse_duplicates(cls, value: list[UUID]) -> list[UUID]:
        """Refuse an id given twice (compared as UUIDs); the message names no id."""
        if len(set(value)) != len(value):
            msg = "Each attachment can be sent only once per message."
            raise ValueError(msg)
        return value


class ChatSummary(BaseModel):
    """One chat as the API lists it: metadata only, never a message."""

    id: UUID
    title: str = Field(max_length=_CHAT_TITLE_MAX_LENGTH)
    title_source: TitleSource
    created_at: datetime
    last_activity_at: datetime


class ChatListResponse(BaseModel):
    """GET /api/chats response: one page of the caller's chats, latest activity first."""

    chats: list[ChatSummary] = Field(max_length=100)
    next_cursor: str | None = Field(default=None, max_length=_CURSOR_MAX_LENGTH)


TrashItemType = Literal["chat", "attachment"]
"""The kind of a trash item (GH-194): V1's trash holds chats and attachments."""


class TrashItem(BaseModel):
    """One item of the caller's trash: metadata only.

    ``name`` is the chat's title (an untitled chat's is empty) or the file's
    name; ``chat_id`` is the file's chat and None for a chat. ``expires_at``
    is ``deleted_at`` plus the org's effective retention.
    """

    item_type: TrashItemType
    id: UUID
    # Bounded like a file name (migration 0027); a chat title is shorter still.
    name: str = Field(max_length=_ATTACHMENT_FILENAME_MAX_LENGTH)
    chat_id: UUID | None
    deleted_at: datetime
    expires_at: datetime


class TrashListResponse(BaseModel):
    """GET /api/trash response: one page of the caller's trash, latest deletion first."""

    items: list[TrashItem] = Field(max_length=100)
    next_cursor: str | None = Field(default=None, max_length=_CURSOR_MAX_LENGTH)
    # The org setting's range: 0 purges a deleted item at once.
    retention_days: int = Field(ge=0, le=90)


class TrashEmptyResponse(BaseModel):
    """DELETE /api/trash response: how many items were purged."""

    chats: int = Field(ge=0)
    attachments: int = Field(ge=0)


class ChatMessageView(BaseModel):
    """One stored message as the API shows it.

    ``content`` is sanitized like ``ChatResponse.response`` and ``tool_calls``
    holds the sanitized ``ToolCallRecord``s; the raw tool inputs the model sent
    stay in the database and are never exposed. ``attachment_ids`` are the
    message's live files, included or excluded, in upload order (GH-190).
    """

    id: UUID
    role: Literal["user", "assistant", "tool"]
    content: str = Field(max_length=65536)
    tool_call_id: str | None = Field(default=None, max_length=128)
    tool_calls: list[ToolCallRecord] | None = Field(default=None, max_length=50)
    status: MessageStatus
    created_at: datetime
    attachment_ids: list[UUID] = Field(
        default_factory=list, max_length=_ATTACHMENTS_PER_MESSAGE_MAX
    )

    @field_validator("content")
    @classmethod
    def _sanitize_content(cls, value: str) -> str:
        """Strip control characters and credential patterns, as in the live reply."""
        return sanitize_display_text(value)


class ChatDetailResponse(ChatSummary):
    """GET /api/chats/{chat_id} response: the summary, a page of messages and the state.

    ``messages`` is chronological (the latest page without a cursor) and
    ``next_cursor`` points to earlier messages. ``confirmation_status`` is
    ``pending`` with a live pending confirmation, ``expired`` when the latest
    message awaits a confirmation that is gone (expired or lost in a restart).
    ``context_usage`` is how full the chat's context is as its next turn
    starts (GH-190). ``retryable`` (GH-245) is true exactly when the chat's
    latest message ended as ``error`` or ``stopped``, whatever page is read:
    then POST /api/chats/{chat_id}/retry passes its status check instead of
    answering ``409`` ``not_retryable``.
    """

    messages: list[ChatMessageView] = Field(max_length=100)
    next_cursor: str | None = Field(default=None, max_length=_CURSOR_MAX_LENGTH)
    pending_confirmation: PendingConfirmationSummary | None = None
    confirmation_status: Literal["none", "pending", "expired"]
    context_usage: ContextUsage
    retryable: bool


# ---------------------------------------------------------------------------
# Streamed chat turns (GH-8): the SSE event payloads and the stop route
# ---------------------------------------------------------------------------

DELTA_MAX_LENGTH: Final = 4096
"""The most characters one ``delta`` event carries (``admino.streaming.MAX_DELTA_CHARS``)."""

StreamErrorCode = Literal[LLMErrorCode, "rate_limit", "internal_error", "chat_not_found"]
"""Stable code of a streamed turn's ``error`` event; the UI shows its translation.

The run's LLM error codes (GH-242), ``rate_limit`` (GH-24: too many pending
confirmations), ``internal_error`` (an uncoded failure, also an agent that
raised: nothing stored) and ``chat_not_found`` (the chat was trashed during the
run: nothing stored).
"""


class RunStartedPayload(BaseModel):
    """``run_started`` event: the first frame, naming the chat the run belongs to."""

    model_config = ConfigDict(extra="forbid")

    chat_id: UUID


class DeltaPayload(BaseModel):
    """``delta`` event: the next piece of the answer as it is shown.

    The text is ``admino.streaming.DisplayDeltas`` output, display text already;
    it is not cleaned again here, since a piece cleaned on its own can differ
    from the same characters cleaned within the whole answer.
    """

    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=DELTA_MAX_LENGTH)


class MessageSavedPayload(BaseModel):
    """``message_saved`` event: the turn is stored; its last message's id and status."""

    model_config = ConfigDict(extra="forbid")

    message_id: UUID
    status: MessageStatus


class ErrorPayload(BaseModel):
    """``error`` event: a stable code and the English fallback the JSON route returns."""

    model_config = ConfigDict(extra="forbid")

    code: StreamErrorCode
    message: str = Field(max_length=65536)

    @field_validator("message")
    @classmethod
    def _sanitize_message(cls, value: str) -> str:
        """Clean the message like ``ChatResponse.response``, so both modes read the same."""
        return sanitize_display_text(value)


class TitlePayload(BaseModel):
    """``title`` event: the chat's stored automatic title."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=_CHAT_TITLE_MAX_LENGTH)


class DonePayload(BaseModel):
    """``done`` event: the last frame; no data."""

    model_config = ConfigDict(extra="forbid")


class ChatStopResponse(BaseModel):
    """POST /api/chats/{chat_id}/stop response: whether a streamed run of the chat was stopped."""

    model_config = ConfigDict(extra="forbid")

    stopped: bool
