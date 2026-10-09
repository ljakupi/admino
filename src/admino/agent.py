"""Agent loop orchestrating LLM interaction, tool dispatch, and tool-call auditing.

This module defines the :class:`Agent` class — the single orchestrator that
ties together the LLM client (``admino.llm``), the tool registry
(``admino.tools.registry``), and an injected :class:`ToolCallRecorder` (the
tool-call audit sink), plus the :class:`ToolCallRecorder` protocol itself.

Architecture & boundaries:
- The agent is the ONLY component that closes the loop between LLM output,
  tool dispatch, and conversation history. It MUST NOT be imported by
  ``permissions.py`` (which remains isolated) and MUST NOT import from
  ``server.py``, the database layer, the audit event store or ``asyncpg`` —
  the recorder is injected by the entry point, which binds it to storage.
- Permission checks happen inside ``registry.dispatch_tool_call``. The agent
  never calls ``check_permission`` directly — dispatch is the single
  enforcement point. The agent awaits the recorder exactly once after every
  dispatch, whatever its outcome, so every decision is recorded.
- Conversation history is owned by the *caller*; the system message is owned
  by the *agent*. The agent copies the caller's history, mutates the local
  list, and returns it as part of :class:`admino.models.AgentResult` — it
  only ever holds user/assistant/tool messages. The system message is added
  to each LLM call's context and never returned in history, so it cannot
  accumulate across turns (GH-140).
- Layered prompt (GH-170): every LLM call's context is built by
  ``admino.prompt_assembly.assemble`` from the run's
  :class:`admino.models.PromptContext` (the org's and the user's
  instructions, languages and timezone; the server loads it per request),
  the run's advertised tools and the run's clock reading (read once per
  run), so every call of a run carries the same system message: the base
  prompt ending with the run's tools line, the instruction sections, then
  the date line. There is no startup-built prompt. Slot 4 (GH-189), the
  chat's active attachments the caller passes as ``attachments``, is not in
  the system message: on every LLM call of the run (the first, the tool loop,
  the streamed path and a resumed confirmation) ``assemble`` puts it at the
  start of the context's current user message as content parts, so attached
  files never get system-message authority. Those parts exist only in the
  call's context: the returned history keeps the user's text as the str it
  was given.
- The agent holds no permission state and there is no module-level mutable
  state (GH-161). Every run gets the requesting org's
  :class:`admino.models.ToolPolicy` (its permissions, promoted tier-2 pairs
  and enabled services) as a required ``tool_policy`` keyword; the tools
  payload, every dispatch and the system message's tools line of that run
  use it alone, so concurrent runs of different orgs never see each other's
  policy.

Security notes:
- No ``eval``, ``exec``, ``compile``, ``importlib``, ``shell=True``, or
  dynamic tool dispatch.
- User message content, raw tool arguments, and assistant text are NEVER
  logged at INFO/DEBUG. Only counts, tool/action names, and status strings
  are emitted via the standard logger.
- The recorder is the tool-call audit sink. It receives only the run's
  principal (the logged-in user, which the agent passes through unread), the
  session id, the tool/action names the LLM asked for, the final permission
  decision, the success flag, the dispatch duration and whether the dispatch
  was escalated — never argument values, tool output or error text. A run
  with attachments (GH-189) also passes ``attachment_ids``, the ids in slot
  order, on every recorder call; a run without them passes exactly the eight
  keywords above. No file name, kind, size or content is passed.
  Conversation content is not audited.
- Untrusted content (GH-243): the whole run executes inside
  ``untrusted.run_boundary()``, so the tool handlers wrap third-party content
  (emails, files, events, memory notes) with the run's random boundary. The
  run counts as having received external content once its history (the
  whole of it, not just the LLM's context window; this covers a resumed
  confirmation and later turns) holds a wrapped ``tool`` message, the caller
  passes ``earlier_external_content=True`` (GH-176: a persisted chat loads
  only its latest messages, and its sticky flag covers the older ones), the
  run has attachments (GH-189: slot 4's blocks are wrapped with the run's
  boundary, so the files count from the first dispatch), or a dispatch (the
  resume pre-dispatch included) returns a wrapped result, judged on the full
  result before the GH-190 cut. From then on every dispatch, the resume
  pre-dispatch included, passes ``escalate_side_effects=True`` and the
  registry turns an allowed side effect into ``confirm``; a hardcoded denial
  such as ``gmail.send`` stays denied. The flag only tightens a decision and
  never reaches the permission engine. The run reports it as
  ``AgentResult.external_content`` on every return path (GH-190), so the
  caller's sticky chat flag holds even when the cut removed a wrapped block's
  begin marker from the stored result. The attachment ids and the flag belong
  to the run (its locals and its report), never to the agent. No content,
  file name, label or boundary is logged.
- Context budget (GH-190, ``admino.context_budget``): before every LLM call
  of a run (the first, the tool loop, the streamed path, after a resumed
  confirmation) the call must satisfy ``instructions + attachments + history
  + reserved output <= budget``. The instructions are the call's system
  message and tools payload, the attachments count their stored
  ``token_estimate`` (never their text), the reserve is the run config's
  ``reserved_output_tokens``, and the budget is ``max_input_tokens`` less
  ``context_margin_percent`` (rounded up). A positive ``max_context_messages``
  (the secondary cap) trims first, as before; 0 is no cap, and the window is
  then the whole history without its leading ``tool`` results (their call
  lies before the load limit). The budget then keeps the newest whole earlier
  turns that fit (a turn is a user message and everything up to the next
  one), so a tool call never travels without its results, nor a result
  without its call. The current turn (the new message, or the request a
  resumed confirmation answers, and everything after it) and the attachments
  are never dropped: when even they don't fit, the run ends before that call
  with status "error", ``error_code="context_too_long"`` and the fixed
  ``CONTEXT_TOO_LONG_MESSAGE`` reply stored like any coded failure. No LLM
  call is made (on the streamed path ``chat_stream`` isn't called), nothing
  more is dispatched, and one line with token and tool-call counts only is
  logged. ``AgentResult.context_notice`` carries the drops (counts only) of
  the run's last call, made or refused; the cap's drops and the leading
  ``tool`` results don't count.
- Tool-result cut (GH-190): every ``tool`` message the run appends (a
  dispatch, the resume pre-dispatch) carries
  ``context_budget.truncate_tool_result(result, max_tool_result_tokens)``: a
  longer result is sent and stored as its longest fitting prefix plus a fixed
  marker, which bounds what one result adds to every later call and to the
  stored chat. Escalation is still decided on the full result (see above).
- A run is never anonymous: ``run`` takes the caller's ``principal`` as a
  required keyword (GH-149); the agent makes no access decision with it.
- Tool context (GH-162): each run derives its ``TenantContext`` once from
  the principal and passes it as ``tenant`` to every dispatch (the resume
  pre-dispatch included), so handlers scope their content by the logged-in
  user's user_id and org_id; it never comes from LLM output or history. A
  principal without an organization (a Super Admin) has no tool context:
  nothing is dispatched, and each tool call ends as a recorded "No
  organization context." deny.
- H-1: if the recorder raises, the run aborts with a fixed
  "Internal error: audit unavailable." result: no further LLM call, no
  further dispatch, and no ``pending_confirmation`` is handed out for an
  unaudited confirmation request. Only a content-free line is logged.
- Every ``system``-role message in caller-supplied history (leading or
  mid-conversation) is dropped before use — it could be persisted prompt
  injection. Only a count is logged, never the content.
- Model policy (GH-242, ``admino.llm_policy``, the V1 bridge of #174's
  gateway): right after the H-2 session check, a run whose org has data
  residency on (``tool_policy.data_residency``) and whose client isn't Swiss
  (``provider`` not infomaniak/vllm, or missing: fail closed) ends at once
  with status "error" and ``error_code="residency_blocked"``: no LLM call, no
  dispatch (not even a resumed confirmation's tool), no recorder call. Every
  LLM call goes through ``llm_policy.chat`` with the run's residency flag and
  ``llm_max_retries``, so a transient failure is retried on the same client
  with the same context; the agent never passes a user/org id, email or name
  to the client. Every call also passes the run config's ``image_input``
  (GH-189, defence in depth behind the server's refusal): with it off, a
  context holding an image part is refused before the client is called, and
  the run ends with the generic error reply and no ``error_code``.
- Streamed runs and stop (GH-8): with a ``stream`` (an
  ``admino.streaming.RunStream``) every LLM call goes through
  ``llm_policy.chat_stream`` instead: each answer text piece is forwarded to
  ``stream.on_delta`` as it arrives, and each tool-call record to
  ``stream.on_tool_call`` right after it is recorded. ``stream.stop`` is
  checked before every LLM call and every LLM-requested dispatch (not before
  a resumed confirmation's dispatch, which always runs); while an LLM call
  waits for its next item it races the stop, so a stop closes the provider's
  stream at once even when nothing arrives. A dispatch in progress is never
  cancelled: it finishes and is recorded first. A stopped run ends with status
  "stopped", keeping the interrupted call's forwarded text up to its last
  ASCII whitespace as its reply: the unfinished last word is dropped, so a key
  the stop cut short is never stored in part; the reply is stripped of control
  characters and lone surrogates and capped at 65536 characters, so it never
  raises a ``ValidationError`` carrying answer text. Only a content-free "run
  stopped" line with the tool-call count is logged.
  Without a stream the run is exactly the JSON path (``llm_policy.chat``, not
  stoppable).
- Cut answers (GH-25): a final answer (no tool calls) whose
  ``LLMResponse.truncated`` is set (the provider stopped at its output cap,
  or the 65536-character cap dropped text) is cut like a stopped reply, up to
  and including its last ASCII whitespace ("" when it has none). That cut
  text is the response and the assistant message, and the run reports
  ``AgentResult.truncated``; the stream still got every raw piece (the
  server's display deltas drop the cut word). Text before tool calls is never
  cut: it isn't a final answer. A streamed call that fails with the
  ``timeout`` code after it forwarded text keeps that call's text, stripped,
  capped and cut like a stop's, as an assistant message before the error
  reply (none when the cut leaves nothing); any other failure stores the
  error reply only.
- Timings (GH-244, ``admino.request_timing``): every LLM call of a run (its
  retries and their waits included) runs inside ``request_timing.llm_call()``,
  its first item (the JSON response, or a streamed call's first item, before
  that item is forwarded) is marked by ``request_timing.llm_first_byte()``, and
  each tool dispatch (not its recording) runs inside
  ``request_timing.tool_call()``. The hooks see durations only, never the
  call's messages, arguments or results.
- Exceptions from the LLM client are caught and converted into a safe
  "error" AgentResult carrying the ``LLMError``'s ``code`` as ``error_code``
  (None for an uncoded error and any other exception). An ``LLMError`` with
  ``user_facing=True`` carries a fixed, actionable provider message (no
  response body or SDK cause) and becomes the run's response (the API's
  English fallback; the PWA shows the translation of ``error_code``); every
  other exception gets the generic reply. The failure is logged by type, HTTP status and code
  only, never message text. ``MemoryError`` and ``RecursionError`` are
  re-raised (mirroring the registry pattern).
- Malformed LLM output never crashes the loop. A reply the client rejected
  as a whole (a malformed tool call, undecodable or wrong-typed data; GH-25)
  is an ``LLMError`` with the code ``malformed_response``: the run ends like
  any coded failure, with that code and the error's fixed message, and it
  isn't retried. Any other failure (e.g. a validation error on an LLM
  response) gets the generic reply.
- Unknown tools (GH-25, D4): a well-formed ``tool.action`` the registry
  doesn't know is denied by ``dispatch_tool_call`` before the permission
  engine, recorded once as a ``deny`` (the recorder gets the requested
  names), reported as the run's ``deny`` record, and the model gets
  ``Unknown tool: <tool>.<action>`` as its result, so the run goes on.
- ``max_tool_calls`` is a hard cap enforced per-call inside the dispatch
  batch — the loop breaks the moment it is reached, even mid-batch.
- A run's limits come from its own ``agent_config`` (the server builds it
  from the stored platform limits on every request, GH-160) or, without
  one, from the construction-time config; a run's config never outlives it.
- The tools line names only the tool/action pairs advertised in that run's
  tools payload (the registry's names, never LLM output), so it can't reveal
  a pair the run's policy denies or switches off.
- Instructions can't widen what a run may do: they sit in their own
  sections after the base prompt, and every tool call still goes through
  ``dispatch_tool_call`` with the run's policy. No instruction text, language
  or timezone is logged, and no user/org id, email or name is put into the
  prompt.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from secrets import token_urlsafe
from typing import TYPE_CHECKING, Protocol

from admino import context_budget, llm_policy, prompt_assembly, request_timing, untrusted
from admino.llm import LLMError, LLMResponse, strip_control_chars
from admino.models import (
    AgentConfig,
    AgentResult,
    ContextNotice,
    LLMMessage,
    PendingConfirmation,
    PromptContext,
    ToolCall,
    ToolCallRecord,
)
from admino.permissions import PermissionResult
from admino.tenancy import NoTenantContextError, TenantContext
from admino.tools.registry import ToolCallResult, dispatch_tool_call, get_registered_tools
from admino.tools.registry import tools_payload as _tool_descriptions_to_payload

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from uuid import UUID

    from admino.access import Principal
    from admino.llm import LLMClient, LLMStreamDelta
    from admino.models import AttachmentContent, LLMErrorCode, ToolPolicy
    from admino.permissions import PermissionState
    from admino.streaming import RunStream

logger = logging.getLogger(__name__)

_IDENTIFIER_RE: re.Pattern[str] = re.compile(r"[a-z][a-z0-9_]{0,62}")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Generic terminal messages. These are surfaced to users via the chat UI, so
# they must be human-readable but must NOT contain any information derived
# from LLM output, exception details, or tool arguments.
_LIMIT_REACHED_MESSAGE: str = (
    "I could not finish this request within the allowed number of tool calls."
    " Please try breaking it into smaller steps."
)
_LLM_ERROR_MESSAGE: str = (
    "I hit an error while processing your request. Please try again in a moment."
)
_AUDIT_UNAVAILABLE_MESSAGE: str = "Internal error: audit unavailable."
# GH-162: the outcome of a tool call in a run without a tool context (a
# principal without an organization): nothing is dispatched.
_NO_ORG_CONTEXT_MESSAGE: str = "No organization context."
# GH-8/GH-25: a stopped, cut or timed-out reply ends at the last of these (the
# display deltas' word boundary), and is at most as long as a run's response may be.
_ASCII_WHITESPACE: str = " \t\n\r"
_MAX_PARTIAL_REPLY_CHARS: int = 65536


# ---------------------------------------------------------------------------
# Tool-call recorder (the injected audit sink)
# ---------------------------------------------------------------------------


class ToolCallRecorder(Protocol):
    """Audit sink the agent awaits exactly once after every tool dispatch.

    The entry point binds it to storage (``admino.main`` writes an
    ``audit_events`` row in the principal's org); the agent only knows this
    protocol, so it never imports the database layer. Implementations receive
    the run's principal plus content-free metadata only and must raise if the
    record could not be written — the agent then aborts the run (H-1).
    """

    async def __call__(
        self,
        *,
        principal: Principal,
        session_id: str,
        tool: str,
        action: str,
        decision: PermissionState,
        success: bool,
        duration_ms: int,
        escalated: bool,
        attachment_ids: tuple[UUID, ...] = (),
    ) -> None:
        """Record one dispatch outcome.

        Args:
            principal: The logged-in user the run acts for.
            session_id: The run's session identifier.
            tool: Tool name exactly as the LLM requested it (unvalidated).
            action: Action name exactly as the LLM requested it (unvalidated).
            decision: The dispatch's final permission decision.
            success: Whether the tool ran and returned a result.
            duration_ms: Wall-clock duration of the dispatch, milliseconds.
            escalated: Whether dispatch tightened an ``allow`` to ``confirm``
                because the run holds external content (GH-243).
            attachment_ids: The ids of the run's attachments in slot order
                (GH-189). The agent passes it only for a run with attachments.
        """


@dataclass
class _RunReport:
    """What a run reports on every return path besides its outcome (GH-190).

    ``external_content`` is the run's escalation flag (GH-243), reported as
    ``AgentResult.external_content``; ``context_notice`` is the drops of the
    run's last LLM call, made or refused. ``Agent.run`` copies both onto the
    result, so no return path can leave them out. One per run, never shared.
    """

    external_content: bool = False
    context_notice: ContextNotice | None = None


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


class Agent:
    """Orchestrates the LLM-tool loop for a single user message.

    The agent is constructed once per process (or once per request — it is
    cheap and stateless) with its dependencies injected. :meth:`run` is the
    single public entry point and is fully async. It holds no permission
    state: each run brings its org's ``ToolPolicy`` (GH-161).

    Dependencies are injected rather than imported at module level so that:
    (a) tests can substitute fakes trivially, (b) there are no import-time
    side effects, and (c) the security boundary with ``permissions.py`` is
    preserved — the agent only ever passes the run's ``PermissionsConfig``
    through to ``dispatch_tool_call``; it never imports ``check_permission``
    itself.
    """

    def __init__(
        self,
        *,
        llm_client: LLMClient,
        tool_call_recorder: ToolCallRecorder,
        agent_config: AgentConfig,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialise the agent with its collaborators.

        Args:
            llm_client: LLM client implementing the LLMClient protocol.
                Can be AnthropicClient or OpenAIClient.
            tool_call_recorder: Tool-call audit sink, awaited exactly once
                after every ``dispatch_tool_call`` with the run's principal
                and content-free metadata. If it raises, the run aborts (H-1).
            agent_config: Runtime limits (``max_tool_calls``,
                ``max_context_messages``, ``confirmation_timeout_s``) and token
                budget (GH-190) of a run that is given none.
            clock: Returns the current timezone-aware time for the system
                prompt's date line, read once per run (GH-170). None: the
                current UTC time.
        """
        self._llm = llm_client
        self._record_tool_call = tool_call_recorder
        self._config = agent_config
        self._clock: Callable[[], datetime] = partial(datetime.now, UTC) if clock is None else clock

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        user_message: str,
        session_id: str,
        *,
        history: list[LLMMessage],
        principal: Principal,
        tool_policy: ToolPolicy,
        pending_confirmation: PendingConfirmation | None = None,
        agent_config: AgentConfig | None = None,
        prompt_context: PromptContext | None = None,
        earlier_external_content: bool = False,
        stream: RunStream | None = None,
        attachments: Sequence[AttachmentContent] = (),
    ) -> AgentResult:
        """Run the agent loop for a single user message.

        The method appends the user message to a copy of ``history``, then
        enters the LLM/tool loop until the LLM produces plain text, a tool
        call needs confirmation, ``max_tool_calls`` is exhausted, or an error
        occurs. Each LLM call gets the run's system message
        (``prompt_assembly.system_prompt`` over ``prompt_context``, the run's
        advertised tools and the run's clock reading: the same on every call
        of the run) and a window of the history in which the current turn is
        always kept; with ``attachments``, slot 4 opens its user message
        (``prompt_assembly.assemble``). The window is the secondary cap's
        (``max_context_messages``; 0: the whole history), then the newest whole
        earlier turns that fit the token budget beside the instructions, the
        attachments' estimates, the current turn and the reserved output
        (GH-190). When even the current turn doesn't fit, the run ends before
        that call with ``error_code="context_too_long"``. Every tool result
        the run appends is cut to ``max_tool_result_tokens``.

        Args:
            user_message: The user's message text. Must already be validated
                for length by the caller (server layer).
            session_id: Session identifier — propagated to the tool-call
                recorder and tool handlers.
            history: Prior conversation history (caller-owned). The agent
                copies this list; the original is not mutated. Any
                ``system``-role messages in it are dropped.
            principal: The logged-in user the run acts for (required). Passed
                unchanged to the tool-call recorder with every dispatch.
            tool_policy: The requesting org's tool policy (required, GH-161):
                its permissions, promoted tier-2 pairs and enabled services
                decide this run's tools payload, tools line and every
                dispatch; its ``data_residency`` (GH-242) blocks a non-Swiss
                client. It applies to this run only.
            pending_confirmation: If set, a previously-issued confirmation is
                being resumed. The first tool call in this turn is dispatched
                with this value so ``registry.dispatch_tool_call`` can verify
                identity/expiry.
            agent_config: This run's limits (``max_tool_calls``,
                ``max_context_messages``, ``confirmation_timeout_s``,
                ``llm_max_retries``; GH-160/GH-242: the stored platform
                limits) and its token budget (``max_input_tokens``,
                ``reserved_output_tokens``, ``context_margin_percent``,
                ``max_tool_result_tokens``; GH-190). None: the
                construction-time config. Applies to this run only.
            prompt_context: The org's and the user's prompt inputs
                (instructions, response languages, timezone; GH-170), loaded
                by the caller for this request. None: ``PromptContext()``.
            earlier_external_content: True when the conversation held external
                content before ``history`` (GH-176: a persisted chat loads only
                its latest messages, but GH-243 counts the whole conversation).
                The run then escalates allowed side effects to ``confirm`` from
                its first dispatch, the resume pre-dispatch included, exactly
                as for a history holding a wrapped tool result. False: only
                ``history`` and this run's results decide. Applies to this run
                only.
            stream: Streams the run (GH-8): every LLM call goes through
                ``llm_policy.chat_stream``, answer text pieces and tool-call
                records are reported to it as they happen, and setting its
                ``stop`` ends the run with status "stopped" (see the module
                docstring). None: the JSON path, unchanged and not stoppable.
            attachments: The chat's active attachments in slot order (GH-189),
                built by the caller from its own rows and derived files. Non-empty:
                every LLM call carries them as slot 4 of the current user
                message, the run escalates allowed side effects from its first
                dispatch (the resume pre-dispatch included), and every recorder
                call gets their ids; each counts its stored ``token_estimate``
                against every call's budget (GH-190). Empty: the run is exactly
                a run without attachments. Applies to this run only.

        Returns:
            :class:`AgentResult` with the terminal status, the updated
            history (user/assistant/tool messages only — never the system
            message; tool results as cut), a summary of tool calls made during
            the run, for a coded LLM failure (``context_too_long`` included)
            its ``error_code``, and on every return path (GH-190) its
            ``context_notice`` (the last LLM call's dropped earlier turns, made
            or refused; None when it dropped none) and ``external_content``
            (whether the run received external content).
        """
        report = _RunReport()
        # GH-243: one random boundary for the whole run, so every tool result
        # this run wraps carries the same markers and no content can guess them.
        with untrusted.run_boundary():
            result = await self._run_in_boundary(
                user_message,
                session_id,
                report=report,
                history=history,
                principal=principal,
                tool_policy=tool_policy,
                pending_confirmation=pending_confirmation,
                agent_config=agent_config,
                prompt_context=prompt_context,
                earlier_external_content=earlier_external_content,
                stream=stream,
                attachments=attachments,
            )
        return result.model_copy(
            update={
                "external_content": report.external_content,
                "context_notice": report.context_notice,
            }
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run_in_boundary(
        self,
        user_message: str,
        session_id: str,
        *,
        report: _RunReport,
        history: list[LLMMessage],
        principal: Principal,
        tool_policy: ToolPolicy,
        pending_confirmation: PendingConfirmation | None,
        agent_config: AgentConfig | None,
        prompt_context: PromptContext | None,
        earlier_external_content: bool,
        stream: RunStream | None,
        attachments: Sequence[AttachmentContent],
    ) -> AgentResult:
        """Run the agent loop inside the run's untrusted-content boundary (see ``run``).

        ``report`` is filled as the run goes: ``run`` copies it onto the result.
        """
        config = self._config if agent_config is None else agent_config
        # GH-162: the run's tool context, derived once from the principal (never
        # from LLM output or history). A principal without an org (a Super
        # Admin) has none, and then no tool call is dispatched.
        tenant: TenantContext | None
        try:
            tenant = TenantContext.from_principal(principal)
        except NoTenantContextError:
            tenant = None
        # Work on a local copy so we never mutate the caller's list. The
        # system message is NOT stored here: prompt_assembly adds it per LLM
        # call, so the returned history never carries it and it cannot pile
        # up when the caller feeds the history back (GH-140).
        working_history: list[LLMMessage] = _drop_system_messages(history)
        # GH-243: once the run holds external content (a wrapped tool result,
        # here or in an earlier turn of the conversation, e.g. the run that
        # asked for the confirmation being resumed), every side effect the
        # policy allows needs the user's confirmation for the rest of the run.
        # GH-176: a persisted chat passes only its latest messages, so the
        # caller's flag covers external content older than that tail. GH-189:
        # attached files are external content too, from the first dispatch on.
        # GH-190: the same flag is the run's reported ``external_content``, so
        # the caller's sticky chat flag survives a tool result the cut stripped
        # of its marker. The flag and the ids belong to this run (its report and
        # locals), never to the agent, so concurrent and later runs keep their own.
        attachment_ids = tuple(attachment.id for attachment in attachments)
        report.external_content = (
            bool(attachments)
            or earlier_external_content
            or _holds_untrusted_content(working_history)
        )
        # Index of this turn's user message, pinned into every context window.
        # On resume there is no new user message, so the request being resumed
        # (the most recent user message) is pinned instead. None only when the
        # history holds no user message at all.
        current_idx: int | None = next(
            (
                i
                for i in range(len(working_history) - 1, -1, -1)
                if working_history[i].role == "user"
            ),
            None,
        )

        # Resume mode: ``pending_confirmation`` is set, meaning the user just
        # approved a previously-issued confirmation via ``/api/confirm``. In
        # that case there is NO new user message — the "user input" is the
        # approval itself, which is a control-plane action, not a chat turn.
        # Appending an empty user message here would (a) break Anthropic's
        # API contract ("user messages must have non-empty content") and
        # (b) pollute the LLM context with a meaningless empty turn.
        is_resume = pending_confirmation is not None
        if not is_resume:
            current_idx = len(working_history)
            working_history.append(LLMMessage(role="user", content=user_message))

        # H-2: Session-identity check — reject cross-session confirmation replay
        # before anything is dispatched.
        if pending_confirmation is not None and pending_confirmation.session_id != session_id:
            logger.warning("Rejected cross-session pending_confirmation for session %s", session_id)
            return self._terminal_error(
                history=working_history,
                tool_records=[],
                message="Pending confirmation session mismatch.",
            )

        # GH-242: data residency — a residency org never reaches a non-Swiss
        # provider. Checked before anything is dispatched or sent to the LLM.
        try:
            llm_policy.check_residency(self._llm, data_residency=tool_policy.data_residency)
        except LLMError as exc:
            logger.warning("Agent run blocked by data residency (code %s)", exc.code)
            return self._terminal_error(
                history=working_history,
                tool_records=[],
                message=exc.message,
                error_code=exc.code,
            )

        tool_records: list[ToolCallRecord] = []
        tool_calls_used: int = 0
        # GH-77: Advertise only tools the permission engine would NOT deny.
        # Passing the run's permissions + promoted state here (the same values
        # forwarded to dispatch) drops hardcoded-denied and un-promoted tier-2
        # actions from the tool list, so the LLM cannot substitute a sibling
        # action for an unavailable one. The agent still never imports
        # check_permission itself — it only forwards PermissionsConfig.
        descriptions = get_registered_tools(
            enabled_tools=tool_policy.enabled_tools or None,
            permissions_config=tool_policy.permissions,
            promoted=tool_policy.promoted,
        )
        tools_payload: list[dict[str, object]] = _tool_descriptions_to_payload(descriptions)
        # GH-170: the system message's inputs are fixed for the whole run, so
        # every LLM call of it carries the same prompt: the context, the
        # advertised descriptions (GH-161: the tools line names exactly what
        # the run advertises) and one clock reading.
        prompt_inputs = PromptContext() if prompt_context is None else prompt_context
        now = self._clock()
        # GH-190: what every call of the run spends besides its history (the
        # system message and tools payload it sends, the attachments' stored
        # estimates, the reply's reserve) is fixed for the run, and so is the
        # budget it must fit.
        system_text = prompt_assembly.system_prompt(prompt_inputs, tools=descriptions, now=now)
        fixed_tokens = (
            context_budget.prompt_tokens(system_text, tools_payload)
            + sum(attachment.token_estimate for attachment in attachments)
            + config.reserved_output_tokens
        )
        token_limit = context_budget.budget_limit(
            config.max_input_tokens, config.context_margin_percent
        )
        # Carry a one-shot pending_confirmation that is applied to the FIRST
        # dispatch only, then cleared. This matches the server contract:
        # a confirmation resumes exactly one tool call.
        carry_confirmation: PendingConfirmation | None = pending_confirmation

        # Resume pre-dispatch: when resuming, the stored history already
        # contains the assistant turn with the ``tool_use`` block from the
        # previous run. The LLM does not need to be called again to decide
        # what to do — it already said "call this tool". Dispatch the
        # pending tool call directly, append its ``tool_result`` to history,
        # and THEN let the main loop call the LLM with a completed history
        # so the assistant can produce its natural-language follow-up.
        if is_resume and pending_confirmation is not None:
            resumed = await self._resume_pending_dispatch(
                pending_confirmation=pending_confirmation,
                principal=principal,
                tenant=tenant,
                tool_policy=tool_policy,
                session_id=session_id,
                working_history=working_history,
                tool_records=tool_records,
                escalate_side_effects=report.external_content,
                attachment_ids=attachment_ids,
                stream=stream,
                max_tool_result_tokens=config.max_tool_result_tokens,
            )
            if isinstance(resumed, AgentResult):
                # H-1: the resumed dispatch could not be recorded —
                # ``_resume_pending_dispatch`` has already logged and built the
                # terminal error. Return it before any LLM call.
                return resumed
            # GH-190: decided on the FULL result, since the stored one may have
            # been cut past its wrapped block's begin marker.
            report.external_content = report.external_content or untrusted.contains_wrapped(
                resumed.result
            )
            tool_calls_used += 1
            carry_confirmation = None  # consumed on pre-dispatch

        # Bounded loop. Each iteration = one LLM round trip, possibly followed
        # by a batch of tool dispatches.
        for _iteration in range(config.max_tool_calls + 1):
            # GH-8 (a): a stopped run makes no further LLM call.
            if stream is not None and stream.stop.is_set():
                return _stopped(working_history, tool_records, "")
            # 1. GH-190: the secondary cap's window first, then the token budget
            #    keeps its newest whole earlier turns that fit beside the current
            #    turn. Every call re-checks, since the run's results grow it.
            window, window_current = _context_window(
                working_history,
                current_idx=current_idx,
                max_messages=config.max_context_messages,
            )
            fitted = context_budget.fit(
                window, current_idx=window_current, fixed_tokens=fixed_tokens, limit=token_limit
            )
            report.context_notice = (
                ContextNotice(
                    dropped_turns=fitted.dropped_turns, dropped_messages=fitted.dropped_messages
                )
                if fitted.dropped_turns
                else None
            )
            if not fitted.fits:
                # Even the current turn doesn't fit: no LLM call is made for it.
                logger.warning(
                    "Agent run refused before its LLM call: context too long"
                    " (%d of %d tokens, %d tool calls)",
                    fitted.used,
                    token_limit,
                    len(tool_records),
                )
                return self._terminal_error(
                    history=working_history,
                    tool_records=tool_records,
                    message=context_budget.CONTEXT_TOO_LONG_MESSAGE,
                    error_code="context_too_long",
                )
            context = prompt_assembly.assemble(
                prompt_inputs,
                tools=descriptions,
                now=now,
                history=fitted.messages,
                # GH-189: slot 4 opens the context's current user message on
                # every call; the history itself keeps the user's text.
                attachments=attachments,
            )
            # The text this call forwards to the stream (a streamed call only), kept
            # so a timeout can store it (GH-25, D9).
            forwarded: list[str] = []
            try:
                # GH-242: the model policy (residency guard + bounded retries on
                # this same client with this same context).
                reply: LLMResponse | str
                with request_timing.llm_call():
                    if stream is None:
                        reply = await llm_policy.chat(
                            self._llm,
                            context,
                            tools_payload,
                            data_residency=tool_policy.data_residency,
                            max_retries=config.llm_max_retries,
                            image_input=config.image_input,
                        )
                        request_timing.llm_first_byte()
                    else:
                        reply = await self._stream_reply(
                            context,
                            tools_payload,
                            stream=stream,
                            forwarded=forwarded,
                            data_residency=tool_policy.data_residency,
                            max_retries=config.llm_max_retries,
                            image_input=config.image_input,
                        )
            except (MemoryError, RecursionError):
                raise
            except Exception as exc:
                # Logged by type (and, for an LLMError, its HTTP status and
                # code) only, never a message: no provider text reaches the log
                # (GH-158). A user-facing LLMError carries a fixed, actionable
                # message (e.g. "set INFOMANIAK_API_TOKEN") that becomes the
                # response (the PWA shows the code's translation instead);
                # every other failure gets the generic reply.
                message = _LLM_ERROR_MESSAGE
                error_code: LLMErrorCode | None = None
                if isinstance(exc, LLMError):
                    logger.error(
                        "LLM chat call failed: %s (status %s, code %s)",
                        type(exc).__name__,
                        exc.status_code,
                        exc.code,
                    )
                    if exc.user_facing:
                        message = exc.message
                    error_code = exc.code
                    # GH-25 (D9): a timeout keeps the text its call already showed, cut
                    # like a stop's, before the error reply. Other failures keep none.
                    if exc.code == "timeout":
                        partial = _partial_reply("".join(forwarded))
                        if partial:
                            working_history.append(LLMMessage(role="assistant", content=partial))
                else:
                    logger.error("LLM chat call failed: %s", type(exc).__name__)
                return self._terminal_error(
                    history=working_history,
                    tool_records=tool_records,
                    message=message,
                    error_code=error_code,
                )
            if isinstance(reply, str):
                # GH-8 (b): stopped during the call; its forwarded text, cut, is the reply.
                return _stopped(working_history, tool_records, reply)
            response = reply

            # 2. Text-only response → we are done.
            if not response.tool_calls:
                assistant_text = response.content or ""
                if response.truncated:
                    # GH-25 (D7): an answer an output cap cut ends like a stopped
                    # one, so a key cut short is never returned or stored in part.
                    assistant_text = _to_last_word(assistant_text)
                working_history.append(LLMMessage(role="assistant", content=assistant_text))
                return AgentResult(
                    status="final",
                    response=assistant_text,
                    history=working_history,
                    tool_calls=tool_records,
                    truncated=response.truncated,
                )

            # 3. LLM requested tool calls. Dispatch each one, honouring the
            #    global max_tool_calls cap. If a call comes back pending
            #    confirmation, short-circuit — the caller will resume us.
            batch: list[ToolCall] = response.tool_calls
            # Record the assistant's tool-call turn in history. Include the
            # tool_use_blocks so that providers requiring structured content in
            # the assistant message (Anthropic) can reconstruct the proper
            # tool_use / tool_result pairing; the OpenAI-compatible serializer
            # replays them as tool_calls so each tool result answers its call.
            working_history.append(
                LLMMessage(
                    role="assistant",
                    content=response.content or "",
                    tool_use_blocks=[
                        {
                            "type": "tool_use",
                            "id": tc.tool_call_id,
                            "name": f"{tc.tool}.{tc.action}",
                            "input": tc.args,
                        }
                        for tc in response.tool_calls
                        if tc.tool_call_id
                    ]
                    or None,
                )
            )

            for tool_call in batch:
                # GH-8 (c): a stop leaves this call and the rest of the batch
                # undispatched (a dispatch in progress was never interrupted).
                if stream is not None and stream.stop.is_set():
                    return _stopped(working_history, tool_records, "")
                if tool_calls_used >= config.max_tool_calls:
                    # Hard cap reached mid-batch — stop immediately.
                    return self._terminal_limit(
                        history=working_history,
                        tool_records=tool_records,
                    )

                dispatched = await self._dispatch_one(
                    tool_call=tool_call,
                    principal=principal,
                    tenant=tenant,
                    tool_policy=tool_policy,
                    session_id=session_id,
                    pending_confirmation=carry_confirmation,
                    escalate_side_effects=report.external_content,
                    attachment_ids=attachment_ids,
                )
                if dispatched is None:
                    # H-1: the dispatch could not be recorded — abort before
                    # any further dispatch, LLM call or confirmation request.
                    return _audit_unavailable(working_history, tool_records)
                result, dispatch_duration_ms = dispatched
                carry_confirmation = None  # consumed on the first dispatch
                # GH-243: from here on, later calls (this batch's included)
                # are escalated once a result carried external content. GH-190:
                # judged on the FULL result, before the cut below.
                report.external_content = report.external_content or untrusted.contains_wrapped(
                    result.result
                )
                # M-4 design note: EVERY dispatch (including denied and
                # validation-failed calls) counts against the cap.  This is
                # intentional — it prevents the LLM from cheaply probing
                # many denied tools to map the permission surface.  Trade-off:
                # an adversarial LLM could exhaust the budget without executing
                # any real tools.  The conservative choice is correct here.
                tool_calls_used += 1

                await _keep_record(
                    tool_records,
                    ToolCallRecord(
                        tool=_safe_identifier(tool_call.tool),
                        action=_safe_identifier(tool_call.action),
                        args=tool_call.args,
                        permission=result.permission.allowed,
                        success=result.success,
                        duration_ms=dispatch_duration_ms,
                    ),
                    stream,
                )

                # Confirmation required and none carried → short-circuit.
                # _dispatch_one has already recorded the confirm outcome.
                if (
                    result.permission.allowed == "confirm"
                    and not result.success
                    and result.pending_confirmation is None
                ):
                    # Build a PendingConfirmation object for the caller so
                    # they can persist it and resume later. Registry does not
                    # currently synthesise one on the "no confirmation
                    # supplied" path; we construct it here from the tool call
                    # plus the configured timeout.
                    pending = _build_pending_confirmation(
                        tool_call=tool_call,
                        session_id=session_id,
                        timeout_s=config.confirmation_timeout_s,
                    )
                    return AgentResult(
                        status="awaiting_confirmation",
                        response=result.result,
                        history=working_history,
                        tool_calls=tool_records,
                        pending_confirmation=pending,
                    )

                # Feed the tool result back to the LLM as a tool-role message.
                # Carry tool_call_id from the ToolCall so Anthropic/OpenAI can
                # link the result to the originating tool_use/tool_call block.
                # GH-190: a result over the cap is sent and stored cut.
                working_history.append(
                    LLMMessage(
                        role="tool",
                        content=context_budget.truncate_tool_result(
                            result.result, config.max_tool_result_tokens
                        ),
                        tool_call_id=tool_call.tool_call_id,
                    )
                )

            # After the batch, loop back for another LLM turn unless the cap
            # has been reached.
            if tool_calls_used >= config.max_tool_calls:
                # Give the LLM one final chance to summarise, OR, if we have
                # already done so once, terminate. The simplest safe choice
                # is to terminate here — the LLM may otherwise issue more
                # tool calls we cannot honour.
                return self._terminal_limit(
                    history=working_history,
                    tool_records=tool_records,
                )

        # Defensive fallthrough: the for-range loop bound means we should
        # never reach here, but if we do, treat as limit reached.
        return self._terminal_limit(
            history=working_history,
            tool_records=tool_records,
        )

    async def _stream_reply(
        self,
        context: list[LLMMessage],
        tools_payload: list[dict[str, object]],
        *,
        stream: RunStream,
        forwarded: list[str],
        data_residency: bool,
        max_retries: int,
        image_input: bool,
    ) -> LLMResponse | str:
        """Make one LLM call through ``llm_policy.chat_stream``, reporting its text to ``stream``.

        Each delta's text goes to ``stream.on_delta`` in order as it arrives,
        and is first appended to ``forwarded`` (the caller's empty list), so the
        caller still has it when the call raises. The wait for the next item
        races ``stream.stop``: a stop cancels the pending read at once (also
        while the provider sends nothing), and a stop set between items ends the
        call before the next read. The stream is closed however the call ends.

        Returns:
            The final ``LLMResponse``, used like ``chat()``'s; or, once stopped
            first, the text forwarded so far (its tool calls are dropped).

        Raises:
            Whatever the policy stream raises (the caller ends the run as for a
            failed ``chat()``); deltas already forwarded stay forwarded.
        """
        items = llm_policy.chat_stream(
            self._llm,
            context,
            tools_payload,
            data_residency=data_residency,
            max_retries=max_retries,
            image_input=image_input,
        )
        stopped = asyncio.ensure_future(stream.stop.wait())
        read: asyncio.Future[LLMStreamDelta | LLMResponse] | None = None
        try:
            while not stream.stop.is_set():
                read = asyncio.ensure_future(anext(items))
                await asyncio.wait((read, stopped), return_when=asyncio.FIRST_COMPLETED)
                if not read.done():
                    break
                item = read.result()
                if not forwarded:
                    # Nothing forwarded yet, so this is the call's first item
                    # (a delta, or the final response, which returns at once).
                    request_timing.llm_first_byte()
                if isinstance(item, LLMResponse):
                    return item
                forwarded.append(item.content)
                await stream.on_delta(item.content)
            return "".join(forwarded)
        finally:
            stopped.cancel()
            if read is not None and not read.done():
                read.cancel()
                # Let the cancelled read unwind the provider stream before closing
                # it. What it ended with no longer matters (the call was stopped),
                # so it is read and dropped rather than logged by asyncio.
                await asyncio.wait((read,))
                if not read.cancelled():
                    read.exception()
            await items.aclose()

    async def _dispatch_one(
        self,
        *,
        tool_call: ToolCall,
        principal: Principal,
        tenant: TenantContext | None,
        tool_policy: ToolPolicy,
        session_id: str,
        pending_confirmation: PendingConfirmation | None,
        escalate_side_effects: bool,
        attachment_ids: tuple[UUID, ...],
    ) -> tuple[ToolCallResult, int] | None:
        """Dispatch a single tool call via the registry, then record it.

        The dispatch is decided by the run's ``tool_policy`` (permissions,
        promoted pairs, enabled services) and ``escalate_side_effects`` (the
        run holds external content, GH-243: the registry then turns an
        allowed side effect into ``confirm``), and the handler gets the run's
        ``tenant`` (GH-162). Without a tool context nothing is dispatched: the
        outcome is a fixed "No organization context." deny. The one place
        that times a dispatch and awaits the recorder, so no call site can
        dispatch without recording. The recorder gets the run's
        principal, the raw tool/action names the LLM asked for, the final
        decision, the success flag, the duration and the escalated flag, plus
        the run's ``attachment_ids`` when it has any (GH-189); never
        arguments, output or error text.

        Returns:
            ``(result, duration_ms)`` once the outcome is recorded, or
            ``None`` if the recorder raised (H-1) — the caller must then
            abort the run. Only the exception type is logged, never its
            message.
        """
        start = time.monotonic()
        if tenant is None:
            result = ToolCallResult(
                success=False,
                result=_NO_ORG_CONTEXT_MESSAGE,
                permission=PermissionResult(allowed="deny", reason=_NO_ORG_CONTEXT_MESSAGE),
            )
        else:
            # The dispatch only: the recorder's write below isn't tool time.
            with request_timing.tool_call():
                result = await dispatch_tool_call(
                    tool_call,
                    tool_policy.permissions,
                    session_id=session_id,
                    tenant=tenant,
                    pending_confirmation=pending_confirmation,
                    promoted=tool_policy.promoted,
                    enabled_tools=tool_policy.enabled_tools or None,
                    escalate_side_effects=escalate_side_effects,
                )
        duration_ms = int((time.monotonic() - start) * 1000)
        # GH-189: a run without attachments records exactly today's keywords.
        attachments_kwarg = {"attachment_ids": attachment_ids} if attachment_ids else {}
        try:
            await self._record_tool_call(
                principal=principal,
                session_id=session_id,
                tool=tool_call.tool,
                action=tool_call.action,
                decision=result.permission.allowed,
                success=result.success,
                duration_ms=duration_ms,
                escalated=result.escalated,
                **attachments_kwarg,
            )
        except (MemoryError, RecursionError):
            raise
        except Exception as exc:
            logger.error("Tool-call audit record failed (%s) — aborting run", type(exc).__name__)
            return None
        return result, duration_ms

    async def _resume_pending_dispatch(
        self,
        *,
        pending_confirmation: PendingConfirmation,
        principal: Principal,
        tenant: TenantContext | None,
        tool_policy: ToolPolicy,
        session_id: str,
        working_history: list[LLMMessage],
        tool_records: list[ToolCallRecord],
        escalate_side_effects: bool,
        attachment_ids: tuple[UUID, ...],
        stream: RunStream | None,
        max_tool_result_tokens: int,
    ) -> ToolCallResult | AgentResult:
        """Resume an approved pending confirmation by dispatching the tool call.

        Called once at the top of ``run()`` when resuming. Dispatches the
        tool call stored inside ``pending_confirmation`` through the registry
        (which verifies tool/action/args identity and expiry one more time),
        with the run's ``escalate_side_effects`` (GH-243: an escalated call
        stays an escalated ``confirm``) and ``attachment_ids`` (GH-189, for
        the recorder), appends the resulting
        ``tool_result`` to ``working_history`` (GH-190: cut to
        ``max_tool_result_tokens``), and records the call in
        ``tool_records`` (reported to ``stream`` when the run is streamed).

        Returns the dispatch's full, uncut result on success (the caller
        judges escalation on it), or a terminal ``AgentResult`` if the
        dispatch could not be recorded (H-1) — in which case the caller must
        return it immediately, before any LLM call.

        The caller is responsible for bumping ``tool_calls_used`` and
        clearing ``carry_confirmation`` after a successful return.
        """
        tool_call = pending_confirmation.tool_call
        dispatched = await self._dispatch_one(
            tool_call=tool_call,
            principal=principal,
            tenant=tenant,
            tool_policy=tool_policy,
            session_id=session_id,
            pending_confirmation=pending_confirmation,
            escalate_side_effects=escalate_side_effects,
            attachment_ids=attachment_ids,
        )
        if dispatched is None:
            return _audit_unavailable(working_history, tool_records)
        result, dispatch_duration_ms = dispatched

        await _keep_record(
            tool_records,
            ToolCallRecord(
                tool=_safe_identifier(tool_call.tool),
                action=_safe_identifier(tool_call.action),
                args=tool_call.args,
                permission=result.permission.allowed,
                success=result.success,
                duration_ms=dispatch_duration_ms,
            ),
            stream,
        )

        # Append the tool_result so the next LLM call sees a well-formed
        # history: [..., assistant(tool_use), tool(tool_result)].
        working_history.append(
            LLMMessage(
                role="tool",
                content=context_budget.truncate_tool_result(result.result, max_tool_result_tokens),
                tool_call_id=tool_call.tool_call_id,
            )
        )
        return result

    def _terminal_limit(
        self,
        *,
        history: list[LLMMessage],
        tool_records: list[ToolCallRecord],
    ) -> AgentResult:
        """Build the terminal "limit reached" result."""
        history.append(LLMMessage(role="assistant", content=_LIMIT_REACHED_MESSAGE))
        logger.info(
            "Agent run terminated: max_tool_calls reached (%d tool calls)",
            len(tool_records),
        )
        return AgentResult(
            status="limit_reached",
            response=_LIMIT_REACHED_MESSAGE,
            history=history,
            tool_calls=tool_records,
        )

    def _terminal_error(
        self,
        *,
        history: list[LLMMessage],
        tool_records: list[ToolCallRecord],
        message: str,
        error_code: LLMErrorCode | None = None,
    ) -> AgentResult:
        """Build a terminal error result with a safe message and its LLM error code."""
        history.append(LLMMessage(role="assistant", content=message))
        # L-3: Log a "run terminated" message mirroring _terminal_limit.
        logger.info("Agent run terminated: error (%d tool calls)", len(tool_records))
        return AgentResult(
            status="error",
            response=message,
            history=history,
            tool_calls=tool_records,
            error_code=error_code,
        )


# ---------------------------------------------------------------------------
# Module-level helpers (pure functions, unit-testable)
# ---------------------------------------------------------------------------


def _drop_system_messages(history: list[LLMMessage]) -> list[LLMMessage]:
    """Return a copy of caller-supplied ``history`` without ``system`` messages.

    The agent is the only source of system content (the run's assembled
    prompt, added per LLM call by ``prompt_assembly.assemble``).
    A ``system`` message in caller history — leading or mid-conversation — is
    either a stale copy of that message or persisted prompt injection, so all
    of them are dropped.
    When any are dropped, one WARNING with the count only is logged; message
    content is never logged.
    """
    kept = [msg for msg in history if msg.role != "system"]
    dropped = len(history) - len(kept)
    if dropped:
        logger.warning("Dropped %d system-role message(s) from caller-supplied history", dropped)
    return kept


def _holds_untrusted_content(history: list[LLMMessage]) -> bool:
    """Return whether a ``tool``-role message of ``history`` holds wrapped external content.

    The whole history counts, not only the window the LLM is sent: content
    that has scrolled out of the context may still have shaped the turn.
    """
    return any(
        message.role == "tool"
        and isinstance(message.content, str)
        and untrusted.contains_wrapped(message.content)
        for message in history
    )


def _context_window(
    history: list[LLMMessage],
    *,
    current_idx: int | None,
    max_messages: int,
) -> tuple[list[LLMMessage], int]:
    """Return the history part of one LLM call's context before the token budget.

    ``history`` must hold no ``system`` messages (see
    :func:`_drop_system_messages`). With a cap (``max_messages`` > 0, the
    secondary cap of GH-190), ``prompt_assembly.assemble`` puts the run's
    system message before the window, so ``max_messages`` counts it. The
    window is then:

    - the current user message ``history[current_idx]``, exactly once — the
      system message and this message are the floor and are always sent, even
      when they alone exceed ``max_messages``;
    - the most recent other messages, in chronological order, filling the
      remaining budget via :func:`_trim_context` (which also drops leading
      orphaned ``tool`` results).

    The pinned message goes back to its chronological position: a window that
    reaches into the messages before it holds every message after it, and the
    first message after it is the assistant turn answering it, so no orphaned
    ``tool`` result can follow it.

    Without a cap (``max_messages`` 0) the window is the whole history without
    its leading ``tool`` messages: a loaded history can start with results
    whose assistant call lies before the load limit, and a result is never
    sent without its call.

    ``current_idx`` is ``None`` only on a resumed confirmation whose history
    holds no user message (the request lies before the load limit): every
    message of it then comes after the request, so the whole window is the
    current turn.

    Returns:
        The window and the index in it where the current turn starts (the
        current user message; 0 when ``current_idx`` is None).
    """
    if max_messages == 0:
        start = 0
        while start < len(history) and history[start].role == "tool":
            start += 1
        return history[start:], 0 if current_idx is None else current_idx - start
    budget = max_messages - 1  # the system message
    if current_idx is None:
        # Guard budget <= 0 so _trim_context does not emit its L-5 warning.
        return (_trim_context(history, budget) if budget > 0 else []), 0
    pinned = history[current_idx]
    after = history[current_idx + 1 :]
    budget -= 1  # the pinned message
    tail = _trim_context(history[:current_idx] + after, budget) if budget > 0 else []
    insert_at = max(0, len(tail) - len(after))
    return [*tail[:insert_at], pinned, *tail[insert_at:]], insert_at


def _trim_context(history: list[LLMMessage], max_messages: int) -> list[LLMMessage]:
    """Return the tail of ``history`` bounded by ``max_messages``.

    System messages at the head of history are preserved; only non-system
    messages are trimmed from the middle/front. The agent calls this via
    :func:`_context_window` on history that is already free of system
    messages, so there it simply keeps the most recent messages; the
    system-message handling here is defence in depth.

    M-1 defence: any ``system``-role message found AFTER the leading block
    is dropped with a warning. Mid-conversation ``system`` messages could
    originate from tainted caller-supplied history (e.g. prompt injection
    persisted across turns) and must not ride through as trusted
    instructions.
    """
    # Split off leading system messages — these are always preserved.
    leading_system: list[LLMMessage] = []
    idx = 0
    for msg in history:
        if msg.role == "system":
            leading_system.append(msg)
            idx += 1
        else:
            break
    rest = history[idx:]
    # M-1: drop mid-conversation system messages from rest.
    rest = _filter_mid_system(rest)

    if len(leading_system) + len(rest) <= max_messages:
        return leading_system + rest
    budget = max_messages - len(leading_system)
    if budget <= 0:
        # L-5: Pathological case — more system messages than the budget.
        # Return just the system messages (trimmed) and warn.
        logger.warning(
            "Context budget (%d) exhausted by %d leading system messages",
            max_messages,
            len(leading_system),
        )
        return leading_system[:max_messages]
    trimmed = rest[-budget:]
    # Most LLMs require every tool_result to reference a tool_use block in
    # the immediately preceding assistant message. If the trim boundary
    # falls between an assistant tool_use and its tool_result responses, the
    # orphaned tool_result messages at the start would cause a 400 error.
    # Drop any leading tool-role messages that lost their assistant parent.
    while trimmed and trimmed[0].role == "tool":
        trimmed.pop(0)
    return leading_system + trimmed


def _filter_mid_system(messages: list[LLMMessage]) -> list[LLMMessage]:
    """Remove any ``system``-role messages from a non-leading position.

    :func:`_trim_context` only keeps system messages at the very start of
    its input. Any system-role message that appears mid-conversation (e.g. from a
    tainted persisted history) is silently dropped with a warning.
    """
    filtered: list[LLMMessage] = []
    for msg in messages:
        if msg.role == "system":
            logger.warning("Dropped mid-conversation system-role message from context")
        else:
            filtered.append(msg)
    return filtered


def _safe_identifier(value: str) -> str:
    """Return ``value`` if it matches the identifier pattern, else a placeholder.

    Used when populating :class:`ToolCallRecord`, whose ``tool``/``action``
    fields enforce the same pattern as the permission engine. A malformed
    identifier from the LLM would otherwise raise a ValidationError during
    result construction.
    """
    if _IDENTIFIER_RE.fullmatch(value):
        return value
    return "invalid"


def _audit_unavailable(
    history: list[LLMMessage], tool_records: list[ToolCallRecord]
) -> AgentResult:
    """Build the H-1 terminal result for a dispatch the recorder failed to record.

    Carries the fixed :data:`_AUDIT_UNAVAILABLE_MESSAGE` and never a
    ``pending_confirmation``: an unaudited confirmation request is not handed
    to the caller.
    """
    return AgentResult(
        status="error",
        response=_AUDIT_UNAVAILABLE_MESSAGE,
        history=history,
        tool_calls=tool_records,
    )


async def _keep_record(
    tool_records: list[ToolCallRecord], record: ToolCallRecord, stream: RunStream | None
) -> None:
    """Append a dispatch's record to the run's records, then report it to a streamed run."""
    tool_records.append(record)
    if stream is not None:
        await stream.on_tool_call(record)


def _to_last_word(text: str) -> str:
    """Return ``text`` up to and including its last ASCII whitespace ("" when it has none).

    The cut of an answer that didn't end as the model meant it (GH-8: a stop;
    GH-25: an output cap, a timeout): its unfinished last word is dropped, as
    the stream's display deltas drop it, so a key cut short of its format's
    length (which no credential rule matches) is never stored or shown in part.
    """
    return text[: max(text.rfind(char) for char in _ASCII_WHITESPACE) + 1]


def _partial_reply(forwarded: str) -> str:
    """Return what is kept of an interrupted LLM call's forwarded text (a stop, a timeout).

    Control characters and lone surrogates are stripped and the text capped
    first (the stream's deltas bypass ``LLMResponse`` validation), so the
    message built from it never raises a ``ValidationError`` carrying answer
    text; then it is cut by :func:`_to_last_word`.
    """
    return _to_last_word(strip_control_chars(forwarded)[:_MAX_PARTIAL_REPLY_CHARS])


def _stopped(
    history: list[LLMMessage], tool_records: list[ToolCallRecord], forwarded: str
) -> AgentResult:
    """Build the result of a run the user stopped (GH-8).

    ``forwarded`` is the text the interrupted LLM call forwarded ("" when the
    stop came between calls or dispatches); the reply is its
    :func:`_partial_reply`. A non-empty reply also ends the history as a plain
    assistant message (the call's tool calls are dropped).
    """
    response = _partial_reply(forwarded)
    if response:
        history.append(LLMMessage(role="assistant", content=response))
    logger.info("Agent run stopped (%d tool calls)", len(tool_records))
    return AgentResult(
        status="stopped",
        response=response,
        history=history,
        tool_calls=tool_records,
    )


def _build_pending_confirmation(
    *,
    tool_call: ToolCall,
    session_id: str,
    timeout_s: float,
) -> PendingConfirmation:
    """Construct a :class:`PendingConfirmation` for the caller to persist.

    The confirmation_id is a cryptographically-random URL-safe token.
    ``expires_at`` is derived from trusted ``AgentConfig.confirmation_timeout_s``,
    never from LLM input.
    """
    now = datetime.now(UTC)
    # Pattern enforces alphanumeric+_-; token_urlsafe produces URL-safe base64
    # which includes '-' and '_' but no '+' or '/'.
    confirmation_id = token_urlsafe(16)
    return PendingConfirmation(
        confirmation_id=confirmation_id,
        session_id=session_id,
        tool_call=tool_call,
        created_at=now,
        expires_at=now + timedelta(seconds=timeout_s),
    )
