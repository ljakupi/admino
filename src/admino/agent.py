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
  the date line. There is no startup-built prompt.
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
  decision, the success flag and the dispatch duration — never argument
  values, tool output or error text. Conversation content is not audited.
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
  to the client.
- Exceptions from the LLM client are caught and converted into a safe
  "error" AgentResult carrying the ``LLMError``'s ``code`` as ``error_code``
  (None for an uncoded error and any other exception). An ``LLMError`` with
  ``user_facing=True`` carries a fixed, actionable provider message (no
  response body or SDK cause) and becomes the run's response (the API's
  English fallback; the PWA shows the translation of ``error_code``); every
  other exception gets the generic reply. The failure is logged by type, HTTP status and code
  only, never message text. ``MemoryError`` and ``RecursionError`` are
  re-raised (mirroring the registry pattern).
- Malformed LLM output (e.g. validation errors on LLM responses) is
  converted to an assistant message with a generic note and returned —
  never crashes the loop.
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

import logging
import re
import time
from datetime import UTC, datetime, timedelta
from functools import partial
from secrets import token_urlsafe
from typing import TYPE_CHECKING, Protocol

from admino import llm_policy, prompt_assembly
from admino.llm import LLMError
from admino.models import (
    AgentConfig,
    AgentResult,
    LLMMessage,
    PendingConfirmation,
    PromptContext,
    ToolCall,
    ToolCallRecord,
)
from admino.permissions import PermissionResult
from admino.tenancy import NoTenantContextError, TenantContext
from admino.tools.registry import ToolCallResult, dispatch_tool_call, get_registered_tools

if TYPE_CHECKING:
    from collections.abc import Callable

    from admino.access import Principal
    from admino.llm import LLMClient
    from admino.models import LLMErrorCode, ToolPolicy
    from admino.permissions import PermissionState
    from admino.tools.registry import ToolDescription

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
        """


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
                ``max_context_messages``, ``confirmation_timeout_s``) of a run
                that is given none.
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
    ) -> AgentResult:
        """Run the agent loop for a single user message.

        The method appends the user message to a copy of ``history``, then
        enters the LLM/tool loop until the LLM produces plain text, a tool
        call needs confirmation, ``max_tool_calls`` is exhausted, or an error
        occurs. Each LLM call gets the run's system message
        (``prompt_assembly.system_prompt`` over ``prompt_context``, the run's
        advertised tools and the run's clock reading: the same on every call
        of the run) and a trimmed window of the history in which the current
        user message is always kept.

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
                limits). None: the construction-time config. Applies to this
                run only.
            prompt_context: The org's and the user's prompt inputs
                (instructions, response languages, timezone; GH-170), loaded
                by the caller for this request. None: ``PromptContext()``.

        Returns:
            :class:`AgentResult` with the terminal status, the updated
            history (user/assistant/tool messages only — never the system
            message), a summary of tool calls made during the run and, for a
            coded LLM failure, its ``error_code``.
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
            pre_result = await self._resume_pending_dispatch(
                pending_confirmation=pending_confirmation,
                principal=principal,
                tenant=tenant,
                tool_policy=tool_policy,
                session_id=session_id,
                working_history=working_history,
                tool_records=tool_records,
            )
            if pre_result is not None:
                # H-1: the resumed dispatch could not be recorded —
                # ``_resume_pending_dispatch`` has already logged and built the
                # terminal error. Return it before any LLM call.
                return pre_result
            tool_calls_used += 1
            carry_confirmation = None  # consumed on pre-dispatch

        # Bounded loop. Each iteration = one LLM round trip, possibly followed
        # by a batch of tool dispatches.
        for _iteration in range(config.max_tool_calls + 1):
            # 1. Call the LLM with the system message + a trimmed context window.
            context = prompt_assembly.assemble(
                prompt_inputs,
                tools=descriptions,
                now=now,
                history=_context_window(
                    working_history,
                    current_idx=current_idx,
                    max_messages=config.max_context_messages,
                ),
            )
            try:
                # GH-242: the model policy (residency guard + bounded retries on
                # this same client with this same context).
                response = await llm_policy.chat(
                    self._llm,
                    context,
                    tools_payload,
                    data_residency=tool_policy.data_residency,
                    max_retries=config.llm_max_retries,
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
                reply = _LLM_ERROR_MESSAGE
                error_code: LLMErrorCode | None = None
                if isinstance(exc, LLMError):
                    logger.error(
                        "LLM chat call failed: %s (status %s, code %s)",
                        type(exc).__name__,
                        exc.status_code,
                        exc.code,
                    )
                    if exc.user_facing:
                        reply = exc.message
                    error_code = exc.code
                else:
                    logger.error("LLM chat call failed: %s", type(exc).__name__)
                return self._terminal_error(
                    history=working_history,
                    tool_records=tool_records,
                    message=reply,
                    error_code=error_code,
                )

            # 2. Text-only response → we are done.
            if not response.tool_calls:
                assistant_text = response.content or ""
                working_history.append(LLMMessage(role="assistant", content=assistant_text))
                return AgentResult(
                    status="final",
                    response=assistant_text,
                    history=working_history,
                    tool_calls=tool_records,
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
                )
                if dispatched is None:
                    # H-1: the dispatch could not be recorded — abort before
                    # any further dispatch, LLM call or confirmation request.
                    return _audit_unavailable(working_history, tool_records)
                result, dispatch_duration_ms = dispatched
                carry_confirmation = None  # consumed on the first dispatch
                # M-4 design note: EVERY dispatch (including denied and
                # validation-failed calls) counts against the cap.  This is
                # intentional — it prevents the LLM from cheaply probing
                # many denied tools to map the permission surface.  Trade-off:
                # an adversarial LLM could exhaust the budget without executing
                # any real tools.  The conservative choice is correct here.
                tool_calls_used += 1

                tool_records.append(
                    ToolCallRecord(
                        tool=_safe_identifier(tool_call.tool),
                        action=_safe_identifier(tool_call.action),
                        args=tool_call.args,
                        permission=result.permission.allowed,
                        success=result.success,
                        duration_ms=dispatch_duration_ms,
                    )
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
                working_history.append(
                    LLMMessage(
                        role="tool",
                        content=result.result,
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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _dispatch_one(
        self,
        *,
        tool_call: ToolCall,
        principal: Principal,
        tenant: TenantContext | None,
        tool_policy: ToolPolicy,
        session_id: str,
        pending_confirmation: PendingConfirmation | None,
    ) -> tuple[ToolCallResult, int] | None:
        """Dispatch a single tool call via the registry, then record it.

        The dispatch is decided by the run's ``tool_policy`` (permissions,
        promoted pairs, enabled services), and the handler gets the run's
        ``tenant`` (GH-162). Without a tool context nothing is dispatched: the
        outcome is a fixed "No organization context." deny. The one place
        that times a dispatch and awaits the recorder, so no call site can
        dispatch without recording. The recorder gets the run's
        principal, the raw tool/action names the LLM asked for, the final
        decision, the success flag and the duration — never arguments, output
        or error text.

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
            result = await dispatch_tool_call(
                tool_call,
                tool_policy.permissions,
                session_id=session_id,
                tenant=tenant,
                pending_confirmation=pending_confirmation,
                promoted=tool_policy.promoted,
                enabled_tools=tool_policy.enabled_tools or None,
            )
        duration_ms = int((time.monotonic() - start) * 1000)
        try:
            await self._record_tool_call(
                principal=principal,
                session_id=session_id,
                tool=tool_call.tool,
                action=tool_call.action,
                decision=result.permission.allowed,
                success=result.success,
                duration_ms=duration_ms,
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
    ) -> AgentResult | None:
        """Resume an approved pending confirmation by dispatching the tool call.

        Called once at the top of ``run()`` when resuming. Dispatches the
        tool call stored inside ``pending_confirmation`` through the registry
        (which verifies tool/action/args identity and expiry one more time),
        appends the resulting ``tool_result`` to ``working_history``, and
        records the call in ``tool_records``.

        Returns ``None`` on success, or a terminal ``AgentResult`` if the
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
        )
        if dispatched is None:
            return _audit_unavailable(working_history, tool_records)
        result, dispatch_duration_ms = dispatched

        tool_records.append(
            ToolCallRecord(
                tool=_safe_identifier(tool_call.tool),
                action=_safe_identifier(tool_call.action),
                args=tool_call.args,
                permission=result.permission.allowed,
                success=result.success,
                duration_ms=dispatch_duration_ms,
            )
        )

        # Append the tool_result so the next LLM call sees a well-formed
        # history: [..., assistant(tool_use), tool(tool_result)].
        working_history.append(
            LLMMessage(
                role="tool",
                content=result.result,
                tool_call_id=tool_call.tool_call_id,
            )
        )
        return None

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


def _context_window(
    history: list[LLMMessage],
    *,
    current_idx: int | None,
    max_messages: int,
) -> list[LLMMessage]:
    """Return the history part of one LLM call's context.

    ``history`` must hold no ``system`` messages (see
    :func:`_drop_system_messages`). ``prompt_assembly.assemble`` puts the
    run's system message before the result, so ``max_messages`` counts it.
    The result is:

    - the current user message ``history[current_idx]``, exactly once — the
      system message and this message are the floor and are always sent, even
      when they alone exceed ``max_messages``;
    - the most recent other messages, in chronological order, filling the
      remaining budget via :func:`_trim_context` (which also drops leading
      orphaned ``tool`` results).

    ``current_idx`` is ``None`` only when the history holds no user message to
    pin; the result is then the trimmed history alone.

    The pinned message goes back to its chronological position: a window that
    reaches into the messages before it holds every message after it, and the
    first message after it is the assistant turn answering it, so no orphaned
    ``tool`` result can follow it.
    """
    budget = max_messages - 1  # the system message
    if current_idx is None:
        # Guard budget <= 0 so _trim_context does not emit its L-5 warning.
        return _trim_context(history, budget) if budget > 0 else []
    pinned = history[current_idx]
    after = history[current_idx + 1 :]
    budget -= 1  # the pinned message
    tail = _trim_context(history[:current_idx] + after, budget) if budget > 0 else []
    insert_at = max(0, len(tail) - len(after))
    return [*tail[:insert_at], pinned, *tail[insert_at:]]


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


def _tool_descriptions_to_payload(
    descriptions: list[ToolDescription],
) -> list[dict[str, object]]:
    """Convert registry tool descriptions to the provider ``tools`` array format.

    Each tool is described as::

        {
            "type": "function",
            "function": {
                "name": "<tool>.<action>",
                "description": "...",
                "parameters": { ...json schema... }
            }
        }
    """
    payload: list[dict[str, object]] = []
    for desc in descriptions:
        payload.append(
            {
                "type": "function",
                "function": {
                    "name": f"{desc.tool}.{desc.action}",
                    "description": desc.description,
                    "parameters": desc.parameters_schema,
                },
            }
        )
    return payload


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
