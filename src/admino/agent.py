"""Agent loop orchestrating LLM interaction, tool dispatch, and audit logging.

This module defines the :class:`Agent` class — the single orchestrator that
ties together the LLM client (``admino.llm``), the tool registry
(``admino.tools.registry``), and the audit logger (``admino.audit``).

Architecture & boundaries:
- The agent is the ONLY component that closes the loop between LLM output,
  tool dispatch, and conversation history. It MUST NOT be imported by
  ``permissions.py`` (which remains isolated) and MUST NOT import from
  ``server.py``.
- Permission checks happen inside ``registry.dispatch_tool_call``. The agent
  never calls ``check_permission`` directly — dispatch is the single
  enforcement point, and passing ``audit_logger`` through ensures every
  decision is recorded at that point.
- Conversation history is owned by the *caller*; the system prompt is owned
  by the *agent*. The agent copies the caller's history, mutates the local
  list, and returns it as part of :class:`admino.models.AgentResult` — it
  only ever holds user/assistant/tool messages. The system prompt is added
  to each LLM call's context and never returned in history, so it cannot
  accumulate across turns (GH-140). There is no module-level state.

Security notes:
- No ``eval``, ``exec``, ``compile``, ``importlib``, ``shell=True``, or
  dynamic tool dispatch.
- User message content, raw tool arguments, and assistant text are NEVER
  logged at INFO/DEBUG. Only counts, tool/action names, and status strings
  are emitted via the standard logger. Audit entries are the authoritative
  record.
- Every ``system``-role message in caller-supplied history (leading or
  mid-conversation) is dropped before use — it could be persisted prompt
  injection. Only a count is logged, never the content.
- Exceptions from the LLM client are caught and converted into a safe
  "error" AgentResult. ``MemoryError`` and ``RecursionError`` are
  re-raised (mirroring the registry pattern).
- Malformed LLM output (e.g. validation errors on LLM responses) is
  converted to an assistant message with a generic note and returned —
  never crashes the loop.
- ``max_tool_calls`` is a hard cap enforced per-call inside the dispatch
  batch — the loop breaks the moment it is reached, even mid-batch.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from typing import TYPE_CHECKING

from admino.audit import AuditWriteError
from admino.llm import LLMError
from admino.models import (
    AgentConfig,
    AgentResult,
    ConversationAuditEntry,
    LLMMessage,
    PendingConfirmation,
    ToolCall,
    ToolCallRecord,
)
from admino.tools.registry import dispatch_tool_call, get_registered_tools

if TYPE_CHECKING:
    from admino.audit import AuditLogger
    from admino.llm import LLMClient
    from admino.permissions import PermissionsConfig
    from admino.tools.registry import ToolCallResult, ToolDescription

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


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


class Agent:
    """Orchestrates the LLM-tool loop for a single user message.

    The agent is constructed once per process (or once per request — it is
    cheap and stateless) with its dependencies injected. :meth:`run` is the
    single public entry point and is fully async.

    Dependencies are injected rather than imported at module level so that:
    (a) tests can substitute fakes trivially, (b) there are no import-time
    side effects, and (c) the security boundary with ``permissions.py`` is
    preserved — the agent only ever passes ``PermissionsConfig`` through to
    ``dispatch_tool_call``; it never imports ``check_permission`` itself.
    """

    def __init__(
        self,
        *,
        llm_client: LLMClient,
        audit_logger: AuditLogger,
        permissions_config: PermissionsConfig,
        agent_config: AgentConfig,
        model_name: str,
        system_prompt: str = "",
        tools_enabled: dict[str, bool] | None = None,
    ) -> None:
        """Initialise the agent with its collaborators.

        Args:
            llm_client: LLM client implementing the LLMClient protocol.
                Can be AnthropicClient or OpenAIClient.
            audit_logger: Append-only audit sink. Passed through to every
                ``dispatch_tool_call`` invocation so tool-call audit entries
                are written at the enforcement point.
            permissions_config: Immutable permissions config, forwarded to
                dispatch on every tool call. The agent itself never inspects
                it.
            agent_config: Runtime limits (``max_tool_calls``,
                ``max_context_messages``).
            model_name: Name of the LLM model used — recorded on every
                conversation audit entry.
            system_prompt: Optional system message sent once, first, on every
                LLM call. Used to communicate available file paths,
                operator constraints, and other static context to the LLM.
                It is never added to the history returned to the caller.
            tools_enabled: Per-tool enabled/disabled state from settings.
                Tools whose name maps to ``False`` are excluded from the
                LLM tool list and rejected at dispatch time.  Hot-reloaded
                by the server when settings change.
        """
        self._llm = llm_client
        self._audit = audit_logger
        self._permissions = permissions_config
        self._promoted: frozenset[tuple[str, str]] = frozenset()
        self._config = agent_config
        self._model_name = model_name
        self._system_prompt = system_prompt
        self._tools_enabled: dict[str, bool] = dict(tools_enabled) if tools_enabled else {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        user_message: str,
        session_id: str,
        *,
        history: list[LLMMessage],
        pending_confirmation: PendingConfirmation | None = None,
    ) -> AgentResult:
        """Run the agent loop for a single user message.

        The method appends the user message to a copy of ``history``, then
        enters the LLM/tool loop until the LLM produces plain text, a tool
        call needs confirmation, ``max_tool_calls`` is exhausted, or an error
        occurs. Each LLM call gets the system prompt plus a trimmed window
        of the history in which the current user message is always kept.

        Args:
            user_message: The user's message text. Must already be validated
                for length by the caller (server layer).
            session_id: Session identifier — propagated to audit entries and
                tool handlers. Must match the audit entry pattern.
            history: Prior conversation history (caller-owned). The agent
                copies this list; the original is not mutated. Any
                ``system``-role messages in it are dropped.
            pending_confirmation: If set, a previously-issued confirmation is
                being resumed. The first tool call in this turn is dispatched
                with this value so ``registry.dispatch_tool_call`` can verify
                identity/expiry.

        Returns:
            :class:`AgentResult` with the terminal status, the updated
            history (user/assistant/tool messages only — never the system
            prompt), and a summary of tool calls made during the run.
        """
        # Work on a local copy so we never mutate the caller's list. The
        # system prompt is NOT stored here: it is added per LLM call by
        # _build_context, so the returned history never carries it and it
        # cannot pile up when the caller feeds the history back (GH-140).
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

            # Audit the user turn before any LLM call so the trail is complete
            # even if the model call fails — including session-mismatch rejections.
            try:
                self._audit_conversation(
                    session_id=session_id,
                    role="user",
                    content=user_message,
                    tool_calls_count=0,
                )
            except AuditWriteError:
                # H-1: Audit failure is fatal for the run.  We cannot continue
                # without a guaranteed audit trail.  Return a structured error
                # rather than letting the raw exception propagate to the server.
                logger.error("Audit write failed for user turn — aborting run")
                return AgentResult(
                    status="error",
                    response="Internal error: audit unavailable.",
                    history=working_history,
                    tool_calls=[],
                )

        # H-2: Session-identity check — reject cross-session confirmation replay.
        # Placed AFTER the user turn is audited so the attempt is recorded.
        if pending_confirmation is not None and pending_confirmation.session_id != session_id:
            logger.warning("Rejected cross-session pending_confirmation for session %s", session_id)
            return self._terminal_error(
                session_id=session_id,
                history=working_history,
                tool_records=[],
                message="Pending confirmation session mismatch.",
            )

        tool_records: list[ToolCallRecord] = []
        tool_calls_used: int = 0
        # GH-77: Advertise only tools the permission engine would NOT deny.
        # Passing permissions + promoted state here (the same values forwarded
        # to dispatch) drops hardcoded-denied and un-promoted tier-2 actions
        # from the tool list, so the LLM cannot substitute a sibling action
        # for an unavailable one. The agent still never imports check_permission
        # itself — it only forwards PermissionsConfig, preserving the boundary.
        tools_payload: list[dict[str, object]] = _tool_descriptions_to_payload(
            get_registered_tools(
                enabled_tools=self._tools_enabled or None,
                permissions_config=self._permissions,
                promoted=self._promoted,
            )
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
            pre_result = await self._resume_pending_dispatch(
                pending_confirmation=pending_confirmation,
                session_id=session_id,
                working_history=working_history,
                tool_records=tool_records,
            )
            if pre_result is not None:
                # Audit write failed during pre-dispatch — ``_resume_pending_dispatch``
                # has already logged and built the terminal error. Return it.
                return pre_result
            tool_calls_used += 1
            carry_confirmation = None  # consumed on pre-dispatch

        # Bounded loop. Each iteration = one LLM round trip, possibly followed
        # by a batch of tool dispatches.
        for _iteration in range(self._config.max_tool_calls + 1):
            # 1. Call the LLM with the system prompt + a trimmed context window.
            context = _build_context(
                working_history,
                system_prompt=self._system_prompt,
                current_idx=current_idx,
                max_messages=self._config.max_context_messages,
            )
            try:
                response = await self._llm.chat(context, tools=tools_payload)
            except (MemoryError, RecursionError):
                raise
            except AuditWriteError:
                # H-1: Propagated from a dispatch audit path inside the LLM
                # layer is impossible (LLM does not audit), but guard for future.
                logger.error("Audit write failed during LLM call — aborting run")
                return self._terminal_error(
                    session_id=session_id,
                    history=working_history,
                    tool_records=tool_records,
                    message="Internal error: audit unavailable.",
                )
            except Exception as exc:
                # For LLMError, log .message (our own safe string, never an HTTP
                # body or credential). For other exceptions, log only the type.
                if isinstance(exc, LLMError):
                    logger.error("LLM chat call failed: %s", exc.message)
                else:
                    logger.error("LLM chat call failed: %s", type(exc).__name__)
                return self._terminal_error(
                    session_id=session_id,
                    history=working_history,
                    tool_records=tool_records,
                    message=_LLM_ERROR_MESSAGE,
                )

            # 2. Text-only response → we are done.
            if not response.tool_calls:
                assistant_text = response.content or ""
                working_history.append(LLMMessage(role="assistant", content=assistant_text))
                try:
                    self._audit_conversation(
                        session_id=session_id,
                        role="assistant",
                        content=assistant_text,
                        tool_calls_count=0,
                    )
                except AuditWriteError:
                    logger.error("Audit write failed for assistant turn — aborting run")
                    return AgentResult(
                        status="error",
                        response="Internal error: audit unavailable.",
                        history=working_history,
                        tool_calls=tool_records,
                    )
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
            # tool_use / tool_result pairing. OpenAI ignores this field.
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
            # L-4: Clamp batch count to le=50 limit on ConversationAuditEntry.
            # tool_calls_count to avoid a ValidationError crash that would
            # bypass audit.
            try:
                self._audit_conversation(
                    session_id=session_id,
                    role="assistant",
                    content=response.content or "",
                    tool_calls_count=min(len(batch), 50),
                )
            except AuditWriteError:
                logger.error("Audit write failed for tool-call turn — aborting run")
                return AgentResult(
                    status="error",
                    response="Internal error: audit unavailable.",
                    history=working_history,
                    tool_calls=tool_records,
                )

            for tool_call in batch:
                if tool_calls_used >= self._config.max_tool_calls:
                    # Hard cap reached mid-batch — stop immediately.
                    return self._terminal_limit(
                        session_id=session_id,
                        history=working_history,
                        tool_records=tool_records,
                    )

                try:
                    dispatch_start = time.monotonic()
                    result = await self._dispatch_one(
                        tool_call=tool_call,
                        session_id=session_id,
                        pending_confirmation=carry_confirmation,
                    )
                    dispatch_duration_ms = int((time.monotonic() - dispatch_start) * 1000)
                except AuditWriteError:
                    # H-1: Audit failure inside dispatch is fatal.
                    logger.error("Audit write failed during tool dispatch — aborting run")
                    return AgentResult(
                        status="error",
                        response="Internal error: audit unavailable.",
                        history=working_history,
                        tool_calls=tool_records,
                    )
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
                # The dispatch layer has already written the audit entry
                # for the pending-confirmation outcome.
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
                        timeout_s=self._config.confirmation_timeout_s,
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
                # H-3: Audit the tool-result turn so the audit log can
                # fully reconstruct the LLM context window.
                try:
                    self._audit_conversation(
                        session_id=session_id,
                        role="tool",
                        content=result.result,
                        tool_calls_count=0,
                    )
                except AuditWriteError:
                    logger.error("Audit write failed for tool-result turn — aborting run")
                    return AgentResult(
                        status="error",
                        response="Internal error: audit unavailable.",
                        history=working_history,
                        tool_calls=tool_records,
                    )

            # After the batch, loop back for another LLM turn unless the cap
            # has been reached.
            if tool_calls_used >= self._config.max_tool_calls:
                # Give the LLM one final chance to summarise, OR, if we have
                # already done so once, terminate. The simplest safe choice
                # is to terminate here — the LLM may otherwise issue more
                # tool calls we cannot honour.
                return self._terminal_limit(
                    session_id=session_id,
                    history=working_history,
                    tool_records=tool_records,
                )

        # Defensive fallthrough: the for-range loop bound means we should
        # never reach here, but if we do, treat as limit reached.
        return self._terminal_limit(
            session_id=session_id,
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
        session_id: str,
        pending_confirmation: PendingConfirmation | None,
    ) -> ToolCallResult:
        """Dispatch a single tool call via the registry.

        Thin wrapper that exists to (a) keep the main loop readable and
        (b) centralise the audit-logger pass-through so it cannot be
        forgotten at a call site.
        """
        return await dispatch_tool_call(
            tool_call,
            self._permissions,
            session_id=session_id,
            pending_confirmation=pending_confirmation,
            audit_logger=self._audit,
            promoted=self._promoted,
            enabled_tools=self._tools_enabled or None,
        )

    async def _resume_pending_dispatch(
        self,
        *,
        pending_confirmation: PendingConfirmation,
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

        Returns ``None`` on success, or a terminal ``AgentResult`` if an
        audit write failed — in which case the caller must return it
        immediately so the run aborts with an auditable error.

        The caller is responsible for bumping ``tool_calls_used`` and
        clearing ``carry_confirmation`` after a successful return.
        """
        tool_call = pending_confirmation.tool_call
        try:
            dispatch_start = time.monotonic()
            result = await self._dispatch_one(
                tool_call=tool_call,
                session_id=session_id,
                pending_confirmation=pending_confirmation,
            )
            dispatch_duration_ms = int((time.monotonic() - dispatch_start) * 1000)
        except AuditWriteError:
            logger.error("Audit write failed during resume dispatch — aborting run")
            return AgentResult(
                status="error",
                response="Internal error: audit unavailable.",
                history=working_history,
                tool_calls=tool_records,
            )

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
        try:
            self._audit_conversation(
                session_id=session_id,
                role="tool",
                content=result.result,
                tool_calls_count=0,
            )
        except AuditWriteError:
            logger.error("Audit write failed for resumed tool-result turn — aborting run")
            return AgentResult(
                status="error",
                response="Internal error: audit unavailable.",
                history=working_history,
                tool_calls=tool_records,
            )
        return None

    def _audit_conversation(
        self,
        *,
        session_id: str,
        role: str,
        content: str,
        tool_calls_count: int,
    ) -> None:
        """Write a conversation audit entry.

        Credential redaction, control-character stripping, and length
        enforcement happen inside ``ConversationAuditEntry`` field
        validators — we just construct the model.
        """
        # ConversationAuditEntry enforces content min_length=1; a genuinely
        # empty assistant turn (tool-call-only) must still be auditable, so
        # substitute a single-space placeholder. The redactor will promote
        # it to "[SANITIZED]" if it collapses to empty.
        safe_content = content if content else " "
        # ConversationAuditEntry.content has max_length=32768. Tool results
        # from the registry can be up to 65,536 chars.  Truncate to prevent
        # a Pydantic ValidationError that would crash the run.
        if len(safe_content) > 32768:
            safe_content = safe_content[:32768]
        # Map to the ConversationAuditEntry role literal.
        audit_role: str = role if role in ("user", "assistant", "tool") else "assistant"
        entry = ConversationAuditEntry(
            session_id=session_id,
            role=audit_role,  # type: ignore[arg-type]  # Literal validated by Pydantic
            content=safe_content,
            model=self._model_name,
            tool_calls_count=tool_calls_count,
        )
        self._audit.log_conversation(entry)

    def _terminal_limit(
        self,
        *,
        session_id: str,
        history: list[LLMMessage],
        tool_records: list[ToolCallRecord],
    ) -> AgentResult:
        """Build and audit the terminal "limit reached" result."""
        history.append(LLMMessage(role="assistant", content=_LIMIT_REACHED_MESSAGE))
        try:
            self._audit_conversation(
                session_id=session_id,
                role="assistant",
                content=_LIMIT_REACHED_MESSAGE,
                tool_calls_count=0,
            )
        except AuditWriteError:
            logger.error("Audit write failed for limit-reached turn")
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
        session_id: str,
        history: list[LLMMessage],
        tool_records: list[ToolCallRecord],
        message: str,
    ) -> AgentResult:
        """Build and audit a terminal error result with a safe message."""
        history.append(LLMMessage(role="assistant", content=message))
        try:
            self._audit_conversation(
                session_id=session_id,
                role="assistant",
                content=message,
                tool_calls_count=0,
            )
        except AuditWriteError:
            logger.error("Audit write failed for error turn")
        # L-3: Log a "run terminated" message mirroring _terminal_limit.
        logger.info("Agent run terminated: error (%d tool calls)", len(tool_records))
        return AgentResult(
            status="error",
            response=message,
            history=history,
            tool_calls=tool_records,
        )


# ---------------------------------------------------------------------------
# Module-level helpers (pure functions, unit-testable)
# ---------------------------------------------------------------------------


def _drop_system_messages(history: list[LLMMessage]) -> list[LLMMessage]:
    """Return a copy of caller-supplied ``history`` without ``system`` messages.

    The agent is the only source of system content (its configured prompt,
    added per LLM call by :func:`_build_context`). A ``system`` message in
    caller history — leading or mid-conversation — is either a stale copy of
    that prompt or persisted prompt injection, so all of them are dropped.
    When any are dropped, one WARNING with the count only is logged; message
    content is never logged.
    """
    kept = [msg for msg in history if msg.role != "system"]
    dropped = len(history) - len(kept)
    if dropped:
        logger.warning("Dropped %d system-role message(s) from caller-supplied history", dropped)
    return kept


def _build_context(
    history: list[LLMMessage],
    *,
    system_prompt: str,
    current_idx: int | None,
    max_messages: int,
) -> list[LLMMessage]:
    """Build the message list for one LLM call.

    ``history`` must hold no ``system`` messages (see
    :func:`_drop_system_messages`). The result is:

    - the agent's ``system_prompt`` once, at index 0 (omitted when empty);
    - the current user message ``history[current_idx]``, exactly once — the
      system prompt and this message are the floor and are always sent, even
      when they alone exceed ``max_messages``;
    - the most recent other messages, in chronological order, filling the
      remaining budget via :func:`_trim_context` (which also drops leading
      orphaned ``tool`` results).

    ``current_idx`` is ``None`` only when the history holds no user message to
    pin; the result is then the system prompt plus the trimmed history.

    The pinned message goes back to its chronological position: a window that
    reaches into the messages before it holds every message after it, and the
    first message after it is the assistant turn answering it, so no orphaned
    ``tool`` result can follow it.
    """
    system = [LLMMessage(role="system", content=system_prompt)] if system_prompt else []
    if current_idx is None:
        budget = max_messages - len(system)
        # Guard budget <= 0 so _trim_context does not emit its L-5 warning.
        return system + (_trim_context(history, budget) if budget > 0 else [])
    pinned = history[current_idx]
    after = history[current_idx + 1 :]
    budget = max_messages - len(system) - 1
    tail = _trim_context(history[:current_idx] + after, budget) if budget > 0 else []
    insert_at = max(0, len(tail) - len(after))
    return [*system, *tail[:insert_at], pinned, *tail[insert_at:]]


def _trim_context(history: list[LLMMessage], max_messages: int) -> list[LLMMessage]:
    """Return the tail of ``history`` bounded by ``max_messages``.

    System messages at the head of history are preserved; only non-system
    messages are trimmed from the middle/front. The agent calls this via
    :func:`_build_context` on history that is already free of system
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
