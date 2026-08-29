"""Local vLLM placeholder backend — the default provider (not yet implemented).

vLLM is admino's default LLM provider, but local vLLM model serving is not yet
implemented. This module provides a pure "not available yet" sentinel client so
that admino boots gracefully with vllm selected: the agent replies with a fixed
guidance message telling the user to pick another provider to chat now.

Inputs/outputs:
- ``VLLMPlaceholderClient.chat()`` ignores its ``messages``/``tools``/``stream``
  arguments and always returns an ``LLMResponse`` carrying ``VLLM_GUIDANCE_MESSAGE``.
- ``VLLMPlaceholderClient.close()`` is a no-op.

Security notes:
- Makes NO network calls — there is no httpx client and no I/O of any kind.
- Imports NO provider SDK — nothing is loaded that could contact an external host.
- Leaks nothing: the response content is a fixed constant, independent of the
  conversation, so no user message or tool result is ever transmitted or reflected.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from admino.llm import LLMResponse

if TYPE_CHECKING:
    from admino.models import LLMMessage

# Fixed guidance shown when vLLM is the active provider. Local serving is not
# yet implemented, so the user is directed to switch to a working provider.
VLLM_GUIDANCE_MESSAGE = "Please select another LLM under Settings → Agent."


class VLLMPlaceholderClient:
    """Sentinel ``LLMClient`` for the not-yet-implemented local vLLM provider.

    Implements the ``admino.llm.LLMClient`` protocol but performs no I/O and
    imports no provider SDK. Every ``chat()`` call returns the same guidance
    message regardless of input, so admino can boot on the default ``vllm``
    provider without an API key or model and still respond coherently.
    """

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        """Return the fixed vLLM guidance message, ignoring all inputs.

        The ``messages``, ``tools``, and ``stream`` arguments are intentionally
        ignored: no network call is made and no input is reflected. The response
        directs the user to select a working provider in Settings → Agent.

        Args:
            messages: Conversation messages (ignored).
            tools: Optional tool definitions (ignored).
            stream: Ignored — no streaming is performed.

        Returns:
            An ``LLMResponse`` whose content is ``VLLM_GUIDANCE_MESSAGE``.
        """
        return LLMResponse(
            content=VLLM_GUIDANCE_MESSAGE,
            tool_calls=[],
            model="vllm",
            done=True,
        )

    async def close(self) -> None:
        """No-op close — there is no underlying HTTP client to release."""
        return None
