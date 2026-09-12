import { fetchJson } from './client';
import type { ChatResponse, ConfirmRequest } from './types';

// The agent loop (multiple LLM calls + tool execution) can take much longer than
// a normal API call — especially with a CPU-served local model. Give these two
// endpoints a generous ceiling so a slow-but-successful run isn't aborted into a
// spurious "Connection lost" error. Other endpoints keep the default 30s.
const AGENT_TIMEOUT_MS = 180_000;

export async function postMessage(
  message: string,
  sessionId: string,
): Promise<ChatResponse> {
  return fetchJson<ChatResponse>(
    '/api/message',
    {
      method: 'POST',
      body: JSON.stringify({ message, session_id: sessionId }),
    },
    AGENT_TIMEOUT_MS,
  );
}

export async function confirmDecision(
  sessionId: string,
  confirmationId: string,
  approved: boolean,
): Promise<ChatResponse> {
  return fetchJson<ChatResponse>(
    `/api/confirm/${confirmationId}`,
    {
      method: 'POST',
      body: JSON.stringify({
        session_id: sessionId,
        confirmation_id: confirmationId,
        approved,
      } satisfies ConfirmRequest),
    },
    AGENT_TIMEOUT_MS,
  );
}
