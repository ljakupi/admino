import { fetchJson } from './client';
import type { ChatResponse, ConfirmRequest } from './types';

export async function postMessage(
  message: string,
  sessionId: string,
): Promise<ChatResponse> {
  return fetchJson<ChatResponse>('/api/message', {
    method: 'POST',
    body: JSON.stringify({ message, session_id: sessionId }),
  });
}

export async function confirmDecision(
  sessionId: string,
  confirmationId: string,
  approved: boolean,
): Promise<ChatResponse> {
  return fetchJson<ChatResponse>(`/api/confirm/${confirmationId}`, {
    method: 'POST',
    body: JSON.stringify({
      session_id: sessionId,
      confirmation_id: confirmationId,
      approved,
    } satisfies ConfirmRequest),
  });
}
