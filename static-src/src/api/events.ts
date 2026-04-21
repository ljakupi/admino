import type { SSEEventType } from './types';

export interface SSECallbacks {
  onStatus?: (data: { status: string }) => void;
  onToolCall?: (data: { tool: string; action: string; success: boolean }) => void;
  onConfirm?: (data: { confirmation_id: string; tool: string; action: string }) => void;
  onMessage?: (data: { content: string }) => void;
  onError?: (data: { message: string }) => void;
  onDone?: () => void;
  onDisconnect?: () => void;
}

export function openEventStream(
  sessionId: string,
  callbacks: SSECallbacks,
): { close: () => void } {
  const token = localStorage.getItem('admino_auth_token');
  const params = new URLSearchParams({ session_id: sessionId });
  if (token) {
    params.set('token', token);
  }

  const source = new EventSource(`/api/events?${params.toString()}`);

  const handlers: Record<SSEEventType, ((data: unknown) => void) | undefined> = {
    status: callbacks.onStatus as (data: unknown) => void,
    tool_call: callbacks.onToolCall as (data: unknown) => void,
    confirm: callbacks.onConfirm as (data: unknown) => void,
    message: callbacks.onMessage as (data: unknown) => void,
    error: callbacks.onError as (data: unknown) => void,
    done: callbacks.onDone as unknown as (data: unknown) => void,
  };

  for (const [event, handler] of Object.entries(handlers)) {
    if (handler) {
      source.addEventListener(event, (e) => {
        const me = e as MessageEvent;
        try {
          const data = JSON.parse(me.data);
          handler(data);
        } catch {
          // ignore parse errors
        }
      });
    }
  }

  source.onerror = () => {
    callbacks.onDisconnect?.();
  };

  return {
    close: () => source.close(),
  };
}
