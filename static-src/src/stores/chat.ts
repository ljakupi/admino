import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { postMessage, confirmDecision } from '@/api/messages';
import { useSettingsStore } from './settings';
import { useConnectionStore } from './connection';
import { useToastStore } from './toasts';
import { ApiError } from '@/api/client';
import type {
  ThreadItem,
  ChatMessage,
  ToolCallUI,
  ChatResponse,
  ToolCallRecord,
} from '@/api/types';

let msgSeq = 0;
function uid(): string {
  return `m-${++msgSeq}-${Date.now().toString(36)}`;
}

export const useChatStore = defineStore('chat', () => {
  const thread = ref<ThreadItem[]>([]);
  const sending = ref(false);

  const pendingConfirmation = computed(() => {
    const items = thread.value;
    for (let i = items.length - 1; i >= 0; i--) {
      const item = items[i];
      if (item.type === 'tool_call' && item.data.state === 'pending') {
        return item.data;
      }
    }
    return null;
  });

  /** All tool calls for the Activity page */
  const toolCallHistory = computed(() =>
    thread.value
      .filter((i): i is Extract<ThreadItem, { type: 'tool_call' }> => i.type === 'tool_call')
      .map((i) => i.data),
  );

  function addUserMessage(content: string): ChatMessage {
    const msg: ChatMessage = {
      id: uid(),
      role: 'user',
      content,
      timestamp: new Date(),
    };
    thread.value.push({ type: 'message', data: msg });
    return msg;
  }

  function addThinking(): string {
    const id = uid();
    thread.value.push({ type: 'thinking', data: { id } });
    return id;
  }

  function removeThinking(id: string) {
    const idx = thread.value.findIndex(
      (i) => i.type === 'thinking' && i.data.id === id,
    );
    if (idx !== -1) thread.value.splice(idx, 1);
  }

  function processResponse(res: ChatResponse) {
    // Add tool calls
    for (const tc of res.tool_calls) {
      const existing = thread.value.find(
        (i) =>
          i.type === 'tool_call' &&
          i.data.tool === tc.tool &&
          i.data.action === tc.action &&
          i.data.state === 'approved',
      );
      if (existing && existing.type === 'tool_call') {
        existing.data.state = tc.success ? 'completed' : 'error';
        continue;
      }

      const tcUI: ToolCallUI = {
        id: uid(),
        tool: tc.tool,
        action: tc.action,
        args: tc.args,
        durationMs: tc.duration_ms,
        state: tc.permission === 'confirm'
          ? (tc.success ? 'completed' : 'error')
          : tc.success
            ? 'completed'
            : 'error',
        timestamp: new Date(),
      };
      thread.value.push({ type: 'tool_call', data: tcUI });
    }

    // Add pending confirmation card
    if (res.pending_confirmation) {
      const pc = res.pending_confirmation;
      const tcUI: ToolCallUI = {
        id: uid(),
        tool: pc.tool,
        action: pc.action,
        args: pc.args,
        state: 'pending',
        confirmationId: pc.confirmation_id,
        expiresAt: pc.expires_at,
        timestamp: new Date(),
      };
      thread.value.push({ type: 'tool_call', data: tcUI });
    }

    // Add agent response
    if (res.response) {
      const msg: ChatMessage = {
        id: uid(),
        role: 'agent',
        content: res.response,
        timestamp: new Date(),
      };
      thread.value.push({ type: 'message', data: msg });
    }
  }

  async function sendMessage(content: string) {
    const settings = useSettingsStore();
    const connection = useConnectionStore();
    const toasts = useToastStore();

    if (sending.value || !content.trim()) return;

    addUserMessage(content);
    sending.value = true;
    connection.setWorking();
    const thinkingId = addThinking();

    try {
      const res = await postMessage(content, settings.sessionId);
      removeThinking(thinkingId);
      processResponse(res);

      if (res.status === 'awaiting_confirmation') {
        connection.setAwaiting();
      } else {
        connection.setIdle();
      }
    } catch (err) {
      removeThinking(thinkingId);
      if (err instanceof ApiError) {
        if (err.status === 401) {
          settings.needsAuth = true;
          toasts.add('error', 'Authentication required');
        } else if (err.status === 429) {
          toasts.add('warning', 'Slow down', 'admino is rate-limited.');
        } else {
          toasts.add('error', 'Something went wrong', 'Check the server logs.');
        }
      } else {
        connection.state = 'offline';
        toasts.add('error', 'Connection lost', 'Cannot reach the server.');
      }
    } finally {
      sending.value = false;
    }
  }

  async function approve(toolCallId: string) {
    const settings = useSettingsStore();
    const connection = useConnectionStore();
    const toasts = useToastStore();

    const item = thread.value.find(
      (i) => i.type === 'tool_call' && i.data.id === toolCallId,
    );
    if (!item || item.type !== 'tool_call' || item.data.state !== 'pending') return;

    const confirmId = item.data.confirmationId;
    if (!confirmId) return;

    item.data.state = 'approved';
    connection.setWorking();

    try {
      const res = await confirmDecision(settings.sessionId, confirmId, true);
      processResponse(res);

      if (res.status === 'awaiting_confirmation') {
        connection.setAwaiting();
      } else {
        connection.setIdle();
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 410) {
        toasts.add('warning', 'Approval expired', 'Send the message again.');
        item.data.state = 'error';
        item.data.error = 'Expired';
      } else if (err instanceof ApiError && err.status === 429) {
        toasts.add('warning', 'Slow down', 'admino is rate-limited.');
        item.data.state = 'pending';
      } else {
        toasts.add('error', 'Something went wrong');
        item.data.state = 'error';
      }
      connection.setIdle();
    }
  }

  async function deny(toolCallId: string) {
    const settings = useSettingsStore();
    const connection = useConnectionStore();
    const toasts = useToastStore();

    const item = thread.value.find(
      (i) => i.type === 'tool_call' && i.data.id === toolCallId,
    );
    if (!item || item.type !== 'tool_call' || item.data.state !== 'pending') return;

    const confirmId = item.data.confirmationId;
    if (!confirmId) return;

    item.data.state = 'denied';

    try {
      const res = await confirmDecision(settings.sessionId, confirmId, false);
      processResponse(res);
      connection.setIdle();
    } catch (err) {
      if (err instanceof ApiError && err.status === 410) {
        toasts.add('info', 'Already expired');
      }
      connection.setIdle();
    }
  }

  function clearThread() {
    thread.value = [];
  }

  return {
    thread,
    sending,
    pendingConfirmation,
    toolCallHistory,
    sendMessage,
    approve,
    deny,
    clearThread,
  };
});
