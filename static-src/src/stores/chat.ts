import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { postMessage, confirmDecision } from '@/api/messages';
import { useSettingsStore } from './settings';
import { useConnectionStore } from './connection';
import { useToastStore } from './toasts';
import { ApiError } from '@/api/client';
import { t } from '@/i18n';
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
    const sessionId = settings.sessionId;

    try {
      const res = await postMessage(content, sessionId);
      removeThinking(thinkingId);
      // Cleared while in flight: the reply belongs to the old conversation.
      if (settings.sessionId !== sessionId) {
        connection.setIdle();
        return;
      }
      processResponse(res);

      if (res.status === 'awaiting_confirmation') {
        connection.setAwaiting();
      } else {
        connection.setIdle();
      }
    } catch (err) {
      removeThinking(thinkingId);
      if (err instanceof ApiError) {
        // The server answered, so it is reachable: end the run instead of leaving it 'working'.
        connection.setIdle();
        if (err.status === 401) {
          settings.needsAuth = true;
          toasts.add('error', t('toast.chat.authRequired'));
        } else if (err.status === 429) {
          toasts.add('warning', t('toast.chat.slowDown.title'), t('toast.chat.slowDown.body'));
        } else {
          toasts.add('error', t('toast.chat.genericError.title'), t('toast.chat.genericError.body'));
        }
      } else {
        connection.state = 'offline';
        toasts.add('error', t('toast.chat.connectionLost.title'), t('toast.chat.connectionLost.body'));
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
    const sessionId = settings.sessionId;

    try {
      const res = await confirmDecision(sessionId, confirmId, true);
      if (settings.sessionId !== sessionId) {
        connection.setIdle();
        return;
      }
      processResponse(res);

      if (res.status === 'awaiting_confirmation') {
        connection.setAwaiting();
      } else {
        connection.setIdle();
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 410) {
        toasts.add('warning', t('toast.chat.approvalExpired.title'), t('toast.chat.approvalExpired.body'));
        item.data.state = 'error';
        item.data.error = t('chat.toolCall.expired');
      } else if (err instanceof ApiError && err.status === 429) {
        toasts.add('warning', t('toast.chat.slowDown.title'), t('toast.chat.slowDown.body'));
        item.data.state = 'pending';
      } else {
        toasts.add('error', t('toast.chat.genericError.title'));
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
    const sessionId = settings.sessionId;

    try {
      const res = await confirmDecision(sessionId, confirmId, false);
      if (settings.sessionId === sessionId) processResponse(res);
      connection.setIdle();
    } catch (err) {
      if (err instanceof ApiError && err.status === 410) {
        toasts.add('info', t('toast.chat.alreadyExpired'));
      }
      connection.setIdle();
    }
  }

  function clearThread() {
    // A clear is a fresh start: rotate the session id so the server never answers with the old context.
    useSettingsStore().newSession();
    thread.value = [];
  }

  return {
    thread,
    sending,
    pendingConfirmation,
    sendMessage,
    approve,
    deny,
    clearThread,
  };
});
