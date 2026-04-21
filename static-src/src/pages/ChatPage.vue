<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import { MessageCircle } from 'lucide-vue-next';
import AppHeader from '@/components/AppHeader.vue';
import MessageBubble from '@/components/MessageBubble.vue';
import ThinkingDots from '@/components/ThinkingDots.vue';
import ToolCallCard from '@/components/ToolCallCard.vue';
import ToolCallChip from '@/components/ToolCallChip.vue';
import InputBar from '@/components/InputBar.vue';
import EmptyState from '@/components/EmptyState.vue';
import SuggestionChip from '@/components/SuggestionChip.vue';
import { useChatStore } from '@/stores/chat';
import { useAutoScroll } from '@/composables/useAutoScroll';
import { useKeyboardShortcuts } from '@/composables/useKeyboardShortcuts';
import type { ThreadItem, ChatMessage, ToolCallUI } from '@/api/types';

const chatStore = useChatStore();
const threadRef = ref<HTMLElement | null>(null);
const { onScroll, scrollToBottom } = useAutoScroll(threadRef);

const isEmpty = computed(() => chatStore.thread.length === 0);

const suggestions = [
  'Search my emails',
  "What's in my documents?",
  'Find a file',
];

/**
 * Group thread items for display:
 * - Consecutive non-pending tool calls followed by an agent message
 *   become a single "agent-group" with a collapsed chip + bubble.
 * - Pending tool calls stay as full cards.
 * - Everything else passes through as-is.
 */
type DisplayItem =
  | { kind: 'message'; data: ChatMessage }
  | { kind: 'tool_call_pending'; data: ToolCallUI }
  | { kind: 'thinking'; data: { id: string } }
  | { kind: 'agent_group'; toolCalls: ToolCallUI[]; message: ChatMessage; id: string }
  | { kind: 'orphan_tools'; toolCalls: ToolCallUI[]; id: string };

const displayItems = computed<DisplayItem[]>(() => {
  const raw = chatStore.thread;
  const result: DisplayItem[] = [];
  let i = 0;

  while (i < raw.length) {
    const item = raw[i];

    if (item.type === 'message' && item.data.role === 'user') {
      result.push({ kind: 'message', data: item.data });
      i++;
      continue;
    }

    if (item.type === 'thinking') {
      result.push({ kind: 'thinking', data: item.data });
      i++;
      continue;
    }

    // Pending tool call → full card
    if (item.type === 'tool_call' && item.data.state === 'pending') {
      result.push({ kind: 'tool_call_pending', data: item.data });
      i++;
      continue;
    }

    // Non-pending tool calls → try to group with following agent message
    if (item.type === 'tool_call') {
      const toolCalls: ToolCallUI[] = [];
      while (i < raw.length && raw[i].type === 'tool_call' && (raw[i] as { data: ToolCallUI }).data.state !== 'pending') {
        toolCalls.push((raw[i] as { type: 'tool_call'; data: ToolCallUI }).data);
        i++;
      }
      // Check if next item is an agent message
      if (i < raw.length && raw[i].type === 'message' && (raw[i] as { data: ChatMessage }).data.role === 'agent') {
        const msg = (raw[i] as { type: 'message'; data: ChatMessage }).data;
        result.push({ kind: 'agent_group', toolCalls, message: msg, id: `ag-${toolCalls[0].id}` });
        i++;
      } else {
        // Orphan tool calls (no following agent message yet)
        result.push({ kind: 'orphan_tools', toolCalls, id: `ot-${toolCalls[0].id}` });
      }
      continue;
    }

    // Standalone agent message (no preceding tool calls)
    if (item.type === 'message' && item.data.role === 'agent') {
      result.push({ kind: 'message', data: item.data });
      i++;
      continue;
    }

    i++;
  }

  return result;
});

function handleSend(message: string) {
  chatStore.sendMessage(message);
}

function handleSuggestion(label: string) {
  chatStore.sendMessage(label);
}

watch(() => chatStore.thread.length, () => {
  scrollToBottom();
});

useKeyboardShortcuts({
  onApprove: () => {
    const pending = chatStore.pendingConfirmation;
    if (pending) chatStore.approve(pending.id);
  },
  onDeny: () => {
    const pending = chatStore.pendingConfirmation;
    if (pending) chatStore.deny(pending.id);
  },
});
</script>

<template>
  <div class="chat-page">
    <AppHeader />
    <div
      ref="threadRef"
      class="thread"
      role="log"
      aria-live="polite"
      @scroll="onScroll"
    >
      <EmptyState
        v-if="isEmpty"
        :icon="MessageCircle"
        heading="How can I help?"
        subtext="Your messages stay on your machine."
      >
        <div class="suggestions">
          <SuggestionChip
            v-for="s in suggestions"
            :key="s"
            :label="s"
            @click="handleSuggestion(s)"
          />
        </div>
      </EmptyState>

      <template v-else>
        <template v-for="(item, idx) in displayItems" :key="idx">

          <!-- User or standalone agent message -->
          <MessageBubble
            v-if="item.kind === 'message'"
            :message="item.data"
          />

          <!-- Pending tool call: full card with approve/deny -->
          <ToolCallCard
            v-else-if="item.kind === 'tool_call_pending'"
            :tool-call="item.data"
            @approve="chatStore.approve(item.data.id)"
            @deny="chatStore.deny(item.data.id)"
          />

          <!-- Agent group: chip + attached agent bubble -->
          <div v-else-if="item.kind === 'agent_group'" class="agent-group">
            <ToolCallChip :tool-calls="item.toolCalls" />
            <MessageBubble :message="item.message" />
          </div>

          <!-- Orphan tool calls (resolved but no agent message yet) -->
          <div v-else-if="item.kind === 'orphan_tools'" class="orphan-tools">
            <ToolCallChip :tool-calls="item.toolCalls" />
          </div>

          <ThinkingDots v-else-if="item.kind === 'thinking'" />
        </template>
      </template>
    </div>
    <InputBar :disabled="chatStore.sending" @send="handleSend" />
  </div>
</template>

<style scoped>
.chat-page {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
}

.thread {
  flex: 1;
  overflow-y: auto;
  padding: var(--space-4);
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}

.thread > * {
  content-visibility: auto;
}

.suggestions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  justify-content: center;
  margin-top: var(--space-4);
}

/* Agent group: chip visually attached to the bubble below */
.agent-group {
  align-self: flex-start;
  max-width: 85%;
  display: flex;
  flex-direction: column;
  gap: 0;
}

.orphan-tools {
  align-self: flex-start;
  max-width: 85%;
}
</style>
