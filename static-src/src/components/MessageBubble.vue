<script setup lang="ts">
import MarkdownBlock from './MarkdownBlock.vue';
import type { ChatMessage } from '@/api/types';

const props = defineProps<{
  message: ChatMessage;
}>();

function formatTime(d: Date): string {
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
</script>

<template>
  <div class="bubble-row" :class="props.message.role">
    <div class="bubble" :class="[props.message.role, { streaming: props.message.streaming }]">
      <MarkdownBlock
        v-if="props.message.role === 'agent'"
        :content="props.message.content"
      />
      <span v-else class="user-text">{{ props.message.content }}</span>
      <span v-if="props.message.streaming" class="cursor">&#9613;</span>
    </div>
    <div class="bubble-meta caption">
      <span>{{ formatTime(props.message.timestamp) }}</span>
      <span v-if="props.message.model" class="model-name">{{ props.message.model }}</span>
    </div>
  </div>
</template>

<style scoped>
.bubble-row {
  display: flex;
  flex-direction: column;
  max-width: 85%;
}

.bubble-row.user {
  align-self: flex-end;
  max-width: 75%;
  align-items: flex-end;
}

.bubble-row.agent {
  align-self: flex-start;
  align-items: flex-start;
}

.bubble {
  padding: var(--space-3) var(--space-4);
  word-break: break-word;
}

.bubble.user {
  background: var(--color-primary);
  color: var(--color-text-on-dark);
  border-radius: 10px 10px 2px 10px;
}

.bubble.agent {
  background: var(--color-bg-surface);
  color: var(--color-text);
  border-radius: 10px 10px 10px 2px;
  border: 1px solid var(--color-border);
}

.bubble.streaming {
  border-left: 3px solid var(--color-sage);
}

.user-text {
  white-space: pre-wrap;
}

.cursor {
  animation: blink 1s step-end infinite;
  color: var(--color-sage);
}

.bubble-meta {
  display: flex;
  gap: var(--space-2);
  padding: var(--space-1) var(--space-1);
}

.model-name {
  font-family: var(--font-mono);
}

@keyframes blink {
  50% { opacity: 0; }
}
</style>
