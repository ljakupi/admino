<script setup lang="ts">
import MarkdownBlock from './MarkdownBlock.vue';
import type { ChatMessage } from '@/api/types';
import { useI18n } from '@/i18n';

const { formatDate } = useI18n();

const props = defineProps<{
  message: ChatMessage;
}>();

function formatTime(d: Date): string {
  return formatDate(d, { hour: '2-digit', minute: '2-digit' });
}
</script>

<template>
  <div class="bubble-row" :class="props.message.role">
    <div class="bubble" :class="props.message.role">
      <MarkdownBlock
        v-if="props.message.role === 'agent'"
        :content="props.message.content"
      />
      <span v-else class="user-text">{{ props.message.content }}</span>
      <span v-if="props.message.streaming" class="cursor"></span>
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
  max-width: 82%;
}

.bubble-row.user {
  align-self: flex-end;
  max-width: 78%;
  align-items: flex-end;
}

.bubble-row.agent {
  align-self: flex-start;
  align-items: flex-start;
}

.bubble {
  padding: 10px 14px;
  font-size: 14.5px;
  line-height: 1.5;
  word-break: break-word;
}

.bubble.user {
  background: var(--color-primary);
  color: var(--color-text-on-dark);
  border-radius: 10px 10px 2px 10px;
}

.bubble.agent {
  background: #FFFFFF;
  color: var(--color-text);
  border-radius: 10px 10px 10px 2px;
  border: 1px solid #E9EDEF;
}

.user-text {
  white-space: pre-wrap;
}

.cursor {
  display: inline-block;
  width: 6px;
  height: 0.95em;
  background: #111B21;
  margin-left: 2px;
  vertical-align: -1px;
  animation: blink 1.2s infinite;
}

.bubble-meta {
  display: flex;
  gap: var(--space-2);
  font-size: 11px;
  padding: 0 6px;
  margin-top: 2px;
}

.model-name {
  font-family: var(--font-mono);
}

@keyframes blink {
  0%, 50% { opacity: 1; }
  51%, 100% { opacity: 0.1; }
}
</style>
