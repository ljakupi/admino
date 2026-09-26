<script setup lang="ts">
import { t } from '@/i18n';
</script>

<template>
  <div class="thinking-row">
    <div class="thinking-bubble">
      <span class="dot" />
      <span class="dot" />
      <span class="dot" />
      <span class="thinking-label caption">{{ t('chat.thinking') }}</span>
    </div>
  </div>
</template>

<style scoped>
.thinking-row {
  align-self: flex-start;
}

.thinking-bubble {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-3) var(--space-4);
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border);
  border-radius: 10px 10px 10px 2px;
}

.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--color-primary);
  animation: pulse-dot 1.4s ease-in-out infinite;
}

.dot:nth-child(2) { animation-delay: 0.2s; }
.dot:nth-child(3) { animation-delay: 0.4s; }

.thinking-label {
  margin-left: var(--space-2);
}

@keyframes pulse-dot {
  0%, 80%, 100% { opacity: 0.3; transform: scale(0.8); }
  40% { opacity: 1; transform: scale(1); }
}
</style>
