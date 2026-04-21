<script setup lang="ts">
import type { ConnectionState } from '@/stores/connection';

const props = defineProps<{
  state: ConnectionState;
}>();

const labels: Record<ConnectionState, string> = {
  idle: 'Ready',
  working: 'Working\u2026',
  awaiting: 'Waiting for you',
  offline: 'Offline',
};
</script>

<template>
  <span class="status-dot-wrap" :title="labels[props.state]">
    <span class="dot" :class="props.state" />
    <span class="label caption">{{ labels[props.state] }}</span>
  </span>
</template>

<style scoped>
.status-dot-wrap {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
}

.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.dot.idle {
  background: var(--color-sage);
}

.dot.working {
  background: var(--color-primary);
  animation: pulse 1.2s ease-in-out infinite;
}

.dot.awaiting {
  background: var(--color-warn);
  animation: pulse 1.2s ease-in-out infinite;
}

.dot.offline {
  background: var(--color-error);
}

.label {
  font-size: var(--fs-caption-mobile);
  color: var(--color-text-muted);
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
</style>
