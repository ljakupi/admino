<script setup lang="ts">
import { computed } from 'vue';
import { t } from '@/i18n';
import type { MessageKey } from '@/i18n';
import type { ConnectionState } from '@/stores/connection';

const props = defineProps<{
  state: ConnectionState;
}>();

const LABEL_KEYS: Record<ConnectionState, MessageKey> = {
  idle: 'status.idle',
  working: 'status.working',
  awaiting: 'status.awaiting',
  offline: 'status.offline',
};

// Resolved in a computed (not a module-level constant) so it re-renders on locale switch.
const label = computed(() => t(LABEL_KEYS[props.state]));
</script>

<template>
  <span class="status-pill" :title="label">
    <span class="dot" :class="props.state" />
    <span class="label">{{ label }}</span>
  </span>
</template>

<style scoped>
.status-pill {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  padding: 7px 14px 7px 12px;
  background: #FFFFFF;
  border: 1px solid #E4E8EA;
  border-radius: 20px;
  font-family: var(--font-body);
  font-size: 13px;
  font-weight: 500;
  line-height: 1;
  white-space: nowrap;
}

.dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  flex-shrink: 0;
}

.dot.idle {
  background: #25D366;
  box-shadow: 0 0 0 3px rgba(37, 211, 102, 0.16);
}

.dot.working {
  background: #128C7E;
  animation: pulse 1.4s ease-in-out infinite;
}

.dot.awaiting {
  background: #E9A23B;
  box-shadow: 0 0 0 3px rgba(233, 162, 59, 0.22);
  animation: attn 1.2s ease-in-out infinite;
}

.dot.offline {
  background: #E35353;
  box-shadow: 0 0 0 3px rgba(227, 83, 83, 0.16);
}

.label {
  color: #111B21;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.45; }
}

@keyframes attn {
  0%, 100% {
    box-shadow: 0 0 0 3px rgba(233, 162, 59, 0.22);
    transform: scale(1);
  }
  50% {
    box-shadow: 0 0 0 7px rgba(233, 162, 59, 0.06);
    transform: scale(1.1);
  }
}
</style>
