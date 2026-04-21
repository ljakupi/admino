<script setup lang="ts">
import { Wrench, Check, X, AlertCircle, ChevronDown, ChevronUp } from 'lucide-vue-next';
import StatusBadge from './StatusBadge.vue';
import BaseButton from './BaseButton.vue';
import type { ToolCallUI } from '@/api/types';
import { ref, computed } from 'vue';

const props = defineProps<{
  toolCall: ToolCallUI;
}>();

const emit = defineEmits<{
  approve: [];
  deny: [];
}>();

const expanded = ref(false);

const borderClass = computed(() => {
  switch (props.toolCall.state) {
    case 'pending': return 'border-pending';
    case 'approved': return 'border-approved';
    case 'denied':
    case 'error': return 'border-denied';
    default: return '';
  }
});

const badgeStatus = computed(() => {
  const map: Record<string, string> = {
    pending: 'pending',
    approved: 'approved',
    denied: 'denied',
    completed: 'approved',
    error: 'denied',
  };
  return map[props.toolCall.state] as 'pending' | 'approved' | 'denied';
});
</script>

<template>
  <div class="tool-card" :class="borderClass">
    <div class="tool-header">
      <div class="tool-name">
        <Wrench :size="16" :stroke-width="1.75" class="tool-icon" />
        <span class="mono">{{ props.toolCall.tool }} &middot; {{ props.toolCall.action }}</span>
      </div>
      <StatusBadge :status="badgeStatus" />
    </div>

    <div v-if="props.toolCall.args" class="tool-args mono">
      <div v-for="(val, key) in props.toolCall.args" :key="String(key)" class="arg-row">
        <span class="arg-key">{{ key }}:</span>
        <span class="arg-val">{{ JSON.stringify(val) }}</span>
      </div>
    </div>

    <div v-if="props.toolCall.state === 'pending'" class="tool-actions">
      <BaseButton variant="primary" @click="emit('approve')">
        <Check :size="16" :stroke-width="2" />
        Approve
        <kbd class="shortcut">&#8984;&#9166;</kbd>
      </BaseButton>
      <BaseButton variant="destructive" @click="emit('deny')">
        <X :size="16" :stroke-width="2" />
        Deny
        <kbd class="shortcut">Esc</kbd>
      </BaseButton>
    </div>

    <div v-if="props.toolCall.state === 'error' && props.toolCall.error" class="tool-error mono">
      <AlertCircle :size="14" :stroke-width="2" />
      {{ props.toolCall.error }}
    </div>

    <div v-if="props.toolCall.state === 'completed' && props.toolCall.result" class="tool-result">
      <button class="expand-toggle caption" @click="expanded = !expanded">
        <component :is="expanded ? ChevronUp : ChevronDown" :size="14" />
        {{ expanded ? 'Hide result' : 'Show result' }}
      </button>
      <div v-if="expanded" class="result-body mono">
        {{ props.toolCall.result }}
      </div>
    </div>
  </div>
</template>

<style scoped>
.tool-card {
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-card);
  padding: var(--space-4);
  border-left-width: 3px;
  width: 100%;
}

.border-pending  { border-left-color: var(--color-warn); }
.border-approved { border-left-color: var(--color-sage); }
.border-denied   { border-left-color: var(--color-error); }

.tool-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3);
  margin-bottom: var(--space-3);
}

.tool-name {
  display: flex;
  align-items: center;
  gap: var(--space-2);
}

.tool-icon {
  color: var(--color-sage);
}

.tool-args {
  padding: var(--space-2) var(--space-3);
  background: var(--color-bg);
  border-radius: var(--radius-input);
  margin-bottom: var(--space-3);
  font-size: var(--fs-mono);
}

.arg-row {
  display: flex;
  gap: var(--space-2);
  padding: 2px 0;
}

.arg-key {
  color: var(--color-text-muted);
  flex-shrink: 0;
}

.arg-val {
  color: var(--color-text);
  word-break: break-all;
}

.tool-actions {
  display: flex;
  gap: var(--space-3);
}

@media (max-width: 767px) {
  .tool-actions {
    flex-direction: column;
  }
  .tool-actions .base-btn {
    width: 100%;
  }
  .shortcut { display: none; }
}

.shortcut {
  font-size: 11px;
  opacity: 0.6;
  margin-left: var(--space-1);
  font-family: var(--font-body);
}

.tool-error {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  color: var(--color-error);
  font-size: var(--fs-mono);
}

.expand-toggle {
  display: flex;
  align-items: center;
  gap: var(--space-1);
  cursor: pointer;
  color: var(--color-text-muted);
  background: none;
  border: none;
  padding: var(--space-1) 0;
}

.result-body {
  margin-top: var(--space-2);
  padding: var(--space-3);
  background: var(--color-bg);
  border-radius: var(--radius-input);
  white-space: pre-wrap;
  font-size: var(--fs-mono);
  max-height: 200px;
  overflow-y: auto;
}
</style>
