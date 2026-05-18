<script setup lang="ts">
import { Check, X, AlertCircle, ChevronDown, ChevronUp } from 'lucide-vue-next';
import StatusBadge from './StatusBadge.vue';
import BaseButton from './BaseButton.vue';
import type { ToolCallUI } from '@/api/types';
import { ref, computed } from 'vue';

const props = defineProps<{
  toolCall: ToolCallUI;
  /** When shown inside a chip expansion, hide approve/deny since already resolved */
  readonly?: boolean;
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

const isPending = computed(() => props.toolCall.state === 'pending' && !props.readonly);
const isCompleted = computed(() => props.toolCall.state === 'completed' || props.toolCall.state === 'approved');

/** Classify a value for color coding: 'str', 'num', or default */
function valueClass(val: unknown): string {
  if (typeof val === 'number') return 'v num';
  if (typeof val === 'string') return 'v str';
  return 'v';
}

/** Format a value for display */
function formatValue(val: unknown): string {
  if (typeof val === 'string') return `"${val}"`;
  return JSON.stringify(val);
}
</script>

<template>
  <div class="tool-card" :class="borderClass">
    <!-- Header: tool/action + badge -->
    <div class="tool-header">
      <span class="tool-title">
        {{ props.toolCall.tool }}
        <span class="tool-sep">&middot;</span>
        {{ props.toolCall.action }}
      </span>
      <StatusBadge :status="badgeStatus" class="card-badge" />
    </div>

    <!-- Args grid -->
    <div v-if="props.toolCall.args && Object.keys(props.toolCall.args).length" class="args-grid">
      <template v-for="(val, key) in props.toolCall.args" :key="String(key)">
        <span class="k">{{ key }}</span>
        <span :class="valueClass(val)">{{ formatValue(val) }}</span>
      </template>
    </div>

    <!-- Approve / Deny actions (pending only) -->
    <div v-if="isPending" class="tool-actions">
      <button class="btn approve" @click="emit('approve')">
        <Check :size="16" :stroke-width="2" />
        Approve
        <kbd class="shortcut">&#8984;&#9166;</kbd>
      </button>
      <button class="btn deny" @click="emit('deny')">
        <X :size="16" :stroke-width="2" />
        Deny
        <kbd class="shortcut">Esc</kbd>
      </button>
    </div>

    <!-- Error display -->
    <div v-if="props.toolCall.state === 'error' && props.toolCall.error" class="tool-error">
      <AlertCircle :size="14" :stroke-width="2" />
      {{ props.toolCall.error }}
    </div>

    <!-- Result footer (completed/approved) -->
    <div v-if="isCompleted" class="result-footer">
      <span v-if="props.toolCall.resultCount != null" class="result-ok">{{ props.toolCall.resultCount }} results</span>
      <span v-if="props.toolCall.resultCount != null && props.toolCall.durationMs != null" class="result-sep">&middot;</span>
      <span v-if="props.toolCall.durationMs != null">{{ props.toolCall.durationMs }} ms</span>
      <template v-if="props.toolCall.result">
        <button class="expand-toggle" @click="expanded = !expanded">
          <component :is="expanded ? ChevronUp : ChevronDown" :size="14" />
          {{ expanded ? 'Hide' : 'Details' }}
        </button>
      </template>
    </div>

    <!-- Expanded result body -->
    <div v-if="expanded && props.toolCall.result" class="result-body">
      {{ props.toolCall.result }}
    </div>
  </div>
</template>

<style scoped>
.tool-card {
  background: #FFFFFF;
  border: 1px solid #E9EDEF;
  border-radius: 10px;
  padding: 12px 14px;
  border-left-width: 3px;
  max-width: 560px;
  width: 100%;
  box-shadow: 0 1px 4px rgba(17,27,33,0.06);
}

.border-pending  { border-left-color: #E9A23B; }
.border-approved { border-left-color: #25D366; }
.border-denied   { border-left-color: #E35353; }

/* Header */
.tool-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding-bottom: 12px;
  margin-bottom: 12px;
  border-bottom: 1px dashed #E9EDEF;
}

.tool-title {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  font-family: var(--font-body);
  font-size: 13px;
  font-weight: 600;
  color: #128C7E;
  letter-spacing: -0.005em;
}

.tool-sep {
  color: #CFD8D8;
  font-weight: 400;
  margin: 0 1px;
}

/* Badge override for card context (slightly smaller) */
.card-badge :deep(.badge) {
  font-size: 11.5px;
  padding: 3px 10px;
}

/* Args grid */
.args-grid {
  display: grid;
  grid-template-columns: auto 1fr;
  column-gap: 10px;
  row-gap: 4px;
  font-family: var(--font-mono);
  font-size: 11.5px;
  line-height: 1.6;
}

.k {
  color: #667781;
}

.v {
  color: var(--color-text);
  word-break: break-all;
}

.v.str {
  color: #1F5C2F;
}

.v.num {
  color: #8A5A14;
}

/* Actions */
.tool-actions {
  display: flex;
  gap: 8px;
  margin-top: 14px;
  padding-top: 12px;
  border-top: 1px dashed #E9EDEF;
}

.btn {
  flex: 1;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 8px 12px;
  border-radius: 6px;
  font-family: var(--font-body);
  font-size: 13px;
  font-weight: 600;
  border: 1px solid;
  cursor: pointer;
  line-height: 1;
  transition: background 150ms ease, border-color 150ms ease, color 150ms ease;
}

.approve {
  background: #075E54;
  color: #FFFFFF;
  border-color: #075E54;
}
.approve:hover {
  background: #0B7164;
  border-color: #0B7164;
}

.deny {
  background: transparent;
  color: #C73B3B;
  border-color: #E35353;
}
.deny:hover {
  background: #FCE4E4;
  border-color: #E35353;
  color: #B82F2F;
}

@media (max-width: 767px) {
  .tool-actions {
    flex-direction: column;
  }
  .btn {
    width: 100%;
  }
  .shortcut { display: none; }
}

.shortcut {
  font-size: 11px;
  opacity: 0.6;
  margin-left: 2px;
  font-family: var(--font-body);
}

/* Error */
.tool-error {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #E35353;
  font-family: var(--font-mono);
  font-size: 12px;
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px dashed #E9EDEF;
}

/* Result footer */
.result-footer {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px dashed #E9EDEF;
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 12px;
  color: #667781;
}

.result-ok {
  color: #1F5C2F;
  font-weight: 500;
}

.result-sep {
  color: #CFD8D8;
}

.expand-toggle {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  cursor: pointer;
  color: #667781;
  background: none;
  border: none;
  padding: 0;
  font-size: 12px;
  margin-left: auto;
}

.expand-toggle:hover {
  color: var(--color-text);
}

/* Result body */
.result-body {
  margin-top: 8px;
  padding: 12px;
  background: var(--color-bg);
  border-radius: 8px;
  white-space: pre-wrap;
  font-family: var(--font-mono);
  font-size: 12px;
  max-height: 200px;
  overflow-y: auto;
  color: var(--color-text);
}
</style>
