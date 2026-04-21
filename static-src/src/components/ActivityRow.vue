<script setup lang="ts">
import { ref } from 'vue';
import { Wrench, ChevronDown, ChevronUp } from 'lucide-vue-next';
import StatusBadge from './StatusBadge.vue';
import type { ToolCallUI } from '@/api/types';

const props = defineProps<{
  entry: ToolCallUI;
}>();

const expanded = ref(false);

function formatTime(d: Date): string {
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function stateToStatus(state: string): 'approved' | 'denied' | 'pending' {
  if (state === 'completed' || state === 'approved') return 'approved';
  if (state === 'denied' || state === 'error') return 'denied';
  return 'pending';
}
</script>

<template>
  <div class="activity-row" @click="expanded = !expanded">
    <div class="row-main">
      <Wrench :size="16" :stroke-width="1.75" class="row-icon" />
      <div class="row-info">
        <span class="mono row-tool">{{ props.entry.tool }} &middot; {{ props.entry.action }}</span>
      </div>
      <span class="caption row-time">{{ formatTime(props.entry.timestamp) }}</span>
      <StatusBadge :status="stateToStatus(props.entry.state)" />
      <component :is="expanded ? ChevronUp : ChevronDown" :size="14" class="expand-icon" />
    </div>
    <div v-if="expanded" class="row-detail">
      <div v-if="props.entry.args" class="detail-args mono">
        <div v-for="(val, key) in props.entry.args" :key="String(key)">
          {{ key }}: {{ JSON.stringify(val) }}
        </div>
      </div>
      <div v-if="props.entry.result" class="detail-result mono">
        {{ props.entry.result }}
      </div>
      <div v-if="props.entry.error" class="detail-error mono">
        {{ props.entry.error }}
      </div>
    </div>
  </div>
</template>

<style scoped>
.activity-row {
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-card);
  padding: var(--space-3) var(--space-4);
  cursor: pointer;
  transition: var(--transition-hover);
}

.activity-row:hover {
  border-color: var(--color-border-strong);
}

.row-main {
  display: flex;
  align-items: center;
  gap: var(--space-3);
}

.row-icon {
  color: var(--color-text-muted);
  flex-shrink: 0;
}

.row-info {
  flex: 1;
  min-width: 0;
}

.row-tool {
  font-size: var(--fs-mono);
}

.row-time {
  flex-shrink: 0;
}

.expand-icon {
  color: var(--color-text-muted);
  flex-shrink: 0;
}

.row-detail {
  margin-top: var(--space-3);
  padding-top: var(--space-3);
  border-top: 1px solid var(--color-border);
}

.detail-args, .detail-result {
  font-size: var(--fs-mono);
  color: var(--color-text-muted);
  white-space: pre-wrap;
  word-break: break-all;
}

.detail-error {
  font-size: var(--fs-mono);
  color: var(--color-error);
}
</style>
