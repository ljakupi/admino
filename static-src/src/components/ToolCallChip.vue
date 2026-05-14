<script setup lang="ts">
import { ref, computed } from 'vue';
import { ChevronDown, ChevronUp } from 'lucide-vue-next';
import ToolCallCard from './ToolCallCard.vue';
import type { ToolCallUI } from '@/api/types';

const props = defineProps<{
  toolCalls: ToolCallUI[];
}>();

const expanded = ref(false);

/** Unique tool names for the chip label */
const toolNames = computed(() => {
  const seen = new Set<string>();
  for (const tc of props.toolCalls) {
    seen.add(tc.tool);
  }
  return [...seen];
});

const dotClass = computed(() => {
  const hasError = props.toolCalls.some((tc) => tc.state === 'error');
  const hasDenied = props.toolCalls.some((tc) => tc.state === 'denied');
  if (hasError || hasDenied) return 'dot-error';
  return 'dot-ok';
});
</script>

<template>
  <div class="chip-wrap">
    <button class="tc-chip" :class="{ multi: toolCalls.length > 1 }" @click="expanded = !expanded">
      <span class="dot" :class="dotClass" />
      <template v-if="toolCalls.length === 1">
        <span class="tool">{{ toolCalls[0].tool }}</span>
        <span class="sep">/</span>
        <span class="action">{{ toolCalls[0].action }}</span>
        <span class="sep">&middot;</span>
        <span class="state-label">{{ toolCalls[0].state }}</span>
      </template>
      <template v-else>
        <span v-for="(name, i) in toolNames" :key="name">
          <span v-if="i > 0" class="sep">&middot;</span>
          <span class="tool">{{ name }}</span>
        </span>
        <span class="count">{{ toolCalls.length }}</span>
      </template>
      <component :is="expanded ? ChevronUp : ChevronDown" :size="12" class="caret" />
    </button>

    <div v-if="expanded" class="chip-detail">
      <ToolCallCard
        v-for="tc in toolCalls"
        :key="tc.id"
        :tool-call="tc"
        :readonly="true"
      />
    </div>
  </div>
</template>

<style scoped>
.chip-wrap {
  align-self: flex-start;
  display: flex;
  flex-direction: column;
  gap: 0;
  max-width: 82%;
}

.tc-chip {
  align-self: flex-start;
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  padding: 4px 10px 4px 8px;
  background: var(--color-bg);
  border: 1px solid var(--color-border);
  border-radius: 12px 12px 12px 4px;
  font-size: 12px;
  color: var(--color-text-muted);
  line-height: 1.4;
  cursor: pointer;
  transition: background var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
  margin-left: 6px;
  margin-bottom: -4px;
  position: relative;
  z-index: 1;
}

.tc-chip:hover {
  background: var(--color-bg-surface);
  border-color: var(--color-border-strong);
}

.dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  flex-shrink: 0;
}

.dot-ok {
  background: var(--color-sage);
}

.dot-error {
  background: var(--color-error);
}

.tool {
  color: var(--color-primary-mid);
  font-weight: var(--fw-medium);
}

.action {
  color: var(--color-text-muted);
  font-weight: var(--fw-regular);
}

.sep {
  color: var(--color-border-strong);
}

.state-label {
  color: var(--color-text-muted);
}

.count {
  background: rgba(37, 211, 102, 0.15);
  color: #1F5C2F;
  padding: 1px 6px;
  border-radius: 10px;
  font-size: 10px;
  font-weight: var(--fw-medium);
  margin-left: 2px;
}

.caret {
  color: var(--color-text-muted);
  opacity: 0.6;
  margin-left: 2px;
}

.chip-detail {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
  margin-top: var(--space-2);
  padding-left: 6px;
}
</style>
