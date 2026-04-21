<script setup lang="ts">
import { type Component } from 'vue';
import BaseToggle from './BaseToggle.vue';

defineProps<{
  icon: Component;
  name: string;
  description: string;
  enabled: boolean;
  connected: boolean;
  locked?: boolean;
}>();

defineEmits<{
  toggle: [value: boolean];
}>();
</script>

<template>
  <div class="tool-group-card" :class="{ locked }">
    <div class="card-header">
      <component :is="icon" :size="20" :stroke-width="1.75" class="card-icon" />
      <div class="card-info">
        <span class="card-name body-strong">{{ name }}</span>
        <span class="card-desc caption">{{ description }}</span>
      </div>
      <BaseToggle
        :model-value="enabled"
        :disabled="locked"
        :aria-label="`Toggle ${name}`"
        @update:model-value="$emit('toggle', $event)"
      />
    </div>
    <div class="card-status">
      <span v-if="locked" class="status-locked caption">
        Restricted by security policy
      </span>
      <span v-else-if="connected" class="status-connected caption">
        Connected
      </span>
      <span v-else class="status-disconnected caption">
        Not connected
      </span>
    </div>
  </div>
</template>

<style scoped>
.tool-group-card {
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-card);
  padding: var(--space-4);
}

.tool-group-card.locked {
  opacity: 0.6;
}

.card-header {
  display: flex;
  align-items: flex-start;
  gap: var(--space-3);
}

.card-icon {
  color: var(--color-primary);
  flex-shrink: 0;
  margin-top: 2px;
}

.card-info {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.card-name {
  font-weight: var(--fw-semibold);
}

.card-status {
  margin-top: var(--space-3);
  padding-top: var(--space-3);
  border-top: 1px solid var(--color-border);
}

.status-connected {
  color: var(--color-sage);
}

.status-disconnected {
  color: var(--color-warn);
}

.status-locked {
  color: var(--color-text-muted);
}
</style>
