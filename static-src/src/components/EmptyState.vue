<script setup lang="ts">
import type { Component } from 'vue';

defineProps<{
  icon: Component;
  heading: string;
  subtext?: string;
}>();
</script>

<template>
  <div class="empty-state">
    <component :is="icon" :size="48" :stroke-width="1.25" class="empty-icon" />
    <h2 class="empty-heading">{{ heading }}</h2>
    <p v-if="subtext" class="empty-subtext caption">{{ subtext }}</p>
    <slot />
  </div>
</template>

<style scoped>
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: var(--space-12) var(--space-6);
  gap: var(--space-3);
  flex: 1;
}

.empty-icon {
  color: var(--color-text-muted);
  opacity: 0.5;
}

.empty-heading {
  font-size: var(--fs-h2-mobile);
  color: var(--color-text);
}

.empty-subtext {
  max-width: 280px;
}
</style>
