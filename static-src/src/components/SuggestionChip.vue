<script setup lang="ts">
defineProps<{
  label: string;
}>();

defineEmits<{
  click: [];
}>();
</script>

<template>
  <button class="chip" @click="$emit('click')">
    {{ label }}
  </button>
</template>

<style scoped>
.chip {
  padding: var(--space-2) var(--space-4);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-pill);
  font-size: var(--fs-caption);
  color: var(--color-text);
  cursor: pointer;
  transition: var(--transition-hover);
  white-space: nowrap;
}

.chip:hover {
  background: var(--color-bg-surface);
  border-color: var(--color-primary);
  color: var(--color-primary);
}
</style>
