<script setup lang="ts">
defineProps<{
  ariaLabel?: string;
  disabled?: boolean;
}>();

defineEmits<{
  click: [e: MouseEvent];
}>();
</script>

<template>
  <button
    class="icon-btn"
    :aria-label="ariaLabel"
    :disabled="disabled"
    @click="$emit('click', $event)"
  >
    <slot />
  </button>
</template>

<style scoped>
.icon-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 44px;
  height: 44px;
  min-width: 44px;
  min-height: 44px;
  border-radius: var(--radius-input);
  color: var(--color-text-muted);
  transition: var(--transition-hover);
  cursor: pointer;
}

.icon-btn:hover:not(:disabled) {
  color: var(--color-text);
  background: var(--color-bg);
}

.icon-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}
</style>
