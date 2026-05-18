<script setup lang="ts">
defineProps<{
  variant?: 'primary' | 'secondary' | 'destructive' | 'ghost' | 'warn';
  size?: 'md' | 'lg';
  disabled?: boolean;
  loading?: boolean;
}>();

defineEmits<{
  click: [e: MouseEvent];
}>();
</script>

<template>
  <button
    class="base-btn"
    :class="[
      `variant-${variant ?? 'primary'}`,
      `size-${size ?? 'md'}`,
      { loading },
    ]"
    :disabled="disabled || loading"
    @click="$emit('click', $event)"
  >
    <span v-if="loading" class="spinner" />
    <slot />
  </button>
</template>

<style scoped>
.base-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-2);
  border-radius: var(--radius-input);
  font-weight: var(--fw-semibold);
  font-size: var(--fs-body);
  min-height: 44px;
  padding: 10px 16px;
  transition: var(--transition-hover);
  cursor: pointer;
  user-select: none;
  white-space: nowrap;
}

.base-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* Variants */
.variant-primary {
  background: var(--color-primary);
  color: var(--color-text-on-dark);
}
.variant-primary:hover:not(:disabled) {
  background: var(--color-primary-hover);
}
.variant-primary:active:not(:disabled) {
  background: var(--color-primary-press);
}

.variant-secondary {
  background: #FFFFFF;
  color: var(--color-text);
  border: 1px solid #CFC7B4;
}
.variant-secondary:hover:not(:disabled) {
  background: var(--color-bg);
}

.variant-destructive {
  background: transparent;
  color: var(--color-error);
  border: 1px solid var(--color-error);
}
.variant-destructive:hover:not(:disabled) {
  background: var(--color-error-soft);
}

.variant-ghost {
  background: #FFFFFF;
  color: #475560;
  border: 1px solid #E4DFD4;
}
.variant-ghost:hover:not(:disabled) {
  color: var(--color-text);
  background: var(--color-bg);
}

.variant-warn {
  background: #E9A23B;
  color: #3A2608;
  border: 1px solid #E9A23B;
}
.variant-warn:hover:not(:disabled) {
  background: #D4912F;
  border-color: #D4912F;
}

/* Sizes */
.size-lg {
  min-height: 48px;
  padding: var(--space-3) var(--space-6);
  font-size: 16px;
}

/* Loading */
.spinner {
  width: 16px;
  height: 16px;
  border: 2px solid currentColor;
  border-right-color: transparent;
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}
</style>
