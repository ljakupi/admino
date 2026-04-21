<script setup lang="ts">
defineProps<{
  variant?: 'primary' | 'secondary' | 'destructive' | 'ghost';
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
  padding: var(--space-2) var(--space-5);
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
  background: transparent;
  color: var(--color-text);
  border: 1px solid var(--color-border-strong);
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
  background: transparent;
  color: var(--color-text-muted);
}
.variant-ghost:hover:not(:disabled) {
  color: var(--color-text);
  background: var(--color-bg);
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
