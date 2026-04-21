<script setup lang="ts">
defineProps<{
  label?: string;
  type?: string;
  placeholder?: string;
  error?: string;
  hint?: string;
  disabled?: boolean;
  modelValue?: string;
}>();

defineEmits<{
  'update:modelValue': [value: string];
  blur: [];
}>();
</script>

<template>
  <div class="input-group" :class="{ 'has-error': error }">
    <label v-if="label" class="input-label">{{ label }}</label>
    <input
      class="input-field"
      :type="type ?? 'text'"
      :placeholder="placeholder"
      :disabled="disabled"
      :value="modelValue"
      @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
      @blur="$emit('blur')"
    />
    <span v-if="error" class="input-error caption">{{ error }}</span>
    <span v-else-if="hint" class="input-hint caption">{{ hint }}</span>
  </div>
</template>

<style scoped>
.input-group {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
}

.input-label {
  font-size: var(--fs-caption);
  font-weight: var(--fw-semibold);
  color: var(--color-text);
}

.input-field {
  height: 44px;
  padding: 0 var(--space-3);
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-input);
  font-size: var(--fs-body);
  color: var(--color-text);
  transition: border-color var(--dur-fast) var(--ease);
}

.input-field::placeholder {
  color: var(--color-text-muted);
}

.input-field:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: var(--shadow-focus);
}

.input-field:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.has-error .input-field {
  border-color: var(--color-error);
}

.input-error {
  color: var(--color-error);
}

.input-hint {
  color: var(--color-text-muted);
}
</style>
