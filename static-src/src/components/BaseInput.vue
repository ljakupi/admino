<script setup lang="ts">
defineProps<{
  label?: string;
  type?: string;
  placeholder?: string;
  error?: string;
  hint?: string;
  disabled?: boolean;
  modelValue?: string;
  autocomplete?: string;
  name?: string;
  maxlength?: number;
  required?: boolean;
  readonly?: boolean;
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
      :autocomplete="autocomplete"
      :name="name"
      :maxlength="maxlength"
      :required="required"
      :readonly="readonly"
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
  gap: 6px;
}

.input-label {
  font-size: 13px;
  font-weight: 500;
  color: #475560;
}

.input-field {
  padding: 10px 14px;
  background: #FFFFFF;
  border: 1px solid #CFC7B4;
  border-radius: var(--radius-input);
  font-size: 14px;
  font-weight: 400;
  color: var(--color-text);
  transition: border-color var(--dur-fast) var(--ease);
}

.input-field::placeholder {
  color: #8A9199;
  font-weight: 400;
}

.input-field:focus {
  outline: 2px solid rgba(7, 94, 84, 0.18);
  outline-offset: 0;
  border-color: var(--color-primary);
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
