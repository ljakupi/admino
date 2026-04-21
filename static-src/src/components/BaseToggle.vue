<script setup lang="ts">
defineProps<{
  modelValue: boolean;
  disabled?: boolean;
  ariaLabel?: string;
}>();

defineEmits<{
  'update:modelValue': [value: boolean];
}>();
</script>

<template>
  <button
    role="switch"
    class="toggle"
    :class="{ on: modelValue }"
    :aria-checked="modelValue"
    :aria-label="ariaLabel"
    :disabled="disabled"
    @click="$emit('update:modelValue', !modelValue)"
  >
    <span class="toggle-thumb" />
  </button>
</template>

<style scoped>
.toggle {
  width: 44px;
  height: 24px;
  border-radius: 12px;
  background: var(--color-border-strong);
  position: relative;
  cursor: pointer;
  transition: background-color var(--dur-fast) var(--ease);
  flex-shrink: 0;
}

.toggle.on {
  background: var(--color-primary);
}

.toggle:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.toggle-thumb {
  position: absolute;
  top: 2px;
  left: 2px;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background: white;
  transition: transform var(--dur-fast) var(--ease);
}

.toggle.on .toggle-thumb {
  transform: translateX(20px);
}
</style>
