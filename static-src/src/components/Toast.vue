<script setup lang="ts">
import { X } from 'lucide-vue-next';
import type { ToastKind } from '@/stores/toasts';

defineProps<{
  kind: ToastKind;
  title: string;
  body?: string;
}>();

defineEmits<{
  dismiss: [];
}>();
</script>

<template>
  <div class="toast" :class="kind" role="alert">
    <div class="bar" />
    <div class="toast-content">
      <span class="toast-title">{{ title }}</span>
      <span v-if="body" class="toast-body">{{ body }}</span>
    </div>
    <button class="toast-close" aria-label="Dismiss" @click="$emit('dismiss')">
      <X :size="14" :stroke-width="2" />
    </button>
  </div>
</template>

<style scoped>
.toast {
  display: grid;
  grid-template-columns: 4px 1fr auto;
  column-gap: 14px;
  align-items: center;
  padding: 12px 14px;
  background: #FFFFFF;
  border: 1px solid #E4E8EA;
  border-radius: 12px;
  box-shadow:
    0 1px 2px rgba(17, 27, 33, 0.04),
    0 4px 16px rgba(17, 27, 33, 0.08);
  max-width: 360px;
  width: 100%;
}

.bar {
  width: 4px;
  height: 100%;
  border-radius: 3px;
  align-self: stretch;
}

.success .bar { background: #25D366; }
.warning .bar { background: #E9A23B; }
.error   .bar { background: #E35353; }
.info    .bar { background: var(--color-primary); }

.toast-content {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.toast-title {
  font-size: 13.5px;
  font-weight: var(--fw-semibold);
  color: #111B21;
  letter-spacing: -0.005em;
  line-height: 1.35;
}

.toast-body {
  font-size: 12.5px;
  color: #667781;
  line-height: 1.45;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.toast-close {
  width: 24px;
  height: 24px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  color: #8A9199;
  cursor: pointer;
  border-radius: 6px;
  transition: background var(--dur-fast) var(--ease), color var(--dur-fast) var(--ease);
}

.toast-close:hover {
  background: #F5F7F5;
  color: #475560;
}
</style>
