<script setup lang="ts">
import { CheckCircle, AlertTriangle, XCircle, Info, X } from 'lucide-vue-next';
import type { ToastKind } from '@/stores/toasts';

defineProps<{
  kind: ToastKind;
  title: string;
  body?: string;
}>();

defineEmits<{
  dismiss: [];
}>();

const icons = {
  success: CheckCircle,
  warning: AlertTriangle,
  error: XCircle,
  info: Info,
};
</script>

<template>
  <div class="toast" :class="kind" role="alert">
    <component :is="icons[kind]" :size="18" :stroke-width="1.75" class="toast-icon" />
    <div class="toast-content">
      <span class="toast-title">{{ title }}</span>
      <span v-if="body" class="toast-body caption">{{ body }}</span>
    </div>
    <button class="toast-close" aria-label="Dismiss" @click="$emit('dismiss')">
      <X :size="14" :stroke-width="2" />
    </button>
  </div>
</template>

<style scoped>
.toast {
  display: flex;
  align-items: flex-start;
  gap: var(--space-3);
  padding: var(--space-3) var(--space-4);
  background: var(--color-bg-elevated);
  border-radius: var(--radius-card);
  box-shadow: var(--shadow-modal);
  max-width: 360px;
  width: 100%;
  border-left: 3px solid;
  animation: slide-up var(--dur-med) var(--ease);
}

.success { border-left-color: var(--color-sage); }
.warning { border-left-color: var(--color-warn); }
.error   { border-left-color: var(--color-error); }
.info    { border-left-color: var(--color-primary); }

.toast-icon { flex-shrink: 0; margin-top: 1px; }
.success .toast-icon { color: var(--color-sage); }
.warning .toast-icon { color: var(--color-warn); }
.error   .toast-icon { color: var(--color-error); }
.info    .toast-icon { color: var(--color-primary); }

.toast-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.toast-title {
  font-size: 14px;
  font-weight: var(--fw-semibold);
}

.toast-body {
  color: var(--color-text-muted);
}

.toast-close {
  flex-shrink: 0;
  color: var(--color-text-muted);
  cursor: pointer;
  padding: var(--space-1);
}

@keyframes slide-up {
  from { transform: translateY(16px); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}
</style>
