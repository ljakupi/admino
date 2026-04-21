<script setup lang="ts">
import Toast from './Toast.vue';
import { useToastStore } from '@/stores/toasts';

const toastStore = useToastStore();
</script>

<template>
  <div class="toast-host" aria-live="assertive">
    <TransitionGroup name="toast">
      <Toast
        v-for="t in toastStore.toasts"
        :key="t.id"
        :kind="t.kind"
        :title="t.title"
        :body="t.body"
        @dismiss="toastStore.remove(t.id)"
      />
    </TransitionGroup>
  </div>
</template>

<style scoped>
.toast-host {
  position: fixed;
  bottom: calc(var(--tabbar-h) + var(--space-4));
  left: 50%;
  transform: translateX(-50%);
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
  z-index: 1000;
  pointer-events: none;
}

.toast-host > :deep(*) {
  pointer-events: auto;
}

@media (min-width: 768px) {
  .toast-host {
    bottom: var(--space-6);
  }
}

.toast-enter-active,
.toast-leave-active {
  transition: all var(--dur-med) var(--ease);
}
.toast-enter-from {
  opacity: 0;
  transform: translateY(16px);
}
.toast-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}
</style>
