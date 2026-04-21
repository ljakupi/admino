import { defineStore } from 'pinia';
import { ref } from 'vue';

export type ToastKind = 'success' | 'warning' | 'error' | 'info';

export interface Toast {
  id: string;
  kind: ToastKind;
  title: string;
  body?: string;
  duration: number;
}

let nextId = 0;

export const useToastStore = defineStore('toasts', () => {
  const toasts = ref<Toast[]>([]);

  function add(kind: ToastKind, title: string, body?: string, duration = 3000) {
    const id = `toast-${++nextId}`;
    const toast: Toast = { id, kind, title, body, duration };

    // Max 2 visible
    if (toasts.value.length >= 2) {
      toasts.value.shift();
    }
    toasts.value.push(toast);

    setTimeout(() => remove(id), duration);
    return id;
  }

  function remove(id: string) {
    const idx = toasts.value.findIndex((t) => t.id === id);
    if (idx !== -1) toasts.value.splice(idx, 1);
  }

  return { toasts, add, remove };
});
