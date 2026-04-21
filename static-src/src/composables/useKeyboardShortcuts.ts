import { onMounted, onUnmounted } from 'vue';

interface ShortcutOptions {
  onApprove?: () => void;
  onDeny?: () => void;
}

export function useKeyboardShortcuts(options: ShortcutOptions) {
  function handler(e: KeyboardEvent) {
    // Cmd+Enter or Ctrl+Enter → approve
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      options.onApprove?.();
      return;
    }

    // Escape → deny (only if not in an input)
    if (e.key === 'Escape') {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA') return;
      e.preventDefault();
      options.onDeny?.();
    }
  }

  onMounted(() => window.addEventListener('keydown', handler));
  onUnmounted(() => window.removeEventListener('keydown', handler));
}
