import { onUnmounted, ref } from 'vue';
import { openEventStream, type SSECallbacks } from '@/api/events';

export function useSSE(sessionId: string, callbacks: SSECallbacks) {
  const connected = ref(false);
  let stream: { close: () => void } | null = null;

  function connect() {
    close();
    stream = openEventStream(sessionId, {
      ...callbacks,
      onStatus: (data) => {
        if (data.status === 'connected') connected.value = true;
        callbacks.onStatus?.(data);
      },
      onDisconnect: () => {
        connected.value = false;
        callbacks.onDisconnect?.();
      },
    });
  }

  function close() {
    stream?.close();
    stream = null;
    connected.value = false;
  }

  onUnmounted(close);

  return { connected, connect, close };
}
