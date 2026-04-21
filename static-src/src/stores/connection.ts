import { defineStore } from 'pinia';
import { ref, onUnmounted } from 'vue';
import type { HealthResponse } from '@/api/types';

export type ConnectionState = 'idle' | 'working' | 'awaiting' | 'offline';

export const useConnectionStore = defineStore('connection', () => {
  const state = ref<ConnectionState>('offline');
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  async function checkHealth(): Promise<boolean> {
    try {
      const res = await fetch('/health');
      if (res.ok) {
        const data = (await res.json()) as HealthResponse;
        if (data.status === 'ok' && state.value === 'offline') {
          state.value = 'idle';
        }
        return true;
      }
    } catch {
      // network error
    }
    state.value = 'offline';
    return false;
  }

  function startPolling() {
    checkHealth();
    pollTimer = setInterval(checkHealth, 10_000);
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function setWorking() {
    if (state.value !== 'offline') state.value = 'working';
  }

  function setAwaiting() {
    if (state.value !== 'offline') state.value = 'awaiting';
  }

  function setIdle() {
    if (state.value !== 'offline') state.value = 'idle';
  }

  return { state, checkHealth, startPolling, stopPolling, setWorking, setAwaiting, setIdle };
});
