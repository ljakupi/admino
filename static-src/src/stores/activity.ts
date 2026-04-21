import { defineStore } from 'pinia';
import { computed } from 'vue';
import { useChatStore } from './chat';

export type ActivityFilter = 'all' | 'today' | 'week';

export const useActivityStore = defineStore('activity', () => {
  const chatStore = useChatStore();

  const entries = computed(() => chatStore.toolCallHistory);

  function filterEntries(filter: ActivityFilter) {
    const now = new Date();
    const items = entries.value;

    if (filter === 'all') return items;

    const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());

    if (filter === 'today') {
      return items.filter((e) => e.timestamp >= startOfDay);
    }

    // week
    const dayOfWeek = now.getDay();
    const startOfWeek = new Date(startOfDay);
    startOfWeek.setDate(startOfWeek.getDate() - dayOfWeek);
    return items.filter((e) => e.timestamp >= startOfWeek);
  }

  return { entries, filterEntries };
});
