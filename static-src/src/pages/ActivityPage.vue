<script setup lang="ts">
import { ref, computed } from 'vue';
import { Scroll } from 'lucide-vue-next';
import ActivityRow from '@/components/ActivityRow.vue';
import EmptyState from '@/components/EmptyState.vue';
import { useActivityStore, type ActivityFilter } from '@/stores/activity';

const activityStore = useActivityStore();
const filter = ref<ActivityFilter>('all');

const filters: { value: ActivityFilter; label: string }[] = [
  { value: 'today', label: 'Today' },
  { value: 'week', label: 'This week' },
  { value: 'all', label: 'All' },
];

const entries = computed(() => activityStore.filterEntries(filter.value));

/** Group entries by date string */
const grouped = computed(() => {
  const groups: { date: string; items: typeof entries.value }[] = [];
  let current = '';
  for (const e of entries.value) {
    const d = e.timestamp.toLocaleDateString();
    if (d !== current) {
      current = d;
      groups.push({ date: d, items: [] });
    }
    groups[groups.length - 1].items.push(e);
  }
  return groups;
});
</script>

<template>
  <div class="activity-page">
    <header class="page-header">
      <h1>Activity</h1>
      <div class="filter-bar">
        <button
          v-for="f in filters"
          :key="f.value"
          class="filter-btn"
          :class="{ active: filter === f.value }"
          @click="filter = f.value"
        >
          {{ f.label }}
        </button>
      </div>
    </header>

    <div class="page-content">
      <EmptyState
        v-if="entries.length === 0"
        :icon="Scroll"
        heading="No activity yet"
        subtext="Tool calls will appear here once you start chatting."
      />

      <template v-else>
        <div v-for="group in grouped" :key="group.date" class="date-group">
          <div class="date-header caption">{{ group.date }}</div>
          <div class="date-entries">
            <ActivityRow
              v-for="entry in group.items"
              v-memo="[entry.state]"
              :key="entry.id"
              :entry="entry"
            />
          </div>
        </div>
      </template>
    </div>
  </div>
</template>

<style scoped>
.activity-page {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
}

.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--space-4) var(--space-4);
  border-bottom: 1px solid var(--color-border);
  background: var(--color-bg-surface);
  flex-shrink: 0;
}

.filter-bar {
  display: flex;
  gap: var(--space-1);
}

.filter-btn {
  padding: var(--space-1) var(--space-3);
  border-radius: var(--radius-pill);
  font-size: var(--fs-caption);
  font-weight: var(--fw-medium);
  color: var(--color-text-muted);
  cursor: pointer;
  transition: var(--transition-hover);
}

.filter-btn.active {
  background: var(--color-primary);
  color: var(--color-text-on-dark);
}

.filter-btn:hover:not(.active) {
  background: var(--color-bg);
}

.page-content {
  flex: 1;
  overflow-y: auto;
  padding: var(--space-4);
}

.date-group {
  margin-bottom: var(--space-4);
}

.date-header {
  position: sticky;
  top: 0;
  background: var(--color-bg);
  padding: var(--space-2) 0;
  font-weight: var(--fw-semibold);
  z-index: 1;
}

.date-entries {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}
</style>
