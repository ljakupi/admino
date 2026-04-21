<script setup lang="ts">
import { ref, computed } from 'vue';
import { Info, X } from 'lucide-vue-next';
import PermissionRow from '@/components/PermissionRow.vue';
import permissionsData from '@/data/permissions.json';

const HARDCODED_DENIALS = new Set([
  'gmail.send', 'gmail.delete',
  'google_calendar.delete', 'google_calendar.update',
  'google_drive.delete',
  'outlook.send', 'outlook.delete',
  'outlook_calendar.delete', 'outlook_calendar.update',
  'onedrive.delete',
  'documents.delete',
  'files.delete', 'files.overwrite',
  'memory.delete',
]);

interface PermEntry {
  tool: string;
  action: string;
  status: 'allow' | 'confirm' | 'deny';
  hardcoded: boolean;
}

const allEntries = computed<PermEntry[]>(() => {
  const entries: PermEntry[] = [];
  const tools = (permissionsData as Record<string, unknown>).tools as Record<string, Record<string, string>>;
  for (const [tool, actions] of Object.entries(tools)) {
    for (const [action, status] of Object.entries(actions)) {
      entries.push({
        tool,
        action,
        status: status as 'allow' | 'confirm' | 'deny',
        hardcoded: HARDCODED_DENIALS.has(`${tool}.${action}`),
      });
    }
  }
  return entries;
});

const search = ref('');
const statusFilter = ref<'all' | 'allow' | 'confirm' | 'deny'>('all');
const bannerDismissed = ref(false);

const filtered = computed(() => {
  let items = allEntries.value;
  if (search.value) {
    const q = search.value.toLowerCase();
    items = items.filter(
      (e) => e.tool.includes(q) || e.action.includes(q),
    );
  }
  if (statusFilter.value !== 'all') {
    items = items.filter((e) => e.status === statusFilter.value);
  }
  return items;
});

const filterOptions = [
  { value: 'all', label: 'All' },
  { value: 'allow', label: 'Allowed' },
  { value: 'confirm', label: 'Approval required' },
  { value: 'deny', label: 'Denied' },
] as const;
</script>

<template>
  <div class="permissions-page">
    <header class="page-header">
      <h1>Permissions</h1>
    </header>

    <div class="page-content">
      <div
        v-if="!bannerDismissed"
        class="info-banner"
      >
        <Info :size="16" :stroke-width="1.75" />
        <span>Permissions are managed via <code>permissions.yaml</code>. UI editing coming soon.</span>
        <button class="banner-close" aria-label="Dismiss" @click="bannerDismissed = true">
          <X :size="14" />
        </button>
      </div>

      <div class="filter-bar">
        <input
          v-model="search"
          class="search-input"
          type="text"
          placeholder="Search tools or actions..."
        />
        <select v-model="statusFilter" class="filter-select">
          <option v-for="opt in filterOptions" :key="opt.value" :value="opt.value">
            {{ opt.label }}
          </option>
        </select>
      </div>

      <div class="table-wrap">
        <table class="perm-table">
          <thead>
            <tr>
              <th>Tool</th>
              <th>Action</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <PermissionRow
              v-for="entry in filtered"
              :key="`${entry.tool}.${entry.action}`"
              :tool="entry.tool"
              :action="entry.action"
              :status="entry.status"
              :hardcoded="entry.hardcoded"
            />
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<style scoped>
.permissions-page {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
}

.page-header {
  padding: var(--space-4);
  border-bottom: 1px solid var(--color-border);
  background: var(--color-bg-surface);
  flex-shrink: 0;
}

.page-content {
  flex: 1;
  overflow-y: auto;
  padding: var(--space-4);
  max-width: var(--content-max);
  margin: 0 auto;
  width: 100%;
}

.info-banner {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-3) var(--space-4);
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-card);
  margin-bottom: var(--space-4);
  font-size: 14px;
  color: var(--color-text-muted);
}

.info-banner code {
  background: var(--color-bg);
  padding: 1px var(--space-1);
  border-radius: 4px;
}

.banner-close {
  margin-left: auto;
  cursor: pointer;
  color: var(--color-text-muted);
  flex-shrink: 0;
}

.filter-bar {
  display: flex;
  gap: var(--space-3);
  margin-bottom: var(--space-4);
}

.search-input {
  flex: 1;
  height: 40px;
  padding: 0 var(--space-3);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-input);
  background: var(--color-bg-surface);
  font-size: var(--fs-body);
}

.search-input:focus {
  outline: none;
  border-color: var(--color-primary);
}

.filter-select {
  height: 40px;
  padding: 0 var(--space-3);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-input);
  background: var(--color-bg-surface);
  font-size: var(--fs-body);
  cursor: pointer;
}

.table-wrap {
  overflow-x: auto;
}

.perm-table {
  width: 100%;
  border-collapse: collapse;
}

.perm-table th {
  padding: var(--space-3) var(--space-4);
  text-align: left;
  font-weight: var(--fw-semibold);
  font-size: var(--fs-caption);
  color: var(--color-text-muted);
  border-bottom: 2px solid var(--color-border);
}
</style>
