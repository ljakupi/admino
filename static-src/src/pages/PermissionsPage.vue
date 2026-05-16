<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { usePermissionsStore } from '@/stores/permissions';
import ToolRow from '@/components/ToolRow.vue';
import type { PermissionState } from '@/api/types';

const store = usePermissionsStore();

const activeFilter = ref<'all' | PermissionState>('all');

const filteredGroups = computed(() => {
  if (activeFilter.value === 'all') {
    return [...store.toolGroups.entries()];
  }
  const result: [string, typeof store.toolGroups extends Map<string, infer V> ? V : never][] = [];
  for (const [tool, entries] of store.toolGroups.entries()) {
    const filtered = entries.filter((e) => e.permission === activeFilter.value);
    if (filtered.length > 0) {
      result.push([tool, filtered]);
    }
  }
  return result;
});

const toolCount = computed(() => store.toolGroups.size);
const actionCount = computed(() => store.permissions.length);
const statusCounts = computed(() => store.statusCounts);

onMounted(() => store.loadPermissions());
</script>

<template>
  <div class="permissions-page">
    <div class="page-content">
      <div class="toolbar">
        <div>
          <h2 class="title">Permissions</h2>
          <div class="subtitle">{{ toolCount }} tools · {{ actionCount }} actions</div>
        </div>
        <div class="filters" role="tablist">
          <button
            :class="['filter-btn', activeFilter === 'all' && 'on']"
            @click="activeFilter = 'all'"
          >
            All <span class="count">{{ statusCounts.all }}</span>
          </button>
          <button
            :class="['filter-btn', activeFilter === 'allow' && 'on', 'is-allow']"
            @click="activeFilter = 'allow'"
          >
            Allowed <span class="count">{{ statusCounts.allow }}</span>
          </button>
          <button
            :class="['filter-btn', activeFilter === 'confirm' && 'on', 'is-approve']"
            @click="activeFilter = 'confirm'"
          >
            Needs approval <span class="count">{{ statusCounts.confirm }}</span>
          </button>
          <button
            :class="['filter-btn', activeFilter === 'deny' && 'on', 'is-deny']"
            @click="activeFilter = 'deny'"
          >
            Denied <span class="count">{{ statusCounts.deny }}</span>
          </button>
        </div>
      </div>

      <!-- Loading state -->
      <div v-if="store.loading" class="loading-state">
        Loading permissions...
      </div>

      <!-- Error state -->
      <div v-else-if="store.error" class="error-state">
        <p>{{ store.error }}</p>
        <button @click="store.loadPermissions()">Retry</button>
      </div>

      <!-- Permissions list -->
      <div v-else class="tools">
        <ToolRow
          v-for="[tool, entries] in filteredGroups"
          :key="tool"
          :tool="tool"
          :entries="entries"
        />
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

.page-content {
  flex: 1;
  overflow-y: auto;
  padding: 24px;
  max-width: 720px;
  margin: 0 auto;
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.title {
  font-family: 'Inter', sans-serif;
  font-weight: 600;
  font-size: 18px;
  letter-spacing: -0.01em;
  color: #111B21;
  margin: 0;
}

.subtitle {
  font-size: 12.5px;
  color: #667781;
  margin-top: 2px;
}

.filters {
  display: inline-flex;
  gap: 4px;
  padding: 3px;
  background: #FFFFFF;
  border: 1px solid #E4E8EA;
  border-radius: 8px;
}

.filter-btn {
  font-family: inherit;
  font-size: 12px;
  font-weight: 500;
  padding: 6px 12px;
  border-radius: 6px;
  border: 0;
  background: transparent;
  color: #475560;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.filter-btn.on {
  background: #F5F7F5;
  color: #111B21;
}

.count {
  font-size: 10.5px;
  padding: 1px 6px;
  border-radius: 10px;
  background: #E9EDEF;
  color: #475560;
  font-weight: 500;
}

.filter-btn.on.is-allow .count {
  background: #DCF8C6;
  color: #1F5C2F;
}

.filter-btn.on.is-approve .count {
  background: #FFF4DC;
  color: #8A5A14;
}

.filter-btn.on.is-deny .count {
  background: #EDEFF0;
  color: #475560;
}

.tools {
  background: #FFFFFF;
  border: 1px solid #E4E8EA;
  border-radius: 12px;
  overflow: hidden;
}

.loading-state,
.error-state {
  text-align: center;
  padding: 48px 24px;
  color: #667781;
}

.error-state button {
  margin-top: 12px;
  padding: 8px 16px;
  border-radius: 8px;
  border: 1px solid #E4E8EA;
  background: #FFFFFF;
  cursor: pointer;
}
</style>
