<script setup lang="ts">
/**
 * Editable permission matrix (issue #161: moved from the top-level
 * Permissions page into the Organization console, Org Admin only). Every
 * tool/action row here is the org's stored permission state; changes go
 * through `usePermissionsStore().updatePermission` (`PATCH
 * /api/org/permissions`). Read-only Editors/Viewers see the effective
 * summary instead (`@/pages/PermissionsPage.vue`).
 */
import { ref, computed, onMounted } from 'vue';
import { usePermissionsStore } from '@/stores/permissions';
import ToolRow from '@/components/ToolRow.vue';
import type { PermissionState } from '@/api/types';
import { useI18n } from '@/i18n';

const { t } = useI18n();

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
  <div class="permission-matrix">
    <div class="toolbar">
      <div>
        <h2 class="title">{{ t('organization.permissions.title') }}</h2>
        <div class="subtitle">
          {{ t('permissions.page.toolCount', { count: toolCount }) }} · {{ t('permissions.page.actionCount', { count: actionCount }) }}
        </div>
      </div>
      <div class="filters" role="tablist">
        <button
          :class="['filter-btn', activeFilter === 'all' && 'on']"
          @click="activeFilter = 'all'"
        >
          {{ t('permissions.filter.all') }} <span class="count">{{ statusCounts.all }}</span>
        </button>
        <button
          :class="['filter-btn', activeFilter === 'allow' && 'on', 'is-allow']"
          @click="activeFilter = 'allow'"
        >
          {{ t('permissionState.allow') }} <span class="count">{{ statusCounts.allow }}</span>
        </button>
        <button
          :class="['filter-btn', activeFilter === 'confirm' && 'on', 'is-approve']"
          @click="activeFilter = 'confirm'"
        >
          {{ t('permissionState.confirm') }} <span class="count">{{ statusCounts.confirm }}</span>
        </button>
        <button
          :class="['filter-btn', activeFilter === 'deny' && 'on', 'is-deny']"
          @click="activeFilter = 'deny'"
        >
          {{ t('permissionState.deny') }} <span class="count">{{ statusCounts.deny }}</span>
        </button>
      </div>
    </div>

    <!-- Loading state -->
    <div v-if="store.loading" class="loading-state">
      {{ t('permissions.page.loading') }}
    </div>

    <!-- Error state -->
    <div v-else-if="store.error" class="error-state">
      <p>{{ store.error }}</p>
      <button @click="store.loadPermissions()">{{ t('common.retry') }}</button>
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
</template>

<style scoped>
.permission-matrix {
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
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 18px;
  letter-spacing: -0.015em;
  color: var(--color-text);
  margin: 0;
}

.subtitle {
  font-size: 12.5px;
  color: var(--color-text-muted);
  margin-top: 2px;
}

.filters {
  display: inline-flex;
  /* Longer DE/FR labels must wrap, not push filters off a phone screen. */
  flex-wrap: wrap;
  max-width: 100%;
  gap: 4px;
  padding: 3px;
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border);
  border-radius: 8px;
}

.filter-btn {
  font-family: inherit;
  font-size: 12px;
  font-weight: 500;
  padding: 6px 12px;
  min-height: 44px;
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
  color: var(--color-text);
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
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border);
  border-radius: 12px;
  overflow: hidden;
}

.loading-state,
.error-state {
  text-align: center;
  padding: 48px 24px;
  color: var(--color-text-muted);
}

.error-state button {
  margin-top: 12px;
  padding: 8px 16px;
  min-height: 44px;
  border-radius: 8px;
  border: 1px solid var(--color-border);
  background: var(--color-bg-elevated);
  cursor: pointer;
}
</style>
