<script setup lang="ts">
/**
 * Read-only permissions summary (issue #161): what the agent may do in the
 * caller's organization, for Editors and Viewers (the Org Admin edits the
 * matrix under Organization instead — no Permissions nav entry for them,
 * see `services/access.ts`). Fed by `usePermissionsStore().loadSummary()`
 * (`GET /api/permissions/summary`); states are allow / confirm / deny /
 * disabled (a tool whose service is switched off for the org). No edit
 * controls anywhere on this page.
 */
import { onMounted } from 'vue';
import { usePermissionsStore } from '@/stores/permissions';
import { useI18n, type MessageKey } from '@/i18n';

const { t } = useI18n();
const store = usePermissionsStore();

const STATE_LABEL_KEYS: Record<string, MessageKey> = {
  allow: 'permissionState.allow',
  confirm: 'permissionState.confirm',
  deny: 'permissionState.deny',
  disabled: 'permissionState.disabled',
};

onMounted(() => store.loadSummary());
</script>

<template>
  <div class="permissions-page">
    <div class="page-content">
      <div class="toolbar">
        <h2 class="title">{{ t('nav.permissions') }}</h2>
        <div class="subtitle">{{ t('permissions.summary.subtitle') }}</div>
      </div>

      <!-- Loading state -->
      <div v-if="store.summaryLoading" class="loading-state">
        {{ t('permissions.page.loading') }}
      </div>

      <!-- Error state -->
      <div v-else-if="store.summaryError" class="error-state">
        <p>{{ store.summaryError }}</p>
        <button @click="store.loadSummary()">{{ t('common.retry') }}</button>
      </div>

      <!-- Empty state -->
      <div v-else-if="store.summaryGroups.size === 0" class="empty-state">
        {{ t('permissions.summary.empty') }}
      </div>

      <!-- Summary list -->
      <div v-else class="tools">
        <div v-for="[tool, entries] in store.summaryGroups" :key="tool" class="tool-group">
          <div class="tool-head">{{ store.getToolMeta(tool).label }}</div>
          <div v-for="entry in entries" :key="entry.action" class="summary-row">
            <span class="a-name">{{ entry.action }}</span>
            <span class="a-desc">{{ store.getActionDescription(entry.tool, entry.action) }}</span>
            <span class="state-pill" :class="`is-${entry.state}`">{{ t(STATE_LABEL_KEYS[entry.state]) }}</span>
          </div>
        </div>
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
  flex-direction: column;
  gap: 2px;
}

.title {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 18px;
  letter-spacing: -0.01em;
  color: var(--color-text);
  margin: 0;
}

.subtitle {
  font-size: 12.5px;
  color: var(--color-text-muted);
}

.tools {
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border);
  border-radius: 12px;
  overflow: hidden;
}

.tool-group {
  border-bottom: 1px solid var(--color-border);
}

.tool-group:last-child {
  border-bottom: 0;
}

.tool-head {
  font-weight: var(--fw-semibold);
  font-size: 13px;
  color: var(--color-text);
  padding: 12px 18px 4px;
}

.summary-row {
  display: grid;
  grid-template-columns: 120px 1fr auto;
  align-items: center;
  gap: 12px;
  padding: 8px 18px;
  font-size: 13px;
}

.a-name {
  font-family: var(--font-mono);
  font-size: 12.5px;
  color: var(--color-text);
}

.a-desc {
  color: var(--color-text-muted);
  font-size: 12.5px;
}

.state-pill {
  display: inline-flex;
  align-items: center;
  padding: 2px 10px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 500;
  white-space: nowrap;
}

.state-pill.is-allow {
  background: #DCF8C6;
  color: #1F5C2F;
}

.state-pill.is-confirm {
  background: #FFF4DC;
  color: #8A5A14;
}

.state-pill.is-deny {
  background: #EDEFF0;
  color: #475560;
}

.state-pill.is-disabled {
  background: var(--color-border);
  color: var(--color-text-muted);
}

.loading-state,
.error-state,
.empty-state {
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
