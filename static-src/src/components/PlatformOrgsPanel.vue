<script setup lang="ts">
/**
 * Organizations tab of the Platform console (issue #168): the list (no budget
 * column in V1), the create and edit-limits sheets and the row actions. All
 * rules live in `stores/platformOrgs.ts` / `services/platformOrgs.ts`; this
 * component binds state and forwards events. Names render as text.
 */
import { computed, onMounted } from 'vue';
import { Building2 } from 'lucide-vue-next';
import BaseButton from '@/components/BaseButton.vue';
import ConfirmSheet from '@/components/ConfirmSheet.vue';
import EmptyState from '@/components/EmptyState.vue';
import PlatformActionMenu, { type ActionMenuItem } from '@/components/PlatformActionMenu.vue';
import PlatformOrgFormSheet from '@/components/PlatformOrgFormSheet.vue';
import { usePlatformOrgsStore } from '@/stores/platformOrgs';
import {
  bytesToGib,
  limitsInputFrom,
  orgActions,
  orgStatusLabel,
  type OrgAction,
  type OrgCreateInput,
  type OrgLimitsInput,
} from '@/services/platformOrgs';
import { useI18n, type MessageKey } from '@/i18n';
import type { OrgStatus, PlatformOrg } from '@/api/types';

const { t, formatDate, formatNumber } = useI18n();
const store = usePlatformOrgsStore();

const emit = defineEmits<{
  open: [orgId: string];
}>();

onMounted(() => {
  void store.load();
});

const BADGE: Record<OrgStatus, 'leaf' | 'clay' | 'amber'> = {
  active: 'leaf',
  deactivated: 'clay',
  pending_deletion: 'amber',
};

/** Badge variant for a server status; an unknown value gets the neutral variant. */
function badgeFor(status: string): 'leaf' | 'clay' | 'amber' | 'neutral' {
  return Object.hasOwn(BADGE, status) ? BADGE[status as OrgStatus] : 'neutral';
}

function gibText(org: PlatformOrg): string {
  return t('platform.orgs.storageGib', { gib: formatNumber(bytesToGib(org.storage_quota), { maximumFractionDigits: 2 }) });
}

function deletionText(org: PlatformOrg): string | null {
  if (org.status !== 'pending_deletion' || org.purge_after === null) return null;
  return t('platform.orgs.deletionOn', { date: formatDate(new Date(org.purge_after)) });
}

const ACTION_LABELS: Record<string, MessageKey> = {
  editLimits: 'platform.orgs.action.editLimits',
  deactivate: 'platform.orgs.action.deactivate',
  reactivate: 'platform.orgs.action.reactivate',
  scheduleDeletion: 'platform.orgs.action.scheduleDeletion',
  cancelDeletion: 'platform.orgs.action.cancelDeletion',
};

function menuItems(org: PlatformOrg): ActionMenuItem[] {
  return orgActions(org).map((action) => {
    if (action === 'residency') {
      return {
        key: action,
        label: t(org.data_residency ? 'platform.orgs.action.residencyOff' : 'platform.orgs.action.residencyOn'),
        destructive: org.data_residency,
      };
    }
    return {
      key: action,
      label: t(ACTION_LABELS[action]),
      destructive: action === 'deactivate' || action === 'scheduleDeletion',
    };
  });
}

function onAction(org: PlatformOrg, action: string): void {
  switch (action as OrgAction) {
    case 'editLimits':
      store.openLimits(org.id);
      break;
    case 'deactivate':
      store.requestDeactivate(org.id);
      break;
    case 'reactivate':
      store.requestReactivate(org.id);
      break;
    case 'scheduleDeletion':
      store.requestScheduleDeletion(org.id);
      break;
    case 'cancelDeletion':
      store.requestCancelDeletion(org.id);
      break;
    case 'residency':
      store.requestResidency(org.id, !org.data_residency);
      break;
  }
}

const limitsInitial = computed<OrgLimitsInput | null>(() => (store.limitsOrg ? limitsInputFrom(store.limitsOrg) : null));

function onCreate(input: OrgCreateInput): void {
  void store.submitCreate(input);
}

function onLimits(input: OrgCreateInput): void {
  void store.submitLimits({ seats: input.seats, budgetChf: input.budgetChf, storageGib: input.storageGib });
}
</script>

<template>
  <div class="orgs-panel">
    <div class="panel-header">
      <BaseButton variant="primary" @click="store.openCreate()">{{ t('platform.orgs.create') }}</BaseButton>
    </div>

    <p v-if="store.loadError" class="error-text" role="alert">
      {{ store.loadError }}
      <button type="button" class="link-btn" @click="store.load()">{{ t('common.retry') }}</button>
    </p>

    <p v-if="store.loading && !store.loaded" class="caption" role="status">{{ t('platform.orgs.loadingLabel') }}</p>

    <EmptyState
      v-else-if="store.loaded && store.orgs.length === 0"
      :icon="Building2"
      :heading="t('platform.orgs.empty.heading')"
      :subtext="t('platform.orgs.empty.subtext')"
    />

    <div v-else-if="store.orgs.length > 0" class="org-list" role="list">
      <div class="org-row org-head" aria-hidden="true">
        <span>{{ t('platform.orgs.col.name') }}</span>
        <span>{{ t('platform.orgs.col.status') }}</span>
        <span>{{ t('platform.orgs.col.seats') }}</span>
        <span>{{ t('platform.orgs.col.storage') }}</span>
        <span>{{ t('platform.orgs.col.residency') }}</span>
        <span />
      </div>
      <div v-for="org in store.orgs" :key="org.id" class="org-row" role="listitem">
        <button
          type="button"
          class="name-btn"
          :aria-label="t('platform.orgs.open', { name: org.name })"
          @click="emit('open', org.id)"
        >
          {{ org.name }}
        </button>
        <span class="cell status-cell">
          <span class="badge" :class="badgeFor(org.status)">{{ orgStatusLabel(org.status) }}</span>
          <span v-if="deletionText(org)" class="caption">{{ deletionText(org) }}</span>
        </span>
        <span class="cell">
          <span class="cell-label caption">{{ t('platform.orgs.col.seats') }}</span>
          {{ t('platform.orgs.seatLimit', { count: formatNumber(org.seats) }) }}
        </span>
        <span class="cell">
          <span class="cell-label caption">{{ t('platform.orgs.col.storage') }}</span>
          {{ gibText(org) }}
        </span>
        <span class="cell">
          <span class="cell-label caption">{{ t('platform.orgs.col.residency') }}</span>
          {{ t(org.data_residency ? 'platform.orgs.residency.on' : 'platform.orgs.residency.off') }}
        </span>
        <PlatformActionMenu
          :items="menuItems(org)"
          :label="t('platform.orgs.actionsLabel', { name: org.name })"
          @select="(key) => onAction(org, key)"
        />
      </div>
    </div>

    <PlatformOrgFormSheet
      v-if="store.createOpen"
      mode="create"
      :initial="null"
      :busy="store.createBusy"
      :errors="store.createErrors"
      :error="store.createError"
      @submit="onCreate"
      @close="store.closeCreate()"
    />
    <PlatformOrgFormSheet
      v-if="store.limitsOrg"
      mode="limits"
      :initial="limitsInitial"
      :busy="store.limitsBusy"
      :errors="store.limitsErrors"
      :error="store.limitsError"
      @submit="onLimits"
      @close="store.closeLimits()"
    />

    <ConfirmSheet
      v-if="store.pendingCopy"
      :heading="store.pendingCopy.heading"
      :subtext="store.pendingCopy.subtext"
      :confirm-label="store.pendingCopy.confirmLabel"
      :variant="store.pendingCopy.destructive ? 'destructive' : 'neutral'"
      :busy="store.actionBusy"
      @confirm="store.confirmPending()"
      @cancel="store.cancelPending()"
    >
      <p v-if="store.actionError" class="error-text" role="alert">{{ store.actionError }}</p>
    </ConfirmSheet>
  </div>
</template>

<style scoped>
.orgs-panel {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.panel-header {
  display: flex;
  justify-content: flex-end;
}

.error-text {
  color: var(--color-error);
  font-size: 13px;
  margin: 0;
}

.link-btn {
  min-height: 44px;
  padding: 0 8px;
  background: transparent;
  border: 0;
  color: var(--color-primary);
  font: inherit;
  text-decoration: underline;
  cursor: pointer;
}

.org-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.org-row {
  display: grid;
  grid-template-columns: 2fr 1.6fr 1fr 1fr 1.2fr 44px;
  gap: 12px;
  align-items: center;
  padding: 8px 12px;
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-card);
  font-size: 14px;
}

.org-head {
  background: transparent;
  border: 0;
  font-size: 12px;
  font-weight: 600;
  color: var(--color-text-muted);
}

.name-btn {
  min-height: 44px;
  padding: 0;
  text-align: left;
  font: inherit;
  font-weight: 600;
  color: var(--color-text);
  background: transparent;
  border: 0;
  cursor: pointer;
  overflow-wrap: anywhere;
}

.name-btn:hover {
  text-decoration: underline;
}

.cell {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.cell-label {
  display: none;
  color: var(--color-text-muted);
}

.badge {
  align-self: flex-start;
  padding: 4px 10px;
  border-radius: 20px;
  border: 1px solid transparent;
  font-size: 12px;
  font-weight: 500;
  white-space: nowrap;
}

.badge.leaf { background: #DCF8C6; color: #1F5C2F; border-color: #BFE6A3; }
.badge.amber { background: #FFF4DC; color: #8A5A14; border-color: #F1D495; }
.badge.clay { background: #FCE4E4; color: #8A2A2A; border-color: #F0BFBF; }

@media (max-width: 767px) {
  .org-head {
    display: none;
  }

  .org-row {
    grid-template-columns: 1fr 44px;
  }

  .name-btn {
    grid-column: 1;
  }

  .cell {
    grid-column: 1 / -1;
    flex-direction: row;
    justify-content: space-between;
    gap: 8px;
  }

  .cell-label {
    display: inline;
  }
}
</style>
