<script setup lang="ts">
/**
 * Org detail of the Platform console (issue #168): the organization's status,
 * metadata as counts only (never content) and its users with the row actions
 * the store allows. Loaded for the `?org=` query id; all rules live in
 * `stores/platformOrgDetail.ts`. Names and emails render as text.
 */
import { watch } from 'vue';
import { ArrowLeft, Building2 } from 'lucide-vue-next';
import ConfirmSheet from '@/components/ConfirmSheet.vue';
import EmptyState from '@/components/EmptyState.vue';
import PlatformActionMenu, { type ActionMenuItem } from '@/components/PlatformActionMenu.vue';
import PlatformReinviteSheet from '@/components/PlatformReinviteSheet.vue';
import { usePlatformOrgDetailStore } from '@/stores/platformOrgDetail';
import { bytesToGib, memberRoleLabel, orgStatusLabel, userStatusLabel, type UserAction } from '@/services/platformOrgs';
import { displayName } from '@/services/orgUsers';
import { useI18n, type MessageKey } from '@/i18n';
import type { PlatformUser } from '@/api/types';

const { t, formatDate, formatNumber } = useI18n();
const store = usePlatformOrgDetailStore();

const props = defineProps<{
  orgId: string;
}>();

const emit = defineEmits<{
  back: [];
}>();

watch(
  () => props.orgId,
  (id) => {
    void store.load(id);
  },
  { immediate: true },
);

const ACTION_LABELS: Record<UserAction, MessageKey> = {
  deactivate: 'platform.users.action.deactivate',
  reactivate: 'platform.users.action.reactivate',
  resetPassword: 'platform.users.action.resetPassword',
  reinvite: 'platform.users.action.reinvite',
};

function menuItems(user: PlatformUser): ActionMenuItem[] {
  return store.actionsFor(user.id).map((action) => ({
    key: action,
    label: t(ACTION_LABELS[action]),
    destructive: action === 'deactivate',
  }));
}

function onAction(user: PlatformUser, action: string): void {
  switch (action as UserAction) {
    case 'deactivate':
      store.requestDeactivate(user.id);
      break;
    case 'reactivate':
      store.requestReactivate(user.id);
      break;
    case 'resetPassword':
      store.requestPasswordReset(user.id);
      break;
    case 'reinvite':
      store.openReinvite(user.id);
      break;
  }
}

function lastLoginText(user: PlatformUser): string {
  return user.last_login_at === null
    ? t('orgUsers.neverLoggedIn')
    : t('orgUsers.lastLogin', { date: formatDate(new Date(user.last_login_at)) });
}

function onReinvite(email: string): void {
  void store.submitReinvite(email);
}
</script>

<template>
  <div class="org-detail">
    <button type="button" class="back-btn" @click="emit('back')">
      <ArrowLeft :size="16" :stroke-width="1.75" />
      {{ t('platform.detail.back') }}
    </button>

    <EmptyState
      v-if="store.notFound"
      :icon="Building2"
      :heading="t('platform.detail.notFound.heading')"
      :subtext="t('platform.detail.notFound.subtext')"
    />
    <p v-else-if="store.loadError" class="error-text" role="alert">
      {{ store.loadError }}
      <button type="button" class="link-btn" @click="store.load(orgId)">{{ t('common.retry') }}</button>
    </p>
    <p v-else-if="store.loading || !store.org" class="caption" role="status">{{ t('platform.detail.loadingLabel') }}</p>

    <template v-else>
      <header class="detail-header">
        <h2>{{ store.org.name }}</h2>
        <span class="caption">{{ orgStatusLabel(store.org.status) }}</span>
      </header>

      <section v-if="store.metadata" class="meta-card">
        <ul class="meta-list">
          <li v-if="store.seatText">{{ store.seatText }}</li>
          <li>
            {{
              t('platform.detail.storageUsed', {
                gib: formatNumber(bytesToGib(store.metadata.storage_used_bytes), { maximumFractionDigits: 2 }),
              })
            }}
          </li>
          <li>{{ t('platform.detail.chatCount', { count: formatNumber(store.metadata.chat_count) }) }}</li>
          <li>{{ t('platform.detail.fileCount', { count: formatNumber(store.metadata.file_count) }) }}</li>
        </ul>
        <p class="caption">{{ t('platform.detail.metadataNote') }}</p>
      </section>

      <section class="users">
        <h3>{{ t('platform.detail.users') }}</h3>
        <p v-if="store.users.length === 0" class="caption">{{ t('platform.detail.noUsers') }}</p>
        <ul v-else class="user-list">
          <li v-for="user in store.users" :key="user.id" class="user-row">
            <div class="user-main">
              <span class="user-name">{{ displayName(user) }}</span>
              <span class="caption user-email">{{ user.email }}</span>
              <span class="caption">
                {{ memberRoleLabel(user.role) }} · {{ userStatusLabel(user.status) }} ·
                {{ lastLoginText(user) }}
              </span>
            </div>
            <PlatformActionMenu
              :items="menuItems(user)"
              :label="t('platform.users.actionsLabel', { name: displayName(user) })"
              @select="(key) => onAction(user, key)"
            />
          </li>
        </ul>
      </section>
    </template>

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

    <PlatformReinviteSheet
      v-if="store.reinviteUserId"
      :busy="store.reinviteBusy"
      :error="store.reinviteError"
      @submit="onReinvite"
      @close="store.closeReinvite()"
    />
  </div>
</template>

<style scoped>
.org-detail {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.back-btn {
  align-self: flex-start;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  min-height: 44px;
  padding: 0 8px;
  background: transparent;
  border: 0;
  font: inherit;
  font-size: 14px;
  color: var(--color-primary);
  cursor: pointer;
}

.detail-header {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.detail-header h2 {
  overflow-wrap: anywhere;
}

.meta-card {
  padding: var(--space-4);
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-card);
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.meta-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-wrap: wrap;
  gap: 8px 24px;
  font-size: 14px;
}

.users {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.user-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.user-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 12px;
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-card);
}

.user-main {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.user-name {
  font-weight: 600;
  font-size: 14px;
  overflow-wrap: anywhere;
}

.user-email {
  overflow-wrap: anywhere;
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
</style>
