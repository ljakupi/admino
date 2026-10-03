<script setup lang="ts">
/**
 * Organization console's Users tab (issue #165): the org's users and pending
 * invitations, search and status filter, the invite sheet, the edit
 * (name/email) sheet and one confirm sheet shared by every row action that
 * needs confirmation. All state and business logic live in
 * `stores/orgUsers.ts`; this component binds the store to the template and
 * forwards row events.
 *
 * Security note: user-supplied names and emails are rendered as plain text
 * interpolation only, never `v-html`.
 */
import { computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Users as UsersIcon } from 'lucide-vue-next';
import BaseButton from '@/components/BaseButton.vue';
import BaseInput from '@/components/BaseInput.vue';
import ConfirmSheet from '@/components/ConfirmSheet.vue';
import OrgUserRow from '@/components/OrgUserRow.vue';
import OrgInvitationRow from '@/components/OrgInvitationRow.vue';
import OrgInviteSheet from '@/components/OrgInviteSheet.vue';
import OrgEditUserSheet from '@/components/OrgEditUserSheet.vue';
import EmptyState from '@/components/EmptyState.vue';
import { useOrgUsersStore } from '@/stores/orgUsers';
import { useAuthStore } from '@/stores/auth';
import { canManageOrgPermissions, homePath } from '@/services/access';
import { STATUS_FILTERS, confirmCopy, displayName, type ConfirmCopy, type StatusFilter } from '@/services/orgUsers';
import { useI18n, type MessageKey } from '@/i18n';
import type { MemberRole } from '@/api/types';

const { t } = useI18n();
const router = useRouter();
const store = useOrgUsersStore();
const auth = useAuthStore();

onMounted(() => store.load());

function isSelf(userId: string): boolean {
  return auth.me?.user_id === userId;
}

const editUser = computed(() => store.users.find((user) => user.id === store.editUserId) ?? null);

const showInvitations = computed(() => store.statusFilter === 'all' || store.statusFilter === 'invited');

const FILTER_LABEL_KEYS: Record<StatusFilter, MessageKey> = {
  all: 'orgUsers.filter.all',
  active: 'orgUsers.filter.active',
  deactivated: 'orgUsers.filter.deactivated',
  invited: 'orgUsers.filter.invited',
};

const confirmSheetCopy = computed<ConfirmCopy | null>(() => {
  const pending = store.pending;
  if (pending === null) return null;

  if (pending.kind === 'revokeInvitation') {
    const invitation = store.invitations.find((i) => i.id === pending.invitationId);
    return confirmCopy('revokeInvitation', invitation?.email ?? '');
  }

  const user = store.users.find((u) => u.id === pending.userId);
  const subject = user !== undefined ? displayName(user) : '';

  if (pending.kind === 'role') {
    return confirmCopy('role', subject, { role: pending.role, isSelf: isSelf(pending.userId) });
  }
  if (pending.kind === 'deactivate' || pending.kind === 'delete') {
    return confirmCopy(pending.kind, subject, { isSelf: isSelf(pending.userId) });
  }
  return confirmCopy(pending.kind, subject);
});

async function confirmAction(): Promise<void> {
  const pending = store.pending;
  const outcome = await store.confirmPending();

  if (outcome === 'signed_out') {
    await router.push('/login');
    return;
  }
  if (outcome === 'done' && pending?.kind === 'role' && isSelf(pending.userId) && !canManageOrgPermissions(auth.role)) {
    await router.push(homePath(auth.role));
  }
}

function onChangeRole(userId: string, role: MemberRole): void {
  store.requestRoleChange(userId, role);
}

function onEditSubmit(input: { name: string; email: string }): void {
  void store.submitEdit(input);
}

function onInviteSubmit(email: string, role: MemberRole): void {
  void store.submitInvite(email, role);
}

function onResend(invitationId: string): void {
  void store.resendInvitation(invitationId);
}
</script>

<template>
  <div class="org-users-panel">
    <header class="panel-header">
      <div>
        <h2 class="panel-title">{{ t('orgUsers.title') }}</h2>
        <p v-if="store.seatText" class="seat-text caption" :class="{ full: store.noFreeSeat }">
          {{ store.seatText }}
        </p>
      </div>
      <BaseButton variant="primary" @click="store.openInvite()">{{ t('orgUsers.invite.button') }}</BaseButton>
    </header>

    <p v-if="store.loadError" class="load-error" role="alert">{{ store.loadError }}</p>

    <div class="filters-row">
      <BaseInput
        :model-value="store.query"
        :label="t('orgUsers.search.label')"
        :placeholder="t('orgUsers.search.placeholder')"
        @update:model-value="store.setQuery($event)"
      />
      <div class="chips" role="tablist" :aria-label="t('orgUsers.filter.label')">
        <button
          v-for="status in STATUS_FILTERS"
          :key="status"
          type="button"
          role="tab"
          class="chip"
          :class="{ on: store.statusFilter === status }"
          :aria-selected="store.statusFilter === status"
          @click="store.setStatusFilter(status)"
        >
          {{ t(FILTER_LABEL_KEYS[status]) }}
        </button>
      </div>
    </div>

    <ul v-if="store.visibleUsers.length > 0" class="user-list">
      <OrgUserRow
        v-for="user in store.visibleUsers"
        :key="user.id"
        :user="user"
        :is-self="isSelf(user.id)"
        @change-role="(role) => onChangeRole(user.id, role)"
        @edit="store.openEdit(user.id)"
        @deactivate="store.requestDeactivate(user.id)"
        @reactivate="store.requestReactivate(user.id)"
        @reset-password="store.requestPasswordReset(user.id)"
        @force-logout="store.requestForceLogout(user.id)"
        @delete="store.requestDelete(user.id)"
      />
    </ul>
    <EmptyState v-else-if="store.loaded" :icon="UsersIcon" :heading="t('orgUsers.empty.users')" />

    <section v-if="showInvitations" class="invitations-section">
      <h3 class="section-title">{{ t('orgUsers.invitations.title') }}</h3>
      <ul v-if="store.visibleInvitations.length > 0" class="invitation-list">
        <OrgInvitationRow
          v-for="invitation in store.visibleInvitations"
          :key="invitation.id"
          :invitation="invitation"
          @resend="onResend(invitation.id)"
          @revoke="store.requestRevokeInvitation(invitation.id)"
        />
      </ul>
      <p v-else-if="store.loaded" class="empty-note caption">{{ t('orgUsers.empty.invitations') }}</p>
    </section>

    <OrgInviteSheet
      :open="store.inviteOpen"
      :busy="store.inviteBusy"
      :error="store.inviteError"
      :seat-text="store.seatText"
      :no-free-seat="store.noFreeSeat"
      @submit="onInviteSubmit"
      @close="store.closeInvite()"
    />

    <OrgEditUserSheet
      :user="editUser"
      :busy="store.editBusy"
      :error="store.editError"
      @submit="onEditSubmit"
      @close="store.closeEdit()"
    />

    <ConfirmSheet
      v-if="confirmSheetCopy"
      :heading="confirmSheetCopy.heading"
      :subtext="confirmSheetCopy.subtext"
      :confirm-label="confirmSheetCopy.confirmLabel"
      :variant="confirmSheetCopy.destructive ? 'destructive' : 'neutral'"
      :busy="store.actionBusy"
      @confirm="confirmAction"
      @cancel="store.cancelPending()"
    >
      <p v-if="store.actionError" class="error-text" role="alert">{{ store.actionError }}</p>
    </ConfirmSheet>
  </div>
</template>

<style scoped>
.org-users-panel {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.panel-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.panel-title {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 18px;
  color: var(--color-text);
  margin: 0;
}

.seat-text {
  color: var(--color-text-muted);
  margin-top: 2px;
}

.seat-text.full {
  color: var(--color-error);
}

.load-error {
  color: var(--color-error);
  font-size: 13px;
}

.filters-row {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.chips {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 4px;
  padding: 3px;
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border);
  border-radius: 8px;
  width: fit-content;
}

.chip {
  font-family: inherit;
  font-size: 12px;
  font-weight: 500;
  padding: 8px 12px;
  min-height: 44px;
  border-radius: 6px;
  border: 0;
  background: transparent;
  color: #475560;
  cursor: pointer;
}

.chip.on {
  background: #F5F7F5;
  color: var(--color-text);
}

.user-list,
.invitation-list {
  list-style: none;
  margin: 0;
  padding: 0;
  border-top: 1px solid var(--color-border);
}

.invitations-section {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.section-title {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 15px;
  color: var(--color-text);
  margin: 0;
}

.empty-note {
  color: var(--color-text-muted);
}

.error-text {
  color: var(--color-error);
  font-size: 13px;
}
</style>
