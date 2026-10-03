<script setup lang="ts">
/**
 * One pending invitation row (issue #165): email, role, sent/expiry dates
 * (an expired invitation gets the Expired badge instead of its expiry date),
 * and the Resend / Revoke actions. Purely presentational.
 */
import { computed } from 'vue';
import { ROLE_LABEL_KEYS } from '@/services/orgUsers';
import { useI18n } from '@/i18n';
import type { OrgInvitation } from '@/api/types';

const { t, formatDate } = useI18n();

const props = defineProps<{
  invitation: OrgInvitation;
}>();

defineEmits<{
  resend: [];
  revoke: [];
}>();

const sentText = computed(() => t('orgUsers.invitations.sent', { date: formatDate(new Date(props.invitation.sent_at)) }));
const expiresText = computed(() =>
  t('orgUsers.invitations.expires', { date: formatDate(new Date(props.invitation.expires_at)) }),
);
</script>

<template>
  <li class="invitation-row">
    <div class="identity">
      <span class="email">{{ invitation.email }}</span>
      <span class="meta caption">{{ t(ROLE_LABEL_KEYS[invitation.role]) }} · {{ sentText }}</span>
    </div>

    <span v-if="invitation.expired" class="status-pill expired">{{ t('orgUsers.status.expired') }}</span>
    <span v-else class="expires caption">{{ expiresText }}</span>

    <div class="actions">
      <button type="button" class="link-btn" @click="$emit('resend')">
        {{ t('orgUsers.actions.resend') }}
      </button>
      <button type="button" class="link-btn danger" @click="$emit('revoke')">
        {{ t('orgUsers.actions.revoke') }}
      </button>
    </div>
  </li>
</template>

<style scoped>
.invitation-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 8px;
  border-bottom: 1px solid var(--color-border);
  flex-wrap: wrap;
}

.identity {
  display: flex;
  flex-direction: column;
  min-width: 180px;
  flex: 1;
}

.email {
  font-weight: var(--fw-semibold);
  color: var(--color-text);
}

.meta,
.expires {
  color: var(--color-text-muted);
}

.status-pill {
  font-size: 12px;
  font-weight: 500;
  padding: 4px 10px;
  border-radius: 20px;
  white-space: nowrap;
}

.status-pill.expired {
  background: #FCE4E4;
  color: #8A2A2A;
}

.actions {
  display: flex;
  gap: 4px;
}

.link-btn {
  min-height: 44px;
  padding: 8px 12px;
  border-radius: var(--radius-input);
  color: var(--color-primary);
  font-weight: 500;
  background: transparent;
}

.link-btn:hover {
  background: var(--color-bg);
}

.link-btn.danger {
  color: var(--color-error);
}
</style>
