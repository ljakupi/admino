<script setup lang="ts">
/**
 * My account: active sessions (issue #166). Renders the account store's
 * session list and forwards a revoke to it, confirmed with the shared
 * `ConfirmSheet`. Revoking the current session already ended it
 * server-side, so this card routes to the login page itself.
 */
import { onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import ConfirmSheet from './ConfirmSheet.vue';
import { describeUserAgent } from '@/services/account';
import { useAccountStore } from '@/stores/account';
import { useI18n, type MessageKey } from '@/i18n';
import type { SessionSummary } from '@/api/types';

const { t, formatDate } = useI18n();
const router = useRouter();
const account = useAccountStore();

const pendingRevoke = ref<SessionSummary | null>(null);
const revokeErrorKey = ref<MessageKey | null>(null);

onMounted(() => {
  void account.loadSessions();
});

function deviceLabel(session: SessionSummary): string {
  const description = describeUserAgent(session.user_agent);
  if (description.kind === 'device') {
    if (description.browser && description.os) {
      return t('account.sessions.device', { browser: description.browser, os: description.os });
    }
    return description.browser ?? description.os ?? t('account.sessions.unknownDevice');
  }
  if (description.kind === 'agent') return description.text;
  return t('account.sessions.unknownDevice');
}

function ipLabel(session: SessionSummary): string {
  return session.ip ? t('account.sessions.ip', { ip: session.ip }) : t('account.sessions.ipUnknown');
}

function lastSeenLabel(session: SessionSummary): string {
  return t('account.sessions.lastSeen', { date: formatDate(new Date(session.last_seen_at)) });
}

async function confirmRevoke(): Promise<void> {
  const target = pendingRevoke.value;
  if (!target) return;
  pendingRevoke.value = null;

  const result = await account.revokeSession(target.id);
  if (result.ok) {
    revokeErrorKey.value = null;
    if (result.endedCurrent) await router.replace('/login');
  } else {
    revokeErrorKey.value = result.messageKey;
  }
}
</script>

<template>
  <div class="section-head">
    <h2 class="section-title">{{ t('account.sessions.title') }}</h2>
    <p class="section-sub">{{ t('account.sessions.subtitle') }}</p>
  </div>

  <div v-if="account.sessionsLoading" class="loading-wrap">
    <span class="s-loading-spinner" :aria-label="t('common.loading')" />
  </div>

  <p v-else-if="account.sessionsError" class="s-error">{{ t(account.sessionsError) }}</p>

  <template v-else>
    <div v-if="account.sessions.length === 0" class="s-card">
      <p class="s-row">{{ t('account.sessions.empty') }}</p>
    </div>
    <div v-else class="s-card">
      <div v-for="session in account.sessions" :key="session.id" class="s-row">
        <div class="row-label">
          <span>
            {{ deviceLabel(session) }}
            <span v-if="session.current" class="current-badge">{{ t('account.sessions.current') }}</span>
          </span>
          <span class="row-hint">{{ ipLabel(session) }} · {{ lastSeenLabel(session) }}</span>
        </div>
        <button
          class="s-btn danger small"
          type="button"
          :disabled="account.revokingId === session.id"
          @click="pendingRevoke = session"
        >
          {{ t('account.sessions.revoke') }}
        </button>
      </div>
    </div>
    <p v-if="revokeErrorKey" class="s-error" role="alert">{{ t(revokeErrorKey) }}</p>
  </template>

  <ConfirmSheet
    v-if="pendingRevoke"
    :heading="t('account.sessions.revokeConfirm.heading')"
    :subtext="t('account.sessions.revokeConfirm.subtext')"
    :confirm-label="t('account.sessions.revokeConfirm.confirm')"
    variant="destructive"
    :busy="account.revokingId === pendingRevoke.id"
    @confirm="confirmRevoke"
    @cancel="pendingRevoke = null"
  />
</template>

<style scoped>
.loading-wrap {
  display: flex;
  align-items: center;
  justify-content: center;
  padding-top: 40px;
}

.current-badge {
  display: inline-block;
  font-size: 9px;
  font-weight: var(--fw-semibold);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  background: var(--color-primary);
  color: var(--color-text-on-dark);
  padding: 1px 6px;
  border-radius: 4px;
  margin-left: 6px;
  vertical-align: middle;
}
</style>
