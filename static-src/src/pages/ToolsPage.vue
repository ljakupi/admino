<script setup lang="ts">
/**
 * Tools page — "my connections" (issue #162). Shows the caller's own Google
 * and Microsoft connections and the per-service status of each (active /
 * turned off by the org / restricted by data residency / not connected).
 * Connecting, disconnecting and the org's per-service switches moved here
 * from the old combined Tools page: `useConnectionsStore` owns this page's
 * state; the org's switches now live on the Organization console
 * (`OrgServicesCard.vue`, `useOrgServicesStore`).
 */
import { computed, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import { Mail, Calendar, Folder, Link } from 'lucide-vue-next';
import ConfirmSheet from '@/components/ConfirmSheet.vue';
import { useConnectionsStore } from '@/stores/connections';
import { useAuthStore } from '@/stores/auth';
import { useToastStore } from '@/stores/toasts';
import { canConnectAccounts } from '@/services/access';
import {
  PROVIDER_TOOLS,
  canConnect,
  canDisconnect,
  oauthCallbackMessageKey,
  providerState,
  serviceState,
  serviceStateKey,
} from '@/services/connections';
import type { ConnectorTool, OAuthProvider } from '@/api/types';
import { useI18n, type MessageKey } from '@/i18n';

const { t } = useI18n();
const router = useRouter();
const connections = useConnectionsStore();
const auth = useAuthStore();
const toasts = useToastStore();

const canConnectOwnAccounts = computed(() => canConnectAccounts(auth.role));

// --- OAuth callback handling ---
onMounted(async () => {
  await connections.load();

  // Only process OAuth callback params if we actually initiated a flow.
  const oauthPending = sessionStorage.getItem('oauth_pending');
  const params = new URLSearchParams(window.location.search);
  const oauthResult = params.get('oauth');
  if (oauthResult && oauthPending) {
    sessionStorage.removeItem('oauth_pending');
    if (oauthResult === 'success') {
      await router.replace({ path: '/tools' });
      toasts.add('success', t('toolsPage.oauth.connected.title'), t('toolsPage.oauth.connected.body'));
    } else if (oauthResult === 'error') {
      const reason = params.get('reason');
      await router.replace({ path: '/tools' });
      toasts.add('error', t('toast.settings.connectionFailed.title'), t(oauthCallbackMessageKey(reason)));
    }
  } else if (oauthResult) {
    // Strip stale or crafted oauth params without showing a toast.
    await router.replace({ path: '/tools' });
  }
});

// --- Provider display metadata ---
interface ProviderDef {
  id: OAuthProvider;
  label: string;
  logoClass: string;
  logoInitial: string;
  connectHintKey: MessageKey;
}

const PROVIDERS: readonly ProviderDef[] = [
  { id: 'google', label: 'Google', logoClass: 'google', logoInitial: 'G', connectHintKey: 'toolsPage.google.connectHint' },
  { id: 'microsoft', label: 'Microsoft', logoClass: 'microsoft', logoInitial: 'M', connectHintKey: 'toolsPage.microsoft.connectHint' },
];

const SERVICE_ICON: Record<ConnectorTool, typeof Mail> = {
  gmail: Mail,
  google_calendar: Calendar,
  google_drive: Folder,
  outlook: Mail,
  outlook_calendar: Calendar,
  onedrive: Folder,
};

const SERVICE_NAME_KEY: Record<ConnectorTool, MessageKey> = {
  gmail: 'tools.gmail.label',
  google_calendar: 'tools.googleCalendar.label',
  google_drive: 'tools.googleDrive.label',
  outlook: 'toolsPage.service.outlookMail',
  outlook_calendar: 'tools.outlookCalendar.label',
  onedrive: 'tools.onedrive.label',
};

const STATUS_PILL_KEY: Record<ReturnType<typeof providerState>, MessageKey> = {
  connected: 'toolsPage.status.connected',
  not_connected: 'toolsPage.status.notConnected',
  residency: 'toolsPage.status.residency',
};

function servicesOf(provider: OAuthProvider): readonly ConnectorTool[] {
  return PROVIDER_TOOLS[provider];
}

function statusOf(provider: OAuthProvider) {
  return connections.accounts[provider];
}

// --- Connect / disconnect ---
function connect(provider: OAuthProvider) {
  connections.connect(provider);
}

const disconnectTarget = ref<OAuthProvider | null>(null);

async function confirmDisconnect() {
  if (disconnectTarget.value) {
    await connections.disconnect(disconnectTarget.value);
  }
  disconnectTarget.value = null;
}
</script>

<template>
  <div class="tools-page">
    <header class="page-header">
      <h1>{{ t('nav.tools') }}</h1>
    </header>

    <div class="page-content">
      <div v-if="connections.loading" class="loading-overlay">
        <span class="loading-spinner" :aria-label="t('common.loading')" />
      </div>

      <div v-else class="tools-inner">
        <section class="tools-section">
          <div class="section-head">
            <h2 class="section-title">{{ t('toolsPage.accounts.title') }}</h2>
            <p class="section-sub">{{ t('toolsPage.accounts.subtitle') }}</p>
          </div>

          <div
            v-for="provider in PROVIDERS"
            :key="provider.id"
            class="provider-card"
            :class="[providerState(statusOf(provider.id)), { residency: statusOf(provider.id).data_residency }]"
          >
            <div class="provider-head">
              <div class="provider-logo" :class="provider.logoClass">{{ provider.logoInitial }}</div>
              <div class="provider-info">
                <div class="provider-title">
                  {{ provider.label }}
                  <span class="pill" :class="providerState(statusOf(provider.id))">
                    <span class="pill-dot" />
                    {{ t(STATUS_PILL_KEY[providerState(statusOf(provider.id))]) }}
                  </span>
                </div>
                <div class="provider-meta">
                  <template v-if="statusOf(provider.id).connected && statusOf(provider.id).healthy && statusOf(provider.id).email">
                    {{ statusOf(provider.id).email }}
                  </template>
                  <template v-else-if="!statusOf(provider.id).data_residency">
                    {{ t(provider.connectHintKey) }}
                  </template>
                </div>
              </div>
              <div class="provider-actions">
                <button
                  v-if="canConnectOwnAccounts && canDisconnect(statusOf(provider.id))"
                  class="s-btn danger small"
                  @click="disconnectTarget = provider.id"
                >
                  {{ t('toolsPage.disconnect') }}
                </button>
                <button
                  v-else-if="canConnectOwnAccounts && canConnect(statusOf(provider.id))"
                  class="s-btn primary small"
                  @click="connect(provider.id)"
                >
                  <Link :size="13" :stroke-width="2" />
                  {{ t('toolsPage.connect') }}
                </button>
              </div>
            </div>

            <p v-if="statusOf(provider.id).data_residency" class="residency-note">
              {{ t('toolsPage.residency.explanation') }}
            </p>

            <div class="provider-services">
              <div v-for="service in servicesOf(provider.id)" :key="service" class="service-row">
                <component :is="SERVICE_ICON[service]" class="service-icon" :size="18" :stroke-width="1.75" />
                <div class="service-info">
                  <span class="service-name">{{ t(SERVICE_NAME_KEY[service]) }}</span>
                </div>
                <span class="service-state" :class="serviceState(statusOf(provider.id), service)">
                  {{ t(serviceStateKey(serviceState(statusOf(provider.id), service))) }}
                </span>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>

    <ConfirmSheet
      v-if="disconnectTarget"
      :heading="t('toolsPage.disconnectConfirm.heading', { provider: disconnectTarget === 'google' ? 'Google' : 'Microsoft' })"
      :subtext="t('toolsPage.disconnectConfirm.subtext')"
      :confirm-label="t('toolsPage.disconnect')"
      variant="destructive"
      @confirm="confirmDisconnect"
      @cancel="disconnectTarget = null"
    />
  </div>
</template>

<style scoped>
.tools-page {
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
}

.loading-overlay {
  display: flex;
  align-items: center;
  justify-content: center;
  padding-top: 80px;
}

.loading-spinner {
  width: 28px;
  height: 28px;
  border: 3px solid var(--color-border);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
  display: inline-block;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.tools-inner {
  max-width: 720px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 36px;
}

/* ── Section ── */
.tools-section {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.section-head {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.section-title {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 18px;
  letter-spacing: -0.015em;
  color: var(--color-text);
}

.section-sub {
  font-size: 13px;
  color: var(--color-text-muted);
}

/* ── Provider (OAuth) cards ── */
.provider-card {
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border);
  border-radius: 12px;
  overflow: hidden;
}

.provider-card + .provider-card {
  margin-top: 12px;
}

.provider-card.residency {
  opacity: 0.7;
}

.provider-head {
  display: grid;
  grid-template-columns: 36px 1fr auto;
  gap: 14px;
  align-items: center;
  padding: 16px 20px;
  border-bottom: 1px solid var(--color-border);
  background: #F5F7F5;
}

.provider-card.connected .provider-head {
  background: linear-gradient(0deg, rgba(37, 211, 102, 0.04), rgba(37, 211, 102, 0.04)), var(--color-bg-elevated);
}

.provider-logo {
  width: 36px;
  height: 36px;
  border-radius: var(--radius-input);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: var(--fw-bold);
  font-size: 16px;
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border);
  color: var(--color-text);
  font-family: var(--font-display);
}

.provider-logo.google {
  color: #4285F4;
}

.provider-logo.microsoft {
  color: #0078D4;
}

.provider-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.provider-title {
  font-weight: var(--fw-semibold);
  font-size: 15px;
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--color-text);
}

.provider-meta {
  font-size: 12.5px;
  color: var(--color-text-muted);
}

.provider-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}

.residency-note {
  padding: 12px 20px;
  font-size: 12.5px;
  color: var(--color-text-muted);
  border-bottom: 1px solid var(--color-border);
  background: var(--color-warn-soft);
}

/* ── Pill badges ── */
.pill {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 9px;
  border-radius: var(--radius-pill);
  font-size: 11.5px;
  font-weight: var(--fw-medium);
  border: 1px solid transparent;
  white-space: nowrap;
}

.pill-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  flex-shrink: 0;
}

.pill.connected {
  background: #DCF8C6;
  color: #1F5C2F;
  border-color: #BFE6A3;
}

.pill.connected .pill-dot {
  background: var(--color-accent);
}

.pill.not_connected,
.pill.residency {
  background: var(--color-warn-soft);
  color: #8A5A14;
  border-color: #F1D495;
}

.pill.not_connected .pill-dot,
.pill.residency .pill-dot {
  background: var(--color-warn);
}

/* ── Services list ── */
.provider-services {
  padding: 4px 0;
}

.service-row {
  display: grid;
  grid-template-columns: 24px 1fr auto;
  gap: 12px;
  align-items: center;
  padding: 12px 20px;
  min-height: 44px;
}

.service-row + .service-row {
  border-top: 1px solid var(--color-border);
}

.service-icon {
  color: var(--color-primary-mid);
  display: flex;
  align-items: center;
}

.service-info {
  display: flex;
  flex-direction: column;
  gap: 1px;
}

.service-name {
  font-weight: var(--fw-medium);
  font-size: 13.5px;
  color: var(--color-text);
}

.service-state {
  font-size: 12px;
  font-weight: var(--fw-medium);
  color: var(--color-text-muted);
  white-space: nowrap;
}

.service-state.active {
  color: #1F5C2F;
}

.service-state.residency,
.service-state.org_disabled {
  color: #8A5A14;
}

/* ── Buttons ── */
.s-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 9px 16px;
  min-height: 44px;
  border-radius: var(--radius-input);
  font: inherit;
  font-size: 13.5px;
  font-weight: var(--fw-semibold);
  border: 1px solid transparent;
  cursor: pointer;
  transition: background-color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease), color var(--dur-fast) var(--ease);
  white-space: nowrap;
}

.s-btn.primary {
  background: var(--color-primary);
  color: var(--color-text-on-dark);
  border-color: var(--color-primary);
}

.s-btn.primary:hover {
  background: var(--color-primary-hover);
  border-color: var(--color-primary-hover);
}

.s-btn.danger {
  background: var(--color-bg-elevated);
  color: #C73B3B;
  border-color: #E0C7C7;
}

.s-btn.danger:hover {
  background: var(--color-error-soft);
  border-color: var(--color-error);
  color: #B82F2F;
}

.s-btn.small {
  padding: 6px 12px;
  min-height: 44px;
  font-size: 12.5px;
}

/* ── Responsive ── */
@media (max-width: 600px) {
  .provider-head {
    grid-template-columns: 36px 1fr;
    gap: 10px;
  }

  .provider-actions {
    grid-column: 1 / -1;
    justify-content: flex-start;
  }
}
</style>
