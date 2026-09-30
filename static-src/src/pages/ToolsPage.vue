<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import {
  Mail, Calendar, Folder, Brain, Link,
} from 'lucide-vue-next';
import BaseToggle from '@/components/BaseToggle.vue';
import ConfirmSheet from '@/components/ConfirmSheet.vue';
import { useSettingsStore } from '@/stores/settings';
import { useAuthStore } from '@/stores/auth';
import { useToastStore } from '@/stores/toasts';
import { canManageOrgSettings } from '@/services/access';
import type { ToolsSettings } from '@/api/types';
import { useI18n, type MessageKey } from '@/i18n';

const { t } = useI18n();
const router = useRouter();
const settings = useSettingsStore();
const auth = useAuthStore();
const toasts = useToastStore();

// Only an Org Admin may see/change which tool services are enabled for the
// organization (until #161 replaces the interim gate; see GH-159 contract).
const canManageTools = computed(() => canManageOrgSettings(auth.role));

// --- OAuth callback handling (moved from SettingsPage) ---
onMounted(async () => {
  await settings.loadConnections();
  if (canManageTools.value) {
    await settings.loadOrgTools();
  }

  // Only process OAuth callback params if we actually initiated a flow
  const oauthPending = sessionStorage.getItem('oauth_pending');
  const params = new URLSearchParams(window.location.search);
  const oauthResult = params.get('oauth');
  if (oauthResult && oauthPending) {
    sessionStorage.removeItem('oauth_pending');
    if (oauthResult === 'success') {
      await router.replace({ path: '/tools' });
      toasts.add('success', t('toolsPage.oauth.connected.title'), t('toolsPage.oauth.connected.body'));
    } else if (oauthResult === 'error') {
      const REASON_KEYS: Record<string, MessageKey> = {
        denied: 'toolsPage.oauth.reason.denied',
        invalid_state: 'toolsPage.oauth.reason.invalidState',
        missing_code: 'toolsPage.oauth.reason.missingCode',
        exchange_failed: 'toolsPage.oauth.reason.exchangeFailed',
      };
      // `reason` comes from the URL: own keys only, never an inherited property.
      const reason = params.get('reason') || '';
      const messageKey: MessageKey = Object.hasOwn(REASON_KEYS, reason)
        ? REASON_KEYS[reason]
        : 'toolsPage.oauth.reason.unexpected';
      await router.replace({ path: '/tools' });
      toasts.add('error', t('toast.settings.connectionFailed.title'), t(messageKey));
    }
  } else if (oauthResult) {
    // Strip stale or crafted oauth params without showing a toast
    await router.replace({ path: '/tools' });
  }
});

// --- Service mappings (ported from SettingsPage) ---
const serviceIconMap: Record<string, typeof Mail> = {
  mail: Mail,
  calendar: Calendar,
  folder: Folder,
};

interface ServiceDef {
  id: string;
  icon: string;
  nameKey: MessageKey;
  toolKey: keyof ToolsSettings;
}

const googleServices: ServiceDef[] = [
  { id: 'gmail', icon: 'mail', nameKey: 'tools.gmail.label', toolKey: 'gmail' },
  { id: 'calendar', icon: 'calendar', nameKey: 'tools.googleCalendar.label', toolKey: 'google_calendar' },
  { id: 'drive', icon: 'folder', nameKey: 'tools.googleDrive.label', toolKey: 'google_drive' },
];

const microsoftServices: ServiceDef[] = [
  { id: 'outlook', icon: 'mail', nameKey: 'toolsPage.service.outlookMail', toolKey: 'outlook' },
  { id: 'outlookc', icon: 'calendar', nameKey: 'tools.outlookCalendar.label', toolKey: 'outlook_calendar' },
  { id: 'onedrive', icon: 'folder', nameKey: 'tools.onedrive.label', toolKey: 'onedrive' },
];

// Derive toggle state from store
const googleServiceToggles = computed<Record<string, boolean>>(() => {
  return Object.fromEntries(
    googleServices.map((svc) => [svc.id, settings.tools[svc.toolKey]]),
  );
});

const microsoftServiceToggles = computed<Record<string, boolean>>(() => {
  return Object.fromEntries(
    microsoftServices.map((svc) => [svc.id, settings.tools[svc.toolKey]]),
  );
});

function onGoogleServiceToggle(serviceId: string, enabled: boolean) {
  const svc = googleServices.find((s) => s.id === serviceId);
  if (svc) settings.setToolEnabled(svc.toolKey, enabled);
}

function onMicrosoftServiceToggle(serviceId: string, enabled: boolean) {
  const svc = microsoftServices.find((s) => s.id === serviceId);
  if (svc) settings.setToolEnabled(svc.toolKey, enabled);
}

// --- Local tools metadata ---
const LOCAL_TOOLS: { id: keyof ToolsSettings; nameKey: MessageKey; descriptionKey: MessageKey; icon: typeof Mail }[] = [
  { id: 'memory', nameKey: 'tools.memory.label', descriptionKey: 'toolsPage.memory.description', icon: Brain },
];

function onLocalToolToggle(toolId: keyof ToolsSettings, enabled: boolean) {
  settings.setToolEnabled(toolId, enabled);
}

// --- Effective connection state ---
// A connected-but-unhealthy account (dead/revoked refresh token) is treated
// the same as not connected: it shows the grey "Not connected" pill and a
// "Connect" button, never a "Reconnect" button. Two states only.
const googleConnected = computed(
  () => settings.connectedAccounts.google.connected && settings.connectedAccounts.google.healthy,
);
const microsoftConnected = computed(
  () =>
    settings.connectedAccounts.microsoft.connected && settings.connectedAccounts.microsoft.healthy,
);

// --- OAuth connect/disconnect ---
function connectGoogle() {
  settings.connectGoogle();
}

function connectMicrosoft() {
  settings.connectMicrosoft();
}

const disconnectTarget = ref<'google' | 'microsoft' | null>(null);

async function confirmDisconnect() {
  if (disconnectTarget.value === 'google') {
    await settings.disconnectGoogle();
  } else if (disconnectTarget.value === 'microsoft') {
    await settings.disconnectMicrosoft();
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
      <div v-if="settings.loading" class="loading-overlay">
        <span class="loading-spinner" :aria-label="t('common.loading')" />
      </div>

      <div v-else class="tools-inner">
        <!-- ── Connected accounts ── -->
        <section class="tools-section">
          <div class="section-head">
            <h2 class="section-title">{{ t('toolsPage.accounts.title') }}</h2>
            <p class="section-sub">{{ t('toolsPage.accounts.subtitle') }}</p>
          </div>

          <!-- Google card -->
          <div class="provider-card" :class="{ connected: googleConnected }">
            <div class="provider-head">
              <div class="provider-logo google">G</div>
              <div class="provider-info">
                <div class="provider-title">
                  Google
                  <span class="pill" :class="googleConnected ? 'leaf' : 'amber'">
                    <span class="pill-dot" />
                    {{ googleConnected ? t('toolsPage.status.connected') : t('toolsPage.status.notConnected') }}
                  </span>
                </div>
                <div class="provider-meta">
                  <template v-if="googleConnected">
                    {{ settings.connectedAccounts.google.email }}
                  </template>
                  <template v-else>
                    {{ t('toolsPage.google.connectHint') }}
                  </template>
                </div>
              </div>
              <div class="provider-actions">
                <button
                  v-if="googleConnected"
                  class="s-btn danger small"
                  @click="disconnectTarget = 'google'"
                >
                  {{ t('toolsPage.disconnect') }}
                </button>
                <button v-else class="s-btn primary small" @click="connectGoogle">
                  <Link :size="13" :stroke-width="2" />
                  {{ t('toolsPage.connect') }}
                </button>
              </div>
            </div>
            <div v-if="googleConnected && canManageTools" class="provider-services">
              <div v-for="svc in googleServices" :key="svc.id" class="service-row">
                <component :is="serviceIconMap[svc.icon]" class="service-icon" :size="18" :stroke-width="1.75" />
                <div class="service-info">
                  <span class="service-name">{{ t(svc.nameKey) }}</span>
                </div>
                <BaseToggle
                  :model-value="googleServiceToggles[svc.id]"
                  @update:model-value="onGoogleServiceToggle(svc.id, $event)"
                />
              </div>
            </div>
          </div>

          <!-- Microsoft card -->
          <div class="provider-card" :class="{ connected: microsoftConnected }">
            <div class="provider-head">
              <div class="provider-logo microsoft">M</div>
              <div class="provider-info">
                <div class="provider-title">
                  Microsoft
                  <span class="pill" :class="microsoftConnected ? 'leaf' : 'amber'">
                    <span class="pill-dot" />
                    {{ microsoftConnected ? t('toolsPage.status.connected') : t('toolsPage.status.notConnected') }}
                  </span>
                </div>
                <div class="provider-meta">
                  <template v-if="microsoftConnected">
                    {{ settings.connectedAccounts.microsoft.email }}
                  </template>
                  <template v-else>
                    {{ t('toolsPage.microsoft.connectHint') }}
                  </template>
                </div>
              </div>
              <div class="provider-actions">
                <button
                  v-if="microsoftConnected"
                  class="s-btn danger small"
                  @click="disconnectTarget = 'microsoft'"
                >
                  {{ t('toolsPage.disconnect') }}
                </button>
                <button v-else class="s-btn primary small" @click="connectMicrosoft">
                  <Link :size="13" :stroke-width="2" />
                  {{ t('toolsPage.connect') }}
                </button>
              </div>
            </div>
            <div v-if="microsoftConnected && canManageTools" class="provider-services">
              <div v-for="svc in microsoftServices" :key="svc.id" class="service-row">
                <component :is="serviceIconMap[svc.icon]" class="service-icon" :size="18" :stroke-width="1.75" />
                <div class="service-info">
                  <span class="service-name">{{ t(svc.nameKey) }}</span>
                </div>
                <BaseToggle
                  :model-value="microsoftServiceToggles[svc.id]"
                  @update:model-value="onMicrosoftServiceToggle(svc.id, $event)"
                />
              </div>
            </div>
          </div>
        </section>

        <!-- ── Local tools ── -->
        <section v-if="canManageTools" class="tools-section">
          <div class="section-head">
            <h2 class="section-title">{{ t('toolsPage.local.title') }}</h2>
            <p class="section-sub">{{ t('toolsPage.local.subtitle') }}</p>
          </div>

          <div class="local-tools">
            <div v-for="tool in LOCAL_TOOLS" :key="tool.id" class="local-tool-row">
              <component :is="tool.icon" class="local-tool-icon" :size="20" :stroke-width="1.75" />
              <div class="local-tool-info">
                <span class="local-tool-name">{{ t(tool.nameKey) }}</span>
                <span class="local-tool-desc">{{ t(tool.descriptionKey) }}</span>
              </div>
              <BaseToggle
                :model-value="settings.tools[tool.id]"
                @update:model-value="onLocalToolToggle(tool.id, $event)"
              />
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

.pill.leaf {
  background: #DCF8C6;
  color: #1F5C2F;
  border-color: #BFE6A3;
}

.pill.leaf .pill-dot {
  background: var(--color-accent);
}

.pill.amber {
  background: var(--color-warn-soft);
  color: #8A5A14;
  border-color: #F1D495;
}

.pill.amber .pill-dot {
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

/* ── Buttons (matching SettingsPage) ── */
.s-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 9px 16px;
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

.s-btn.secondary {
  background: var(--color-bg-elevated);
  color: var(--color-text);
  border-color: var(--color-border-strong);
}

.s-btn.secondary:hover {
  background: #F5F7F5;
  border-color: var(--color-text-muted);
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
  font-size: 12.5px;
}

/* ── Local tools ── */
.local-tools {
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border);
  border-radius: 12px;
  overflow: hidden;
}

.local-tool-row {
  display: grid;
  grid-template-columns: 28px 1fr auto;
  gap: 14px;
  align-items: center;
  padding: 14px 20px;
}

.local-tool-row + .local-tool-row {
  border-top: 1px solid var(--color-border);
}

.local-tool-icon {
  color: var(--color-primary-mid);
  display: flex;
  align-items: center;
}

.local-tool-info {
  display: flex;
  flex-direction: column;
  gap: 1px;
  min-width: 0;
}

.local-tool-name {
  font-weight: var(--fw-semibold);
  font-size: 14px;
  color: var(--color-text);
}

.local-tool-desc {
  font-size: 12.5px;
  color: var(--color-text-muted);
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
