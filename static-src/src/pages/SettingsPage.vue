<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  Key, Palette, Bell, Info, TriangleAlert,
  Plus, Github, LogOut,
} from 'lucide-vue-next';
import BaseToggle from '@/components/BaseToggle.vue';
import ConfirmSheet from '@/components/ConfirmSheet.vue';
import CriticalPermissionsCard from '@/components/CriticalPermissionsCard.vue';
import { useSettingsStore } from '@/stores/settings';
import { useAuthStore } from '@/stores/auth';
import { useChatStore } from '@/stores/chat';
import { useToastStore } from '@/stores/toasts';
import { useI18n, type MessageKey } from '@/i18n';

const { t } = useI18n();

const route = useRoute();
const router = useRouter();
const settings = useSettingsStore();
const auth = useAuthStore();
const chatStore = useChatStore();
const toasts = useToastStore();

const showResetConfirm = ref(false);
const activeSection = ref(route.hash === '#danger' ? 'danger' : 'appearance');

// --- Subnav definition ---
const NAV: {
  groupKey: MessageKey;
  items: { id: string; labelKey: MessageKey; icon: typeof Key; danger?: boolean }[];
}[] = [
  {
    groupKey: 'settings.nav.group.account',
    items: [
      { id: 'session', labelKey: 'settings.nav.session', icon: Key },
    ],
  },
  {
    groupKey: 'settings.nav.group.app',
    items: [
      { id: 'appearance', labelKey: 'settings.nav.appearance', icon: Palette },
      { id: 'notifications', labelKey: 'settings.nav.notifications', icon: Bell },
    ],
  },
  {
    groupKey: 'settings.nav.group.system',
    items: [
      { id: 'about', labelKey: 'settings.nav.about', icon: Info },
      { id: 'danger', labelKey: 'settings.nav.danger', icon: TriangleAlert, danger: true },
    ],
  },
];

// --- Session section ---
const draftSessionId = ref('');

function syncDrafts() {
  draftSessionId.value = settings.sessionId;
}

onMounted(async () => {
  await settings.loadSettings();
  syncDrafts();
});

// --- Notifications ---
async function onNotificationsChange(value: boolean) {
  await settings.setNotificationsEnabled(value);
}

async function onTaskDoneChange(value: boolean) {
  await settings.setTaskDoneNotifications(value);
}

function handleNewSession() {
  chatStore.clearThread();
  draftSessionId.value = settings.sessionId;
  toasts.add('success', t('settings.toast.newSession'));
}

async function handleLogout() {
  await auth.logout();
  await router.replace('/login');
}

// --- Danger section ---
async function handleResetConfirmed() {
  await settings.resetSettings();
  showResetConfirm.value = false;
}
</script>

<template>
  <div class="settings-page">
    <!-- Subnav -->
    <nav class="settings-subnav">
      <div class="subnav-title">{{ t('nav.settings') }}</div>
      <div v-for="group in NAV" :key="group.groupKey" class="subnav-group">
        <div class="subnav-group-label">{{ t(group.groupKey) }}</div>
        <button
          v-for="item in group.items"
          :key="item.id"
          class="subnav-item"
          :class="{ active: activeSection === item.id, danger: item.danger }"
          @click="activeSection = item.id"
        >
          <component :is="item.icon" class="subnav-icon" :size="16" :stroke-width="1.75" />
          <span>{{ t(item.labelKey) }}</span>
        </button>
      </div>
    </nav>

    <!-- Detail pane -->
    <main class="settings-detail">
      <!-- Loading state -->
      <div v-if="settings.loading" class="loading-overlay">
        <span class="loading-spinner" :aria-label="t('settings.loadingLabel')" />
      </div>

      <div v-else class="detail-inner">
        <!-- Error banner -->
        <div v-if="settings.error" class="error-banner">
          {{ t('settings.error.loadBanner', { error: settings.error }) }}
        </div>

        <!-- ── SESSION ── -->
        <template v-if="activeSection === 'session'">
          <div class="section-head">
            <h2 class="section-title">{{ t('settings.nav.session') }}</h2>
            <p class="section-sub">{{ t('settings.session.subtitle') }}</p>
          </div>
          <div class="s-card">
            <div class="s-row">
              <div class="row-label">
                {{ t('settings.session.id.label') }}
                <span class="row-hint">{{ t('settings.session.id.hint') }}</span>
              </div>
              <input
                v-model="draftSessionId"
                class="s-input mono"
                type="text"
                readonly
              />
            </div>
            <div class="s-row">
              <div class="row-label">
                {{ t('settings.session.new.label') }}
                <span class="row-hint">{{ t('settings.session.new.hint') }}</span>
              </div>
              <button class="s-btn secondary" @click="handleNewSession">
                <Plus :size="14" :stroke-width="2" />
                {{ t('settings.session.new.label') }}
              </button>
            </div>
            <div class="s-row">
              <div class="row-label">
                {{ t('settings.session.logout.label') }}
                <span class="row-hint">{{ t('settings.session.logout.hint') }}</span>
              </div>
              <button class="s-btn danger" @click="handleLogout">
                <LogOut :size="14" :stroke-width="2" />
                {{ t('settings.session.logout.label') }}
              </button>
            </div>
          </div>
        </template>

        <!-- ── APPEARANCE ── -->
        <template v-if="activeSection === 'appearance'">
          <div class="section-head">
            <h2 class="section-title">{{ t('settings.nav.appearance') }}</h2>
            <p class="section-sub">{{ t('settings.appearance.subtitle') }}</p>
          </div>
          <div class="s-card">
            <div class="s-row">
              <div class="row-label">
                {{ t('settings.appearance.theme.label') }}
                <span class="row-hint">{{ t('settings.appearance.theme.hint') }}</span>
              </div>
              <div class="seg">
                <button class="seg-btn active">{{ t('settings.appearance.theme.light') }}</button>
                <button class="seg-btn" disabled>
                  {{ t('settings.appearance.theme.dark') }} <span class="soon-badge">{{ t('settings.soonBadge') }}</span>
                </button>
                <button class="seg-btn" disabled>{{ t('settings.appearance.theme.system') }}</button>
              </div>
            </div>
          </div>
        </template>

        <!-- ── NOTIFICATIONS ── -->
        <template v-if="activeSection === 'notifications'">
          <div class="section-head">
            <h2 class="section-title">{{ t('settings.nav.notifications') }}</h2>
            <p class="section-sub">{{ t('settings.notifications.subtitle') }}</p>
          </div>
          <div class="s-card">
            <div class="s-row">
              <div class="row-label">
                {{ t('settings.notifications.approval.label') }}
                <span class="row-hint">{{ t('settings.notifications.approval.hint') }}</span>
              </div>
              <BaseToggle
                :model-value="settings.notificationsEnabled"
                @update:model-value="onNotificationsChange"
              />
            </div>
            <div class="s-row">
              <div class="row-label">
                {{ t('settings.notifications.taskDone.label') }}
                <span class="row-hint">{{ t('settings.notifications.taskDone.hint') }}</span>
              </div>
              <BaseToggle
                :model-value="settings.taskDoneNotifications"
                @update:model-value="onTaskDoneChange"
              />
            </div>
          </div>
        </template>

        <!-- ── ABOUT ── -->
        <template v-if="activeSection === 'about'">
          <div class="section-head">
            <h2 class="section-title">{{ t('settings.nav.about') }}</h2>
            <p class="section-sub">{{ t('settings.about.subtitle') }}</p>
          </div>
          <div class="s-card">
            <div class="s-row">
              <div class="row-label">{{ t('settings.about.version') }}</div>
              <span class="mono-value">{{ t('settings.about.versionValue', { version: '0.1.0' }) }}</span>
            </div>
            <div class="s-row">
              <div class="row-label">{{ t('settings.about.sourceCode') }}</div>
              <a href="https://github.com/ljakupi/admino" class="source-link" target="_blank" rel="noopener noreferrer">
                <Github :size="14" :stroke-width="1.75" />
                github.com/ljakupi/admino
              </a>
            </div>
            <div class="s-row">
              <div class="row-label">{{ t('settings.about.license') }}</div>
              <span class="muted-value">Apache-2.0</span>
            </div>
          </div>
        </template>

        <!-- ── DANGER ZONE ── -->
        <template v-if="activeSection === 'danger'">
          <div class="section-head">
            <h2 class="section-title danger-title">{{ t('settings.nav.danger') }}</h2>
            <p class="section-sub">{{ t('settings.danger.subtitle') }}</p>
          </div>

          <CriticalPermissionsCard />

          <div class="danger-card">
            <div class="s-row">
              <div class="row-label">
                {{ t('settings.danger.reset.label') }}
                <span class="row-hint">{{ t('settings.danger.reset.hint') }}</span>
              </div>
              <button class="s-btn danger" @click="showResetConfirm = true">{{ t('settings.danger.reset.button') }}</button>
            </div>
          </div>
        </template>
      </div>
    </main>

    <ConfirmSheet
      v-if="showResetConfirm"
      :heading="t('settings.danger.resetConfirm.heading')"
      :subtext="t('settings.danger.resetConfirm.subtext')"
      :confirm-label="t('settings.danger.resetConfirm.confirm')"
      variant="destructive"
      @confirm="handleResetConfirmed"
      @cancel="showResetConfirm = false"
    />
  </div>
</template>

<style scoped>
/* ── Layout shell ── */
.settings-page {
  display: flex;
  height: 100%;
  overflow: hidden;
}

/* ── Subnav ── */
.settings-subnav {
  width: 240px;
  flex-shrink: 0;
  background: var(--color-bg-elevated);
  border-right: 1px solid var(--color-border);
  padding: 22px 12px 12px;
  overflow-y: auto;
}

.subnav-title {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 20px;
  letter-spacing: -0.02em;
  color: var(--color-text);
  padding: 0 10px 16px;
}

.subnav-group {
  display: flex;
  flex-direction: column;
  gap: 1px;
  margin-bottom: 18px;
}

.subnav-group-label {
  font-size: 10.5px;
  font-weight: var(--fw-semibold);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--color-text-muted);
  padding: 8px 10px 6px;
}

.subnav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border-radius: var(--radius-input);
  color: #475560;
  font-size: 13.5px;
  font-weight: var(--fw-medium);
  cursor: pointer;
  border: 0;
  background: transparent;
  text-align: left;
  transition: background var(--dur-fast) var(--ease), color var(--dur-fast) var(--ease);
  width: 100%;
}

.subnav-item:hover {
  background: #F5F7F5;
  color: var(--color-text);
}

.subnav-item.active {
  background: #DCF8C6;
  color: #1F5C2F;
}

.subnav-item.active .subnav-icon {
  color: #1F5C2F;
}

.subnav-item.danger {
  color: #8A2A2A;
}

.subnav-item.danger.active {
  background: var(--color-error-soft);
  color: #8A2A2A;
}

.subnav-icon {
  flex-shrink: 0;
  color: var(--color-text-muted);
}

.subnav-item:hover .subnav-icon {
  color: var(--color-text);
}

.subnav-item.danger .subnav-icon {
  color: #8A2A2A;
}

/* ── Detail pane ── */
.settings-detail {
  flex: 1;
  overflow-y: auto;
  padding: 36px 48px 64px;
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

.detail-inner {
  max-width: 720px;
  display: flex;
  flex-direction: column;
  gap: 28px;
}

.error-banner {
  background: color-mix(in srgb, var(--color-error) 10%, transparent);
  border: 1px solid var(--color-error);
  color: var(--color-error);
  border-radius: var(--radius-input);
  padding: var(--space-3) var(--space-4);
  font-size: var(--fs-caption);
}

/* ── Section header ── */
.section-head {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.section-title {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 22px;
  letter-spacing: -0.015em;
  color: var(--color-text);
}

.section-sub {
  font-size: 13px;
  color: var(--color-text-muted);
}

/* ── Setting card ── */
.s-card {
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border);
  border-radius: 12px;
  overflow: hidden;
}

/* ── Setting row ── */
.s-row {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 20px;
  align-items: center;
  padding: 18px 20px;
  border-bottom: 1px solid var(--color-border);
}

.s-row:last-child {
  border-bottom: 0;
}

.s-row.stack {
  grid-template-columns: 1fr;
  align-items: stretch;
  gap: 10px;
}

.row-label {
  font-weight: var(--fw-semibold);
  font-size: 14px;
  color: var(--color-text);
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.row-hint {
  font-size: 12.5px;
  color: var(--color-text-muted);
  font-weight: var(--fw-regular);
}

/* ── Inputs ── */
.s-input {
  min-height: 38px;
  padding: 8px 12px;
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-input);
  font: inherit;
  font-size: 13.5px;
  color: var(--color-text);
  transition: border-color var(--dur-fast) var(--ease), box-shadow var(--dur-fast) var(--ease);
  max-width: 280px;
  width: 100%;
}

.s-input:focus {
  outline: 0;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px rgba(7, 94, 84, 0.12);
}

.s-input.mono {
  font-family: var(--font-mono);
}

.s-row.stack .s-input {
  max-width: 100%;
}

/* ── Buttons ── */
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

/* ── Segmented control (new pill style) ── */
.seg {
  display: inline-flex;
  gap: 3px;
  background: #F5F7F5;
  padding: 3px;
  border-radius: var(--radius-input);
  border: 1px solid var(--color-border);
}

.seg-btn {
  padding: 6px 14px;
  font: inherit;
  font-size: 13px;
  font-weight: var(--fw-medium);
  background: transparent;
  border: 0;
  color: #475560;
  border-radius: 6px;
  cursor: pointer;
  transition: background var(--dur-fast) var(--ease), color var(--dur-fast) var(--ease);
}

.seg-btn:hover:not(.active):not(:disabled) {
  color: var(--color-text);
}

.seg-btn.active {
  background: var(--color-bg-elevated);
  color: var(--color-text);
  box-shadow: 0 1px 2px rgba(17, 27, 33, 0.06);
}

.seg-btn:disabled {
  color: #B8C2C8;
  cursor: not-allowed;
}

.soon-badge {
  display: inline-block;
  font-size: 9px;
  font-weight: var(--fw-semibold);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  background: var(--color-border);
  color: var(--color-text-muted);
  padding: 1px 5px;
  border-radius: 4px;
  margin-left: 4px;
  vertical-align: middle;
}

/* ── About section ── */
.mono-value {
  font-family: var(--font-mono);
  font-size: 13px;
  color: #475560;
}

.muted-value {
  color: #475560;
}

.source-link {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--color-primary-mid);
  font-weight: var(--fw-medium);
  text-decoration: none;
  font-size: 13.5px;
}

.source-link:hover {
  text-decoration: underline;
}

/* ── Danger zone ── */
.danger-title {
  color: #8A2A2A;
}

.danger-card {
  background: var(--color-bg-elevated);
  border: 1px solid #F0BFBF;
  border-radius: 12px;
  overflow: hidden;
}

.danger-card .s-row {
  border-bottom-color: #F5DBDB;
}
</style>
