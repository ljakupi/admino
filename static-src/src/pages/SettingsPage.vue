<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  User, Key, Palette, Bell, Info, TriangleAlert,
  Plus, Github, LogOut,
} from 'lucide-vue-next';
import AccountProfileCard from '@/components/AccountProfileCard.vue';
import AccountPasswordCard from '@/components/AccountPasswordCard.vue';
import AccountSessionsCard from '@/components/AccountSessionsCard.vue';
import BaseToggle from '@/components/BaseToggle.vue';
import ConfirmSheet from '@/components/ConfirmSheet.vue';
import { defaultSettingsSection, settingsSectionsFor, type SettingsSectionId } from '@/services/settingsSections';
import { useAccountStore } from '@/stores/account';
import { useSettingsStore } from '@/stores/settings';
import { useAuthStore } from '@/stores/auth';
import { useChatStore } from '@/stores/chat';
import { useToastStore } from '@/stores/toasts';
import { useI18n, type MessageKey } from '@/i18n';

const { t } = useI18n();

const route = useRoute();
const router = useRouter();
const settings = useSettingsStore();
const account = useAccountStore();
const auth = useAuthStore();
const chatStore = useChatStore();
const toasts = useToastStore();

const showResetConfirm = ref(false);

// Issue #166: which sections a role may see (the Super Admin only gets
// My account and About); the hash picks the one that opens first.
const sections = computed<readonly SettingsSectionId[]>(() => settingsSectionsFor(auth.role));
const activeSection = ref<SettingsSectionId | null>(defaultSettingsSection(auth.role, route.hash));

// --- Subnav definition ---
const NAV_GROUPS: {
  groupKey: MessageKey;
  items: { id: SettingsSectionId; labelKey: MessageKey; icon: typeof Key; danger?: boolean }[];
}[] = [
  {
    groupKey: 'settings.nav.group.account',
    items: [
      { id: 'account', labelKey: 'settings.nav.account', icon: User },
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

const NAV = computed(() =>
  NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => sections.value.includes(item.id)),
  })).filter((group) => group.items.length > 0),
);

// --- Session section ---
const draftSessionId = ref('');

function syncDrafts() {
  draftSessionId.value = settings.sessionId;
}

onMounted(async () => {
  void account.load();
  if (sections.value.includes('session')) {
    await settings.loadSettings();
    syncDrafts();
  }
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

        <!-- ── MY ACCOUNT (issue #166) ── -->
        <template v-if="activeSection === 'account'">
          <AccountProfileCard />
          <AccountPasswordCard />
          <AccountSessionsCard />
        </template>

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

/* .section-head/.section-title/.section-sub, .s-card, .s-row (+ :last-child,
   .stack), .row-label/.row-hint, .s-input (+ :focus, .mono), .s-btn (+
   variants/hover) and .seg/.seg-btn now live in src/styles/global.css —
   shared by this page and the My account cards (issue #166). */

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
