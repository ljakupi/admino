<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRoute } from 'vue-router';
import {
  Key, BrainCircuit, Palette, Bell, Info, TriangleAlert,
  ShieldCheck, Plus, Github,
} from 'lucide-vue-next';
import BaseToggle from '@/components/BaseToggle.vue';
import ConfirmSheet from '@/components/ConfirmSheet.vue';
import CriticalPermissionsCard from '@/components/CriticalPermissionsCard.vue';
import I18nT from '@/components/I18nT.vue';
import { useSettingsStore, type LLMProvider } from '@/stores/settings';
import { useChatStore } from '@/stores/chat';
import { useToastStore } from '@/stores/toasts';
import { modelOptions, providerLabel, trustNote } from '@/services/llmProviders';
import { useI18n, type MessageKey } from '@/i18n';

const { t } = useI18n();

const route = useRoute();
const settings = useSettingsStore();
const chatStore = useChatStore();
const toasts = useToastStore();

const showClearConfirm = ref(false);
const activeSection = ref(route.hash === '#danger' ? 'danger' : 'agent');

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
      { id: 'agent', labelKey: 'settings.nav.agent', icon: BrainCircuit },
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

// --- LLM / Agent section ---
const providers: { value: LLMProvider; label: string; badge?: string }[] = [
  { value: 'infomaniak', label: providerLabel('infomaniak') },
  { value: 'vllm', label: providerLabel('vllm') },
  { value: 'claude', label: providerLabel('anthropic') },
  { value: 'openai', label: providerLabel('openai') },
];

const draftAnthropicModel = ref('');
const draftOpenAiModel = ref('');

// Keys, not text, so a shown error follows a locale switch.
const anthropicModelError = ref<MessageKey | undefined>(undefined);
const openAiModelError = ref<MessageKey | undefined>(undefined);

// --- Session section ---
const draftSessionId = ref('');

function syncDrafts() {
  draftAnthropicModel.value = settings.llmAnthropicModel;
  draftOpenAiModel.value = settings.llmOpenAiModel;
  draftSessionId.value = settings.sessionId;
}

onMounted(async () => {
  await settings.loadSettings();
  syncDrafts();
});

async function onProviderChange(p: LLMProvider) {
  await settings.setProvider(p);
}

function validateModel(value: string): MessageKey | undefined {
  if (!value.trim()) return 'settings.agent.model.emptyError';
  return undefined;
}

async function onAnthropicModelBlur() {
  const err = validateModel(draftAnthropicModel.value);
  anthropicModelError.value = err;
  if (err) return;
  if (draftAnthropicModel.value !== settings.llmAnthropicModel) {
    await settings.setAnthropicModel(draftAnthropicModel.value.trim());
  }
}

async function onOpenAiModelBlur() {
  const err = validateModel(draftOpenAiModel.value);
  openAiModelError.value = err;
  if (err) return;
  if (draftOpenAiModel.value !== settings.llmOpenAiModel) {
    await settings.setOpenAiModel(draftOpenAiModel.value.trim());
  }
}

// --- Notifications ---
async function onNotificationsChange(value: boolean) {
  await settings.setNotificationsEnabled(value);
}

// --- Data / Danger section ---
function handleClearChat() {
  chatStore.clearThread();
  draftSessionId.value = settings.sessionId;
  showClearConfirm.value = false;
  toasts.add('success', t('settings.toast.chatCleared'));
}

function handleNewSession() {
  chatStore.clearThread();
  draftSessionId.value = settings.sessionId;
  toasts.add('success', t('settings.toast.newSession'));
}

async function handleDisconnectAll() {
  if (settings.connectedAccounts.google.connected) {
    await settings.disconnectGoogle();
  }
  if (settings.connectedAccounts.microsoft.connected) {
    await settings.disconnectMicrosoft();
  }
}

function handleResetSettings() {
  toasts.add('info', t('settings.comingSoon.title'), t('settings.comingSoon.resetSettings'));
}

function handleEraseAll() {
  toasts.add('info', t('settings.comingSoon.title'), t('settings.comingSoon.eraseAll'));
}

function handleComingSoonToggle() {
  toasts.add('info', t('settings.comingSoon.title'), t('settings.comingSoon.toggle'));
}

const currentProvider = computed(() => settings.llmProvider);
const anthropicConfigured = computed(() => settings.anthropicKeyConfigured);
const openAiConfigured = computed(() => settings.openAiKeyConfigured);

// The env var whose absence the API-key/token status row for the active
// provider points at.
const apiKeyEnvVar = computed(() => {
  if (currentProvider.value === 'anthropic') return 'ANTHROPIC_API_KEY';
  if (currentProvider.value === 'openai') return 'OPENAI_API_KEY';
  return 'INFOMANIAK_API_TOKEN';
});

// vLLM / Infomaniak: the dropdown options are the union of live served/listed
// models + the configured model (so it stays visible even when the server is
// unreachable and the list is []).
const vllmModelOptions = computed<string[]>(() =>
  modelOptions(settings.vllmAvailableModels, settings.llmVllmModel),
);

const infomaniakModelOptions = computed<string[]>(() =>
  modelOptions(settings.infomaniakAvailableModels, settings.llmInfomaniakModel),
);

async function onVllmModelChange(event: Event) {
  const value = (event.target as HTMLSelectElement).value;
  if (!value) return;
  if (value === settings.llmVllmModel) return;
  await settings.setVllmModel(value);
}

async function onInfomaniakModelChange(event: Event) {
  const value = (event.target as HTMLSelectElement).value;
  if (!value) return;
  if (value === settings.llmInfomaniakModel) return;
  await settings.setInfomaniakModel(value);
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
          </div>
        </template>

        <!-- ── AGENT ── -->
        <template v-if="activeSection === 'agent'">
          <div class="section-head">
            <h2 class="section-title">{{ t('settings.nav.agent') }}</h2>
            <p class="section-sub">{{ t('settings.agent.subtitle') }}</p>
          </div>
          <div class="s-card">
            <!-- Provider segmented control -->
            <div class="s-row">
              <div class="row-label">
                {{ t('settings.agent.provider.label') }}
                <span class="row-hint">{{ t('settings.agent.provider.hint') }}</span>
              </div>
              <div class="seg">
                <button
                  v-for="p in providers"
                  :key="p.value"
                  class="seg-btn"
                  :class="{ active: settings.provider === p.value }"
                  @click="onProviderChange(p.value)"
                >
                  {{ p.label }}<span v-if="p.badge" class="soon-badge">{{ p.badge }}</span>
                </button>
              </div>
            </div>

            <!-- Model field -->
            <div class="s-row stack">
              <div class="row-label">{{ t('settings.agent.model.label') }}</div>
              <template v-if="currentProvider === 'infomaniak'">
                <select
                  class="s-input"
                  :value="settings.llmInfomaniakModel"
                  @change="onInfomaniakModelChange"
                >
                  <option
                    v-for="model in infomaniakModelOptions"
                    :key="model"
                    :value="model"
                  >{{ model }}</option>
                </select>
                <I18nT
                  v-if="settings.infomaniakAvailableModels.length === 0"
                  class="row-hint"
                  keypath="settings.agent.infomaniak.noModels"
                >
                  <template #env><code class="inline-code">INFOMANIAK_API_TOKEN</code></template>
                </I18nT>
                <span class="row-hint model-hint">
                  {{ t('settings.agent.infomaniak.privacy') }}
                </span>
              </template>
              <template v-else-if="currentProvider === 'anthropic'">
                <input
                  v-model="draftAnthropicModel"
                  class="s-input mono"
                  type="text"
                  :placeholder="t('settings.agent.model.placeholder', { example: 'claude-sonnet-4-6' })"
                  @blur="onAnthropicModelBlur"
                />
                <span v-if="anthropicModelError" class="input-error">{{ t(anthropicModelError) }}</span>
                <I18nT class="row-hint model-hint" keypath="settings.agent.model.exactIdHint">
                  <template #example><code class="inline-code">claude-sonnet-4-6</code></template>
                  <template #link>
                    <a
                      href="https://docs.claude.com/en/docs/about-claude/models/overview"
                      class="hint-link"
                      target="_blank"
                      rel="noopener noreferrer"
                    >{{ t('settings.agent.anthropic.modelList') }}</a>
                  </template>
                </I18nT>
              </template>
              <template v-else-if="currentProvider === 'openai'">
                <input
                  v-model="draftOpenAiModel"
                  class="s-input mono"
                  type="text"
                  :placeholder="t('settings.agent.model.placeholder', { example: 'gpt-4o' })"
                  @blur="onOpenAiModelBlur"
                />
                <span v-if="openAiModelError" class="input-error">{{ t(openAiModelError) }}</span>
                <I18nT class="row-hint model-hint" keypath="settings.agent.model.exactIdHint">
                  <template #example><code class="inline-code">gpt-4o</code></template>
                  <template #link>
                    <a
                      href="https://platform.openai.com/docs/models"
                      class="hint-link"
                      target="_blank"
                      rel="noopener noreferrer"
                    >{{ t('settings.agent.openai.modelList') }}</a>
                  </template>
                </I18nT>
              </template>
              <template v-else-if="currentProvider === 'vllm'">
                <select
                  class="s-input"
                  :value="settings.llmVllmModel"
                  @change="onVllmModelChange"
                >
                  <option
                    v-for="model in vllmModelOptions"
                    :key="model"
                    :value="model"
                  >{{ model }}</option>
                </select>
                <I18nT
                  v-if="settings.vllmAvailableModels.length === 0"
                  class="row-hint"
                  keypath="settings.agent.vllm.noModels"
                >
                  <template #cmd><code class="inline-code">make start-local</code></template>
                </I18nT>
                <span class="row-hint model-hint">
                  {{ t('settings.agent.vllm.modelHint') }}
                </span>
              </template>
            </div>

            <!-- Infomaniak: API token indicator -->
            <div v-if="currentProvider === 'infomaniak'" class="s-row">
              <div class="row-label">
                {{ t('settings.agent.apiToken.label') }}
                <I18nT class="row-hint" keypath="settings.agent.secretHint">
                  <template #env><code class="inline-code">{{ apiKeyEnvVar }}</code></template>
                </I18nT>
              </div>
              <span
                class="api-key-status"
                :class="settings.infomaniakTokenConfigured ? 'status-ok' : 'status-missing'"
              >
                {{ settings.infomaniakTokenConfigured ? t('settings.agent.secret.configured') : t('settings.agent.secret.notConfigured') }}
              </span>
            </div>

            <!-- Claude / OpenAI: API key indicator -->
            <div v-if="currentProvider === 'anthropic' || currentProvider === 'openai'" class="s-row">
              <div class="row-label">
                {{ t('settings.agent.apiKey.label') }}
                <I18nT class="row-hint" keypath="settings.agent.secretHint">
                  <template #env><code class="inline-code">{{ apiKeyEnvVar }}</code></template>
                </I18nT>
              </div>
              <span
                class="api-key-status"
                :class="(currentProvider === 'anthropic' ? anthropicConfigured : openAiConfigured) ? 'status-ok' : 'status-missing'"
              >
                {{ (currentProvider === 'anthropic' ? anthropicConfigured : openAiConfigured) ? t('settings.agent.secret.configured') : t('settings.agent.secret.notConfigured') }}
              </span>
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
              <BaseToggle :model-value="false" @update:model-value="handleComingSoonToggle" />
            </div>
            <div class="s-row">
              <div class="row-label">
                {{ t('settings.notifications.sound.label') }}
                <span class="row-hint">{{ t('settings.notifications.sound.hint') }}</span>
              </div>
              <BaseToggle :model-value="false" @update:model-value="handleComingSoonToggle" />
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
          <div class="trust-badge">
            <ShieldCheck :size="20" :stroke-width="1.75" class="trust-icon" />
            <div>
              <div class="trust-title">{{ t('settings.about.trustTitle') }}</div>
              <div class="trust-body">{{ trustNote(settings.llmProvider) }}</div>
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
                {{ t('settings.danger.clear.label') }}
                <span class="row-hint">{{ t('settings.danger.clear.hint') }}</span>
              </div>
              <button class="s-btn danger" @click="showClearConfirm = true">{{ t('settings.danger.clear.button') }}</button>
            </div>
            <div class="s-row">
              <div class="row-label">
                {{ t('settings.danger.disconnectAll.label') }}
                <span class="row-hint">{{ t('settings.danger.disconnectAll.hint') }}</span>
              </div>
              <button class="s-btn danger" @click="handleDisconnectAll">{{ t('settings.danger.disconnectAll.button') }}</button>
            </div>
            <div class="s-row">
              <div class="row-label">
                {{ t('settings.danger.reset.label') }}
                <span class="row-hint">{{ t('settings.danger.reset.hint') }}</span>
              </div>
              <button class="s-btn danger" @click="handleResetSettings">{{ t('settings.danger.reset.button') }}</button>
            </div>
            <div class="s-row">
              <div class="row-label danger-label">
                {{ t('settings.danger.erase.label') }}
                <span class="row-hint">{{ t('settings.danger.erase.hint') }}</span>
              </div>
              <button class="s-btn danger solid" @click="handleEraseAll">{{ t('settings.danger.erase.button') }}</button>
            </div>
          </div>
        </template>
      </div>
    </main>

    <ConfirmSheet
      v-if="showClearConfirm"
      :heading="t('settings.danger.clearConfirm.heading')"
      :subtext="t('settings.danger.clearConfirm.subtext')"
      :confirm-label="t('settings.danger.clearConfirm.confirm')"
      variant="destructive"
      @confirm="handleClearChat"
      @cancel="showClearConfirm = false"
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

.input-error {
  font-size: 12px;
  color: var(--color-error);
}

.model-hint {
  line-height: var(--lh-relaxed);
}

.hint-link {
  color: var(--color-primary-mid);
  font-weight: var(--fw-medium);
  text-decoration: underline;
  text-underline-offset: 2px;
}

.hint-link:hover {
  color: var(--color-primary);
}

.inline-code {
  font-family: var(--font-mono);
  background: #F5F7F5;
  padding: 1px 5px;
  border-radius: 4px;
  font-size: 0.9em;
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

.s-btn.danger.solid {
  background: var(--color-error);
  color: var(--color-text-on-dark);
  border-color: var(--color-error);
}

.s-btn.danger.solid:hover {
  background: #D34646;
  border-color: #D34646;
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

/* ── API key status ── */
.api-key-status {
  font-size: var(--fs-caption);
  font-weight: var(--fw-medium);
}

.status-ok {
  color: #1F5C2F;
}

.status-missing {
  color: var(--color-text-muted);
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

/* ── Trust badge ── */
.trust-badge {
  padding: 14px 18px;
  background: #DCF8C6;
  border: 1px solid #BFE6A3;
  border-radius: 10px;
  display: flex;
  align-items: flex-start;
  gap: 12px;
  color: #1F5C2F;
  font-size: 13px;
}

.trust-icon {
  color: var(--color-accent);
  flex-shrink: 0;
  margin-top: 1px;
}

.trust-title {
  font-weight: var(--fw-semibold);
  margin-bottom: 2px;
}

.trust-body {
  color: #1F5C2F;
  line-height: var(--lh-relaxed);
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

.danger-label {
  color: #8A2A2A;
}
</style>
