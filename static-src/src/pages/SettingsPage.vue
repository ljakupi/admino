<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import BaseInput from '@/components/BaseInput.vue';
import BaseToggle from '@/components/BaseToggle.vue';
import BaseButton from '@/components/BaseButton.vue';
import ConfirmSheet from '@/components/ConfirmSheet.vue';
import { useSettingsStore, type LLMProvider } from '@/stores/settings';
import { useChatStore } from '@/stores/chat';
import { useToastStore } from '@/stores/toasts';

const settings = useSettingsStore();
const chatStore = useChatStore();
const toasts = useToastStore();

const showClearConfirm = ref(false);

// --- LLM section ---
const providers: { value: LLMProvider; label: string }[] = [
  { value: 'ollama', label: 'Ollama' },
  { value: 'claude', label: 'Claude' },
  { value: 'openai', label: 'OpenAI' },
];

// Local draft values for text inputs so we only patch on blur
const draftOllamaModel = ref('');
const draftOllamaUrl = ref('');
const draftAnthropicModel = ref('');
const draftOpenAiModel = ref('');

// Inline validation errors
const ollamaUrlError = ref<string | undefined>(undefined);
const ollamaModelError = ref<string | undefined>(undefined);
const anthropicModelError = ref<string | undefined>(undefined);
const openAiModelError = ref<string | undefined>(undefined);

function syncDrafts() {
  draftOllamaModel.value = settings.llmModel;
  draftOllamaUrl.value = settings.llmOllamaUrl;
  draftAnthropicModel.value = settings.llmAnthropicModel;
  draftOpenAiModel.value = settings.llmOpenAiModel;
}

onMounted(async () => {
  await settings.loadSettings();
  syncDrafts();
});

async function onProviderChange(p: LLMProvider) {
  await settings.setProvider(p);
}

function validateOllamaUrl(value: string): string | undefined {
  if (!value.startsWith('http://') && !value.startsWith('https://')) {
    return 'URL must start with http:// or https://';
  }
  return undefined;
}

function validateModel(value: string): string | undefined {
  if (!value.trim()) return 'Model name must not be empty';
  return undefined;
}

async function onOllamaModelBlur() {
  const err = validateModel(draftOllamaModel.value);
  ollamaModelError.value = err;
  if (err) return;
  if (draftOllamaModel.value !== settings.llmModel) {
    await settings.setOllamaModel(draftOllamaModel.value.trim());
  }
}

async function onOllamaUrlBlur() {
  const err = validateOllamaUrl(draftOllamaUrl.value);
  ollamaUrlError.value = err;
  if (err) return;
  if (draftOllamaUrl.value !== settings.llmOllamaUrl) {
    await settings.setOllamaUrl(draftOllamaUrl.value.trim());
  }
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

// --- Connected accounts ---
function connectGoogle() {
  window.location.href = '/api/oauth/google/start';
}

function connectMicrosoft() {
  window.location.href = '/api/oauth/microsoft/start';
}

function disconnectGoogle() {
  toasts.add('info', 'Coming soon', 'Account disconnection is not yet available.');
}

function disconnectMicrosoft() {
  toasts.add('info', 'Coming soon', 'Account disconnection is not yet available.');
}

// --- Data section ---
function handleClearChat() {
  chatStore.clearThread();
  showClearConfirm.value = false;
  toasts.add('success', 'Chat cleared');
}

function handleNewSession() {
  settings.newSession();
  chatStore.clearThread();
  toasts.add('success', 'New session started');
}

const currentProvider = computed(() => settings.llmProvider);
const anthropicConfigured = computed(() => settings.anthropicKeyConfigured);
const openAiConfigured = computed(() => settings.openAiKeyConfigured);
</script>

<template>
  <div class="settings-page">
    <header class="page-header">
      <h1>Settings</h1>
    </header>

    <!-- Loading state -->
    <div v-if="settings.loading" class="loading-overlay">
      <span class="loading-spinner" aria-label="Loading settings" />
    </div>

    <div v-else class="page-content">
      <!-- Error banner -->
      <div v-if="settings.error" class="error-banner caption">
        Failed to load settings: {{ settings.error }}
      </div>

      <!-- Agent / LLM section -->
      <div class="settings-section">
        <h3>Agent</h3>
        <div class="setting-card">
          <!-- Provider segmented control -->
          <div class="setting-row">
            <span class="setting-label">LLM Provider</span>
            <div class="segmented-control">
              <button
                v-for="p in providers"
                :key="p.value"
                class="segment"
                :class="{ active: settings.provider === p.value }"
                @click="onProviderChange(p.value)"
              >
                {{ p.label }}
              </button>
            </div>
          </div>

          <!-- Ollama fields -->
          <template v-if="currentProvider === 'ollama'">
            <BaseInput
              v-model="draftOllamaModel"
              label="Model"
              placeholder="e.g. llama3.2:3b"
              :error="ollamaModelError"
              @blur="onOllamaModelBlur"
            />
            <BaseInput
              v-model="draftOllamaUrl"
              label="Ollama URL"
              placeholder="http://localhost:11434"
              :error="ollamaUrlError"
              @blur="onOllamaUrlBlur"
            />
          </template>

          <!-- Anthropic / Claude fields -->
          <template v-else-if="currentProvider === 'anthropic'">
            <BaseInput
              v-model="draftAnthropicModel"
              label="Model"
              placeholder="e.g. claude-3-5-sonnet-20241022"
              :error="anthropicModelError"
              @blur="onAnthropicModelBlur"
            />
            <div class="api-key-row">
              <span
                class="caption"
                :class="anthropicConfigured ? 'text-success' : 'text-muted'"
              >
                API key {{ anthropicConfigured ? 'configured ✓' : 'not configured' }}
              </span>
            </div>
          </template>

          <!-- OpenAI fields -->
          <template v-else-if="currentProvider === 'openai'">
            <BaseInput
              v-model="draftOpenAiModel"
              label="Model"
              placeholder="e.g. gpt-4o"
              :error="openAiModelError"
              @blur="onOpenAiModelBlur"
            />
            <div class="api-key-row">
              <span
                class="caption"
                :class="openAiConfigured ? 'text-success' : 'text-muted'"
              >
                API key {{ openAiConfigured ? 'configured ✓' : 'not configured' }}
              </span>
            </div>
          </template>

          <div class="setting-row">
            <span class="setting-label">Session</span>
            <BaseButton variant="secondary" @click="handleNewSession">
              New Session
            </BaseButton>
          </div>
        </div>
      </div>

      <!-- Appearance section -->
      <div class="settings-section">
        <h3>Appearance</h3>
        <div class="setting-card">
          <div class="setting-row">
            <div>
              <span class="setting-label">Theme</span>
              <span class="caption">Dark mode coming soon.</span>
            </div>
            <div class="segmented-control">
              <button class="segment active" disabled>Light</button>
              <button class="segment" disabled>Dark</button>
              <button class="segment" disabled>System</button>
            </div>
          </div>
        </div>
      </div>

      <!-- Notifications section -->
      <div class="settings-section">
        <h3>Notifications</h3>
        <div class="setting-card">
          <div class="setting-row">
            <span class="setting-label">Push notifications</span>
            <BaseToggle
              :model-value="settings.notificationsEnabled"
              @update:model-value="onNotificationsChange"
            />
          </div>
        </div>
      </div>

      <!-- Connected Accounts section -->
      <div class="settings-section">
        <h3>Connected Accounts</h3>
        <div class="setting-card">
          <!-- Google -->
          <div class="account-row">
            <div class="account-info">
              <span class="setting-label">Google</span>
              <template v-if="settings.connectedAccounts.google.connected">
                <span class="caption text-success">Connected</span>
                <span
                  v-if="settings.connectedAccounts.google.email"
                  class="caption text-muted"
                >
                  {{ settings.connectedAccounts.google.email }}
                </span>
                <span
                  v-if="settings.connectedAccounts.google.services.length"
                  class="caption text-muted"
                >
                  {{ settings.connectedAccounts.google.services.join(', ') }}
                </span>
              </template>
              <span v-else class="caption text-muted">Not connected</span>
            </div>
            <BaseButton
              v-if="settings.connectedAccounts.google.connected"
              variant="secondary"
              @click="disconnectGoogle"
            >
              Disconnect
            </BaseButton>
            <BaseButton
              v-else
              variant="secondary"
              @click="connectGoogle"
            >
              Connect
            </BaseButton>
          </div>

          <div class="account-divider" />

          <!-- Microsoft -->
          <div class="account-row">
            <div class="account-info">
              <span class="setting-label">Microsoft</span>
              <template v-if="settings.connectedAccounts.microsoft.connected">
                <span class="caption text-success">Connected</span>
                <span
                  v-if="settings.connectedAccounts.microsoft.email"
                  class="caption text-muted"
                >
                  {{ settings.connectedAccounts.microsoft.email }}
                </span>
                <span
                  v-if="settings.connectedAccounts.microsoft.services.length"
                  class="caption text-muted"
                >
                  {{ settings.connectedAccounts.microsoft.services.join(', ') }}
                </span>
              </template>
              <span v-else class="caption text-muted">Not connected</span>
            </div>
            <BaseButton
              v-if="settings.connectedAccounts.microsoft.connected"
              variant="secondary"
              @click="disconnectMicrosoft"
            >
              Disconnect
            </BaseButton>
            <BaseButton
              v-else
              variant="secondary"
              @click="connectMicrosoft"
            >
              Connect
            </BaseButton>
          </div>
        </div>
      </div>

      <!-- Data section -->
      <div class="settings-section">
        <h3>Data</h3>
        <div class="setting-card">
          <div class="setting-row">
            <span class="setting-label">Clear conversation</span>
            <BaseButton variant="destructive" @click="showClearConfirm = true">
              Clear
            </BaseButton>
          </div>
        </div>
      </div>

      <!-- About section -->
      <div class="settings-section">
        <h3>About</h3>
        <div class="setting-card">
          <div class="about-line caption">
            <strong>admino</strong> v1.0.0
          </div>
          <div class="about-line caption trust-badge">
            Running locally. Your data never leaves this machine.
          </div>
        </div>
      </div>
    </div>

    <ConfirmSheet
      v-if="showClearConfirm"
      heading="Clear conversation?"
      subtext="This will remove all messages and tool call history from the current session."
      confirm-label="Clear"
      variant="destructive"
      @confirm="handleClearChat"
      @cancel="showClearConfirm = false"
    />
  </div>
</template>

<style scoped>
.settings-page {
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

.loading-overlay {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
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

.error-banner {
  background: color-mix(in srgb, var(--color-error) 10%, transparent);
  border: 1px solid var(--color-error);
  color: var(--color-error);
  border-radius: var(--radius-input);
  padding: var(--space-3) var(--space-4);
  margin-bottom: var(--space-4);
}

.page-content {
  flex: 1;
  overflow-y: auto;
  padding: var(--space-4);
  max-width: var(--content-max);
  margin: 0 auto;
  width: 100%;
}

.settings-section {
  margin-bottom: var(--space-6);
}

.settings-section h3 {
  margin-bottom: var(--space-3);
}

.setting-card {
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-card);
  padding: var(--space-4);
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.setting-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
}

.setting-label {
  font-weight: var(--fw-semibold);
  font-size: var(--fs-body);
}

/* Segmented control */
.segmented-control {
  display: flex;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-input);
  overflow: hidden;
}

.segment {
  padding: var(--space-2) var(--space-4);
  font-size: var(--fs-caption);
  font-weight: var(--fw-medium);
  cursor: pointer;
  transition: var(--transition-hover);
  color: var(--color-text-muted);
  border-right: 1px solid var(--color-border);
  min-height: 36px;
}

.segment:last-child {
  border-right: none;
}

.segment.active {
  background: var(--color-primary);
  color: var(--color-text-on-dark);
}

.segment:hover:not(.active):not(:disabled) {
  background: var(--color-bg);
}

.segment:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* API key indicator row */
.api-key-row {
  padding: var(--space-1) 0;
}

/* Connected accounts */
.account-row {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-4);
}

.account-info {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
}

.account-divider {
  height: 1px;
  background: var(--color-border);
  margin: 0 calc(var(--space-4) * -1);
}

/* Color utilities */
.text-success {
  color: var(--color-sage);
}

.text-muted {
  color: var(--color-text-muted);
}

/* About section */
.about-line {
  padding: var(--space-1) 0;
}

.trust-badge {
  color: var(--color-sage);
  font-weight: var(--fw-medium);
}
</style>
