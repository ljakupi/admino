<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import {
  Key, PlugZap, BrainCircuit, Palette, Bell, Info, TriangleAlert,
  Mail, Calendar, Folder, ShieldCheck, Plus, Link, Github,
} from 'lucide-vue-next';
import BaseToggle from '@/components/BaseToggle.vue';
import ConfirmSheet from '@/components/ConfirmSheet.vue';
import { useSettingsStore, type LLMProvider } from '@/stores/settings';
import { useChatStore } from '@/stores/chat';
import { useToastStore } from '@/stores/toasts';

const router = useRouter();
const settings = useSettingsStore();
const chatStore = useChatStore();
const toasts = useToastStore();

const showClearConfirm = ref(false);
const activeSection = ref('agent');

// --- Subnav definition ---
const NAV = [
  {
    group: 'Account',
    items: [
      { id: 'session', label: 'Session', icon: Key },
      { id: 'accounts', label: 'Accounts', icon: PlugZap },
    ],
  },
  {
    group: 'App',
    items: [
      { id: 'agent', label: 'Agent', icon: BrainCircuit },
      { id: 'appearance', label: 'Appearance', icon: Palette },
      { id: 'notifications', label: 'Notifications', icon: Bell },
    ],
  },
  {
    group: 'System',
    items: [
      { id: 'about', label: 'About', icon: Info },
      { id: 'danger', label: 'Danger zone', icon: TriangleAlert, danger: true },
    ],
  },
];

// --- LLM / Agent section ---
const providers: { value: LLMProvider; label: string }[] = [
  { value: 'ollama', label: 'Ollama' },
  { value: 'claude', label: 'Claude' },
  { value: 'openai', label: 'OpenAI' },
];

const draftOllamaModel = ref('');
const draftOllamaUrl = ref('');
const draftAnthropicModel = ref('');
const draftOpenAiModel = ref('');

const ollamaUrlError = ref<string | undefined>(undefined);
const ollamaModelError = ref<string | undefined>(undefined);
const anthropicModelError = ref<string | undefined>(undefined);
const openAiModelError = ref<string | undefined>(undefined);

// --- Session section ---
const draftToken = ref('');
const draftSessionId = ref('');

function syncDrafts() {
  draftOllamaModel.value = settings.llmModel;
  draftOllamaUrl.value = settings.llmOllamaUrl;
  draftAnthropicModel.value = settings.llmAnthropicModel;
  draftOpenAiModel.value = settings.llmOpenAiModel;
  draftToken.value = settings.token ?? '';
  draftSessionId.value = settings.sessionId;
}

onMounted(async () => {
  await settings.loadSettings();
  syncDrafts();

  // Handle OAuth callback result from URL params
  const params = new URLSearchParams(window.location.search);
  const oauthResult = params.get('oauth');
  if (oauthResult === 'success') {
    toasts.add('success', 'Account connected', 'Your account has been linked successfully.');
    await router.replace({ path: '/settings' });
    activeSection.value = 'accounts';
  } else if (oauthResult === 'error') {
    const REASON_MESSAGES: Record<string, string> = {
      denied: 'You declined the consent screen.',
      invalid_state: 'Session expired. Please try again.',
      missing_code: 'No authorization code received.',
      exchange_failed: 'Token exchange failed. Check OAuth credentials.',
    };
    const reason = params.get('reason') || '';
    const message = REASON_MESSAGES[reason] ?? 'An unexpected error occurred.';
    toasts.add('error', 'Connection failed', message);
    await router.replace({ path: '/settings' });
    activeSection.value = 'accounts';
  }
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

function onTokenBlur() {
  if (draftToken.value && draftToken.value !== settings.token) {
    settings.setToken(draftToken.value);
    toasts.add('success', 'Token saved');
  }
}

// --- Notifications ---
async function onNotificationsChange(value: boolean) {
  await settings.setNotificationsEnabled(value);
}

// --- Connected accounts ---
function connectGoogle() {
  settings.connectGoogle();
}

function connectMicrosoft() {
  settings.connectMicrosoft();
}

async function disconnectGoogle() {
  await settings.disconnectGoogle();
}

async function disconnectMicrosoft() {
  await settings.disconnectMicrosoft();
}

// --- Data / Danger section ---
function handleClearChat() {
  chatStore.clearThread();
  showClearConfirm.value = false;
  toasts.add('success', 'Chat cleared');
}

function handleNewSession() {
  settings.newSession();
  draftSessionId.value = settings.sessionId;
  chatStore.clearThread();
  toasts.add('success', 'New session started');
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
  toasts.add('info', 'Coming soon', 'Reset settings is not yet available.');
}

function handleEraseAll() {
  toasts.add('info', 'Coming soon', 'Erase all data is not yet available.');
}

const currentProvider = computed(() => settings.llmProvider);
const anthropicConfigured = computed(() => settings.anthropicKeyConfigured);
const openAiConfigured = computed(() => settings.openAiKeyConfigured);

// Service icon helper
const serviceIconMap: Record<string, typeof Mail> = {
  mail: Mail,
  calendar: Calendar,
  folder: Folder,
};

const googleServices = [
  { id: 'gmail', icon: 'mail', name: 'Gmail', scope: 'gmail.readonly' },
  { id: 'calendar', icon: 'calendar', name: 'Google Calendar', scope: 'calendar.events' },
  { id: 'drive', icon: 'folder', name: 'Google Drive', scope: 'drive.readonly' },
];

const microsoftServices = [
  { id: 'outlook', icon: 'mail', name: 'Outlook Mail', scope: 'Mail.Read' },
  { id: 'outlookc', icon: 'calendar', name: 'Outlook Calendar', scope: 'Calendars.ReadWrite' },
  { id: 'onedrive', icon: 'folder', name: 'OneDrive', scope: 'Files.Read' },
];

// Map between frontend service IDs and the backend service name strings
const GOOGLE_SERVICE_MAP: Record<string, string> = {
  gmail: 'gmail',
  calendar: 'google_calendar',
  drive: 'google_drive',
};

const MICROSOFT_SERVICE_MAP: Record<string, string> = {
  outlook: 'outlook',
  outlookc: 'outlook_calendar',
  onedrive: 'onedrive',
};

// Derive toggle state from the store's connectedAccounts so it always reflects backend truth
const googleServiceToggles = computed<Record<string, boolean>>(() => {
  const active = settings.connectedAccounts.google.services;
  return Object.fromEntries(
    Object.keys(GOOGLE_SERVICE_MAP).map((id) => [id, active.includes(GOOGLE_SERVICE_MAP[id])]),
  );
});

const microsoftServiceToggles = computed<Record<string, boolean>>(() => {
  const active = settings.connectedAccounts.microsoft.services;
  return Object.fromEntries(
    Object.keys(MICROSOFT_SERVICE_MAP).map((id) => [id, active.includes(MICROSOFT_SERVICE_MAP[id])]),
  );
});

function onServiceToggle() {
  toasts.add('info', 'Coming soon', 'Per-service toggles are not yet available.');
}
</script>

<template>
  <div class="settings-page">
    <!-- Subnav -->
    <nav class="settings-subnav">
      <div class="subnav-title">Settings</div>
      <div v-for="group in NAV" :key="group.group" class="subnav-group">
        <div class="subnav-group-label">{{ group.group }}</div>
        <button
          v-for="item in group.items"
          :key="item.id"
          class="subnav-item"
          :class="{ active: activeSection === item.id, danger: item.danger }"
          @click="activeSection = item.id"
        >
          <component :is="item.icon" class="subnav-icon" :size="16" :stroke-width="1.75" />
          <span>{{ item.label }}</span>
        </button>
      </div>
    </nav>

    <!-- Detail pane -->
    <main class="settings-detail">
      <!-- Loading state -->
      <div v-if="settings.loading" class="loading-overlay">
        <span class="loading-spinner" aria-label="Loading settings" />
      </div>

      <div v-else class="detail-inner">
        <!-- Error banner -->
        <div v-if="settings.error" class="error-banner">
          Failed to load settings: {{ settings.error }}
        </div>

        <!-- ── SESSION ── -->
        <template v-if="activeSection === 'session'">
          <div class="section-head">
            <h2 class="section-title">Session</h2>
            <p class="section-sub">Identifies this conversation thread on the admino backend.</p>
          </div>
          <div class="s-card">
            <div class="s-row">
              <div class="row-label">
                Bearer token
                <span class="row-hint">Required only when the server runs in <code class="inline-code">auth.mode: token</code>.</span>
              </div>
              <input
                v-model="draftToken"
                class="s-input mono"
                type="password"
                placeholder="Enter bearer token"
                @blur="onTokenBlur"
              />
            </div>
            <div class="s-row">
              <div class="row-label">
                Session ID
                <span class="row-hint">Alphanumeric, hyphens, underscores. Max 64 chars.</span>
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
                New session
                <span class="row-hint">Clears the chat thread. The conversation history stays in audit log.</span>
              </div>
              <button class="s-btn secondary" @click="handleNewSession">
                <Plus :size="14" :stroke-width="2" />
                New session
              </button>
            </div>
          </div>
        </template>

        <!-- ── ACCOUNTS ── -->
        <template v-if="activeSection === 'accounts'">
          <div class="section-head">
            <h2 class="section-title">Accounts</h2>
            <p class="section-sub">Connect a provider once. Toggle individual services any time. Disconnecting revokes the OAuth refresh token.</p>
          </div>

          <!-- Google provider card -->
          <div class="provider-card" :class="{ connected: settings.connectedAccounts.google.connected }">
            <div class="provider-head">
              <div class="provider-logo google">G</div>
              <div class="provider-info">
                <div class="provider-title">
                  Google
                  <span
                    class="pill"
                    :class="settings.connectedAccounts.google.connected ? 'leaf' : 'amber'"
                  >
                    <span class="pill-dot" />
                    {{ settings.connectedAccounts.google.connected ? 'Connected' : 'Not connected' }}
                  </span>
                </div>
                <div class="provider-meta">
                  <template v-if="settings.connectedAccounts.google.connected">
                    {{ settings.connectedAccounts.google.email }}
                  </template>
                  <template v-else>
                    Connect to use Gmail, Google Calendar, Google Drive.
                  </template>
                </div>
              </div>
              <div class="provider-actions">
                <template v-if="settings.connectedAccounts.google.connected">
                  <button class="s-btn secondary small">Reconnect</button>
                  <button class="s-btn danger small" @click="disconnectGoogle">Disconnect</button>
                </template>
                <button v-else class="s-btn primary small" @click="connectGoogle">
                  <Link :size="13" :stroke-width="2" />
                  Connect
                </button>
              </div>
            </div>
            <div v-if="settings.connectedAccounts.google.connected" class="provider-services">
              <div v-for="svc in googleServices" :key="svc.id" class="service-row">
                <component :is="serviceIconMap[svc.icon]" class="service-icon" :size="18" :stroke-width="1.75" />
                <div class="service-info">
                  <span class="service-name">{{ svc.name }}</span>
                </div>
                <BaseToggle
                  :model-value="googleServiceToggles[svc.id]"
                  @update:model-value="onServiceToggle"
                />
              </div>
            </div>
          </div>

          <!-- Microsoft provider card -->
          <div class="provider-card" :class="{ connected: settings.connectedAccounts.microsoft.connected }">
            <div class="provider-head">
              <div class="provider-logo microsoft">M</div>
              <div class="provider-info">
                <div class="provider-title">
                  Microsoft
                  <span
                    class="pill"
                    :class="settings.connectedAccounts.microsoft.connected ? 'leaf' : 'amber'"
                  >
                    <span class="pill-dot" />
                    {{ settings.connectedAccounts.microsoft.connected ? 'Connected' : 'Not connected' }}
                  </span>
                </div>
                <div class="provider-meta">
                  <template v-if="settings.connectedAccounts.microsoft.connected">
                    {{ settings.connectedAccounts.microsoft.email }}
                  </template>
                  <template v-else>
                    Connect to use Outlook Mail, Outlook Calendar, OneDrive.
                  </template>
                </div>
              </div>
              <div class="provider-actions">
                <template v-if="settings.connectedAccounts.microsoft.connected">
                  <button class="s-btn secondary small">Reconnect</button>
                  <button class="s-btn danger small" @click="disconnectMicrosoft">Disconnect</button>
                </template>
                <button v-else class="s-btn primary small" @click="connectMicrosoft">
                  <Link :size="13" :stroke-width="2" />
                  Connect
                </button>
              </div>
            </div>
            <div v-if="settings.connectedAccounts.microsoft.connected" class="provider-services">
              <div v-for="svc in microsoftServices" :key="svc.id" class="service-row">
                <component :is="serviceIconMap[svc.icon]" class="service-icon" :size="18" :stroke-width="1.75" />
                <div class="service-info">
                  <span class="service-name">{{ svc.name }}</span>
                </div>
                <BaseToggle
                  :model-value="microsoftServiceToggles[svc.id]"
                  @update:model-value="onServiceToggle"
                />
              </div>
            </div>
          </div>
        </template>

        <!-- ── AGENT ── -->
        <template v-if="activeSection === 'agent'">
          <div class="section-head">
            <h2 class="section-title">Agent</h2>
            <p class="section-sub">Which LLM admino talks to. Local is default — cloud providers are opt-in.</p>
          </div>
          <div class="s-card">
            <!-- Provider segmented control -->
            <div class="s-row">
              <div class="row-label">
                Provider
                <span class="row-hint">Ollama runs on your machine. Claude and OpenAI send data to their servers.</span>
              </div>
              <div class="seg">
                <button
                  v-for="p in providers"
                  :key="p.value"
                  class="seg-btn"
                  :class="{ active: settings.provider === p.value }"
                  @click="onProviderChange(p.value)"
                >
                  {{ p.label }}
                </button>
              </div>
            </div>

            <!-- Model field -->
            <div class="s-row stack">
              <div class="row-label">Model</div>
              <template v-if="currentProvider === 'ollama'">
                <input
                  v-model="draftOllamaModel"
                  class="s-input mono"
                  type="text"
                  placeholder="e.g. llama3.2:3b"
                  @blur="onOllamaModelBlur"
                />
                <span v-if="ollamaModelError" class="input-error">{{ ollamaModelError }}</span>
              </template>
              <template v-else-if="currentProvider === 'anthropic'">
                <input
                  v-model="draftAnthropicModel"
                  class="s-input mono"
                  type="text"
                  placeholder="e.g. claude-3-5-sonnet-20241022"
                  @blur="onAnthropicModelBlur"
                />
                <span v-if="anthropicModelError" class="input-error">{{ anthropicModelError }}</span>
              </template>
              <template v-else-if="currentProvider === 'openai'">
                <input
                  v-model="draftOpenAiModel"
                  class="s-input mono"
                  type="text"
                  placeholder="e.g. gpt-4o"
                  @blur="onOpenAiModelBlur"
                />
                <span v-if="openAiModelError" class="input-error">{{ openAiModelError }}</span>
              </template>
            </div>

            <!-- Ollama: endpoint URL -->
            <div v-if="currentProvider === 'ollama'" class="s-row stack">
              <div class="row-label">
                Endpoint URL
                <span class="row-hint">Where the local Ollama server is reachable.</span>
              </div>
              <input
                v-model="draftOllamaUrl"
                class="s-input mono"
                type="text"
                placeholder="http://localhost:11434"
                @blur="onOllamaUrlBlur"
              />
              <span v-if="ollamaUrlError" class="input-error">{{ ollamaUrlError }}</span>
            </div>

            <!-- Claude / OpenAI: API key indicator -->
            <div v-if="currentProvider === 'anthropic' || currentProvider === 'openai'" class="s-row">
              <div class="row-label">
                API key
                <span class="row-hint">Stored encrypted. Never written to logs or the audit trail.</span>
              </div>
              <span
                class="api-key-status"
                :class="(currentProvider === 'anthropic' ? anthropicConfigured : openAiConfigured) ? 'status-ok' : 'status-missing'"
              >
                {{ (currentProvider === 'anthropic' ? anthropicConfigured : openAiConfigured) ? 'Configured' : 'Not configured' }}
              </span>
            </div>
          </div>
        </template>

        <!-- ── APPEARANCE ── -->
        <template v-if="activeSection === 'appearance'">
          <div class="section-head">
            <h2 class="section-title">Appearance</h2>
            <p class="section-sub">How the interface looks. Changes apply immediately.</p>
          </div>
          <div class="s-card">
            <div class="s-row">
              <div class="row-label">
                Theme
                <span class="row-hint">Dark mode is on the roadmap for v2.</span>
              </div>
              <div class="seg">
                <button class="seg-btn active">Light</button>
                <button class="seg-btn" disabled>
                  Dark <span class="soon-badge">Soon</span>
                </button>
                <button class="seg-btn" disabled>System</button>
              </div>
            </div>
          </div>
        </template>

        <!-- ── NOTIFICATIONS ── -->
        <template v-if="activeSection === 'notifications'">
          <div class="section-head">
            <h2 class="section-title">Notifications</h2>
            <p class="section-sub">In-app pings. Browser push is opt-in once per device.</p>
          </div>
          <div class="s-card">
            <div class="s-row">
              <div class="row-label">
                Tool-approval pings
                <span class="row-hint">Ping me when admino needs my approval to run a tool.</span>
              </div>
              <BaseToggle
                :model-value="settings.notificationsEnabled"
                @update:model-value="onNotificationsChange"
              />
            </div>
            <div class="s-row">
              <div class="row-label">
                Task-done pings
                <span class="row-hint">Ping me when a long-running response is ready.</span>
              </div>
              <BaseToggle :model-value="false" @update:model-value="onServiceToggle" />
            </div>
            <div class="s-row">
              <div class="row-label">
                Sound
                <span class="row-hint">Subtle chime on pings. Respects system Do Not Disturb.</span>
              </div>
              <BaseToggle :model-value="false" @update:model-value="onServiceToggle" />
            </div>
          </div>
        </template>

        <!-- ── ABOUT ── -->
        <template v-if="activeSection === 'about'">
          <div class="section-head">
            <h2 class="section-title">About</h2>
            <p class="section-sub">Local-only, security-first personal AI agent.</p>
          </div>
          <div class="s-card">
            <div class="s-row">
              <div class="row-label">Version</div>
              <span class="mono-value">admino 1.0.0</span>
            </div>
            <div class="s-row">
              <div class="row-label">Source code</div>
              <a href="https://github.com/admino/admino" class="source-link" target="_blank" rel="noopener noreferrer">
                <Github :size="14" :stroke-width="1.75" />
                github.com/admino/admino
              </a>
            </div>
            <div class="s-row">
              <div class="row-label">License</div>
              <span class="muted-value">MIT</span>
            </div>
          </div>
          <div class="trust-badge">
            <ShieldCheck :size="20" :stroke-width="1.75" class="trust-icon" />
            <div>
              <div class="trust-title">Running locally</div>
              <div class="trust-body">Your messages, documents, and audit log stay on this machine. Only your configured LLM provider sees the conversation.</div>
            </div>
          </div>
        </template>

        <!-- ── DANGER ZONE ── -->
        <template v-if="activeSection === 'danger'">
          <div class="section-head">
            <h2 class="section-title danger-title">Danger zone</h2>
            <p class="section-sub">These actions cannot be undone. Each one prompts for confirmation.</p>
          </div>
          <div class="danger-card">
            <div class="s-row">
              <div class="row-label">
                Clear conversation
                <span class="row-hint">Wipes the current chat thread. Audit log is preserved by design.</span>
              </div>
              <button class="s-btn danger" @click="showClearConfirm = true">Clear thread</button>
            </div>
            <div class="s-row">
              <div class="row-label">
                Disconnect all accounts
                <span class="row-hint">Revokes OAuth refresh tokens for Google and Microsoft.</span>
              </div>
              <button class="s-btn danger" @click="handleDisconnectAll">Disconnect all</button>
            </div>
            <div class="s-row">
              <div class="row-label">
                Reset settings
                <span class="row-hint">Resets all settings to defaults. Connected accounts stay connected.</span>
              </div>
              <button class="s-btn danger" @click="handleResetSettings">Reset to defaults</button>
            </div>
            <div class="s-row">
              <div class="row-label danger-label">
                Erase all data
                <span class="row-hint">Deletes the audit log, memory, and document store. Cannot be recovered.</span>
              </div>
              <button class="s-btn danger solid" @click="handleEraseAll">Erase everything</button>
            </div>
          </div>
        </template>
      </div>
    </main>

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
