import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { getSettings, patchSettings, getOAuthAuthorizeUrl, disconnectOAuth } from '@/api/settings';
import { useToastStore } from '@/stores/toasts';
import type {
  SettingsResponse,
  SettingsPatch,
  LLMProviderName,
  AppTheme,
  ConnectedAccounts,
  ToolsSettings,
} from '@/api/types';

// Keep the old union type alias for backward compat with components
// The API uses 'anthropic' but the UI labels it 'claude' — we map here.
export type LLMProvider = 'claude' | 'openai' | 'vllm';

const TOKEN_KEY = 'admino_auth_token';
const SESSION_KEY = 'admino_session_id';

const TOKEN_RE = /^[\x21-\x7E]{8,512}$/;
const SESSION_RE = /^[a-zA-Z0-9_-]{1,64}$/;

function generateSessionId(): string {
  const ts = Date.now().toString(36);
  const rand = Array.from(crypto.getRandomValues(new Uint8Array(8)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `s-${ts}-${rand}`;
}

/** Map API provider name to UI provider label */
function apiToUiProvider(api: LLMProviderName): LLMProvider {
  return api === 'anthropic' ? 'claude' : api;
}

/** Map UI provider label back to API provider name */
function uiToApiProvider(ui: LLMProvider): LLMProviderName {
  return ui === 'claude' ? 'anthropic' : ui;
}

export const useSettingsStore = defineStore('settings', () => {
  // Auth token — stays in localStorage
  const token = ref<string | null>(loadToken());
  const needsAuth = ref(!token.value);

  function loadToken(): string | null {
    const stored = localStorage.getItem(TOKEN_KEY);
    if (stored && TOKEN_RE.test(stored)) return stored;
    return null;
  }

  function setToken(value: string | null) {
    if (value && TOKEN_RE.test(value)) {
      localStorage.setItem(TOKEN_KEY, value);
      token.value = value;
      needsAuth.value = false;
    } else if (value === null) {
      localStorage.removeItem(TOKEN_KEY);
      token.value = null;
      needsAuth.value = false;
    }
  }

  function skipAuth() {
    localStorage.removeItem(TOKEN_KEY);
    token.value = null;
    needsAuth.value = false;
  }

  // Session ID — stays in localStorage
  const sessionId = ref(loadSessionId());

  function loadSessionId(): string {
    const stored = localStorage.getItem(SESSION_KEY);
    if (stored && SESSION_RE.test(stored)) return stored;
    const fresh = generateSessionId();
    localStorage.setItem(SESSION_KEY, fresh);
    return fresh;
  }

  function newSession() {
    const fresh = generateSessionId();
    localStorage.setItem(SESSION_KEY, fresh);
    sessionId.value = fresh;
  }

  // --- Server-side settings ---
  const loading = ref(false);
  const error = ref<string | null>(null);

  // LLM
  const llmProvider = ref<LLMProviderName>('vllm');
  const llmAnthropicModel = ref('');
  const llmOpenAiModel = ref('');
  const llmVllmModel = ref('');
  const vllmAvailableModels = ref<string[]>([]);
  const anthropicKeyConfigured = ref(false);
  const openAiKeyConfigured = ref(false);

  // Appearance
  const theme = ref<AppTheme>('light');

  // Notifications
  const notificationsEnabled = ref(false);

  // Connected accounts
  const connectedAccounts = ref<ConnectedAccounts>({
    google: { connected: false, healthy: false, email: null, services: [] },
    microsoft: { connected: false, healthy: false, email: null, services: [] },
  });

  // Tools enabled state
  const tools = ref<ToolsSettings>({
    gmail: true,
    google_calendar: true,
    google_drive: true,
    outlook: true,
    outlook_calendar: true,
    onedrive: true,
    files: true,
    memory: true,
  });

  // Computed ref for backward compat with components that read `provider`.
  const provider = computed<LLMProvider>(() => apiToUiProvider(llmProvider.value));

  function applyResponse(data: SettingsResponse) {
    llmProvider.value = data.llm.provider;
    llmAnthropicModel.value = data.llm.anthropic_model;
    llmOpenAiModel.value = data.llm.openai_model;
    llmVllmModel.value = data.llm.vllm_model;
    vllmAvailableModels.value = data.llm.vllm_available_models;
    anthropicKeyConfigured.value = data.llm.anthropic_key_configured;
    openAiKeyConfigured.value = data.llm.openai_key_configured;
    theme.value = data.appearance.theme;
    notificationsEnabled.value = data.notifications.enabled;
    connectedAccounts.value = data.connected_accounts;
    tools.value = data.tools;
  }

  async function loadSettings() {
    loading.value = true;
    error.value = null;
    try {
      const data = await getSettings();
      applyResponse(data);
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Failed to load settings';
    } finally {
      loading.value = false;
    }
  }

  async function saveSetting(patch: SettingsPatch) {
    const toasts = useToastStore();
    try {
      const data = await patchSettings(patch);
      applyResponse(data);
      toasts.add('success', 'Saved');
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to save settings';
      toasts.add('error', 'Save failed', msg);
      throw e;
    }
  }

  // Convenience setters that call saveSetting internally
  async function setProvider(ui: LLMProvider) {
    const previous = llmProvider.value;
    llmProvider.value = uiToApiProvider(ui);
    try {
      await saveSetting({ llm: { provider: llmProvider.value } });
    } catch (e) {
      // Revert the optimistic switch so the UI reflects the server's rejection.
      llmProvider.value = previous;
      throw e;
    }
  }

  async function setAnthropicModel(value: string) {
    llmAnthropicModel.value = value;
    await saveSetting({ llm: { anthropic_model: value } });
  }

  async function setOpenAiModel(value: string) {
    llmOpenAiModel.value = value;
    await saveSetting({ llm: { openai_model: value } });
  }

  async function setVllmModel(value: string) {
    llmVllmModel.value = value;
    await saveSetting({ llm: { vllm_model: value } });
  }

  async function setNotificationsEnabled(value: boolean) {
    notificationsEnabled.value = value;
    await saveSetting({ notifications: { enabled: value } });
  }

  async function connectGoogle() {
    const toasts = useToastStore();
    try {
      const { url } = await getOAuthAuthorizeUrl('google');
      const parsed = new URL(url);
      if (parsed.protocol !== 'https:') {
        toasts.add('error', 'Connection failed', 'Unexpected OAuth redirect URL.');
        return;
      }
      sessionStorage.setItem('oauth_pending', 'google');
      window.location.href = url;
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to start OAuth flow';
      toasts.add('error', 'Connection failed', msg);
    }
  }

  async function connectMicrosoft() {
    const toasts = useToastStore();
    try {
      const { url } = await getOAuthAuthorizeUrl('microsoft');
      const parsed = new URL(url);
      if (parsed.protocol !== 'https:') {
        toasts.add('error', 'Connection failed', 'Unexpected OAuth redirect URL.');
        return;
      }
      sessionStorage.setItem('oauth_pending', 'microsoft');
      window.location.href = url;
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to start OAuth flow';
      toasts.add('error', 'Connection failed', msg);
    }
  }

  async function disconnectGoogle() {
    const toasts = useToastStore();
    try {
      await disconnectOAuth('google');
      await loadSettings();
      toasts.add('success', 'Google disconnected');
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to disconnect';
      toasts.add('error', 'Disconnect failed', msg);
    }
  }

  async function disconnectMicrosoft() {
    const toasts = useToastStore();
    try {
      await disconnectOAuth('microsoft');
      await loadSettings();
      toasts.add('success', 'Microsoft disconnected');
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to disconnect';
      toasts.add('error', 'Disconnect failed', msg);
    }
  }

  async function setToolEnabled(tool: keyof ToolsSettings, enabled: boolean) {
    const previous = tools.value[tool];
    tools.value = { ...tools.value, [tool]: enabled };
    try {
      await saveSetting({ tools: { [tool]: enabled } });
    } catch {
      tools.value = { ...tools.value, [tool]: previous };
    }
  }

  return {
    // Auth
    token,
    needsAuth,
    setToken,
    skipAuth,
    // Session
    sessionId,
    newSession,
    // Compat computed
    provider,
    // Raw LLM state
    llmProvider,
    llmAnthropicModel,
    llmOpenAiModel,
    llmVllmModel,
    vllmAvailableModels,
    anthropicKeyConfigured,
    openAiKeyConfigured,
    // Appearance
    theme,
    // Notifications
    notificationsEnabled,
    // Connected accounts
    connectedAccounts,
    // Tools
    tools,
    setToolEnabled,
    // Loading state
    loading,
    error,
    // Actions
    loadSettings,
    saveSetting,
    setProvider,
    setAnthropicModel,
    setOpenAiModel,
    setVllmModel,
    setNotificationsEnabled,
    connectGoogle,
    connectMicrosoft,
    disconnectGoogle,
    disconnectMicrosoft,
  };
});
