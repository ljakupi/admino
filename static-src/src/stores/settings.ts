import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { getSettings, patchSettings, getOAuthAuthorizeUrl, disconnectOAuth } from '@/api/settings';
import { useToastStore } from '@/stores/toasts';
import { t } from '@/i18n';
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
export type LLMProvider = 'infomaniak' | 'claude' | 'openai' | 'vllm';

const SESSION_KEY = 'admino_session_id';

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
  const llmProvider = ref<LLMProviderName>('infomaniak');
  const llmAnthropicModel = ref('');
  const llmOpenAiModel = ref('');
  const llmVllmModel = ref('');
  const vllmAvailableModels = ref<string[]>([]);
  const anthropicKeyConfigured = ref(false);
  const openAiKeyConfigured = ref(false);
  const llmInfomaniakModel = ref('');
  const infomaniakAvailableModels = ref<string[]>([]);
  const infomaniakTokenConfigured = ref(false);

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
    llmInfomaniakModel.value = data.llm.infomaniak_model;
    infomaniakAvailableModels.value = data.llm.infomaniak_available_models;
    infomaniakTokenConfigured.value = data.llm.infomaniak_token_configured;
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
      error.value = e instanceof Error ? e.message : t('settings.error.loadFailed');
    } finally {
      loading.value = false;
    }
  }

  async function saveSetting(patch: SettingsPatch) {
    const toasts = useToastStore();
    try {
      const data = await patchSettings(patch);
      applyResponse(data);
      toasts.add('success', t('toast.common.saved'));
    } catch (e) {
      const msg = e instanceof Error ? e.message : t('settings.error.saveFailed');
      toasts.add('error', t('toast.common.saveFailed.title'), msg);
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

  async function setInfomaniakModel(value: string) {
    llmInfomaniakModel.value = value;
    await saveSetting({ llm: { infomaniak_model: value } });
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
        toasts.add('error', t('toast.settings.connectionFailed.title'), t('settings.error.unexpectedRedirect'));
        return;
      }
      sessionStorage.setItem('oauth_pending', 'google');
      window.location.href = url;
    } catch (e) {
      const msg = e instanceof Error ? e.message : t('settings.error.oauthStartFailed');
      toasts.add('error', t('toast.settings.connectionFailed.title'), msg);
    }
  }

  async function connectMicrosoft() {
    const toasts = useToastStore();
    try {
      const { url } = await getOAuthAuthorizeUrl('microsoft');
      const parsed = new URL(url);
      if (parsed.protocol !== 'https:') {
        toasts.add('error', t('toast.settings.connectionFailed.title'), t('settings.error.unexpectedRedirect'));
        return;
      }
      sessionStorage.setItem('oauth_pending', 'microsoft');
      window.location.href = url;
    } catch (e) {
      const msg = e instanceof Error ? e.message : t('settings.error.oauthStartFailed');
      toasts.add('error', t('toast.settings.connectionFailed.title'), msg);
    }
  }

  async function disconnectGoogle() {
    const toasts = useToastStore();
    try {
      await disconnectOAuth('google');
      await loadSettings();
      toasts.add('success', t('toast.settings.googleDisconnected'));
    } catch (e) {
      const msg = e instanceof Error ? e.message : t('settings.error.disconnectFailed');
      toasts.add('error', t('toast.settings.disconnectFailed.title'), msg);
    }
  }

  async function disconnectMicrosoft() {
    const toasts = useToastStore();
    try {
      await disconnectOAuth('microsoft');
      await loadSettings();
      toasts.add('success', t('toast.settings.microsoftDisconnected'));
    } catch (e) {
      const msg = e instanceof Error ? e.message : t('settings.error.disconnectFailed');
      toasts.add('error', t('toast.settings.disconnectFailed.title'), msg);
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
    llmInfomaniakModel,
    infomaniakAvailableModels,
    infomaniakTokenConfigured,
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
    setInfomaniakModel,
    setNotificationsEnabled,
    connectGoogle,
    connectMicrosoft,
    disconnectGoogle,
    disconnectMicrosoft,
  };
});
