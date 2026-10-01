/**
 * Settings store (issue #159: settings split into platform, organization and
 * user scopes).
 *
 * The Settings page now shows only the caller's own settings, so this store
 * keeps no LLM state or actions (the Agent section left Settings). It owns:
 * - `loadSettings` / `saveSetting`: the user's theme and notifications
 *   through `GET` / `PATCH /api/me/settings`.
 * - `setNotificationsEnabled`: optimistic, reverted on failure.
 * - `taskDoneNotifications` / `setTaskDoneNotifications` (issue #35): the
 *   task-done pings flag, same optimistic pattern as `setNotificationsEnabled`.
 * - `resetSettings` (issue #35): `POST /api/me/settings/reset` via
 *   `resetMySettings`, applies the returned defaults and toasts; never
 *   touches connections, org tools or the session id.
 * - `loadConnections`: the Google/Microsoft OAuth connection status.
 * - `loadOrgTools` / `setToolEnabled`: the organization's enabled tool
 *   services through `GET` / `PATCH /api/org/settings` (Org Admin only).
 * - `connectGoogle` / `connectMicrosoft` / `disconnectGoogle` /
 *   `disconnectMicrosoft`: unchanged OAuth flows.
 * - `sessionId` / `newSession`: unchanged (the chat store depends on them).
 */
import { defineStore } from 'pinia';
import { ref } from 'vue';
import {
  disconnectOAuth,
  getMySettings,
  getOAuthAuthorizeUrl,
  getOAuthStatus,
  getOrgSettings,
  patchMySettings,
  patchOrgSettings,
  resetMySettings,
} from '@/api/settings';
import { useToastStore } from '@/stores/toasts';
import { t } from '@/i18n';
import type {
  AppTheme,
  ConnectedAccounts,
  OAuthConnectionStatus,
  ToolsSettings,
  UserSettingsPatch,
  UserSettingsResponse,
} from '@/api/types';

const SESSION_KEY = 'admino_session_id';

const SESSION_RE = /^[a-zA-Z0-9_-]{1,64}$/;

function generateSessionId(): string {
  const ts = Date.now().toString(36);
  const rand = Array.from(crypto.getRandomValues(new Uint8Array(8)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `s-${ts}-${rand}`;
}

const DISCONNECTED: OAuthConnectionStatus = { connected: false, healthy: false, email: null, services: [] };

/** The status as given, with a non-string `email` normalized to `null`. */
function normalizeStatus(status: OAuthConnectionStatus): OAuthConnectionStatus {
  return { ...status, email: typeof status.email === 'string' ? status.email : null };
}

const DEFAULT_TOOLS: ToolsSettings = {
  gmail: true,
  google_calendar: true,
  google_drive: true,
  outlook: true,
  outlook_calendar: true,
  onedrive: true,
  memory: true,
};

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

  // --- User settings (GET/PATCH /api/me/settings) ---
  const loading = ref(false);
  const error = ref<string | null>(null);
  const theme = ref<AppTheme>('light');
  const notificationsEnabled = ref(true);
  const taskDoneNotifications = ref(false);

  // --- Connected accounts (GET /api/oauth/{provider}/status) ---
  const connectedAccounts = ref<ConnectedAccounts>({
    google: { ...DISCONNECTED },
    microsoft: { ...DISCONNECTED },
  });

  // --- Organization tools (GET/PATCH /api/org/settings) ---
  const tools = ref<ToolsSettings>({ ...DEFAULT_TOOLS });

  function applyUserSettings(data: UserSettingsResponse) {
    theme.value = data.appearance.theme;
    notificationsEnabled.value = data.notifications.enabled;
    taskDoneNotifications.value = data.notifications.task_done;
  }

  async function loadSettings() {
    loading.value = true;
    error.value = null;
    try {
      const data = await getMySettings();
      applyUserSettings(data);
    } catch (e) {
      error.value = e instanceof Error ? e.message : t('settings.error.loadFailed');
    } finally {
      loading.value = false;
    }
  }

  async function saveSetting(patch: UserSettingsPatch) {
    const toasts = useToastStore();
    try {
      const data = await patchMySettings(patch);
      applyUserSettings(data);
      toasts.add('success', t('toast.common.saved'));
    } catch (e) {
      const msg = e instanceof Error ? e.message : t('settings.error.saveFailed');
      toasts.add('error', t('toast.common.saveFailed.title'), msg);
      throw e;
    }
  }

  async function setNotificationsEnabled(value: boolean) {
    const previous = notificationsEnabled.value;
    notificationsEnabled.value = value;
    try {
      await saveSetting({ notifications: { enabled: value } });
    } catch {
      notificationsEnabled.value = previous;
    }
  }

  async function setTaskDoneNotifications(value: boolean) {
    const previous = taskDoneNotifications.value;
    taskDoneNotifications.value = value;
    try {
      await saveSetting({ notifications: { task_done: value } });
    } catch {
      taskDoneNotifications.value = previous;
    }
  }

  async function resetSettings() {
    const toasts = useToastStore();
    try {
      const data = await resetMySettings();
      applyUserSettings(data);
      toasts.add('success', t('toast.settings.settingsReset'));
    } catch (e) {
      const msg = e instanceof Error ? e.message : t('settings.error.resetFailed');
      toasts.add('error', t('toast.settings.resetFailed.title'), msg);
    }
  }

  async function loadConnections() {
    const [google, microsoft] = await Promise.all([
      getOAuthStatus('google').catch(() => DISCONNECTED),
      getOAuthStatus('microsoft').catch(() => DISCONNECTED),
    ]);
    connectedAccounts.value = {
      google: normalizeStatus(google),
      microsoft: normalizeStatus(microsoft),
    };
  }

  async function loadOrgTools() {
    try {
      const data = await getOrgSettings();
      tools.value = data.tools;
    } catch {
      // Keep the current tools — the caller may not be an Org Admin.
    }
  }

  async function setToolEnabled(tool: keyof ToolsSettings, enabled: boolean) {
    const toasts = useToastStore();
    const previous = tools.value[tool];
    tools.value = { ...tools.value, [tool]: enabled };
    try {
      const data = await patchOrgSettings({ tools: { [tool]: enabled } });
      tools.value = data.tools;
      toasts.add('success', t('toast.common.saved'));
    } catch (e) {
      tools.value = { ...tools.value, [tool]: previous };
      const msg = e instanceof Error ? e.message : t('settings.error.saveFailed');
      toasts.add('error', t('toast.common.saveFailed.title'), msg);
    }
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
      await loadConnections();
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
      await loadConnections();
      toasts.add('success', t('toast.settings.microsoftDisconnected'));
    } catch (e) {
      const msg = e instanceof Error ? e.message : t('settings.error.disconnectFailed');
      toasts.add('error', t('toast.settings.disconnectFailed.title'), msg);
    }
  }

  return {
    // Session
    sessionId,
    newSession,
    // User settings
    theme,
    notificationsEnabled,
    taskDoneNotifications,
    loading,
    error,
    loadSettings,
    saveSetting,
    setNotificationsEnabled,
    setTaskDoneNotifications,
    resetSettings,
    // Connected accounts
    connectedAccounts,
    loadConnections,
    connectGoogle,
    connectMicrosoft,
    disconnectGoogle,
    disconnectMicrosoft,
    // Organization tools
    tools,
    loadOrgTools,
    setToolEnabled,
  };
});
