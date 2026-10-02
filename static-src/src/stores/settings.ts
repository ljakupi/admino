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
 * - `sessionId` / `newSession`: unchanged (the chat store depends on them).
 *
 * Issue #162 (the Tools page becomes "my connections"; the Org Admin's
 * service switches move to the Organization console): the connection and
 * org-tool state/actions left this store. `connectedAccounts`,
 * `loadConnections`, `connectGoogle`, `connectMicrosoft`, `disconnectGoogle`,
 * `disconnectMicrosoft`, `tools`, `loadOrgTools` and `setToolEnabled` live in
 * `stores/connections.ts` (`useConnectionsStore`) and `stores/orgServices.ts`
 * (`useOrgServicesStore`) instead.
 */
import { defineStore } from 'pinia';
import { ref } from 'vue';
import { getMySettings, patchMySettings, resetMySettings } from '@/api/settings';
import { useToastStore } from '@/stores/toasts';
import { t } from '@/i18n';
import type { AppTheme, UserSettingsPatch, UserSettingsResponse } from '@/api/types';

const SESSION_KEY = 'admino_session_id';

const SESSION_RE = /^[a-zA-Z0-9_-]{1,64}$/;

function generateSessionId(): string {
  const ts = Date.now().toString(36);
  const rand = Array.from(crypto.getRandomValues(new Uint8Array(8)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `s-${ts}-${rand}`;
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

  // --- User settings (GET/PATCH /api/me/settings) ---
  const loading = ref(false);
  const error = ref<string | null>(null);
  const theme = ref<AppTheme>('light');
  const notificationsEnabled = ref(true);
  const taskDoneNotifications = ref(false);

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
  };
});
