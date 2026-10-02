/**
 * Connections store (issue #162: the Tools page becomes "my connections").
 *
 * Owns the caller's own Google and Microsoft OAuth connections, which moved
 * out of `stores/settings.ts`: `accounts` (both providers, loaded from
 * `GET /api/oauth/{provider}/status`), `loading`, and the `connect` /
 * `disconnect` actions. `services/connections.ts` decides whether a connect
 * or disconnect is offered (`canConnect` / `canDisconnect`) from the stored
 * status, including the residency gate.
 *
 * Security notes: `connect` never navigates anywhere but an `https:` URL
 * (defense in depth in front of the backend's own validation), and a
 * residency-blocked connect never reaches the network.
 */
import { defineStore } from 'pinia';
import { reactive, ref } from 'vue';
import { disconnectOAuth, getOAuthAuthorizeUrl, getOAuthStatus } from '@/api/settings';
import { canConnect } from '@/services/connections';
import { useToastStore } from '@/stores/toasts';
import { t } from '@/i18n';
import type { OAuthConnectionStatus, OAuthProvider } from '@/api/types';

const DISCONNECTED: OAuthConnectionStatus = {
  connected: false,
  healthy: false,
  email: null,
  data_residency: false,
  services: [],
};

const PENDING_KEY = 'oauth_pending';

const DISCONNECT_TOAST_KEY: Record<OAuthProvider, 'toast.settings.googleDisconnected' | 'toast.settings.microsoftDisconnected'> = {
  google: 'toast.settings.googleDisconnected',
  microsoft: 'toast.settings.microsoftDisconnected',
};

/** The status as given, with a non-string `email` normalized to `null`. */
function normalizeStatus(status: OAuthConnectionStatus): OAuthConnectionStatus {
  return { ...status, email: typeof status.email === 'string' ? status.email : null };
}

export const useConnectionsStore = defineStore('connections', () => {
  const accounts = reactive<Record<OAuthProvider, OAuthConnectionStatus>>({
    google: { ...DISCONNECTED },
    microsoft: { ...DISCONNECTED },
  });
  const loading = ref(false);

  async function load() {
    loading.value = true;
    try {
      const [google, microsoft] = await Promise.all([
        getOAuthStatus('google').catch(() => DISCONNECTED),
        getOAuthStatus('microsoft').catch(() => DISCONNECTED),
      ]);
      accounts.google = normalizeStatus(google);
      accounts.microsoft = normalizeStatus(microsoft);
    } finally {
      loading.value = false;
    }
  }

  async function connect(provider: OAuthProvider) {
    const toasts = useToastStore();
    if (!canConnect(accounts[provider])) {
      if (accounts[provider].data_residency) {
        toasts.add('error', t('toast.settings.connectionFailed.title'), t('toolsPage.residency.connectBlocked'));
      }
      return;
    }

    try {
      const { url } = await getOAuthAuthorizeUrl(provider);
      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        toasts.add('error', t('toast.settings.connectionFailed.title'), t('settings.error.unexpectedRedirect'));
        return;
      }
      if (parsed.protocol !== 'https:') {
        toasts.add('error', t('toast.settings.connectionFailed.title'), t('settings.error.unexpectedRedirect'));
        return;
      }
      sessionStorage.setItem(PENDING_KEY, provider);
      window.location.href = url;
    } catch (e) {
      const msg = e instanceof Error ? e.message : t('settings.error.oauthStartFailed');
      toasts.add('error', t('toast.settings.connectionFailed.title'), msg);
    }
  }

  async function disconnect(provider: OAuthProvider) {
    const toasts = useToastStore();
    try {
      await disconnectOAuth(provider);
      await load();
      toasts.add('success', t(DISCONNECT_TOAST_KEY[provider]));
    } catch (e) {
      const msg = e instanceof Error ? e.message : t('settings.error.disconnectFailed');
      toasts.add('error', t('toast.settings.disconnectFailed.title'), msg);
    }
  }

  return { accounts, loading, load, connect, disconnect };
});
