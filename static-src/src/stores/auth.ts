/**
 * Auth store (issue #155: auth pages and role-aware app shell; issue #166
 * adds `applyAccount` and `forgetSession`, and fires the account store's
 * timezone preset after a login / invitation accept).
 *
 * Owns who is logged in: `me` (the `GET /api/auth/me` payload, or `null`),
 * `loaded`, `role` (`shellRole(me)`, fails closed) and `isAuthenticated`
 * (`role !== null`). Every action here is fail-closed and never throws —
 * network/auth failures always leave the store logged out rather than in an
 * unknown state.
 */
import { defineStore } from 'pinia';
import { computed, ref } from 'vue';
import { getMe, login as apiLogin, logout as apiLogout } from '@/api/auth';
import { ApiError } from '@/api/client';
import { setLocale, t } from '@/i18n';
import { browserLocale } from '@/services/locale';
import { shellRole, type ShellRole } from '@/services/access';
import { useAccountStore } from './account';
import { useChatStore } from './chat';
import { useToastStore } from './toasts';
import type { MeResponse, MyAccount } from '@/api/types';

export type LoginOutcome = 'ok' | 'invalid' | 'rate_limited' | 'error';

export const useAuthStore = defineStore('auth', () => {
  const me = ref<MeResponse | null>(null);
  const loaded = ref(false);
  // Tracks the last user a profile was successfully loaded for, independent of
  // `me` (which a 401 clears): lets a later login tell "same user, resumed
  // session" apart from "a different user signed in", so the chat thread is
  // only cleared on an actual user switch, never on a plain re-login.
  const lastUserId = ref<string | null>(null);
  let ensurePromise: Promise<void> | null = null;

  const role = computed<ShellRole | null>(() => shellRole(me.value));
  const isAuthenticated = computed(() => role.value !== null);

  function applyProfile(profile: MeResponse): void {
    if (lastUserId.value !== null && lastUserId.value !== profile.user_id) {
      useChatStore().clearThread();
    }
    lastUserId.value = profile.user_id;
    me.value = profile;
    loaded.value = true;
    setLocale(profile.ui_language);
  }

  function applyLoggedOut(): void {
    me.value = null;
    loaded.value = true;
  }

  /** Fetches `/api/auth/me` once per app load; concurrent/later callers share or skip the request. */
  async function ensureLoaded(): Promise<void> {
    if (loaded.value) return;
    if (ensurePromise) return ensurePromise;
    ensurePromise = (async () => {
      try {
        applyProfile(await getMe());
      } catch {
        applyLoggedOut();
        setLocale(browserLocale());
      } finally {
        ensurePromise = null;
      }
    })();
    return ensurePromise;
  }

  /** Reloads the profile (e.g. after accepting an invitation, whose 204 sets the session cookie). */
  async function loadMe(): Promise<boolean> {
    try {
      applyProfile(await getMe());
      // Fire-and-forget: never delays or changes the outcome of this call.
      void useAccountStore().presetTimezone();
      return true;
    } catch {
      applyLoggedOut();
      return false;
    }
  }

  async function login(email: string, password: string): Promise<LoginOutcome> {
    try {
      await apiLogin(email, password);
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401) return 'invalid';
        if (err.status === 429) return 'rate_limited';
      }
      return 'error';
    }
    return (await loadMe()) ? 'ok' : 'error';
  }

  /**
   * Everything `logout()` does once the session is over locally: forgets the
   * user, clears the chat, resets the account store and returns to the
   * browser's language — without calling the logout API and without a
   * session-expired toast (a password change or revoking the current
   * session already ended the session server-side).
   */
  function forgetSession(): void {
    me.value = null;
    loaded.value = true;
    lastUserId.value = null;
    useChatStore().clearThread();
    useAccountStore().reset();
    setLocale(browserLocale());
  }

  async function logout(): Promise<void> {
    try {
      await apiLogout();
    } catch {
      // The session may already be gone server-side — log out locally regardless.
    }
    forgetSession();
  }

  /** Called by the global 401 handler. The first 401 of a session shows one toast and forgets the user. */
  function handleUnauthorized(): boolean {
    if (me.value === null) return false;
    useToastStore().add('warning', t('auth.sessionExpired.title'), t('auth.sessionExpired.body'));
    me.value = null;
    return true;
  }

  /** Signed in: the profile's languages and the UI locale follow the saved account. Logged out: no-op. */
  function applyAccount(account: MyAccount): void {
    if (me.value === null) return;
    me.value = { ...me.value, ui_language: account.ui_language, response_language: account.response_language };
    setLocale(account.ui_language);
  }

  return {
    me,
    loaded,
    role,
    isAuthenticated,
    ensureLoaded,
    login,
    loadMe,
    logout,
    forgetSession,
    handleUnauthorized,
    applyAccount,
  };
});
