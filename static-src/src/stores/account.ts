/**
 * Account store (issue #166: account self-service — profile, languages,
 * timezone, personal instructions, password change, sessions).
 *
 * Owns the "My account" settings section. No action ever throws — failures
 * come back as a catalog key (`Result`) or a translated-key error field, so
 * the page can always show something sensible. The password is never kept
 * in this store's state (it is only ever passed straight through to the
 * API call).
 */
import { defineStore } from 'pinia';
import { ref } from 'vue';
import {
  changeMyPassword,
  getMyAccount,
  listMySessions,
  patchMyAccount,
  revokeMySession,
} from '@/api/account';
import { ApiError } from '@/api/client';
import { locale, setLocale, t, type MessageKey } from '@/i18n';
import {
  DEFAULT_TIMEZONE,
  accountPatch,
  accountSaveMessageKey,
  browserTimezone,
  passwordChangeMessageKey,
  sortSessions,
  validateDraft,
  type AccountDraft,
  type AccountDraftIssue,
} from '@/services/account';
import { checkNewPassword, issueMessageKey } from '@/services/passwordPolicy';
import { useAuthStore } from './auth';
import { useToastStore } from './toasts';
import type { MyAccount, SessionSummary, UiLanguage } from '@/api/types';

export type AccountResult = { ok: true } | { ok: false; messageKey: MessageKey };

const DRAFT_ISSUE_KEYS: Record<AccountDraftIssue, MessageKey> = {
  name_required: 'account.error.nameRequired',
  name_too_long: 'account.error.nameTooLong',
  instructions_too_long: 'account.error.instructionsTooLong',
};

export const useAccountStore = defineStore('account', () => {
  const account = ref<MyAccount | null>(null);
  const loading = ref(false);
  const saving = ref(false);
  const loadError = ref<MessageKey | null>(null);

  const sessions = ref<SessionSummary[]>([]);
  const sessionsLoading = ref(false);
  const sessionsError = ref<MessageKey | null>(null);
  const revokingId = ref<string | null>(null);

  const changingPassword = ref(false);

  // Runs the timezone preset at most once per signed-in user per app load.
  const timezonePresetUserIds = new Set<string>();

  async function load(): Promise<void> {
    loading.value = true;
    try {
      account.value = await getMyAccount();
      loadError.value = null;
    } catch {
      loadError.value = 'account.error.load';
    } finally {
      loading.value = false;
    }
  }

  async function saveProfile(draft: AccountDraft): Promise<AccountResult> {
    const issues = validateDraft(draft);
    if (issues.length > 0) {
      return { ok: false, messageKey: DRAFT_ISSUE_KEYS[issues[0]] };
    }
    if (account.value === null) return { ok: true };

    const patch = accountPatch(account.value, draft);
    if (patch === null) return { ok: true };

    saving.value = true;
    try {
      const updated = await patchMyAccount(patch);
      account.value = updated;
      useAuthStore().applyAccount(updated);
      useToastStore().add('success', t('account.toast.saved'));
      return { ok: true };
    } catch (err) {
      return { ok: false, messageKey: accountSaveMessageKey(err) };
    } finally {
      saving.value = false;
    }
  }

  async function setUiLanguage(lang: UiLanguage): Promise<AccountResult> {
    if (locale.value === lang) return { ok: true };

    const previousLocale = locale.value;
    setLocale(lang);
    try {
      const updated = await patchMyAccount({ ui_language: lang });
      account.value = updated;
      useAuthStore().applyAccount(updated);
      return { ok: true };
    } catch (err) {
      setLocale(previousLocale);
      return { ok: false, messageKey: accountSaveMessageKey(err) };
    }
  }

  /** After a login / invitation accept: presets a NULL stored timezone. Swallows every error. */
  async function presetTimezone(): Promise<void> {
    const userId = useAuthStore().me?.user_id;
    if (userId === undefined || timezonePresetUserIds.has(userId)) return;
    timezonePresetUserIds.add(userId);

    let current: MyAccount;
    try {
      current = await getMyAccount();
    } catch {
      return;
    }
    account.value = current;
    if (current.timezone !== null) return;

    const browserZone = browserTimezone();
    try {
      account.value = await patchMyAccount({ timezone: browserZone });
      return;
    } catch (err) {
      if (!(err instanceof ApiError) || err.status !== 422 || browserZone === DEFAULT_TIMEZONE) return;
    }

    try {
      account.value = await patchMyAccount({ timezone: DEFAULT_TIMEZONE });
    } catch {
      // The fallback failed too; the server keeps the timezone unset.
    }
  }

  async function changePassword(
    current: string,
    next: string,
    confirm: string,
    email: string,
  ): Promise<AccountResult> {
    const issues = checkNewPassword(next, confirm, email);
    if (issues.length > 0) {
      return { ok: false, messageKey: issueMessageKey(issues[0]) };
    }
    if (current.trim() === '') {
      return { ok: false, messageKey: 'account.password.error.currentRequired' };
    }

    changingPassword.value = true;
    try {
      await changeMyPassword(current, next);
      useAuthStore().forgetSession();
      return { ok: true };
    } catch (err) {
      return { ok: false, messageKey: passwordChangeMessageKey(err) };
    } finally {
      changingPassword.value = false;
    }
  }

  async function loadSessions(): Promise<void> {
    sessionsLoading.value = true;
    try {
      sessions.value = sortSessions(await listMySessions());
      sessionsError.value = null;
    } catch {
      sessionsError.value = 'account.sessions.error.load';
    } finally {
      sessionsLoading.value = false;
    }
  }

  async function revokeSession(id: string): Promise<AccountResult & { endedCurrent?: boolean }> {
    revokingId.value = id;
    try {
      await revokeMySession(id);
    } catch (err) {
      if (!(err instanceof ApiError) || err.status !== 404) {
        revokingId.value = null;
        return { ok: false, messageKey: 'account.sessions.error.revoke' };
      }
      // A 404 means the session is already gone — treat it like a success.
    }

    const removed = sessions.value.find((session) => session.id === id);
    sessions.value = sessions.value.filter((session) => session.id !== id);
    revokingId.value = null;

    if (removed?.current) {
      useAuthStore().forgetSession();
      return { ok: true, endedCurrent: true };
    }
    return { ok: true };
  }

  function reset(): void {
    account.value = null;
    loading.value = false;
    saving.value = false;
    loadError.value = null;
    sessions.value = [];
    sessionsLoading.value = false;
    sessionsError.value = null;
    revokingId.value = null;
    changingPassword.value = false;
  }

  return {
    account,
    loading,
    saving,
    loadError,
    sessions,
    sessionsLoading,
    sessionsError,
    revokingId,
    changingPassword,
    load,
    saveProfile,
    setUiLanguage,
    presetTimezone,
    changePassword,
    loadSessions,
    revokeSession,
    reset,
  };
});
