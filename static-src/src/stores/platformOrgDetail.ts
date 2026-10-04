/**
 * Platform organization detail store (issue #168: Platform console UI, org
 * detail view `?org=<uuid>`; routes from #154 and #167).
 *
 * Holds one org (taken from the org list), its metadata (seat usage, storage,
 * counts; never content) and its users with their actions. `load()` always
 * clears the previous org's data first (another org's data is never shown) and
 * ignores a response that arrives after a newer load started. User actions
 * follow `userActions`: `request*` opens the confirm sheet only when allowed
 * and never calls the API; `confirmPending()` makes exactly one call.
 *
 * Security notes: only `/api/platform/*` metadata is held; nothing here logs
 * and every message comes from the i18n catalogs via `platformErrorMessage`
 * (a backend `detail` is never shown). No action throws.
 */
import { defineStore } from 'pinia';
import { computed, ref } from 'vue';
import {
  deactivatePlatformUser,
  getPlatformOrgMetadata,
  listPlatformOrgs,
  listPlatformOrgUsers,
  reactivatePlatformUser,
  reinvitePlatformUser,
  resetPlatformUserPassword,
} from '@/api/platform';
import { ApiError } from '@/api/client';
import { t } from '@/i18n';
import { displayName, isPlausibleEmail, type ConfirmCopy } from '@/services/orgUsers';
import {
  orgIdFrom,
  platformErrorMessage,
  userActions,
  userConfirmCopy,
  type UserAction,
  type UserConfirmKind,
} from '@/services/platformOrgs';
import { useToastStore } from '@/stores/toasts';
import type { PlatformOrg, PlatformOrgMetadata, PlatformUser } from '@/api/types';

export interface PendingUserAction {
  kind: UserConfirmKind;
  userId: string;
}

export const usePlatformOrgDetailStore = defineStore('platformOrgDetail', () => {
  const orgId = ref<string | null>(null);
  const org = ref<PlatformOrg | null>(null);
  const metadata = ref<PlatformOrgMetadata | null>(null);
  const users = ref<PlatformUser[]>([]);
  const loading = ref(false);
  const loadError = ref<string | null>(null);
  const notFound = ref(false);

  const pending = ref<PendingUserAction | null>(null);
  const actionBusy = ref(false);
  const actionError = ref<string | null>(null);

  const reinviteUserId = ref<string | null>(null);
  const reinviteBusy = ref(false);
  const reinviteError = ref<string | null>(null);

  // Incremented by every load(); a response from an older load is dropped.
  let loadToken = 0;

  const pendingCopy = computed<ConfirmCopy | null>(() => {
    if (pending.value === null) return null;
    const user = findUser(pending.value.userId);
    return user === undefined ? null : userConfirmCopy(pending.value.kind, displayName(user));
  });

  const seatText = computed(() =>
    metadata.value === null
      ? null
      : t('platform.orgs.seats', { used: metadata.value.seats.used, limit: metadata.value.seats.limit }),
  );

  function findUser(userId: string): PlatformUser | undefined {
    return users.value.find((user) => user.id === userId);
  }

  function actionsFor(userId: string): UserAction[] {
    const user = findUser(userId);
    if (user === undefined || org.value === null) return [];
    return userActions(user, org.value, users.value);
  }

  function replaceUser(updated: PlatformUser): void {
    users.value = users.value.map((user) => (user.id === updated.id ? updated : user));
  }

  /** Re-reads the metadata; a failure keeps the old value and is not an error. */
  async function refreshMetadata(id: string): Promise<void> {
    try {
      const fresh = await getPlatformOrgMetadata(id);
      if (orgId.value === id) metadata.value = fresh;
    } catch {
      // Intentionally ignored: stale counts are better than an error for a successful action.
    }
  }

  // --- Load --------------------------------------------------------------------------

  async function load(id: string): Promise<void> {
    const token = ++loadToken;
    orgId.value = id;
    org.value = null;
    metadata.value = null;
    users.value = [];
    pending.value = null;
    actionError.value = null;
    reinviteUserId.value = null;
    reinviteError.value = null;
    loadError.value = null;
    notFound.value = false;

    if (orgIdFrom(id) === null) {
      notFound.value = true;
      loading.value = false;
      return;
    }

    loading.value = true;
    try {
      const [list, meta, userList] = await Promise.all([
        listPlatformOrgs(),
        getPlatformOrgMetadata(id),
        listPlatformOrgUsers(id),
      ]);
      if (token !== loadToken) return;
      const found = list.organizations.find((candidate) => candidate.id === id) ?? null;
      if (found === null) {
        notFound.value = true;
        return;
      }
      org.value = found;
      metadata.value = meta;
      users.value = userList.users;
    } catch (e) {
      if (token !== loadToken) return;
      if (e instanceof ApiError && e.status === 404) {
        notFound.value = true;
      } else {
        loadError.value = platformErrorMessage(e, 'org');
      }
    } finally {
      if (token === loadToken) loading.value = false;
    }
  }

  // --- Confirm sheet ----------------------------------------------------------------------

  function open(kind: UserConfirmKind, action: UserAction, userId: string): void {
    if (!actionsFor(userId).includes(action)) return;
    pending.value = { kind, userId };
    actionError.value = null;
  }

  function requestDeactivate(userId: string): void {
    open('deactivate', 'deactivate', userId);
  }

  function requestReactivate(userId: string): void {
    open('reactivate', 'reactivate', userId);
  }

  function requestPasswordReset(userId: string): void {
    open('resetPassword', 'resetPassword', userId);
  }

  function cancelPending(): void {
    pending.value = null;
    actionError.value = null;
  }

  async function confirmPending(): Promise<boolean> {
    const action = pending.value;
    const id = orgId.value;
    if (action === null || id === null || actionBusy.value) return false;
    const token = loadToken;

    actionBusy.value = true;
    actionError.value = null;
    try {
      if (action.kind === 'resetPassword') {
        await resetPlatformUserPassword(id, action.userId);
        useToastStore().add('success', t('platform.toast.passwordResetSent'));
      } else {
        const updated =
          action.kind === 'deactivate'
            ? await deactivatePlatformUser(id, action.userId)
            : await reactivatePlatformUser(id, action.userId);
        if (token === loadToken) {
          replaceUser(updated);
          await refreshMetadata(id);
        }
        useToastStore().add(
          'success',
          t(action.kind === 'deactivate' ? 'platform.toast.userDeactivated' : 'platform.toast.userReactivated'),
        );
      }
      if (token === loadToken) pending.value = null;
      return true;
    } catch (e) {
      // A late failure from the previous org must not show in the new org's sheet.
      if (token === loadToken) actionError.value = platformErrorMessage(e, 'user');
      return false;
    } finally {
      actionBusy.value = false;
    }
  }

  // --- Re-invite -----------------------------------------------------------------------------

  function openReinvite(userId: string): void {
    if (!actionsFor(userId).includes('reinvite')) return;
    reinviteUserId.value = userId;
    reinviteError.value = null;
  }

  function closeReinvite(): void {
    reinviteUserId.value = null;
    reinviteError.value = null;
  }

  async function submitReinvite(email: string): Promise<boolean> {
    const userId = reinviteUserId.value;
    const id = orgId.value;
    if (userId === null || id === null || reinviteBusy.value) return false;

    const token = loadToken;
    const trimmed = email.trim();
    if (trimmed !== '' && !isPlausibleEmail(trimmed)) {
      reinviteError.value = t('platform.orgs.form.error.email');
      return false;
    }

    reinviteBusy.value = true;
    reinviteError.value = null;
    try {
      if (trimmed === '') {
        await reinvitePlatformUser(id, userId);
      } else {
        await reinvitePlatformUser(id, userId, trimmed);
      }
      if (token === loadToken) closeReinvite();
      if (token === loadToken) {
        const [userList, meta] = await Promise.allSettled([listPlatformOrgUsers(id), getPlatformOrgMetadata(id)]);
        if (token === loadToken) {
          if (userList.status === 'fulfilled') users.value = userList.value.users;
          if (meta.status === 'fulfilled') metadata.value = meta.value;
        }
      }
      useToastStore().add('success', t('platform.toast.invitationSent'));
      return true;
    } catch (e) {
      if (token === loadToken) reinviteError.value = platformErrorMessage(e, 'user');
      return false;
    } finally {
      reinviteBusy.value = false;
    }
  }

  return {
    orgId,
    org,
    metadata,
    users,
    loading,
    loadError,
    notFound,
    pending,
    actionBusy,
    actionError,
    reinviteUserId,
    reinviteBusy,
    reinviteError,
    pendingCopy,
    seatText,
    actionsFor,
    load,
    requestDeactivate,
    requestReactivate,
    requestPasswordReset,
    cancelPending,
    confirmPending,
    openReinvite,
    closeReinvite,
    submitReinvite,
  };
});
