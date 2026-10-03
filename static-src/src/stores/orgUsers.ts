/**
 * Org users store (issue #165: Organization console, users and invitations
 * UI; backend routes come from #153's invitations and #164's org users).
 *
 * Owns the Org Admin's Users tab: the org's users, pending invitations and
 * seat usage (`load()`), the search/status filter (`visibleUsers` /
 * `visibleInvitations`), the invite sheet, the edit (name/email) sheet and
 * one confirm sheet shared by every row action that needs confirmation
 * (`request*` opens it, never calls the API; `confirmPending()` makes exactly
 * one call; `cancelPending()` closes it without one). `resendInvitation`
 * needs no confirmation.
 *
 * Security notes: no action here ever logs, and every user-facing message
 * comes from `services/orgUsers.ts`'s `orgUserErrorMessage` — a backend
 * error's `detail` is never shown (#139 §5). Acting on your own account
 * refreshes (`auth.loadMe()`, a role change) or ends (`auth.logout()`, a
 * deactivation/forced-logout/deletion) your session; every other flow leaves
 * auth untouched. No action throws: failures are recorded as a translated
 * `loadError` / `inviteError` / `editError` / `actionError` instead.
 */
import { defineStore } from 'pinia';
import { computed, ref } from 'vue';
import {
  createInvitation,
  deactivateOrgUser,
  deleteOrgUser,
  forceLogoutOrgUser,
  listInvitations,
  listOrgUsers,
  reactivateOrgUser,
  resendInvitation as apiResendInvitation,
  resetOrgUserPassword,
  revokeInvitation as apiRevokeInvitation,
  updateOrgUser,
} from '@/api/org-users';
import { t } from '@/i18n';
import {
  buildProfilePatch,
  filterInvitations,
  filterUsers,
  isAssignableRole,
  isPlausibleEmail,
  isStatusFilter,
  orgUserErrorMessage,
  seatLabel,
  seatsFull,
  type StatusFilter,
} from '@/services/orgUsers';
import { useAuthStore } from '@/stores/auth';
import { useToastStore } from '@/stores/toasts';
import type { MemberRole, OrgInvitation, OrgSeats, OrgUser } from '@/api/types';

export type PendingAction =
  | { kind: 'role'; userId: string; role: MemberRole }
  | { kind: 'deactivate' | 'reactivate' | 'resetPassword' | 'forceLogout' | 'delete'; userId: string }
  | { kind: 'revokeInvitation'; invitationId: string };

export type ConfirmOutcome = 'done' | 'failed' | 'signed_out';

export const useOrgUsersStore = defineStore('orgUsers', () => {
  const users = ref<OrgUser[]>([]);
  const invitations = ref<OrgInvitation[]>([]);
  const seats = ref<OrgSeats | null>(null);
  const loading = ref(false);
  const loaded = ref(false);
  const loadError = ref<string | null>(null);

  const query = ref('');
  const statusFilter = ref<StatusFilter>('all');

  const inviteOpen = ref(false);
  const inviteBusy = ref(false);
  const inviteError = ref<string | null>(null);

  const editUserId = ref<string | null>(null);
  const editBusy = ref(false);
  const editError = ref<string | null>(null);

  const pending = ref<PendingAction | null>(null);
  const actionBusy = ref(false);
  const actionError = ref<string | null>(null);

  const visibleUsers = computed(() =>
    filterUsers(users.value, { query: query.value, status: statusFilter.value }),
  );
  const visibleInvitations = computed(() =>
    filterInvitations(invitations.value, { query: query.value, status: statusFilter.value }),
  );
  const seatText = computed(() => seatLabel(seats.value));
  const noFreeSeat = computed(() => seatsFull(seats.value));

  function findUser(userId: string): OrgUser | undefined {
    return users.value.find((user) => user.id === userId);
  }

  function findInvitation(invitationId: string): OrgInvitation | undefined {
    return invitations.value.find((invitation) => invitation.id === invitationId);
  }

  function replaceUser(updated: OrgUser): void {
    users.value = users.value.map((user) => (user.id === updated.id ? updated : user));
  }

  /** Adjusts the used-seat count by `delta`; a no-op while seats are unknown, never below 0. */
  function adjustSeatsUsed(delta: number): void {
    if (seats.value === null) return;
    seats.value = { ...seats.value, used: Math.max(0, seats.value.used + delta) };
  }

  function isMe(userId: string): boolean {
    return useAuthStore().me?.user_id === userId;
  }

  // --- Load --------------------------------------------------------------------

  async function load(): Promise<void> {
    loading.value = true;
    try {
      const [usersResponse, invitationsResponse] = await Promise.all([listOrgUsers(), listInvitations()]);
      users.value = usersResponse.users;
      seats.value = usersResponse.seats;
      invitations.value = invitationsResponse.invitations;
      loaded.value = true;
      loadError.value = null;
    } catch (e) {
      loadError.value = orgUserErrorMessage(e);
    } finally {
      loading.value = false;
    }
  }

  function setQuery(value: string): void {
    query.value = value;
  }

  function setStatusFilter(value: unknown): void {
    if (isStatusFilter(value)) statusFilter.value = value;
  }

  // --- Invite sheet --------------------------------------------------------------

  function openInvite(): void {
    inviteOpen.value = true;
    inviteError.value = null;
  }

  function closeInvite(): void {
    inviteOpen.value = false;
    inviteError.value = null;
  }

  async function submitInvite(email: string, role: MemberRole): Promise<boolean> {
    if (inviteBusy.value) return false;
    if (!isAssignableRole(role)) {
      inviteError.value = t('orgUsers.error.invalidInput');
      return false;
    }
    if (!isPlausibleEmail(email)) {
      inviteError.value = t('orgUsers.error.invalidEmail');
      return false;
    }

    inviteBusy.value = true;
    try {
      const created = await createInvitation(email.trim(), role);
      invitations.value = [created, ...invitations.value];
      adjustSeatsUsed(1);
      inviteOpen.value = false;
      inviteError.value = null;
      useToastStore().add('success', t('toast.orgUsers.invited'));
      return true;
    } catch (e) {
      inviteError.value = orgUserErrorMessage(e, 'invitation');
      return false;
    } finally {
      inviteBusy.value = false;
    }
  }

  // --- Edit sheet (name and email) ------------------------------------------------

  function openEdit(userId: string): void {
    if (findUser(userId) === undefined) return;
    editUserId.value = userId;
    editError.value = null;
  }

  function closeEdit(): void {
    editUserId.value = null;
    editError.value = null;
  }

  async function submitEdit(input: { name: string; email: string }): Promise<boolean> {
    const userId = editUserId.value;
    if (userId === null || editBusy.value) return false;
    const user = findUser(userId);
    if (user === undefined) return false;

    if (!isPlausibleEmail(input.email)) {
      editError.value = t('orgUsers.error.invalidEmail');
      return false;
    }

    const patch = buildProfilePatch(user, input);
    if (patch === null) {
      editUserId.value = null;
      editError.value = null;
      return true;
    }

    editBusy.value = true;
    try {
      const updated = await updateOrgUser(userId, patch);
      replaceUser(updated);
      editUserId.value = null;
      editError.value = null;
      useToastStore().add('success', t('toast.orgUsers.profileSaved'));
      return true;
    } catch (e) {
      editError.value = orgUserErrorMessage(e);
      return false;
    } finally {
      editBusy.value = false;
    }
  }

  // --- Confirm sheet: request*, cancel ---------------------------------------------

  function requestRoleChange(userId: string, role: MemberRole): void {
    const user = findUser(userId);
    if (user === undefined || !isAssignableRole(role) || role === user.role) return;
    pending.value = { kind: 'role', userId, role };
    actionError.value = null;
  }

  function requestDeactivate(userId: string): void {
    const user = findUser(userId);
    if (user === undefined || user.status !== 'active') return;
    pending.value = { kind: 'deactivate', userId };
    actionError.value = null;
  }

  function requestReactivate(userId: string): void {
    const user = findUser(userId);
    if (user === undefined || user.status !== 'deactivated') return;
    pending.value = { kind: 'reactivate', userId };
    actionError.value = null;
  }

  function requestPasswordReset(userId: string): void {
    const user = findUser(userId);
    if (user === undefined || user.status !== 'active') return;
    pending.value = { kind: 'resetPassword', userId };
    actionError.value = null;
  }

  function requestForceLogout(userId: string): void {
    if (findUser(userId) === undefined) return;
    pending.value = { kind: 'forceLogout', userId };
    actionError.value = null;
  }

  function requestDelete(userId: string): void {
    if (findUser(userId) === undefined) return;
    pending.value = { kind: 'delete', userId };
    actionError.value = null;
  }

  function requestRevokeInvitation(invitationId: string): void {
    if (findInvitation(invitationId) === undefined) return;
    pending.value = { kind: 'revokeInvitation', invitationId };
    actionError.value = null;
  }

  function cancelPending(): void {
    pending.value = null;
    actionError.value = null;
  }

  /** Makes the one API call `action` stands for and applies its effect. Throws on failure. */
  async function runAction(action: PendingAction): Promise<ConfirmOutcome> {
    const auth = useAuthStore();
    const toasts = useToastStore();

    switch (action.kind) {
      case 'role': {
        const updated = await updateOrgUser(action.userId, { role: action.role });
        replaceUser(updated);
        toasts.add('success', t('toast.orgUsers.roleChanged'));
        if (isMe(action.userId)) await auth.loadMe();
        return 'done';
      }
      case 'deactivate': {
        const updated = await deactivateOrgUser(action.userId);
        replaceUser(updated);
        adjustSeatsUsed(-1);
        toasts.add('success', t('toast.orgUsers.deactivated'));
        if (isMe(action.userId)) {
          await auth.logout();
          return 'signed_out';
        }
        return 'done';
      }
      case 'reactivate': {
        const updated = await reactivateOrgUser(action.userId);
        replaceUser(updated);
        adjustSeatsUsed(1);
        toasts.add('success', t('toast.orgUsers.reactivated'));
        return 'done';
      }
      case 'resetPassword': {
        await resetOrgUserPassword(action.userId);
        toasts.add('success', t('toast.orgUsers.passwordResetSent'));
        return 'done';
      }
      case 'forceLogout': {
        await forceLogoutOrgUser(action.userId);
        toasts.add('success', t('toast.orgUsers.loggedOut'));
        if (isMe(action.userId)) {
          await auth.logout();
          return 'signed_out';
        }
        return 'done';
      }
      case 'delete': {
        const wasActive = findUser(action.userId)?.status === 'active';
        await deleteOrgUser(action.userId);
        users.value = users.value.filter((user) => user.id !== action.userId);
        if (wasActive) adjustSeatsUsed(-1);
        toasts.add('success', t('toast.orgUsers.deleted'));
        if (isMe(action.userId)) {
          await auth.logout();
          return 'signed_out';
        }
        return 'done';
      }
      case 'revokeInvitation': {
        await apiRevokeInvitation(action.invitationId);
        invitations.value = invitations.value.filter((invitation) => invitation.id !== action.invitationId);
        adjustSeatsUsed(-1);
        toasts.add('success', t('toast.orgUsers.invitationRevoked'));
        return 'done';
      }
      default: {
        const unreachable: never = action;
        throw new Error(`unknown pending action: ${JSON.stringify(unreachable)}`);
      }
    }
  }

  async function confirmPending(): Promise<ConfirmOutcome> {
    if (pending.value === null || actionBusy.value) return 'failed';

    const action = pending.value;
    actionBusy.value = true;
    try {
      const outcome = await runAction(action);
      pending.value = null;
      actionError.value = null;
      return outcome;
    } catch (e) {
      actionError.value = orgUserErrorMessage(e, action.kind === 'revokeInvitation' ? 'invitation' : 'user');
      return 'failed';
    } finally {
      actionBusy.value = false;
    }
  }

  // --- Resend invitation (no confirmation) -----------------------------------------

  async function resendInvitation(invitationId: string): Promise<boolean> {
    if (findInvitation(invitationId) === undefined) return false;

    try {
      const updated = await apiResendInvitation(invitationId);
      invitations.value = invitations.value.map((invitation) =>
        invitation.id === invitationId ? updated : invitation,
      );
      useToastStore().add('success', t('toast.orgUsers.invitationResent'));
      return true;
    } catch (e) {
      useToastStore().add('error', t('toast.orgUsers.failed'), orgUserErrorMessage(e, 'invitation'));
      return false;
    }
  }

  return {
    users,
    invitations,
    seats,
    loading,
    loaded,
    loadError,
    query,
    statusFilter,
    inviteOpen,
    inviteBusy,
    inviteError,
    editUserId,
    editBusy,
    editError,
    pending,
    actionBusy,
    actionError,
    visibleUsers,
    visibleInvitations,
    seatText,
    noFreeSeat,
    load,
    setQuery,
    setStatusFilter,
    openInvite,
    closeInvite,
    submitInvite,
    openEdit,
    closeEdit,
    submitEdit,
    requestRoleChange,
    requestDeactivate,
    requestReactivate,
    requestPasswordReset,
    requestForceLogout,
    requestDelete,
    requestRevokeInvitation,
    cancelPending,
    confirmPending,
    resendInvitation,
  };
});
