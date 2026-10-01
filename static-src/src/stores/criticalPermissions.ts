import { defineStore } from 'pinia';
import { ref } from 'vue';
import {
  getCriticalPermissions,
  promoteCriticalPermission,
  demoteCriticalPermission,
  cancelPendingPromotion,
} from '@/api/critical-permissions';
import { useToastStore } from '@/stores/toasts';
import { t } from '@/i18n';
import type { MessageKey } from '@/i18n';
import { ApiError } from '@/api/client';
import type { CriticalPermissionPatchResponse } from '@/api/types';

export interface CritPermDef {
  tool: string;
  action: string;
  icon: string;
  labelKey: MessageKey;
  descriptionKey: MessageKey;
}

export const CRIT_PERMS: CritPermDef[] = [
  {
    tool: 'gmail', action: 'send',
    icon: 'mail', labelKey: 'permissions.critical.gmailSend.label',
    descriptionKey: 'permissions.critical.sendEmail.description',
  },
  {
    tool: 'outlook', action: 'send',
    icon: 'mail', labelKey: 'permissions.critical.outlookSend.label',
    descriptionKey: 'permissions.critical.sendEmail.description',
  },
  {
    tool: 'google_calendar', action: 'update',
    icon: 'calendar', labelKey: 'permissions.critical.googleCalendarUpdate.label',
    descriptionKey: 'permissions.critical.updateEvent.description',
  },
  {
    tool: 'outlook_calendar', action: 'update',
    icon: 'calendar', labelKey: 'permissions.critical.outlookCalendarUpdate.label',
    descriptionKey: 'permissions.critical.updateEvent.description',
  },
];

export const COOLDOWN_SEC = 300;

function critKey(tool: string, action: string): string {
  return `${tool}.${action}`;
}

/** Formats a duration in seconds as `m:ss`, for the promotion-scheduled toast. */
function formatCooldown(totalSeconds: number): string {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = String(totalSeconds % 60).padStart(2, '0');
  return `${minutes}:${seconds}`;
}

interface PermState {
  state: 'deny' | 'confirm';
  pendingAt: number | null;
}

/** The (tool, action) pair the password re-auth prompt is open for. */
export interface ReauthTarget {
  tool: string;
  action: string;
}

export const useCriticalPermissionsStore = defineStore('criticalPermissions', () => {
  const permissions = ref<Map<string, PermState>>(new Map());
  const loading = ref(false);
  const error = ref<string | null>(null);

  // Password re-auth prompt (issue #161: promoting a critical permission
  // needs the Org Admin's password). The password itself is never kept in
  // any store state — it only ever lives as a function argument.
  const reauthTarget = ref<ReauthTarget | null>(null);
  const reauthError = ref<string | null>(null);
  const reauthBusy = ref(false);

  function getState(tool: string, action: string): PermState {
    return permissions.value.get(critKey(tool, action)) ?? { state: 'deny', pendingAt: null };
  }

  async function load() {
    loading.value = true;
    error.value = null;
    try {
      const res = await getCriticalPermissions();
      const map = new Map<string, PermState>();
      for (const entry of res.permissions) {
        map.set(critKey(entry.tool, entry.action), {
          state: entry.state,
          pendingAt: entry.pending_at ? new Date(entry.pending_at).getTime() : null,
        });
      }
      permissions.value = map;
    } catch (e) {
      error.value = e instanceof Error ? e.message : t('criticalPermissions.error.loadFailed');
    } finally {
      loading.value = false;
    }
  }

  function applyState(tool: string, action: string, res: CriticalPermissionPatchResponse) {
    permissions.value.set(critKey(tool, action), {
      state: res.state,
      pendingAt: res.pending_at ? new Date(res.pending_at).getTime() : null,
    });
    // Force reactivity
    permissions.value = new Map(permissions.value);
  }

  /** Requests a promotion with the Org Admin's password. Rethrows on failure (used directly and by `confirmReauth`). */
  async function promote(tool: string, action: string, password: string): Promise<CriticalPermissionPatchResponse> {
    const toasts = useToastStore();
    try {
      const res = await promoteCriticalPermission(tool, action, password);
      applyState(tool, action, res);
      toasts.add(
        'success',
        t('toast.criticalPermissions.promotionScheduled.title'),
        t('toast.criticalPermissions.promotionScheduled.body', { time: formatCooldown(COOLDOWN_SEC) }),
      );
      return res;
    } catch (e) {
      if (e instanceof ApiError) {
        toasts.add('error', t('toast.criticalPermissions.promotionFailed.title'), e.message);
      } else {
        toasts.add('error', t('toast.criticalPermissions.promotionFailed.title'));
      }
      throw e;
    }
  }

  async function cancelPending(tool: string, action: string) {
    const toasts = useToastStore();
    try {
      await cancelPendingPromotion(tool, action);
      permissions.value.set(critKey(tool, action), { state: 'deny', pendingAt: null });
      permissions.value = new Map(permissions.value);
      toasts.add('success', t('toast.criticalPermissions.cancelled.title'));
    } catch (e) {
      toasts.add('error', t('toast.criticalPermissions.cancelFailed.title'));
    }
  }

  async function demote(tool: string, action: string) {
    const toasts = useToastStore();
    const perm = CRIT_PERMS.find(p => p.tool === tool && p.action === action);
    const displayName = perm ? t(perm.labelKey) : tool;
    try {
      await demoteCriticalPermission(tool, action);
      permissions.value.set(critKey(tool, action), { state: 'deny', pendingAt: null });
      permissions.value = new Map(permissions.value);
      toasts.add('success', t('toast.criticalPermissions.disabled', { permission: displayName }));
    } catch (e) {
      toasts.add('error', t('toast.criticalPermissions.disableFailed.title'));
    }
  }

  /**
   * On an "on" (confirm, not pending) row, demotes it; on a pending row
   * still inside the cooldown, cancels the pending promotion; otherwise
   * opens the password re-auth prompt and makes no request.
   */
  async function toggle(tool: string, action: string, now: number = Date.now()) {
    const row = getState(tool, action);
    const pending = row.pendingAt !== null && now - row.pendingAt < COOLDOWN_SEC * 1000;
    if (pending) {
      await cancelPending(tool, action);
    } else if (row.state === 'confirm') {
      await demote(tool, action);
    } else {
      reauthTarget.value = { tool, action };
      reauthError.value = null;
    }
  }

  /** Confirms the open re-auth prompt with `password`. A no-op when no prompt is open. Never throws. */
  async function confirmReauth(password: string): Promise<void> {
    const target = reauthTarget.value;
    if (!target) return;

    reauthBusy.value = true;
    try {
      await promote(target.tool, target.action, password);
      reauthTarget.value = null;
      reauthError.value = null;
    } catch (e) {
      reauthError.value =
        e instanceof ApiError && e.status === 403
          ? t('reauth.error.wrongPassword' as MessageKey)
          : t('reauth.error.failed' as MessageKey);
    } finally {
      reauthBusy.value = false;
    }
  }

  /** Closes the re-auth prompt without a request. */
  function cancelReauth(): void {
    reauthTarget.value = null;
    reauthError.value = null;
  }

  return {
    permissions,
    loading,
    error,
    reauthTarget,
    reauthError,
    reauthBusy,
    getState,
    load,
    promote,
    cancelPending,
    demote,
    toggle,
    confirmReauth,
    cancelReauth,
  };
});
