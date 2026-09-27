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

export const useCriticalPermissionsStore = defineStore('criticalPermissions', () => {
  const permissions = ref<Map<string, PermState>>(new Map());
  const loading = ref(false);
  const error = ref<string | null>(null);

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

  async function promote(tool: string, action: string) {
    const toasts = useToastStore();
    try {
      const res = await promoteCriticalPermission(tool, action);
      permissions.value.set(critKey(tool, action), {
        state: res.state,
        pendingAt: res.pending_at ? new Date(res.pending_at).getTime() : null,
      });
      // Force reactivity
      permissions.value = new Map(permissions.value);
      toasts.add(
        'success',
        t('toast.criticalPermissions.promotionScheduled.title'),
        t('toast.criticalPermissions.promotionScheduled.body', { time: formatCooldown(COOLDOWN_SEC) }),
      );
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

  return {
    permissions,
    loading,
    error,
    getState,
    load,
    promote,
    cancelPending,
    demote,
  };
});
