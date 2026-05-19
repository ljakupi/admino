import { defineStore } from 'pinia';
import { ref } from 'vue';
import {
  getCriticalPermissions,
  promoteCriticalPermission,
  demoteCriticalPermission,
  cancelPendingPromotion,
} from '@/api/critical-permissions';
import { useToastStore } from '@/stores/toasts';
import { ApiError } from '@/api/client';

export interface CritPermDef {
  tool: string;
  action: string;
  icon: string;
  label: string;
  description: string;
}

export const CRIT_PERMS: CritPermDef[] = [
  {
    tool: 'gmail', action: 'send',
    icon: 'mail', label: 'Send email \u00b7 Gmail',
    description: 'When enabled, the agent can draft emails and ask for your approval before sending.',
  },
  {
    tool: 'outlook', action: 'send',
    icon: 'mail', label: 'Send email \u00b7 Outlook',
    description: 'When enabled, the agent can draft emails and ask for your approval before sending.',
  },
  {
    tool: 'google_calendar', action: 'update',
    icon: 'calendar', label: 'Update event \u00b7 Google Calendar',
    description: 'When enabled, the agent can propose changes to existing events for your approval.',
  },
  {
    tool: 'outlook_calendar', action: 'update',
    icon: 'calendar', label: 'Update event \u00b7 Outlook Calendar',
    description: 'When enabled, the agent can propose changes to existing events for your approval.',
  },
];

export const COOLDOWN_SEC = 300;

function critKey(tool: string, action: string): string {
  return `${tool}.${action}`;
}

interface PermState {
  state: 'deny' | 'confirm';
  pendingAt: number | null;
}

export const useCriticalPermissionsStore = defineStore('criticalPermissions', () => {
  const permissions = ref<Map<string, PermState>>(new Map());
  const loading = ref(false);
  const error = ref<string | null>(null);
  const authRow = ref<CritPermDef | null>(null);

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
      error.value = e instanceof Error ? e.message : 'Failed to load critical permissions';
    } finally {
      loading.value = false;
    }
  }

  async function promote(tool: string, action: string, bearerToken: string) {
    const toasts = useToastStore();
    try {
      const res = await promoteCriticalPermission(tool, action, bearerToken);
      permissions.value.set(critKey(tool, action), {
        state: res.state,
        pendingAt: res.pending_at ? new Date(res.pending_at).getTime() : null,
      });
      // Force reactivity
      permissions.value = new Map(permissions.value);
      toasts.add('success', 'Promotion scheduled', 'Active in 5:00');
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        toasts.add('error', 'Authentication failed', 'The token you entered is invalid.');
      } else {
        toasts.add('error', 'Promotion failed');
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
      toasts.add('success', 'Pending promotion cancelled');
    } catch (e) {
      toasts.add('error', 'Cancel failed');
    }
  }

  async function demote(tool: string, action: string) {
    const toasts = useToastStore();
    const perm = CRIT_PERMS.find(p => p.tool === tool && p.action === action);
    const displayName = perm?.label ?? 'permission';
    try {
      await demoteCriticalPermission(tool, action);
      permissions.value.set(critKey(tool, action), { state: 'deny', pendingAt: null });
      permissions.value = new Map(permissions.value);
      toasts.add('success', `Disabled: ${displayName}`);
    } catch (e) {
      toasts.add('error', 'Disable failed');
    }
  }

  function openAuth(row: CritPermDef) {
    authRow.value = row;
  }

  function closeAuth() {
    authRow.value = null;
  }

  return {
    permissions,
    loading,
    error,
    authRow,
    getState,
    load,
    promote,
    cancelPending,
    demote,
    openAuth,
    closeAuth,
  };
});
