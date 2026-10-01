import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { getPermissions, getPermissionsSummary, patchPermission } from '@/api/permissions';
import { useToastStore } from '@/stores/toasts';
import { t } from '@/i18n';
import type { MessageKey } from '@/i18n';
import type { PermissionEntry, PermissionState, PermissionSummaryEntry } from '@/api/types';

// Tier-1: truly immutable denials — cannot be overridden by any config.
// Must mirror HARDCODED_DENIALS in src/admino/permissions.py (minus promotable entries).
const HARDCODED_DENIALS = new Set([
  'gmail.delete',
  'google_calendar.delete',
  'google_drive.delete',
  'outlook.delete',
  'outlook_calendar.delete',
  'onedrive.delete',
  'documents.delete',
  'memory.delete',
]);

// Tier-2: promotable via Settings > Danger Zone (deny → confirm with cooldown).
// Must mirror PROMOTABLE_DENIALS in src/admino/permissions.py.
export const PROMOTABLE_DENIALS = new Set([
  'gmail.send',
  'outlook.send',
  'google_calendar.update',
  'outlook_calendar.update',
]);

interface ToolMetaKeys {
  labelKey: MessageKey;
  descriptionKey: MessageKey;
  actions: Record<string, MessageKey>;
}

// Catalog keys for each known tool's label, description and per-action
// description (issue #144): resolved with `t()` in `getToolMeta` /
// `getActionDescription` so they follow the active locale.
const TOOL_META: Record<string, ToolMetaKeys> = {
  gmail: {
    labelKey: 'tools.gmail.label',
    descriptionKey: 'tools.gmail.description',
    actions: {
      read: 'tools.gmail.actions.read',
      list: 'tools.gmail.actions.list',
      search: 'tools.gmail.actions.search',
      send: 'tools.gmail.actions.send',
      delete: 'tools.gmail.actions.delete',
    },
  },
  google_calendar: {
    labelKey: 'tools.googleCalendar.label',
    descriptionKey: 'tools.googleCalendar.description',
    actions: {
      read: 'tools.googleCalendar.actions.read',
      list: 'tools.googleCalendar.actions.list',
      create: 'tools.googleCalendar.actions.create',
      update: 'tools.googleCalendar.actions.update',
      delete: 'tools.googleCalendar.actions.delete',
    },
  },
  google_drive: {
    labelKey: 'tools.googleDrive.label',
    descriptionKey: 'tools.googleDrive.description',
    actions: {
      read: 'tools.googleDrive.actions.read',
      list: 'tools.googleDrive.actions.list',
      search: 'tools.googleDrive.actions.search',
      download: 'tools.googleDrive.actions.download',
      delete: 'tools.googleDrive.actions.delete',
    },
  },
  outlook: {
    labelKey: 'tools.outlook.label',
    descriptionKey: 'tools.outlook.description',
    actions: {
      read: 'tools.outlook.actions.read',
      list: 'tools.outlook.actions.list',
      search: 'tools.outlook.actions.search',
      send: 'tools.outlook.actions.send',
      delete: 'tools.outlook.actions.delete',
    },
  },
  outlook_calendar: {
    labelKey: 'tools.outlookCalendar.label',
    descriptionKey: 'tools.outlookCalendar.description',
    actions: {
      read: 'tools.outlookCalendar.actions.read',
      list: 'tools.outlookCalendar.actions.list',
      create: 'tools.outlookCalendar.actions.create',
      update: 'tools.outlookCalendar.actions.update',
      delete: 'tools.outlookCalendar.actions.delete',
    },
  },
  onedrive: {
    labelKey: 'tools.onedrive.label',
    descriptionKey: 'tools.onedrive.description',
    actions: {
      read: 'tools.onedrive.actions.read',
      list: 'tools.onedrive.actions.list',
      search: 'tools.onedrive.actions.search',
      download: 'tools.onedrive.actions.download',
      delete: 'tools.onedrive.actions.delete',
    },
  },
  memory: {
    labelKey: 'tools.memory.label',
    descriptionKey: 'tools.memory.description',
    actions: {
      get: 'tools.memory.actions.get',
      set: 'tools.memory.actions.set',
      list: 'tools.memory.actions.list',
      delete: 'tools.memory.actions.delete',
    },
  },
  database: {
    labelKey: 'tools.database.label',
    descriptionKey: 'tools.database.description',
    actions: {
      query: 'tools.database.actions.query',
    },
  },
};

export const usePermissionsStore = defineStore('permissions', () => {
  const permissions = ref<PermissionEntry[]>([]);
  const loading = ref(false);
  const error = ref<string | null>(null);
  const savingKey = ref<string | null>(null);

  // Read-only summary (issue #161): every member role (Org Admin, Editor,
  // Viewer) sees the org's effective permission states through this,
  // independent of `permissions`/`loadPermissions` (the editable matrix,
  // Org Admin only).
  const summary = ref<PermissionSummaryEntry[]>([]);
  const summaryLoading = ref(false);
  const summaryError = ref<string | null>(null);

  const summaryGroups = computed(() => {
    const map = new Map<string, PermissionSummaryEntry[]>();
    for (const entry of summary.value) {
      const group = map.get(entry.tool) ?? [];
      group.push(entry);
      map.set(entry.tool, group);
    }
    return map;
  });

  const toolGroups = computed(() => {
    const map = new Map<string, PermissionEntry[]>();
    for (const entry of permissions.value) {
      const group = map.get(entry.tool) ?? [];
      group.push(entry);
      map.set(entry.tool, group);
    }
    return map;
  });

  const statusCounts = computed(() => {
    let allow = 0;
    let confirm = 0;
    let deny = 0;
    for (const entry of permissions.value) {
      if (entry.permission === 'allow') allow++;
      else if (entry.permission === 'confirm') confirm++;
      else if (entry.permission === 'deny') deny++;
    }
    return { all: permissions.value.length, allow, confirm, deny };
  });

  function toolSummary(tool: string): { allow: number; confirm: number; deny: number } {
    const entries = toolGroups.value.get(tool) ?? [];
    let allow = 0;
    let confirm = 0;
    let deny = 0;
    for (const entry of entries) {
      if (entry.permission === 'allow') allow++;
      else if (entry.permission === 'confirm') confirm++;
      else if (entry.permission === 'deny') deny++;
    }
    return { allow, confirm, deny };
  }

  function isHardcoded(tool: string, action: string): boolean {
    return HARDCODED_DENIALS.has(`${tool}.${action}`);
  }

  function isPromotable(tool: string, action: string): boolean {
    return PROMOTABLE_DENIALS.has(`${tool}.${action}`);
  }

  // Tool/action names come from the server's permission table: look them up
  // as own keys only, so a name like `constructor` never hits Object.prototype.
  function toolMetaKeys(tool: string): ToolMetaKeys | undefined {
    return Object.hasOwn(TOOL_META, tool) ? TOOL_META[tool] : undefined;
  }

  function getToolMeta(tool: string): { label: string; description: string; actions: Record<string, string> } {
    const meta = toolMetaKeys(tool);
    if (!meta) return { label: tool, description: '', actions: {} };
    return {
      label: t(meta.labelKey),
      description: t(meta.descriptionKey),
      actions: Object.fromEntries(Object.entries(meta.actions).map(([action, key]) => [action, t(key)])),
    };
  }

  function getActionDescription(tool: string, action: string): string {
    const actions = toolMetaKeys(tool)?.actions;
    return actions && Object.hasOwn(actions, action) ? t(actions[action]) : '';
  }

  async function loadPermissions() {
    loading.value = true;
    error.value = null;
    try {
      const data = await getPermissions();
      permissions.value = data.permissions;
    } catch (e) {
      error.value = e instanceof Error ? e.message : t('permissions.error.loadFailed');
    } finally {
      loading.value = false;
    }
  }

  async function updatePermission(tool: string, action: string, permission: PermissionState) {
    const toasts = useToastStore();
    savingKey.value = `${tool}.${action}`;
    try {
      const data = await patchPermission({ tool, action, permission });
      permissions.value = data.permissions;
      toasts.add('success', t('toast.common.saved'));
    } catch (e) {
      const msg = e instanceof Error ? e.message : t('permissions.error.saveFailed');
      toasts.add('error', t('toast.common.saveFailed.title'), msg);
    } finally {
      savingKey.value = null;
    }
  }

  async function loadSummary() {
    summaryLoading.value = true;
    summaryError.value = null;
    try {
      const data = await getPermissionsSummary();
      summary.value = data.permissions;
    } catch (e) {
      summaryError.value = e instanceof Error ? e.message : t('permissions.error.loadFailed');
    } finally {
      summaryLoading.value = false;
    }
  }

  return {
    permissions,
    loading,
    error,
    savingKey,
    toolGroups,
    statusCounts,
    toolSummary,
    isHardcoded,
    isPromotable,
    getToolMeta,
    getActionDescription,
    loadPermissions,
    updatePermission,
    summary,
    summaryLoading,
    summaryError,
    summaryGroups,
    loadSummary,
  };
});
