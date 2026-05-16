import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { getPermissions, patchPermission } from '@/api/permissions';
import { useToastStore } from '@/stores/toasts';
import type { PermissionEntry, PermissionState } from '@/api/types';

// Must mirror HARDCODED_DENIALS in src/admino/permissions.py exactly.
// This is a UI-only display hint — backend enforces the real constraint.
// When adding a new hardcoded denial to permissions.py, update this set too.
const HARDCODED_DENIALS = new Set([
  'gmail.send', 'gmail.delete',
  'google_calendar.delete', 'google_calendar.update',
  'google_drive.delete',
  'outlook.send', 'outlook.delete',
  'outlook_calendar.delete', 'outlook_calendar.update',
  'onedrive.delete',
  'documents.delete',
  'files.delete', 'files.overwrite',
  'memory.delete',
]);

const TOOL_META: Record<string, { label: string; description: string; actions: Record<string, string> }> = {
  gmail: {
    label: 'Gmail',
    description: 'Read, search, and send from your inbox',
    actions: {
      read: 'Read a message body',
      list: 'List messages in inbox',
      search: 'Find messages by query',
      send: 'Send an email on your behalf',
      delete: 'Permanently delete a thread',
    },
  },
  google_calendar: {
    label: 'Google Calendar',
    description: 'Read events, create with approval',
    actions: {
      read: 'View event details',
      list: 'List upcoming events',
      create: 'Create a new event',
      update: 'Modify an existing event',
      delete: 'Remove an event',
    },
  },
  google_drive: {
    label: 'Google Drive',
    description: 'Search and download your Drive files',
    actions: {
      read: 'Read file contents',
      list: 'List files and folders',
      search: 'Search for files',
      download: 'Download a file',
      delete: 'Delete a file',
    },
  },
  outlook: {
    label: 'Outlook',
    description: 'Read, search, and send from your mailbox',
    actions: {
      read: 'Read a message body',
      list: 'List messages in inbox',
      search: 'Find messages by query',
      send: 'Send an email on your behalf',
      delete: 'Permanently delete a message',
    },
  },
  outlook_calendar: {
    label: 'Outlook Calendar',
    description: 'Read events, create with approval',
    actions: {
      read: 'View event details',
      list: 'List upcoming events',
      create: 'Create a new event',
      update: 'Modify an existing event',
      delete: 'Remove an event',
    },
  },
  onedrive: {
    label: 'OneDrive',
    description: 'Search and download your OneDrive files',
    actions: {
      read: 'Read file contents',
      list: 'List files and folders',
      search: 'Search for files',
      download: 'Download a file',
      delete: 'Delete a file',
    },
  },
  documents: {
    label: 'Documents',
    description: 'Private document store, scanned & indexed',
    actions: {
      store: 'Store a new document',
      classify: 'Auto-classify a document',
      search: 'Search stored documents',
      query: 'Query document contents',
      delete: 'Delete a document',
    },
  },
  web_search: {
    label: 'Web Search',
    description: 'Search the web for information',
    actions: {
      search: 'Run a web search query',
    },
  },
  files: {
    label: 'Files',
    description: 'Local files under ~/Downloads/admino',
    actions: {
      read: 'Read file contents',
      list: 'List files in directory',
      search: 'Search for files',
      write: 'Write a new file',
      move: 'Move or rename a file',
      delete: 'Delete a file',
      overwrite: 'Overwrite an existing file',
    },
  },
  memory: {
    label: 'Memory',
    description: 'Long-term key-value store',
    actions: {
      get: 'Retrieve a stored value',
      set: 'Store a key-value pair',
      list: 'List all stored keys',
      delete: 'Delete a stored key',
    },
  },
  database: {
    label: 'Database',
    description: 'Application database access',
    actions: {
      query: 'Run a read-only query',
    },
  },
};

export const usePermissionsStore = defineStore('permissions', () => {
  const permissions = ref<PermissionEntry[]>([]);
  const loading = ref(false);
  const error = ref<string | null>(null);
  const savingKey = ref<string | null>(null);

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

  function getToolMeta(tool: string): { label: string; description: string; actions: Record<string, string> } {
    return TOOL_META[tool] ?? { label: tool, description: '', actions: {} };
  }

  function getActionDescription(tool: string, action: string): string {
    return TOOL_META[tool]?.actions[action] ?? '';
  }

  async function loadPermissions() {
    loading.value = true;
    error.value = null;
    try {
      const data = await getPermissions();
      permissions.value = data.permissions;
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Failed to load permissions';
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
      toasts.add('success', 'Saved');
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to save permission';
      toasts.add('error', 'Save failed', msg);
    } finally {
      savingKey.value = null;
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
    getToolMeta,
    getActionDescription,
    loadPermissions,
    updatePermission,
  };
});
