/**
 * Org services store (issue #162: the Org Admin's service switches move from
 * the Tools page to the Organization console).
 *
 * Owns the organization's seven tool switches, which moved out of
 * `stores/settings.ts`: `tools` (the stored switches), `dataResidency` (the
 * org's residency policy) and `loaded`. `isLocked` mirrors
 * `services/connections.ts`'s `isResidencyLocked` so the Google/Microsoft
 * rows are disabled under residency; `memory` is never locked.
 *
 * Security notes: `dataResidency` starts `true` (fail closed) so a slow or
 * failed `load()` never offers the Google/Microsoft switches of a residency
 * org before the server has actually said otherwise.
 */
import { defineStore } from 'pinia';
import { ref } from 'vue';
import { getOrgSettings, patchOrgSettings } from '@/api/settings';
import { isResidencyLocked } from '@/services/connections';
import { useToastStore } from '@/stores/toasts';
import { t } from '@/i18n';
import type { ToolsSettings } from '@/api/types';

const DEFAULT_TOOLS: ToolsSettings = {
  gmail: true,
  google_calendar: true,
  google_drive: true,
  outlook: true,
  outlook_calendar: true,
  onedrive: true,
  memory: true,
};

export const useOrgServicesStore = defineStore('orgServices', () => {
  const tools = ref<ToolsSettings>({ ...DEFAULT_TOOLS });
  const dataResidency = ref(true);
  const loaded = ref(false);

  async function load() {
    try {
      const data = await getOrgSettings();
      tools.value = data.tools;
      dataResidency.value = data.data_residency;
      loaded.value = true;
    } catch {
      // Keep the current (fail-closed) state; the caller may not be an Org Admin.
    }
  }

  function isLocked(tool: keyof ToolsSettings): boolean {
    return isResidencyLocked(tool, dataResidency.value);
  }

  async function setEnabled(tool: keyof ToolsSettings, enabled: boolean) {
    if (isLocked(tool)) return;

    const toasts = useToastStore();
    const previous = tools.value[tool];
    tools.value = { ...tools.value, [tool]: enabled };
    try {
      const data = await patchOrgSettings({ tools: { [tool]: enabled } });
      tools.value = data.tools;
      dataResidency.value = data.data_residency;
      toasts.add('success', t('toast.common.saved'));
    } catch (e) {
      tools.value = { ...tools.value, [tool]: previous };
      const msg = e instanceof Error ? e.message : t('settings.error.saveFailed');
      toasts.add('error', t('toast.common.saveFailed.title'), msg);
    }
  }

  return { tools, dataResidency, loaded, load, isLocked, setEnabled };
});
