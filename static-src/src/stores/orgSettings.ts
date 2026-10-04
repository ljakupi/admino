/**
 * Org settings store (issue #169): the Org Admin's Organization -> Settings
 * page state. Loads the settings, keeps an editable draft, validates and
 * saves only the changed fields. Tool switches live in `orgServices`.
 *
 * Security notes: `dataResidency` fails closed (true) until loaded; backend
 * error text never reaches state or toasts.
 */
import { defineStore } from 'pinia';
import { computed, ref } from 'vue';
import { getOrgSettings, patchOrgSettings } from '@/api/settings';
import { t } from '@/i18n';
import {
  buildOrgSettingsPatch,
  draftFrom,
  instructionsRemaining as remainingFor,
  orgSettingsErrorMessage,
  validateOrgSettingsDraft,
  type OrgSettingsDraft,
  type OrgSettingsIssue,
} from '@/services/orgSettings';
import { useToastStore } from '@/stores/toasts';
import type { OrgSettingsResponse } from '@/api/types';

export const useOrgSettingsStore = defineStore('orgSettings', () => {
  const settings = ref<OrgSettingsResponse | null>(null);
  const draft = ref<OrgSettingsDraft | null>(null);
  const loading = ref(false);
  const loaded = ref(false);
  const loadError = ref<string | null>(null);
  const saving = ref(false);
  const saveError = ref<string | null>(null);
  const issues = ref<OrgSettingsIssue[]>([]);

  const dirty = computed(
    () =>
      settings.value !== null &&
      draft.value !== null &&
      buildOrgSettingsPatch(settings.value, draft.value) !== null,
  );
  const dataResidency = computed(() => settings.value?.data_residency ?? true);
  const instructionsRemaining = computed(() => remainingFor(draft.value?.instructions ?? ''));

  function apply(response: OrgSettingsResponse): void {
    settings.value = response;
    draft.value = draftFrom(response);
  }

  async function load(): Promise<void> {
    loading.value = true;
    try {
      apply(await getOrgSettings());
      loaded.value = true;
      loadError.value = null;
    } catch (e) {
      loadError.value = orgSettingsErrorMessage(e);
    } finally {
      loading.value = false;
    }
  }

  function resetDraft(): void {
    if (settings.value) draft.value = draftFrom(settings.value);
    issues.value = [];
    saveError.value = null;
  }

  async function save(): Promise<boolean> {
    if (saving.value || !settings.value || !draft.value) return false;
    const found = validateOrgSettingsDraft(draft.value, settings.value);
    issues.value = found;
    if (found.length > 0) return false;
    const patch = buildOrgSettingsPatch(settings.value, draft.value);
    if (patch === null) return true;
    saving.value = true;
    try {
      apply(await patchOrgSettings(patch));
      saveError.value = null;
      useToastStore().add('success', t('toast.common.saved'));
      return true;
    } catch (e) {
      saveError.value = orgSettingsErrorMessage(e);
      useToastStore().add('error', saveError.value);
      return false;
    } finally {
      saving.value = false;
    }
  }

  return {
    settings,
    draft,
    loading,
    loaded,
    loadError,
    saving,
    saveError,
    issues,
    dirty,
    dataResidency,
    instructionsRemaining,
    load,
    resetDraft,
    save,
  };
});
