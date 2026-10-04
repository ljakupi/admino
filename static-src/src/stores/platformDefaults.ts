/**
 * Platform defaults store (issue #168: Platform console UI, Defaults tab;
 * routes from #160, residency confirmation from #242).
 *
 * Holds the stored platform settings and an editable draft of the editable
 * fields. `save()` validates, sends only the changed fields and, when the
 * change switches to a non-Swiss provider, first asks for a residency
 * confirmation naming how many organizations are affected
 * (`confirmResidency()` then sends `confirm_residency_orgs`). When the server
 * refuses with a 409 `residency_confirmation` (the count changed meanwhile) the
 * settings are reloaded and the dialog stays open with the new count, rebasing
 * the admin's own edits onto the fresh settings.
 *
 * Security notes: nothing here logs; read-only fields never enter the patch;
 * every message comes from the i18n catalogs via `platformErrorMessage`.
 * No action throws.
 */
import { defineStore } from 'pinia';
import { computed, ref } from 'vue';
import { getPlatformSettings, patchPlatformSettings } from '@/api/platform';
import { ApiError } from '@/api/client';
import { t } from '@/i18n';
import {
  buildDefaultsPatch,
  applyPatch,
  draftFrom,
  validateDraft,
  type DefaultsDraft,
} from '@/services/platformDefaults';
import { needsResidencyConfirmation } from '@/services/platformModel';
import { platformErrorMessage } from '@/services/platformOrgs';
import { useToastStore } from '@/stores/toasts';
import type { PlatformSettings, PlatformSettingsPatch } from '@/api/types';

export const usePlatformDefaultsStore = defineStore('platformDefaults', () => {
  const settings = ref<PlatformSettings | null>(null);
  const draft = ref<DefaultsDraft | null>(null);
  const loading = ref(false);
  const loaded = ref(false);
  const loadError = ref<string | null>(null);
  const saving = ref(false);
  const saveError = ref<string | null>(null);
  const fieldErrors = ref<Record<string, string>>({});
  const residencyConfirm = ref<{ count: number } | null>(null);

  const dirty = computed(
    () =>
      settings.value !== null &&
      draft.value !== null &&
      buildDefaultsPatch(settings.value, draft.value) !== null,
  );

  const residencyConfirmText = computed(() => {
    if (residencyConfirm.value === null) return null;
    const params = { count: residencyConfirm.value.count };
    return {
      title: t('platform.defaults.residencyConfirm.title', params),
      body: t('platform.defaults.residencyConfirm.body', params),
      confirm: t('platform.defaults.residencyConfirm.confirm', params),
    };
  });

  function apply(next: PlatformSettings): void {
    settings.value = next;
    draft.value = draftFrom(next);
  }

  async function load(): Promise<void> {
    loading.value = true;
    try {
      apply(await getPlatformSettings());
      loaded.value = true;
      loadError.value = null;
    } catch (e) {
      loadError.value = platformErrorMessage(e, 'settings');
    } finally {
      loading.value = false;
    }
  }

  function reset(): void {
    if (settings.value !== null) draft.value = draftFrom(settings.value);
    fieldErrors.value = {};
    saveError.value = null;
  }

  async function send(patch: PlatformSettingsPatch): Promise<boolean> {
    saving.value = true;
    saveError.value = null;
    try {
      apply(await patchPlatformSettings(patch));
      residencyConfirm.value = null;
      useToastStore().add('success', t('platform.toast.defaultsSaved'));
      return true;
    } catch (e) {
      if (
        residencyConfirm.value !== null &&
        e instanceof ApiError &&
        e.status === 409 &&
        e.reason === 'residency_confirmation'
      ) {
        await reloadForConfirmation();
      } else {
        residencyConfirm.value = null;
        saveError.value = platformErrorMessage(e, 'settings');
      }
      return false;
    } finally {
      saving.value = false;
    }
  }

  /** Reloads the settings after a stale-count refusal; the admin's own edits are rebased onto the fresh settings and the dialog shows the new count. */
  async function reloadForConfirmation(): Promise<void> {
    try {
      const fresh = await getPlatformSettings();
      // Rebase: keep only the admin's own edits, so a field another admin changed meanwhile isn't reverted.
      const own = settings.value !== null && draft.value !== null ? buildDefaultsPatch(settings.value, draft.value) : null;
      settings.value = fresh;
      draft.value = applyPatch(draftFrom(fresh), own);
      residencyConfirm.value = { count: fresh.llm.residency_orgs };
    } catch (e) {
      residencyConfirm.value = null;
      saveError.value = platformErrorMessage(e, 'settings');
    }
  }

  async function save(): Promise<boolean> {
    const stored = settings.value;
    const current = draft.value;
    if (stored === null || current === null || saving.value) return false;

    fieldErrors.value = validateDraft(current, stored);
    if (Object.keys(fieldErrors.value).length > 0) return false;

    const patch = buildDefaultsPatch(stored, current);
    if (patch === null) return true;

    const nextProvider = patch.llm?.provider;
    if (nextProvider !== undefined && needsResidencyConfirmation(stored.llm.provider, nextProvider)) {
      residencyConfirm.value = { count: stored.llm.residency_orgs };
      return false;
    }

    return send(patch);
  }

  async function confirmResidency(): Promise<boolean> {
    const confirm = residencyConfirm.value;
    const stored = settings.value;
    const current = draft.value;
    if (confirm === null || stored === null || current === null || saving.value) return false;

    const patch = buildDefaultsPatch(stored, current);
    return send({ ...patch, confirm_residency_orgs: confirm.count });
  }

  function cancelResidency(): void {
    residencyConfirm.value = null;
  }

  return {
    settings,
    draft,
    loading,
    loaded,
    loadError,
    saving,
    saveError,
    fieldErrors,
    residencyConfirm,
    dirty,
    residencyConfirmText,
    load,
    reset,
    save,
    confirmResidency,
    cancelResidency,
  };
});
