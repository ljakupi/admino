/**
 * Platform organizations store (issue #168: Platform console UI, Organizations
 * tab; routes from #154).
 *
 * Owns the Super Admin's organization list (`load()`), the create sheet, the
 * edit-limits sheet and one confirm sheet shared by every org status action
 * (`request*` opens it only when `orgActions` allows the action and never
 * calls the API; `confirmPending()` makes exactly one call; `cancelPending()`
 * closes it without one).
 *
 * Security notes: only `/api/platform/*` metadata is held; nothing here logs
 * and every user-facing message comes from the i18n catalogs via
 * `platformErrorMessage` (a backend `detail` is never shown). No action
 * throws: failures are recorded as translated `loadError` / `createError` /
 * `limitsError` / `actionError`.
 */
import { defineStore } from 'pinia';
import { computed, ref } from 'vue';
import {
  cancelPlatformOrgDeletion,
  createPlatformOrg,
  deactivatePlatformOrg,
  listPlatformOrgs,
  reactivatePlatformOrg,
  schedulePlatformOrgDeletion,
  setPlatformOrgResidency,
  updatePlatformOrgLimits,
} from '@/api/platform';
import { t, type MessageKey } from '@/i18n';
import {
  buildCreateOrgRequest,
  buildLimitsPatch,
  orgActions,
  orgConfirmCopy,
  platformErrorMessage,
  type FormErrors,
  type OrgAction,
  type OrgConfirmKind,
  type OrgCreateInput,
  type OrgLimitsInput,
} from '@/services/platformOrgs';
import type { ConfirmCopy } from '@/services/orgUsers';
import { useToastStore } from '@/stores/toasts';
import type { PlatformOrg } from '@/api/types';

export interface PendingOrgAction {
  kind: OrgConfirmKind;
  orgId: string;
}

const TOAST_KEYS: Record<OrgConfirmKind, MessageKey> = {
  deactivate: 'platform.toast.orgDeactivated',
  reactivate: 'platform.toast.orgReactivated',
  scheduleDeletion: 'platform.toast.deletionScheduled',
  cancelDeletion: 'platform.toast.deletionCancelled',
  residencyOn: 'platform.toast.residencyOn',
  residencyOff: 'platform.toast.residencyOff',
};

export const usePlatformOrgsStore = defineStore('platformOrgs', () => {
  const orgs = ref<PlatformOrg[]>([]);
  const loading = ref(false);
  const loaded = ref(false);
  const loadError = ref<string | null>(null);

  const createOpen = ref(false);
  const createBusy = ref(false);
  const createErrors = ref<FormErrors>({});
  const createError = ref<string | null>(null);

  const limitsOrgId = ref<string | null>(null);
  const limitsBusy = ref(false);
  const limitsErrors = ref<FormErrors>({});
  const limitsError = ref<string | null>(null);

  const pending = ref<PendingOrgAction | null>(null);
  const actionBusy = ref(false);
  const actionError = ref<string | null>(null);

  const limitsOrg = computed(() => findOrg(limitsOrgId.value));
  const pendingCopy = computed<ConfirmCopy | null>(() => {
    if (pending.value === null) return null;
    const org = findOrg(pending.value.orgId);
    return org === null ? null : orgConfirmCopy(pending.value.kind, org.name);
  });

  function findOrg(orgId: string | null): PlatformOrg | null {
    if (orgId === null) return null;
    return orgs.value.find((org) => org.id === orgId) ?? null;
  }

  function replaceOrg(updated: PlatformOrg): void {
    orgs.value = orgs.value.map((org) => (org.id === updated.id ? updated : org));
  }

  function allowed(orgId: string, action: OrgAction): PlatformOrg | null {
    const org = findOrg(orgId);
    return org !== null && orgActions(org).includes(action) ? org : null;
  }

  // --- Load ----------------------------------------------------------------------

  async function load(): Promise<void> {
    loading.value = true;
    try {
      const response = await listPlatformOrgs();
      orgs.value = response.organizations;
      loaded.value = true;
      loadError.value = null;
    } catch (e) {
      loadError.value = platformErrorMessage(e, 'org');
    } finally {
      loading.value = false;
    }
  }

  // --- Create sheet ----------------------------------------------------------------

  function openCreate(): void {
    createOpen.value = true;
    createErrors.value = {};
    createError.value = null;
  }

  function closeCreate(): void {
    createOpen.value = false;
    createErrors.value = {};
    createError.value = null;
  }

  async function submitCreate(input: OrgCreateInput): Promise<boolean> {
    if (createBusy.value) return false;
    const result = buildCreateOrgRequest(input);
    if (!result.ok) {
      createErrors.value = result.errors;
      return false;
    }
    createErrors.value = {};
    createError.value = null;

    createBusy.value = true;
    try {
      const created = await createPlatformOrg(result.value);
      orgs.value = [...orgs.value, created.organization];
      closeCreate();
      useToastStore().add('success', t('platform.toast.orgCreated'));
      return true;
    } catch (e) {
      createError.value = platformErrorMessage(e, 'org');
      return false;
    } finally {
      createBusy.value = false;
    }
  }

  // --- Limits sheet -----------------------------------------------------------------

  function openLimits(orgId: string): void {
    if (allowed(orgId, 'editLimits') === null) return;
    limitsOrgId.value = orgId;
    limitsErrors.value = {};
    limitsError.value = null;
  }

  function closeLimits(): void {
    limitsOrgId.value = null;
    limitsErrors.value = {};
    limitsError.value = null;
  }

  async function submitLimits(input: OrgLimitsInput): Promise<boolean> {
    const org = limitsOrg.value;
    if (org === null || limitsBusy.value) return false;

    const result = buildLimitsPatch(org, input);
    if (!result.ok) {
      limitsErrors.value = result.errors;
      return false;
    }
    limitsErrors.value = {};
    limitsError.value = null;
    if (result.value === null) {
      closeLimits();
      return true;
    }

    limitsBusy.value = true;
    try {
      replaceOrg(await updatePlatformOrgLimits(org.id, result.value));
      closeLimits();
      useToastStore().add('success', t('platform.toast.limitsSaved'));
      return true;
    } catch (e) {
      limitsError.value = platformErrorMessage(e, 'org');
      return false;
    } finally {
      limitsBusy.value = false;
    }
  }

  // --- Confirm sheet ------------------------------------------------------------------

  function open(kind: OrgConfirmKind, orgId: string): void {
    pending.value = { kind, orgId };
    actionError.value = null;
  }

  function requestDeactivate(orgId: string): void {
    if (allowed(orgId, 'deactivate') !== null) open('deactivate', orgId);
  }

  function requestReactivate(orgId: string): void {
    if (allowed(orgId, 'reactivate') !== null) open('reactivate', orgId);
  }

  function requestScheduleDeletion(orgId: string): void {
    if (allowed(orgId, 'scheduleDeletion') !== null) open('scheduleDeletion', orgId);
  }

  function requestCancelDeletion(orgId: string): void {
    if (allowed(orgId, 'cancelDeletion') !== null) open('cancelDeletion', orgId);
  }

  function requestResidency(orgId: string, enabled: boolean): void {
    const org = allowed(orgId, 'residency');
    if (org === null || enabled === org.data_residency) return;
    open(enabled ? 'residencyOn' : 'residencyOff', orgId);
  }

  function cancelPending(): void {
    pending.value = null;
    actionError.value = null;
  }

  function send(action: PendingOrgAction): Promise<PlatformOrg> {
    switch (action.kind) {
      case 'deactivate':
        return deactivatePlatformOrg(action.orgId);
      case 'reactivate':
        return reactivatePlatformOrg(action.orgId);
      case 'scheduleDeletion':
        return schedulePlatformOrgDeletion(action.orgId);
      case 'cancelDeletion':
        return cancelPlatformOrgDeletion(action.orgId);
      case 'residencyOn':
        return setPlatformOrgResidency(action.orgId, true);
      case 'residencyOff':
        return setPlatformOrgResidency(action.orgId, false);
    }
  }

  async function confirmPending(): Promise<boolean> {
    const action = pending.value;
    if (action === null || actionBusy.value) return false;

    actionBusy.value = true;
    actionError.value = null;
    try {
      replaceOrg(await send(action));
      pending.value = null;
      useToastStore().add('success', t(TOAST_KEYS[action.kind]));
      return true;
    } catch (e) {
      actionError.value = platformErrorMessage(e, 'org');
      return false;
    } finally {
      actionBusy.value = false;
    }
  }

  return {
    orgs,
    loading,
    loaded,
    loadError,
    createOpen,
    createBusy,
    createErrors,
    createError,
    limitsOrgId,
    limitsBusy,
    limitsErrors,
    limitsError,
    pending,
    actionBusy,
    actionError,
    limitsOrg,
    pendingCopy,
    load,
    openCreate,
    closeCreate,
    submitCreate,
    openLimits,
    closeLimits,
    submitLimits,
    requestDeactivate,
    requestReactivate,
    requestScheduleDeletion,
    requestCancelDeletion,
    requestResidency,
    cancelPending,
    confirmPending,
  };
});
