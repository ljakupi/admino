/**
 * Platform organizations store tests (issue #168: Platform console UI, Super
 * Admin; backend routes from #154).
 *
 * `usePlatformOrgsStore` (Pinia id 'platformOrgs', setup style) owns the
 * Organizations tab of the Platform area, the only area a Super Admin sees:
 * every organization with its status, seats and residency (no budget column
 * in V1), the create sheet, the edit-limits sheet and one confirm sheet for
 * deactivate / reactivate / schedule or cancel deletion / residency on or off.
 *
 * - `load()`: `GET /api/platform/orgs`. Success replaces the list (API order
 *   kept); failure keeps the previous list and sets a translated `loadError`.
 * - Create: `submitCreate(input)` validates every field client-side (no
 *   request when anything is invalid), then posts exactly the five API
 *   fields; the new org is appended, the sheet closes, a success toast shows.
 *   A refusal (409 `email_taken`) keeps the sheet open with a translated
 *   `createError`. A second submit while one is in flight makes no request.
 * - Edit limits: only for orgs whose status allows it (never while a deletion
 *   is pending); only the changed limits are sent; nothing changed closes the
 *   sheet without a request; the response replaces the org.
 * - Confirm flows: every `request*` only opens `pending` (never a request),
 *   and only when the org's status allows that action (residency only towards
 *   the other value); `cancelPending()` makes no request; `confirmPending()`
 *   makes exactly one request, replaces the org with the response, closes and
 *   toasts; a failure keeps `pending` with a translated `actionError`.
 *   `pendingCopy` is the confirm copy naming the org.
 *
 * Security notes (#139 §5): operator blindness, every request goes through
 * `@/api/platform` (mocked here; `fetch` is stubbed and must never be called,
 * so no other API module is used); a backend error's `detail` is never shown,
 * every message comes from the i18n catalogs (compared with `t(...)` after
 * checking the English catalog has the key); nothing names an org, a person
 * or an email in the console. The real toasts store is used. No component is
 * mounted and nothing touches the network.
 */
import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import {
  cancelPlatformOrgDeletion,
  createPlatformOrg,
  deactivatePlatformOrg,
  deactivatePlatformUser,
  getPlatformOrgMetadata,
  getPlatformSettings,
  listPlatformOrgs,
  listPlatformOrgUsers,
  patchPlatformSettings,
  reactivatePlatformOrg,
  reactivatePlatformUser,
  reinvitePlatformUser,
  resetPlatformUserPassword,
  schedulePlatformOrgDeletion,
  setPlatformOrgResidency,
  updatePlatformOrgLimits,
} from '@/api/platform';
import { ApiError } from '@/api/client';
import { setLocale, t, type MessageKey, type Params } from '@/i18n';
import { en } from '@/i18n/locales/en';
import { usePlatformOrgsStore } from '@/stores/platformOrgs';
import { useToastStore } from '@/stores/toasts';
import type { OrgConfirmKind, OrgCreateInput, OrgFormField, OrgLimitsInput } from '@/services/platformOrgs';
import type { PlatformOrg, PlatformOrgCreateResponse, PlatformOrgLimitsPatch, PlatformOrgListResponse } from '@/api/types';

vi.mock('@/api/platform', () => ({
  listPlatformOrgs: vi.fn(),
  createPlatformOrg: vi.fn(),
  updatePlatformOrgLimits: vi.fn(),
  deactivatePlatformOrg: vi.fn(),
  reactivatePlatformOrg: vi.fn(),
  schedulePlatformOrgDeletion: vi.fn(),
  cancelPlatformOrgDeletion: vi.fn(),
  setPlatformOrgResidency: vi.fn(),
  listPlatformOrgUsers: vi.fn(),
  getPlatformOrgMetadata: vi.fn(),
  deactivatePlatformUser: vi.fn(),
  reactivatePlatformUser: vi.fn(),
  resetPlatformUserPassword: vi.fn(),
  reinvitePlatformUser: vi.fn(),
  getPlatformSettings: vi.fn(),
  patchPlatformSettings: vi.fn(),
}));

const api = {
  listPlatformOrgs: vi.mocked(listPlatformOrgs),
  createPlatformOrg: vi.mocked(createPlatformOrg),
  updatePlatformOrgLimits: vi.mocked(updatePlatformOrgLimits),
  deactivatePlatformOrg: vi.mocked(deactivatePlatformOrg),
  reactivatePlatformOrg: vi.mocked(reactivatePlatformOrg),
  schedulePlatformOrgDeletion: vi.mocked(schedulePlatformOrgDeletion),
  cancelPlatformOrgDeletion: vi.mocked(cancelPlatformOrgDeletion),
  setPlatformOrgResidency: vi.mocked(setPlatformOrgResidency),
  listPlatformOrgUsers: vi.mocked(listPlatformOrgUsers),
  getPlatformOrgMetadata: vi.mocked(getPlatformOrgMetadata),
  deactivatePlatformUser: vi.mocked(deactivatePlatformUser),
  reactivatePlatformUser: vi.mocked(reactivatePlatformUser),
  resetPlatformUserPassword: vi.mocked(resetPlatformUserPassword),
  reinvitePlatformUser: vi.mocked(reinvitePlatformUser),
  getPlatformSettings: vi.mocked(getPlatformSettings),
  patchPlatformSettings: vi.mocked(patchPlatformSettings),
};

type ApiName = keyof typeof api;

/** Every platform API function with zero calls. */
const NO_CALLS: Readonly<Record<ApiName, number>> = {
  listPlatformOrgs: 0,
  createPlatformOrg: 0,
  updatePlatformOrgLimits: 0,
  deactivatePlatformOrg: 0,
  reactivatePlatformOrg: 0,
  schedulePlatformOrgDeletion: 0,
  cancelPlatformOrgDeletion: 0,
  setPlatformOrgResidency: 0,
  listPlatformOrgUsers: 0,
  getPlatformOrgMetadata: 0,
  deactivatePlatformUser: 0,
  reactivatePlatformUser: 0,
  resetPlatformUserPassword: 0,
  reinvitePlatformUser: 0,
  getPlatformSettings: 0,
  patchPlatformSettings: 0,
};

/** How many times each platform API function was called. */
function apiCalls(): Record<ApiName, number> {
  const counts = { ...NO_CALLS };
  for (const name of Object.keys(api) as ApiName[]) {
    counts[name] = api[name].mock.calls.length;
  }
  return counts;
}

/** The mock behind `name`, loosely typed so a case table can arrange any of them. */
function mockOf(name: ApiName): Mock<(...args: unknown[]) => Promise<unknown>> {
  return api[name] as unknown as Mock<(...args: unknown[]) => Promise<unknown>>;
}

/** The stubbed global `fetch`: no request may ever leave the mocked `@/api/platform`. */
let fetchSpy: Mock<(...args: unknown[]) => Promise<never>>;

// --- Fixtures -------------------------------------------------------------

const GIB = 1024 ** 3;

const ACME = '5a1c2e3f-4b5d-4e6f-8a7b-9c0d1e2f3a4b';
const BETA = '6b2d3f40-5c6e-4f70-9b8c-0d1e2f3a4b5c';
const GAMMA = '7c3e4051-6d7f-4081-ac9d-1e2f3a4b5c6d';
const DELTA = '8d4f5162-7e80-4192-bdae-2f3a4b5c6d7e';
const UNKNOWN = '9e506273-8f91-42a3-8ebf-3a4b5c6d7e8f';
const DELTA_INVITE = '0f617384-90a2-43b4-9fc0-4b5c6d7e8f90';

const LATER = '2026-10-04T12:00:00Z';
const PURGE = '2026-11-03T12:00:00Z';

const ORGS: Readonly<Record<string, PlatformOrg>> = {
  [ACME]: {
    id: ACME,
    name: 'Acme AG',
    status: 'active',
    seats: 10,
    monthly_budget_chf: '100.00',
    storage_quota: 10 * GIB,
    data_residency: true,
    deletion_requested_at: null,
    purge_after: null,
    created_at: '2026-01-10T09:00:00Z',
    updated_at: '2026-01-10T09:00:00Z',
  },
  [BETA]: {
    id: BETA,
    name: 'Beta GmbH',
    status: 'deactivated',
    seats: 5,
    monthly_budget_chf: '50.00',
    storage_quota: 5 * GIB,
    data_residency: false,
    deletion_requested_at: null,
    purge_after: null,
    created_at: '2026-02-01T08:30:00Z',
    updated_at: '2026-08-15T10:00:00Z',
  },
  [GAMMA]: {
    id: GAMMA,
    name: 'Gamma SA',
    status: 'pending_deletion',
    seats: 20,
    monthly_budget_chf: '200.00',
    storage_quota: 20 * GIB,
    data_residency: true,
    deletion_requested_at: '2026-09-20T10:00:00Z',
    purge_after: '2026-10-20T10:00:00Z',
    created_at: '2026-03-05T14:00:00Z',
    updated_at: '2026-09-20T10:00:00Z',
  },
};

const ORG_ORDER = [ACME, BETA, GAMMA];

/** A fresh copy of the org `id` with `overrides` applied. */
function org(id: string, overrides: Partial<PlatformOrg> = {}): PlatformOrg {
  const base = ORGS[id];
  if (base === undefined) throw new Error(`no fixture org ${id}`);
  return { ...base, ...overrides };
}

function allOrgs(): PlatformOrg[] {
  return ORG_ORDER.map((id) => org(id));
}

/** `allOrgs()` with the org `id` replaced by `replacement`. */
function orgsWith(id: string, replacement: PlatformOrg): PlatformOrg[] {
  return allOrgs().map((item) => (item.id === id ? replacement : item));
}

/** The org the create flow makes, as the API answers it. */
function deltaOrg(): PlatformOrg {
  return {
    id: DELTA,
    name: 'Delta AG',
    status: 'active',
    seats: 25,
    monthly_budget_chf: '250.50',
    storage_quota: 20 * GIB,
    data_residency: true,
    deletion_requested_at: null,
    purge_after: null,
    created_at: LATER,
    updated_at: LATER,
  };
}

function createdResponse(): PlatformOrgCreateResponse {
  return {
    organization: deltaOrg(),
    invitation: {
      id: DELTA_INVITE,
      email: 'admin@delta.ch',
      role: 'org_admin',
      sent_at: LATER,
      expires_at: '2026-10-07T12:00:00Z',
      expired: false,
    },
  };
}

/** A valid create form (padded name and email, a one-decimal budget). */
function createInput(overrides: Partial<OrgCreateInput> = {}): OrgCreateInput {
  return { name: '  Delta AG ', email: ' admin@delta.ch ', seats: 25, budgetChf: '250.5', storageGib: 20, ...overrides };
}

/** The limits form showing Acme's current limits unchanged. */
function acmeLimits(overrides: Partial<OrgLimitsInput> = {}): OrgLimitsInput {
  return { seats: 10, budgetChf: '100.00', storageGib: 10, ...overrides };
}

/** Every org name and email the fixtures and flows use: none may ever reach the console. */
const PERSONAL_DATA = ['Acme AG', 'Beta GmbH', 'Gamma SA', 'Delta AG', 'admin@delta.ch', 'admin@acme.ch'];

/** Backend error text the store must never show (it names an org and an address on purpose). */
const DETAIL = 'backend detail: Acme AG admin@acme.ch already has an account';

function apiError(status: number, reason?: string): ApiError {
  return new ApiError(status, 'Error', DETAIL, reason);
}

type Catalog = Record<string, unknown>;

const EN: Catalog = en;

/**
 * `t(key, params)` in the active locale, after checking the English catalog
 * really has `key` (a missing key would make `t` return the key itself, which
 * an implementation would then match by accident).
 */
function msg(key: string, params?: Params): string {
  const value = Object.hasOwn(EN, key) ? EN[key] : undefined;
  const present = (typeof value === 'string' && value.trim() !== '') || (typeof value === 'object' && value !== null);
  if (!present) throw new Error(`the en catalog has no text for ${key}`);
  return t(key as MessageKey, params);
}

const FORM_ERROR_KEYS: Readonly<Record<OrgFormField, string>> = {
  name: 'platform.orgs.form.error.name',
  email: 'platform.orgs.form.error.email',
  seats: 'platform.orgs.form.error.seats',
  budgetChf: 'platform.orgs.form.error.budget',
  storageGib: 'platform.orgs.form.error.storage',
};

/** A promise the test settles by hand. Its rejection is never "unhandled". */
function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  promise.catch(() => undefined);
  return { promise, resolve, reject };
}

/** 'resolved' when `promise` fulfils (whatever with), else `{ threw: error }`. */
function outcomeOf(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => 'resolved',
    (e: unknown) => ({ threw: e }),
  );
}

/** Lets every queued microtask and zero-delay timer run. */
function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/** The toasts as kind + title (a body, if any, is the implementer's choice). */
function toastTitles(): Array<{ kind: string; title: string }> {
  return useToastStore().toasts.map(({ kind, title }) => ({ kind, title }));
}

type Store = ReturnType<typeof usePlatformOrgsStore>;

/** The store loaded with `orgs` (default: Acme, Beta, Gamma); API call logs and toasts cleared. */
async function setup(orgs: PlatformOrg[] = allOrgs()): Promise<Store> {
  const store = usePlatformOrgsStore();
  api.listPlatformOrgs.mockResolvedValueOnce({ organizations: orgs });
  await store.load();
  if (!store.loaded) throw new Error('setup: load() did not load the store');
  for (const mock of Object.values(api)) mock.mockClear();
  useToastStore().toasts.splice(0);
  return store;
}

beforeEach(() => {
  localStorage.clear();
  setActivePinia(createPinia());
  setLocale('en');
  for (const mock of Object.values(api)) mock.mockReset();
  fetchSpy = vi.fn<(...args: unknown[]) => Promise<never>>(() =>
    Promise.reject(new TypeError('network disabled in tests')),
  );
  vi.stubGlobal('fetch', fetchSpy);
});

afterEach(() => {
  setLocale('en');
});

// --- Initial state --------------------------------------------------------

describe('platformOrgsStore initial state', () => {
  it('is the "platformOrgs" store with no orgs, nothing loaded and every sheet closed', () => {
    const store = usePlatformOrgsStore();

    expect({
      id: store.$id,
      orgs: store.orgs,
      loading: store.loading,
      loaded: store.loaded,
      loadError: store.loadError,
      createOpen: store.createOpen,
      createBusy: store.createBusy,
      createErrors: store.createErrors,
      createError: store.createError,
      limitsOrgId: store.limitsOrgId,
      limitsOrg: store.limitsOrg,
      limitsBusy: store.limitsBusy,
      limitsErrors: store.limitsErrors,
      limitsError: store.limitsError,
      pending: store.pending,
      pendingCopy: store.pendingCopy,
      actionBusy: store.actionBusy,
      actionError: store.actionError,
    }).toStrictEqual({
      id: 'platformOrgs',
      orgs: [],
      loading: false,
      loaded: false,
      loadError: null,
      createOpen: false,
      createBusy: false,
      createErrors: {},
      createError: null,
      limitsOrgId: null,
      limitsOrg: null,
      limitsBusy: false,
      limitsErrors: {},
      limitsError: null,
      pending: null,
      pendingCopy: null,
      actionBusy: false,
      actionError: null,
    });
  });

  it('asks nothing of the server until load() is called', () => {
    usePlatformOrgsStore();

    expect({ calls: apiCalls(), fetchCalls: fetchSpy.mock.calls.length }).toEqual({ calls: NO_CALLS, fetchCalls: 0 });
  });
});

// --- load(): GET /api/platform/orgs ----------------------------------------

describe('platformOrgsStore load', () => {
  it('loads every org in the order the API returns them and marks the store loaded', async () => {
    const listed = [org(GAMMA), org(ACME), org(BETA)];
    api.listPlatformOrgs.mockResolvedValueOnce({ organizations: listed });
    const store = usePlatformOrgsStore();

    const outcome = await outcomeOf(store.load());

    expect({
      outcome,
      listArgs: api.listPlatformOrgs.mock.calls,
      calls: apiCalls(),
      orgs: store.orgs,
      loaded: store.loaded,
      loadError: store.loadError,
      loading: store.loading,
    }).toStrictEqual({
      outcome: 'resolved',
      listArgs: [[]],
      calls: { ...NO_CALLS, listPlatformOrgs: 1 },
      orgs: [org(GAMMA), org(ACME), org(BETA)],
      loaded: true,
      loadError: null,
      loading: false,
    });
  });

  it('is loading while the request is in flight, and not afterwards', async () => {
    const response = deferred<PlatformOrgListResponse>();
    api.listPlatformOrgs.mockReturnValueOnce(response.promise);
    const store = usePlatformOrgsStore();

    const done = outcomeOf(store.load());
    const during = { loading: store.loading, loaded: store.loaded };
    response.resolve({ organizations: allOrgs() });
    await done;

    expect({ during, after: { loading: store.loading, loaded: store.loaded } }).toEqual({
      during: { loading: true, loaded: false },
      after: { loading: false, loaded: true },
    });
  });

  it('sets a translated loadError, stays not loaded, stops loading and never throws when the first load fails', async () => {
    api.listPlatformOrgs.mockRejectedValueOnce(apiError(403));
    const store = usePlatformOrgsStore();

    const outcome = await outcomeOf(store.load());

    expect({
      outcome,
      loadError: store.loadError,
      loaded: store.loaded,
      loading: store.loading,
      orgs: store.orgs,
    }).toStrictEqual({
      outcome: 'resolved',
      loadError: msg('platform.error.forbidden'),
      loaded: false,
      loading: false,
      orgs: [],
    });
  });

  it.each([
    { label: 'a 403', error: () => apiError(403), key: 'platform.error.forbidden' },
    { label: 'a 429', error: () => apiError(429), key: 'platform.error.rateLimited' },
    { label: 'a 500', error: () => apiError(500), key: 'platform.error.generic' },
    { label: 'a network failure', error: () => new TypeError('Failed to fetch'), key: 'platform.error.generic' },
  ])('maps $label to its catalog message and never shows the backend detail', async ({ error, key }) => {
    api.listPlatformOrgs.mockRejectedValueOnce(error());
    const store = usePlatformOrgsStore();

    await store.load();

    expect({ loadError: store.loadError, echoesDetail: String(store.loadError).includes(DETAIL) }).toEqual({
      loadError: msg(key),
      echoesDetail: false,
    });
  });

  it('keeps the previously loaded orgs when a reload fails', async () => {
    const store = await setup();
    api.listPlatformOrgs.mockRejectedValueOnce(apiError(500));

    const outcome = await outcomeOf(store.load());

    expect({ outcome, orgs: store.orgs, loadError: store.loadError, loading: store.loading }).toStrictEqual({
      outcome: 'resolved',
      orgs: allOrgs(),
      loadError: msg('platform.error.generic'),
      loading: false,
    });
  });

  it('replaces the list and clears the loadError when a later load succeeds', async () => {
    const store = await setup();
    api.listPlatformOrgs.mockRejectedValueOnce(apiError(429));
    await store.load();
    const failed = store.loadError;
    api.listPlatformOrgs.mockResolvedValueOnce({ organizations: [org(BETA, { status: 'active' })] });

    await store.load();

    expect({ failed, loadError: store.loadError, orgs: store.orgs }).toStrictEqual({
      failed: msg('platform.error.rateLimited'),
      loadError: null,
      orgs: [org(BETA, { status: 'active' })],
    });
  });

  it('shows the loadError in the active locale (German)', async () => {
    setLocale('de');
    api.listPlatformOrgs.mockRejectedValueOnce(apiError(403));
    const store = usePlatformOrgsStore();

    await store.load();

    expect({
      loadError: store.loadError,
      differsFromEnglish: store.loadError !== EN['platform.error.forbidden'],
    }).toEqual({ loadError: msg('platform.error.forbidden'), differsFromEnglish: true });
  });
});

// --- Create sheet ------------------------------------------------------------

describe('platformOrgsStore create flow', () => {
  it('openCreate opens the create sheet with no errors', async () => {
    const store = await setup();

    store.openCreate();

    expect({
      createOpen: store.createOpen,
      createErrors: store.createErrors,
      createError: store.createError,
      calls: apiCalls(),
    }).toStrictEqual({ createOpen: true, createErrors: {}, createError: null, calls: NO_CALLS });
  });

  it('openCreate clears the field errors and the request error of an earlier attempt', async () => {
    const store = await setup();
    store.openCreate();
    await store.submitCreate(createInput({ seats: 0 }));
    const fieldErrorsBefore = { ...store.createErrors };
    api.createPlatformOrg.mockRejectedValueOnce(apiError(409, 'email_taken'));
    await store.submitCreate(createInput());
    const requestErrorBefore = store.createError;

    store.openCreate();

    expect({
      fieldErrorsBefore,
      requestErrorBefore,
      createOpen: store.createOpen,
      createErrors: store.createErrors,
      createError: store.createError,
    }).toStrictEqual({
      fieldErrorsBefore: { seats: msg('platform.orgs.form.error.seats') },
      requestErrorBefore: msg('platform.error.emailTaken'),
      createOpen: true,
      createErrors: {},
      createError: null,
    });
  });

  it('closeCreate closes the sheet and clears its errors without a request', async () => {
    const store = await setup();
    store.openCreate();
    await store.submitCreate(createInput({ name: '' }));
    api.createPlatformOrg.mockRejectedValueOnce(apiError(409, 'email_taken'));
    await store.submitCreate(createInput());
    const callsBefore = apiCalls();

    store.closeCreate();

    expect({
      createOpen: store.createOpen,
      createErrors: store.createErrors,
      createError: store.createError,
      newCalls: api.createPlatformOrg.mock.calls.length - callsBefore.createPlatformOrg,
    }).toStrictEqual({ createOpen: false, createErrors: {}, createError: null, newCalls: 0 });
  });

  it('reports every invalid field at once, makes no request and keeps the sheet open', async () => {
    const store = await setup();
    store.openCreate();

    const result = await store.submitCreate({ name: '   ', email: 'not-an-email', seats: 0, budgetChf: '-1', storageGib: -1 });

    expect({
      result,
      createErrors: store.createErrors,
      createError: store.createError,
      createOpen: store.createOpen,
      createBusy: store.createBusy,
      calls: apiCalls(),
      orgs: store.orgs,
      toasts: toastTitles(),
    }).toStrictEqual({
      result: false,
      createErrors: {
        name: msg('platform.orgs.form.error.name'),
        email: msg('platform.orgs.form.error.email'),
        seats: msg('platform.orgs.form.error.seats'),
        budgetChf: msg('platform.orgs.form.error.budget'),
        storageGib: msg('platform.orgs.form.error.storage'),
      },
      createError: null,
      createOpen: true,
      createBusy: false,
      calls: NO_CALLS,
      orgs: allOrgs(),
      toasts: [],
    });
  });

  it.each([
    { label: 'a blank name', field: 'name', overrides: { name: '' } },
    { label: 'a 121-character name', field: 'name', overrides: { name: 'x'.repeat(121) } },
    { label: 'a name with a zero-width space', field: 'name', overrides: { name: `Delta${String.fromCharCode(0x200b)}AG` } },
    { label: 'an email without a domain dot', field: 'email', overrides: { email: 'admin@delta' } },
    { label: 'zero seats', field: 'seats', overrides: { seats: 0 } },
    { label: 'fractional seats', field: 'seats', overrides: { seats: 2.5 } },
    { label: 'a budget in exponent notation', field: 'budgetChf', overrides: { budgetChf: '1e3' } },
    { label: 'a budget with three decimals', field: 'budgetChf', overrides: { budgetChf: '1.234' } },
    { label: 'fractional storage', field: 'storageGib', overrides: { storageGib: 1.5 } },
  ] satisfies Array<{ label: string; field: OrgFormField; overrides: Partial<OrgCreateInput> }>)(
    'reports only $label on its own field and makes no request',
    async ({ field, overrides }) => {
      const store = await setup();
      store.openCreate();

      const result = await store.submitCreate(createInput(overrides));

      expect({ result, createErrors: store.createErrors, calls: apiCalls(), createOpen: store.createOpen }).toStrictEqual({
        result: false,
        createErrors: { [field]: msg(FORM_ERROR_KEYS[field]) },
        calls: NO_CALLS,
        createOpen: true,
      });
    },
  );

  it('posts exactly the five API fields: trimmed name and email, the budget with two decimals, storage in bytes', async () => {
    const store = await setup();
    api.createPlatformOrg.mockResolvedValueOnce(createdResponse());
    store.openCreate();

    await store.submitCreate(createInput());

    expect({ createArgs: api.createPlatformOrg.mock.calls, calls: apiCalls() }).toStrictEqual({
      createArgs: [
        [
          {
            name: 'Delta AG',
            primary_admin_email: 'admin@delta.ch',
            seats: 25,
            monthly_budget_chf: '250.50',
            storage_quota: 20 * GIB,
          },
        ],
      ],
      calls: { ...NO_CALLS, createPlatformOrg: 1 },
    });
  });

  it('appends the new org, closes the sheet, clears its errors and toasts success', async () => {
    const store = await setup();
    api.createPlatformOrg.mockResolvedValueOnce(createdResponse());
    store.openCreate();

    const result = await store.submitCreate(createInput());

    expect({
      result,
      orgs: store.orgs,
      createOpen: store.createOpen,
      createErrors: store.createErrors,
      createError: store.createError,
      createBusy: store.createBusy,
      toasts: toastTitles(),
    }).toStrictEqual({
      result: true,
      orgs: [...allOrgs(), deltaOrg()],
      createOpen: false,
      createErrors: {},
      createError: null,
      createBusy: false,
      toasts: [{ kind: 'success', title: msg('platform.toast.orgCreated') }],
    });
  });

  it('clears the errors of earlier attempts when a later submit succeeds', async () => {
    const store = await setup();
    store.openCreate();
    await store.submitCreate(createInput({ email: 'nope' }));
    api.createPlatformOrg.mockRejectedValueOnce(apiError(409, 'email_taken'));
    await store.submitCreate(createInput());
    api.createPlatformOrg.mockResolvedValueOnce(createdResponse());

    const result = await store.submitCreate(createInput());

    expect({
      result,
      createErrors: store.createErrors,
      createError: store.createError,
      createOpen: store.createOpen,
    }).toStrictEqual({ result: true, createErrors: {}, createError: null, createOpen: false });
  });

  it('keeps the sheet open with a translated createError when the address already has an account (409 email_taken)', async () => {
    const store = await setup();
    api.createPlatformOrg.mockRejectedValueOnce(apiError(409, 'email_taken'));
    store.openCreate();

    const outcome = await outcomeOf(store.submitCreate(createInput()));

    expect({
      outcome,
      createError: store.createError,
      createOpen: store.createOpen,
      createBusy: store.createBusy,
      orgs: store.orgs,
      toasts: toastTitles(),
    }).toStrictEqual({
      outcome: 'resolved',
      createError: msg('platform.error.emailTaken'),
      createOpen: true,
      createBusy: false,
      orgs: allOrgs(),
      toasts: [],
    });
  });

  it.each([
    { label: 'a 422', error: () => apiError(422), key: 'platform.error.invalidInput' },
    { label: 'a 403', error: () => apiError(403), key: 'platform.error.forbidden' },
    { label: 'a network failure', error: () => new TypeError('Failed to fetch'), key: 'platform.error.generic' },
  ])('maps $label on create to its catalog message, never the backend detail', async ({ error, key }) => {
    const store = await setup();
    api.createPlatformOrg.mockRejectedValueOnce(error());
    store.openCreate();

    const result = await store.submitCreate(createInput());

    expect({ result, createError: store.createError, createOpen: store.createOpen }).toEqual({
      result: false,
      createError: msg(key),
      createOpen: true,
    });
  });

  it('makes no second request while a create is in flight', async () => {
    const store = await setup();
    const response = deferred<PlatformOrgCreateResponse>();
    api.createPlatformOrg.mockReturnValueOnce(response.promise);
    store.openCreate();

    const first = store.submitCreate(createInput());
    const busy = store.createBusy;
    const second = await store.submitCreate(createInput());
    response.resolve(createdResponse());
    const firstResult = await first;

    expect({
      busy,
      second,
      firstResult,
      createCalls: api.createPlatformOrg.mock.calls.length,
      createBusy: store.createBusy,
      orgIds: store.orgs.map((item) => item.id),
    }).toStrictEqual({
      busy: true,
      second: false,
      firstResult: true,
      createCalls: 1,
      createBusy: false,
      orgIds: [ACME, BETA, GAMMA, DELTA],
    });
  });
});

// --- Edit limits sheet ----------------------------------------------------------

describe('platformOrgsStore edit limits', () => {
  it.each([
    { label: 'an active org', orgId: ACME },
    { label: 'a deactivated org', orgId: BETA },
  ])('openLimits opens the sheet for $label', async ({ orgId }) => {
    const store = await setup();

    store.openLimits(orgId);

    expect({ limitsOrgId: store.limitsOrgId, limitsOrg: store.limitsOrg, calls: apiCalls() }).toStrictEqual({
      limitsOrgId: orgId,
      limitsOrg: org(orgId),
      calls: NO_CALLS,
    });
  });

  it.each([
    { label: 'an org pending deletion', orgId: GAMMA },
    { label: 'an unknown org', orgId: UNKNOWN },
  ])('openLimits does not open the sheet for $label', async ({ orgId }) => {
    const store = await setup();

    store.openLimits(orgId);

    expect({ limitsOrgId: store.limitsOrgId, limitsOrg: store.limitsOrg, calls: apiCalls() }).toStrictEqual({
      limitsOrgId: null,
      limitsOrg: null,
      calls: NO_CALLS,
    });
  });

  it('openLimits clears the field errors and the request error of an earlier attempt', async () => {
    const store = await setup();
    store.openLimits(ACME);
    await store.submitLimits(acmeLimits({ seats: 0 }));
    const fieldErrorsBefore = { ...store.limitsErrors };
    store.openLimits(BETA);
    const afterFieldErrors = { limitsOrgId: store.limitsOrgId, limitsErrors: { ...store.limitsErrors } };
    api.updatePlatformOrgLimits.mockRejectedValueOnce(apiError(409, 'invalid_status'));
    await store.submitLimits({ seats: 6, budgetChf: '50.00', storageGib: 5 });
    const requestErrorBefore = store.limitsError;

    store.openLimits(BETA);

    expect({
      fieldErrorsBefore,
      afterFieldErrors,
      requestErrorBefore,
      limitsError: store.limitsError,
      limitsErrors: store.limitsErrors,
      limitsOrgId: store.limitsOrgId,
    }).toStrictEqual({
      fieldErrorsBefore: { seats: msg('platform.orgs.form.error.seats') },
      afterFieldErrors: { limitsOrgId: BETA, limitsErrors: {} },
      requestErrorBefore: msg('platform.error.orgInvalidStatus'),
      limitsError: null,
      limitsErrors: {},
      limitsOrgId: BETA,
    });
  });

  it('closeLimits closes the sheet without a request', async () => {
    const store = await setup();
    store.openLimits(ACME);

    store.closeLimits();

    expect({ limitsOrgId: store.limitsOrgId, limitsOrg: store.limitsOrg, calls: apiCalls() }).toStrictEqual({
      limitsOrgId: null,
      limitsOrg: null,
      calls: NO_CALLS,
    });
  });

  it.each([
    { label: 'the same values', input: acmeLimits() },
    { label: 'the same budget written without decimals', input: acmeLimits({ budgetChf: '100' }) },
    { label: 'the same budget with one decimal and spaces', input: acmeLimits({ budgetChf: ' 100.0 ' }) },
  ])('closes without a request when nothing changed ($label)', async ({ input }) => {
    const store = await setup();
    store.openLimits(ACME);

    const result = await store.submitLimits(input);

    expect({ result, calls: apiCalls(), limitsOrgId: store.limitsOrgId, orgs: store.orgs }).toStrictEqual({
      result: true,
      calls: NO_CALLS,
      limitsOrgId: null,
      orgs: allOrgs(),
    });
  });

  it.each([
    { label: 'only the seats', orgId: ACME, input: acmeLimits({ seats: 25 }), patch: { seats: 25 } },
    {
      label: 'only the budget, with two decimals',
      orgId: ACME,
      input: acmeLimits({ budgetChf: '120' }),
      patch: { monthly_budget_chf: '120.00' },
    },
    {
      label: 'only the storage, in bytes',
      orgId: ACME,
      input: acmeLimits({ storageGib: 50 }),
      patch: { storage_quota: 50 * GIB },
    },
    {
      label: 'all three limits',
      orgId: ACME,
      input: { seats: 3, budgetChf: '0.5', storageGib: 0 },
      patch: { seats: 3, monthly_budget_chf: '0.50', storage_quota: 0 },
    },
    {
      label: 'the seats of a deactivated org',
      orgId: BETA,
      input: { seats: 6, budgetChf: '50.00', storageGib: 5 },
      patch: { seats: 6 },
    },
  ] satisfies Array<{ label: string; orgId: string; input: OrgLimitsInput; patch: PlatformOrgLimitsPatch }>)(
    'sends $label and nothing else',
    async ({ orgId, input, patch }) => {
      const store = await setup();
      api.updatePlatformOrgLimits.mockResolvedValueOnce(org(orgId, { ...patch, updated_at: LATER }));
      store.openLimits(orgId);

      await store.submitLimits(input);

      expect({ updateArgs: api.updatePlatformOrgLimits.mock.calls, calls: apiCalls() }).toStrictEqual({
        updateArgs: [[orgId, patch]],
        calls: { ...NO_CALLS, updatePlatformOrgLimits: 1 },
      });
    },
  );

  it('replaces the org with the response, closes the sheet and toasts success', async () => {
    const store = await setup();
    const updated = org(ACME, { seats: 25, updated_at: LATER });
    api.updatePlatformOrgLimits.mockResolvedValueOnce(updated);
    store.openLimits(ACME);

    const result = await store.submitLimits(acmeLimits({ seats: 25 }));

    expect({
      result,
      orgs: store.orgs,
      limitsOrgId: store.limitsOrgId,
      limitsOrg: store.limitsOrg,
      limitsErrors: store.limitsErrors,
      limitsError: store.limitsError,
      limitsBusy: store.limitsBusy,
      toasts: toastTitles(),
    }).toStrictEqual({
      result: true,
      orgs: [updated, org(BETA), org(GAMMA)],
      limitsOrgId: null,
      limitsOrg: null,
      limitsErrors: {},
      limitsError: null,
      limitsBusy: false,
      toasts: [{ kind: 'success', title: msg('platform.toast.limitsSaved') }],
    });
  });

  it.each([
    { label: 'zero seats', field: 'seats', input: acmeLimits({ seats: 0 }) },
    { label: 'an unparseable budget', field: 'budgetChf', input: acmeLimits({ budgetChf: 'abc' }) },
    { label: 'negative storage', field: 'storageGib', input: acmeLimits({ storageGib: -1 }) },
  ] satisfies Array<{ label: string; field: OrgFormField; input: OrgLimitsInput }>)(
    'reports $label on its field, makes no request and keeps the sheet open',
    async ({ field, input }) => {
      const store = await setup();
      store.openLimits(ACME);

      const result = await store.submitLimits(input);

      expect({
        result,
        limitsErrors: store.limitsErrors,
        calls: apiCalls(),
        limitsOrgId: store.limitsOrgId,
        orgs: store.orgs,
      }).toStrictEqual({
        result: false,
        limitsErrors: { [field]: msg(FORM_ERROR_KEYS[field]) },
        calls: NO_CALLS,
        limitsOrgId: ACME,
        orgs: allOrgs(),
      });
    },
  );

  it('keeps the sheet open with a translated limitsError when the request fails (409 invalid_status)', async () => {
    const store = await setup();
    api.updatePlatformOrgLimits.mockRejectedValueOnce(apiError(409, 'invalid_status'));
    store.openLimits(ACME);

    const outcome = await outcomeOf(store.submitLimits(acmeLimits({ seats: 25 })));

    expect({
      outcome,
      limitsError: store.limitsError,
      limitsOrgId: store.limitsOrgId,
      limitsBusy: store.limitsBusy,
      orgs: store.orgs,
      toasts: toastTitles(),
    }).toStrictEqual({
      outcome: 'resolved',
      limitsError: msg('platform.error.orgInvalidStatus'),
      limitsOrgId: ACME,
      limitsBusy: false,
      orgs: allOrgs(),
      toasts: [],
    });
  });

  it('is limitsBusy while the request is in flight, and not afterwards', async () => {
    const store = await setup();
    const response = deferred<PlatformOrg>();
    api.updatePlatformOrgLimits.mockReturnValueOnce(response.promise);
    store.openLimits(ACME);

    const done = store.submitLimits(acmeLimits({ seats: 12 }));
    const during = store.limitsBusy;
    response.resolve(org(ACME, { seats: 12 }));
    const result = await done;

    expect({ during, after: store.limitsBusy, result }).toEqual({ during: true, after: false, result: true });
  });

  it('makes no request when no limits sheet is open', async () => {
    const store = await setup();

    const outcome = await outcomeOf(store.submitLimits(acmeLimits({ seats: 25 })));

    expect({ outcome, calls: apiCalls(), orgs: store.orgs }).toStrictEqual({
      outcome: 'resolved',
      calls: NO_CALLS,
      orgs: allOrgs(),
    });
  });
});

// --- Confirm flows -------------------------------------------------------------------

interface ConfirmCase {
  label: string;
  request: (store: Store) => void;
  kind: OrgConfirmKind;
  orgId: string;
  call: ApiName;
  args: unknown[];
  response: () => PlatformOrg;
  toast: string;
  destructive: boolean;
}

const CONFIRM_CASES: ConfirmCase[] = [
  {
    label: 'deactivate an active org',
    request: (store) => store.requestDeactivate(ACME),
    kind: 'deactivate',
    orgId: ACME,
    call: 'deactivatePlatformOrg',
    args: [ACME],
    response: () => org(ACME, { status: 'deactivated', updated_at: LATER }),
    toast: 'platform.toast.orgDeactivated',
    destructive: true,
  },
  {
    label: 'reactivate a deactivated org',
    request: (store) => store.requestReactivate(BETA),
    kind: 'reactivate',
    orgId: BETA,
    call: 'reactivatePlatformOrg',
    args: [BETA],
    response: () => org(BETA, { status: 'active', updated_at: LATER }),
    toast: 'platform.toast.orgReactivated',
    destructive: false,
  },
  {
    label: 'schedule the deletion of an active org',
    request: (store) => store.requestScheduleDeletion(ACME),
    kind: 'scheduleDeletion',
    orgId: ACME,
    call: 'schedulePlatformOrgDeletion',
    args: [ACME],
    response: () =>
      org(ACME, { status: 'pending_deletion', deletion_requested_at: LATER, purge_after: PURGE, updated_at: LATER }),
    toast: 'platform.toast.deletionScheduled',
    destructive: true,
  },
  {
    label: 'schedule the deletion of a deactivated org',
    request: (store) => store.requestScheduleDeletion(BETA),
    kind: 'scheduleDeletion',
    orgId: BETA,
    call: 'schedulePlatformOrgDeletion',
    args: [BETA],
    response: () =>
      org(BETA, { status: 'pending_deletion', deletion_requested_at: LATER, purge_after: PURGE, updated_at: LATER }),
    toast: 'platform.toast.deletionScheduled',
    destructive: true,
  },
  {
    label: 'cancel a pending deletion',
    request: (store) => store.requestCancelDeletion(GAMMA),
    kind: 'cancelDeletion',
    orgId: GAMMA,
    call: 'cancelPlatformOrgDeletion',
    args: [GAMMA],
    response: () =>
      org(GAMMA, { status: 'deactivated', deletion_requested_at: null, purge_after: null, updated_at: LATER }),
    toast: 'platform.toast.deletionCancelled',
    destructive: false,
  },
  {
    label: 'turn data residency off',
    request: (store) => store.requestResidency(ACME, false),
    kind: 'residencyOff',
    orgId: ACME,
    call: 'setPlatformOrgResidency',
    args: [ACME, false],
    response: () => org(ACME, { data_residency: false, updated_at: LATER }),
    toast: 'platform.toast.residencyOff',
    destructive: true,
  },
  {
    label: 'turn data residency on',
    request: (store) => store.requestResidency(BETA, true),
    kind: 'residencyOn',
    orgId: BETA,
    call: 'setPlatformOrgResidency',
    args: [BETA, true],
    response: () => org(BETA, { data_residency: true, updated_at: LATER }),
    toast: 'platform.toast.residencyOn',
    destructive: false,
  },
];

const DISALLOWED_REQUESTS: Array<{ label: string; request: (store: Store) => void }> = [
  { label: 'reactivate an active org', request: (store) => store.requestReactivate(ACME) },
  { label: 'deactivate a deactivated org', request: (store) => store.requestDeactivate(BETA) },
  { label: 'deactivate an org pending deletion', request: (store) => store.requestDeactivate(GAMMA) },
  { label: 'reactivate an org pending deletion', request: (store) => store.requestReactivate(GAMMA) },
  { label: 'schedule the deletion of an org already pending deletion', request: (store) => store.requestScheduleDeletion(GAMMA) },
  { label: 'cancel the deletion of an active org', request: (store) => store.requestCancelDeletion(ACME) },
  { label: 'cancel the deletion of a deactivated org', request: (store) => store.requestCancelDeletion(BETA) },
  { label: 'turn residency on for an org that has it on', request: (store) => store.requestResidency(ACME, true) },
  { label: 'turn residency off for an org that has it off', request: (store) => store.requestResidency(BETA, false) },
  { label: 'change the residency of an org pending deletion', request: (store) => store.requestResidency(GAMMA, false) },
  { label: 'deactivate an unknown org', request: (store) => store.requestDeactivate(UNKNOWN) },
  { label: 'reactivate an unknown org', request: (store) => store.requestReactivate(UNKNOWN) },
  { label: 'schedule the deletion of an unknown org', request: (store) => store.requestScheduleDeletion(UNKNOWN) },
  { label: 'cancel the deletion of an unknown org', request: (store) => store.requestCancelDeletion(UNKNOWN) },
  { label: 'set the residency of an unknown org', request: (store) => store.requestResidency(UNKNOWN, false) },
];

describe('platformOrgsStore request* (open the confirm sheet, never call the API)', () => {
  it.each(CONFIRM_CASES)('opens the confirm sheet to $label without a request', async ({ request, kind, orgId }) => {
    const store = await setup();

    request(store);

    expect({ pending: store.pending, calls: apiCalls(), fetchCalls: fetchSpy.mock.calls.length }).toStrictEqual({
      pending: { kind, orgId },
      calls: NO_CALLS,
      fetchCalls: 0,
    });
  });

  it.each(DISALLOWED_REQUESTS)('does not open the confirm sheet to $label', async ({ request }) => {
    const store = await setup();

    request(store);

    expect({ pending: store.pending, pendingCopy: store.pendingCopy, calls: apiCalls() }).toStrictEqual({
      pending: null,
      pendingCopy: null,
      calls: NO_CALLS,
    });
  });

  it('a new request clears the actionError of a failed confirmation', async () => {
    const store = await setup();
    store.requestDeactivate(ACME);
    api.deactivatePlatformOrg.mockRejectedValueOnce(apiError(409, 'invalid_status'));
    await store.confirmPending();
    const before = store.actionError;

    store.requestScheduleDeletion(ACME);

    expect({ before, actionError: store.actionError, pending: store.pending }).toStrictEqual({
      before: msg('platform.error.orgInvalidStatus'),
      actionError: null,
      pending: { kind: 'scheduleDeletion', orgId: ACME },
    });
  });

  it('cancelPending closes the confirm sheet without a request', async () => {
    const store = await setup();
    store.requestDeactivate(ACME);
    const before = store.pending === null ? null : { ...store.pending };

    store.cancelPending();

    expect({ before, pending: store.pending, pendingCopy: store.pendingCopy, calls: apiCalls() }).toStrictEqual({
      before: { kind: 'deactivate', orgId: ACME },
      pending: null,
      pendingCopy: null,
      calls: NO_CALLS,
    });
  });
});

describe('platformOrgsStore confirmPending', () => {
  it.each(CONFIRM_CASES)(
    'makes exactly one request to $label, replaces the org, closes and toasts',
    async ({ request, orgId, call, args, response, toast }) => {
      const store = await setup();
      mockOf(call).mockResolvedValueOnce(response());
      request(store);

      const result = await store.confirmPending();

      expect({
        result,
        calls: apiCalls(),
        args: mockOf(call).mock.calls,
        orgs: store.orgs,
        pending: store.pending,
        actionError: store.actionError,
        actionBusy: store.actionBusy,
        toasts: toastTitles(),
      }).toStrictEqual({
        result: true,
        calls: { ...NO_CALLS, [call]: 1 },
        args: [args],
        orgs: orgsWith(orgId, response()),
        pending: null,
        actionError: null,
        actionBusy: false,
        toasts: [{ kind: 'success', title: msg(toast) }],
      });
    },
  );

  it('makes no request and returns false when nothing is pending', async () => {
    const store = await setup();

    const result = await store.confirmPending();

    expect({ result, calls: apiCalls(), toasts: toastTitles() }).toStrictEqual({
      result: false,
      calls: NO_CALLS,
      toasts: [],
    });
  });

  it('makes no request after the confirm sheet was cancelled', async () => {
    const store = await setup();
    store.requestDeactivate(ACME);
    store.cancelPending();

    const result = await store.confirmPending();

    expect({ result, calls: apiCalls(), orgs: store.orgs }).toStrictEqual({
      result: false,
      calls: NO_CALLS,
      orgs: allOrgs(),
    });
  });

  it('keeps the confirm sheet open with a translated actionError when the status no longer allows it (409 invalid_status)', async () => {
    const store = await setup();
    api.reactivatePlatformOrg.mockRejectedValueOnce(apiError(409, 'invalid_status'));
    store.requestReactivate(BETA);

    const outcome = await outcomeOf(store.confirmPending());

    expect({
      outcome,
      pending: store.pending,
      actionError: store.actionError,
      actionBusy: store.actionBusy,
      orgs: store.orgs,
      toasts: toastTitles(),
    }).toStrictEqual({
      outcome: 'resolved',
      pending: { kind: 'reactivate', orgId: BETA },
      actionError: msg('platform.error.orgInvalidStatus'),
      actionBusy: false,
      orgs: allOrgs(),
      toasts: [],
    });
  });

  it.each([
    { label: 'a 404', error: () => apiError(404), key: 'platform.error.orgNotFound' },
    { label: 'a 429', error: () => apiError(429), key: 'platform.error.rateLimited' },
    { label: 'a network failure', error: () => new TypeError('Failed to fetch'), key: 'platform.error.generic' },
  ])('returns false and maps $label to its catalog message', async ({ error, key }) => {
    const store = await setup();
    api.setPlatformOrgResidency.mockRejectedValueOnce(error());
    store.requestResidency(ACME, false);

    const result = await store.confirmPending();

    expect({ result, actionError: store.actionError, pending: store.pending }).toStrictEqual({
      result: false,
      actionError: msg(key),
      pending: { kind: 'residencyOff', orgId: ACME },
    });
  });

  it('succeeds on a retry after a failure and clears the actionError', async () => {
    const store = await setup();
    api.schedulePlatformOrgDeletion.mockRejectedValueOnce(apiError(500));
    const scheduled = org(ACME, { status: 'pending_deletion', deletion_requested_at: LATER, purge_after: PURGE });
    api.schedulePlatformOrgDeletion.mockResolvedValueOnce(scheduled);
    store.requestScheduleDeletion(ACME);
    await store.confirmPending();
    const failed = store.actionError;

    const result = await store.confirmPending();

    expect({
      failed,
      result,
      actionError: store.actionError,
      pending: store.pending,
      orgs: store.orgs,
      scheduleCalls: api.schedulePlatformOrgDeletion.mock.calls.length,
    }).toStrictEqual({
      failed: msg('platform.error.generic'),
      result: true,
      actionError: null,
      pending: null,
      orgs: orgsWith(ACME, scheduled),
      scheduleCalls: 2,
    });
  });

  it('makes exactly one request when confirmed twice while the first is in flight', async () => {
    const store = await setup();
    const response = deferred<PlatformOrg>();
    api.deactivatePlatformOrg.mockReturnValueOnce(response.promise);
    store.requestDeactivate(ACME);

    const first = store.confirmPending();
    const busy = store.actionBusy;
    const second = await store.confirmPending();
    response.resolve(org(ACME, { status: 'deactivated' }));
    const firstResult = await first;

    expect({
      busy,
      second,
      firstResult,
      deactivateCalls: api.deactivatePlatformOrg.mock.calls.length,
      actionBusy: store.actionBusy,
      toasts: toastTitles().length,
    }).toStrictEqual({ busy: true, second: false, firstResult: true, deactivateCalls: 1, actionBusy: false, toasts: 1 });
  });
});

// --- pendingCopy ---------------------------------------------------------------------

describe('platformOrgsStore pendingCopy', () => {
  it.each(CONFIRM_CASES)('names the org in the copy to $label', async ({ request, kind, orgId, destructive }) => {
    const store = await setup();
    const name = org(orgId).name;

    request(store);
    const copy = store.pendingCopy;

    expect({ copy, namesTheOrg: copy?.heading.includes(name) ?? false }).toStrictEqual({
      copy: {
        heading: msg(`platform.orgs.confirm.${kind}.heading`, { name }),
        subtext: msg(`platform.orgs.confirm.${kind}.subtext`, { name }),
        confirmLabel: msg(`platform.orgs.confirm.${kind}.confirm`, { name }),
        destructive,
      },
      namesTheOrg: true,
    });
  });
});

// --- Operator blindness and logging ------------------------------------------------------

describe('platformOrgsStore operator blindness', () => {
  it('only ever uses @/api/platform and never writes org names, emails or backend text to the console', async () => {
    const methods = ['log', 'info', 'warn', 'error', 'debug'] as const;
    const spies = methods.map((method) => vi.spyOn(console, method).mockImplementation(() => undefined));
    const store = usePlatformOrgsStore();

    // Load: failure, then success.
    api.listPlatformOrgs.mockRejectedValueOnce(apiError(500));
    await store.load();
    api.listPlatformOrgs.mockResolvedValueOnce({ organizations: allOrgs() });
    await store.load();

    // Create: invalid, refused, created.
    store.openCreate();
    await store.submitCreate(createInput({ email: 'admin@acme' }));
    api.createPlatformOrg.mockRejectedValueOnce(apiError(409, 'email_taken'));
    await store.submitCreate(createInput({ email: 'admin@acme.ch' }));
    api.createPlatformOrg.mockResolvedValueOnce(createdResponse());
    await store.submitCreate(createInput());

    // Limits: invalid, refused, saved.
    store.openLimits(ACME);
    await store.submitLimits(acmeLimits({ budgetChf: 'x' }));
    api.updatePlatformOrgLimits.mockRejectedValueOnce(apiError(409, 'invalid_status'));
    await store.submitLimits(acmeLimits({ seats: 11 }));
    api.updatePlatformOrgLimits.mockResolvedValueOnce(org(ACME, { seats: 11 }));
    await store.submitLimits(acmeLimits({ seats: 11 }));

    // Confirm flows: refused, cancelled, done.
    store.requestResidency(ACME, false);
    api.setPlatformOrgResidency.mockRejectedValueOnce(apiError(403));
    await store.confirmPending();
    store.cancelPending();
    store.requestCancelDeletion(GAMMA);
    api.cancelPlatformOrgDeletion.mockResolvedValueOnce(org(GAMMA, { status: 'deactivated' }));
    await store.confirmPending();
    store.requestReactivate(BETA);
    api.reactivatePlatformOrg.mockResolvedValueOnce(org(BETA, { status: 'active' }));
    await store.confirmPending();

    const logged = spies
      .flatMap((spy) => spy.mock.calls.flat())
      .map((arg: unknown) => {
        if (arg instanceof Error) return `${arg.name} ${arg.message}`;
        if (typeof arg === 'string') return arg;
        try {
          return JSON.stringify(arg) ?? String(arg);
        } catch {
          return String(arg);
        }
      })
      .join('\n');
    const leaked = [...PERSONAL_DATA, DETAIL].filter((value) => logged.includes(value));

    expect({
      leaked,
      fetchCalls: fetchSpy.mock.calls.length,
      calls: apiCalls(),
      orgCount: store.orgs.length,
    }).toEqual({
      leaked: [],
      fetchCalls: 0,
      calls: {
        ...NO_CALLS,
        listPlatformOrgs: 2,
        createPlatformOrg: 2,
        updatePlatformOrgLimits: 2,
        setPlatformOrgResidency: 1,
        cancelPlatformOrgDeletion: 1,
        reactivatePlatformOrg: 1,
      },
      orgCount: 4,
    });
  });
});
