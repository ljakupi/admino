/**
 * Platform organization detail store tests (issue #168: Platform console UI,
 * Super Admin; backend routes from #154 and #167).
 *
 * `usePlatformOrgDetailStore` (Pinia id 'platformOrgDetail', setup style)
 * owns the organization detail view of the Platform area (`?org=<uuid>`): the
 * org itself (taken from the org list), its metadata (seat usage, storage,
 * counts; never content) and its users with their actions.
 *
 * - `load(orgId)`: a non-UUID id is "not found" without any request; else
 *   `GET /api/platform/orgs`, `.../{id}/metadata` and `.../{id}/users`
 *   together. An org missing from the list or a 404 from any call is "not
 *   found"; any other failure is a translated `loadError`. A new load first
 *   clears the previous org's data (never shows another org's data), and a
 *   response that arrives after a newer load started is ignored.
 * - `seatText` is the catalog's seat text from `metadata.seats`;
 *   `actionsFor(userId)` follows the contract's user-action rules.
 * - Confirm flows: `request*` only opens `pending` when `actionsFor` allows it
 *   (never a request); `confirmPending()` makes one request; deactivate and
 *   reactivate replace the user with the response and refresh the metadata (a
 *   failed refresh keeps the old metadata and is not an error); a password
 *   reset (202) only toasts. A failure keeps `pending` with a translated
 *   `actionError`.
 * - Re-invite: only for the invited Org Admin of an active org without an
 *   active Org Admin. A blank email resends (no email argument); a valid one
 *   is trimmed and sent; an implausible one is refused client-side. Success
 *   reloads users and metadata; a refusal keeps the sheet open.
 *
 * Security notes (#139 §5): operator blindness, the store only uses
 * `@/api/platform` (mocked here; `fetch` is stubbed and must never be called);
 * a backend error's `detail` is never shown, every message comes from the i18n
 * catalogs (compared with `t(...)` after checking the English catalog has the
 * key); no name or email ever reaches the console. The real toasts store is
 * used. No component is mounted and nothing touches the network.
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
import { usePlatformOrgDetailStore } from '@/stores/platformOrgDetail';
import { useToastStore } from '@/stores/toasts';
import type { UserAction, UserConfirmKind } from '@/services/platformOrgs';
import type {
  OrgInvitation,
  OrgStatus,
  PlatformOrg,
  PlatformOrgListResponse,
  PlatformOrgMetadata,
  PlatformUser,
  PlatformUserListResponse,
} from '@/api/types';

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
const UNKNOWN_ORG = '9e506273-8f91-42a3-8ebf-3a4b5c6d7e8f';

const ADA = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d';
const BRUNO = 'b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e';
const CARLA = 'c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f';
const DORA = 'd4e5f6a7-b8c9-4d0e-9f2a-3b4c5d6e7f80';
const GINA = 'e5f6a7b8-c9d0-4e1f-8a3b-4c5d6e7f8091';
const HUGO = 'f6a7b8c9-d0e1-4f2a-9b4c-5d6e7f809102';
const NEW_ADMIN = '07b8c9d0-e1f2-4a3b-8c5d-6e7f80910213';
const ZOE = '18c9d0e1-f2a3-4b4c-9d6e-7f8091021324';
const UNKNOWN_USER = '29d0e1f2-a3b4-4c5d-8e7f-809102132435';
const INVITE = '3ae1f203-b4c5-4d6e-9f80-910213243546';

const LATER = '2026-10-04T12:00:00Z';

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

/** A fresh copy of the org `id` with `overrides` applied. */
function org(id: string, overrides: Partial<PlatformOrg> = {}): PlatformOrg {
  const base = ORGS[id];
  if (base === undefined) throw new Error(`no fixture org ${id}`);
  return { ...base, ...overrides };
}

/** The org list with Gamma first (the detail view must pick its own org, not the first one). */
function allOrgs(): PlatformOrg[] {
  return [org(GAMMA), org(ACME), org(BETA)];
}

/** The org list with Acme's status set to `status`. */
function orgsWithAcme(status: OrgStatus): PlatformOrg[] {
  return allOrgs().map((item) => (item.id === ACME ? { ...item, status } : item));
}

const USERS: Readonly<Record<string, PlatformUser>> = {
  [ADA]: {
    id: ADA,
    name: 'Ada Admin',
    email: 'ada@acme.ch',
    role: 'org_admin',
    status: 'active',
    created_at: '2026-01-10T09:05:00Z',
    last_login_at: '2026-10-01T08:00:00Z',
  },
  [BRUNO]: {
    id: BRUNO,
    name: 'Bruno Editor',
    email: 'bruno@acme.ch',
    role: 'editor',
    status: 'active',
    created_at: '2026-02-10T10:00:00Z',
    last_login_at: '2026-09-30T12:30:00Z',
  },
  [CARLA]: {
    id: CARLA,
    name: 'Carla Gone',
    email: 'carla@acme.ch',
    role: 'editor',
    status: 'deactivated',
    created_at: '2026-03-01T11:00:00Z',
    last_login_at: null,
  },
  [DORA]: {
    id: DORA,
    name: null,
    email: 'dora@acme.ch',
    role: 'editor',
    status: 'active',
    created_at: '2026-04-12T07:45:00Z',
    last_login_at: '2026-09-01T16:00:00Z',
  },
  [GINA]: {
    id: GINA,
    name: null,
    email: 'gina@acme.ch',
    role: 'org_admin',
    status: 'invited',
    created_at: '2026-09-28T10:00:00Z',
    last_login_at: null,
  },
  [HUGO]: {
    id: HUGO,
    name: null,
    email: 'hugo@acme.ch',
    role: 'editor',
    status: 'invited',
    created_at: '2026-09-29T10:00:00Z',
    last_login_at: null,
  },
  [NEW_ADMIN]: {
    id: NEW_ADMIN,
    name: null,
    email: 'new.admin@acme.ch',
    role: 'org_admin',
    status: 'invited',
    created_at: LATER,
    last_login_at: null,
  },
  [ZOE]: {
    id: ZOE,
    name: 'Zoe Beta',
    email: 'zoe@beta.ch',
    role: 'org_admin',
    status: 'active',
    created_at: '2026-02-01T08:35:00Z',
    last_login_at: '2026-08-14T09:00:00Z',
  },
};

/** A fresh copy of the user `id` with `overrides` applied. */
function user(id: string, overrides: Partial<PlatformUser> = {}): PlatformUser {
  const base = USERS[id];
  if (base === undefined) throw new Error(`no fixture user ${id}`);
  return { ...base, ...overrides };
}

/** Acme's users: an active Org Admin (Ada), active editors, a deactivated editor and two invited accounts. */
function acmeUsers(): PlatformUser[] {
  return [ADA, BRUNO, CARLA, DORA, GINA, HUGO].map((id) => user(id));
}

/** Acme's users after Ada (the only Org Admin who ever logged in) was deactivated: Gina's invitation is re-invitable. */
function noActiveAdminUsers(): PlatformUser[] {
  return [user(ADA, { status: 'deactivated' }), user(BRUNO), user(CARLA), user(GINA), user(HUGO)];
}

/** `users` with the user `id` replaced by `replacement`. */
function usersWith(users: PlatformUser[], id: string, replacement: PlatformUser): PlatformUser[] {
  return users.map((item) => (item.id === id ? replacement : item));
}

function betaUsers(): PlatformUser[] {
  return [user(ZOE)];
}

function metadata(used = 5, limit = 10): PlatformOrgMetadata {
  return { seats: { used, limit }, storage_used_bytes: 123_456, chat_count: 0, file_count: 0 };
}

function betaMetadata(): PlatformOrgMetadata {
  return { seats: { used: 1, limit: 5 }, storage_used_bytes: 42, chat_count: 0, file_count: 0 };
}

function invitation(email = 'gina@acme.ch'): OrgInvitation {
  return {
    id: INVITE,
    email,
    role: 'org_admin',
    sent_at: LATER,
    expires_at: '2026-10-07T12:00:00Z',
    expired: false,
  };
}

/** Every name and email the fixtures and flows use: none may ever reach the console. */
const PERSONAL_DATA = [
  'Acme AG',
  'Beta GmbH',
  'Ada Admin',
  'ada@acme.ch',
  'Bruno Editor',
  'bruno@acme.ch',
  'Carla Gone',
  'carla@acme.ch',
  'dora@acme.ch',
  'gina@acme.ch',
  'hugo@acme.ch',
  'new.admin@acme.ch',
  'Zoe Beta',
  'zoe@beta.ch',
];

/** Backend error text the store must never show (it names a user on purpose). */
const DETAIL = 'backend detail: ada@acme.ch is the last Org Admin of Acme AG';

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

type Store = ReturnType<typeof usePlatformOrgDetailStore>;
type LoadCall = 'listPlatformOrgs' | 'getPlatformOrgMetadata' | 'listPlatformOrgUsers';

interface LoadData {
  orgs?: PlatformOrg[];
  users?: PlatformUser[];
  metadata?: PlatformOrgMetadata;
  /** One of the three load calls rejects with `error` instead. */
  fail?: { call: LoadCall; error: unknown };
}

/** Arranges one answer for each of the three load calls (default: Acme's data). */
function arrangeLoad(data: LoadData = {}): void {
  const answers: Record<LoadCall, unknown> = {
    listPlatformOrgs: { organizations: data.orgs ?? allOrgs() },
    getPlatformOrgMetadata: data.metadata ?? metadata(),
    listPlatformOrgUsers: { users: data.users ?? acmeUsers() },
  };
  for (const call of Object.keys(answers) as LoadCall[]) {
    if (data.fail?.call === call) {
      mockOf(call).mockRejectedValueOnce(data.fail.error);
    } else {
      mockOf(call).mockResolvedValueOnce(answers[call]);
    }
  }
}

/** The store showing `orgId` (default Acme) loaded with `data`; API call logs and toasts cleared. */
async function setup(data: LoadData = {}, orgId: string = ACME): Promise<Store> {
  const store = usePlatformOrgDetailStore();
  arrangeLoad(data);
  await store.load(orgId);
  if (store.org === null) throw new Error('setup: load() did not load the org');
  for (const mock of Object.values(api)) mock.mockClear();
  useToastStore().toasts.splice(0);
  return store;
}

/** Hand-settled answers for the metadata and users calls of `orgId` (the org list answers at once). */
interface PendingLoad {
  metadata: ReturnType<typeof deferred<PlatformOrgMetadata>>;
  users: ReturnType<typeof deferred<PlatformUserListResponse>>;
}

/** Routes the metadata/users calls by org id to hand-settled answers; the org list always answers at once. */
function arrangePendingLoads(orgIds: string[]): Record<string, PendingLoad> {
  const loads: Record<string, PendingLoad> = {};
  for (const id of orgIds) {
    loads[id] = { metadata: deferred<PlatformOrgMetadata>(), users: deferred<PlatformUserListResponse>() };
  }
  api.listPlatformOrgs.mockResolvedValue({ organizations: allOrgs() });
  api.getPlatformOrgMetadata.mockImplementation((id: string) => {
    const pending = loads[id];
    return pending === undefined ? Promise.reject(apiError(404)) : pending.metadata.promise;
  });
  api.listPlatformOrgUsers.mockImplementation((id: string) => {
    const pending = loads[id];
    return pending === undefined ? Promise.reject(apiError(404)) : pending.users.promise;
  });
  return loads;
}

/** A copy of everything the detail view shows for an org (copies, so later in-place changes can't rewrite it). */
function shown(store: Store): {
  org: PlatformOrg | null;
  metadata: PlatformOrgMetadata | null;
  users: PlatformUser[];
  notFound: boolean;
  loadError: string | null;
} {
  return {
    org: store.org === null ? null : { ...store.org },
    metadata: store.metadata === null ? null : { ...store.metadata, seats: { ...store.metadata.seats } },
    users: store.users.map((item) => ({ ...item })),
    notFound: store.notFound,
    loadError: store.loadError,
  };
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

describe('platformOrgDetailStore initial state', () => {
  it('is the "platformOrgDetail" store showing no org, no metadata, no users and no sheet', () => {
    const store = usePlatformOrgDetailStore();

    expect({
      id: store.$id,
      orgId: store.orgId,
      org: store.org,
      metadata: store.metadata,
      users: store.users,
      loading: store.loading,
      loadError: store.loadError,
      notFound: store.notFound,
      pending: store.pending,
      pendingCopy: store.pendingCopy,
      actionBusy: store.actionBusy,
      actionError: store.actionError,
      reinviteUserId: store.reinviteUserId,
      reinviteBusy: store.reinviteBusy,
      reinviteError: store.reinviteError,
      seatText: store.seatText,
    }).toStrictEqual({
      id: 'platformOrgDetail',
      orgId: null,
      org: null,
      metadata: null,
      users: [],
      loading: false,
      loadError: null,
      notFound: false,
      pending: null,
      pendingCopy: null,
      actionBusy: false,
      actionError: null,
      reinviteUserId: null,
      reinviteBusy: false,
      reinviteError: null,
      seatText: null,
    });
  });

  it('offers no action for anyone and asks nothing of the server before a load', () => {
    const store = usePlatformOrgDetailStore();

    expect({ actions: store.actionsFor(BRUNO), calls: apiCalls(), fetchCalls: fetchSpy.mock.calls.length }).toStrictEqual({
      actions: [],
      calls: NO_CALLS,
      fetchCalls: 0,
    });
  });
});

// --- load(orgId) -----------------------------------------------------------------

describe('platformOrgDetailStore load', () => {
  it.each([
    { label: 'a malformed id', orgId: 'not-a-uuid' },
    { label: 'an empty id', orgId: '' },
    { label: 'a path traversal', orgId: '../x' },
    { label: 'a UUID with a trailing character', orgId: `${ACME}x` },
    { label: 'a UUID with a slash appended', orgId: `${ACME}/users` },
  ])('treats $label as not found without any request', async ({ orgId }) => {
    const store = usePlatformOrgDetailStore();

    const outcome = await outcomeOf(store.load(orgId));

    expect({
      outcome,
      notFound: store.notFound,
      org: store.org,
      loadError: store.loadError,
      calls: apiCalls(),
      fetchCalls: fetchSpy.mock.calls.length,
    }).toStrictEqual({
      outcome: 'resolved',
      notFound: true,
      org: null,
      loadError: null,
      calls: NO_CALLS,
      fetchCalls: 0,
    });
  });

  it('asks for the org list, the org metadata and the org users together, with the right org id', async () => {
    const list = deferred<PlatformOrgListResponse>();
    const meta = deferred<PlatformOrgMetadata>();
    const users = deferred<PlatformUserListResponse>();
    api.listPlatformOrgs.mockReturnValueOnce(list.promise);
    api.getPlatformOrgMetadata.mockReturnValueOnce(meta.promise);
    api.listPlatformOrgUsers.mockReturnValueOnce(users.promise);
    const store = usePlatformOrgDetailStore();

    const done = outcomeOf(store.load(ACME));
    await flush();
    // Copies: `mock.calls` is a live array that the later calls would extend.
    const before = {
      listArgs: api.listPlatformOrgs.mock.calls.map((args) => [...args]),
      metadataArgs: api.getPlatformOrgMetadata.mock.calls.map((args) => [...args]),
      usersArgs: api.listPlatformOrgUsers.mock.calls.map((args) => [...args]),
    };
    list.resolve({ organizations: allOrgs() });
    meta.resolve(metadata());
    users.resolve({ users: acmeUsers() });
    const outcome = await done;

    expect({ before, outcome, calls: apiCalls() }).toStrictEqual({
      before: { listArgs: [[]], metadataArgs: [[ACME]], usersArgs: [[ACME]] },
      outcome: 'resolved',
      calls: { ...NO_CALLS, listPlatformOrgs: 1, getPlatformOrgMetadata: 1, listPlatformOrgUsers: 1 },
    });
  });

  it('shows the org taken from the list, its metadata and its users in API order', async () => {
    arrangeLoad();
    const store = usePlatformOrgDetailStore();

    await store.load(ACME);

    expect({ orgId: store.orgId, loading: store.loading, ...shown(store) }).toStrictEqual({
      orgId: ACME,
      loading: false,
      org: org(ACME),
      metadata: metadata(),
      users: acmeUsers(),
      notFound: false,
      loadError: null,
    });
  });

  it('is loading while the requests are in flight, and not afterwards', async () => {
    const meta = deferred<PlatformOrgMetadata>();
    api.listPlatformOrgs.mockResolvedValueOnce({ organizations: allOrgs() });
    api.getPlatformOrgMetadata.mockReturnValueOnce(meta.promise);
    api.listPlatformOrgUsers.mockResolvedValueOnce({ users: acmeUsers() });
    const store = usePlatformOrgDetailStore();

    const done = store.load(ACME);
    await flush();
    const during = { loading: store.loading, org: store.org };
    meta.resolve(metadata());
    await done;

    expect({ during, after: store.loading }).toStrictEqual({ during: { loading: true, org: null }, after: false });
  });

  it('is not found when the org is missing from the org list', async () => {
    arrangeLoad({ orgs: [org(BETA), org(GAMMA)] });
    const store = usePlatformOrgDetailStore();

    const outcome = await outcomeOf(store.load(UNKNOWN_ORG));

    expect({ outcome, notFound: store.notFound, org: store.org, loadError: store.loadError }).toStrictEqual({
      outcome: 'resolved',
      notFound: true,
      org: null,
      loadError: null,
    });
  });

  it.each(['listPlatformOrgs', 'getPlatformOrgMetadata', 'listPlatformOrgUsers'] satisfies LoadCall[])(
    'is not found, without a loadError, when %s answers 404',
    async (call) => {
      arrangeLoad({ fail: { call, error: apiError(404) } });
      const store = usePlatformOrgDetailStore();

      const outcome = await outcomeOf(store.load(ACME));

      expect({ outcome, notFound: store.notFound, org: store.org, loadError: store.loadError }).toStrictEqual({
        outcome: 'resolved',
        notFound: true,
        org: null,
        loadError: null,
      });
    },
  );

  it.each([
    { label: 'a 403 on the metadata', call: 'getPlatformOrgMetadata', error: () => apiError(403), key: 'platform.error.forbidden' },
    { label: 'a 429 on the users', call: 'listPlatformOrgUsers', error: () => apiError(429), key: 'platform.error.rateLimited' },
    { label: 'a 500 on the org list', call: 'listPlatformOrgs', error: () => apiError(500), key: 'platform.error.generic' },
    {
      label: 'a 409 invalid_status (an org error) on the users',
      call: 'listPlatformOrgUsers',
      error: () => apiError(409, 'invalid_status'),
      key: 'platform.error.orgInvalidStatus',
    },
    {
      label: 'a network failure',
      call: 'getPlatformOrgMetadata',
      error: () => new TypeError('Failed to fetch'),
      key: 'platform.error.generic',
    },
  ] satisfies Array<{ label: string; call: LoadCall; error: () => unknown; key: string }>)(
    'sets a translated loadError (not "not found") for $label and never throws',
    async ({ call, error, key }) => {
      arrangeLoad({ fail: { call, error: error() } });
      const store = usePlatformOrgDetailStore();

      const outcome = await outcomeOf(store.load(ACME));

      expect({
        outcome,
        loadError: store.loadError,
        notFound: store.notFound,
        loading: store.loading,
        echoesDetail: String(store.loadError).includes(DETAIL),
      }).toStrictEqual({ outcome: 'resolved', loadError: msg(key), notFound: false, loading: false, echoesDetail: false });
    },
  );

  it("clears the previous org's data, pending action and errors before another org's data arrives", async () => {
    const store = await setup();
    store.requestDeactivate(ADA);
    api.deactivatePlatformUser.mockRejectedValueOnce(apiError(409, 'last_admin'));
    await store.confirmPending();
    const before = { org: store.org?.id, pending: { ...store.pending }, actionError: store.actionError };
    const loads = arrangePendingLoads([BETA]);

    const done = store.load(BETA);
    await flush();
    const during = {
      ...shown(store),
      pending: store.pending === null ? null : { ...store.pending },
      pendingCopy: store.pendingCopy,
      actionError: store.actionError,
      seatText: store.seatText,
      actionsForAda: store.actionsFor(ADA),
    };
    loads[BETA]?.metadata.resolve(betaMetadata());
    loads[BETA]?.users.resolve({ users: betaUsers() });
    await done;

    expect({ before, during, after: shown(store) }).toStrictEqual({
      before: { org: ACME, pending: { kind: 'deactivate', userId: ADA }, actionError: msg('platform.error.lastAdmin') },
      during: {
        org: null,
        metadata: null,
        users: [],
        notFound: false,
        loadError: null,
        pending: null,
        pendingCopy: null,
        actionError: null,
        seatText: null,
        actionsForAda: [],
      },
      after: { org: org(BETA), metadata: betaMetadata(), users: betaUsers(), notFound: false, loadError: null },
    });
  });

  it('clears "not found" as soon as a new load starts', async () => {
    const store = usePlatformOrgDetailStore();
    await store.load('not-a-uuid');
    const before = store.notFound;
    const loads = arrangePendingLoads([ACME]);

    const done = store.load(ACME);
    await flush();
    const during = store.notFound;
    loads[ACME]?.metadata.resolve(metadata());
    loads[ACME]?.users.resolve({ users: acmeUsers() });
    await done;

    expect({ before, during, after: store.notFound, org: store.org }).toStrictEqual({
      before: true,
      during: false,
      after: false,
      org: org(ACME),
    });
  });

  it('clears the loadError as soon as a new load starts', async () => {
    const store = usePlatformOrgDetailStore();
    arrangeLoad({ fail: { call: 'getPlatformOrgMetadata', error: apiError(403) } });
    await store.load(ACME);
    const before = store.loadError;
    const loads = arrangePendingLoads([ACME]);

    const done = store.load(ACME);
    await flush();
    const during = store.loadError;
    loads[ACME]?.metadata.resolve(metadata());
    loads[ACME]?.users.resolve({ users: acmeUsers() });
    await done;

    expect({ before, during, after: store.loadError }).toStrictEqual({
      before: msg('platform.error.forbidden'),
      during: null,
      after: null,
    });
  });

  it('ignores the answer of an earlier load that arrives after a newer load finished', async () => {
    const loads = arrangePendingLoads([ACME, BETA]);
    const store = usePlatformOrgDetailStore();

    const first = store.load(ACME);
    const second = store.load(BETA);
    loads[BETA]?.metadata.resolve(betaMetadata());
    loads[BETA]?.users.resolve({ users: betaUsers() });
    await second;
    loads[ACME]?.metadata.resolve(metadata());
    loads[ACME]?.users.resolve({ users: acmeUsers() });
    await first;

    expect({ orgId: store.orgId, ...shown(store) }).toStrictEqual({
      orgId: BETA,
      org: org(BETA),
      metadata: betaMetadata(),
      users: betaUsers(),
      notFound: false,
      loadError: null,
    });
  });

  it('never shows the earlier org when its answer arrives while the newer load is still in flight', async () => {
    const loads = arrangePendingLoads([ACME, BETA]);
    const store = usePlatformOrgDetailStore();

    const first = store.load(ACME);
    const second = store.load(BETA);
    loads[ACME]?.metadata.resolve(metadata());
    loads[ACME]?.users.resolve({ users: acmeUsers() });
    await first;
    const whileNewerInFlight = shown(store);
    loads[BETA]?.metadata.resolve(betaMetadata());
    loads[BETA]?.users.resolve({ users: betaUsers() });
    await second;

    expect({ whileNewerInFlight, after: shown(store) }).toStrictEqual({
      whileNewerInFlight: { org: null, metadata: null, users: [], notFound: false, loadError: null },
      after: { org: org(BETA), metadata: betaMetadata(), users: betaUsers(), notFound: false, loadError: null },
    });
  });

  it.each([
    { label: 'a 403', error: () => apiError(403) },
    { label: 'a 404', error: () => apiError(404) },
  ])('ignores $label of an earlier load that fails after a newer load started', async ({ error }) => {
    const loads = arrangePendingLoads([ACME, BETA]);
    const store = usePlatformOrgDetailStore();

    const first = store.load(ACME);
    const second = store.load(BETA);
    loads[ACME]?.metadata.reject(error());
    loads[ACME]?.users.resolve({ users: acmeUsers() });
    await first;
    const afterStaleFailure = { notFound: store.notFound, loadError: store.loadError };
    loads[BETA]?.metadata.resolve(betaMetadata());
    loads[BETA]?.users.resolve({ users: betaUsers() });
    await second;

    expect({ afterStaleFailure, after: shown(store) }).toStrictEqual({
      afterStaleFailure: { notFound: false, loadError: null },
      after: { org: org(BETA), metadata: betaMetadata(), users: betaUsers(), notFound: false, loadError: null },
    });
  });

  it('ignores an earlier org answer after a newer load with a malformed id', async () => {
    const loads = arrangePendingLoads([ACME]);
    const store = usePlatformOrgDetailStore();

    const first = store.load(ACME);
    await store.load('not-a-uuid');
    loads[ACME]?.metadata.resolve(metadata());
    loads[ACME]?.users.resolve({ users: acmeUsers() });
    await first;

    expect(shown(store)).toStrictEqual({ org: null, metadata: null, users: [], notFound: true, loadError: null });
  });
});

// --- seatText ------------------------------------------------------------------------

describe('platformOrgDetailStore seatText', () => {
  it('is the catalog seat text from the metadata seats', async () => {
    const store = await setup({ metadata: metadata(7, 12) });

    expect(store.seatText).toBe(msg('platform.orgs.seats', { used: 7, limit: 12 }));
  });

  it('follows the refreshed metadata after a user is deactivated', async () => {
    const store = await setup({ metadata: metadata(5, 10) });
    api.deactivatePlatformUser.mockResolvedValueOnce(user(BRUNO, { status: 'deactivated' }));
    api.getPlatformOrgMetadata.mockResolvedValueOnce(metadata(4, 10));
    store.requestDeactivate(BRUNO);

    await store.confirmPending();

    expect(store.seatText).toBe(msg('platform.orgs.seats', { used: 4, limit: 10 }));
  });
});

// --- actionsFor(userId) --------------------------------------------------------------

describe('platformOrgDetailStore actionsFor', () => {
  it.each([
    { label: 'an active editor of an active org', status: 'active', users: acmeUsers(), userId: BRUNO, expected: ['deactivate', 'resetPassword'] },
    { label: 'an active Org Admin of an active org', status: 'active', users: acmeUsers(), userId: ADA, expected: ['deactivate', 'resetPassword'] },
    { label: 'a deactivated user of an active org', status: 'active', users: acmeUsers(), userId: CARLA, expected: ['reactivate'] },
    {
      label: 'the invited Org Admin of an active org that has an active Org Admin',
      status: 'active',
      users: acmeUsers(),
      userId: GINA,
      expected: [],
    },
    {
      label: 'the invited Org Admin of an active org without an active Org Admin',
      status: 'active',
      users: noActiveAdminUsers(),
      userId: GINA,
      expected: ['reinvite'],
    },
    {
      label: 'an invited editor of an active org without an active Org Admin',
      status: 'active',
      users: noActiveAdminUsers(),
      userId: HUGO,
      expected: [],
    },
    { label: 'an active user of a deactivated org', status: 'deactivated', users: acmeUsers(), userId: BRUNO, expected: ['deactivate'] },
    { label: 'a deactivated user of a deactivated org', status: 'deactivated', users: acmeUsers(), userId: CARLA, expected: ['reactivate'] },
    {
      label: 'the invited Org Admin of a deactivated org without an active Org Admin',
      status: 'deactivated',
      users: noActiveAdminUsers(),
      userId: GINA,
      expected: [],
    },
    { label: 'an active user of an org pending deletion', status: 'pending_deletion', users: acmeUsers(), userId: BRUNO, expected: ['deactivate'] },
    { label: 'a deactivated user of an org pending deletion', status: 'pending_deletion', users: acmeUsers(), userId: CARLA, expected: [] },
    {
      label: 'the invited Org Admin of an org pending deletion without an active Org Admin',
      status: 'pending_deletion',
      users: noActiveAdminUsers(),
      userId: GINA,
      expected: [],
    },
    { label: 'an unknown user', status: 'active', users: acmeUsers(), userId: UNKNOWN_USER, expected: [] },
  ] satisfies Array<{ label: string; status: OrgStatus; users: PlatformUser[]; userId: string; expected: UserAction[] }>)(
    'offers $expected to $label',
    async ({ status, users, userId, expected }) => {
      const store = await setup({ orgs: orgsWithAcme(status), users });

      expect(store.actionsFor(userId)).toStrictEqual(expected);
    },
  );
});

// --- request* and cancelPending ---------------------------------------------------------

describe('platformOrgDetailStore request* (open the confirm sheet, never call the API)', () => {
  it.each([
    { label: 'deactivate an active editor', status: 'active', request: (s: Store) => s.requestDeactivate(BRUNO), pending: { kind: 'deactivate', userId: BRUNO } },
    { label: 'deactivate the active Org Admin', status: 'active', request: (s: Store) => s.requestDeactivate(ADA), pending: { kind: 'deactivate', userId: ADA } },
    { label: 'reactivate a deactivated user', status: 'active', request: (s: Store) => s.requestReactivate(CARLA), pending: { kind: 'reactivate', userId: CARLA } },
    { label: 'reset the password of an active user', status: 'active', request: (s: Store) => s.requestPasswordReset(BRUNO), pending: { kind: 'resetPassword', userId: BRUNO } },
    { label: 'deactivate a user of a deactivated org', status: 'deactivated', request: (s: Store) => s.requestDeactivate(BRUNO), pending: { kind: 'deactivate', userId: BRUNO } },
    { label: 'reactivate a user of a deactivated org', status: 'deactivated', request: (s: Store) => s.requestReactivate(CARLA), pending: { kind: 'reactivate', userId: CARLA } },
  ] satisfies Array<{
    label: string;
    status: OrgStatus;
    request: (s: Store) => void;
    pending: { kind: UserConfirmKind; userId: string };
  }>)('opens the confirm sheet to $label without a request', async ({ status, request, pending }) => {
    const store = await setup({ orgs: orgsWithAcme(status) });

    request(store);

    expect({ pending: store.pending, calls: apiCalls(), fetchCalls: fetchSpy.mock.calls.length }).toStrictEqual({
      pending,
      calls: NO_CALLS,
      fetchCalls: 0,
    });
  });

  it.each([
    { label: 'deactivate a deactivated user', status: 'active', request: (s: Store) => s.requestDeactivate(CARLA) },
    { label: 'deactivate an invited account', status: 'active', request: (s: Store) => s.requestDeactivate(GINA) },
    { label: 'reactivate an active user', status: 'active', request: (s: Store) => s.requestReactivate(BRUNO) },
    { label: 'reactivate an invited account', status: 'active', request: (s: Store) => s.requestReactivate(HUGO) },
    { label: 'reset the password of a deactivated user', status: 'active', request: (s: Store) => s.requestPasswordReset(CARLA) },
    { label: 'reset the password of an invited account', status: 'active', request: (s: Store) => s.requestPasswordReset(GINA) },
    { label: 'reset a password in a deactivated org', status: 'deactivated', request: (s: Store) => s.requestPasswordReset(BRUNO) },
    { label: 'reset a password in an org pending deletion', status: 'pending_deletion', request: (s: Store) => s.requestPasswordReset(BRUNO) },
    { label: 'reactivate a user of an org pending deletion', status: 'pending_deletion', request: (s: Store) => s.requestReactivate(CARLA) },
    { label: 'deactivate an unknown user', status: 'active', request: (s: Store) => s.requestDeactivate(UNKNOWN_USER) },
    { label: 'reactivate an unknown user', status: 'active', request: (s: Store) => s.requestReactivate(UNKNOWN_USER) },
    { label: 'reset the password of an unknown user', status: 'active', request: (s: Store) => s.requestPasswordReset(UNKNOWN_USER) },
  ] satisfies Array<{ label: string; status: OrgStatus; request: (s: Store) => void }>)(
    'does not open the confirm sheet to $label',
    async ({ status, request }) => {
      const store = await setup({ orgs: orgsWithAcme(status) });

      request(store);

      expect({ pending: store.pending, pendingCopy: store.pendingCopy, calls: apiCalls() }).toStrictEqual({
        pending: null,
        pendingCopy: null,
        calls: NO_CALLS,
      });
    },
  );

  it('opens nothing before an org is loaded', () => {
    const store = usePlatformOrgDetailStore();

    store.requestDeactivate(BRUNO);
    store.requestReactivate(CARLA);
    store.requestPasswordReset(BRUNO);

    expect({ pending: store.pending, calls: apiCalls() }).toStrictEqual({ pending: null, calls: NO_CALLS });
  });

  it('a new request clears the actionError of a failed confirmation', async () => {
    const store = await setup();
    api.deactivatePlatformUser.mockRejectedValueOnce(apiError(409, 'last_admin'));
    store.requestDeactivate(ADA);
    await store.confirmPending();
    const before = store.actionError;

    store.requestPasswordReset(BRUNO);

    expect({ before, actionError: store.actionError, pending: store.pending }).toStrictEqual({
      before: msg('platform.error.lastAdmin'),
      actionError: null,
      pending: { kind: 'resetPassword', userId: BRUNO },
    });
  });

  it('cancelPending closes the confirm sheet without a request', async () => {
    const store = await setup();
    store.requestDeactivate(BRUNO);
    const before = store.pending === null ? null : { ...store.pending };

    store.cancelPending();
    const result = await store.confirmPending();

    expect({ before, pending: store.pending, result, calls: apiCalls() }).toStrictEqual({
      before: { kind: 'deactivate', userId: BRUNO },
      pending: null,
      result: false,
      calls: NO_CALLS,
    });
  });
});

// --- confirmPending -------------------------------------------------------------------

describe('platformOrgDetailStore confirmPending', () => {
  it('deactivates the user with one request, replaces the user, refreshes the metadata and toasts', async () => {
    const store = await setup();
    const updated = user(BRUNO, { status: 'deactivated' });
    api.deactivatePlatformUser.mockResolvedValueOnce(updated);
    api.getPlatformOrgMetadata.mockResolvedValueOnce(metadata(4, 10));
    store.requestDeactivate(BRUNO);

    const result = await store.confirmPending();

    expect({
      result,
      calls: apiCalls(),
      actionArgs: api.deactivatePlatformUser.mock.calls,
      metadataArgs: api.getPlatformOrgMetadata.mock.calls,
      refreshedAfterTheAction:
        (api.getPlatformOrgMetadata.mock.invocationCallOrder[0] ?? 0) >
        (api.deactivatePlatformUser.mock.invocationCallOrder[0] ?? Infinity),
      users: store.users,
      metadata: store.metadata,
      pending: store.pending,
      actionError: store.actionError,
      actionBusy: store.actionBusy,
      actionsForBruno: store.actionsFor(BRUNO),
      toasts: toastTitles(),
    }).toStrictEqual({
      result: true,
      calls: { ...NO_CALLS, deactivatePlatformUser: 1, getPlatformOrgMetadata: 1 },
      actionArgs: [[ACME, BRUNO]],
      metadataArgs: [[ACME]],
      refreshedAfterTheAction: true,
      users: usersWith(acmeUsers(), BRUNO, updated),
      metadata: metadata(4, 10),
      pending: null,
      actionError: null,
      actionBusy: false,
      actionsForBruno: ['reactivate'],
      toasts: [{ kind: 'success', title: msg('platform.toast.userDeactivated') }],
    });
  });

  it('reactivates the user with one request, replaces the user, refreshes the metadata and toasts', async () => {
    const store = await setup();
    const updated = user(CARLA, { status: 'active', last_login_at: null });
    api.reactivatePlatformUser.mockResolvedValueOnce(updated);
    api.getPlatformOrgMetadata.mockResolvedValueOnce(metadata(6, 10));
    store.requestReactivate(CARLA);

    const result = await store.confirmPending();

    expect({
      result,
      calls: apiCalls(),
      actionArgs: api.reactivatePlatformUser.mock.calls,
      metadataArgs: api.getPlatformOrgMetadata.mock.calls,
      refreshedAfterTheAction:
        (api.getPlatformOrgMetadata.mock.invocationCallOrder[0] ?? 0) >
        (api.reactivatePlatformUser.mock.invocationCallOrder[0] ?? Infinity),
      users: store.users,
      metadata: store.metadata,
      pending: store.pending,
      toasts: toastTitles(),
    }).toStrictEqual({
      result: true,
      calls: { ...NO_CALLS, reactivatePlatformUser: 1, getPlatformOrgMetadata: 1 },
      actionArgs: [[ACME, CARLA]],
      metadataArgs: [[ACME]],
      refreshedAfterTheAction: true,
      users: usersWith(acmeUsers(), CARLA, updated),
      metadata: metadata(6, 10),
      pending: null,
      toasts: [{ kind: 'success', title: msg('platform.toast.userReactivated') }],
    });
  });

  it('sends a password reset (202) with one request and toasts, without touching the users', async () => {
    const store = await setup();
    api.resetPlatformUserPassword.mockResolvedValueOnce(undefined);
    store.requestPasswordReset(BRUNO);

    const result = await store.confirmPending();

    expect({
      result,
      resetArgs: api.resetPlatformUserPassword.mock.calls,
      otherActionCalls: {
        deactivatePlatformUser: api.deactivatePlatformUser.mock.calls.length,
        reactivatePlatformUser: api.reactivatePlatformUser.mock.calls.length,
        reinvitePlatformUser: api.reinvitePlatformUser.mock.calls.length,
      },
      users: store.users,
      pending: store.pending,
      actionError: store.actionError,
      toasts: toastTitles(),
    }).toStrictEqual({
      result: true,
      resetArgs: [[ACME, BRUNO]],
      otherActionCalls: { deactivatePlatformUser: 0, reactivatePlatformUser: 0, reinvitePlatformUser: 0 },
      users: acmeUsers(),
      pending: null,
      actionError: null,
      toasts: [{ kind: 'success', title: msg('platform.toast.passwordResetSent') }],
    });
  });

  it('keeps the old metadata and reports no error when the refresh after an action fails', async () => {
    const store = await setup({ metadata: metadata(5, 10) });
    const updated = user(BRUNO, { status: 'deactivated' });
    api.deactivatePlatformUser.mockResolvedValueOnce(updated);
    api.getPlatformOrgMetadata.mockRejectedValueOnce(apiError(500));
    store.requestDeactivate(BRUNO);

    const result = await store.confirmPending();

    expect({
      result,
      metadata: store.metadata,
      users: store.users,
      pending: store.pending,
      actionError: store.actionError,
      loadError: store.loadError,
      notFound: store.notFound,
      toasts: toastTitles(),
    }).toStrictEqual({
      result: true,
      metadata: metadata(5, 10),
      users: usersWith(acmeUsers(), BRUNO, updated),
      pending: null,
      actionError: null,
      loadError: null,
      notFound: false,
      toasts: [{ kind: 'success', title: msg('platform.toast.userDeactivated') }],
    });
  });

  it.each([
    {
      label: 'deactivating the last active Org Admin (409 last_admin)',
      request: (s: Store) => s.requestDeactivate(ADA),
      call: 'deactivatePlatformUser',
      error: () => apiError(409, 'last_admin'),
      pending: { kind: 'deactivate', userId: ADA },
      key: 'platform.error.lastAdmin',
    },
    {
      label: 'reactivating without a free seat (409 seat_limit)',
      request: (s: Store) => s.requestReactivate(CARLA),
      call: 'reactivatePlatformUser',
      error: () => apiError(409, 'seat_limit'),
      pending: { kind: 'reactivate', userId: CARLA },
      key: 'platform.error.seatLimit',
    },
    {
      label: 'a reset for a user whose status changed meanwhile (409 invalid_status)',
      request: (s: Store) => s.requestPasswordReset(BRUNO),
      call: 'resetPlatformUserPassword',
      error: () => apiError(409, 'invalid_status'),
      pending: { kind: 'resetPassword', userId: BRUNO },
      key: 'platform.error.userInvalidStatus',
    },
    {
      label: 'a user that is gone (404)',
      request: (s: Store) => s.requestDeactivate(BRUNO),
      call: 'deactivatePlatformUser',
      error: () => apiError(404),
      pending: { kind: 'deactivate', userId: BRUNO },
      key: 'platform.error.userNotFound',
    },
    {
      label: 'a network failure',
      request: (s: Store) => s.requestReactivate(CARLA),
      call: 'reactivatePlatformUser',
      error: () => new TypeError('Failed to fetch'),
      pending: { kind: 'reactivate', userId: CARLA },
      key: 'platform.error.generic',
    },
  ] satisfies Array<{
    label: string;
    request: (s: Store) => void;
    call: ApiName;
    error: () => unknown;
    pending: { kind: UserConfirmKind; userId: string };
    key: string;
  }>)('keeps the confirm sheet open with a translated actionError for $label', async ({ request, call, error, pending, key }) => {
    const store = await setup();
    mockOf(call).mockRejectedValueOnce(error());
    request(store);

    const outcome = await outcomeOf(store.confirmPending());

    expect({
      outcome,
      pending: store.pending,
      calls: mockOf(call).mock.calls.length,
      actionError: store.actionError,
      actionBusy: store.actionBusy,
      users: store.users,
      toasts: toastTitles(),
    }).toStrictEqual({
      outcome: 'resolved',
      pending,
      calls: 1,
      actionError: msg(key),
      actionBusy: false,
      users: acmeUsers(),
      toasts: [],
    });
  });

  it('returns false for a failed confirmation', async () => {
    const store = await setup();
    api.deactivatePlatformUser.mockRejectedValueOnce(apiError(409, 'last_admin'));
    store.requestDeactivate(ADA);

    expect(await store.confirmPending()).toBe(false);
  });

  it('makes no request and returns false when nothing is pending', async () => {
    const store = await setup();

    const result = await store.confirmPending();

    expect({ result, calls: apiCalls(), toasts: toastTitles() }).toStrictEqual({ result: false, calls: NO_CALLS, toasts: [] });
  });

  it('makes exactly one request when confirmed twice while the first is in flight', async () => {
    const store = await setup();
    const response = deferred<PlatformUser>();
    api.deactivatePlatformUser.mockReturnValueOnce(response.promise);
    api.getPlatformOrgMetadata.mockResolvedValueOnce(metadata(4, 10));
    store.requestDeactivate(BRUNO);

    const first = store.confirmPending();
    const busy = store.actionBusy;
    const second = await store.confirmPending();
    response.resolve(user(BRUNO, { status: 'deactivated' }));
    const firstResult = await first;

    expect({
      busy,
      second,
      firstResult,
      deactivateCalls: api.deactivatePlatformUser.mock.calls.length,
      actionBusy: store.actionBusy,
    }).toStrictEqual({ busy: true, second: false, firstResult: true, deactivateCalls: 1, actionBusy: false });
  });
});

// --- pendingCopy ------------------------------------------------------------------------

describe('platformOrgDetailStore pendingCopy', () => {
  it.each([
    { kind: 'deactivate', request: (s: Store) => s.requestDeactivate(BRUNO), subject: 'Bruno Editor', destructive: true },
    { kind: 'reactivate', request: (s: Store) => s.requestReactivate(CARLA), subject: 'Carla Gone', destructive: false },
    { kind: 'resetPassword', request: (s: Store) => s.requestPasswordReset(DORA), subject: 'dora@acme.ch', destructive: false },
  ] satisfies Array<{ kind: UserConfirmKind; request: (s: Store) => void; subject: string; destructive: boolean }>)(
    'names the user ($subject) in the $kind copy',
    async ({ kind, request, subject, destructive }) => {
      const store = await setup();

      request(store);
      const copy = store.pendingCopy;

      expect({ copy, namesTheUser: copy?.heading.includes(subject) ?? false }).toStrictEqual({
        copy: {
          heading: msg(`platform.users.confirm.${kind}.heading`, { name: subject }),
          subtext: msg(`platform.users.confirm.${kind}.subtext`, { name: subject }),
          confirmLabel: msg(`platform.users.confirm.${kind}.confirm`, { name: subject }),
          destructive,
        },
        namesTheUser: true,
      });
    },
  );
});

// --- Re-invite the primary admin --------------------------------------------------------

describe('platformOrgDetailStore re-invite', () => {
  it('openReinvite opens the sheet for the invited Org Admin of an active org without an active Org Admin', async () => {
    const store = await setup({ users: noActiveAdminUsers() });

    store.openReinvite(GINA);

    expect({ reinviteUserId: store.reinviteUserId, reinviteError: store.reinviteError, calls: apiCalls() }).toStrictEqual({
      reinviteUserId: GINA,
      reinviteError: null,
      calls: NO_CALLS,
    });
  });

  it.each([
    { label: 'while the org has an active Org Admin', status: 'active', users: acmeUsers(), userId: GINA },
    { label: 'for an invited editor', status: 'active', users: noActiveAdminUsers(), userId: HUGO },
    { label: 'for an active user', status: 'active', users: noActiveAdminUsers(), userId: BRUNO },
    { label: 'for a deactivated Org Admin', status: 'active', users: noActiveAdminUsers(), userId: ADA },
    { label: 'while the org is deactivated', status: 'deactivated', users: noActiveAdminUsers(), userId: GINA },
    { label: 'while the org is pending deletion', status: 'pending_deletion', users: noActiveAdminUsers(), userId: GINA },
    { label: 'for an unknown user', status: 'active', users: noActiveAdminUsers(), userId: UNKNOWN_USER },
  ] satisfies Array<{ label: string; status: OrgStatus; users: PlatformUser[]; userId: string }>)(
    'openReinvite does not open the sheet $label',
    async ({ status, users, userId }) => {
      const store = await setup({ orgs: orgsWithAcme(status), users });

      store.openReinvite(userId);

      expect({ reinviteUserId: store.reinviteUserId, calls: apiCalls() }).toStrictEqual({
        reinviteUserId: null,
        calls: NO_CALLS,
      });
    },
  );

  it('closeReinvite closes the sheet without a request', async () => {
    const store = await setup({ users: noActiveAdminUsers() });
    store.openReinvite(GINA);

    store.closeReinvite();
    const outcome = await outcomeOf(store.submitReinvite(''));

    expect({ reinviteUserId: store.reinviteUserId, outcome, calls: apiCalls() }).toStrictEqual({
      reinviteUserId: null,
      outcome: 'resolved',
      calls: NO_CALLS,
    });
  });

  it.each([
    { label: 'an empty email', email: '' },
    { label: 'a blank email', email: '   ' },
  ])('resends the invitation without an email argument for $label', async ({ email }) => {
    const store = await setup({ users: noActiveAdminUsers() });
    api.reinvitePlatformUser.mockResolvedValueOnce(invitation());
    api.listPlatformOrgUsers.mockResolvedValueOnce({ users: noActiveAdminUsers() });
    api.getPlatformOrgMetadata.mockResolvedValueOnce(metadata());
    store.openReinvite(GINA);

    await store.submitReinvite(email);

    expect({
      args: api.reinvitePlatformUser.mock.calls,
      argCount: api.reinvitePlatformUser.mock.calls[0]?.length,
    }).toStrictEqual({ args: [[ACME, GINA]], argCount: 2 });
  });

  it('sends the trimmed new address when one is given', async () => {
    const store = await setup({ users: noActiveAdminUsers() });
    api.reinvitePlatformUser.mockResolvedValueOnce(invitation('new.admin@acme.ch'));
    api.listPlatformOrgUsers.mockResolvedValueOnce({ users: noActiveAdminUsers() });
    api.getPlatformOrgMetadata.mockResolvedValueOnce(metadata());
    store.openReinvite(GINA);

    await store.submitReinvite('  new.admin@acme.ch ');

    expect(api.reinvitePlatformUser.mock.calls).toStrictEqual([[ACME, GINA, 'new.admin@acme.ch']]);
  });

  it.each([
    { label: 'no @', email: 'new.admin' },
    { label: 'no dot in the domain', email: 'new.admin@acme' },
    { label: 'a space inside', email: 'new admin@acme.ch' },
    { label: 'two @', email: 'new@admin@acme.ch' },
  ])('refuses an implausible address ($label) without a request and keeps the sheet open', async ({ email }) => {
    const store = await setup({ users: noActiveAdminUsers() });
    store.openReinvite(GINA);

    const result = await store.submitReinvite(email);

    expect({
      result,
      reinviteError: store.reinviteError,
      reinviteUserId: store.reinviteUserId,
      calls: apiCalls(),
    }).toStrictEqual({
      result: false,
      reinviteError: msg('platform.orgs.form.error.email'),
      reinviteUserId: GINA,
      calls: NO_CALLS,
    });
  });

  it('closes the sheet, reloads the users and the metadata and toasts when the invitation is sent', async () => {
    const store = await setup({ users: noActiveAdminUsers(), metadata: metadata(5, 10) });
    const reloaded = [user(ADA, { status: 'deactivated' }), user(BRUNO), user(CARLA), user(HUGO), user(NEW_ADMIN)];
    api.reinvitePlatformUser.mockResolvedValueOnce(invitation('new.admin@acme.ch'));
    api.listPlatformOrgUsers.mockResolvedValueOnce({ users: reloaded });
    api.getPlatformOrgMetadata.mockResolvedValueOnce(metadata(5, 12));
    store.openReinvite(GINA);

    const result = await store.submitReinvite('new.admin@acme.ch');

    expect({
      result,
      reinviteUserId: store.reinviteUserId,
      reinviteError: store.reinviteError,
      reinviteBusy: store.reinviteBusy,
      usersArgs: api.listPlatformOrgUsers.mock.calls,
      metadataArgs: api.getPlatformOrgMetadata.mock.calls,
      users: store.users,
      metadata: store.metadata,
      org: store.org,
      toasts: toastTitles(),
    }).toStrictEqual({
      result: true,
      reinviteUserId: null,
      reinviteError: null,
      reinviteBusy: false,
      usersArgs: [[ACME]],
      metadataArgs: [[ACME]],
      users: reloaded,
      metadata: metadata(5, 12),
      org: org(ACME),
      toasts: [{ kind: 'success', title: msg('platform.toast.invitationSent') }],
    });
  });

  it.each([
    { label: 'an address that already has an account (409 email_taken)', error: () => apiError(409, 'email_taken'), key: 'platform.error.emailTaken' },
    {
      label: 'an org that has an active Org Admin by now (409 has_active_admin)',
      error: () => apiError(409, 'has_active_admin'),
      key: 'platform.error.hasActiveAdmin',
    },
    { label: 'no free seat (409 seat_limit)', error: () => apiError(409, 'seat_limit'), key: 'platform.error.seatLimit' },
    { label: 'an account that is gone (404)', error: () => apiError(404), key: 'platform.error.userNotFound' },
  ])('keeps the sheet open with a translated reinviteError for $label', async ({ error, key }) => {
    const store = await setup({ users: noActiveAdminUsers() });
    api.reinvitePlatformUser.mockRejectedValueOnce(error());
    store.openReinvite(GINA);

    const outcome = await outcomeOf(store.submitReinvite('new.admin@acme.ch'));

    expect({
      outcome,
      reinviteUserId: store.reinviteUserId,
      reinviteError: store.reinviteError,
      reinviteBusy: store.reinviteBusy,
      users: store.users,
      toasts: toastTitles(),
      echoesDetail: String(store.reinviteError).includes(DETAIL),
    }).toStrictEqual({
      outcome: 'resolved',
      reinviteUserId: GINA,
      reinviteError: msg(key),
      reinviteBusy: false,
      users: noActiveAdminUsers(),
      toasts: [],
      echoesDetail: false,
    });
  });

  it('returns false when the re-invite is refused', async () => {
    const store = await setup({ users: noActiveAdminUsers() });
    api.reinvitePlatformUser.mockRejectedValueOnce(apiError(409, 'email_taken'));
    store.openReinvite(GINA);

    expect(await store.submitReinvite('new.admin@acme.ch')).toBe(false);
  });

  it('is reinviteBusy while the request is in flight, and not afterwards', async () => {
    const store = await setup({ users: noActiveAdminUsers() });
    const response = deferred<OrgInvitation>();
    api.reinvitePlatformUser.mockReturnValueOnce(response.promise);
    api.listPlatformOrgUsers.mockResolvedValueOnce({ users: noActiveAdminUsers() });
    api.getPlatformOrgMetadata.mockResolvedValueOnce(metadata());
    store.openReinvite(GINA);

    const done = store.submitReinvite('');
    const during = store.reinviteBusy;
    response.resolve(invitation());
    const result = await done;

    expect({ during, after: store.reinviteBusy, result }).toStrictEqual({ during: true, after: false, result: true });
  });
});

// --- Operator blindness and logging ------------------------------------------------------

describe('platformOrgDetailStore operator blindness', () => {
  it('only ever uses @/api/platform and never writes names, emails or backend text to the console', async () => {
    const methods = ['log', 'info', 'warn', 'error', 'debug'] as const;
    const spies = methods.map((method) => vi.spyOn(console, method).mockImplementation(() => undefined));
    const store = usePlatformOrgDetailStore();

    // Loads: malformed id, failure, success.
    await store.load('not-a-uuid');
    arrangeLoad({ fail: { call: 'listPlatformOrgUsers', error: apiError(500) } });
    await store.load(ACME);
    arrangeLoad({ users: noActiveAdminUsers() });
    await store.load(ACME);

    // Confirm flows: refused, cancelled, done (with a failed metadata refresh).
    store.requestReactivate(ADA);
    api.reactivatePlatformUser.mockRejectedValueOnce(apiError(409, 'seat_limit'));
    await store.confirmPending();
    store.cancelPending();
    store.requestDeactivate(BRUNO);
    api.deactivatePlatformUser.mockResolvedValueOnce(user(BRUNO, { status: 'deactivated' }));
    api.getPlatformOrgMetadata.mockRejectedValueOnce(apiError(500));
    await store.confirmPending();

    // Re-invite: implausible, refused, sent.
    store.openReinvite(GINA);
    await store.submitReinvite('new.admin@acme');
    api.reinvitePlatformUser.mockRejectedValueOnce(apiError(409, 'email_taken'));
    await store.submitReinvite('new.admin@acme.ch');
    api.reinvitePlatformUser.mockResolvedValueOnce(invitation('new.admin@acme.ch'));
    api.listPlatformOrgUsers.mockResolvedValueOnce({ users: [user(BRUNO), user(NEW_ADMIN)] });
    api.getPlatformOrgMetadata.mockResolvedValueOnce(metadata());
    await store.submitReinvite('new.admin@acme.ch');

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
      users: store.users.map((item) => item.id),
    }).toEqual({
      leaked: [],
      fetchCalls: 0,
      // Proof the flows above really ran (the reads around them are counted by the dedicated tests).
      calls: expect.objectContaining({ reactivatePlatformUser: 1, deactivatePlatformUser: 1, reinvitePlatformUser: 2 }),
      users: [BRUNO, NEW_ADMIN],
    });
  });
});
