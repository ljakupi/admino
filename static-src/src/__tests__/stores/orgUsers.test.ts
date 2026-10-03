/**
 * Org users store tests (issue #165: Organization console, users and
 * invitations UI).
 *
 * `useOrgUsersStore` (Pinia id 'orgUsers', setup style) owns the Org Admin's
 * Users tab: the org's users, pending invitations and seat usage, the
 * search/status filter, the invite sheet, the edit (name/email) sheet and one
 * confirm sheet for every destructive or consequential row action.
 *
 * - `load()`: `GET /api/org/users` (users + seats) and `GET /api/org/invitations`
 *   together. Success applies all three and marks the store loaded; failure
 *   keeps the previous data and sets a translated `loadError`.
 * - Filters: `visibleUsers` / `visibleInvitations` follow `query` and
 *   `statusFilter`; `seatText` is "7 / 10 seats"; `noFreeSeat` when used >= limit.
 * - Invite: `submitInvite(email, role)` validates the role (no Viewer in V1)
 *   and the email client-side before `POST /api/org/invitations`.
 * - Edit: `submitEdit({ name, email })` sends only the changed fields.
 * - Confirm flows: every `request*` only opens the confirm sheet (never an API
 *   call); `cancelPending()` closes it without a call; `confirmPending()` makes
 *   exactly one call. A failure (e.g. the 409 last-admin guard) keeps the sheet
 *   open with a translated `actionError`.
 * - `resendInvitation(id)` needs no confirmation.
 *
 * Security notes: backend error text (`detail`) is never shown; every message
 * comes from the i18n catalogs. Nothing is logged (no names or emails in the
 * console). Acting on your own account refreshes (`loadMe`) or ends
 * (`logout`) your session. `@/api/org-users` and `@/api/auth` are mocked; the
 * auth store is the real one with spied `loadMe` / `logout`. No component is
 * mounted and nothing touches the network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import {
  createInvitation,
  deactivateOrgUser,
  deleteOrgUser,
  forceLogoutOrgUser,
  listInvitations,
  listOrgUsers,
  reactivateOrgUser,
  resendInvitation,
  resetOrgUserPassword,
  revokeInvitation,
  updateOrgUser,
} from '@/api/org-users';
import { ApiError } from '@/api/client';
import { setLocale } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { useAuthStore } from '@/stores/auth';
import { useOrgUsersStore } from '@/stores/orgUsers';
import { useToastStore } from '@/stores/toasts';
import type {
  MemberRole,
  MeResponse,
  OrgInvitation,
  OrgInvitationListResponse,
  OrgSeats,
  OrgUser,
  OrgUserListResponse,
  OrgUserPatch,
} from '@/api/types';

vi.mock('@/api/org-users', () => ({
  listOrgUsers: vi.fn(),
  updateOrgUser: vi.fn(),
  deactivateOrgUser: vi.fn(),
  reactivateOrgUser: vi.fn(),
  deleteOrgUser: vi.fn(),
  resetOrgUserPassword: vi.fn(),
  forceLogoutOrgUser: vi.fn(),
  listInvitations: vi.fn(),
  createInvitation: vi.fn(),
  revokeInvitation: vi.fn(),
  resendInvitation: vi.fn(),
}));

vi.mock('@/api/auth', () => ({
  getMe: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  requestPasswordReset: vi.fn(),
  confirmPasswordReset: vi.fn(),
  getInvitation: vi.fn(),
  acceptInvitation: vi.fn(),
}));

const api = {
  listOrgUsers: vi.mocked(listOrgUsers),
  updateOrgUser: vi.mocked(updateOrgUser),
  deactivateOrgUser: vi.mocked(deactivateOrgUser),
  reactivateOrgUser: vi.mocked(reactivateOrgUser),
  deleteOrgUser: vi.mocked(deleteOrgUser),
  resetOrgUserPassword: vi.mocked(resetOrgUserPassword),
  forceLogoutOrgUser: vi.mocked(forceLogoutOrgUser),
  listInvitations: vi.mocked(listInvitations),
  createInvitation: vi.mocked(createInvitation),
  revokeInvitation: vi.mocked(revokeInvitation),
  resendInvitation: vi.mocked(resendInvitation),
};

type ApiName = keyof typeof api;

/** Every org-users API function with zero calls. */
const NO_CALLS: Readonly<Record<ApiName, number>> = {
  listOrgUsers: 0,
  updateOrgUser: 0,
  deactivateOrgUser: 0,
  reactivateOrgUser: 0,
  deleteOrgUser: 0,
  resetOrgUserPassword: 0,
  forceLogoutOrgUser: 0,
  listInvitations: 0,
  createInvitation: 0,
  revokeInvitation: 0,
  resendInvitation: 0,
};

/** How many times each org-users API function was called. */
function apiCalls(): Record<ApiName, number> {
  const counts = { ...NO_CALLS };
  for (const name of Object.keys(api) as ApiName[]) {
    counts[name] = api[name].mock.calls.length;
  }
  return counts;
}

// --- Fixtures -------------------------------------------------------------

const ORG_ID = '3f6b2c1d-8e4a-4b7c-9d2e-1a0f5c6b7d8e';
/** The logged-in Org Admin ("you"). */
const ADA = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d';
const BRUNO = 'b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e';
const CARLA = 'c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f';
const DORA = 'd4e5f6a7-b8c9-4d0e-9f2a-3b4c5d6e7f80';
const EMIL = 'e5f6a7b8-c9d0-4e1f-8a3b-4c5d6e7f8091';
const FINN_INVITE = 'f6a7b8c9-d0e1-4f2a-9b4c-5d6e7f809102';
const GINA_INVITE = '07b8c9d0-e1f2-4a3b-8c5d-6e7f80910213';
const NEW_INVITE = '18c9d0e1-f2a3-4b4c-9d6e-7f8091021324';
const UNKNOWN = '29d0e1f2-a3b4-4c5d-8e7f-809102132435';

const USERS: Readonly<Record<string, OrgUser>> = {
  [ADA]: {
    id: ADA,
    name: 'Ada Admin',
    email: 'ada@example.ch',
    role: 'org_admin',
    status: 'active',
    created_at: '2026-01-05T09:00:00Z',
    last_login_at: '2026-10-01T08:00:00Z',
  },
  [BRUNO]: {
    id: BRUNO,
    name: 'Bruno Editor',
    email: 'bruno@example.ch',
    role: 'editor',
    status: 'active',
    created_at: '2026-02-10T10:00:00Z',
    last_login_at: '2026-09-30T12:30:00Z',
  },
  [CARLA]: {
    id: CARLA,
    name: 'Carla Gone',
    email: 'carla@example.ch',
    role: 'editor',
    status: 'deactivated',
    created_at: '2026-03-01T11:00:00Z',
    last_login_at: null,
  },
  [DORA]: {
    id: DORA,
    name: null,
    email: 'dora.viewer@example.ch',
    role: 'viewer',
    status: 'active',
    created_at: '2026-04-12T07:45:00Z',
    last_login_at: '2026-09-01T16:00:00Z',
  },
  [EMIL]: {
    id: EMIL,
    name: 'Emil Second',
    email: 'emil@example.ch',
    role: 'org_admin',
    status: 'active',
    created_at: '2026-05-20T13:15:00Z',
    last_login_at: '2026-10-02T09:10:00Z',
  },
};

const INVITATIONS: Readonly<Record<string, OrgInvitation>> = {
  [FINN_INVITE]: {
    id: FINN_INVITE,
    email: 'finn@example.ch',
    role: 'editor',
    sent_at: '2026-09-28T10:00:00Z',
    expires_at: '2026-10-05T10:00:00Z',
    expired: false,
  },
  [GINA_INVITE]: {
    id: GINA_INVITE,
    email: 'gina@example.ch',
    role: 'org_admin',
    sent_at: '2026-09-01T10:00:00Z',
    expires_at: '2026-09-08T10:00:00Z',
    expired: true,
  },
};

const USER_ORDER = [ADA, BRUNO, CARLA, DORA, EMIL];
const INVITATION_ORDER = [FINN_INVITE, GINA_INVITE];

/** Every name and email the fixtures (and the flows below) use: none may ever reach the console. */
const PERSONAL_DATA = [
  'Ada Admin',
  'ada@example.ch',
  'Bruno Editor',
  'bruno@example.ch',
  'Bruno Neu',
  'bruno.new@example.ch',
  'Carla Gone',
  'carla@example.ch',
  'dora.viewer@example.ch',
  'Emil Second',
  'emil@example.ch',
  'finn@example.ch',
  'gina@example.ch',
  'new.person@example.ch',
];

/** A fresh copy of the user `id` with `overrides` applied. */
function user(id: string, overrides: Partial<OrgUser> = {}): OrgUser {
  const base = USERS[id];
  if (base === undefined) throw new Error(`no fixture user ${id}`);
  return { ...base, ...overrides };
}

/** A fresh copy of the invitation `id` with `overrides` applied. */
function invitation(id: string, overrides: Partial<OrgInvitation> = {}): OrgInvitation {
  const base = INVITATIONS[id];
  if (base === undefined) throw new Error(`no fixture invitation ${id}`);
  return { ...base, ...overrides };
}

function allUsers(): OrgUser[] {
  return USER_ORDER.map((id) => user(id));
}

function allInvitations(): OrgInvitation[] {
  return INVITATION_ORDER.map((id) => invitation(id));
}

function seats(used = 7, limit = 10): OrgSeats {
  return { used, limit };
}

function newInvitation(overrides: Partial<OrgInvitation> = {}): OrgInvitation {
  return {
    id: NEW_INVITE,
    email: 'new.person@example.ch',
    role: 'editor',
    sent_at: '2026-10-03T08:00:00Z',
    expires_at: '2026-10-10T08:00:00Z',
    expired: false,
    ...overrides,
  };
}

/** The logged-in Org Admin's profile (Ada). */
function me(): MeResponse {
  return {
    user_id: ADA,
    kind: 'member',
    org_id: ORG_ID,
    role: 'org_admin',
    ui_language: 'en',
    response_language: null,
  };
}

type Catalog = Record<string, unknown>;

const EN: Catalog = en;
const DE: Catalog = de;

/** The catalog's own non-blank string for `key`; throws when the catalog lacks it. */
function text(catalog: Catalog, key: string): string {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`the catalog has no text for ${key}`);
  }
  return value;
}

/** The English text of `key`. */
function msg(key: string): string {
  return text(EN, key);
}

/** Backend error text the store must never show (it names a user on purpose). */
const DETAIL = 'backend detail: bruno@example.ch cannot be changed';

function apiError(status: number, reason?: string): ApiError {
  return new ApiError(status, 'Error', DETAIL, reason);
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

/** What `promise` fulfils with, or `{ threw: error }` when it rejects. */
function settled<T>(promise: Promise<T>): Promise<T | { threw: unknown }> {
  return promise.then(
    (value) => value,
    (e: unknown) => ({ threw: e }),
  );
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

function toastSummary(): Array<{ kind: string; title: string; body?: string }> {
  return useToastStore().toasts.map(({ kind, title, body }) => (body === undefined ? { kind, title } : { kind, title, body }));
}

/** A JSON snapshot of the data the confirm/invite/edit failures must leave untouched. */
function dataSnapshot(store: ReturnType<typeof useOrgUsersStore>): string {
  return JSON.stringify({ users: store.users, invitations: store.invitations, seats: store.seats });
}

interface Harness {
  store: ReturnType<typeof useOrgUsersStore>;
  loadMe: ReturnType<typeof spyLoadMe>;
  logout: ReturnType<typeof spyLogout>;
}

function spyLoadMe(auth: ReturnType<typeof useAuthStore>) {
  return vi.spyOn(auth, 'loadMe').mockResolvedValue(true);
}

function spyLogout(auth: ReturnType<typeof useAuthStore>) {
  return vi.spyOn(auth, 'logout').mockResolvedValue(undefined);
}

/**
 * Ada is logged in (the real auth store, `loadMe` / `logout` spied BEFORE the
 * org users store exists), and the org users store is loaded with `options`.
 * API call logs and toasts are cleared afterwards.
 */
async function setup(
  options: { users?: OrgUser[]; invitations?: OrgInvitation[]; seats?: OrgSeats } = {},
): Promise<Harness> {
  const auth = useAuthStore();
  auth.me = me();
  const loadMe = spyLoadMe(auth);
  const logout = spyLogout(auth);
  const store = useOrgUsersStore();
  api.listOrgUsers.mockResolvedValueOnce({ users: options.users ?? allUsers(), seats: options.seats ?? seats() });
  api.listInvitations.mockResolvedValueOnce({ invitations: options.invitations ?? allInvitations() });
  await store.load();
  if (!store.loaded) throw new Error('setup: load() did not load the store');
  for (const mock of Object.values(api)) mock.mockClear();
  useToastStore().toasts.splice(0);
  return { store, loadMe, logout };
}

function ids(items: ReadonlyArray<{ id: string }>): string[] {
  return items.map((item) => item.id);
}

beforeEach(() => {
  localStorage.clear();
  setActivePinia(createPinia());
  setLocale('en');
  for (const mock of Object.values(api)) mock.mockReset();
});

afterEach(() => {
  setLocale('en');
});

// --- Initial state --------------------------------------------------------

describe('orgUsersStore initial state', () => {
  it('is the "orgUsers" store with empty data, no seats, the "all" filter and every sheet closed', () => {
    const store = useOrgUsersStore();

    expect({
      id: store.$id,
      users: store.users,
      invitations: store.invitations,
      seats: store.seats,
      loading: store.loading,
      loaded: store.loaded,
      loadError: store.loadError,
      query: store.query,
      statusFilter: store.statusFilter,
      inviteOpen: store.inviteOpen,
      inviteBusy: store.inviteBusy,
      inviteError: store.inviteError,
      editUserId: store.editUserId,
      editBusy: store.editBusy,
      editError: store.editError,
      pending: store.pending,
      actionBusy: store.actionBusy,
      actionError: store.actionError,
    }).toStrictEqual({
      id: 'orgUsers',
      users: [],
      invitations: [],
      seats: null,
      loading: false,
      loaded: false,
      loadError: null,
      query: '',
      statusFilter: 'all',
      inviteOpen: false,
      inviteBusy: false,
      inviteError: null,
      editUserId: null,
      editBusy: false,
      editError: null,
      pending: null,
      actionBusy: false,
      actionError: null,
    });
  });

  it('shows no seat text, no full-seat warning and nothing visible before the first load', () => {
    const store = useOrgUsersStore();

    expect({
      seatText: store.seatText,
      noFreeSeat: store.noFreeSeat,
      visibleUsers: store.visibleUsers,
      visibleInvitations: store.visibleInvitations,
    }).toStrictEqual({ seatText: null, noFreeSeat: false, visibleUsers: [], visibleInvitations: [] });
  });

  it('asks nothing of the server until load() is called', () => {
    useOrgUsersStore();

    expect(apiCalls()).toEqual(NO_CALLS);
  });
});

// --- load(): GET /api/org/users + GET /api/org/invitations -----------------

describe('orgUsersStore load', () => {
  it('loads the users, the seats from the users response and the invitations, and marks the store loaded', async () => {
    api.listOrgUsers.mockResolvedValueOnce({ users: allUsers(), seats: seats(7, 10) });
    api.listInvitations.mockResolvedValueOnce({ invitations: allInvitations() });
    const store = useOrgUsersStore();

    const outcome = await outcomeOf(store.load());

    expect({
      outcome,
      listUsersCalls: api.listOrgUsers.mock.calls,
      listInvitationsCalls: api.listInvitations.mock.calls,
      calls: apiCalls(),
      users: store.users,
      seats: store.seats,
      invitations: store.invitations,
      loaded: store.loaded,
      loadError: store.loadError,
      loading: store.loading,
    }).toEqual({
      outcome: 'resolved',
      listUsersCalls: [[]],
      listInvitationsCalls: [[]],
      calls: { ...NO_CALLS, listOrgUsers: 1, listInvitations: 1 },
      users: allUsers(),
      seats: seats(7, 10),
      invitations: allInvitations(),
      loaded: true,
      loadError: null,
      loading: false,
    });
  });

  it('is loading while the requests are in flight, and not afterwards', async () => {
    const usersResponse = deferred<OrgUserListResponse>();
    const invitationsResponse = deferred<OrgInvitationListResponse>();
    api.listOrgUsers.mockReturnValueOnce(usersResponse.promise);
    api.listInvitations.mockReturnValueOnce(invitationsResponse.promise);
    const store = useOrgUsersStore();

    const done = outcomeOf(store.load());
    const during = { loading: store.loading, loaded: store.loaded };
    usersResponse.resolve({ users: allUsers(), seats: seats() });
    invitationsResponse.resolve({ invitations: allInvitations() });
    await done;

    expect({ during, after: { loading: store.loading, loaded: store.loaded } }).toEqual({
      during: { loading: true, loaded: false },
      after: { loading: false, loaded: true },
    });
  });

  it('sets a translated loadError, stays not loaded, stops loading and never throws when the first load fails', async () => {
    api.listOrgUsers.mockRejectedValueOnce(apiError(403));
    api.listInvitations.mockResolvedValueOnce({ invitations: allInvitations() });
    const store = useOrgUsersStore();

    const outcome = await outcomeOf(store.load());

    expect({
      outcome,
      loadError: store.loadError,
      loaded: store.loaded,
      loading: store.loading,
      users: store.users,
      invitations: store.invitations,
      seats: store.seats,
    }).toEqual({
      outcome: 'resolved',
      loadError: msg('orgUsers.error.forbidden'),
      loaded: false,
      loading: false,
      users: [],
      invitations: [],
      seats: null,
    });
  });

  it('keeps the previously loaded users, invitations and seats when a reload fails', async () => {
    const { store } = await setup();
    // The users answer arrives with different data, but the invitations request fails: nothing is applied.
    api.listOrgUsers.mockResolvedValueOnce({ users: [user(ADA)], seats: seats(1, 3) });
    api.listInvitations.mockRejectedValueOnce(new TypeError('Failed to fetch'));

    const outcome = await outcomeOf(store.load());

    expect({
      outcome,
      users: store.users,
      invitations: store.invitations,
      seats: store.seats,
      loaded: store.loaded,
      loadError: store.loadError,
      loading: store.loading,
    }).toEqual({
      outcome: 'resolved',
      users: allUsers(),
      invitations: allInvitations(),
      seats: seats(),
      loaded: true,
      loadError: msg('orgUsers.error.generic'),
      loading: false,
    });
  });

  it.each<[string, unknown, string]>([
    ['a 429', apiError(429), 'orgUsers.error.rateLimited'],
    ['a 500 with backend detail', apiError(500), 'orgUsers.error.generic'],
    ['a network failure', new TypeError('Failed to fetch'), 'orgUsers.error.generic'],
    ['a non-Error rejection', 'boom', 'orgUsers.error.generic'],
  ])('maps %s to the translated message, never the backend text', async (_label, error, key) => {
    api.listOrgUsers.mockRejectedValueOnce(error);
    api.listInvitations.mockResolvedValueOnce({ invitations: [] });
    const store = useOrgUsersStore();

    const outcome = await outcomeOf(store.load());

    expect({ outcome, loadError: store.loadError }).toEqual({ outcome: 'resolved', loadError: msg(key) });
  });

  it('clears an earlier loadError and replaces the data on a successful reload', async () => {
    api.listOrgUsers.mockRejectedValueOnce(apiError(500));
    api.listInvitations.mockResolvedValueOnce({ invitations: [] });
    const store = useOrgUsersStore();
    await store.load();
    api.listOrgUsers.mockResolvedValueOnce({ users: [user(ADA), user(EMIL)], seats: seats(2, 5) });
    api.listInvitations.mockResolvedValueOnce({ invitations: [invitation(GINA_INVITE)] });

    await store.load();

    expect({
      loadError: store.loadError,
      loaded: store.loaded,
      users: ids(store.users),
      invitations: ids(store.invitations),
      seats: store.seats,
    }).toEqual({
      loadError: null,
      loaded: true,
      users: [ADA, EMIL],
      invitations: [GINA_INVITE],
      seats: seats(2, 5),
    });
  });

  it('shows the load error in the active locale', async () => {
    setLocale('de');
    api.listOrgUsers.mockRejectedValueOnce(apiError(403));
    api.listInvitations.mockResolvedValueOnce({ invitations: [] });
    const store = useOrgUsersStore();

    await store.load();

    expect(store.loadError).toBe(text(DE, 'orgUsers.error.forbidden'));
  });
});

// --- Search, status filter and seats ---------------------------------------

describe('orgUsersStore filters', () => {
  it('shows every user and invitation in their order with no query and the "all" filter', async () => {
    const { store } = await setup();

    expect({ users: ids(store.visibleUsers), invitations: ids(store.visibleInvitations) }).toEqual({
      users: USER_ORDER,
      invitations: INVITATION_ORDER,
    });
  });

  it.each<[string, string[], string[]]>([
    ['active', [ADA, BRUNO, DORA, EMIL], []],
    ['deactivated', [CARLA], []],
    ['invited', [], INVITATION_ORDER],
    ['all', USER_ORDER, INVITATION_ORDER],
  ])('the "%s" status filter shows the matching users and invitations', async (filter, users, invitations) => {
    const { store } = await setup();

    store.setStatusFilter(filter);

    expect({
      statusFilter: store.statusFilter,
      users: ids(store.visibleUsers),
      invitations: ids(store.visibleInvitations),
    }).toEqual({ statusFilter: filter, users, invitations });
  });

  it.each<[string, unknown]>([
    ['a role', 'viewer'],
    ['a different case', 'Active'],
    ['an empty string', ''],
    ['a prototype key', 'constructor'],
    ['__proto__', '__proto__'],
    ['undefined', undefined],
    ['null', null],
    ['a number', 1],
    ['an array', ['active']],
  ])('setStatusFilter ignores %s and keeps the current filter', async (_label, value) => {
    const { store } = await setup();
    store.setStatusFilter('deactivated');

    expect(() => store.setStatusFilter(value)).not.toThrow();
    expect({ statusFilter: store.statusFilter, users: ids(store.visibleUsers) }).toEqual({
      statusFilter: 'deactivated',
      users: [CARLA],
    });
  });

  it.each<[string, string, string[], string[]]>([
    ['a name, case-insensitively', 'BRUNO', [BRUNO], []],
    ['an email of a user without a name', 'dora.viewer', [DORA], []],
    ['an invitation email (padded with spaces)', '  finn  ', [], [FINN_INVITE]],
    ['the shared email domain', 'example.ch', USER_ORDER, INVITATION_ORDER],
    ['the name, not the role', 'admin', [ADA], []],
    ['nothing', 'zzz-nobody', [], []],
  ])('the search matches %s', async (_label, query, users, invitations) => {
    const { store } = await setup();

    store.setQuery(query);

    expect({ users: ids(store.visibleUsers), invitations: ids(store.visibleInvitations) }).toEqual({
      users,
      invitations,
    });
  });

  it('setQuery stores the search text', async () => {
    const { store } = await setup();

    store.setQuery('bruno');

    expect(store.query).toBe('bruno');
  });

  it('combines the search with the status filter', async () => {
    const { store } = await setup();

    store.setQuery('gone');
    store.setStatusFilter('active');
    const whileActive = ids(store.visibleUsers);
    store.setStatusFilter('deactivated');

    expect({ whileActive, whileDeactivated: ids(store.visibleUsers) }).toEqual({
      whileActive: [],
      whileDeactivated: [CARLA],
    });
  });

  it('never calls the API when the search or the filter changes', async () => {
    const { store } = await setup();

    store.setQuery('bruno');
    store.setStatusFilter('invited');
    store.setStatusFilter('nonsense');

    expect(apiCalls()).toEqual(NO_CALLS);
  });

  it('shows the seat usage as "7 / 10 seats" with a free seat left', async () => {
    const { store } = await setup({ seats: seats(7, 10) });

    expect({ seatText: store.seatText, noFreeSeat: store.noFreeSeat }).toEqual({
      seatText: '7 / 10 seats',
      noFreeSeat: false,
    });
  });

  it.each<[number, number]>([
    [10, 10],
    [12, 10],
    [0, 0],
  ])('reports no free seat when %i of %i seats are used', async (used, limit) => {
    const { store } = await setup({ seats: seats(used, limit) });

    expect({ seatText: store.seatText, noFreeSeat: store.noFreeSeat }).toEqual({
      seatText: `${used} / ${limit} seats`,
      noFreeSeat: true,
    });
  });
});

// --- Invite flow --------------------------------------------------------------

describe('orgUsersStore invite flow', () => {
  it('openInvite opens the sheet with no error and makes no API call', async () => {
    const { store } = await setup();

    store.openInvite();

    expect({ inviteOpen: store.inviteOpen, inviteError: store.inviteError, calls: apiCalls() }).toEqual({
      inviteOpen: true,
      inviteError: null,
      calls: NO_CALLS,
    });
  });

  it('openInvite clears the error of an earlier attempt', async () => {
    const { store } = await setup();
    store.openInvite();
    api.createInvitation.mockRejectedValueOnce(apiError(409, 'seat_limit'));
    await store.submitInvite('new.person@example.ch', 'editor');

    store.openInvite();

    expect({ inviteOpen: store.inviteOpen, inviteError: store.inviteError }).toEqual({
      inviteOpen: true,
      inviteError: null,
    });
  });

  it('closeInvite closes the sheet, clears the error and makes no API call', async () => {
    const { store } = await setup();
    store.openInvite();
    await store.submitInvite('not-an-email', 'editor');

    store.closeInvite();

    expect({ inviteOpen: store.inviteOpen, inviteError: store.inviteError, calls: apiCalls() }).toEqual({
      inviteOpen: false,
      inviteError: null,
      calls: NO_CALLS,
    });
  });

  it.each<[string, string]>([
    ['viewer (not offered in V1)', 'viewer'],
    ['an unknown role', 'owner'],
    ['super_admin', 'super_admin'],
    ['an empty role', ''],
    ['a prototype key', 'constructor'],
  ])('refuses %s without an API call', async (_label, role) => {
    const { store } = await setup();
    store.openInvite();
    const before = dataSnapshot(store);

    const outcome = await settled(store.submitInvite('new.person@example.ch', role as MemberRole));

    expect({
      outcome,
      calls: apiCalls(),
      inviteError: store.inviteError,
      inviteOpen: store.inviteOpen,
      inviteBusy: store.inviteBusy,
      data: dataSnapshot(store),
      toasts: toastSummary(),
    }).toEqual({
      outcome: false,
      calls: NO_CALLS,
      inviteError: msg('orgUsers.error.invalidInput'),
      inviteOpen: true,
      inviteBusy: false,
      data: before,
      toasts: [],
    });
  });

  it.each<[string, string]>([
    ['an empty email', ''],
    ['only spaces', '   '],
    ['no @', 'new.person.example.ch'],
    ['two @', 'new@@example.ch'],
    ['an empty local part', '@example.ch'],
    ['a domain without a dot', 'new@localhost'],
    ['a domain ending in a dot', 'new@example.'],
    ['a space inside', 'new person@example.ch'],
    ['a control character inside', `new${String.fromCharCode(0)}@example.ch`],
  ])('refuses an implausible email (%s) without an API call', async (_label, email) => {
    const { store } = await setup();
    store.openInvite();
    const before = dataSnapshot(store);

    const outcome = await settled(store.submitInvite(email, 'editor'));

    expect({
      outcome,
      calls: apiCalls(),
      inviteError: store.inviteError,
      inviteOpen: store.inviteOpen,
      data: dataSnapshot(store),
    }).toEqual({
      outcome: false,
      calls: NO_CALLS,
      inviteError: msg('orgUsers.error.invalidEmail'),
      inviteOpen: true,
      data: before,
    });
  });

  it('sends the trimmed email and the role once, prepends the invitation, takes a seat, closes the sheet and toasts', async () => {
    const { store } = await setup({ seats: seats(7, 10) });
    store.openInvite();
    api.createInvitation.mockResolvedValueOnce(newInvitation());

    const outcome = await settled(store.submitInvite('  new.person@example.ch  ', 'editor'));

    expect({
      outcome,
      createCalls: api.createInvitation.mock.calls,
      calls: apiCalls(),
      invitations: store.invitations,
      seats: store.seats,
      seatText: store.seatText,
      inviteOpen: store.inviteOpen,
      inviteError: store.inviteError,
      inviteBusy: store.inviteBusy,
      users: store.users,
      toasts: toastSummary(),
    }).toStrictEqual({
      outcome: true,
      createCalls: [['new.person@example.ch', 'editor']],
      calls: { ...NO_CALLS, createInvitation: 1 },
      invitations: [newInvitation(), ...allInvitations()],
      seats: seats(8, 10),
      seatText: '8 / 10 seats',
      inviteOpen: false,
      inviteError: null,
      inviteBusy: false,
      users: allUsers(),
      toasts: [{ kind: 'success', title: msg('toast.orgUsers.invited') }],
    });
  });

  it('invites an Org Admin', async () => {
    const { store } = await setup();
    api.createInvitation.mockResolvedValueOnce(newInvitation({ role: 'org_admin' }));

    const outcome = await store.submitInvite('new.person@example.ch', 'org_admin');

    expect({ outcome, createCalls: api.createInvitation.mock.calls }).toStrictEqual({
      outcome: true,
      createCalls: [['new.person@example.ch', 'org_admin']],
    });
  });

  it('marks the org full when the invitation takes the last free seat', async () => {
    const { store } = await setup({ seats: seats(9, 10) });
    api.createInvitation.mockResolvedValueOnce(newInvitation());

    await store.submitInvite('new.person@example.ch', 'editor');

    expect({ seats: store.seats, noFreeSeat: store.noFreeSeat }).toEqual({ seats: seats(10, 10), noFreeSeat: true });
  });

  it('leaves unknown seats unknown after a successful invitation', async () => {
    const { store } = await setup();
    store.seats = null;
    api.createInvitation.mockResolvedValueOnce(newInvitation());

    const outcome = await settled(store.submitInvite('new.person@example.ch', 'editor'));

    expect({ outcome, seats: store.seats, invitations: ids(store.invitations) }).toEqual({
      outcome: true,
      seats: null,
      invitations: [NEW_INVITE, ...INVITATION_ORDER],
    });
  });

  it('is busy while the invitation is being sent, and not afterwards', async () => {
    const { store } = await setup();
    const response = deferred<OrgInvitation>();
    api.createInvitation.mockReturnValueOnce(response.promise);

    const done = settled(store.submitInvite('new.person@example.ch', 'editor'));
    const during = store.inviteBusy;
    response.resolve(newInvitation());
    await done;

    expect({ during, after: store.inviteBusy }).toEqual({ during: true, after: false });
  });

  it('is not busy any more after a failed invitation', async () => {
    const { store } = await setup();
    const response = deferred<OrgInvitation>();
    api.createInvitation.mockReturnValueOnce(response.promise);

    const done = settled(store.submitInvite('new.person@example.ch', 'editor'));
    const during = store.inviteBusy;
    response.reject(apiError(409, 'seat_limit'));
    await done;

    expect({ during, after: store.inviteBusy }).toEqual({ during: true, after: false });
  });

  it('refuses a second send while the first is in flight, with no second request', async () => {
    const { store } = await setup();
    const response = deferred<OrgInvitation>();
    api.createInvitation.mockReturnValueOnce(response.promise);

    const first = settled(store.submitInvite('new.person@example.ch', 'editor'));
    const second = await settled(store.submitInvite('new.person@example.ch', 'editor'));
    response.resolve(newInvitation());

    expect({ first: await first, second, calls: api.createInvitation.mock.calls.length }).toEqual({
      first: true,
      second: false,
      calls: 1,
    });
  });

  it.each<[string, unknown, string]>([
    ['the seat limit (409 seat_limit)', apiError(409, 'seat_limit'), 'orgUsers.error.seatLimit'],
    ['a taken email (409 email_taken)', apiError(409, 'email_taken'), 'orgUsers.error.emailTaken'],
    ['the rate limit (429)', apiError(429), 'orgUsers.error.rateLimited'],
    ['a rejected email (422)', apiError(422), 'orgUsers.error.invalidInput'],
    ['a missing capability (403)', apiError(403), 'orgUsers.error.forbidden'],
    ['a 404 (an invitation subject)', apiError(404), 'orgUsers.error.invitationNotFound'],
    ['a server error', apiError(500), 'orgUsers.error.generic'],
    ['a network failure', new TypeError('Failed to fetch'), 'orgUsers.error.generic'],
    ['a non-Error rejection', undefined, 'orgUsers.error.generic'],
  ])('surfaces %s as a translated message and keeps the sheet open', async (_label, error, key) => {
    const { store } = await setup();
    store.openInvite();
    const before = dataSnapshot(store);
    api.createInvitation.mockRejectedValueOnce(error);

    const outcome = await settled(store.submitInvite('new.person@example.ch', 'editor'));

    expect({
      outcome,
      calls: apiCalls(),
      inviteError: store.inviteError,
      inviteOpen: store.inviteOpen,
      inviteBusy: store.inviteBusy,
      data: dataSnapshot(store),
      toasts: toastSummary(),
    }).toEqual({
      outcome: false,
      calls: { ...NO_CALLS, createInvitation: 1 },
      inviteError: msg(key),
      inviteOpen: true,
      inviteBusy: false,
      data: before,
      toasts: [],
    });
  });

  it('clears the error of a failed attempt when a retry succeeds', async () => {
    const { store } = await setup();
    store.openInvite();
    api.createInvitation.mockRejectedValueOnce(apiError(429)).mockResolvedValueOnce(newInvitation());

    const first = await store.submitInvite('new.person@example.ch', 'editor');
    const errorAfterFirst = store.inviteError;
    const second = await store.submitInvite('new.person@example.ch', 'editor');

    expect({ first, errorAfterFirst, second, inviteError: store.inviteError, inviteOpen: store.inviteOpen }).toEqual({
      first: false,
      errorAfterFirst: msg('orgUsers.error.rateLimited'),
      second: true,
      inviteError: null,
      inviteOpen: false,
    });
  });
});

// --- Edit flow (name and email) -------------------------------------------

describe('orgUsersStore edit flow', () => {
  it('openEdit opens the sheet for a known user without an API call', async () => {
    const { store } = await setup();

    store.openEdit(BRUNO);

    expect({ editUserId: store.editUserId, editError: store.editError, calls: apiCalls() }).toEqual({
      editUserId: BRUNO,
      editError: null,
      calls: NO_CALLS,
    });
  });

  it('openEdit ignores an unknown user', async () => {
    const { store } = await setup();

    store.openEdit(UNKNOWN);

    expect({ editUserId: store.editUserId, calls: apiCalls() }).toEqual({ editUserId: null, calls: NO_CALLS });
  });

  it('closeEdit closes the sheet and clears its error without an API call', async () => {
    const { store } = await setup();
    store.openEdit(BRUNO);
    await store.submitEdit({ name: 'Bruno Editor', email: 'bruno-at-example' });

    store.closeEdit();

    expect({ editUserId: store.editUserId, editError: store.editError, calls: apiCalls() }).toEqual({
      editUserId: null,
      editError: null,
      calls: NO_CALLS,
    });
  });

  it('openEdit clears the error left by another user\'s failed edit', async () => {
    const { store } = await setup();
    store.openEdit(BRUNO);
    api.updateOrgUser.mockRejectedValueOnce(apiError(409, 'email_taken'));
    await store.submitEdit({ name: 'Bruno Editor', email: 'emil@example.ch' });

    store.openEdit(CARLA);

    expect({ editUserId: store.editUserId, editError: store.editError }).toEqual({ editUserId: CARLA, editError: null });
  });

  it('submitEdit without an open sheet makes no call and returns false', async () => {
    const { store } = await setup();

    const outcome = await settled(store.submitEdit({ name: 'Bruno Neu', email: 'bruno@example.ch' }));

    expect({ outcome, calls: apiCalls() }).toEqual({ outcome: false, calls: NO_CALLS });
  });

  it('refuses an implausible email without an API call and keeps the sheet open', async () => {
    const { store } = await setup();
    store.openEdit(BRUNO);
    const before = dataSnapshot(store);

    const outcome = await settled(store.submitEdit({ name: 'Bruno Editor', email: 'bruno-at-example' }));

    expect({
      outcome,
      calls: apiCalls(),
      editError: store.editError,
      editUserId: store.editUserId,
      data: dataSnapshot(store),
    }).toEqual({
      outcome: false,
      calls: NO_CALLS,
      editError: msg('orgUsers.error.invalidEmail'),
      editUserId: BRUNO,
      data: before,
    });
  });

  it.each<[string, { name: string; email: string }]>([
    ['the same values padded with spaces', { name: '  Bruno Editor ', email: ' bruno@example.ch ' }],
    ['an empty name (a name is never cleared)', { name: '   ', email: 'bruno@example.ch' }],
  ])('closes the sheet without an API call when nothing changed: %s', async (_label, input) => {
    const { store } = await setup();
    store.openEdit(BRUNO);

    const outcome = await settled(store.submitEdit(input));

    expect({ outcome, calls: apiCalls(), editUserId: store.editUserId, users: store.users, toasts: toastSummary() }).toEqual({
      outcome: true,
      calls: NO_CALLS,
      editUserId: null,
      users: allUsers(),
      toasts: [],
    });
  });

  it.each<[string, { name: string; email: string }, OrgUserPatch]>([
    ['only the trimmed name', { name: '  Bruno Neu  ', email: 'bruno@example.ch' }, { name: 'Bruno Neu' }],
    ['only the trimmed email', { name: 'Bruno Editor', email: ' bruno.new@example.ch ' }, { email: 'bruno.new@example.ch' }],
    [
      'both changed fields',
      { name: 'Bruno Neu', email: 'bruno.new@example.ch' },
      { name: 'Bruno Neu', email: 'bruno.new@example.ch' },
    ],
  ])('sends %s to PATCH /api/org/users/{id}', async (_label, input, patch) => {
    const { store } = await setup();
    store.openEdit(BRUNO);
    api.updateOrgUser.mockResolvedValueOnce(user(BRUNO, patch));

    await store.submitEdit(input);

    expect({ updateCalls: api.updateOrgUser.mock.calls, calls: apiCalls() }).toStrictEqual({
      updateCalls: [[BRUNO, patch]],
      calls: { ...NO_CALLS, updateOrgUser: 1 },
    });
  });

  it('replaces the user with the response, closes the sheet and toasts on success', async () => {
    const { store } = await setup();
    store.openEdit(BRUNO);
    const saved = user(BRUNO, { name: 'Bruno Neu', email: 'bruno.new@example.ch' });
    api.updateOrgUser.mockResolvedValueOnce(saved);

    const outcome = await settled(store.submitEdit({ name: 'Bruno Neu', email: 'bruno.new@example.ch' }));

    expect({
      outcome,
      users: store.users,
      editUserId: store.editUserId,
      editError: store.editError,
      editBusy: store.editBusy,
      toasts: toastSummary(),
    }).toStrictEqual({
      outcome: true,
      users: [user(ADA), saved, user(CARLA), user(DORA), user(EMIL)],
      editUserId: null,
      editError: null,
      editBusy: false,
      toasts: [{ kind: 'success', title: msg('toast.orgUsers.profileSaved') }],
    });
  });

  it('is busy while the profile is being saved, and not afterwards', async () => {
    const { store } = await setup();
    store.openEdit(BRUNO);
    const response = deferred<OrgUser>();
    api.updateOrgUser.mockReturnValueOnce(response.promise);

    const done = settled(store.submitEdit({ name: 'Bruno Neu', email: 'bruno@example.ch' }));
    const during = store.editBusy;
    response.reject(apiError(409, 'email_taken'));
    await done;

    expect({ during, after: store.editBusy }).toEqual({ during: true, after: false });
  });

  it('refuses a second save while the first is in flight, with no second request', async () => {
    const { store } = await setup();
    store.openEdit(BRUNO);
    const response = deferred<OrgUser>();
    api.updateOrgUser.mockReturnValueOnce(response.promise);

    const first = settled(store.submitEdit({ name: 'Bruno Neu', email: 'bruno@example.ch' }));
    const second = await settled(store.submitEdit({ name: 'Bruno Neu', email: 'bruno@example.ch' }));
    response.reject(apiError(409, 'email_taken'));
    await first;

    expect({ second, calls: api.updateOrgUser.mock.calls.length }).toEqual({ second: false, calls: 1 });
  });

  it.each<[string, unknown, string]>([
    ['a taken email (409 email_taken)', apiError(409, 'email_taken'), 'orgUsers.error.emailTaken'],
    ['a user of another org or a deleted one (404)', apiError(404), 'orgUsers.error.userNotFound'],
    ['a rejected value (422)', apiError(422), 'orgUsers.error.invalidInput'],
    ['a network failure', new TypeError('Failed to fetch'), 'orgUsers.error.generic'],
  ])('surfaces %s as editError and keeps the sheet open with the users unchanged', async (_label, error, key) => {
    const { store } = await setup();
    store.openEdit(BRUNO);
    api.updateOrgUser.mockRejectedValueOnce(error);

    const outcome = await settled(store.submitEdit({ name: 'Bruno Editor', email: 'emil@example.ch' }));

    expect({
      outcome,
      editError: store.editError,
      editUserId: store.editUserId,
      users: store.users,
      toasts: toastSummary(),
    }).toEqual({
      outcome: false,
      editError: msg(key),
      editUserId: BRUNO,
      users: allUsers(),
      toasts: [],
    });
  });
});

// --- Confirm sheet: request*, cancelPending ----------------------------------

type Store = ReturnType<typeof useOrgUsersStore>;

describe('orgUsersStore request* (open the confirm sheet, never call the API)', () => {
  it.each<[string, (store: Store) => void, unknown]>([
    ['requestRoleChange', (s) => s.requestRoleChange(BRUNO, 'org_admin'), { kind: 'role', userId: BRUNO, role: 'org_admin' }],
    ['requestRoleChange on a Viewer', (s) => s.requestRoleChange(DORA, 'editor'), { kind: 'role', userId: DORA, role: 'editor' }],
    ['requestDeactivate', (s) => s.requestDeactivate(BRUNO), { kind: 'deactivate', userId: BRUNO }],
    ['requestReactivate', (s) => s.requestReactivate(CARLA), { kind: 'reactivate', userId: CARLA }],
    ['requestPasswordReset', (s) => s.requestPasswordReset(BRUNO), { kind: 'resetPassword', userId: BRUNO }],
    ['requestForceLogout', (s) => s.requestForceLogout(BRUNO), { kind: 'forceLogout', userId: BRUNO }],
    ['requestForceLogout on a deactivated user', (s) => s.requestForceLogout(CARLA), { kind: 'forceLogout', userId: CARLA }],
    ['requestDelete', (s) => s.requestDelete(BRUNO), { kind: 'delete', userId: BRUNO }],
    ['requestDelete on a deactivated user', (s) => s.requestDelete(CARLA), { kind: 'delete', userId: CARLA }],
    [
      'requestRevokeInvitation',
      (s) => s.requestRevokeInvitation(FINN_INVITE),
      { kind: 'revokeInvitation', invitationId: FINN_INVITE },
    ],
  ])('%s opens the confirm sheet and makes no API call', async (_label, request, pending) => {
    const { store, loadMe, logout } = await setup();
    const before = dataSnapshot(store);

    request(store);

    expect({
      pending: store.pending,
      actionError: store.actionError,
      calls: apiCalls(),
      data: dataSnapshot(store),
      auth: [loadMe.mock.calls.length, logout.mock.calls.length],
      toasts: toastSummary(),
    }).toEqual({ pending, actionError: null, calls: NO_CALLS, data: before, auth: [0, 0], toasts: [] });
  });

  it.each<[string, (store: Store) => void]>([
    ['requestRoleChange to Viewer (not offered in V1)', (s) => s.requestRoleChange(BRUNO, 'viewer')],
    ['requestRoleChange to the current role', (s) => s.requestRoleChange(BRUNO, 'editor')],
    ['requestRoleChange to an unknown role', (s) => s.requestRoleChange(BRUNO, 'owner' as MemberRole)],
    ['requestRoleChange for an unknown user', (s) => s.requestRoleChange(UNKNOWN, 'org_admin')],
    ['requestDeactivate for a deactivated user', (s) => s.requestDeactivate(CARLA)],
    ['requestDeactivate for an unknown user', (s) => s.requestDeactivate(UNKNOWN)],
    ['requestReactivate for an active user', (s) => s.requestReactivate(BRUNO)],
    ['requestReactivate for an unknown user', (s) => s.requestReactivate(UNKNOWN)],
    ['requestPasswordReset for a deactivated user', (s) => s.requestPasswordReset(CARLA)],
    ['requestPasswordReset for an unknown user', (s) => s.requestPasswordReset(UNKNOWN)],
    ['requestForceLogout for an unknown user', (s) => s.requestForceLogout(UNKNOWN)],
    ['requestDelete for an unknown user', (s) => s.requestDelete(UNKNOWN)],
    ['requestDelete for an invitation id', (s) => s.requestDelete(FINN_INVITE)],
    ['requestRevokeInvitation for an unknown invitation', (s) => s.requestRevokeInvitation(UNKNOWN)],
    ['requestRevokeInvitation for a user id', (s) => s.requestRevokeInvitation(BRUNO)],
  ])('%s changes nothing and makes no API call', async (_label, request) => {
    const { store } = await setup();
    store.requestForceLogout(EMIL);

    expect(() => request(store)).not.toThrow();
    expect({ pending: store.pending, calls: apiCalls() }).toEqual({
      pending: { kind: 'forceLogout', userId: EMIL },
      calls: NO_CALLS,
    });
  });

  it('a no-op request leaves the sheet closed when nothing was pending', async () => {
    const { store } = await setup();

    store.requestRoleChange(BRUNO, 'viewer');
    store.requestReactivate(BRUNO);
    store.requestRevokeInvitation(UNKNOWN);

    expect(store.pending).toBeNull();
  });

  it('cancelPending closes the sheet without an API call and changes no data', async () => {
    const { store, loadMe, logout } = await setup();
    store.requestDelete(BRUNO);
    const before = dataSnapshot(store);

    store.cancelPending();

    expect({
      pending: store.pending,
      actionError: store.actionError,
      calls: apiCalls(),
      data: dataSnapshot(store),
      auth: [loadMe.mock.calls.length, logout.mock.calls.length],
      toasts: toastSummary(),
    }).toEqual({ pending: null, actionError: null, calls: NO_CALLS, data: before, auth: [0, 0], toasts: [] });
  });

  it.each<[string, (store: Store) => void]>([
    ['a role change', (s) => s.requestRoleChange(ADA, 'editor')],
    ['a deactivation', (s) => s.requestDeactivate(BRUNO)],
    ['a reactivation', (s) => s.requestReactivate(CARLA)],
    ['a password reset', (s) => s.requestPasswordReset(BRUNO)],
    ['a forced logout', (s) => s.requestForceLogout(BRUNO)],
    ['a deletion', (s) => s.requestDelete(BRUNO)],
    ['an invitation revocation', (s) => s.requestRevokeInvitation(FINN_INVITE)],
  ])('cancelling %s makes no API call at all', async (_label, request) => {
    const { store } = await setup();
    request(store);

    store.cancelPending();

    expect({ pending: store.pending, calls: apiCalls() }).toEqual({ pending: null, calls: NO_CALLS });
  });

  it('cancelPending after a failed confirmation clears the error without another call', async () => {
    const { store } = await setup();
    store.requestRoleChange(ADA, 'editor');
    api.updateOrgUser.mockRejectedValueOnce(apiError(409, 'last_admin'));
    await store.confirmPending();

    store.cancelPending();

    expect({ pending: store.pending, actionError: store.actionError, calls: apiCalls() }).toEqual({
      pending: null,
      actionError: null,
      calls: { ...NO_CALLS, updateOrgUser: 1 },
    });
  });

  it('a new request after a failed confirmation replaces the sheet and clears the error', async () => {
    const { store } = await setup();
    store.requestDelete(ADA);
    api.deleteOrgUser.mockRejectedValueOnce(apiError(409, 'last_admin'));
    await store.confirmPending();

    store.requestPasswordReset(BRUNO);

    expect({ pending: store.pending, actionError: store.actionError }).toEqual({
      pending: { kind: 'resetPassword', userId: BRUNO },
      actionError: null,
    });
  });
});

// --- confirmPending: role change ------------------------------------------------

describe('orgUsersStore role-change flow', () => {
  it('confirm sends PATCH with ONLY the role, replaces the user, toasts and closes the sheet', async () => {
    const { store, loadMe, logout } = await setup();
    store.requestRoleChange(BRUNO, 'org_admin');
    const promoted = user(BRUNO, { role: 'org_admin' });
    api.updateOrgUser.mockResolvedValueOnce(promoted);

    const outcome = await settled(store.confirmPending());

    expect({
      outcome,
      updateCalls: api.updateOrgUser.mock.calls,
      calls: apiCalls(),
      users: store.users,
      seats: store.seats,
      pending: store.pending,
      actionError: store.actionError,
      actionBusy: store.actionBusy,
      toasts: toastSummary(),
      auth: [loadMe.mock.calls.length, logout.mock.calls.length],
    }).toStrictEqual({
      outcome: 'done',
      updateCalls: [[BRUNO, { role: 'org_admin' }]],
      calls: { ...NO_CALLS, updateOrgUser: 1 },
      users: [user(ADA), promoted, user(CARLA), user(DORA), user(EMIL)],
      seats: seats(),
      pending: null,
      actionError: null,
      actionBusy: false,
      toasts: [{ kind: 'success', title: msg('toast.orgUsers.roleChanged') }],
      auth: [0, 0],
    });
  });

  it('promotes a Viewer to Editor with a role-only body', async () => {
    const { store } = await setup();
    store.requestRoleChange(DORA, 'editor');
    api.updateOrgUser.mockResolvedValueOnce(user(DORA, { role: 'editor' }));

    const outcome = await store.confirmPending();

    expect({ outcome, updateCalls: api.updateOrgUser.mock.calls }).toStrictEqual({
      outcome: 'done',
      updateCalls: [[DORA, { role: 'editor' }]],
    });
  });

  it('surfaces the last-admin guard (409 last_admin) as a clear message and keeps the sheet open', async () => {
    const { store, loadMe, logout } = await setup();
    store.requestRoleChange(ADA, 'editor');
    const before = dataSnapshot(store);
    api.updateOrgUser.mockRejectedValueOnce(apiError(409, 'last_admin'));

    const outcome = await settled(store.confirmPending());

    expect({
      outcome,
      actionError: store.actionError,
      pending: store.pending,
      data: dataSnapshot(store),
      actionBusy: store.actionBusy,
      toasts: toastSummary(),
      auth: [loadMe.mock.calls.length, logout.mock.calls.length],
      calls: apiCalls(),
    }).toEqual({
      outcome: 'failed',
      actionError: msg('orgUsers.error.lastAdmin'),
      pending: { kind: 'role', userId: ADA, role: 'editor' },
      data: before,
      actionBusy: false,
      toasts: [],
      auth: [0, 0],
      calls: { ...NO_CALLS, updateOrgUser: 1 },
    });
  });

  it('shows the last-admin message in the active locale, never the backend text', async () => {
    const { store } = await setup();
    setLocale('de');
    store.requestRoleChange(ADA, 'editor');
    api.updateOrgUser.mockRejectedValueOnce(apiError(409, 'last_admin'));

    await store.confirmPending();

    expect({ actionError: store.actionError, echoesDetail: store.actionError?.includes(DETAIL) }).toEqual({
      actionError: text(DE, 'orgUsers.error.lastAdmin'),
      echoesDetail: false,
    });
  });

  it('can retry after a failure: the second confirmation makes the second call', async () => {
    const { store } = await setup();
    store.requestRoleChange(ADA, 'editor');
    api.updateOrgUser
      .mockRejectedValueOnce(apiError(409, 'last_admin'))
      .mockResolvedValueOnce(user(ADA, { role: 'editor' }));

    const first = await store.confirmPending();
    const second = await store.confirmPending();

    expect({ first, second, updateCalls: api.updateOrgUser.mock.calls, pending: store.pending }).toStrictEqual({
      first: 'failed',
      second: 'done',
      updateCalls: [
        [ADA, { role: 'editor' }],
        [ADA, { role: 'editor' }],
      ],
      pending: null,
    });
  });

  it('reloads your own profile after changing your own role', async () => {
    const { store, loadMe, logout } = await setup();
    store.requestRoleChange(ADA, 'editor');
    api.updateOrgUser.mockResolvedValueOnce(user(ADA, { role: 'editor' }));

    const outcome = await settled(store.confirmPending());

    expect({ outcome, loadMe: loadMe.mock.calls.length, logout: logout.mock.calls.length }).toEqual({
      outcome: 'done',
      loadMe: 1,
      logout: 0,
    });
  });

  it('waits for your profile to reload before it resolves', async () => {
    const { store, loadMe } = await setup();
    const reloaded = deferred<boolean>();
    loadMe.mockReturnValueOnce(reloaded.promise);
    store.requestRoleChange(ADA, 'editor');
    api.updateOrgUser.mockResolvedValueOnce(user(ADA, { role: 'editor' }));

    let resolved = false;
    const done = store.confirmPending().then((outcome) => {
      resolved = true;
      return outcome;
    });
    await flush();
    const beforeReload = resolved;
    reloaded.resolve(true);
    const outcome = await done;

    expect({ beforeReload, outcome, loadMe: loadMe.mock.calls.length }).toEqual({
      beforeReload: false,
      outcome: 'done',
      loadMe: 1,
    });
  });

  it("leaves your session alone when another user's role changes", async () => {
    const { store, loadMe, logout } = await setup();
    store.requestRoleChange(EMIL, 'editor');
    api.updateOrgUser.mockResolvedValueOnce(user(EMIL, { role: 'editor' }));

    await store.confirmPending();

    expect([loadMe.mock.calls.length, logout.mock.calls.length]).toEqual([0, 0]);
  });

  it('is busy while the role change is in flight, and not afterwards', async () => {
    const { store } = await setup();
    store.requestRoleChange(BRUNO, 'org_admin');
    const response = deferred<OrgUser>();
    api.updateOrgUser.mockReturnValueOnce(response.promise);

    const done = settled(store.confirmPending());
    const during = store.actionBusy;
    response.resolve(user(BRUNO, { role: 'org_admin' }));
    await done;

    expect({ during, after: store.actionBusy }).toEqual({ during: true, after: false });
  });
});

// --- confirmPending: delete -------------------------------------------------------

describe('orgUsersStore delete flow', () => {
  it('confirm deletes the user once, removes them, frees an active user\'s seat and toasts', async () => {
    const { store, loadMe, logout } = await setup({ seats: seats(7, 10) });
    store.requestDelete(BRUNO);
    api.deleteOrgUser.mockResolvedValueOnce(undefined);

    const outcome = await settled(store.confirmPending());

    expect({
      outcome,
      deleteCalls: api.deleteOrgUser.mock.calls,
      calls: apiCalls(),
      users: ids(store.users),
      seats: store.seats,
      pending: store.pending,
      actionError: store.actionError,
      toasts: toastSummary(),
      auth: [loadMe.mock.calls.length, logout.mock.calls.length],
    }).toStrictEqual({
      outcome: 'done',
      deleteCalls: [[BRUNO]],
      calls: { ...NO_CALLS, deleteOrgUser: 1 },
      users: [ADA, CARLA, DORA, EMIL],
      seats: seats(6, 10),
      pending: null,
      actionError: null,
      toasts: [{ kind: 'success', title: msg('toast.orgUsers.deleted') }],
      auth: [0, 0],
    });
  });

  it('keeps the seat count when the deleted user was deactivated (they held no seat)', async () => {
    const { store } = await setup({ seats: seats(7, 10) });
    store.requestDelete(CARLA);
    api.deleteOrgUser.mockResolvedValueOnce(undefined);

    const outcome = await store.confirmPending();

    expect({ outcome, users: ids(store.users), seats: store.seats }).toEqual({
      outcome: 'done',
      users: [ADA, BRUNO, DORA, EMIL],
      seats: seats(7, 10),
    });
  });

  it('cancel makes no API call and keeps the user', async () => {
    const { store } = await setup();
    store.requestDelete(BRUNO);

    store.cancelPending();

    expect({ calls: apiCalls(), users: ids(store.users), seats: store.seats }).toEqual({
      calls: NO_CALLS,
      users: USER_ORDER,
      seats: seats(),
    });
  });

  it('surfaces the last-admin guard as a message and keeps the user and the sheet', async () => {
    const { store, logout } = await setup();
    store.requestDelete(ADA);
    const before = dataSnapshot(store);
    api.deleteOrgUser.mockRejectedValueOnce(apiError(409, 'last_admin'));

    const outcome = await settled(store.confirmPending());

    expect({
      outcome,
      actionError: store.actionError,
      pending: store.pending,
      data: dataSnapshot(store),
      toasts: toastSummary(),
      logout: logout.mock.calls.length,
    }).toEqual({
      outcome: 'failed',
      actionError: msg('orgUsers.error.lastAdmin'),
      pending: { kind: 'delete', userId: ADA },
      data: before,
      toasts: [],
      logout: 0,
    });
  });

  it('a 404 (another org\'s or an already deleted user) reads "user not found"', async () => {
    const { store } = await setup();
    store.requestDelete(BRUNO);
    api.deleteOrgUser.mockRejectedValueOnce(apiError(404));

    const outcome = await store.confirmPending();

    expect({ outcome, actionError: store.actionError, users: ids(store.users) }).toEqual({
      outcome: 'failed',
      actionError: msg('orgUsers.error.userNotFound'),
      users: USER_ORDER,
    });
  });

  it('deleting your own account logs you out and reports signed_out', async () => {
    const { store, loadMe, logout } = await setup();
    store.requestDelete(ADA);
    api.deleteOrgUser.mockResolvedValueOnce(undefined);

    const outcome = await settled(store.confirmPending());

    expect({
      outcome,
      deleteCalls: api.deleteOrgUser.mock.calls,
      logout: logout.mock.calls.length,
      loadMe: loadMe.mock.calls.length,
    }).toEqual({ outcome: 'signed_out', deleteCalls: [[ADA]], logout: 1, loadMe: 0 });
  });
});

// --- confirmPending: deactivate / reactivate -----------------------------------

describe('orgUsersStore deactivate and reactivate', () => {
  it('deactivate calls the API once, replaces the user, frees a seat and toasts', async () => {
    const { store, logout } = await setup({ seats: seats(7, 10) });
    store.requestDeactivate(BRUNO);
    const deactivated = user(BRUNO, { status: 'deactivated' });
    api.deactivateOrgUser.mockResolvedValueOnce(deactivated);

    const outcome = await settled(store.confirmPending());

    expect({
      outcome,
      deactivateCalls: api.deactivateOrgUser.mock.calls,
      calls: apiCalls(),
      users: store.users,
      seats: store.seats,
      pending: store.pending,
      toasts: toastSummary(),
      logout: logout.mock.calls.length,
    }).toStrictEqual({
      outcome: 'done',
      deactivateCalls: [[BRUNO]],
      calls: { ...NO_CALLS, deactivateOrgUser: 1 },
      users: [user(ADA), deactivated, user(CARLA), user(DORA), user(EMIL)],
      seats: seats(6, 10),
      pending: null,
      toasts: [{ kind: 'success', title: msg('toast.orgUsers.deactivated') }],
      logout: 0,
    });
  });

  it('a deactivated user leaves the "active" view and joins the "deactivated" one', async () => {
    const { store } = await setup();
    store.setStatusFilter('active');
    store.requestDeactivate(BRUNO);
    api.deactivateOrgUser.mockResolvedValueOnce(user(BRUNO, { status: 'deactivated' }));

    await store.confirmPending();
    const active = ids(store.visibleUsers);
    store.setStatusFilter('deactivated');

    expect({ active, deactivated: ids(store.visibleUsers) }).toEqual({
      active: [ADA, DORA, EMIL],
      deactivated: [BRUNO, CARLA],
    });
  });

  it('deactivating your own account logs you out and reports signed_out', async () => {
    const { store, logout } = await setup();
    store.requestDeactivate(ADA);
    api.deactivateOrgUser.mockResolvedValueOnce(user(ADA, { status: 'deactivated' }));

    const outcome = await settled(store.confirmPending());

    expect({ outcome, deactivateCalls: api.deactivateOrgUser.mock.calls, logout: logout.mock.calls.length }).toEqual({
      outcome: 'signed_out',
      deactivateCalls: [[ADA]],
      logout: 1,
    });
  });

  it('waits for the logout to finish before reporting signed_out', async () => {
    const { store, logout } = await setup();
    const loggedOut = deferred<void>();
    logout.mockReturnValueOnce(loggedOut.promise);
    store.requestDeactivate(ADA);
    api.deactivateOrgUser.mockResolvedValueOnce(user(ADA, { status: 'deactivated' }));

    let resolved = false;
    const done = store.confirmPending().then((outcome) => {
      resolved = true;
      return outcome;
    });
    await flush();
    const beforeLogout = resolved;
    loggedOut.resolve();
    const outcome = await done;

    expect({ beforeLogout, outcome }).toEqual({ beforeLogout: false, outcome: 'signed_out' });
  });

  it.each<[string, unknown, string]>([
    ['the last-admin guard (409 last_admin)', apiError(409, 'last_admin'), 'orgUsers.error.lastAdmin'],
    ['a changed status (409 invalid_status)', apiError(409, 'invalid_status'), 'orgUsers.error.invalidStatus'],
    ['a missing user (404)', apiError(404), 'orgUsers.error.userNotFound'],
  ])('deactivate surfaces %s and changes nothing', async (_label, error, key) => {
    const { store, logout } = await setup();
    store.requestDeactivate(ADA);
    const before = dataSnapshot(store);
    api.deactivateOrgUser.mockRejectedValueOnce(error);

    const outcome = await settled(store.confirmPending());

    expect({
      outcome,
      actionError: store.actionError,
      pending: store.pending,
      data: dataSnapshot(store),
      toasts: toastSummary(),
      logout: logout.mock.calls.length,
    }).toEqual({
      outcome: 'failed',
      actionError: msg(key),
      pending: { kind: 'deactivate', userId: ADA },
      data: before,
      toasts: [],
      logout: 0,
    });
  });

  it('reactivate calls the API once, replaces the user, takes a seat and toasts', async () => {
    const { store } = await setup({ seats: seats(7, 10) });
    store.requestReactivate(CARLA);
    const reactivated = user(CARLA, { status: 'active' });
    api.reactivateOrgUser.mockResolvedValueOnce(reactivated);

    const outcome = await settled(store.confirmPending());

    expect({
      outcome,
      reactivateCalls: api.reactivateOrgUser.mock.calls,
      calls: apiCalls(),
      users: store.users,
      seats: store.seats,
      pending: store.pending,
      toasts: toastSummary(),
    }).toStrictEqual({
      outcome: 'done',
      reactivateCalls: [[CARLA]],
      calls: { ...NO_CALLS, reactivateOrgUser: 1 },
      users: [user(ADA), user(BRUNO), reactivated, user(DORA), user(EMIL)],
      seats: seats(8, 10),
      pending: null,
      toasts: [{ kind: 'success', title: msg('toast.orgUsers.reactivated') }],
    });
  });

  it.each<[string, unknown, string]>([
    ['the seat limit (409 seat_limit)', apiError(409, 'seat_limit'), 'orgUsers.error.seatLimit'],
    ['a changed status (409 invalid_status)', apiError(409, 'invalid_status'), 'orgUsers.error.invalidStatus'],
  ])('reactivate surfaces %s and keeps the seats', async (_label, error, key) => {
    const { store } = await setup({ seats: seats(10, 10) });
    store.requestReactivate(CARLA);
    const before = dataSnapshot(store);
    api.reactivateOrgUser.mockRejectedValueOnce(error);

    const outcome = await settled(store.confirmPending());

    expect({ outcome, actionError: store.actionError, pending: store.pending, data: dataSnapshot(store) }).toEqual({
      outcome: 'failed',
      actionError: msg(key),
      pending: { kind: 'reactivate', userId: CARLA },
      data: before,
    });
  });
});

// --- confirmPending: password reset / force logout ---------------------------

describe('orgUsersStore password reset and forced logout', () => {
  it('password reset calls the API once, changes no data and toasts', async () => {
    const { store, logout } = await setup();
    store.requestPasswordReset(BRUNO);
    const before = dataSnapshot(store);
    api.resetOrgUserPassword.mockResolvedValueOnce(undefined);

    const outcome = await settled(store.confirmPending());

    expect({
      outcome,
      resetCalls: api.resetOrgUserPassword.mock.calls,
      calls: apiCalls(),
      data: dataSnapshot(store),
      pending: store.pending,
      toasts: toastSummary(),
      logout: logout.mock.calls.length,
    }).toStrictEqual({
      outcome: 'done',
      resetCalls: [[BRUNO]],
      calls: { ...NO_CALLS, resetOrgUserPassword: 1 },
      data: before,
      pending: null,
      toasts: [{ kind: 'success', title: msg('toast.orgUsers.passwordResetSent') }],
      logout: 0,
    });
  });

  it('a password reset for your own account keeps you signed in', async () => {
    const { store, loadMe, logout } = await setup();
    store.requestPasswordReset(ADA);
    api.resetOrgUserPassword.mockResolvedValueOnce(undefined);

    const outcome = await settled(store.confirmPending());

    expect({ outcome, auth: [loadMe.mock.calls.length, logout.mock.calls.length] }).toEqual({
      outcome: 'done',
      auth: [0, 0],
    });
  });

  it('a rate-limited password reset (429) keeps the sheet open with the message', async () => {
    const { store } = await setup();
    store.requestPasswordReset(BRUNO);
    api.resetOrgUserPassword.mockRejectedValueOnce(apiError(429));

    const outcome = await settled(store.confirmPending());

    expect({ outcome, actionError: store.actionError, pending: store.pending, toasts: toastSummary() }).toEqual({
      outcome: 'failed',
      actionError: msg('orgUsers.error.rateLimited'),
      pending: { kind: 'resetPassword', userId: BRUNO },
      toasts: [],
    });
  });

  it('force logout calls the API once, changes no data and toasts', async () => {
    const { store, logout } = await setup();
    store.requestForceLogout(BRUNO);
    const before = dataSnapshot(store);
    api.forceLogoutOrgUser.mockResolvedValueOnce(undefined);

    const outcome = await settled(store.confirmPending());

    expect({
      outcome,
      forceLogoutCalls: api.forceLogoutOrgUser.mock.calls,
      calls: apiCalls(),
      data: dataSnapshot(store),
      pending: store.pending,
      toasts: toastSummary(),
      logout: logout.mock.calls.length,
    }).toStrictEqual({
      outcome: 'done',
      forceLogoutCalls: [[BRUNO]],
      calls: { ...NO_CALLS, forceLogoutOrgUser: 1 },
      data: before,
      pending: null,
      toasts: [{ kind: 'success', title: msg('toast.orgUsers.loggedOut') }],
      logout: 0,
    });
  });

  it('forcing your own logout logs you out and reports signed_out', async () => {
    const { store, logout } = await setup();
    store.requestForceLogout(ADA);
    api.forceLogoutOrgUser.mockResolvedValueOnce(undefined);

    const outcome = await settled(store.confirmPending());

    expect({ outcome, forceLogoutCalls: api.forceLogoutOrgUser.mock.calls, logout: logout.mock.calls.length }).toEqual({
      outcome: 'signed_out',
      forceLogoutCalls: [[ADA]],
      logout: 1,
    });
  });

  it('a failed forced logout of your own account keeps you signed in', async () => {
    const { store, logout } = await setup();
    store.requestForceLogout(ADA);
    api.forceLogoutOrgUser.mockRejectedValueOnce(apiError(404));

    const outcome = await settled(store.confirmPending());

    expect({ outcome, actionError: store.actionError, logout: logout.mock.calls.length }).toEqual({
      outcome: 'failed',
      actionError: msg('orgUsers.error.userNotFound'),
      logout: 0,
    });
  });
});

// --- confirmPending: revoke invitation -----------------------------------------

describe('orgUsersStore revoke invitation', () => {
  it('confirm revokes once, removes the invitation, frees a seat and toasts', async () => {
    const { store } = await setup({ seats: seats(7, 10) });
    store.requestRevokeInvitation(FINN_INVITE);
    api.revokeInvitation.mockResolvedValueOnce(undefined);

    const outcome = await settled(store.confirmPending());

    expect({
      outcome,
      revokeCalls: api.revokeInvitation.mock.calls,
      calls: apiCalls(),
      invitations: ids(store.invitations),
      users: store.users,
      seats: store.seats,
      pending: store.pending,
      toasts: toastSummary(),
    }).toStrictEqual({
      outcome: 'done',
      revokeCalls: [[FINN_INVITE]],
      calls: { ...NO_CALLS, revokeInvitation: 1 },
      invitations: [GINA_INVITE],
      users: allUsers(),
      seats: seats(6, 10),
      pending: null,
      toasts: [{ kind: 'success', title: msg('toast.orgUsers.invitationRevoked') }],
    });
  });

  it('frees the seat again when a full org revokes an invitation', async () => {
    const { store } = await setup({ seats: seats(10, 10) });
    store.requestRevokeInvitation(GINA_INVITE);
    api.revokeInvitation.mockResolvedValueOnce(undefined);

    await store.confirmPending();

    expect({ seats: store.seats, noFreeSeat: store.noFreeSeat }).toEqual({ seats: seats(9, 10), noFreeSeat: false });
  });

  it('a 404 reads "invitation not found", not "user not found"', async () => {
    const { store } = await setup();
    store.requestRevokeInvitation(FINN_INVITE);
    const before = dataSnapshot(store);
    api.revokeInvitation.mockRejectedValueOnce(apiError(404));

    const outcome = await settled(store.confirmPending());

    expect({
      outcome,
      actionError: store.actionError,
      pending: store.pending,
      data: dataSnapshot(store),
      toasts: toastSummary(),
    }).toEqual({
      outcome: 'failed',
      actionError: msg('orgUsers.error.invitationNotFound'),
      pending: { kind: 'revokeInvitation', invitationId: FINN_INVITE },
      data: before,
      toasts: [],
    });
  });
});

// --- Seat arithmetic bounds ---------------------------------------------------

describe('orgUsersStore seat arithmetic', () => {
  it.each<[string, (store: Store) => void, ApiName, unknown]>([
    ['a deactivation', (s) => s.requestDeactivate(BRUNO), 'deactivateOrgUser', user(BRUNO, { status: 'deactivated' })],
    ['a deletion of an active user', (s) => s.requestDelete(BRUNO), 'deleteOrgUser', undefined],
    ['a revocation', (s) => s.requestRevokeInvitation(FINN_INVITE), 'revokeInvitation', undefined],
  ])('never counts below 0 seats after %s', async (_label, request, name, response) => {
    const { store } = await setup({ seats: seats(0, 10) });
    request(store);
    api[name].mockResolvedValueOnce(response as never);

    const outcome = await store.confirmPending();

    expect({ outcome, seats: store.seats }).toEqual({ outcome: 'done', seats: seats(0, 10) });
  });

  it.each<[string, (store: Store) => void, ApiName, unknown]>([
    ['a deactivation', (s) => s.requestDeactivate(BRUNO), 'deactivateOrgUser', user(BRUNO, { status: 'deactivated' })],
    ['a reactivation', (s) => s.requestReactivate(CARLA), 'reactivateOrgUser', user(CARLA, { status: 'active' })],
    ['a deletion', (s) => s.requestDelete(BRUNO), 'deleteOrgUser', undefined],
    ['a revocation', (s) => s.requestRevokeInvitation(FINN_INVITE), 'revokeInvitation', undefined],
  ])('leaves unknown seats unknown after %s', async (_label, request, name, response) => {
    const { store } = await setup();
    store.seats = null;
    request(store);
    api[name].mockResolvedValueOnce(response as never);

    const outcome = await settled(store.confirmPending());

    expect({ outcome, seats: store.seats, seatText: store.seatText }).toEqual({
      outcome: 'done',
      seats: null,
      seatText: null,
    });
  });
});

// --- confirmPending guards ------------------------------------------------------

describe('orgUsersStore confirmPending guards', () => {
  it('reports failed and calls nothing when nothing is pending', async () => {
    const { store, loadMe, logout } = await setup();

    const outcome = await settled(store.confirmPending());

    expect({
      outcome,
      calls: apiCalls(),
      toasts: toastSummary(),
      auth: [loadMe.mock.calls.length, logout.mock.calls.length],
    }).toEqual({ outcome: 'failed', calls: NO_CALLS, toasts: [], auth: [0, 0] });
  });

  it('reports failed and calls nothing after the sheet was cancelled', async () => {
    const { store } = await setup();
    store.requestDelete(BRUNO);
    store.cancelPending();

    const outcome = await settled(store.confirmPending());

    expect({ outcome, calls: apiCalls(), users: ids(store.users) }).toEqual({
      outcome: 'failed',
      calls: NO_CALLS,
      users: USER_ORDER,
    });
  });

  it('a second confirmation while the first is in flight fails without a second call', async () => {
    const { store } = await setup({ seats: seats(7, 10) });
    store.requestDelete(BRUNO);
    const response = deferred<void>();
    api.deleteOrgUser.mockReturnValueOnce(response.promise);

    const first = settled(store.confirmPending());
    const busy = store.actionBusy;
    const second = await settled(store.confirmPending());
    response.resolve();
    const firstOutcome = await first;

    expect({
      busy,
      second,
      firstOutcome,
      deleteCalls: api.deleteOrgUser.mock.calls,
      calls: apiCalls(),
      users: ids(store.users),
      seats: store.seats,
      actionBusy: store.actionBusy,
      pending: store.pending,
    }).toEqual({
      busy: true,
      second: 'failed',
      firstOutcome: 'done',
      deleteCalls: [[BRUNO]],
      calls: { ...NO_CALLS, deleteOrgUser: 1 },
      users: [ADA, CARLA, DORA, EMIL],
      seats: seats(6, 10),
      actionBusy: false,
      pending: null,
    });
  });

  it.each<[string, (store: Store) => void, ApiName]>([
    ['role', (s) => s.requestRoleChange(BRUNO, 'org_admin'), 'updateOrgUser'],
    ['deactivate', (s) => s.requestDeactivate(BRUNO), 'deactivateOrgUser'],
    ['reactivate', (s) => s.requestReactivate(CARLA), 'reactivateOrgUser'],
    ['resetPassword', (s) => s.requestPasswordReset(BRUNO), 'resetOrgUserPassword'],
    ['forceLogout', (s) => s.requestForceLogout(BRUNO), 'forceLogoutOrgUser'],
    ['delete', (s) => s.requestDelete(BRUNO), 'deleteOrgUser'],
    ['revokeInvitation', (s) => s.requestRevokeInvitation(FINN_INVITE), 'revokeInvitation'],
  ])('a failed %s confirmation never throws, even on a non-Error rejection', async (_label, request, name) => {
    const { store } = await setup();
    request(store);
    api[name].mockRejectedValueOnce('boom' as never);

    const outcome = await settled(store.confirmPending());

    expect({ outcome, actionError: store.actionError, actionBusy: store.actionBusy, calls: apiCalls() }).toEqual({
      outcome: 'failed',
      actionError: msg('orgUsers.error.generic'),
      actionBusy: false,
      calls: { ...NO_CALLS, [name]: 1 },
    });
  });
});

// --- resendInvitation (no confirmation) -----------------------------------------

describe('orgUsersStore resendInvitation', () => {
  it('ignores an unknown invitation: false, no call, no toast', async () => {
    const { store } = await setup();

    const outcome = await settled(store.resendInvitation(UNKNOWN));

    expect({ outcome, calls: apiCalls(), toasts: toastSummary() }).toEqual({
      outcome: false,
      calls: NO_CALLS,
      toasts: [],
    });
  });

  it('resends once without a confirm sheet, replaces the invitation in place and toasts', async () => {
    // The expired invitation comes first, so a replace that moves it would be visible.
    const { store } = await setup({ seats: seats(7, 10), invitations: [invitation(GINA_INVITE), invitation(FINN_INVITE)] });
    const resent = invitation(GINA_INVITE, {
      sent_at: '2026-10-03T09:00:00Z',
      expires_at: '2026-10-10T09:00:00Z',
      expired: false,
    });
    api.resendInvitation.mockResolvedValueOnce(resent);

    const outcome = await settled(store.resendInvitation(GINA_INVITE));

    expect({
      outcome,
      resendCalls: api.resendInvitation.mock.calls,
      calls: apiCalls(),
      invitations: store.invitations,
      seats: store.seats,
      pending: store.pending,
      toasts: toastSummary(),
    }).toStrictEqual({
      outcome: true,
      resendCalls: [[GINA_INVITE]],
      calls: { ...NO_CALLS, resendInvitation: 1 },
      invitations: [resent, invitation(FINN_INVITE)],
      seats: seats(7, 10),
      pending: null,
      toasts: [{ kind: 'success', title: msg('toast.orgUsers.invitationResent') }],
    });
  });

  it.each<[string, unknown, string]>([
    ['a revoked or accepted invitation (404)', apiError(404), 'orgUsers.error.invitationNotFound'],
    ['the rate limit (429)', apiError(429), 'orgUsers.error.rateLimited'],
    ['a network failure', new TypeError('Failed to fetch'), 'orgUsers.error.generic'],
    ['a non-Error rejection', null, 'orgUsers.error.generic'],
  ])('shows %s as an error toast and returns false', async (_label, error, key) => {
    const { store } = await setup();
    const before = dataSnapshot(store);
    api.resendInvitation.mockRejectedValueOnce(error);

    const outcome = await settled(store.resendInvitation(FINN_INVITE));

    expect({ outcome, data: dataSnapshot(store), toasts: toastSummary() }).toEqual({
      outcome: false,
      data: before,
      toasts: [{ kind: 'error', title: msg('toast.orgUsers.failed'), body: msg(key) }],
    });
  });
});

// --- No logging of personal data ------------------------------------------------

describe('orgUsersStore logging', () => {
  it('never writes names, emails or backend text to the console in any flow', async () => {
    const methods = ['log', 'info', 'warn', 'error', 'debug'] as const;
    const spies = methods.map((method) => vi.spyOn(console, method).mockImplementation(() => undefined));
    const { store } = await setup();

    // Load failure and success.
    api.listOrgUsers.mockRejectedValueOnce(apiError(500));
    api.listInvitations.mockResolvedValueOnce({ invitations: [] });
    await store.load();
    api.listOrgUsers.mockResolvedValueOnce({ users: allUsers(), seats: seats() });
    api.listInvitations.mockResolvedValueOnce({ invitations: allInvitations() });
    await store.load();
    store.setQuery('bruno');
    store.setStatusFilter('nonsense');

    // Invite: invalid, failure, success.
    store.openInvite();
    await store.submitInvite('new.person@@example.ch', 'editor');
    await store.submitInvite('new.person@example.ch', 'viewer');
    api.createInvitation.mockRejectedValueOnce(apiError(409, 'email_taken'));
    await store.submitInvite('new.person@example.ch', 'editor');
    api.createInvitation.mockResolvedValueOnce(newInvitation());
    await store.submitInvite('new.person@example.ch', 'editor');

    // Edit: failure, success.
    store.openEdit(BRUNO);
    api.updateOrgUser.mockRejectedValueOnce(apiError(409, 'email_taken'));
    await store.submitEdit({ name: 'Bruno Neu', email: 'bruno.new@example.ch' });
    api.updateOrgUser.mockResolvedValueOnce(user(BRUNO, { name: 'Bruno Neu', email: 'bruno.new@example.ch' }));
    await store.submitEdit({ name: 'Bruno Neu', email: 'bruno.new@example.ch' });

    // Confirm flows: failures and successes.
    store.requestRoleChange(ADA, 'editor');
    api.updateOrgUser.mockRejectedValueOnce(apiError(409, 'last_admin'));
    await store.confirmPending();
    store.cancelPending();
    store.requestRoleChange(EMIL, 'editor');
    api.updateOrgUser.mockResolvedValueOnce(user(EMIL, { role: 'editor' }));
    await store.confirmPending();
    store.requestDeactivate(BRUNO);
    api.deactivateOrgUser.mockResolvedValueOnce(user(BRUNO, { status: 'deactivated' }));
    await store.confirmPending();
    store.requestReactivate(CARLA);
    api.reactivateOrgUser.mockRejectedValueOnce(apiError(409, 'seat_limit'));
    await store.confirmPending();
    store.requestPasswordReset(DORA);
    api.resetOrgUserPassword.mockResolvedValueOnce(undefined);
    await store.confirmPending();
    store.requestForceLogout(EMIL);
    api.forceLogoutOrgUser.mockResolvedValueOnce(undefined);
    await store.confirmPending();
    store.requestDelete(CARLA);
    api.deleteOrgUser.mockRejectedValueOnce(apiError(404));
    await store.confirmPending();
    store.requestRevokeInvitation(FINN_INVITE);
    api.revokeInvitation.mockResolvedValueOnce(undefined);
    await store.confirmPending();
    api.resendInvitation.mockRejectedValueOnce(apiError(429));
    await store.resendInvitation(GINA_INVITE);
    api.resendInvitation.mockResolvedValueOnce(invitation(GINA_INVITE, { expired: false }));
    await store.resendInvitation(GINA_INVITE);
    store.requestDelete(ADA);
    api.deleteOrgUser.mockResolvedValueOnce(undefined);
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
    const plainLogs = spies.slice(0, 1).concat(spies.slice(4)).map((spy) => spy.mock.calls.length);

    expect({ leaked, logAndDebugCalls: plainLogs, infoCalls: spies[1]?.mock.calls.length }).toEqual({
      leaked: [],
      logAndDebugCalls: [0, 0],
      infoCalls: 0,
    });
  });
});
