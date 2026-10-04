/**
 * Org settings store tests (issue #169: Organization profile, policies and
 * instructions; the Organization -> Settings page).
 *
 * `useOrgSettingsStore` (Pinia id 'orgSettings', `stores/orgSettings.ts`)
 * owns the Org Admin's settings page (contract §7):
 * - state: `settings` (null), `draft` (null), `loading` / `loaded` (false),
 *   `loadError` (null), `saving` (false), `saveError` (null), `issues` ([]).
 * - getters: `dirty` (the built patch is non-null), `dataResidency`
 *   (`settings?.data_residency ?? true`: fail closed while nothing is loaded)
 *   and `instructionsRemaining` (8000 minus the draft's code points; may be
 *   negative).
 * - `load()`: `GET /api/org/settings`; success sets `settings`, a fresh
 *   `draft` (the response's EFFECTIVE trash retention), `loaded` and clears
 *   `loadError`; a failure sets `loadError` to catalog text (never the
 *   server's detail) and keeps everything else. Never throws.
 * - `resetDraft()`: the draft back to the loaded settings; clears `issues`
 *   and `saveError`.
 * - `save()`: validates first (issues -> `issues`, no request, `false`); an
 *   unchanged draft -> no request, `true`; otherwise `PATCH /api/org/settings`
 *   with exactly the changed fields (display name trimmed, instructions
 *   verbatim; never `tools`, `data_residency`, `plan` or the trash bounds).
 *   Success applies the response (settings and a fresh draft), clears
 *   `issues` / `saveError`, toasts `toast.common.saved` and returns `true`.
 *   A failure sets the catalog `saveError` (400 `trash_retention_bounds`,
 *   400/422, 403, 429, anything else), KEEPS the draft, adds an error toast
 *   and returns `false`. `saving` is true while the PATCH is in flight; a
 *   second `save()` meanwhile returns `false` without a request. Never throws.
 *
 * Contract readings (where §7 leaves a detail open):
 * - `dirty` is false while nothing is loaded.
 * - `save()` before the first load sends nothing and does not throw.
 * - A save that passes validation leaves `issues` empty, also on the
 *   "nothing changed" path (stale issues never survive a clean draft).
 * - Only the error toast's kind is pinned (its title/body are the
 *   implementer's), but no toast or state ever carries the server's detail.
 *
 * Security notes: the store talks only to `getOrgSettings` /
 * `patchOrgSettings` of `@/api/settings` (mocked here; `fetch` is a spy that
 * must never be called). The read-only residency flag fails closed. Backend
 * error text never reaches the store state or a toast. `services/orgSettings`
 * (validation, patch building, error mapping) and the i18n catalogs are the
 * real ones. No component is mounted.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Mock } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import {
  disconnectOAuth,
  getMySettings,
  getOAuthAuthorizeUrl,
  getOAuthStatus,
  getOrgSettings,
  patchMySettings,
  patchOrgSettings,
  resetMySettings,
} from '@/api/settings';
import { ApiError } from '@/api/client';
import { setLocale } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';
import { useOrgSettingsStore } from '@/stores/orgSettings';
import { useToastStore } from '@/stores/toasts';
import type { OrgSettingsDraft, OrgSettingsIssue } from '@/services/orgSettings';
import type {
  OrgPlan,
  OrgProfile,
  OrgRetention,
  OrgSecurity,
  OrgSettingsPatch,
  OrgSettingsResponse,
  ToolsSettings,
} from '@/api/types';

vi.mock('@/api/settings', () => ({
  getMySettings: vi.fn(),
  patchMySettings: vi.fn(),
  resetMySettings: vi.fn(),
  getOrgSettings: vi.fn(),
  patchOrgSettings: vi.fn(),
  getOAuthStatus: vi.fn(),
  getOAuthAuthorizeUrl: vi.fn(),
  disconnectOAuth: vi.fn(),
}));

const api = {
  getOrgSettings: vi.mocked(getOrgSettings),
  patchOrgSettings: vi.mocked(patchOrgSettings),
};

const otherApi = [
  vi.mocked(getMySettings),
  vi.mocked(patchMySettings),
  vi.mocked(resetMySettings),
  vi.mocked(getOAuthStatus),
  vi.mocked(getOAuthAuthorizeUrl),
  vi.mocked(disconnectOAuth),
];

let fetchSpy: Mock<(...args: unknown[]) => Promise<never>>;

/** Requests that are not the org settings GET/PATCH (other API functions or raw fetch). */
function otherRequests(): number {
  return otherApi.reduce((sum, mock) => sum + mock.mock.calls.length, 0) + fetchSpy.mock.calls.length;
}

/** Deep copies of every PATCH body sent so far (never the live calls array). */
function patchBodies(): OrgSettingsPatch[] {
  return api.patchOrgSettings.mock.calls.map(([patch]) => JSON.parse(JSON.stringify(patch)) as OrgSettingsPatch);
}

// --- Fixtures -------------------------------------------------------------

/** 52 code points, 53 UTF-16 units (the trailing emoji is a surrogate pair). */
const INSTRUCTIONS = 'Sie antworten förmlich und nennen nie Kundennamen. 👋';

/** A server detail the store must never show or keep. */
const DETAIL = 'srv-detail-4f2a: retention outside 7..60 (stored 21)';

const ALL_TOOLS: ToolsSettings = {
  gmail: true,
  google_calendar: true,
  google_drive: true,
  outlook: true,
  outlook_calendar: true,
  onedrive: true,
  memory: true,
};

interface ResponseOverrides {
  profile?: Partial<OrgProfile>;
  instructions?: string;
  security?: Partial<OrgSecurity>;
  retention?: Partial<OrgRetention>;
  tools?: Partial<ToolsSettings>;
  data_residency?: boolean;
  plan?: Partial<OrgPlan>;
}

/**
 * A loaded org: non-default security values (45 min / 10 h) and platform
 * trash bounds of 7..60 days, so a store that falls back to code defaults or
 * the 0..90 model bounds is caught.
 */
function response(overrides: ResponseOverrides = {}): OrgSettingsResponse {
  return {
    profile: { display_name: 'Treuhand Muster AG', default_response_language: 'de', ...overrides.profile },
    instructions: overrides.instructions ?? INSTRUCTIONS,
    security: { session_idle_timeout_minutes: 45, session_max_lifetime_hours: 10, ...overrides.security },
    retention: { trash_retention_days: 21, trash_min_days: 7, trash_max_days: 60, ...overrides.retention },
    tools: { ...ALL_TOOLS, ...overrides.tools },
    data_residency: overrides.data_residency ?? false,
    plan: { seats: 25, storage_quota: 53_687_091_200, ...overrides.plan },
  };
}

/** The draft the contract's `draftFrom` makes of `settings` (written out here, not imported). */
function expectedDraft(settings: OrgSettingsResponse): OrgSettingsDraft {
  return {
    display_name: settings.profile.display_name,
    default_response_language: settings.profile.default_response_language,
    instructions: settings.instructions,
    session_idle_timeout_minutes: settings.security.session_idle_timeout_minutes,
    session_max_lifetime_hours: settings.security.session_max_lifetime_hours,
    trash_retention_days: settings.retention.trash_retention_days,
  };
}

type Catalog = Record<string, unknown>;

const EN: Catalog = en;
const DE: Catalog = de;
const FR: Catalog = fr;

/** The catalog's own non-blank string for `key`; throws when the catalog lacks it. */
function text(catalog: Catalog, key: string): string {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`the catalog has no text for ${key}`);
  }
  return value;
}

const ERROR = {
  trashBounds: 'organization.settings.error.trashBounds',
  invalid: 'organization.settings.error.invalid',
  forbidden: 'organization.settings.error.forbidden',
  rateLimited: 'organization.settings.error.rateLimited',
  generic: 'organization.settings.error.generic',
} as const;

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

/** What `promise` resolved with, or `{ threw }` when it rejected. */
async function settle<T>(promise: Promise<T>): Promise<T | { threw: unknown }> {
  try {
    return await promise;
  } catch (e) {
    return { threw: e };
  }
}

/** Lets pending microtasks and zero-delay timers run (the mocked request stays pending). */
function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function toastSummary(): Array<{ kind: string; title: string }> {
  return useToastStore().toasts.map(({ kind, title }) => ({ kind, title }));
}

/** Everything the store and the toasts hold, as one string (for "never the server detail" scans). */
function everythingShown(store: ReturnType<typeof useOrgSettingsStore>): string {
  return JSON.stringify({ state: store.$state, toasts: useToastStore().toasts });
}

type Store = ReturnType<typeof useOrgSettingsStore>;

/** A store loaded from `settings`, with every mock call log cleared. */
async function loadedStore(settings: OrgSettingsResponse = response()): Promise<Store> {
  api.getOrgSettings.mockResolvedValueOnce(settings);
  const store = useOrgSettingsStore();
  await store.load();
  if (store.draft === null) throw new Error('the store did not load');
  api.getOrgSettings.mockClear();
  api.patchOrgSettings.mockClear();
  return store;
}

/** Edits the loaded draft in place, the way a form's v-model does. */
function edit(store: Store, changes: Partial<OrgSettingsDraft>): void {
  if (store.draft === null) throw new Error('no draft to edit');
  Object.assign(store.draft, changes);
}

/** A copy of the store's draft (never the live object). */
function draftCopy(store: Store): OrgSettingsDraft | null {
  return store.draft === null ? null : { ...store.draft };
}

beforeEach(() => {
  localStorage.clear();
  setActivePinia(createPinia());
  api.getOrgSettings.mockReset();
  api.patchOrgSettings.mockReset();
  for (const mock of otherApi) mock.mockReset();
  fetchSpy = vi.fn<(...args: unknown[]) => Promise<never>>(() => Promise.reject(new TypeError('network disabled in tests')));
  vi.stubGlobal('fetch', fetchSpy);
});

afterEach(() => {
  setLocale('en');
});

// --- Initial state --------------------------------------------------------

describe('orgSettingsStore initial state', () => {
  it('is the "orgSettings" store with nothing loaded, residency assumed on (fail closed) and nothing dirty', () => {
    const store = useOrgSettingsStore();

    expect({
      id: store.$id,
      settings: store.settings,
      draft: store.draft,
      loading: store.loading,
      loaded: store.loaded,
      loadError: store.loadError,
      saving: store.saving,
      saveError: store.saveError,
      issues: store.issues,
      dataResidency: store.dataResidency,
      dirty: store.dirty,
    }).toStrictEqual({
      id: 'orgSettings',
      settings: null,
      draft: null,
      loading: false,
      loaded: false,
      loadError: null,
      saving: false,
      saveError: null,
      issues: [],
      dataResidency: true,
      dirty: false,
    });
  });

  it('asks nothing of the server until load() is called', () => {
    const store = useOrgSettingsStore();

    expect({
      id: store.$id,
      gets: api.getOrgSettings.mock.calls.length,
      patches: api.patchOrgSettings.mock.calls.length,
      other: otherRequests(),
    }).toEqual({ id: 'orgSettings', gets: 0, patches: 0, other: 0 });
  });
});

// --- load: GET /api/org/settings --------------------------------------------

describe('orgSettingsStore load', () => {
  it('stores the settings, builds the draft from them and marks the store loaded', async () => {
    const settings = response();
    api.getOrgSettings.mockResolvedValueOnce(settings);
    const store = useOrgSettingsStore();

    const outcome = await settle(store.load());

    expect({
      outcome,
      gets: api.getOrgSettings.mock.calls.length,
      getArgs: api.getOrgSettings.mock.calls[0],
      patches: api.patchOrgSettings.mock.calls.length,
      other: otherRequests(),
      settings: store.settings,
      draft: draftCopy(store),
      loading: store.loading,
      loaded: store.loaded,
      loadError: store.loadError,
      dirty: store.dirty,
    }).toStrictEqual({
      outcome: undefined,
      gets: 1,
      getArgs: [],
      patches: 0,
      other: 0,
      settings: response(),
      draft: {
        display_name: 'Treuhand Muster AG',
        default_response_language: 'de',
        instructions: INSTRUCTIONS,
        session_idle_timeout_minutes: 45,
        session_max_lifetime_hours: 10,
        trash_retention_days: 21,
      },
      loading: false,
      loaded: true,
      loadError: null,
      dirty: false,
    });
  });

  it('takes the draft\'s trash retention from the response\'s effective value, not a bound', async () => {
    const store = await loadedStore(
      response({ retention: { trash_retention_days: 14, trash_min_days: 14, trash_max_days: 40 } }),
    );

    expect(draftCopy(store)?.trash_retention_days).toBe(14);
  });

  it('is loading while the GET is in flight and stops loading once it resolves', async () => {
    const pending = deferred<OrgSettingsResponse>();
    api.getOrgSettings.mockReturnValueOnce(pending.promise);
    const store = useOrgSettingsStore();

    const done = settle(store.load());
    await flush();
    const during = { loading: store.loading, loaded: store.loaded, settings: store.settings };
    pending.resolve(response());
    await done;

    expect({ during, after: { loading: store.loading, loaded: store.loaded } }).toStrictEqual({
      during: { loading: true, loaded: false, settings: null },
      after: { loading: false, loaded: true },
    });
  });

  it.each<[string, unknown, string]>([
    ['a 403', new ApiError(403, 'Forbidden', DETAIL), ERROR.forbidden],
    ['a 429', new ApiError(429, 'Too Many Requests', DETAIL), ERROR.rateLimited],
    ['a 500', new ApiError(500, 'Internal Server Error', DETAIL), ERROR.generic],
    ['a network error', new TypeError('Failed to fetch'), ERROR.generic],
    ['a non-Error rejection', DETAIL, ERROR.generic],
  ])(
    'sets the catalog loadError for %s on the first load, keeps the empty state and never throws',
    async (_label, failure, key) => {
      api.getOrgSettings.mockRejectedValueOnce(failure);
      const store = useOrgSettingsStore();

      const outcome = await settle(store.load());

      expect({
        outcome,
        loadError: store.loadError,
        settings: store.settings,
        draft: store.draft,
        loading: store.loading,
        loaded: store.loaded,
        dataResidency: store.dataResidency,
        detailShown: everythingShown(store).includes(DETAIL),
      }).toStrictEqual({
        outcome: undefined,
        loadError: text(EN, key),
        settings: null,
        draft: null,
        loading: false,
        loaded: false,
        dataResidency: true,
        detailShown: false,
      });
    },
  );

  it('keeps the loaded settings and the edited draft when a later load fails', async () => {
    const store = await loadedStore(response({ data_residency: false }));
    edit(store, { instructions: 'Antworten Sie kurz.', session_idle_timeout_minutes: 90 });
    const editedDraft = draftCopy(store);
    api.getOrgSettings.mockRejectedValueOnce(new ApiError(500, 'Internal Server Error', DETAIL));

    const outcome = await settle(store.load());

    expect({
      outcome,
      settings: store.settings,
      draft: draftCopy(store),
      loaded: store.loaded,
      loading: store.loading,
      loadError: store.loadError,
      dataResidency: store.dataResidency,
    }).toStrictEqual({
      outcome: undefined,
      settings: response({ data_residency: false }),
      draft: editedDraft,
      loaded: true,
      loading: false,
      loadError: text(EN, ERROR.generic),
      dataResidency: false,
    });
  });

  it('replaces the settings and the draft and clears the loadError on a successful reload', async () => {
    const store = await loadedStore();
    edit(store, { display_name: 'Entwurf' });
    api.getOrgSettings.mockRejectedValueOnce(new TypeError('Failed to fetch'));
    await store.load();
    const errorAfterFailure = store.loadError;
    const reloaded = response({
      profile: { display_name: 'Muster Treuhand GmbH', default_response_language: 'fr' },
      instructions: '',
      security: { session_idle_timeout_minutes: 120 },
      retention: { trash_retention_days: 60 },
      data_residency: true,
    });
    api.getOrgSettings.mockResolvedValueOnce(reloaded);

    await store.load();

    expect({
      errorAfterFailure,
      loadError: store.loadError,
      settings: store.settings,
      draft: draftCopy(store),
      dataResidency: store.dataResidency,
      dirty: store.dirty,
    }).toStrictEqual({
      errorAfterFailure: text(EN, ERROR.generic),
      loadError: null,
      settings: reloaded,
      draft: expectedDraft(reloaded),
      dataResidency: true,
      dirty: false,
    });
  });

  it('takes the loadError from the active locale\'s catalog', async () => {
    setLocale('de');
    api.getOrgSettings.mockRejectedValueOnce(new ApiError(403, 'Forbidden', DETAIL));
    const store = useOrgSettingsStore();

    await store.load();

    expect({ loadError: store.loadError, differsFromEn: text(DE, ERROR.forbidden) !== text(EN, ERROR.forbidden) }).toEqual({
      loadError: text(DE, ERROR.forbidden),
      differsFromEn: true,
    });
  });
});

// --- dataResidency (read-only, fail closed) ---------------------------------

describe('orgSettingsStore dataResidency', () => {
  it('follows the loaded flag of an org without residency', async () => {
    const store = await loadedStore(response({ data_residency: false }));

    expect({ loaded: store.loaded, dataResidency: store.dataResidency }).toEqual({ loaded: true, dataResidency: false });
  });

  it('follows the loaded flag of a residency org', async () => {
    const store = await loadedStore(response({ data_residency: true }));

    expect({ loaded: store.loaded, dataResidency: store.dataResidency }).toEqual({ loaded: true, dataResidency: true });
  });

  it('stays on (fail closed) when the first load fails', async () => {
    api.getOrgSettings.mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'));
    const store = useOrgSettingsStore();

    await store.load();

    expect({ loadError: store.loadError, dataResidency: store.dataResidency }).toEqual({
      loadError: text(EN, ERROR.generic),
      dataResidency: true,
    });
  });
});

// --- dirty ------------------------------------------------------------------

describe('orgSettingsStore dirty', () => {
  it.each<[string, Partial<OrgSettingsDraft>]>([
    ['display_name', { display_name: 'Muster Treuhand GmbH' }],
    ['default_response_language', { default_response_language: 'it' }],
    ['instructions', { instructions: 'Antworten Sie kurz.' }],
    ['session_idle_timeout_minutes', { session_idle_timeout_minutes: 90 }],
    ['session_max_lifetime_hours', { session_max_lifetime_hours: 24 }],
    ['trash_retention_days', { trash_retention_days: 30 }],
  ])('is true once %s differs from the loaded settings', async (_field, changes) => {
    const store = await loadedStore();
    const before = store.dirty;

    edit(store, changes);

    expect({ before, after: store.dirty }).toEqual({ before: false, after: true });
  });

  it('is false again once an edited field is set back to the loaded value', async () => {
    const store = await loadedStore();
    edit(store, { session_max_lifetime_hours: 24 });
    const edited = store.dirty;

    edit(store, { session_max_lifetime_hours: 10 });

    expect({ edited, reverted: store.dirty }).toEqual({ edited: true, reverted: false });
  });

  it('ignores whitespace around an unchanged display name (it is compared trimmed)', async () => {
    const store = await loadedStore();
    edit(store, { instructions: `${INSTRUCTIONS} ` });
    const withInstructions = store.dirty;
    edit(store, { instructions: INSTRUCTIONS, display_name: '  Treuhand Muster AG \t' });

    expect({ withInstructions, nameOnlyPadded: store.dirty }).toEqual({ withInstructions: true, nameOnlyPadded: false });
  });

  it('counts whitespace added to the instructions as a change (they are compared verbatim)', async () => {
    const store = await loadedStore();

    edit(store, { instructions: `${INSTRUCTIONS}\n` });

    expect(store.dirty).toBe(true);
  });
});

// --- instructionsRemaining ----------------------------------------------------

describe('orgSettingsStore instructionsRemaining', () => {
  it('is 8000 minus the loaded instructions\' code points (not UTF-16 units)', async () => {
    const store = await loadedStore();

    expect(store.instructionsRemaining).toBe(7948);
  });

  it('follows the draft as it is edited, down to a negative count', async () => {
    const store = await loadedStore();
    edit(store, { instructions: 'ä👋👋' });
    const short = store.instructionsRemaining;
    edit(store, { instructions: 'x'.repeat(8001) });
    const over = store.instructionsRemaining;
    edit(store, { instructions: '' });

    expect({ short, over, empty: store.instructionsRemaining }).toEqual({ short: 7997, over: -1, empty: 8000 });
  });
});

// --- resetDraft ---------------------------------------------------------------

describe('orgSettingsStore resetDraft', () => {
  it('puts the draft back to the loaded settings and clears the issues', async () => {
    const store = await loadedStore();
    edit(store, { display_name: '   ', session_idle_timeout_minutes: 5 });
    await store.save();
    const issuesBefore = [...store.issues];

    store.resetDraft();

    expect({
      issuesBefore,
      draft: draftCopy(store),
      issues: store.issues,
      saveError: store.saveError,
      dirty: store.dirty,
      requests: api.getOrgSettings.mock.calls.length + api.patchOrgSettings.mock.calls.length + otherRequests(),
    }).toStrictEqual({
      issuesBefore: ['name_required', 'idle_timeout_range'],
      draft: expectedDraft(response()),
      issues: [],
      saveError: null,
      dirty: false,
      requests: 0,
    });
  });

  it('clears the saveError a failed save left', async () => {
    const store = await loadedStore();
    edit(store, { trash_retention_days: 45 });
    api.patchOrgSettings.mockRejectedValueOnce(new ApiError(400, 'Bad Request', DETAIL, 'trash_retention_bounds'));
    await store.save();
    const errorBefore = store.saveError;

    store.resetDraft();

    expect({ errorBefore, saveError: store.saveError, draft: draftCopy(store), settings: store.settings }).toStrictEqual({
      errorBefore: text(EN, ERROR.trashBounds),
      saveError: null,
      draft: expectedDraft(response()),
      settings: response(),
    });
  });
});

// --- save: validation ---------------------------------------------------------

describe('orgSettingsStore save validation', () => {
  it.each<[string, Partial<OrgSettingsDraft>, OrgSettingsIssue]>([
    ['an empty display name', { display_name: '' }, 'name_required'],
    ['a blank display name', { display_name: ' \t ' }, 'name_required'],
    ['a 121-character display name', { display_name: 'A'.repeat(121) }, 'name_too_long'],
    ['8001 characters of instructions', { instructions: 'x'.repeat(8001) }, 'instructions_too_long'],
    ['an idle timeout of 14 minutes', { session_idle_timeout_minutes: 14 }, 'idle_timeout_range'],
    ['an idle timeout of 481 minutes', { session_idle_timeout_minutes: 481 }, 'idle_timeout_range'],
    ['a fractional idle timeout', { session_idle_timeout_minutes: 30.5 }, 'idle_timeout_range'],
    ['a lifetime of 0 hours', { session_max_lifetime_hours: 0 }, 'lifetime_range'],
    ['a lifetime of 73 hours', { session_max_lifetime_hours: 73 }, 'lifetime_range'],
    ['a retention below the platform minimum (6 < 7)', { trash_retention_days: 6 }, 'trash_retention_range'],
    ['a retention above the platform maximum (61 > 60)', { trash_retention_days: 61 }, 'trash_retention_range'],
    ['a retention within 0..90 but above the platform maximum', { trash_retention_days: 90 }, 'trash_retention_range'],
  ])('refuses %s without a request and returns false', async (_label, changes, issue) => {
    const store = await loadedStore();
    edit(store, changes);
    const draftBefore = draftCopy(store);

    const outcome = await settle(store.save());

    expect({
      outcome,
      issues: store.issues,
      patches: api.patchOrgSettings.mock.calls.length,
      other: otherRequests(),
      saving: store.saving,
      draft: draftCopy(store),
      settings: store.settings,
    }).toStrictEqual({
      outcome: false,
      issues: [issue],
      patches: 0,
      other: 0,
      saving: false,
      draft: draftBefore,
      settings: response(),
    });
  });

  it('lists every issue in the contract\'s order', async () => {
    const store = await loadedStore();
    edit(store, {
      trash_retention_days: 0,
      session_max_lifetime_hours: 100,
      session_idle_timeout_minutes: 500,
      instructions: '👋'.repeat(8001),
      display_name: 'B'.repeat(130),
    });

    const outcome = await settle(store.save());

    expect({ outcome, issues: store.issues, patches: api.patchOrgSettings.mock.calls.length }).toStrictEqual({
      outcome: false,
      issues: ['name_too_long', 'instructions_too_long', 'idle_timeout_range', 'lifetime_range', 'trash_retention_range'],
      patches: 0,
    });
  });

  it('sends the boundary values (120-character name, 8000 code points, 15 min, 72 h, the platform maximum)', async () => {
    const store = await loadedStore();
    const name = 'N'.repeat(120);
    const instructions = '👋'.repeat(8000);
    edit(store, {
      display_name: name,
      instructions,
      session_idle_timeout_minutes: 15,
      session_max_lifetime_hours: 72,
      trash_retention_days: 60,
    });
    api.patchOrgSettings.mockResolvedValueOnce(
      response({
        profile: { display_name: name },
        instructions,
        security: { session_idle_timeout_minutes: 15, session_max_lifetime_hours: 72 },
        retention: { trash_retention_days: 60 },
      }),
    );

    const outcome = await settle(store.save());

    expect({ outcome, issues: store.issues, patches: patchBodies() }).toStrictEqual({
      outcome: true,
      issues: [],
      patches: [
        {
          profile: { display_name: name },
          instructions,
          security: { session_idle_timeout_minutes: 15, session_max_lifetime_hours: 72 },
          retention: { trash_retention_days: 60 },
        },
      ],
    });
  });

  it('sends the other boundary values (480 min, 1 h, the platform minimum)', async () => {
    const store = await loadedStore();
    edit(store, { session_idle_timeout_minutes: 480, session_max_lifetime_hours: 1, trash_retention_days: 7 });
    api.patchOrgSettings.mockResolvedValueOnce(
      response({
        security: { session_idle_timeout_minutes: 480, session_max_lifetime_hours: 1 },
        retention: { trash_retention_days: 7 },
      }),
    );

    const outcome = await settle(store.save());

    expect({ outcome, issues: store.issues, patches: patchBodies() }).toStrictEqual({
      outcome: true,
      issues: [],
      patches: [
        {
          security: { session_idle_timeout_minutes: 480, session_max_lifetime_hours: 1 },
          retention: { trash_retention_days: 7 },
        },
      ],
    });
  });

  it('replaces earlier issues once the draft is fixed and saved', async () => {
    const store = await loadedStore();
    edit(store, { display_name: '', session_max_lifetime_hours: 0 });
    await store.save();
    const issuesBefore = [...store.issues];
    edit(store, { display_name: 'Muster Treuhand GmbH', session_max_lifetime_hours: 10 });
    api.patchOrgSettings.mockResolvedValueOnce(response({ profile: { display_name: 'Muster Treuhand GmbH' } }));

    const outcome = await settle(store.save());

    expect({ issuesBefore, outcome, issues: store.issues, patches: patchBodies() }).toStrictEqual({
      issuesBefore: ['name_required', 'lifetime_range'],
      outcome: true,
      issues: [],
      patches: [{ profile: { display_name: 'Muster Treuhand GmbH' } }],
    });
  });
});

// --- save: nothing changed ----------------------------------------------------

describe('orgSettingsStore save without changes', () => {
  it('sends nothing and returns true for an untouched draft', async () => {
    const store = await loadedStore();

    const outcome = await settle(store.save());

    expect({
      outcome,
      patches: api.patchOrgSettings.mock.calls.length,
      gets: api.getOrgSettings.mock.calls.length,
      other: otherRequests(),
      saving: store.saving,
      settings: store.settings,
      draft: draftCopy(store),
    }).toStrictEqual({
      outcome: true,
      patches: 0,
      gets: 0,
      other: 0,
      saving: false,
      settings: response(),
      draft: expectedDraft(response()),
    });
  });

  it('sends nothing for a display name that only gained surrounding whitespace', async () => {
    const store = await loadedStore();
    edit(store, { display_name: '\t Treuhand Muster AG  ' });

    const outcome = await settle(store.save());

    expect({ outcome, patches: api.patchOrgSettings.mock.calls.length }).toEqual({ outcome: true, patches: 0 });
  });

  it('clears earlier issues when the draft is set back to the loaded values', async () => {
    const store = await loadedStore();
    edit(store, { session_idle_timeout_minutes: 1 });
    await store.save();
    const issuesBefore = [...store.issues];
    edit(store, { session_idle_timeout_minutes: 45 });

    const outcome = await settle(store.save());

    expect({ issuesBefore, outcome, issues: store.issues, patches: api.patchOrgSettings.mock.calls.length }).toStrictEqual({
      issuesBefore: ['idle_timeout_range'],
      outcome: true,
      issues: [],
      patches: 0,
    });
  });

  it('sends nothing and does not throw before the settings are loaded', async () => {
    const store = useOrgSettingsStore();

    const outcome = await settle(store.save());

    expect({
      threw: typeof outcome === 'object' && outcome !== null && 'threw' in outcome,
      patches: api.patchOrgSettings.mock.calls.length,
      other: otherRequests(),
      id: store.$id,
    }).toEqual({ threw: false, patches: 0, other: 0, id: 'orgSettings' });
  });
});

// --- save: PATCH /api/org/settings --------------------------------------------

describe('orgSettingsStore save request', () => {
  it.each<[string, Partial<OrgSettingsDraft>, OrgSettingsPatch]>([
    ['the display name, trimmed', { display_name: '  Muster Treuhand GmbH ' }, { profile: { display_name: 'Muster Treuhand GmbH' } }],
    ['the response language', { default_response_language: 'fr' }, { profile: { default_response_language: 'fr' } }],
    [
      'the instructions, verbatim',
      { instructions: '  Antworten Sie kurz.\n\tKeine Namen. ' },
      { instructions: '  Antworten Sie kurz.\n\tKeine Namen. ' },
    ],
    ['cleared instructions', { instructions: '' }, { instructions: '' }],
    ['the idle timeout', { session_idle_timeout_minutes: 90 }, { security: { session_idle_timeout_minutes: 90 } }],
    ['the session lifetime', { session_max_lifetime_hours: 24 }, { security: { session_max_lifetime_hours: 24 } }],
    ['the trash retention', { trash_retention_days: 45 }, { retention: { trash_retention_days: 45 } }],
  ])('sends only %s when only that changed', async (_label, changes, expected) => {
    const store = await loadedStore();
    edit(store, changes);
    api.patchOrgSettings.mockResolvedValueOnce(response());

    await store.save();

    expect({ patches: api.patchOrgSettings.mock.calls, other: otherRequests() }).toStrictEqual({
      patches: [[expected]],
      other: 0,
    });
  });

  it('sends every changed field, grouped by section, and never tools, residency, plan or the bounds', async () => {
    const store = await loadedStore(response({ data_residency: true, tools: { gmail: false } }));
    edit(store, {
      display_name: 'Muster Treuhand GmbH',
      default_response_language: 'en',
      instructions: 'Antworten Sie kurz.',
      session_idle_timeout_minutes: 30,
      session_max_lifetime_hours: 8,
      trash_retention_days: 14,
    });
    api.patchOrgSettings.mockResolvedValueOnce(response());

    await store.save();

    expect(api.patchOrgSettings.mock.calls).toStrictEqual([
      [
        {
          profile: { display_name: 'Muster Treuhand GmbH', default_response_language: 'en' },
          instructions: 'Antworten Sie kurz.',
          security: { session_idle_timeout_minutes: 30, session_max_lifetime_hours: 8 },
          retention: { trash_retention_days: 14 },
        },
      ],
    ]);
  });

  it('leaves an unchanged padded display name out of a patch with another change', async () => {
    const store = await loadedStore();
    edit(store, { display_name: ' Treuhand Muster AG ', session_max_lifetime_hours: 24 });
    api.patchOrgSettings.mockResolvedValueOnce(response({ security: { session_max_lifetime_hours: 24 } }));

    await store.save();

    expect(api.patchOrgSettings.mock.calls).toStrictEqual([[{ security: { session_max_lifetime_hours: 24 } }]]);
  });

  it('is saving while the PATCH is in flight and stops saving once it resolves', async () => {
    const store = await loadedStore();
    edit(store, { session_idle_timeout_minutes: 90 });
    const pending = deferred<OrgSettingsResponse>();
    api.patchOrgSettings.mockReturnValueOnce(pending.promise);

    const done = settle(store.save());
    await flush();
    const during = store.saving;
    pending.resolve(response({ security: { session_idle_timeout_minutes: 90 } }));
    const outcome = await done;

    expect({ during, outcome, after: store.saving }).toEqual({ during: true, outcome: true, after: false });
  });

  it('returns false without a request for a second save while the first is in flight', async () => {
    const store = await loadedStore();
    edit(store, { session_idle_timeout_minutes: 90 });
    const pending = deferred<OrgSettingsResponse>();
    api.patchOrgSettings.mockReturnValueOnce(pending.promise);

    const first = settle(store.save());
    await flush();
    const second = await settle(store.save());
    const patchesWhileInFlight = api.patchOrgSettings.mock.calls.length;
    pending.resolve(response({ security: { session_idle_timeout_minutes: 90 } }));
    const firstOutcome = await first;

    expect({
      second,
      patchesWhileInFlight,
      firstOutcome,
      patches: api.patchOrgSettings.mock.calls.length,
      saving: store.saving,
    }).toEqual({ second: false, patchesWhileInFlight: 1, firstOutcome: true, patches: 1, saving: false });
  });
});

// --- save: success --------------------------------------------------------------

describe('orgSettingsStore save success', () => {
  it('applies the response to the settings and a fresh draft, toasts "Saved" and returns true', async () => {
    const store = await loadedStore();
    edit(store, { display_name: 'Muster Treuhand GmbH', trash_retention_days: 45 });
    // The server's truth may differ from what was sent (another admin, the clamped retention).
    const saved = response({
      profile: { display_name: 'Muster Treuhand GmbH' },
      security: { session_idle_timeout_minutes: 120 },
      retention: { trash_retention_days: 40, trash_max_days: 40 },
      tools: { outlook: false },
      data_residency: true,
    });
    api.patchOrgSettings.mockResolvedValueOnce(saved);

    const outcome = await settle(store.save());

    expect({
      outcome,
      settings: store.settings,
      draft: draftCopy(store),
      issues: store.issues,
      saveError: store.saveError,
      saving: store.saving,
      dirty: store.dirty,
      dataResidency: store.dataResidency,
      toasts: toastSummary(),
      gets: api.getOrgSettings.mock.calls.length,
      other: otherRequests(),
    }).toStrictEqual({
      outcome: true,
      settings: saved,
      draft: {
        display_name: 'Muster Treuhand GmbH',
        default_response_language: 'de',
        instructions: INSTRUCTIONS,
        session_idle_timeout_minutes: 120,
        session_max_lifetime_hours: 10,
        trash_retention_days: 40,
      },
      issues: [],
      saveError: null,
      saving: false,
      dirty: false,
      dataResidency: true,
      toasts: [{ kind: 'success', title: text(EN, 'toast.common.saved') }],
      gets: 0,
      other: 0,
    });
  });

  it('clears the saveError an earlier failed save left', async () => {
    const store = await loadedStore();
    edit(store, { session_max_lifetime_hours: 24 });
    api.patchOrgSettings
      .mockRejectedValueOnce(new ApiError(429, 'Too Many Requests', DETAIL))
      .mockResolvedValueOnce(response({ security: { session_max_lifetime_hours: 24 } }));
    await store.save();
    const errorBefore = store.saveError;

    const outcome = await settle(store.save());

    expect({ errorBefore, outcome, saveError: store.saveError, patches: patchBodies() }).toStrictEqual({
      errorBefore: text(EN, ERROR.rateLimited),
      outcome: true,
      saveError: null,
      patches: [{ security: { session_max_lifetime_hours: 24 } }, { security: { session_max_lifetime_hours: 24 } }],
    });
  });

  it('titles the success toast with the fr catalog string under fr', async () => {
    const store = await loadedStore();
    setLocale('fr');
    edit(store, { default_response_language: 'fr' });
    api.patchOrgSettings.mockResolvedValueOnce(response({ profile: { default_response_language: 'fr' } }));

    await store.save();

    expect(toastSummary()).toEqual([{ kind: 'success', title: text(FR, 'toast.common.saved') }]);
  });
});

// --- save: failure ----------------------------------------------------------------

describe('orgSettingsStore save failure', () => {
  it.each<[string, unknown, string]>([
    ['a 400 trash_retention_bounds', new ApiError(400, 'Bad Request', DETAIL, 'trash_retention_bounds'), ERROR.trashBounds],
    ['a 400 without a reason', new ApiError(400, 'Bad Request', DETAIL), ERROR.invalid],
    ['a 422', new ApiError(422, 'Unprocessable Entity', DETAIL), ERROR.invalid],
    ['a 403', new ApiError(403, 'Forbidden', DETAIL), ERROR.forbidden],
    ['a 429', new ApiError(429, 'Too Many Requests', DETAIL), ERROR.rateLimited],
    ['a 500', new ApiError(500, 'Internal Server Error', DETAIL), ERROR.generic],
    ['a network error', new TypeError('Failed to fetch'), ERROR.generic],
    ['a non-Error rejection', DETAIL, ERROR.generic],
  ])(
    'sets the catalog saveError for %s, keeps the draft, toasts an error and returns false',
    async (_label, failure, key) => {
      const store = await loadedStore();
      edit(store, { trash_retention_days: 45, instructions: 'Antworten Sie kurz.' });
      const draftBefore = draftCopy(store);
      api.patchOrgSettings.mockRejectedValueOnce(failure);

      const outcome = await settle(store.save());

      expect({
        outcome,
        saveError: store.saveError,
        draft: draftCopy(store),
        settings: store.settings,
        saving: store.saving,
        dirty: store.dirty,
        toastKinds: toastSummary().map(({ kind }) => kind),
        patches: patchBodies(),
        detailShown: everythingShown(store).includes(DETAIL),
      }).toStrictEqual({
        outcome: false,
        saveError: text(EN, key),
        draft: draftBefore,
        settings: response(),
        saving: false,
        dirty: true,
        toastKinds: ['error'],
        patches: [{ instructions: 'Antworten Sie kurz.', retention: { trash_retention_days: 45 } }],
        detailShown: false,
      });
    },
  );

  it('takes the saveError from the active locale\'s catalog', async () => {
    const store = await loadedStore();
    setLocale('fr');
    edit(store, { trash_retention_days: 50 });
    api.patchOrgSettings.mockRejectedValueOnce(new ApiError(400, 'Bad Request', DETAIL, 'trash_retention_bounds'));

    await store.save();

    expect({
      saveError: store.saveError,
      differsFromEn: text(FR, ERROR.trashBounds) !== text(EN, ERROR.trashBounds),
    }).toEqual({ saveError: text(FR, ERROR.trashBounds), differsFromEn: true });
  });

  it('can save the kept draft again after a failure', async () => {
    const store = await loadedStore();
    edit(store, { session_idle_timeout_minutes: 240 });
    api.patchOrgSettings
      .mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockResolvedValueOnce(response({ security: { session_idle_timeout_minutes: 240 } }));
    const first = await settle(store.save());

    const second = await settle(store.save());

    expect({
      first,
      second,
      patches: patchBodies(),
      draft: draftCopy(store),
      saving: store.saving,
      toastKinds: toastSummary().map(({ kind }) => kind),
    }).toStrictEqual({
      first: false,
      second: true,
      patches: [{ security: { session_idle_timeout_minutes: 240 } }, { security: { session_idle_timeout_minutes: 240 } }],
      draft: expectedDraft(response({ security: { session_idle_timeout_minutes: 240 } })),
      saving: false,
      toastKinds: ['error', 'success'],
    });
  });
});
