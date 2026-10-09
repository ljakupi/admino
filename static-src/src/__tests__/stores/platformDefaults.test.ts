/**
 * Platform defaults store tests (issue #168: Platform console UI (Super
 * Admin), the Platform -> Defaults page; issue #242 D1: switching the
 * platform's provider to a non-Swiss one needs a confirmation naming the
 * number of organizations with data residency on).
 *
 * `usePlatformDefaultsStore` (Pinia id 'platformDefaults', setup style) owns
 * the platform settings (`GET /api/platform/settings`) and an editable draft of
 * their editable fields (the provider, the four model IDs, `max_input_tokens`,
 * `image_input`, `max_retries` and the limits, files, retention and security
 * sections).
 *
 * - `load()`: success sets `settings` and a deep-copied `draft`; failure keeps
 *   the previous state and sets a translated `loadError`.
 * - `reset()` restores the draft from `settings` and clears the errors;
 *   `dirty` is true while the draft differs from `settings`.
 * - `save()`: nothing before load or while saving; an invalid draft fills
 *   `fieldErrors` (keyed '<section>.<field>') and sends nothing; an unchanged
 *   draft is `true` with no request; otherwise `PATCH /api/platform/settings`
 *   with only the changed fields. Success applies the response to `settings`
 *   and `draft` with a success toast; failure keeps the draft and sets a
 *   translated `saveError`.
 * - Residency confirmation (#242): a provider switch for which
 *   `needsResidencyConfirmation(stored, next)` holds opens `residencyConfirm`
 *   with `count = settings.llm.residency_orgs` and sends NOTHING.
 *   `residencyConfirmText` is the `platform.defaults.residencyConfirm.*` copy
 *   (plural body with the count). `cancelResidency()` closes it without a
 *   request; `confirmResidency()` sends the patch plus `confirm_residency_orgs`
 *   equal to the count. A `409` with `reason: 'residency_confirmation'`
 *   reloads the settings, keeps the draft and asks again with the reloaded
 *   count; a failed reload or any other failure closes the dialog with a
 *   translated `saveError`.
 *
 * Contract readings (where `RUN_DIR/contract.md` leaves a detail open):
 * - `save()` before the first load and `confirmResidency()` without an open
 *   dialog resolve `false` (nothing was saved).
 * - A successful save clears a `saveError` left by an earlier failure.
 * - After the 409 the dialog itself tells the admin what happened, so
 *   `saveError` may stay null or be `platform.error.residencyConfirmation`
 *   (never the backend text).
 * - Bodies are compared as they reach the wire (`JSON.stringify` at call
 *   time), so an `undefined`-valued key counts as absent, like in `fetchJson`.
 *
 * Security notes: operator blindness. The store talks only to
 * `@/api/platform` (`getPlatformSettings`, `patchPlatformSettings`), never to
 * `fetch` directly or another API module, and its state holds no credential
 * (only the `*_configured` booleans the backend returns). Backend error text
 * (`detail`) is never shown; every message comes from the i18n catalogs.
 * Nothing is logged. `@/api/platform` is mocked (it may not exist yet, so the
 * factory lists every function of the contract), `fetch` is a spy that fails
 * every call, and the toast store is the real one. No component is mounted.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { ApiError } from '@/api/client';
import { setLocale, t } from '@/i18n';
import type { MessageKey } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';
import { usePlatformDefaultsStore } from '@/stores/platformDefaults';
import { useToastStore } from '@/stores/toasts';
import type { DefaultsDraft } from '@/services/platformDefaults';
import type {
  LlmProvider,
  PlatformFiles,
  PlatformLimits,
  PlatformRetention,
  PlatformSecurity,
  PlatformSettings,
  PlatformSettingsLLM,
} from '@/api/types';

const platform = vi.hoisted(() => ({
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

vi.mock('@/api/platform', () => platform);

type PlatformFn = keyof typeof platform;

interface Calls {
  getPlatformSettings: number;
  patchPlatformSettings: number;
  /** Every other `@/api/platform` function (orgs, users, metadata): never used by this store. */
  other: number;
}

const NO_CALLS: Readonly<Calls> = { getPlatformSettings: 0, patchPlatformSettings: 0, other: 0 };

/** How many times the store called each platform API function. */
function apiCalls(): Calls {
  let other = 0;
  for (const name of Object.keys(platform) as PlatformFn[]) {
    if (name !== 'getPlatformSettings' && name !== 'patchPlatformSettings') {
      other += platform[name].mock.calls.length;
    }
  }
  return {
    getPlatformSettings: platform.getPlatformSettings.mock.calls.length,
    patchPlatformSettings: platform.patchPlatformSettings.mock.calls.length,
    other,
  };
}

/** `fetch` must never be called: the store goes through `@/api/platform` only. */
const fetchSpy = vi.fn((): Promise<Response> => Promise.reject(new Error('the network is disabled in this test')));

// --- Fixtures -------------------------------------------------------------

/** What `GET /api/platform/settings` returns (models.py `PlatformSettingsResponse`). */
const BASE: PlatformSettings = {
  llm: {
    provider: 'infomaniak',
    anthropic_model: 'claude-sonnet-4-5',
    openai_model: 'gpt-4o',
    infomaniak_model: 'qwen3',
    // vLLM isn't configured: a blank stored model is shown blank, never an error.
    vllm_model: '',
    infomaniak_available_models: ['qwen3', 'mistral3', 'llama3'],
    vllm_available_models: [],
    max_input_tokens: 200000,
    image_input: true,
    max_retries: 2,
    residency_orgs: 3,
    anthropic_key_configured: true,
    openai_key_configured: false,
    infomaniak_token_configured: true,
  },
  limits: {
    max_tool_calls_per_message: 10,
    max_pending_confirmations: 3,
    confirmation_timeout_s: 300,
    max_message_length: 4000,
    max_context_messages: 20,
  },
  files: { max_file_size_mb: 50, max_files_per_message: 10, max_pages_per_file: 100, render_dpi: 150 },
  retention: { trash_min_days: 0, trash_max_days: 90, audit_months: 12, org_deletion_grace_days: 30 },
  security: {
    rate_limit_per_minute: 20,
    lockout_after_failures: 10,
    lockout_window_minutes: 15,
    lockout_minutes: 15,
    session_idle_timeout_minutes: 60,
    session_max_lifetime_hours: 12,
  },
};

interface SettingsOverrides {
  llm?: Partial<PlatformSettingsLLM>;
  limits?: Partial<PlatformLimits>;
  files?: Partial<PlatformFiles>;
  retention?: Partial<PlatformRetention>;
  security?: Partial<PlatformSecurity>;
}

/** A fresh deep copy of the platform settings with `overrides` applied per section. */
function settings(overrides: SettingsOverrides = {}): PlatformSettings {
  return {
    llm: {
      ...BASE.llm,
      infomaniak_available_models: [...BASE.llm.infomaniak_available_models],
      vllm_available_models: [...BASE.llm.vllm_available_models],
      ...overrides.llm,
    },
    limits: { ...BASE.limits, ...overrides.limits },
    files: { ...BASE.files, ...overrides.files },
    retention: { ...BASE.retention, ...overrides.retention },
    security: { ...BASE.security, ...overrides.security },
  };
}

/** The draft `draftFrom(s)` must give: exactly the editable fields, nothing read-only. */
function draftOf(s: PlatformSettings): DefaultsDraft {
  return {
    llm: {
      provider: s.llm.provider,
      infomaniak_model: s.llm.infomaniak_model,
      vllm_model: s.llm.vllm_model,
      anthropic_model: s.llm.anthropic_model,
      openai_model: s.llm.openai_model,
      max_input_tokens: s.llm.max_input_tokens,
      image_input: s.llm.image_input,
      max_retries: s.llm.max_retries,
    },
    limits: { ...s.limits },
    files: { ...s.files },
    retention: { ...s.retention },
    security: { ...s.security },
  };
}

type Catalog = Record<string, unknown>;
type Locale = 'en' | 'de' | 'fr';

const CATALOGS: Readonly<Record<Locale, Catalog>> = { en, de, fr };
const EN: Catalog = en;

/** The active-locale text of a contract key; throws when the en catalog lacks the key. */
function msg(key: string, params?: Record<string, string | number>): string {
  if (!Object.hasOwn(EN, key)) throw new Error(`the en catalog has no ${key}`);
  return t(key as MessageKey, params);
}

/** Backend error text the store must never show or log. */
const DETAIL = 'backend detail: provider switch refused for org 7c1e (secret sk-live-123)';

function apiError(status: number, reason?: string): ApiError {
  return new ApiError(status, 'Error', DETAIL, reason);
}

function residencyConflict(): ApiError {
  return apiError(409, 'residency_confirmation');
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

/** What `promise` fulfils with, or `{ threw: error }` when it rejects (stores never throw). */
function settled<T>(promise: Promise<T>): Promise<T | { threw: unknown }> {
  return promise.then(
    (value) => value,
    (e: unknown) => ({ threw: e }),
  );
}

/** True when `settled()` saw the promise reject. */
function didThrow(outcome: unknown): boolean {
  return typeof outcome === 'object' && outcome !== null && 'threw' in outcome;
}

/** Every PATCH body as it reached the API client (JSON at call time, like the wire). */
let sent: unknown[] = [];

function wire(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value)) as unknown;
}

/** The next `patchPlatformSettings` call records its body and resolves `result` (or rejects with it). */
function answerPatch(result: PlatformSettings | Error | Promise<PlatformSettings>): void {
  platform.patchPlatformSettings.mockImplementationOnce((patch: unknown) => {
    sent.push(wire(patch));
    if (result instanceof Error) return Promise.reject(result);
    return Promise.resolve(result);
  });
}

function toastSummary(): Array<{ kind: string; title: string }> {
  return useToastStore().toasts.map(({ kind, title }) => ({ kind, title }));
}

type Store = ReturnType<typeof usePlatformDefaultsStore>;

/** Applies `change` to the store's draft (as the form does). */
function edit(store: Store, change: (draft: DefaultsDraft) => void): void {
  const draft = store.draft as DefaultsDraft | null;
  if (draft === null) throw new Error('edit: the store has no draft');
  change(draft);
}

/** A JSON snapshot of the draft (what a failure must leave untouched). */
function draftJson(store: Store): string {
  return JSON.stringify(store.draft);
}

/** The store loaded with `loaded`; API call logs, sent bodies and toasts are cleared afterwards. */
async function setup(loaded: PlatformSettings = settings()): Promise<Store> {
  const store = usePlatformDefaultsStore();
  platform.getPlatformSettings.mockResolvedValueOnce(loaded);
  await store.load();
  if (!store.loaded) throw new Error('setup: load() did not load the store');
  for (const fn of Object.values(platform)) fn.mockClear();
  sent = [];
  useToastStore().toasts.splice(0);
  return store;
}

/** The store loaded with `loaded` and the residency dialog opened by switching to `next`. */
async function withDialog(next: LlmProvider = 'anthropic', loaded: PlatformSettings = settings()): Promise<Store> {
  const store = await setup(loaded);
  edit(store, (d) => {
    d.llm.provider = next;
  });
  const outcome = await settled(store.save());
  if (outcome !== false || store.residencyConfirm === null || apiCalls().patchPlatformSettings !== 0) {
    throw new Error('withDialog: save() did not open the residency dialog');
  }
  return store;
}

beforeEach(() => {
  localStorage.clear();
  setActivePinia(createPinia());
  setLocale('en');
  for (const fn of Object.values(platform)) fn.mockReset();
  sent = [];
  fetchSpy.mockClear();
  vi.stubGlobal('fetch', fetchSpy);
});

afterEach(() => {
  setLocale('en');
});

// --- Initial state --------------------------------------------------------

describe('platformDefaultsStore initial state', () => {
  it('is the "platformDefaults" store with no settings, no draft, no errors and the dialog closed', () => {
    const store = usePlatformDefaultsStore();

    expect({
      id: store.$id,
      settings: store.settings,
      draft: store.draft,
      loading: store.loading,
      loaded: store.loaded,
      loadError: store.loadError,
      saving: store.saving,
      saveError: store.saveError,
      fieldErrors: store.fieldErrors,
      residencyConfirm: store.residencyConfirm,
      dirty: store.dirty,
      residencyConfirmText: store.residencyConfirmText,
    }).toStrictEqual({
      id: 'platformDefaults',
      settings: null,
      draft: null,
      loading: false,
      loaded: false,
      loadError: null,
      saving: false,
      saveError: null,
      fieldErrors: {},
      residencyConfirm: null,
      dirty: false,
      residencyConfirmText: null,
    });
  });

  it('asks nothing of the server until load() is called', () => {
    usePlatformDefaultsStore();

    expect(apiCalls()).toEqual(NO_CALLS);
  });
});

// --- load(): GET /api/platform/settings ------------------------------------

describe('platformDefaultsStore load', () => {
  it('loads the settings once, builds the draft from their editable fields and marks the store loaded', async () => {
    platform.getPlatformSettings.mockResolvedValueOnce(settings());
    const store = usePlatformDefaultsStore();

    const outcome = await settled(store.load());

    expect({
      threw: didThrow(outcome),
      calls: apiCalls(),
      args: platform.getPlatformSettings.mock.calls,
      settings: store.settings,
      draft: store.draft,
      loaded: store.loaded,
      loading: store.loading,
      loadError: store.loadError,
      dirty: store.dirty,
      residencyConfirm: store.residencyConfirm,
    }).toStrictEqual({
      threw: false,
      calls: { ...NO_CALLS, getPlatformSettings: 1 },
      args: [[]],
      settings: settings(),
      draft: draftOf(settings()),
      loaded: true,
      loading: false,
      loadError: null,
      dirty: false,
      residencyConfirm: null,
    });
  });

  it('keeps the draft a deep copy: editing it changes neither the settings nor the API response', async () => {
    const response = settings();
    platform.getPlatformSettings.mockResolvedValueOnce(response);
    const store = usePlatformDefaultsStore();
    await store.load();

    edit(store, (d) => {
      d.llm.provider = 'vllm';
      d.llm.max_retries = 4;
      d.limits.max_message_length = 8000;
      d.files.render_dpi = 300;
      d.retention.audit_months = 24;
      d.security.lockout_minutes = 30;
    });

    expect({ settings: store.settings, response, dirty: store.dirty }).toStrictEqual({
      settings: settings(),
      response: settings(),
      dirty: true,
    });
  });

  it('is loading while the request is in flight, and not afterwards', async () => {
    const response = deferred<PlatformSettings>();
    platform.getPlatformSettings.mockReturnValueOnce(response.promise);
    const store = usePlatformDefaultsStore();

    const done = settled(store.load());
    const during = { loading: store.loading, loaded: store.loaded };
    response.resolve(settings());
    await done;

    expect({ during, after: { loading: store.loading, loaded: store.loaded } }).toEqual({
      during: { loading: true, loaded: false },
      after: { loading: false, loaded: true },
    });
  });

  it.each<[string, unknown, string]>([
    ['a 500', apiError(500), 'platform.error.generic'],
    ['a 404 (no org involved: generic)', apiError(404), 'platform.error.generic'],
    ['a 403', apiError(403), 'platform.error.forbidden'],
    ['a 429', apiError(429), 'platform.error.rateLimited'],
    ['a network failure', new TypeError('Failed to fetch'), 'platform.error.generic'],
  ])('on %s sets the translated loadError and stays unloaded, without throwing', async (_label, error, key) => {
    platform.getPlatformSettings.mockRejectedValueOnce(error);
    const store = usePlatformDefaultsStore();

    const outcome = await settled(store.load());

    expect({
      threw: didThrow(outcome),
      loadError: store.loadError,
      settings: store.settings,
      draft: store.draft,
      loaded: store.loaded,
      loading: store.loading,
    }).toStrictEqual({
      threw: false,
      loadError: msg(key),
      settings: null,
      draft: null,
      loaded: false,
      loading: false,
    });
  });

  it('keeps the previous settings and the edited draft when a reload fails', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.limits.max_context_messages = 30;
    });
    const draftBefore = draftJson(store);
    platform.getPlatformSettings.mockRejectedValueOnce(apiError(500));

    await settled(store.load());

    expect({
      settings: store.settings,
      draft: draftJson(store),
      loaded: store.loaded,
      loadError: store.loadError,
    }).toStrictEqual({
      settings: settings(),
      draft: draftBefore,
      loaded: true,
      loadError: msg('platform.error.generic'),
    });
  });

  it('clears the loadError on a later successful load', async () => {
    const store = usePlatformDefaultsStore();
    platform.getPlatformSettings.mockRejectedValueOnce(apiError(429));
    await settled(store.load());
    const before = store.loadError;
    platform.getPlatformSettings.mockResolvedValueOnce(settings());

    await settled(store.load());

    expect({ before, after: store.loadError, loaded: store.loaded }).toEqual({
      before: msg('platform.error.rateLimited'),
      after: null,
      loaded: true,
    });
  });

  it('replaces the settings and rebuilds the draft from a successful reload (unsaved edits are dropped)', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.limits.max_context_messages = 30;
    });
    const reloaded = settings({ llm: { max_retries: 4, residency_orgs: 6 }, files: { render_dpi: 200 } });
    platform.getPlatformSettings.mockResolvedValueOnce(reloaded);

    await settled(store.load());

    expect({ settings: store.settings, draft: store.draft, dirty: store.dirty }).toStrictEqual({
      settings: settings({ llm: { max_retries: 4, residency_orgs: 6 }, files: { render_dpi: 200 } }),
      draft: draftOf(reloaded),
      dirty: false,
    });
  });
});

// --- dirty and reset() --------------------------------------------------------

describe('platformDefaultsStore dirty', () => {
  it.each<[string, (d: DefaultsDraft) => void]>([
    ['the provider', (d) => (d.llm.provider = 'vllm')],
    ['a model', (d) => (d.llm.vllm_model = 'qwen2.5-7b')],
    ['max_input_tokens', (d) => (d.llm.max_input_tokens = 100000)],
    ['image_input', (d) => (d.llm.image_input = false)],
    ['max_retries', (d) => (d.llm.max_retries = 0)],
    ['a limit', (d) => (d.limits.confirmation_timeout_s = 600)],
    ['a file limit', (d) => (d.files.max_files_per_message = 5)],
    ['a retention value', (d) => (d.retention.org_deletion_grace_days = 60)],
    ['a security value', (d) => (d.security.session_max_lifetime_hours = 8)],
  ])('is true after editing %s and false again once the value is back', async (_label, change) => {
    const store = await setup();
    const before = store.dirty;
    const original = draftJson(store);

    edit(store, change);
    const changed = store.dirty;
    store.draft = JSON.parse(original) as DefaultsDraft;

    expect({ before, changed, restored: store.dirty }).toEqual({ before: false, changed: true, restored: false });
  });
});

describe('platformDefaultsStore reset', () => {
  it('restores the draft from the settings and makes no request', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.llm.provider = 'openai';
      d.limits.max_message_length = 9000;
      d.security.lockout_minutes = 60;
    });

    store.reset();

    expect({ draft: store.draft, dirty: store.dirty, calls: apiCalls() }).toStrictEqual({
      draft: draftOf(settings()),
      dirty: false,
      calls: NO_CALLS,
    });
  });

  it('clears the field errors of an invalid save', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.llm.max_retries = 9;
    });
    await settled(store.save());
    const before = Object.keys(store.fieldErrors);

    store.reset();

    expect({ before, after: store.fieldErrors }).toStrictEqual({ before: ['llm.max_retries'], after: {} });
  });

  it('clears the saveError of a failed save', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.limits.max_message_length = 9000;
    });
    answerPatch(apiError(500));
    await settled(store.save());
    const before = store.saveError;

    store.reset();

    expect({ before, after: store.saveError }).toEqual({ before: msg('platform.error.generic'), after: null });
  });

  it('does nothing and does not throw before the first load', () => {
    const store = usePlatformDefaultsStore();

    let threw: unknown = null;
    try {
      store.reset();
    } catch (e: unknown) {
      threw = e;
    }

    expect({ threw, draft: store.draft, settings: store.settings, calls: apiCalls() }).toStrictEqual({
      threw: null,
      draft: null,
      settings: null,
      calls: NO_CALLS,
    });
  });
});

// --- save(): guards ---------------------------------------------------------

describe('platformDefaultsStore save guards', () => {
  it('sends nothing and resolves false before the first load', async () => {
    const store = usePlatformDefaultsStore();

    const outcome = await settled(store.save());

    expect({ outcome, calls: apiCalls(), toasts: toastSummary() }).toStrictEqual({
      outcome: false,
      calls: NO_CALLS,
      toasts: [],
    });
  });

  it('sends nothing more while a save is in flight, and is saving until it settles', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.limits.max_message_length = 8000;
    });
    const response = deferred<PlatformSettings>();
    answerPatch(response.promise);

    const first = settled(store.save());
    const during = store.saving;
    await settled(store.save());
    const callsDuring = apiCalls();
    response.resolve(settings({ limits: { max_message_length: 8000 } }));
    const outcome = await first;

    expect({ during, callsDuring, outcome, after: store.saving, calls: apiCalls() }).toStrictEqual({
      during: true,
      callsDuring: { ...NO_CALLS, patchPlatformSettings: 1 },
      outcome: true,
      after: false,
      calls: { ...NO_CALLS, patchPlatformSettings: 1 },
    });
  });
});

// --- save(): client-side validation --------------------------------------------

type Expected = Record<string, [string, Record<string, number>?]>;

describe('platformDefaultsStore save validation', () => {
  it.each<[string, (d: DefaultsDraft) => void, Expected]>([
    [
      'max_retries above 5',
      (d) => (d.llm.max_retries = 6),
      { 'llm.max_retries': ['platform.defaults.error.range', { min: 0, max: 5 }] },
    ],
    [
      'max_input_tokens below 1000',
      (d) => (d.llm.max_input_tokens = 999),
      { 'llm.max_input_tokens': ['platform.defaults.error.range', { min: 1000, max: 2000000 }] },
    ],
    [
      'a message length of 0',
      (d) => (d.limits.max_message_length = 0),
      { 'limits.max_message_length': ['platform.defaults.error.range', { min: 1, max: 100000 }] },
    ],
    [
      'a non-integer render DPI',
      (d) => (d.files.render_dpi = 150.5),
      { 'files.render_dpi': ['platform.defaults.error.range', { min: 72, max: 300 }] },
    ],
    [
      'an emptied number field (NaN)',
      (d) => (d.limits.max_context_messages = Number.NaN),
      // GH-190 (Decision 15): the range is 0 (no cap) to 200.
      { 'limits.max_context_messages': ['platform.defaults.error.range', { min: 0, max: 200 }] },
    ],
    [
      'audit retention above 84 months',
      (d) => (d.retention.audit_months = 85),
      { 'retention.audit_months': ['platform.defaults.error.range', { min: 6, max: 84 }] },
    ],
    [
      'an idle timeout below 15 minutes',
      (d) => (d.security.session_idle_timeout_minutes = 10),
      { 'security.session_idle_timeout_minutes': ['platform.defaults.error.range', { min: 15, max: 480 }] },
    ],
    [
      'a changed model name with a shell metacharacter',
      (d) => (d.llm.anthropic_model = 'claude;rm -rf'),
      { 'llm.anthropic_model': ['platform.defaults.error.modelName'] },
    ],
    [
      'a set model name changed to blank',
      (d) => (d.llm.infomaniak_model = ''),
      { 'llm.infomaniak_model': ['platform.defaults.error.modelName'] },
    ],
    [
      'a trash minimum above the maximum',
      (d) => {
        d.retention.trash_min_days = 40;
        d.retention.trash_max_days = 30;
      },
      { 'retention.trash_min_days': ['platform.defaults.error.trashOrder'] },
    ],
  ])('rejects %s with a field error keyed by section.field and sends nothing', async (_label, change, expected) => {
    const store = await setup();
    edit(store, change);
    const draftBefore = draftJson(store);

    const outcome = await settled(store.save());

    const wanted = Object.fromEntries(
      Object.entries(expected).map(([path, [key, params]]) => [path, msg(key, params)]),
    );
    expect({
      outcome,
      fieldErrors: store.fieldErrors,
      calls: apiCalls(),
      draft: draftJson(store),
      saving: store.saving,
      residencyConfirm: store.residencyConfirm,
      toasts: toastSummary(),
    }).toStrictEqual({
      outcome: false,
      fieldErrors: wanted,
      calls: NO_CALLS,
      draft: draftBefore,
      saving: false,
      residencyConfirm: null,
      toasts: [],
    });
  });

  it('reports every invalid field at once', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.llm.max_retries = -1;
      d.llm.openai_model = 'gpt 4';
      d.files.max_file_size_mb = 501;
      d.security.lockout_after_failures = 2;
    });

    const outcome = await settled(store.save());

    expect({ outcome, fieldErrors: store.fieldErrors, calls: apiCalls() }).toStrictEqual({
      outcome: false,
      fieldErrors: {
        'llm.max_retries': msg('platform.defaults.error.range', { min: 0, max: 5 }),
        'llm.openai_model': msg('platform.defaults.error.modelName'),
        'files.max_file_size_mb': msg('platform.defaults.error.range', { min: 1, max: 500 }),
        'security.lockout_after_failures': msg('platform.defaults.error.range', { min: 3, max: 100 }),
      },
      calls: NO_CALLS,
    });
  });

  it('validates before asking for the residency confirmation: an invalid draft opens no dialog', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.llm.provider = 'anthropic';
      d.llm.max_retries = 9;
    });

    const outcome = await settled(store.save());

    expect({
      outcome,
      fieldErrors: store.fieldErrors,
      residencyConfirm: store.residencyConfirm,
      calls: apiCalls(),
    }).toStrictEqual({
      outcome: false,
      fieldErrors: { 'llm.max_retries': msg('platform.defaults.error.range', { min: 0, max: 5 }) },
      residencyConfirm: null,
      calls: NO_CALLS,
    });
  });

  it('never flags an unchanged blank stored model: a valid change is sent', async () => {
    const store = await setup(settings({ llm: { vllm_model: '', anthropic_model: '' } }));
    edit(store, (d) => {
      d.limits.max_tool_calls_per_message = 12;
    });
    answerPatch(settings({ llm: { vllm_model: '', anthropic_model: '' }, limits: { max_tool_calls_per_message: 12 } }));

    const outcome = await settled(store.save());

    expect({ outcome, fieldErrors: store.fieldErrors, sent }).toStrictEqual({
      outcome: true,
      fieldErrors: {},
      sent: [{ limits: { max_tool_calls_per_message: 12 } }],
    });
  });

  it('clears the field errors once the draft is fixed and saved', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.files.render_dpi = 20;
    });
    await settled(store.save());
    const before = Object.keys(store.fieldErrors);
    edit(store, (d) => {
      d.files.render_dpi = 96;
    });
    answerPatch(settings({ files: { render_dpi: 96 } }));

    const outcome = await settled(store.save());

    expect({ before, outcome, fieldErrors: store.fieldErrors, sent }).toStrictEqual({
      before: ['files.render_dpi'],
      outcome: true,
      fieldErrors: {},
      sent: [{ files: { render_dpi: 96 } }],
    });
  });
});

// --- save(): nothing changed --------------------------------------------------

describe('platformDefaultsStore save without changes', () => {
  it('resolves true without a request when the draft equals the settings', async () => {
    const store = await setup();

    const outcome = await settled(store.save());

    expect({ outcome, calls: apiCalls(), fieldErrors: store.fieldErrors }).toStrictEqual({
      outcome: true,
      calls: NO_CALLS,
      fieldErrors: {},
    });
  });

  it('resolves true without a request or a dialog when the provider was switched away and back', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.llm.provider = 'anthropic';
    });
    edit(store, (d) => {
      d.llm.provider = 'infomaniak';
    });

    const outcome = await settled(store.save());

    expect({ outcome, calls: apiCalls(), residencyConfirm: store.residencyConfirm }).toStrictEqual({
      outcome: true,
      calls: NO_CALLS,
      residencyConfirm: null,
    });
  });
});

// --- save(): PATCH /api/platform/settings ---------------------------------------

describe('platformDefaultsStore save', () => {
  it('sends only the changed fields, then applies the response to the settings and the draft', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.limits.max_message_length = 8000;
      d.security.lockout_minutes = 30;
    });
    // The server's answer also carries a change made elsewhere (max_retries 3).
    const response = settings({
      llm: { max_retries: 3 },
      limits: { max_message_length: 8000 },
      security: { lockout_minutes: 30 },
    });
    answerPatch(response);

    const outcome = await settled(store.save());

    expect({
      outcome,
      calls: apiCalls(),
      sent,
      settings: store.settings,
      draft: store.draft,
      dirty: store.dirty,
      saving: store.saving,
      saveError: store.saveError,
      fieldErrors: store.fieldErrors,
      residencyConfirm: store.residencyConfirm,
      toasts: toastSummary(),
    }).toStrictEqual({
      outcome: true,
      calls: { ...NO_CALLS, patchPlatformSettings: 1 },
      sent: [{ limits: { max_message_length: 8000 }, security: { lockout_minutes: 30 } }],
      settings: response,
      draft: draftOf(response),
      dirty: false,
      saving: false,
      saveError: null,
      fieldErrors: {},
      residencyConfirm: null,
      toasts: [{ kind: 'success', title: msg('platform.toast.defaultsSaved') }],
    });
  });

  it('sends the llm fields that changed without the provider, and no confirmation count', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.llm.max_input_tokens = 128000;
      d.llm.image_input = false;
      d.llm.max_retries = 4;
      d.llm.infomaniak_model = 'mistral3';
    });
    answerPatch(
      settings({ llm: { max_input_tokens: 128000, image_input: false, max_retries: 4, infomaniak_model: 'mistral3' } }),
    );

    const outcome = await settled(store.save());

    expect({ outcome, sent, residencyConfirm: store.residencyConfirm }).toStrictEqual({
      outcome: true,
      sent: [{ llm: { max_input_tokens: 128000, image_input: false, max_retries: 4, infomaniak_model: 'mistral3' } }],
      residencyConfirm: null,
    });
  });

  it.each<[string, unknown, string]>([
    ['a 422 (out of range on the server)', apiError(422), 'platform.error.invalidInput'],
    ['a 400 (trash order after the merge)', apiError(400), 'platform.error.invalidInput'],
    ['a 429', apiError(429), 'platform.error.rateLimited'],
    ['a 403', apiError(403), 'platform.error.forbidden'],
    ['a 404', apiError(404), 'platform.error.generic'],
    ['a 500', apiError(500), 'platform.error.generic'],
    ['a network failure', new TypeError('Failed to fetch'), 'platform.error.generic'],
  ])('on %s keeps the draft and the settings and sets the translated saveError', async (_label, error, key) => {
    const store = await setup();
    edit(store, (d) => {
      d.retention.trash_min_days = 7;
      d.llm.max_retries = 3;
    });
    const draftBefore = draftJson(store);
    answerPatch(error as Error);

    const outcome = await settled(store.save());

    expect({
      outcome,
      saveError: store.saveError,
      draft: draftJson(store),
      settings: store.settings,
      dirty: store.dirty,
      saving: store.saving,
      successToasts: toastSummary().filter((toast) => toast.kind === 'success'),
    }).toStrictEqual({
      outcome: false,
      saveError: msg(key),
      draft: draftBefore,
      settings: settings(),
      dirty: true,
      saving: false,
      successToasts: [],
    });
  });

  it('clears an earlier saveError when a later save succeeds', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.files.max_pages_per_file = 200;
    });
    answerPatch(apiError(500));
    await settled(store.save());
    const before = store.saveError;
    answerPatch(settings({ files: { max_pages_per_file: 200 } }));

    const outcome = await settled(store.save());

    expect({ before, outcome, after: store.saveError }).toEqual({
      before: msg('platform.error.generic'),
      outcome: true,
      after: null,
    });
  });
});

// --- Residency confirmation (#242 D1) -------------------------------------------

describe('platformDefaultsStore residency confirmation: opening', () => {
  it.each<[LlmProvider, LlmProvider, number]>([
    ['infomaniak', 'anthropic', 3],
    ['infomaniak', 'openai', 3],
    ['vllm', 'anthropic', 2],
    ['vllm', 'openai', 11],
    ['anthropic', 'openai', 4],
    ['openai', 'anthropic', 1],
  ])(
    'switching from %s to the non-Swiss %s opens the dialog with the residency count and sends nothing',
    async (stored, next, count) => {
      const store = await setup(settings({ llm: { provider: stored, vllm_model: 'qwen2.5-7b', residency_orgs: count } }));
      edit(store, (d) => {
        d.llm.provider = next;
        d.limits.max_context_messages = 25;
      });
      const draftBefore = draftJson(store);

      const outcome = await settled(store.save());

      expect({
        outcome,
        residencyConfirm: store.residencyConfirm,
        calls: apiCalls(),
        draft: draftJson(store),
        settings: store.settings,
        saving: store.saving,
        saveError: store.saveError,
        fieldErrors: store.fieldErrors,
        toasts: toastSummary(),
        fetch: fetchSpy.mock.calls.length,
      }).toStrictEqual({
        outcome: false,
        residencyConfirm: { count },
        calls: NO_CALLS,
        draft: draftBefore,
        settings: settings({ llm: { provider: stored, vllm_model: 'qwen2.5-7b', residency_orgs: count } }),
        saving: false,
        saveError: null,
        fieldErrors: {},
        toasts: [],
        fetch: 0,
      });
    },
  );

  it('asks even when no organization has data residency on (count 0: the server still wants the number)', async () => {
    const store = await setup(settings({ llm: { residency_orgs: 0 } }));
    edit(store, (d) => {
      d.llm.provider = 'openai';
    });

    const outcome = await settled(store.save());

    expect({ outcome, residencyConfirm: store.residencyConfirm, calls: apiCalls() }).toStrictEqual({
      outcome: false,
      residencyConfirm: { count: 0 },
      calls: NO_CALLS,
    });
  });
});

describe('platformDefaultsStore residencyConfirmText', () => {
  const TITLE = 'platform.defaults.residencyConfirm.title';
  const BODY = 'platform.defaults.residencyConfirm.body';
  const CONFIRM = 'platform.defaults.residencyConfirm.confirm';

  /** The catalog's own text, with the plural form chosen by hand (fr counts 0 as "one"). */
  function expectedText(locale: Locale, count: number, form: 'one' | 'other') {
    const catalog = CATALOGS[locale];
    const body = catalog[BODY] as Record<string, string>;
    return {
      title: catalog[TITLE] as string,
      body: (body[form] ?? '').replace('{count}', String(count)),
      confirm: catalog[CONFIRM] as string,
    };
  }

  it.each<[Locale, number, 'one' | 'other']>([
    ['en', 0, 'other'],
    ['en', 1, 'one'],
    ['en', 7, 'other'],
    ['de', 0, 'other'],
    ['de', 1, 'one'],
    ['de', 7, 'other'],
    ['fr', 0, 'one'],
    ['fr', 7, 'other'],
  ])('in %s with %i residency orgs is the title, the %s body with the count and the confirm label', async (locale, count, form) => {
    setLocale(locale);
    const store = await withDialog('anthropic', settings({ llm: { residency_orgs: count } }));

    const text = store.residencyConfirmText;

    expect({ text, namesCount: text?.body.includes(String(count)) ?? false }).toStrictEqual({
      text: expectedText(locale, count, form),
      namesCount: true,
    });
  });

  it('is null while the dialog is closed, and again after it is cancelled', async () => {
    const store = await setup();
    const before = store.residencyConfirmText;
    edit(store, (d) => {
      d.llm.provider = 'anthropic';
    });
    await settled(store.save());
    const open = store.residencyConfirmText === null ? 'closed' : 'open';

    store.cancelResidency();

    expect({ before, open, after: store.residencyConfirmText }).toStrictEqual({
      before: null,
      open: 'open',
      after: null,
    });
  });
});

describe('platformDefaultsStore cancelResidency', () => {
  it('closes the dialog without a request and keeps the draft with all its edits', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.llm.provider = 'anthropic';
      d.llm.anthropic_model = 'claude-opus-4-1';
      d.files.max_file_size_mb = 100;
    });
    await settled(store.save());
    const draftBefore = draftJson(store);

    store.cancelResidency();

    expect({
      residencyConfirm: store.residencyConfirm,
      calls: apiCalls(),
      draft: draftJson(store),
      dirty: store.dirty,
      settings: store.settings,
      toasts: toastSummary(),
    }).toStrictEqual({
      residencyConfirm: null,
      calls: NO_CALLS,
      draft: draftBefore,
      dirty: true,
      settings: settings(),
      toasts: [],
    });
  });
});

describe('platformDefaultsStore confirmResidency', () => {
  it('sends the changed fields plus confirm_residency_orgs, then closes the dialog and applies the response', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.llm.provider = 'anthropic';
      d.llm.anthropic_model = 'claude-opus-4-1';
      d.limits.max_context_messages = 30;
    });
    await settled(store.save());
    const response = settings({
      llm: { provider: 'anthropic', anthropic_model: 'claude-opus-4-1' },
      limits: { max_context_messages: 30 },
    });
    answerPatch(response);

    const outcome = await settled(store.confirmResidency());

    expect({
      outcome,
      calls: apiCalls(),
      sent,
      residencyConfirm: store.residencyConfirm,
      settings: store.settings,
      draft: store.draft,
      dirty: store.dirty,
      saving: store.saving,
      saveError: store.saveError,
      toasts: toastSummary(),
    }).toStrictEqual({
      outcome: true,
      calls: { ...NO_CALLS, patchPlatformSettings: 1 },
      sent: [
        {
          llm: { provider: 'anthropic', anthropic_model: 'claude-opus-4-1' },
          limits: { max_context_messages: 30 },
          confirm_residency_orgs: 3,
        },
      ],
      residencyConfirm: null,
      settings: response,
      draft: draftOf(response),
      dirty: false,
      saving: false,
      saveError: null,
      toasts: [{ kind: 'success', title: msg('platform.toast.defaultsSaved') }],
    });
  });

  it('sends confirm_residency_orgs 0 (the key is present) when no organization has data residency on', async () => {
    const store = await withDialog('openai', settings({ llm: { residency_orgs: 0 } }));
    answerPatch(settings({ llm: { provider: 'openai', residency_orgs: 0 } }));

    const outcome = await settled(store.confirmResidency());

    expect({ outcome, sent }).toStrictEqual({
      outcome: true,
      sent: [{ llm: { provider: 'openai' }, confirm_residency_orgs: 0 }],
    });
  });

  it('is saving while the confirmed switch is in flight, and sends nothing more meanwhile', async () => {
    const store = await withDialog('anthropic');
    const response = deferred<PlatformSettings>();
    answerPatch(response.promise);

    const first = settled(store.confirmResidency());
    const during = store.saving;
    await settled(store.confirmResidency());
    await settled(store.save());
    const callsDuring = apiCalls();
    response.resolve(settings({ llm: { provider: 'anthropic' } }));
    const outcome = await first;

    expect({ during, callsDuring, outcome, after: store.saving, residencyConfirm: store.residencyConfirm }).toStrictEqual({
      during: true,
      callsDuring: { ...NO_CALLS, patchPlatformSettings: 1 },
      outcome: true,
      after: false,
      residencyConfirm: null,
    });
  });

  it('sends nothing and resolves false before the first load', async () => {
    const store = usePlatformDefaultsStore();

    const outcome = await settled(store.confirmResidency());

    expect({ outcome, calls: apiCalls() }).toStrictEqual({ outcome: false, calls: NO_CALLS });
  });

  it('sends nothing and resolves false when no dialog is open, even with a pending provider switch', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.llm.provider = 'anthropic';
    });

    const outcome = await settled(store.confirmResidency());

    expect({ outcome, calls: apiCalls(), residencyConfirm: store.residencyConfirm }).toStrictEqual({
      outcome: false,
      calls: NO_CALLS,
      residencyConfirm: null,
    });
  });

  it('sends nothing after the dialog was cancelled', async () => {
    const store = await withDialog('openai');
    store.cancelResidency();

    const outcome = await settled(store.confirmResidency());

    expect({ outcome, calls: apiCalls() }).toStrictEqual({ outcome: false, calls: NO_CALLS });
  });
});

describe('platformDefaultsStore confirmResidency after a residency 409', () => {
  it.each<[number]>([[5], [0]])(
    'reloads the settings, keeps the draft and asks again with the reloaded count (%i)',
    async (newCount) => {
      const store = await setup();
      edit(store, (d) => {
        d.llm.provider = 'anthropic';
        d.security.rate_limit_per_minute = 40;
      });
      await settled(store.save());
      const draftBefore = draftJson(store);
      answerPatch(residencyConflict());
      const reloaded = settings({ llm: { residency_orgs: newCount } });
      platform.getPlatformSettings.mockResolvedValueOnce(reloaded);

      const outcome = await settled(store.confirmResidency());

      expect({
        outcome,
        calls: apiCalls(),
        reloadArgs: platform.getPlatformSettings.mock.calls,
        settings: store.settings,
        draft: draftJson(store),
        dirty: store.dirty,
        residencyConfirm: store.residencyConfirm,
        saving: store.saving,
        saveErrorIsCatalogText: [null, msg('platform.error.residencyConfirmation')].includes(store.saveError),
        successToasts: toastSummary().filter((toast) => toast.kind === 'success'),
      }).toStrictEqual({
        outcome: false,
        calls: { ...NO_CALLS, patchPlatformSettings: 1, getPlatformSettings: 1 },
        reloadArgs: [[]],
        settings: settings({ llm: { residency_orgs: newCount } }),
        draft: draftBefore,
        dirty: true,
        residencyConfirm: { count: newCount },
        saving: false,
        saveErrorIsCatalogText: true,
        successToasts: [],
      });
    },
  );

  it('sends the reloaded count on the next confirmation, keeps the other edits and then succeeds', async () => {
    const store = await setup();
    edit(store, (d) => {
      d.llm.provider = 'openai';
      d.llm.openai_model = 'gpt-4.1';
      d.retention.audit_months = 24;
    });
    await settled(store.save());
    answerPatch(residencyConflict());
    platform.getPlatformSettings.mockResolvedValueOnce(settings({ llm: { residency_orgs: 4 } }));
    await settled(store.confirmResidency());
    const response = settings({
      llm: { provider: 'openai', openai_model: 'gpt-4.1', residency_orgs: 4 },
      retention: { audit_months: 24 },
    });
    answerPatch(response);

    const outcome = await settled(store.confirmResidency());

    const patch = { llm: { provider: 'openai', openai_model: 'gpt-4.1' }, retention: { audit_months: 24 } };
    expect({
      outcome,
      sent,
      residencyConfirm: store.residencyConfirm,
      settings: store.settings,
      draft: store.draft,
      saveError: store.saveError,
      toasts: toastSummary(),
    }).toStrictEqual({
      outcome: true,
      sent: [
        { ...patch, confirm_residency_orgs: 3 },
        { ...patch, confirm_residency_orgs: 4 },
      ],
      residencyConfirm: null,
      settings: response,
      draft: draftOf(response),
      saveError: null,
      toasts: [{ kind: 'success', title: msg('platform.toast.defaultsSaved') }],
    });
  });

  it.each<[string, unknown, string]>([
    ['a 429', apiError(429), 'platform.error.rateLimited'],
    ['a 403', apiError(403), 'platform.error.forbidden'],
    ['a network failure', new TypeError('Failed to fetch'), 'platform.error.generic'],
  ])('closes the dialog with the translated reload error when the reload fails with %s', async (_label, error, key) => {
    const store = await withDialog('anthropic');
    const draftBefore = draftJson(store);
    answerPatch(residencyConflict());
    platform.getPlatformSettings.mockRejectedValueOnce(error);

    const outcome = await settled(store.confirmResidency());

    expect({
      outcome,
      calls: apiCalls(),
      residencyConfirm: store.residencyConfirm,
      saveError: store.saveError,
      settings: store.settings,
      draft: draftJson(store),
      saving: store.saving,
    }).toStrictEqual({
      outcome: false,
      calls: { ...NO_CALLS, patchPlatformSettings: 1, getPlatformSettings: 1 },
      residencyConfirm: null,
      saveError: msg(key),
      settings: settings(),
      draft: draftBefore,
      saving: false,
    });
  });
});

describe('platformDefaultsStore confirmResidency other failures', () => {
  it.each<[string, unknown, string]>([
    ['a 409 without a reason', apiError(409), 'platform.error.generic'],
    ['a 409 with another reason', apiError(409, 'stale_settings'), 'platform.error.generic'],
    ['a 422', apiError(422), 'platform.error.invalidInput'],
    ['a 400', apiError(400), 'platform.error.invalidInput'],
    ['a 429', apiError(429), 'platform.error.rateLimited'],
    ['a 403', apiError(403), 'platform.error.forbidden'],
    ['a 500', apiError(500), 'platform.error.generic'],
    ['a network failure', new TypeError('Failed to fetch'), 'platform.error.generic'],
  ])('on %s closes the dialog, keeps the draft and sets the translated saveError without a reload', async (_label, error, key) => {
    const store = await withDialog('openai');
    const draftBefore = draftJson(store);
    answerPatch(error as Error);

    const outcome = await settled(store.confirmResidency());

    expect({
      outcome,
      calls: apiCalls(),
      residencyConfirm: store.residencyConfirm,
      saveError: store.saveError,
      settings: store.settings,
      draft: draftJson(store),
      saving: store.saving,
      successToasts: toastSummary().filter((toast) => toast.kind === 'success'),
    }).toStrictEqual({
      outcome: false,
      calls: { ...NO_CALLS, patchPlatformSettings: 1 },
      residencyConfirm: null,
      saveError: msg(key),
      settings: settings(),
      draft: draftBefore,
      saving: false,
      successToasts: [],
    });
  });
});

describe('platformDefaultsStore provider changes without a confirmation', () => {
  it.each<[LlmProvider, LlmProvider]>([
    ['infomaniak', 'vllm'],
    ['vllm', 'infomaniak'],
    ['anthropic', 'infomaniak'],
    ['openai', 'vllm'],
  ])('switching from %s to the Swiss %s is sent at once, without a dialog or a count', async (stored, next) => {
    const store = await setup(settings({ llm: { provider: stored, vllm_model: 'qwen2.5-7b' } }));
    edit(store, (d) => {
      d.llm.provider = next;
    });
    const response = settings({ llm: { provider: next, vllm_model: 'qwen2.5-7b' } });
    answerPatch(response);

    const outcome = await settled(store.save());

    expect({
      outcome,
      sent,
      residencyConfirm: store.residencyConfirm,
      settings: store.settings,
      toasts: toastSummary(),
    }).toStrictEqual({
      outcome: true,
      sent: [{ llm: { provider: next } }],
      residencyConfirm: null,
      settings: response,
      toasts: [{ kind: 'success', title: msg('platform.toast.defaultsSaved') }],
    });
  });

  it.each<[LlmProvider]>([['anthropic'], ['openai']])(
    'keeping the non-Swiss %s while changing other fields needs no confirmation',
    async (stored) => {
      const store = await setup(settings({ llm: { provider: stored } }));
      edit(store, (d) => {
        d.llm.max_retries = 5;
        d.llm.anthropic_model = 'claude-haiku-4-5';
        d.limits.max_pending_confirmations = 5;
      });
      answerPatch(
        settings({
          llm: { provider: stored, max_retries: 5, anthropic_model: 'claude-haiku-4-5' },
          limits: { max_pending_confirmations: 5 },
        }),
      );

      const outcome = await settled(store.save());

      expect({ outcome, sent, residencyConfirm: store.residencyConfirm }).toStrictEqual({
        outcome: true,
        sent: [{ llm: { max_retries: 5, anthropic_model: 'claude-haiku-4-5' }, limits: { max_pending_confirmations: 5 } }],
        residencyConfirm: null,
      });
    },
  );
});

// --- Operator blindness and logging ----------------------------------------------

/** Runs every flow of the page once: load failure and success, invalid, failing and good saves, the dialog with a 409. */
async function everyFlow(): Promise<Store> {
  const store = usePlatformDefaultsStore();
  platform.getPlatformSettings.mockRejectedValueOnce(apiError(500));
  await settled(store.load());
  platform.getPlatformSettings.mockResolvedValueOnce(settings());
  await settled(store.load());

  edit(store, (d) => {
    d.llm.anthropic_model = 'bad model; rm';
  });
  await settled(store.save());
  store.reset();

  edit(store, (d) => {
    d.limits.max_message_length = 6000;
  });
  answerPatch(apiError(422));
  await settled(store.save());
  answerPatch(settings({ limits: { max_message_length: 6000 } }));
  await settled(store.save());

  edit(store, (d) => {
    d.llm.provider = 'anthropic';
  });
  await settled(store.save());
  store.cancelResidency();
  await settled(store.save());
  answerPatch(residencyConflict());
  platform.getPlatformSettings.mockResolvedValueOnce(
    settings({ llm: { residency_orgs: 4 }, limits: { max_message_length: 6000 } }),
  );
  await settled(store.confirmResidency());
  answerPatch(apiError(500));
  await settled(store.confirmResidency());
  await settled(store.save());
  answerPatch(settings({ llm: { provider: 'anthropic', residency_orgs: 4 }, limits: { max_message_length: 6000 } }));
  await settled(store.confirmResidency());
  return store;
}

describe('platformDefaultsStore operator blindness', () => {
  it('talks only to getPlatformSettings and patchPlatformSettings, never to fetch or another platform route', async () => {
    await everyFlow();

    expect({ calls: apiCalls(), fetch: fetchSpy.mock.calls.length }).toStrictEqual({
      calls: { getPlatformSettings: 3, patchPlatformSettings: 5, other: 0 },
      fetch: 0,
    });
  });

  it('holds no credential: the only key/token fields in its state are the *_configured booleans', async () => {
    const store = await everyFlow();

    const credentialLike = /secret|password|credential|api_?key|_key$|^key$|token$/i;
    const found: Array<[string, string]> = [];
    const walk = (value: unknown, path: string): void => {
      if (value === null || typeof value !== 'object') return;
      for (const [name, child] of Object.entries(value as Record<string, unknown>)) {
        const childPath = path === '' ? name : `${path}.${name}`;
        if (/(key|token)_configured$/i.test(name) || credentialLike.test(name)) {
          found.push([childPath, typeof child]);
        }
        walk(child, childPath);
      }
    };
    walk(store.$state, '');

    expect(found.sort()).toStrictEqual([
      ['settings.llm.anthropic_key_configured', 'boolean'],
      ['settings.llm.infomaniak_token_configured', 'boolean'],
      ['settings.llm.openai_key_configured', 'boolean'],
    ]);
  });
});

describe('platformDefaultsStore logging', () => {
  it('never writes to the console, and never the backend text, in any flow', async () => {
    const methods = ['log', 'info', 'warn', 'error', 'debug'] as const;
    const spies = methods.map((method) => vi.spyOn(console, method).mockImplementation(() => undefined));

    const store = await everyFlow();

    const logged = spies
      .flatMap((spy) => spy.mock.calls.flat())
      .map((arg: unknown) => (arg instanceof Error ? `${arg.name} ${arg.message}` : String(arg)))
      .join('\n');
    expect({
      calls: spies.map((spy) => spy.mock.calls.length),
      leaked: logged.includes(DETAIL) || logged.includes('sk-live-123'),
      shown: [store.loadError, store.saveError].some((text) => text?.includes('backend detail') ?? false),
    }).toStrictEqual({ calls: [0, 0, 0, 0, 0], leaked: false, shown: false });
  });
});
