/**
 * Stale-result tests for the platform stores (issue #168: Platform console UI,
 * Super Admin; behaviour added by the security audit's fix round, findings L1
 * and I4).
 *
 * L1, `usePlatformDefaultsStore` after a `409 residency_confirmation`: the
 * store reloads the settings, and another Super Admin may have changed other
 * fields in the meantime. The draft is rebased: the admin's own edits (what the
 * draft changed against the settings it was built from) are laid over the
 * reloaded settings. The draft therefore keeps the admin's edits and takes the
 * fresh value of every other field, and the next `confirmResidency()` sends the
 * admin's edits (with the provider) plus `confirm_residency_orgs` = the
 * reloaded count, never the other admin's fields set back to their old values.
 * Where both admins changed the same field, the admin's value wins (it is the
 * value the admin is confirming).
 *
 * I4, `usePlatformOrgDetailStore` after an org switch: a user action started on
 * org 1 (`confirmPending()` for deactivate, reactivate or a password reset;
 * `submitReinvite()`) can settle after `load()` switched to org 2. Its result
 * then belongs to no visible org: org 2's `users`, `metadata`, confirm sheet
 * (`pending`, `actionError`) and re-invite sheet (`reinviteUserId`,
 * `reinviteError`) stay as they are, no users/metadata/org-list request is made
 * for either org after the late result, and the busy flags end false. The same
 * holds when the switch happens during the re-invite's follow-up reload, also
 * while org 2 is still loading.
 *
 * Security notes: the view never shows another org's data (tenancy in the UI),
 * and a confirmation never quietly reverts another admin's security settings
 * (audit L1). `@/api/platform` is mocked with every function of the contract,
 * `fetch` is a spy that fails every call, and the real toast store is used.
 * No component is mounted and nothing touches the network.
 */
import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { ApiError } from '@/api/client';
import { setLocale, t, type MessageKey } from '@/i18n';
import { en } from '@/i18n/locales/en';
import { usePlatformDefaultsStore } from '@/stores/platformDefaults';
import { usePlatformOrgDetailStore } from '@/stores/platformOrgDetail';
import { useToastStore } from '@/stores/toasts';
import type { DefaultsDraft } from '@/services/platformDefaults';
import type { UserConfirmKind } from '@/services/platformOrgs';
import type {
  OrgInvitation,
  PlatformFiles,
  PlatformLimits,
  PlatformOrg,
  PlatformOrgMetadata,
  PlatformRetention,
  PlatformSecurity,
  PlatformSettings,
  PlatformSettingsLLM,
  PlatformUser,
  PlatformUserListResponse,
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

/** `fetch` must never be called: the stores go through `@/api/platform` only. */
const fetchSpy = vi.fn((): Promise<Response> => Promise.reject(new Error('the network is disabled in this test')));

// --- Shared helpers ---------------------------------------------------------

/** Backend error text a store must never show. */
const DETAIL = 'backend detail: ada@acme.ch is the last Org Admin of Acme AG';

function apiError(status: number, reason?: string): ApiError {
  return new ApiError(status, 'Error', DETAIL, reason);
}

/** The active-locale text of a key; throws when the en catalog lacks the key (`t` would echo it). */
function msg(key: string): string {
  if (!Object.hasOwn(en, key)) throw new Error(`the en catalog has no ${key}`);
  return t(key as MessageKey);
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

/** 'resolved' when `promise` fulfils (whatever with), else `{ threw: error }` (stores never throw). */
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

function clearCalls(): void {
  for (const fn of Object.values(platform)) fn.mockClear();
}

beforeEach(() => {
  localStorage.clear();
  setActivePinia(createPinia());
  setLocale('en');
  for (const fn of Object.values(platform)) fn.mockReset();
  fetchSpy.mockClear();
  vi.stubGlobal('fetch', fetchSpy);
});

afterEach(() => {
  setLocale('en');
});

// =============================================================================
// L1: rebase the defaults draft after a residency 409
// =============================================================================

/** What `GET /api/platform/settings` returns (models.py `PlatformSettingsResponse`). */
const BASE: PlatformSettings = {
  llm: {
    provider: 'infomaniak',
    anthropic_model: 'claude-sonnet-4-5',
    openai_model: 'gpt-4o',
    infomaniak_model: 'qwen3',
    vllm_model: '',
    infomaniak_available_models: ['qwen3', 'mistral3', 'llama3'],
    vllm_available_models: [],
    max_input_tokens: 200000,
    image_input: true,
    max_retries: 2,
    residency_orgs: 3,
    anthropic_key_configured: true,
    openai_key_configured: true,
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

/** The draft of `s` (exactly the editable fields) with `edits` applied. */
function draftOf(s: PlatformSettings, edits: (draft: DefaultsDraft) => void = () => undefined): DefaultsDraft {
  const draft: DefaultsDraft = {
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
  edits(draft);
  return draft;
}

/** Every PATCH body as it reached the API client (JSON at call time, like the wire). */
let sent: unknown[] = [];

/** The next `patchPlatformSettings` call records its body and resolves `result` (or rejects with it). */
function answerPatch(result: PlatformSettings | Error): void {
  platform.patchPlatformSettings.mockImplementationOnce((patch: unknown) => {
    sent.push(JSON.parse(JSON.stringify(patch)) as unknown);
    return result instanceof Error ? Promise.reject(result) : Promise.resolve(result);
  });
}

/** How many PATCH requests were made since the last `clearCalls()`. */
function patchCalls(): number {
  return platform.patchPlatformSettings.mock.calls.length;
}

function residencyConflict(): ApiError {
  return apiError(409, 'residency_confirmation');
}

type DefaultsStore = ReturnType<typeof usePlatformDefaultsStore>;

/**
 * The store loaded with the base settings, the admin's `edits` applied to the
 * draft (they include a switch to a non-Swiss provider), the residency dialog
 * opened by `save()`, and the first confirmation refused with the 409 while
 * the reload returns `reloaded` (another admin's changes). Call logs and the
 * recorded bodies are cleared afterwards.
 */
async function afterConflict(edits: (draft: DefaultsDraft) => void, reloaded: PlatformSettings): Promise<DefaultsStore> {
  const store = usePlatformDefaultsStore();
  platform.getPlatformSettings.mockResolvedValueOnce(settings());
  await store.load();
  const draft = store.draft as DefaultsDraft | null;
  if (draft === null) throw new Error('afterConflict: load() gave no draft');
  edits(draft);
  if ((await store.save()) !== false || store.residencyConfirm === null || patchCalls() !== 0) {
    throw new Error('afterConflict: save() did not open the residency dialog');
  }
  answerPatch(residencyConflict());
  platform.getPlatformSettings.mockResolvedValueOnce(reloaded);
  const outcome = await store.confirmResidency();
  if (outcome !== false || patchCalls() !== 1 || platform.getPlatformSettings.mock.calls.length !== 2) {
    throw new Error('afterConflict: the confirmation was not refused and reloaded');
  }
  clearCalls();
  sent = [];
  return store;
}

/** A JSON snapshot of the defaults store's dialog state. */
function dialogState(store: DefaultsStore): unknown {
  return JSON.parse(
    JSON.stringify({
      settings: store.settings,
      draft: store.draft,
      residencyConfirm: store.residencyConfirm,
      dirty: store.dirty,
      saving: store.saving,
    }),
  ) as unknown;
}

describe('platformDefaultsStore rebases the draft after a residency 409', () => {
  beforeEach(() => {
    sent = [];
  });

  it("keeps the admin's edit and takes the fresh value of a field another admin changed", async () => {
    const reloaded = settings({ llm: { residency_orgs: 4 }, security: { lockout_after_failures: 5 } });

    const store = await afterConflict((d) => {
      d.llm.provider = 'anthropic';
      d.security.session_idle_timeout_minutes = 30;
    }, reloaded);

    expect(dialogState(store)).toStrictEqual({
      settings: reloaded,
      draft: draftOf(reloaded, (d) => {
        d.llm.provider = 'anthropic';
        d.security.session_idle_timeout_minutes = 30;
      }),
      residencyConfirm: { count: 4 },
      dirty: true,
      saving: false,
    });
  });

  it("sends only the admin's edits and the reloaded count on the next confirmation, not the other admin's field", async () => {
    const reloaded = settings({ llm: { residency_orgs: 4 }, security: { lockout_after_failures: 5 } });
    const store = await afterConflict((d) => {
      d.llm.provider = 'anthropic';
      d.security.session_idle_timeout_minutes = 30;
    }, reloaded);
    const response = settings({
      llm: { provider: 'anthropic', residency_orgs: 4 },
      security: { lockout_after_failures: 5, session_idle_timeout_minutes: 30 },
    });
    answerPatch(response);

    const outcome = await outcomeOf(store.confirmResidency());

    expect({ outcome, sent, residencyConfirm: store.residencyConfirm }).toStrictEqual({
      outcome: 'resolved',
      sent: [
        {
          llm: { provider: 'anthropic' },
          security: { session_idle_timeout_minutes: 30 },
          confirm_residency_orgs: 4,
        },
      ],
      residencyConfirm: null,
    });
  });

  it('merges per field: changes in the llm section and in other sections both survive on their own side', async () => {
    const reloaded = settings({
      llm: { residency_orgs: 0, max_retries: 4, infomaniak_model: 'mistral3' },
      files: { render_dpi: 200 },
      retention: { audit_months: 24 },
    });
    const store = await afterConflict((d) => {
      d.llm.provider = 'openai';
      d.llm.openai_model = 'gpt-4.1';
      d.limits.max_context_messages = 40;
    }, reloaded);
    const draftAfterReload = JSON.parse(JSON.stringify(store.draft)) as unknown;
    answerPatch(settings({ llm: { provider: 'openai', openai_model: 'gpt-4.1' } }));

    await outcomeOf(store.confirmResidency());

    expect({ draftAfterReload, sent }).toStrictEqual({
      draftAfterReload: draftOf(reloaded, (d) => {
        d.llm.provider = 'openai';
        d.llm.openai_model = 'gpt-4.1';
        d.limits.max_context_messages = 40;
      }),
      sent: [
        {
          llm: { provider: 'openai', openai_model: 'gpt-4.1' },
          limits: { max_context_messages: 40 },
          confirm_residency_orgs: 0,
        },
      ],
    });
  });

  it.each<[string, (d: DefaultsDraft) => void, SettingsOverrides, object]>([
    [
      'a security bound',
      (d) => {
        d.llm.provider = 'anthropic';
        d.security.lockout_after_failures = 20;
      },
      { llm: { residency_orgs: 4 }, security: { lockout_after_failures: 5 } },
      { llm: { provider: 'anthropic' }, security: { lockout_after_failures: 20 }, confirm_residency_orgs: 4 },
    ],
    [
      'the provider itself',
      (d) => {
        d.llm.provider = 'anthropic';
      },
      { llm: { residency_orgs: 4, provider: 'openai' } },
      { llm: { provider: 'anthropic' }, confirm_residency_orgs: 4 },
    ],
  ])("keeps the admin's value when the other admin changed the same field (%s)", async (_label, edits, theirs, body) => {
    const reloaded = settings(theirs);
    const store = await afterConflict(edits, reloaded);
    const draftAfterReload = JSON.parse(JSON.stringify(store.draft)) as unknown;
    answerPatch(settings());

    await outcomeOf(store.confirmResidency());

    expect({ draftAfterReload, sent }).toStrictEqual({ draftAfterReload: draftOf(reloaded, edits), sent: [body] });
  });

  it('rebases again on a second 409: every reload contributes its fresh values, the edits stay', async () => {
    const edits = (d: DefaultsDraft): void => {
      d.llm.provider = 'anthropic';
      d.security.session_idle_timeout_minutes = 30;
    };
    const first = settings({ llm: { residency_orgs: 4 }, security: { lockout_after_failures: 5 } });
    const store = await afterConflict(edits, first);
    const second = settings({
      llm: { residency_orgs: 6 },
      security: { lockout_after_failures: 5 },
      files: { max_files_per_message: 20 },
    });
    answerPatch(residencyConflict());
    platform.getPlatformSettings.mockResolvedValueOnce(second);
    const secondOutcome = await store.confirmResidency();
    const afterSecond = dialogState(store);
    answerPatch(settings());

    await outcomeOf(store.confirmResidency());

    expect({ secondOutcome, afterSecond, sent }).toStrictEqual({
      secondOutcome: false,
      afterSecond: {
        settings: second,
        draft: draftOf(second, edits),
        residencyConfirm: { count: 6 },
        dirty: true,
        saving: false,
      },
      sent: [
        { llm: { provider: 'anthropic' }, security: { session_idle_timeout_minutes: 30 }, confirm_residency_orgs: 4 },
        { llm: { provider: 'anthropic' }, security: { session_idle_timeout_minutes: 30 }, confirm_residency_orgs: 6 },
      ],
    });
  });
});

// =============================================================================
// I4: late user-action results after an org switch
// =============================================================================

const GIB = 1024 ** 3;

const ACME = '5a1c2e3f-4b5d-4e6f-8a7b-9c0d1e2f3a4b';
const BETA = '6b2d3f40-5c6e-4f70-9b8c-0d1e2f3a4b5c';

const ADA = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d';
const BRUNO = 'b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e';
const GINA = 'e5f6a7b8-c9d0-4e1f-8a3b-4c5d6e7f8091';
const YANN = '4b5c6d7e-8f90-4a1b-9c2d-3e4f5a6b7c8d';
const ZOE = '18c9d0e1-f2a3-4b4c-9d6e-7f8091021324';

function org(id: string): PlatformOrg {
  return {
    id,
    name: id === ACME ? 'Acme AG' : 'Beta GmbH',
    status: 'active',
    seats: id === ACME ? 10 : 5,
    monthly_budget_chf: id === ACME ? '100.00' : '50.00',
    storage_quota: (id === ACME ? 10 : 5) * GIB,
    data_residency: id === ACME,
    deletion_requested_at: null,
    purge_after: null,
    created_at: '2026-01-10T09:00:00Z',
    updated_at: '2026-01-10T09:00:00Z',
  };
}

function user(
  id: string,
  name: string | null,
  email: string,
  role: PlatformUser['role'],
  status: PlatformUser['status'],
): PlatformUser {
  return { id, name, email, role, status, created_at: '2026-02-01T08:00:00Z', last_login_at: null };
}

/**
 * Acme (org 1): its only Org Admin Ada is deactivated (reactivatable), Bruno is
 * an active editor (deactivate, password reset) and Gina is an invited Org
 * Admin who can be re-invited (no active Org Admin).
 */
function acmeUsers(): PlatformUser[] {
  return [
    user(ADA, 'Ada Admin', 'ada@acme.ch', 'org_admin', 'deactivated'),
    user(BRUNO, 'Bruno Editor', 'bruno@acme.ch', 'editor', 'active'),
    user(GINA, null, 'gina@acme.ch', 'org_admin', 'invited'),
  ];
}

/** What a late answer for Acme would bring: visibly different from both orgs' loaded data. */
function acmeLateUsers(): PlatformUser[] {
  return [
    user(ADA, 'Ada Admin', 'ada@acme.ch', 'org_admin', 'active'),
    user(BRUNO, 'Bruno Editor', 'bruno@acme.ch', 'editor', 'deactivated'),
  ];
}

/** Beta (org 2): Yann is an active editor (deactivatable), Zoe an invited Org Admin (re-invitable). */
function betaUsers(): PlatformUser[] {
  return [
    user(YANN, 'Yann Beta', 'yann@beta.ch', 'editor', 'active'),
    user(ZOE, null, 'zoe@beta.ch', 'org_admin', 'invited'),
  ];
}

function acmeMeta(): PlatformOrgMetadata {
  return { seats: { used: 2, limit: 10 }, storage_used_bytes: 123_456, chat_count: 0, file_count: 0 };
}

function acmeLateMeta(): PlatformOrgMetadata {
  return { seats: { used: 9, limit: 10 }, storage_used_bytes: 999_999, chat_count: 0, file_count: 0 };
}

function betaMeta(): PlatformOrgMetadata {
  return { seats: { used: 1, limit: 5 }, storage_used_bytes: 42, chat_count: 0, file_count: 0 };
}

function invitation(email: string): OrgInvitation {
  return {
    id: '3ae1f203-b4c5-4d6e-9f80-910213243546',
    email,
    role: 'org_admin',
    sent_at: '2026-10-04T12:00:00Z',
    expires_at: '2026-10-07T12:00:00Z',
    expired: false,
  };
}

interface OrgAnswers {
  metadata: () => Promise<PlatformOrgMetadata>;
  users: () => Promise<PlatformUserListResponse>;
}

/** How the metadata and users calls answer, per org id (tests swap entries to hold an answer back). */
let serve: Record<string, OrgAnswers> = {};

function servedAtOnce(meta: () => PlatformOrgMetadata, users: () => PlatformUser[]): OrgAnswers {
  return { metadata: () => Promise.resolve(meta()), users: () => Promise.resolve({ users: users() }) };
}

beforeEach(() => {
  serve = {
    // Org 1 answers its follow-up reads with the "late" data, so applying them would show.
    [ACME]: servedAtOnce(acmeLateMeta, acmeLateUsers),
    [BETA]: servedAtOnce(betaMeta, betaUsers),
  };
  platform.listPlatformOrgs.mockImplementation(() => Promise.resolve({ organizations: [org(ACME), org(BETA)] }));
  platform.getPlatformOrgMetadata.mockImplementation((id: string) =>
    Object.hasOwn(serve, id) ? serve[id].metadata() : Promise.reject(apiError(404)),
  );
  platform.listPlatformOrgUsers.mockImplementation((id: string) =>
    Object.hasOwn(serve, id) ? serve[id].users() : Promise.reject(apiError(404)),
  );
});

type DetailStore = ReturnType<typeof usePlatformOrgDetailStore>;

/** The detail store showing Acme with its initial data; call logs and toasts cleared. */
async function acmeLoaded(): Promise<DetailStore> {
  const store = usePlatformOrgDetailStore();
  const later = serve[ACME];
  serve[ACME] = servedAtOnce(acmeMeta, acmeUsers);
  await store.load(ACME);
  serve[ACME] = later;
  if (store.org?.id !== ACME || store.users.length !== 3) throw new Error('acmeLoaded: Acme did not load');
  clearCalls();
  useToastStore().toasts.splice(0);
  return store;
}

/** Switches the store to Beta, waits for its data and opens both of Beta's sheets (Yann's deactivation, Zoe's re-invite). */
async function switchToBeta(store: DetailStore): Promise<void> {
  await store.load(BETA);
  store.requestDeactivate(YANN);
  store.openReinvite(ZOE);
}

/** A copy of everything the detail view shows, including both sheets. */
function view(store: DetailStore): unknown {
  return JSON.parse(
    JSON.stringify({
      orgId: store.orgId,
      org: store.org,
      metadata: store.metadata,
      users: store.users,
      loading: store.loading,
      loadError: store.loadError,
      notFound: store.notFound,
      pending: store.pending,
      actionError: store.actionError,
      reinviteUserId: store.reinviteUserId,
      reinviteError: store.reinviteError,
    }),
  ) as unknown;
}

/** What the view must show for Beta with both sheets open. */
const BETA_VIEW = {
  orgId: BETA,
  org: org(BETA),
  metadata: betaMeta(),
  users: betaUsers(),
  loading: false,
  loadError: null,
  notFound: false,
  pending: { kind: 'deactivate', userId: YANN },
  actionError: null,
  reinviteUserId: ZOE,
  reinviteError: null,
};

/** Read requests (org list, metadata, users) for any org since the last `clearCalls()`. */
function readRequests(): Record<'listPlatformOrgs' | 'getPlatformOrgMetadata' | 'listPlatformOrgUsers', unknown[][]> {
  return {
    listPlatformOrgs: platform.listPlatformOrgs.mock.calls.map((args: unknown[]) => [...args]),
    getPlatformOrgMetadata: platform.getPlatformOrgMetadata.mock.calls.map((args: unknown[]) => [...args]),
    listPlatformOrgUsers: platform.listPlatformOrgUsers.mock.calls.map((args: unknown[]) => [...args]),
  };
}

const NO_READS = { listPlatformOrgs: [], getPlatformOrgMetadata: [], listPlatformOrgUsers: [] };

function mockOf(name: PlatformFn): Mock<(...args: unknown[]) => Promise<unknown>> {
  return platform[name] as unknown as Mock<(...args: unknown[]) => Promise<unknown>>;
}

interface ActionCase {
  kind: UserConfirmKind;
  userId: string;
  fn: PlatformFn;
  request: (store: DetailStore, userId: string) => void;
  success: () => unknown;
}

const ACTIONS: ReadonlyArray<[string, ActionCase]> = [
  [
    'deactivate',
    {
      kind: 'deactivate',
      userId: BRUNO,
      fn: 'deactivatePlatformUser',
      request: (store, id) => store.requestDeactivate(id),
      success: () => user(BRUNO, 'Bruno Editor', 'bruno@acme.ch', 'editor', 'deactivated'),
    },
  ],
  [
    'reactivate',
    {
      kind: 'reactivate',
      userId: ADA,
      fn: 'reactivatePlatformUser',
      request: (store, id) => store.requestReactivate(id),
      success: () => user(ADA, 'Ada Admin', 'ada@acme.ch', 'org_admin', 'active'),
    },
  ],
  [
    'resetPassword',
    {
      kind: 'resetPassword',
      userId: BRUNO,
      fn: 'resetPlatformUserPassword',
      request: (store, id) => store.requestPasswordReset(id),
      success: () => undefined,
    },
  ],
];

type Settle = 'resolves' | 'rejects';

const SETTLES: readonly Settle[] = ['resolves', 'rejects'];

const ACTION_MATRIX = ACTIONS.flatMap(([label, action]) =>
  SETTLES.map((settle): [string, Settle, ActionCase] => [label, settle, action]),
);

describe('platformOrgDetailStore confirmPending result after an org switch', () => {
  it.each(ACTION_MATRIX)(
    'a %s on org 1 that %s after the switch leaves org 2 untouched and reloads nothing',
    async (_label, settle, action) => {
      const store = await acmeLoaded();
      action.request(store, action.userId);
      if (store.pending?.kind !== action.kind) throw new Error('the confirm sheet did not open on org 1');
      const call = deferred<unknown>();
      mockOf(action.fn).mockReturnValueOnce(call.promise);
      const confirming = store.confirmPending();
      await switchToBeta(store);
      const before = view(store);
      clearCalls();

      if (settle === 'resolves') call.resolve(action.success());
      else call.reject(apiError(409, 'invalid_status'));
      const outcome = await outcomeOf(confirming);
      await flush();

      expect({
        before,
        after: view(store),
        reads: readRequests(),
        actionBusy: store.actionBusy,
        threw: typeof outcome === 'object',
      }).toStrictEqual({ before: BETA_VIEW, after: BETA_VIEW, reads: NO_READS, actionBusy: false, threw: false });
    },
  );

  it('control: without a switch the deactivate result is applied and the metadata refreshed', async () => {
    const store = await acmeLoaded();
    store.requestDeactivate(BRUNO);
    platform.deactivatePlatformUser.mockResolvedValueOnce(
      user(BRUNO, 'Bruno Editor', 'bruno@acme.ch', 'editor', 'deactivated'),
    );

    await outcomeOf(store.confirmPending());
    await flush();

    expect({
      bruno: store.users.find((item) => item.id === BRUNO)?.status,
      metadata: store.metadata,
      pending: store.pending,
      reads: readRequests().getPlatformOrgMetadata,
    }).toStrictEqual({ bruno: 'deactivated', metadata: acmeLateMeta(), pending: null, reads: [[ACME]] });
  });
});

describe('platformOrgDetailStore submitReinvite result after an org switch', () => {
  it.each<[string, Settle, string]>([
    ['a resend', 'resolves', ''],
    ['a resend', 'rejects', ''],
    ['an address change', 'resolves', 'gina.new@acme.ch'],
    ['an address change', 'rejects', 'gina.new@acme.ch'],
  ])('%s on org 1 that %s after the switch leaves org 2 untouched and reloads nothing', async (_label, settle, email) => {
    const store = await acmeLoaded();
    store.openReinvite(GINA);
    if (store.reinviteUserId !== GINA) throw new Error('the re-invite sheet did not open on org 1');
    const call = deferred<OrgInvitation>();
    platform.reinvitePlatformUser.mockReturnValueOnce(call.promise);
    const submitting = store.submitReinvite(email);
    await switchToBeta(store);
    const before = view(store);
    clearCalls();

    if (settle === 'resolves') call.resolve(invitation(email === '' ? 'gina@acme.ch' : email));
    else call.reject(apiError(409, 'has_active_admin'));
    const outcome = await outcomeOf(submitting);
    await flush();

    expect({
      before,
      after: view(store),
      reads: readRequests(),
      reinviteBusy: store.reinviteBusy,
      threw: typeof outcome === 'object',
    }).toStrictEqual({ before: BETA_VIEW, after: BETA_VIEW, reads: NO_READS, reinviteBusy: false, threw: false });
  });

  it("a switch during the re-invite's follow-up reload keeps org 1's users and metadata out of org 2", async () => {
    const store = await acmeLoaded();
    store.openReinvite(GINA);
    platform.reinvitePlatformUser.mockResolvedValueOnce(invitation('gina@acme.ch'));
    const followMeta = deferred<PlatformOrgMetadata>();
    const followUsers = deferred<PlatformUserListResponse>();
    serve[ACME] = { metadata: () => followMeta.promise, users: () => followUsers.promise };
    const submitting = store.submitReinvite('');
    await flush();
    const followUpStarted = readRequests();
    await switchToBeta(store);
    const before = view(store);
    clearCalls();

    followUsers.resolve({ users: acmeLateUsers() });
    followMeta.resolve(acmeLateMeta());
    const outcome = await outcomeOf(submitting);
    await flush();

    expect({
      followUpStarted,
      before,
      after: view(store),
      reads: readRequests(),
      reinviteBusy: store.reinviteBusy,
      outcome,
    }).toStrictEqual({
      followUpStarted: { listPlatformOrgs: [], getPlatformOrgMetadata: [[ACME]], listPlatformOrgUsers: [[ACME]] },
      before: BETA_VIEW,
      after: BETA_VIEW,
      reads: NO_READS,
      reinviteBusy: false,
      outcome: 'resolved',
    });
  });

  it("never shows org 1's follow-up data while org 2 is still loading, then shows org 2's own data", async () => {
    const store = await acmeLoaded();
    store.openReinvite(GINA);
    platform.reinvitePlatformUser.mockResolvedValueOnce(invitation('gina@acme.ch'));
    const followMeta = deferred<PlatformOrgMetadata>();
    const followUsers = deferred<PlatformUserListResponse>();
    serve[ACME] = { metadata: () => followMeta.promise, users: () => followUsers.promise };
    const betaMetaAnswer = deferred<PlatformOrgMetadata>();
    const betaUsersAnswer = deferred<PlatformUserListResponse>();
    serve[BETA] = { metadata: () => betaMetaAnswer.promise, users: () => betaUsersAnswer.promise };
    const submitting = store.submitReinvite('');
    await flush();
    const loadingBeta = store.load(BETA);

    followUsers.resolve({ users: acmeLateUsers() });
    followMeta.resolve(acmeLateMeta());
    await outcomeOf(submitting);
    await flush();
    const whileLoading = view(store);
    betaMetaAnswer.resolve(betaMeta());
    betaUsersAnswer.resolve({ users: betaUsers() });
    await outcomeOf(loadingBeta);
    await flush();

    expect({ whileLoading, loaded: view(store), reinviteBusy: store.reinviteBusy }).toStrictEqual({
      whileLoading: {
        orgId: BETA,
        org: null,
        metadata: null,
        users: [],
        loading: true,
        loadError: null,
        notFound: false,
        pending: null,
        actionError: null,
        reinviteUserId: null,
        reinviteError: null,
      },
      loaded: { ...BETA_VIEW, pending: null, reinviteUserId: null },
      reinviteBusy: false,
    });
  });

  it('control: without a switch the re-invite closes the sheet and reloads org 1', async () => {
    const store = await acmeLoaded();
    store.openReinvite(GINA);
    platform.reinvitePlatformUser.mockResolvedValueOnce(invitation('gina@acme.ch'));

    const outcome = await outcomeOf(store.submitReinvite(''));
    await flush();

    expect({
      outcome,
      reinviteUserId: store.reinviteUserId,
      users: JSON.parse(JSON.stringify(store.users)) as unknown,
      metadata: store.metadata,
      toasts: useToastStore().toasts.map(({ kind, title }) => ({ kind, title })),
    }).toStrictEqual({
      outcome: 'resolved',
      reinviteUserId: null,
      users: acmeLateUsers(),
      metadata: acmeLateMeta(),
      toasts: [{ kind: 'success', title: msg('platform.toast.invitationSent') }],
    });
  });
});
