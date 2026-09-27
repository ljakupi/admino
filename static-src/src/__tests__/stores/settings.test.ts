/**
 * Settings store tests (issue #142: Infomaniak provider, the new default).
 *
 * Covers the LLM part of the settings store: Infomaniak as the initial
 * provider, mapping the `llm.infomaniak_*` fields of `GET /api/settings` into
 * store state, the `setInfomaniakModel` / `setProvider('infomaniak')` actions
 * (request formation, applying the server response, reverting on rejection),
 * and that a response can never smuggle the API token into the store: only
 * the boolean "token configured" indicator is kept. Issue #144 translates
 * the UI: the save toast copy comes from the i18n catalogs and follows the
 * active locale. Issue #149 replaces the bearer token with a server-side
 * session cookie: the store keeps no `token` / `needsAuth` state, has no
 * `setToken` / `skipAuth` actions and never reads the old `admino_auth_token`
 * localStorage key. The network layer (`@/api/settings`) is mocked; nothing
 * touches `fetch`.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { getSettings, patchSettings } from '@/api/settings';
import { ApiError } from '@/api/client';
import { setLocale } from '@/i18n';
import { fr } from '@/i18n/locales/fr';
import { useSettingsStore, type LLMProvider } from '@/stores/settings';
import { useToastStore } from '@/stores/toasts';
import type { LLMProviderName, LLMSettings, SettingsResponse } from '@/api/types';

vi.mock('@/api/settings', () => ({
  getSettings: vi.fn(),
  patchSettings: vi.fn(),
  getOAuthAuthorizeUrl: vi.fn(),
  disconnectOAuth: vi.fn(),
}));

const mockedGetSettings = vi.mocked(getSettings);
const mockedPatchSettings = vi.mocked(patchSettings);

const DEFAULT_INFOMANIAK_MODEL = 'Qwen/Qwen3.5-397B-A17B-FP8';
const SMALLER_INFOMANIAK_MODEL = 'Qwen/Qwen3.5-122B-A10B-FP8';
/** A token-shaped secret a misbehaving backend or proxy might inject. */
const LEAKED_TOKEN = 'ik-SECRET-infomaniak-token-7539-do-not-store';

// --- Fixtures -------------------------------------------------------------

function makeSettings(llm: Partial<LLMSettings> = {}): SettingsResponse {
  return {
    llm: {
      provider: 'infomaniak',
      anthropic_model: 'claude-sonnet-4-5',
      openai_model: 'gpt-4o',
      vllm_model: 'google/gemma-3-12b-it',
      vllm_available_models: [],
      anthropic_key_configured: false,
      openai_key_configured: false,
      infomaniak_model: DEFAULT_INFOMANIAK_MODEL,
      infomaniak_available_models: [DEFAULT_INFOMANIAK_MODEL, SMALLER_INFOMANIAK_MODEL],
      infomaniak_token_configured: true,
      ...llm,
    },
    appearance: { theme: 'light' },
    notifications: { enabled: false },
    limits: {
      max_tool_calls_per_message: 10,
      confirmation_timeout_s: 120,
      max_message_length: 4000,
    },
    server: { host: '127.0.0.1', port: 8000 },
    connected_accounts: {
      google: { connected: false, healthy: false, email: null, services: [] },
      microsoft: { connected: false, healthy: false, email: null, services: [] },
    },
    tools: {
      gmail: true,
      google_calendar: true,
      google_drive: true,
      outlook: true,
      outlook_calendar: true,
      onedrive: true,
      memory: true,
    },
  };
}

/** A response whose `llm` block carries an extra, unknown token field. */
function withLeakedToken(data: SettingsResponse): SettingsResponse {
  const llm: LLMSettings & { infomaniak_api_token: string } = {
    ...data.llm,
    infomaniak_api_token: LEAKED_TOKEN,
  };
  return { ...data, llm };
}

/** Load a settings response into the store through its public API. */
async function loadWith(data: SettingsResponse) {
  mockedGetSettings.mockResolvedValueOnce(data);
  const store = useSettingsStore();
  await store.loadSettings();
  if (store.error) throw new Error(`test setup: loadSettings failed: ${store.error}`);
  return store;
}

/** True when `needle` occurs in any string reachable from `value`. */
function holdsString(value: unknown, needle: string, seen = new Set<unknown>()): boolean {
  if (typeof value === 'string') return value.includes(needle);
  if (value === null || typeof value !== 'object' || seen.has(value)) return false;
  seen.add(value);
  return Object.values(value).some((v) => holdsString(v, needle, seen));
}

/** Every state/getter key the store exposes (actions and Pinia internals excluded). */
function exposedValues(store: ReturnType<typeof useSettingsStore>): Record<string, unknown> {
  const record = store as unknown as Record<string, unknown>;
  return Object.fromEntries(
    Object.keys(record)
      .filter((key) => !key.startsWith('$') && !key.startsWith('_'))
      .map((key) => [key, record[key]] as const)
      .filter(([, value]) => typeof value !== 'function'),
  );
}

beforeEach(() => {
  localStorage.clear();
  setActivePinia(createPinia());
  mockedGetSettings.mockReset();
  mockedPatchSettings.mockReset();
});

afterEach(() => {
  setLocale('en');
});

// --- Initial state --------------------------------------------------------

describe('settingsStore initial LLM state', () => {
  it('starts on the infomaniak provider', () => {
    expect(useSettingsStore().llmProvider).toBe('infomaniak');
  });

  it('exposes infomaniak as the initial UI provider', () => {
    expect(useSettingsStore().provider).toBe('infomaniak');
  });

  it('starts with no infomaniak model, no listed models and no token configured', () => {
    const store = useSettingsStore();

    expect({
      model: store.llmInfomaniakModel,
      available: store.infomaniakAvailableModels,
      tokenConfigured: store.infomaniakTokenConfigured,
    }).toEqual({ model: '', available: [], tokenConfigured: false });
  });
});

// --- loadSettings mapping -------------------------------------------------

describe('settingsStore loadSettings infomaniak mapping', () => {
  it('maps llm.infomaniak_model into llmInfomaniakModel', async () => {
    const store = await loadWith(makeSettings({ infomaniak_model: SMALLER_INFOMANIAK_MODEL }));

    expect(store.llmInfomaniakModel).toBe(SMALLER_INFOMANIAK_MODEL);
  });

  it('maps llm.infomaniak_available_models into infomaniakAvailableModels in order', async () => {
    const listed = [SMALLER_INFOMANIAK_MODEL, 'mistralai/Mistral-Small-3.2-24B', DEFAULT_INFOMANIAK_MODEL];

    const store = await loadWith(makeSettings({ infomaniak_available_models: listed }));

    expect(store.infomaniakAvailableModels).toEqual(listed);
  });

  it('maps an empty infomaniak model list (server unreachable) to []', async () => {
    await loadWith(makeSettings({ infomaniak_available_models: [SMALLER_INFOMANIAK_MODEL] }));

    const store = await loadWith(makeSettings({ infomaniak_available_models: [] }));

    expect(store.infomaniakAvailableModels).toEqual([]);
  });

  it('maps infomaniak_token_configured=true to infomaniakTokenConfigured=true', async () => {
    const store = await loadWith(makeSettings({ infomaniak_token_configured: true }));

    expect(store.infomaniakTokenConfigured).toBe(true);
  });

  it('maps infomaniak_token_configured=false to false after a previous true', async () => {
    await loadWith(makeSettings({ infomaniak_token_configured: true }));

    const store = await loadWith(makeSettings({ infomaniak_token_configured: false }));

    expect(store.infomaniakTokenConfigured).toBe(false);
  });

  it('switches the API and UI provider to infomaniak along with its model', async () => {
    await loadWith(makeSettings({ provider: 'vllm' }));

    const store = await loadWith(
      makeSettings({ provider: 'infomaniak', infomaniak_model: SMALLER_INFOMANIAK_MODEL }),
    );

    expect({
      llmProvider: store.llmProvider,
      provider: store.provider,
      model: store.llmInfomaniakModel,
    }).toEqual({
      llmProvider: 'infomaniak',
      provider: 'infomaniak',
      model: SMALLER_INFOMANIAK_MODEL,
    });
  });

  // Regression guards: the other providers keep their UI mapping.
  it.each<[LLMProviderName, LLMProvider]>([
    ['anthropic', 'claude'],
    ['openai', 'openai'],
    ['vllm', 'vllm'],
  ])('maps API provider %s to UI provider %s', async (apiName, uiName) => {
    const store = await loadWith(makeSettings({ provider: apiName }));

    expect(store.provider).toBe(uiName);
  });

  it('keeps the infomaniak state when another provider is active', async () => {
    const store = await loadWith(
      makeSettings({
        provider: 'anthropic',
        infomaniak_model: SMALLER_INFOMANIAK_MODEL,
        infomaniak_token_configured: true,
      }),
    );

    expect({
      model: store.llmInfomaniakModel,
      tokenConfigured: store.infomaniakTokenConfigured,
    }).toEqual({ model: SMALLER_INFOMANIAK_MODEL, tokenConfigured: true });
  });
});

// --- setInfomaniakModel ---------------------------------------------------

describe('settingsStore setInfomaniakModel', () => {
  it('patches exactly { llm: { infomaniak_model } }', async () => {
    mockedPatchSettings.mockResolvedValueOnce(
      makeSettings({ infomaniak_model: SMALLER_INFOMANIAK_MODEL }),
    );
    const store = useSettingsStore();

    await store.setInfomaniakModel(SMALLER_INFOMANIAK_MODEL);

    expect(mockedPatchSettings.mock.calls).toEqual([
      [{ llm: { infomaniak_model: SMALLER_INFOMANIAK_MODEL } }],
    ]);
  });

  it('sets llmInfomaniakModel to the saved model', async () => {
    mockedPatchSettings.mockResolvedValueOnce(
      makeSettings({ infomaniak_model: SMALLER_INFOMANIAK_MODEL }),
    );
    const store = await loadWith(makeSettings({ infomaniak_model: DEFAULT_INFOMANIAK_MODEL }));

    await store.setInfomaniakModel(SMALLER_INFOMANIAK_MODEL);

    expect(store.llmInfomaniakModel).toBe(SMALLER_INFOMANIAK_MODEL);
  });

  it('applies the server response to the rest of the infomaniak state', async () => {
    const refreshed = ['mistralai/Mistral-Small-3.2-24B', SMALLER_INFOMANIAK_MODEL];
    mockedPatchSettings.mockResolvedValueOnce(
      makeSettings({
        infomaniak_model: SMALLER_INFOMANIAK_MODEL,
        infomaniak_available_models: refreshed,
        infomaniak_token_configured: true,
      }),
    );
    const store = await loadWith(
      makeSettings({ infomaniak_available_models: [], infomaniak_token_configured: false }),
    );

    await store.setInfomaniakModel(SMALLER_INFOMANIAK_MODEL);

    expect({
      available: store.infomaniakAvailableModels,
      tokenConfigured: store.infomaniakTokenConfigured,
    }).toEqual({ available: refreshed, tokenConfigured: true });
  });
});

// --- setProvider('infomaniak') -------------------------------------------

describe('settingsStore setProvider infomaniak', () => {
  it("patches exactly { llm: { provider: 'infomaniak' } } and applies the response", async () => {
    mockedPatchSettings.mockResolvedValueOnce(
      makeSettings({
        provider: 'infomaniak',
        infomaniak_model: DEFAULT_INFOMANIAK_MODEL,
        infomaniak_available_models: [DEFAULT_INFOMANIAK_MODEL],
        infomaniak_token_configured: true,
      }),
    );
    const store = await loadWith(
      makeSettings({
        provider: 'anthropic',
        infomaniak_model: '',
        infomaniak_available_models: [],
        infomaniak_token_configured: false,
      }),
    );

    await store.setProvider('infomaniak');

    expect({
      patches: mockedPatchSettings.mock.calls,
      provider: store.provider,
      model: store.llmInfomaniakModel,
      available: store.infomaniakAvailableModels,
      tokenConfigured: store.infomaniakTokenConfigured,
    }).toEqual({
      patches: [[{ llm: { provider: 'infomaniak' } }]],
      provider: 'infomaniak',
      model: DEFAULT_INFOMANIAK_MODEL,
      available: [DEFAULT_INFOMANIAK_MODEL],
      tokenConfigured: true,
    });
  });

  it('reverts to the previous provider and keeps the infomaniak state when rejected', async () => {
    mockedPatchSettings.mockRejectedValueOnce(
      new ApiError(422, 'Unprocessable Entity', 'Invalid provider'),
    );
    const store = await loadWith(
      makeSettings({
        provider: 'openai',
        infomaniak_model: SMALLER_INFOMANIAK_MODEL,
        infomaniak_token_configured: true,
      }),
    );

    await expect(store.setProvider('infomaniak')).rejects.toThrow();

    expect({
      llmProvider: store.llmProvider,
      provider: store.provider,
      model: store.llmInfomaniakModel,
      tokenConfigured: store.infomaniakTokenConfigured,
    }).toEqual({
      llmProvider: 'openai',
      provider: 'openai',
      model: SMALLER_INFOMANIAK_MODEL,
      tokenConfigured: true,
    });
  });

  it('reverts to the initial infomaniak provider when switching away is rejected', async () => {
    mockedPatchSettings.mockRejectedValueOnce(new TypeError('Failed to fetch'));
    const store = useSettingsStore();

    await expect(store.setProvider('claude')).rejects.toThrow();

    expect(store.llmProvider).toBe('infomaniak');
  });
});

// --- Token never reaches the browser state -------------------------------

describe('settingsStore infomaniak token handling', () => {
  it.each(['loadSettings', 'setInfomaniakModel'] as const)(
    'keeps only the boolean indicator when a %s response carries a token field',
    async (path) => {
      const crafted = withLeakedToken(
        makeSettings({ infomaniak_token_configured: true, infomaniak_model: SMALLER_INFOMANIAK_MODEL }),
      );
      const store = useSettingsStore();
      if (path === 'loadSettings') {
        mockedGetSettings.mockResolvedValueOnce(crafted);
        await store.loadSettings();
      } else {
        mockedPatchSettings.mockResolvedValueOnce(crafted);
        await store.setInfomaniakModel(SMALLER_INFOMANIAK_MODEL);
      }

      const leakingKeys = Object.entries(exposedValues(store))
        .filter(([, value]) => holdsString(value, LEAKED_TOKEN))
        .map(([key]) => key);

      expect({
        tokenConfigured: store.infomaniakTokenConfigured,
        leakingKeys,
      }).toEqual({ tokenConfigured: true, leakingKeys: [] });
    },
  );
});

// --- Tools toggles (issue #143: local files tool removed) -----------------

describe('settingsStore tools toggles', () => {
  it('default tools state covers exactly the remaining tools, with no files key', () => {
    const store = useSettingsStore();

    expect(Object.keys(store.tools).sort()).toEqual([
      'gmail',
      'google_calendar',
      'google_drive',
      'memory',
      'onedrive',
      'outlook',
      'outlook_calendar',
    ]);
    expect('files' in store.tools).toBe(false);
  });
});

// --- Save toast copy follows the locale (issue #144) ---------------------

describe('settingsStore save toast follows the locale', () => {
  /** Title of the success toast a successful saveSetting produces under `locale`. */
  async function savedToastTitle(locale: string): Promise<string | undefined> {
    setLocale(locale);
    mockedPatchSettings.mockResolvedValueOnce(makeSettings());

    await useSettingsStore().saveSetting({ notifications: { enabled: true } });

    return useToastStore().toasts.find((toast) => toast.kind === 'success')?.title;
  }

  it('titles the success toast "Saved" under en', async () => {
    expect(await savedToastTitle('en')).toBe('Saved');
  });

  it('titles the success toast with the fr catalog string under fr', async () => {
    const title = await savedToastTitle('fr');

    expect(title).not.toBe('Saved');
    expect(Object.values(fr)).toContain(title);
  });
});


/**
 * A stand-in localStorage that records every key read. happy-dom's Storage
 * can't be spied through Storage.prototype, so the global is replaced.
 */
function recordingStorage(initial: Record<string, string>): { storage: Storage; reads: string[] } {
  const data = new Map(Object.entries(initial));
  const reads: string[] = [];
  const storage: Storage = {
    get length() {
      return data.size;
    },
    clear: () => data.clear(),
    getItem: (key: string) => {
      reads.push(key);
      return data.get(key) ?? null;
    },
    key: (index: number) => [...data.keys()][index] ?? null,
    removeItem: (key: string) => {
      data.delete(key);
    },
    setItem: (key: string, value: string) => {
      data.set(key, String(value));
    },
  };
  return { storage, reads };
}

// --- No bearer token (issue #149) -----------------------------------------

describe('settingsStore has no bearer token', () => {
  it.each(['token', 'needsAuth', 'setToken', 'skipAuth'])('exposes no %s', (key) => {
    expect(key in useSettingsStore()).toBe(false);
  });

  it('never reads a legacy admino_auth_token left in localStorage', () => {
    const { storage, reads } = recordingStorage({
      admino_auth_token: 'legacy-bearer-token-0123456789-abcdef',
    });
    vi.stubGlobal('localStorage', storage);

    useSettingsStore();

    expect(reads).not.toContain('admino_auth_token');
  });
});
