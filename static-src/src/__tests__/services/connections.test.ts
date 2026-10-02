/**
 * Connections service tests (issue #162: the Tools page becomes "my
 * connections"; the Org Admin's service switches move to the Organization
 * console; residency orgs see the Google/Microsoft rows disabled).
 *
 * `@/services/connections` is a pure module: it decides, from a provider's
 * `GET /api/oauth/{provider}/status` answer, what the Tools page offers, and
 * from the org's residency flag which Organization-console switches are
 * locked. Contract (GH-162 §14):
 * - `PROVIDER_TOOLS`: google -> gmail, google_calendar, google_drive;
 *   microsoft -> outlook, outlook_calendar, onedrive (in this order).
 * - `RESIDENCY_BLOCKED_TOOLS`: exactly those six tools (never `memory`).
 * - `providerState(status)`: 'residency' whenever `data_residency`; else
 *   'connected' iff connected AND healthy; else 'not_connected'.
 * - `serviceState(status, tool)`: residency -> 'residency'; not (connected
 *   AND healthy) -> 'not_connected'; the tool missing from `services`, or its
 *   `enabled` not strictly `true` -> 'org_disabled'; else 'active'.
 * - `serviceStateKey(state)`: the `toolsPage.service.state.*` catalog key.
 * - `canConnect(status)`: no residency AND not (connected AND healthy).
 * - `canDisconnect(status)`: connected AND healthy (also under residency, so
 *   a kept-but-inactive connection can still be removed).
 * - `oauthCallbackMessageKey(reason)`: the six callback reasons map to their
 *   `toolsPage.oauth.reason.*` key through own keys only; anything else
 *   (null, '', prototype keys such as '__proto__' / 'toString') gives
 *   `toolsPage.oauth.reason.unexpected`.
 * - `isResidencyLocked(tool, dataResidency)`: dataResidency AND the tool is
 *   one of the six; `memory` is never locked.
 *
 * Security notes: residency and the org switches fail closed (anything but a
 * literal `enabled: true` is "org disabled"), and a crafted callback reason
 * can never resolve to an inherited property instead of a catalog key.
 * No component is mounted and nothing touches the network.
 */
import { describe, it, expect } from 'vitest';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';
import {
  PROVIDER_TOOLS,
  RESIDENCY_BLOCKED_TOOLS,
  canConnect,
  canDisconnect,
  isResidencyLocked,
  oauthCallbackMessageKey,
  providerState,
  serviceState,
  serviceStateKey,
  type ProviderState,
  type ServiceState,
} from '@/services/connections';
import type {
  ConnectorTool,
  OAuthConnectionStatus,
  OAuthProvider,
  OAuthServiceStatus,
  ToolsSettings,
} from '@/api/types';

const GOOGLE_TOOLS: readonly ConnectorTool[] = ['gmail', 'google_calendar', 'google_drive'];
const MICROSOFT_TOOLS: readonly ConnectorTool[] = ['outlook', 'outlook_calendar', 'onedrive'];
const CONNECTOR_TOOLS: readonly ConnectorTool[] = [...GOOGLE_TOOLS, ...MICROSOFT_TOOLS];
const ALL_TOOLS: ReadonlyArray<keyof ToolsSettings> = [...CONNECTOR_TOOLS, 'memory'];

const SERVICE_STATES: readonly ServiceState[] = ['active', 'org_disabled', 'residency', 'not_connected'];

const CALLBACK_REASONS: ReadonlyArray<[string, string]> = [
  ['denied', 'toolsPage.oauth.reason.denied'],
  ['invalid_state', 'toolsPage.oauth.reason.invalidState'],
  ['missing_code', 'toolsPage.oauth.reason.missingCode'],
  ['exchange_failed', 'toolsPage.oauth.reason.exchangeFailed'],
  ['forbidden', 'toolsPage.oauth.reason.forbidden'],
  ['residency', 'toolsPage.oauth.reason.residency'],
];

const UNEXPECTED_KEY = 'toolsPage.oauth.reason.unexpected';

/** Reasons the backend never sends: each must fall back to the "unexpected" key. */
const UNKNOWN_REASONS: ReadonlyArray<string | null> = [
  null,
  '',
  '__proto__',
  'constructor',
  'toString',
  'hasOwnProperty',
  'valueOf',
  'isPrototypeOf',
  'success',
  'Denied',
  'DENIED',
  ' denied',
  'denied ',
  'invalidState',
  'exchangeFailed',
  'toolsPage.oauth.reason.denied',
  'unexpected',
];

type CatalogLocale = 'en' | 'de' | 'fr';

const CATALOGS: Record<CatalogLocale, Record<string, unknown>> = { en, de, fr };
const LOCALES: readonly CatalogLocale[] = ['en', 'de', 'fr'];

// --- Fixtures -------------------------------------------------------------

function providerOf(tool: ConnectorTool): OAuthProvider {
  return GOOGLE_TOOLS.includes(tool) ? 'google' : 'microsoft';
}

/** The provider's three services, all enabled unless overridden. */
function services(provider: OAuthProvider, enabled: Partial<Record<ConnectorTool, boolean>> = {}): OAuthServiceStatus[] {
  const tools = provider === 'google' ? GOOGLE_TOOLS : MICROSOFT_TOOLS;
  return tools.map((tool) => ({ tool, enabled: enabled[tool] ?? true }));
}

/** A connected, healthy, non-residency Google status unless overridden. */
function status(overrides: Partial<OAuthConnectionStatus> = {}): OAuthConnectionStatus {
  return {
    connected: true,
    healthy: true,
    email: null,
    data_residency: false,
    services: services('google'),
    ...overrides,
  };
}

/** A status whose `services` holds `tool` with an `enabled` value a well-behaved backend never sends. */
function craftedEnabled(tool: ConnectorTool, enabled: unknown): OAuthConnectionStatus {
  const crafted = services(providerOf(tool)).map((entry) =>
    entry.tool === tool ? ({ tool, enabled } as unknown as OAuthServiceStatus) : entry,
  );
  return status({ services: crafted });
}

/** The connected/healthy/residency combinations, as [connected, healthy, data_residency]. */
const FLAG_COMBINATIONS: ReadonlyArray<[boolean, boolean, boolean]> = [
  [true, true, false],
  [true, false, false],
  [false, true, false],
  [false, false, false],
  [true, true, true],
  [true, false, true],
  [false, true, true],
  [false, false, true],
];

function ownText(catalog: Record<string, unknown>, key: string): string | undefined {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  return typeof value === 'string' ? value : undefined;
}

// --- PROVIDER_TOOLS / RESIDENCY_BLOCKED_TOOLS -----------------------------

describe('connections PROVIDER_TOOLS', () => {
  it('maps google and microsoft to their three services, in order', () => {
    expect({ google: [...PROVIDER_TOOLS.google], microsoft: [...PROVIDER_TOOLS.microsoft] }).toEqual({
      google: ['gmail', 'google_calendar', 'google_drive'],
      microsoft: ['outlook', 'outlook_calendar', 'onedrive'],
    });
  });

  it('has exactly the two providers', () => {
    expect(Object.keys(PROVIDER_TOOLS).sort()).toEqual(['google', 'microsoft']);
  });

  it('never lists memory as a provider service', () => {
    expect([...PROVIDER_TOOLS.google, ...PROVIDER_TOOLS.microsoft]).not.toContain('memory');
  });
});

describe('connections RESIDENCY_BLOCKED_TOOLS', () => {
  it('holds exactly the six Google and Microsoft tools', () => {
    expect({ size: RESIDENCY_BLOCKED_TOOLS.size, tools: [...RESIDENCY_BLOCKED_TOOLS].sort() }).toEqual({
      size: 6,
      tools: [...CONNECTOR_TOOLS].sort(),
    });
  });

  it('never blocks memory', () => {
    expect(RESIDENCY_BLOCKED_TOOLS.has('memory')).toBe(false);
  });

  it('is the union of both providers\' services', () => {
    expect([...RESIDENCY_BLOCKED_TOOLS].sort()).toEqual([...PROVIDER_TOOLS.google, ...PROVIDER_TOOLS.microsoft].sort());
  });
});

// --- providerState --------------------------------------------------------

describe('connections providerState', () => {
  const expected: Record<string, ProviderState> = {
    'true,true,false': 'connected',
    'true,false,false': 'not_connected',
    'false,true,false': 'not_connected',
    'false,false,false': 'not_connected',
    'true,true,true': 'residency',
    'true,false,true': 'residency',
    'false,true,true': 'residency',
    'false,false,true': 'residency',
  };

  it.each(FLAG_COMBINATIONS)(
    'connected=%s healthy=%s data_residency=%s',
    (connected, healthy, dataResidency) => {
      expect(providerState(status({ connected, healthy, data_residency: dataResidency }))).toBe(
        expected[`${connected},${healthy},${dataResidency}`],
      );
    },
  );

  it('reads a microsoft status the same way', () => {
    expect(
      providerState({
        connected: true,
        healthy: true,
        email: 'alice@contoso.example',
        data_residency: false,
        services: services('microsoft'),
      }),
    ).toBe('connected');
  });
});

// --- serviceState ---------------------------------------------------------

describe('connections serviceState', () => {
  it.each(CONNECTOR_TOOLS)('gives active for %s when connected, healthy, no residency and enabled', (tool) => {
    expect(serviceState(status({ services: services(providerOf(tool)) }), tool)).toBe('active');
  });

  it.each(FLAG_COMBINATIONS.filter(([, , residency]) => residency))(
    'gives residency whenever data_residency is on (connected=%s healthy=%s)',
    (connected, healthy) => {
      const states = CONNECTOR_TOOLS.map((tool) =>
        serviceState(status({ connected, healthy, data_residency: true, services: services(providerOf(tool)) }), tool),
      );

      expect(states).toEqual(CONNECTOR_TOOLS.map(() => 'residency'));
    },
  );

  it('gives residency, not org_disabled, for a switched-off service under residency', () => {
    expect(
      serviceState(status({ data_residency: true, services: services('google', { gmail: false }) }), 'gmail'),
    ).toBe('residency');
  });

  it('gives residency, not org_disabled, under residency when services is empty', () => {
    expect(serviceState(status({ data_residency: true, services: [] }), 'google_drive')).toBe('residency');
  });

  it.each([
    [true, false],
    [false, true],
    [false, false],
  ])('gives not_connected for an enabled service when connected=%s healthy=%s', (connected, healthy) => {
    expect(serviceState(status({ connected, healthy }), 'gmail')).toBe('not_connected');
  });

  it('gives not_connected, not org_disabled, when not connected and the service is switched off', () => {
    expect(
      serviceState(status({ connected: false, healthy: false, services: services('google', { google_drive: false }) }), 'google_drive'),
    ).toBe('not_connected');
  });

  it('gives not_connected for a connected but unhealthy account with an empty services list', () => {
    expect(serviceState(status({ healthy: false, services: [] }), 'gmail')).toBe('not_connected');
  });

  it.each(CONNECTOR_TOOLS)('gives org_disabled for %s when the org switched it off', (tool) => {
    const provider = providerOf(tool);

    expect(serviceState(status({ services: services(provider, { [tool]: false }) }), tool)).toBe('org_disabled');
  });

  it.each(CONNECTOR_TOOLS)('gives org_disabled for %s when it is missing from services', (tool) => {
    expect(serviceState(status({ services: [] }), tool)).toBe('org_disabled');
  });

  it('gives org_disabled when services only lists the other provider\'s tools', () => {
    expect(serviceState(status({ services: services('google') }), 'outlook')).toBe('org_disabled');
  });

  it.each([
    ['the string "true"', 'true'],
    ['the number 1', 1],
    ['null', null],
    ['undefined', undefined],
    ['an object', { enabled: true }],
    ['an array', [true]],
    ['the string "yes"', 'yes'],
  ])('gives org_disabled when enabled is %s (not strictly true)', (_label, enabled) => {
    expect(serviceState(craftedEnabled('gmail', enabled), 'gmail')).toBe('org_disabled');
  });

  it('reads each service by its tool name, not by its position in services', () => {
    const reordered: OAuthServiceStatus[] = [
      { tool: 'google_drive', enabled: false },
      { tool: 'google_calendar', enabled: true },
      { tool: 'gmail', enabled: false },
    ];

    expect(GOOGLE_TOOLS.map((tool) => serviceState(status({ services: reordered }), tool))).toEqual([
      'org_disabled',
      'active',
      'org_disabled',
    ]);
  });

  it('gives each service of one status its own state', () => {
    const mixed = status({ services: services('google', { google_calendar: false }) });

    expect(GOOGLE_TOOLS.map((tool) => serviceState(mixed, tool))).toEqual(['active', 'org_disabled', 'active']);
  });

  it.each(['__proto__', 'constructor', 'toString', 'memory'])(
    'never gives active for the tool name %j that no service lists',
    (tool) => {
      expect(serviceState(status(), tool as ConnectorTool)).toBe('org_disabled');
    },
  );
});

// --- serviceStateKey ------------------------------------------------------

describe('connections serviceStateKey', () => {
  it.each([
    ['active', 'toolsPage.service.state.active'],
    ['org_disabled', 'toolsPage.service.state.orgDisabled'],
    ['residency', 'toolsPage.service.state.residency'],
    ['not_connected', 'toolsPage.service.state.notConnected'],
  ] as Array<[ServiceState, string]>)('maps %s to %s', (state, key) => {
    expect(serviceStateKey(state)).toBe(key);
  });

  it.each(LOCALES)('returns only keys with their own non-blank %s string', (locale) => {
    const missing = SERVICE_STATES.map((state) => serviceStateKey(state)).filter(
      (key) => (ownText(CATALOGS[locale], key) ?? '').trim() === '',
    );

    expect(missing).toEqual([]);
  });
});

// --- canConnect / canDisconnect ---------------------------------------------

describe('connections canConnect', () => {
  const expected: Record<string, boolean> = {
    'true,true,false': false,
    'true,false,false': true,
    'false,true,false': true,
    'false,false,false': true,
    'true,true,true': false,
    'true,false,true': false,
    'false,true,true': false,
    'false,false,true': false,
  };

  it.each(FLAG_COMBINATIONS)('connected=%s healthy=%s data_residency=%s', (connected, healthy, dataResidency) => {
    expect(canConnect(status({ connected, healthy, data_residency: dataResidency }))).toBe(
      expected[`${connected},${healthy},${dataResidency}`],
    );
  });

  it('lets a connected but unhealthy account reconnect', () => {
    expect(canConnect(status({ connected: true, healthy: false }))).toBe(true);
  });

  it('refuses connect under residency even with nothing connected', () => {
    expect(canConnect(status({ connected: false, healthy: false, data_residency: true, services: [] }))).toBe(false);
  });
});

describe('connections canDisconnect', () => {
  const expected: Record<string, boolean> = {
    'true,true,false': true,
    'true,false,false': false,
    'false,true,false': false,
    'false,false,false': false,
    'true,true,true': true,
    'true,false,true': false,
    'false,true,true': false,
    'false,false,true': false,
  };

  it.each(FLAG_COMBINATIONS)('connected=%s healthy=%s data_residency=%s', (connected, healthy, dataResidency) => {
    expect(canDisconnect(status({ connected, healthy, data_residency: dataResidency }))).toBe(
      expected[`${connected},${healthy},${dataResidency}`],
    );
  });

  it('still offers disconnect for a kept healthy connection under residency', () => {
    expect(canDisconnect(status({ connected: true, healthy: true, data_residency: true }))).toBe(true);
  });
});

// --- oauthCallbackMessageKey ----------------------------------------------

describe('connections oauthCallbackMessageKey', () => {
  it.each(CALLBACK_REASONS)('maps the reason %j to %s', (reason, key) => {
    expect(oauthCallbackMessageKey(reason)).toBe(key);
  });

  it.each(UNKNOWN_REASONS)('maps %j to the unexpected key', (reason) => {
    expect(oauthCallbackMessageKey(reason)).toBe(UNEXPECTED_KEY);
  });

  it('gives every known reason its own key', () => {
    const keys = CALLBACK_REASONS.map(([reason]) => oauthCallbackMessageKey(reason));

    expect(new Set([...keys, UNEXPECTED_KEY]).size).toBe(CALLBACK_REASONS.length + 1);
  });

  it.each(LOCALES)('returns only keys with their own non-blank %s string', (locale) => {
    const reasons: Array<string | null> = [...CALLBACK_REASONS.map(([reason]) => reason), ...UNKNOWN_REASONS];
    const missing = reasons
      .map((reason) => oauthCallbackMessageKey(reason))
      .filter((key) => typeof key !== 'string' || (ownText(CATALOGS[locale], key) ?? '').trim() === '');

    expect(missing).toEqual([]);
  });
});

// --- isResidencyLocked ----------------------------------------------------

describe('connections isResidencyLocked', () => {
  it.each(CONNECTOR_TOOLS)('locks %s under residency', (tool) => {
    expect(isResidencyLocked(tool, true)).toBe(true);
  });

  it.each(ALL_TOOLS)('never locks %s without residency', (tool) => {
    expect(isResidencyLocked(tool, false)).toBe(false);
  });

  it('never locks memory, with or without residency', () => {
    expect([isResidencyLocked('memory', true), isResidencyLocked('memory', false)]).toEqual([false, false]);
  });

  it('locks exactly the six blocked tools under residency', () => {
    expect(ALL_TOOLS.filter((tool) => isResidencyLocked(tool, true))).toEqual([...CONNECTOR_TOOLS]);
  });

  it.each(['__proto__', 'constructor', 'toString', 'files'])('never locks the unknown tool %j', (tool) => {
    expect(isResidencyLocked(tool as keyof ToolsSettings, true)).toBe(false);
  });
});
