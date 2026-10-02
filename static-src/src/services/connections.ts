/**
 * Connections service (issue #162: the Tools page becomes "my connections";
 * the Org Admin's service switches move to the Organization console;
 * residency orgs see the Google/Microsoft rows disabled).
 *
 * Pure module: from a provider's `GET /api/oauth/{provider}/status` answer
 * it decides what the Tools page offers (`providerState`, `serviceState`,
 * `canConnect`, `canDisconnect`), and from the org's residency flag which
 * Organization-console switches are locked (`isResidencyLocked`). Nothing
 * here touches the network or the DOM — see `stores/connections.ts` and
 * `stores/orgServices.ts` for the stateful wiring.
 *
 * Security notes: everything fails closed. A service is only "active" when
 * its `enabled` flag is the literal boolean `true` — any other value (a
 * string, a number, an object, `undefined`) is treated as org-disabled.
 * `oauthCallbackMessageKey` only ever resolves a reason through
 * `Object.hasOwn`, so a crafted reason (including a prototype-chain name
 * like `__proto__` or `toString`) can never resolve to an inherited
 * property instead of falling back to the "unexpected" key.
 */
import type { MessageKey } from '@/i18n';
import type { ConnectorTool, OAuthConnectionStatus, OAuthProvider, ToolsSettings } from '@/api/types';

/** The OAuth provider -> its tools (the Google/Microsoft "services"), in this order. */
export const PROVIDER_TOOLS: Readonly<Record<OAuthProvider, readonly ConnectorTool[]>> = Object.freeze({
  google: Object.freeze<ConnectorTool[]>(['gmail', 'google_calendar', 'google_drive']),
  microsoft: Object.freeze<ConnectorTool[]>(['outlook', 'outlook_calendar', 'onedrive']),
});

/** The tools an org's data residency policy switches off (both providers' tools). */
export const RESIDENCY_BLOCKED_TOOLS: ReadonlySet<keyof ToolsSettings> = new Set<keyof ToolsSettings>([
  ...PROVIDER_TOOLS.google,
  ...PROVIDER_TOOLS.microsoft,
]);

export type ProviderState = 'connected' | 'not_connected' | 'residency';

/** 'residency' whenever `data_residency`; else 'connected' iff connected AND healthy; else 'not_connected'. */
export function providerState(status: OAuthConnectionStatus): ProviderState {
  if (status.data_residency) return 'residency';
  return status.connected && status.healthy ? 'connected' : 'not_connected';
}

export type ServiceState = 'active' | 'org_disabled' | 'residency' | 'not_connected';

/**
 * residency -> 'residency'; not (connected AND healthy) -> 'not_connected';
 * the tool missing from `services`, or its `enabled` not strictly `true` ->
 * 'org_disabled'; else 'active'.
 */
export function serviceState(status: OAuthConnectionStatus, tool: ConnectorTool): ServiceState {
  if (status.data_residency) return 'residency';
  if (!(status.connected && status.healthy)) return 'not_connected';
  const entry = status.services.find((candidate) => candidate.tool === tool);
  return entry !== undefined && entry.enabled === true ? 'active' : 'org_disabled';
}

const SERVICE_STATE_KEYS: Readonly<Record<ServiceState, MessageKey>> = {
  active: 'toolsPage.service.state.active',
  org_disabled: 'toolsPage.service.state.orgDisabled',
  residency: 'toolsPage.service.state.residency',
  not_connected: 'toolsPage.service.state.notConnected',
};

/** The `toolsPage.service.state.*` catalog key for a service state. */
export function serviceStateKey(state: ServiceState): MessageKey {
  return SERVICE_STATE_KEYS[state];
}

/** No residency AND not (connected AND healthy). */
export function canConnect(status: OAuthConnectionStatus): boolean {
  return !status.data_residency && !(status.connected && status.healthy);
}

/** Connected AND healthy (also under residency, so a kept-but-inactive connection can still be removed). */
export function canDisconnect(status: OAuthConnectionStatus): boolean {
  return status.connected && status.healthy;
}

const CALLBACK_REASON_KEYS: Readonly<Record<string, MessageKey>> = {
  denied: 'toolsPage.oauth.reason.denied',
  invalid_state: 'toolsPage.oauth.reason.invalidState',
  missing_code: 'toolsPage.oauth.reason.missingCode',
  exchange_failed: 'toolsPage.oauth.reason.exchangeFailed',
  forbidden: 'toolsPage.oauth.reason.forbidden',
  residency: 'toolsPage.oauth.reason.residency',
};

/**
 * The six callback reasons map to their `toolsPage.oauth.reason.*` key
 * through own keys only; anything else (null, '', prototype keys such as
 * `__proto__` / `toString`) gives `toolsPage.oauth.reason.unexpected`.
 */
export function oauthCallbackMessageKey(reason: string | null): MessageKey {
  if (reason !== null && Object.hasOwn(CALLBACK_REASON_KEYS, reason)) {
    return CALLBACK_REASON_KEYS[reason];
  }
  return 'toolsPage.oauth.reason.unexpected';
}

/** `dataResidency` AND the tool is one of the six; `memory` is never locked. */
export function isResidencyLocked(tool: keyof ToolsSettings, dataResidency: boolean): boolean {
  return dataResidency && RESIDENCY_BLOCKED_TOOLS.has(tool);
}
