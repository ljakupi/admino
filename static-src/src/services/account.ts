/**
 * My account service (issue #166: account self-service — profile, languages,
 * timezone, personal instructions, password change, sessions).
 *
 * Pure logic behind the "My account" settings section: no store, no fetch.
 * Mirrors the backend's limits (code-point counts, like Python's `len()`)
 * for instant feedback; the backend stays authoritative.
 */
import { ApiError } from '@/api/client';
import { policyMessageKey } from './passwordPolicy';
import type { MessageKey } from '@/i18n';
import type { MeResponse, MyAccount, MyAccountPatch, ResponseLanguage, SessionSummary } from '@/api/types';

export const DEFAULT_TIMEZONE = 'Europe/Zurich';
export const PERSONAL_INSTRUCTIONS_MAX = 1500;
export const NAME_MAX = 120;

/** The browser's resolved IANA time zone, falling back to {@link DEFAULT_TIMEZONE}. */
export function browserTimezone(): string {
  try {
    const zone = new Intl.DateTimeFormat().resolvedOptions().timeZone;
    return zone ? zone : DEFAULT_TIMEZONE;
  } catch {
    return DEFAULT_TIMEZONE;
  }
}

/** Every zone the runtime supports (when it can tell us), plus `current` and the default, deduplicated and sorted. */
export function timezoneOptions(current: string | null): string[] {
  const supported =
    typeof Intl.supportedValuesOf === 'function' ? [...Intl.supportedValuesOf('timeZone')] : [];
  const zones = new Set(supported);
  zones.add(DEFAULT_TIMEZONE);
  if (current !== null) zones.add(current);
  return [...zones].sort((a, b) => a.localeCompare(b));
}

/** Unicode code-point count, like Python's `len()` — an emoji is one character, a combining accent is its own. */
export function codePointLength(text: string): number {
  return Array.from(text).length;
}

/** How many code points remain of {@link PERSONAL_INSTRUCTIONS_MAX} (may go negative when over). */
export function instructionsRemaining(text: string): number {
  return PERSONAL_INSTRUCTIONS_MAX - codePointLength(text);
}

export const RESPONSE_LANGUAGE_OPTIONS = ['org_default', 'de', 'fr', 'it', 'en'] as const;
export type ResponseLanguageChoice = (typeof RESPONSE_LANGUAGE_OPTIONS)[number];

/** `null` (the org default) maps to the 'org_default' choice; a language maps to itself. */
export function toResponseLanguageChoice(value: ResponseLanguage | null): ResponseLanguageChoice {
  return value === null ? 'org_default' : value;
}

/** The inverse of {@link toResponseLanguageChoice}. */
export function fromResponseLanguageChoice(choice: ResponseLanguageChoice): ResponseLanguage | null {
  return choice === 'org_default' ? null : choice;
}

/** The editable fields of a saved account, as the profile form holds them. */
export interface AccountDraft {
  name: string;
  response_language: ResponseLanguage | null;
  timezone: string;
  personal_instructions: string;
}

/** `account` -> an editable draft: a `null` name becomes `''`, a `null` timezone becomes {@link DEFAULT_TIMEZONE}. */
export function draftFrom(account: MyAccount): AccountDraft {
  return {
    name: account.name ?? '',
    response_language: account.response_language,
    timezone: account.timezone ?? DEFAULT_TIMEZONE,
    personal_instructions: account.personal_instructions,
  };
}

export type AccountDraftIssue = 'name_required' | 'name_too_long' | 'instructions_too_long';

/** Validation issues for `draft`, in a fixed order: name_required, name_too_long, instructions_too_long. */
export function validateDraft(draft: AccountDraft): AccountDraftIssue[] {
  const issues: AccountDraftIssue[] = [];
  const trimmedName = draft.name.trim();
  if (trimmedName === '') {
    issues.push('name_required');
  } else if (codePointLength(trimmedName) > NAME_MAX) {
    issues.push('name_too_long');
  }
  if (codePointLength(draft.personal_instructions) > PERSONAL_INSTRUCTIONS_MAX) {
    issues.push('instructions_too_long');
  }
  return issues;
}

/**
 * Only the fields of `draft` that differ from `saved` (name compared and
 * sent trimmed; personal instructions sent as typed; `response_language:
 * null` when switched to the org default; a saved `timezone: null` always
 * differs from the draft's default). `null` when nothing changed.
 * `ui_language` and `email` are never part of it, even if present on `draft`.
 */
export function accountPatch(saved: MyAccount, draft: AccountDraft): MyAccountPatch | null {
  const patch: MyAccountPatch = {};

  const trimmedName = draft.name.trim();
  if (trimmedName !== (saved.name ?? '')) patch.name = trimmedName;

  if (draft.response_language !== saved.response_language) patch.response_language = draft.response_language;

  if (draft.timezone !== saved.timezone) patch.timezone = draft.timezone;

  if (draft.personal_instructions !== saved.personal_instructions) {
    patch.personal_instructions = draft.personal_instructions;
  }

  return Object.keys(patch).length > 0 ? patch : null;
}

export type UserAgentDescription =
  | { kind: 'device'; browser: string | null; os: string | null }
  | { kind: 'agent'; text: string }
  | { kind: 'unknown' };

const AGENT_TEXT_MAX = 80;

function detectBrowser(ua: string): string | null {
  if (ua.includes('Edg/')) return 'Edge';
  if (ua.includes('OPR/') || ua.includes('Opera')) return 'Opera';
  if (ua.includes('Firefox/')) return 'Firefox';
  if (ua.includes('Chrome/') || ua.includes('CriOS/')) return 'Chrome';
  if (ua.includes('Safari/') && ua.includes('Version/')) return 'Safari';
  return null;
}

function detectOs(ua: string): string | null {
  if (ua.includes('iPhone') || ua.includes('iPad') || ua.includes('iPod')) return 'iOS';
  if (ua.includes('Android')) return 'Android';
  if (ua.includes('CrOS')) return 'ChromeOS';
  if (ua.includes('Windows')) return 'Windows';
  if (ua.includes('Mac OS X') || ua.includes('Macintosh')) return 'macOS';
  if (ua.includes('Linux')) return 'Linux';
  return null;
}

/** Cuts `text` to {@link AGENT_TEXT_MAX} code points, adding '…' when it was longer; never splits an emoji. */
function cutAgentText(text: string): string {
  const codePoints = Array.from(text);
  return codePoints.length <= AGENT_TEXT_MAX ? text : `${codePoints.slice(0, AGENT_TEXT_MAX).join('')}…`;
}

/**
 * Browser/OS of a real browser's user agent, the trimmed text of a
 * non-browser agent (curl, a monitoring bot, …) cut to 80 code points, or
 * unknown for a null/blank one.
 */
export function describeUserAgent(ua: string | null): UserAgentDescription {
  if (ua === null) return { kind: 'unknown' };
  const trimmed = ua.trim();
  if (trimmed === '') return { kind: 'unknown' };

  const browser = detectBrowser(trimmed);
  const os = detectOs(trimmed);
  if (browser !== null || os !== null) return { kind: 'device', browser, os };
  return { kind: 'agent', text: cutAgentText(trimmed) };
}

/** `list`, sorted current session first, then by last seen (most recent first); a new array. */
export function sortSessions(list: readonly SessionSummary[]): SessionSummary[] {
  return [...list].sort((a, b) => {
    if (a.current !== b.current) return a.current ? -1 : 1;
    return new Date(b.last_seen_at).getTime() - new Date(a.last_seen_at).getTime();
  });
}

/** Catalog key for a failed password change: wrong current password, policy, rate limit, or generic. */
export function passwordChangeMessageKey(err: unknown): MessageKey {
  if (err instanceof ApiError) {
    if (err.status === 403) return 'account.password.error.current';
    if (err.status === 422) return policyMessageKey(err.reason);
    if (err.status === 429) return 'auth.error.rateLimited';
  }
  return 'auth.error.generic';
}

const MESSAGE_PARAMS: Partial<Record<MessageKey, Record<string, number>>> = {
  'account.error.nameTooLong': { max: NAME_MAX },
  'account.error.instructionsTooLong': { max: PERSONAL_INSTRUCTIONS_MAX },
};

/** The values a message's placeholders take (the `{max}` limits); none for any other key. */
export function accountMessageParams(key: MessageKey): Record<string, number> {
  return MESSAGE_PARAMS[key] ?? {};
}

/** Catalog key for a failed profile save: invalid input, rate limit, or generic. */
export function accountSaveMessageKey(err: unknown): MessageKey {
  if (err instanceof ApiError) {
    if (err.status === 422) return 'account.error.invalid';
    if (err.status === 429) return 'auth.error.rateLimited';
  }
  return 'account.error.generic';
}

/** Response language and personal instructions are for members only — hidden for the Super Admin and when logged out. */
export function showsChatPreferences(me: MeResponse | null): boolean {
  return me !== null && me.kind === 'member';
}
