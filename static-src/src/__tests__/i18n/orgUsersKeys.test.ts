/**
 * Catalog keys for the Organization console's Users tab (issue #165: users
 * and invitations UI; all strings go through the i18n catalogs with en/de/fr
 * entries, #139 §5).
 *
 * Every key the Users tab, its sheets, the confirm copy, the error mapping
 * and the store's toasts use must exist in the `en` source catalog with a
 * non-blank value and have its own non-blank `de` and `fr` entry (never
 * falling back to English or to the raw key). The placeholders are exactly
 * the contract's: `orgUsers.seats` {used} {limit} (en: "{used} / {limit}
 * seats"), `orgUsers.lastLogin` / `orgUsers.invitations.sent` /
 * `orgUsers.invitations.expires` {date}, `orgUsers.actions.menu` {name},
 * `orgUsers.confirm.role.subtext` {name} {role}, the deactivate / reactivate
 * / forceLogout / delete headings {name}, the resetPassword / revoke
 * subtexts {name}; every other new key has none. A de/fr value never equals
 * the en value of a sentence (no English fallback), nor the en seat label.
 * The eleven error messages are distinct in each locale so the user can tell
 * them apart, and the en last-admin message says an organization needs at
 * least one active Org Admin and to make another user an Org Admin first.
 *
 * Kept: `organization.empty.heading|subtext` (the non-admin fallback still
 * uses them).
 *
 * The key lists are pinned from the GH-165 contract (§2e) rather than read
 * from `@/services/orgUsers`, so this file runs on its own;
 * `services/orgUsers.test.ts` cross-checks the strings the functions return.
 * Key-set and placeholder parity between catalogs is also enforced by
 * `catalogs.test.ts` and `npm run check:i18n`. No component is mounted.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { setLocale, t, type MessageKey } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';

type CatalogLocale = 'en' | 'de' | 'fr';

const CATALOGS: Record<CatalogLocale, Record<string, unknown>> = { en, de, fr };
const LOCALES: readonly CatalogLocale[] = ['en', 'de', 'fr'];
const TRANSLATIONS: readonly CatalogLocale[] = ['de', 'fr'];
const PLACEHOLDER = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

const PAGE_KEYS: readonly string[] = [
  'organization.tabs.users',
  'organization.tabs.permissions',
  'orgUsers.title',
  'orgUsers.search.label',
  'orgUsers.search.placeholder',
  'orgUsers.filter.label',
  'orgUsers.filter.all',
  'orgUsers.filter.active',
  'orgUsers.filter.deactivated',
  'orgUsers.filter.invited',
  'orgUsers.seats',
  'orgUsers.seatsFull',
  'orgUsers.status.active',
  'orgUsers.status.deactivated',
  'orgUsers.status.invited',
  'orgUsers.status.expired',
  'orgUsers.you',
  'orgUsers.lastLogin',
  'orgUsers.neverLoggedIn',
  'orgUsers.invitations.title',
  'orgUsers.invitations.sent',
  'orgUsers.invitations.expires',
  'orgUsers.empty.users',
  'orgUsers.empty.invitations',
  'orgUsers.actions.menu',
  'orgUsers.actions.changeRole',
  'orgUsers.actions.edit',
  'orgUsers.actions.deactivate',
  'orgUsers.actions.reactivate',
  'orgUsers.actions.resetPassword',
  'orgUsers.actions.forceLogout',
  'orgUsers.actions.delete',
  'orgUsers.actions.resend',
  'orgUsers.actions.revoke',
];

const INVITE_KEYS: readonly string[] = [
  'orgUsers.invite.button',
  'orgUsers.invite.heading',
  'orgUsers.invite.email.label',
  'orgUsers.invite.role.label',
  'orgUsers.invite.submit',
];

const EDIT_KEYS: readonly string[] = [
  'orgUsers.edit.heading',
  'orgUsers.edit.name.label',
  'orgUsers.edit.email.label',
  'orgUsers.edit.emailHint',
  'orgUsers.edit.submit',
];

const CONFIRM_SEGMENTS: readonly string[] = [
  'role',
  'deactivate',
  'reactivate',
  'resetPassword',
  'forceLogout',
  'delete',
  'revoke',
];

const CONFIRM_KEYS: readonly string[] = [
  ...CONFIRM_SEGMENTS.flatMap((segment) =>
    ['heading', 'subtext', 'confirm'].map((part) => `orgUsers.confirm.${segment}.${part}`),
  ),
  'orgUsers.confirm.selfWarning',
];

const ERROR_KEYS: readonly string[] = [
  'orgUsers.error.lastAdmin',
  'orgUsers.error.emailTaken',
  'orgUsers.error.seatLimit',
  'orgUsers.error.invalidStatus',
  'orgUsers.error.userNotFound',
  'orgUsers.error.invitationNotFound',
  'orgUsers.error.invalidInput',
  'orgUsers.error.invalidEmail',
  'orgUsers.error.rateLimited',
  'orgUsers.error.forbidden',
  'orgUsers.error.generic',
];

const TOAST_KEYS: readonly string[] = [
  'toast.orgUsers.invited',
  'toast.orgUsers.roleChanged',
  'toast.orgUsers.profileSaved',
  'toast.orgUsers.deactivated',
  'toast.orgUsers.reactivated',
  'toast.orgUsers.deleted',
  'toast.orgUsers.passwordResetSent',
  'toast.orgUsers.loggedOut',
  'toast.orgUsers.invitationResent',
  'toast.orgUsers.invitationRevoked',
  'toast.orgUsers.failed',
];

const NEW_KEYS: readonly string[] = [
  ...PAGE_KEYS,
  ...INVITE_KEYS,
  ...EDIT_KEYS,
  ...CONFIRM_KEYS,
  ...ERROR_KEYS,
  ...TOAST_KEYS,
];

/** Still used by the non-admin fallback of the Organization page. */
const KEPT_KEYS: readonly string[] = ['organization.empty.heading', 'organization.empty.subtext'];

/** The only new keys with placeholders (sorted names); every other new key has none. */
const PLACEHOLDERS: Readonly<Record<string, readonly string[]>> = {
  'orgUsers.seats': ['limit', 'used'],
  'orgUsers.lastLogin': ['date'],
  'orgUsers.invitations.sent': ['date'],
  'orgUsers.invitations.expires': ['date'],
  'orgUsers.actions.menu': ['name'],
  'orgUsers.confirm.role.subtext': ['name', 'role'],
  'orgUsers.confirm.deactivate.heading': ['name'],
  'orgUsers.confirm.reactivate.heading': ['name'],
  'orgUsers.confirm.resetPassword.subtext': ['name'],
  'orgUsers.confirm.forceLogout.heading': ['name'],
  'orgUsers.confirm.delete.heading': ['name'],
  'orgUsers.confirm.revoke.subtext': ['name'],
};

/** True when the catalog has its own non-blank string for `key`. */
function hasText(catalog: Record<string, unknown>, key: string): boolean {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  return typeof value === 'string' && value.trim() !== '';
}

/** The catalog's own string for `key`, or undefined. */
function textOf(catalog: Record<string, unknown>, key: string): string | undefined {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  return typeof value === 'string' ? value : undefined;
}

/** Sorted placeholder names of a catalog value (`null` when the key has no string). */
function placeholdersOf(catalog: Record<string, unknown>, key: string): string[] | null {
  const value = textOf(catalog, key);
  if (value === undefined) return null;
  return [...new Set([...value.matchAll(PLACEHOLDER)].map((match) => match[1]))].sort();
}

/** A sentence: at least three words (placeholders and punctuation-only tokens aside), or end punctuation. */
function isSentence(text: string): boolean {
  const words = text
    .replace(PLACEHOLDER, ' ')
    .trim()
    .split(/\s+/)
    .filter((token) => /\p{L}/u.test(token));
  return words.length >= 3 || /[.!?…]$/.test(text.trim());
}

beforeEach(() => {
  setLocale('en');
});

afterEach(() => {
  setLocale('en');
});

describe('i18n org users keys added by issue #165', () => {
  it.each(LOCALES)('gives every new key (and the kept organization.empty.* keys) its own non-blank %s entry', (target) => {
    expect([...NEW_KEYS, ...KEPT_KEYS].filter((key) => !hasText(CATALOGS[target], key))).toEqual([]);
  });

  it.each(TRANSLATIONS)('resolves every new key under %s to a translation, not the key', (target) => {
    setLocale(target);

    const unresolved = NEW_KEYS.filter((key) => {
      const text = t(key as MessageKey);
      return text === key || text.trim() === '';
    });

    expect(unresolved).toEqual([]);
  });

  it.each(LOCALES)('%s uses exactly the contract placeholders for every new key', (target) => {
    const actual = Object.fromEntries(NEW_KEYS.map((key) => [key, placeholdersOf(CATALOGS[target], key)]));
    const wanted = Object.fromEntries(NEW_KEYS.map((key) => [key, [...(PLACEHOLDERS[key] ?? [])]]));

    expect(actual).toEqual(wanted);
  });

  it('the en seat label is "{used} / {limit} seats"', () => {
    expect(textOf(en, 'orgUsers.seats')).toBe('{used} / {limit} seats');
  });

  it.each(TRANSLATIONS)('%s translates every en sentence and the seat label (no English fallback)', (target) => {
    const catalog = CATALOGS[target];
    const untranslated = NEW_KEYS.filter((key) => {
      const source = textOf(en, key);
      const translated = textOf(catalog, key);
      if (source === undefined || translated === undefined || source.trim() === '' || translated.trim() === '') {
        return true;
      }
      const mustDiffer = isSentence(source) || key === 'orgUsers.seats';
      return mustDiffer && translated.trim() === source.trim();
    });

    expect(untranslated).toEqual([]);
  });

  it('test setup: the en catalog has sentences among the new keys (the fallback check is not vacuous)', () => {
    const sentences = NEW_KEYS.filter((key) => {
      const source = textOf(en, key);
      return source !== undefined && isSentence(source);
    });

    expect(sentences.length).toBeGreaterThanOrEqual(ERROR_KEYS.length);
  });

  it.each(LOCALES)('the eleven error messages are distinct in %s', (target) => {
    const values = ERROR_KEYS.map((key) => textOf(CATALOGS[target], key));

    expect({
      allText: values.every((value) => typeof value === 'string' && value.trim() !== ''),
      distinct: new Set(values.map((value) => value?.trim())).size,
    }).toEqual({ allText: true, distinct: ERROR_KEYS.length });
  });

  it('the en last-admin message asks to keep an active Org Admin and to promote another user first', () => {
    const text = textOf(en, 'orgUsers.error.lastAdmin') ?? '';

    expect({
      needsOne: /at least one active Org Admin/i.test(text),
      promoteFirst: /another\b.*\bOrg Admin\b.*\bfirst\b/i.test(text),
    }).toEqual({ needsOne: true, promoteFirst: true });
  });

  it('the en self warning and the selfWarning-free subtexts are distinct sentences', () => {
    const warning = textOf(en, 'orgUsers.confirm.selfWarning');
    const subtexts = CONFIRM_SEGMENTS.map((segment) => textOf(en, `orgUsers.confirm.${segment}.subtext`));

    expect({
      warningIsSentence: warning !== undefined && isSentence(warning),
      warningIsNotASubtext: warning !== undefined && !subtexts.includes(warning),
    }).toEqual({ warningIsSentence: true, warningIsNotASubtext: true });
  });
});
