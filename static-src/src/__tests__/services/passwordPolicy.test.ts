/**
 * Password policy service tests (issue #155: "password fields show the
 * policy requirements").
 *
 * `@/services/passwordPolicy` mirrors the backend policy (`passwords.py`)
 * for instant feedback on the Reset password and Accept invitation pages;
 * the backend stays authoritative (the common-password list is a
 * server-only check):
 *
 * - `PASSWORD_MIN_LENGTH` 12 and `PASSWORD_MAX_LENGTH` 128, counted in
 *   Unicode code points like Python's `len()` (an emoji is one character,
 *   not two UTF-16 units; a combining accent is its own character).
 * - `checkNewPassword(password, confirm, email)` lists the problems in the
 *   fixed order too_short, too_long, equals_email, mismatch.
 * - `policyMessageKey(reason)` maps the backend's 422 `reason` to a catalog
 *   key (anything unknown, prototype keys included, is the generic key), and
 *   `issueMessageKey(issue)` maps a client-side issue to its key.
 * - `PASSWORD_RULE_KEYS` lists the requirement texts the fields show; the
 *   length rule takes `{min}` and `{max}`.
 *
 * Every key resolves in en, de and fr.
 */
import { describe, it, expect, afterEach } from 'vitest';
import {
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  PASSWORD_RULE_KEYS,
  checkNewPassword,
  issueMessageKey,
  policyMessageKey,
  type PasswordIssue,
} from '@/services/passwordPolicy';
import { setLocale, t, type MessageKey } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';

const EMAIL = 'alice@example.ch';
const EMOJI = String.fromCodePoint(0x1f600);
const COMBINING_ACUTE = String.fromCharCode(0x0301);

/** Checks `password` against a matching confirmation and an unrelated email. */
function issuesOf(password: string): PasswordIssue[] {
  return checkNewPassword(password, password, EMAIL);
}

afterEach(() => {
  setLocale('en');
});

describe('passwordPolicy limits', () => {
  it('matches the backend: 12 to 128 characters', () => {
    expect([PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH]).toEqual([12, 128]);
  });
});

describe('passwordPolicy checkNewPassword length', () => {
  it.each([
    ['empty', '', ['too_short']],
    ['11 characters', 'a'.repeat(11), ['too_short']],
    ['12 characters', 'a'.repeat(12), []],
    ['128 characters', 'a'.repeat(128), []],
    ['129 characters', 'a'.repeat(129), ['too_long']],
    ['11 emoji (22 UTF-16 units)', EMOJI.repeat(11), ['too_short']],
    ['12 emoji', EMOJI.repeat(12), []],
    ['65 emoji (130 UTF-16 units, 65 characters)', EMOJI.repeat(65), []],
    ['127 letters and an emoji (128 characters)', `${'a'.repeat(127)}${EMOJI}`, []],
    ['128 letters and an emoji (129 characters)', `${'a'.repeat(128)}${EMOJI}`, ['too_long']],
    ['6 accented letters as base + combining accent (12 code points)', `e${COMBINING_ACUTE}`.repeat(6), []],
    ['5 accented letters and a letter (11 code points)', `${`e${COMBINING_ACUTE}`.repeat(5)}a`, ['too_short']],
  ] as Array<[string, string, PasswordIssue[]]>)('%s gives %j', (_label, password, expected) => {
    expect(issuesOf(password)).toEqual(expected);
  });
});

describe('passwordPolicy checkNewPassword email and confirmation', () => {
  it('accepts a valid, confirmed password', () => {
    expect(checkNewPassword('Plumbago-Lantern-4417', 'Plumbago-Lantern-4417', EMAIL)).toEqual([]);
  });

  it('flags a password equal to the email, ignoring case', () => {
    expect(checkNewPassword('Alice@Example.CH', 'Alice@Example.CH', EMAIL)).toEqual(['equals_email']);
  });

  it('trims the email before comparing', () => {
    expect(checkNewPassword(EMAIL, EMAIL, `  ${EMAIL.toUpperCase()} `)).toEqual(['equals_email']);
  });

  it('does not trim the password before comparing', () => {
    expect(checkNewPassword(` ${EMAIL}`, ` ${EMAIL}`, EMAIL)).toEqual([]);
  });

  it('never matches an empty email', () => {
    expect(checkNewPassword('', '', '')).toEqual(['too_short']);
  });

  it('never matches a whitespace-only email (empty once trimmed)', () => {
    expect(checkNewPassword('', '', '   ')).toEqual(['too_short']);
  });

  it('flags a confirmation that differs', () => {
    expect(checkNewPassword('Plumbago-Lantern-4417', 'Plumbago-Lantern-4418', EMAIL)).toEqual(['mismatch']);
  });

  it('flags a confirmation that differs only in case', () => {
    expect(checkNewPassword('Plumbago-Lantern-4417', 'plumbago-lantern-4417', EMAIL)).toEqual(['mismatch']);
  });

  it('lists too_short, equals_email and mismatch in that order', () => {
    expect(checkNewPassword('a@b.ch', 'x', 'A@B.CH')).toEqual(['too_short', 'equals_email', 'mismatch']);
  });

  it('lists too_long, equals_email and mismatch in that order', () => {
    const longEmail = `${'a'.repeat(125)}@b.ch`;

    expect(checkNewPassword(longEmail, 'different', longEmail)).toEqual(['too_long', 'equals_email', 'mismatch']);
  });
});

describe('passwordPolicy message keys', () => {
  it.each([
    ['too_short', 'auth.password.error.tooShort'],
    ['too_long', 'auth.password.error.tooLong'],
    ['common', 'auth.password.error.common'],
    ['equals_email', 'auth.password.error.equalsEmail'],
  ])('maps the backend reason %s to %s', (reason, key) => {
    expect(policyMessageKey(reason)).toBe(key);
  });

  it.each([
    undefined,
    '',
    'mismatch',
    'unknown_reason',
    'TOO_SHORT',
    'too_short ',
    'constructor',
    '__proto__',
    'toString',
    'hasOwnProperty',
    'valueOf',
  ])('maps the unknown reason %j to the generic key', (reason) => {
    expect(policyMessageKey(reason)).toBe('auth.password.error.generic');
  });

  it.each([
    ['too_short', 'auth.password.error.tooShort'],
    ['too_long', 'auth.password.error.tooLong'],
    ['equals_email', 'auth.password.error.equalsEmail'],
    ['mismatch', 'auth.password.error.mismatch'],
  ] as Array<[PasswordIssue, string]>)('maps the issue %s to %s', (issue, key) => {
    expect(issueMessageKey(issue)).toBe(key);
  });
});

describe('passwordPolicy rule texts', () => {
  it('lists the length, common and email rules', () => {
    expect([...PASSWORD_RULE_KEYS]).toEqual([
      'auth.password.rule.length',
      'auth.password.rule.common',
      'auth.password.rule.email',
    ]);
  });

  it('takes {min} and {max} in the length rule of every catalog', () => {
    const raw = [en, de, fr].map((catalog) => String((catalog as Record<string, unknown>)['auth.password.rule.length']));

    expect(raw.map((text) => text.includes('{min}') && text.includes('{max}'))).toEqual([true, true, true]);
  });

  it.each(['en', 'de', 'fr'])('fills the limits into the length rule under %s', (target) => {
    setLocale(target);

    const text = t('auth.password.rule.length' as MessageKey, { min: PASSWORD_MIN_LENGTH, max: PASSWORD_MAX_LENGTH });

    expect(text.includes('12') && text.includes('128') && !text.includes('{')).toBe(true);
  });
});

describe('passwordPolicy catalog keys', () => {
  const keys: string[] = [
    'auth.password.error.tooShort',
    'auth.password.error.tooLong',
    'auth.password.error.common',
    'auth.password.error.equalsEmail',
    'auth.password.error.mismatch',
    'auth.password.error.generic',
    'auth.password.rule.length',
    'auth.password.rule.common',
    'auth.password.rule.email',
  ];

  it('defines every policy key in the en catalog', () => {
    expect(keys.filter((key) => !Object.hasOwn(en, key))).toEqual([]);
  });

  it.each(['de', 'fr'])('translates every policy key under %s (never the raw key)', (target) => {
    setLocale(target);

    const untranslated = keys.filter((key) => {
      const text = t(key as MessageKey);
      return text === key || text.trim() === '';
    });

    expect(untranslated).toEqual([]);
  });

  it('only produces keys the catalogs define', () => {
    const produced = [
      ...['too_short', 'too_long', 'common', 'equals_email', undefined].map((reason) => policyMessageKey(reason)),
      ...(['too_short', 'too_long', 'equals_email', 'mismatch'] as PasswordIssue[]).map((issue) =>
        issueMessageKey(issue),
      ),
      ...PASSWORD_RULE_KEYS,
    ];

    expect(produced.filter((key) => !Object.hasOwn(en, key))).toEqual([]);
  });
});
