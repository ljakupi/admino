/**
 * My account service tests (issue #166: account self-service, the profile,
 * languages, timezone, personal instructions, password change and the
 * session list).
 *
 * `@/services/account` is pure logic (no store, no fetch) behind the account
 * section of Settings:
 * - Constants: `DEFAULT_TIMEZONE` 'Europe/Zurich', `PERSONAL_INSTRUCTIONS_MAX`
 *   1500, `NAME_MAX` 120 (code points, like the backend's `len()`).
 * - `browserTimezone()`: `Intl.DateTimeFormat().resolvedOptions().timeZone`,
 *   falling back to 'Europe/Zurich' when it is empty/undefined or throws.
 * - `timezoneOptions(current)`: `Intl.supportedValuesOf('timeZone')` when
 *   the runtime has it (else nothing), plus `current` (when not null) and
 *   'Europe/Zurich', deduplicated and sorted with `localeCompare`.
 * - `codePointLength(text)` / `instructionsRemaining(text)`: an emoji counts
 *   as one; remaining = 1500 - code points (negative when over).
 * - `RESPONSE_LANGUAGE_OPTIONS` and `to/fromResponseLanguageChoice`: `null`
 *   (the org default) is the 'org_default' choice.
 * - `draftFrom(account)`: the editable fields (null name -> '', null
 *   timezone -> 'Europe/Zurich').
 * - `validateDraft(draft)`: 'name_required' (trimmed name empty),
 *   'name_too_long' (> 120 code points after trim), 'instructions_too_long'
 *   (> 1500 code points, never trimmed), in that order.
 * - `accountPatch(saved, draft)`: only the changed fields (name compared and
 *   sent trimmed; instructions sent as typed; `response_language: null` when
 *   switched to the org default; a saved `timezone: null` always differs);
 *   `null` when nothing changed; never `ui_language` or `email`.
 * - `describeUserAgent(ua)`: browser/OS of a real browser UA, the trimmed UA
 *   text (cut to 80 code points + '…') for a non-browser agent, or unknown.
 * - `sortSessions(list)`: current first, then most recently seen first; a
 *   new array (the input is not mutated).
 * - `passwordChangeMessageKey(err)` / `accountSaveMessageKey(err)`: catalog
 *   keys for a failed password change / profile save.
 * - `showsChatPreferences(me)`: response language and personal instructions
 *   are for members only (hidden for the Super Admin and when logged out).
 *
 * `Intl` is spied on or stubbed per test (auto-restored); nothing touches
 * the network and no component is mounted.
 */
import { describe, it, expect, vi } from 'vitest';
import { ApiError } from '@/api/client';
import type { MeResponse, MyAccount, SessionSummary } from '@/api/types';
import { setLocale, t } from '@/i18n';
import { en } from '@/i18n/locales/en';
import {
  DEFAULT_TIMEZONE,
  NAME_MAX,
  PERSONAL_INSTRUCTIONS_MAX,
  RESPONSE_LANGUAGE_OPTIONS,
  accountMessageParams,
  accountPatch,
  accountSaveMessageKey,
  browserTimezone,
  codePointLength,
  describeUserAgent,
  draftFrom,
  fromResponseLanguageChoice,
  instructionsRemaining,
  passwordChangeMessageKey,
  showsChatPreferences,
  sortSessions,
  timezoneOptions,
  toResponseLanguageChoice,
  validateDraft,
} from '@/services/account';
import { policyMessageKey } from '@/services/passwordPolicy';

type AccountDraft = ReturnType<typeof draftFrom>;

const SAVED: MyAccount = {
  email: 'alice@example.ch',
  name: 'Alice Muster',
  ui_language: 'de',
  response_language: 'fr',
  timezone: 'Europe/Zurich',
  personal_instructions: 'Sign off with Grüsse',
};

const SMILE = String.fromCodePoint(0x1f600);
const ROBOT = String.fromCodePoint(0x1f916);
const ELLIPSIS = '…';

/** A copy of the real resolved options with `timeZone` replaced. */
function resolvedWith(timeZone: string | undefined): Intl.ResolvedDateTimeFormatOptions {
  return { ...new Intl.DateTimeFormat().resolvedOptions(), timeZone: timeZone as string };
}

/** Replaces the global `Intl` with a copy whose own properties are overridden (or removed with `undefined`). */
function stubIntl(overrides: Record<string, unknown>): void {
  const copy: Record<string, unknown> = {};
  for (const name of Object.getOwnPropertyNames(Intl)) {
    copy[name] = (Intl as unknown as Record<string, unknown>)[name];
  }
  for (const [name, value] of Object.entries(overrides)) {
    if (value === undefined) delete copy[name];
    else copy[name] = value;
  }
  vi.stubGlobal('Intl', copy);
}

function member(role: 'org_admin' | 'editor' | 'viewer'): MeResponse {
  return {
    user_id: '0b9f6c1e-3a52-4c1d-9a8e-5f2d7c3b1a90',
    kind: 'member',
    org_id: '7d3e2f10-6b4a-4e8c-8f1d-2a9b0c5e6d71',
    role,
    ui_language: 'en',
    response_language: null,
  };
}

const SUPER_ADMIN: MeResponse = {
  user_id: '5a1c9e2d-7b3f-4d8a-9c6e-1f0b2a3d4e5f',
  kind: 'super_admin',
  org_id: null,
  role: null,
  ui_language: 'en',
  response_language: null,
};

function apiError(status: number, reason?: string): ApiError {
  return new ApiError(status, 'Status', `Backend detail ${status}.`, reason);
}

// --- Constants ------------------------------------------------------------

describe('account constants', () => {
  it('pins the default timezone and the two limits', () => {
    expect({ DEFAULT_TIMEZONE, PERSONAL_INSTRUCTIONS_MAX, NAME_MAX }).toEqual({
      DEFAULT_TIMEZONE: 'Europe/Zurich',
      PERSONAL_INSTRUCTIONS_MAX: 1500,
      NAME_MAX: 120,
    });
  });
});

// --- browserTimezone ------------------------------------------------------

describe('account browserTimezone', () => {
  it("returns the browser's resolved time zone", () => {
    vi.spyOn(Intl.DateTimeFormat.prototype, 'resolvedOptions').mockReturnValue(resolvedWith('America/New_York'));

    expect(browserTimezone()).toBe('America/New_York');
  });

  it.each([
    ['empty', ''],
    ['undefined', undefined],
  ])('falls back to Europe/Zurich when the resolved zone is %s', (_label, zone) => {
    vi.spyOn(Intl.DateTimeFormat.prototype, 'resolvedOptions').mockReturnValue(resolvedWith(zone));

    expect(browserTimezone()).toBe('Europe/Zurich');
  });

  it('falls back to Europe/Zurich when resolvedOptions() throws', () => {
    vi.spyOn(Intl.DateTimeFormat.prototype, 'resolvedOptions').mockImplementation(() => {
      throw new RangeError('Unsupported time zone');
    });

    expect(browserTimezone()).toBe('Europe/Zurich');
  });

  it('falls back to Europe/Zurich when Intl.DateTimeFormat itself throws', () => {
    stubIntl({
      DateTimeFormat: () => {
        throw new TypeError('Intl.DateTimeFormat is not available');
      },
    });

    expect(browserTimezone()).toBe('Europe/Zurich');
  });
});

// --- timezoneOptions --------------------------------------------------------

describe('account timezoneOptions', () => {
  const SUPPORTED = ['Europe/Berlin', 'Asia/Tokyo', 'America/New_York'];

  it('lists the supported zones plus the current one and Europe/Zurich, sorted', () => {
    vi.spyOn(Intl, 'supportedValuesOf').mockReturnValue([...SUPPORTED]);

    expect(timezoneOptions('Pacific/Auckland')).toEqual([
      'America/New_York',
      'Asia/Tokyo',
      'Europe/Berlin',
      'Europe/Zurich',
      'Pacific/Auckland',
    ]);
  });

  it("asks Intl for the 'timeZone' values", () => {
    const spy = vi.spyOn(Intl, 'supportedValuesOf').mockReturnValue([...SUPPORTED]);

    timezoneOptions(null);

    expect(spy.mock.calls).toEqual([['timeZone']]);
  });

  it('never lists a zone twice (current and Europe/Zurich already supported)', () => {
    vi.spyOn(Intl, 'supportedValuesOf').mockReturnValue([...SUPPORTED, 'Europe/Zurich']);

    expect(timezoneOptions('Asia/Tokyo')).toEqual(['America/New_York', 'Asia/Tokyo', 'Europe/Berlin', 'Europe/Zurich']);
  });

  it('adds a current zone the runtime does not list (e.g. UTC)', () => {
    vi.spyOn(Intl, 'supportedValuesOf').mockReturnValue([...SUPPORTED]);

    expect(timezoneOptions('UTC')).toContain('UTC');
  });

  it('adds only Europe/Zurich for a null current zone (no "null" entry)', () => {
    vi.spyOn(Intl, 'supportedValuesOf').mockReturnValue([...SUPPORTED]);

    expect(timezoneOptions(null)).toEqual(['America/New_York', 'Asia/Tokyo', 'Europe/Berlin', 'Europe/Zurich']);
  });

  it('sorts with localeCompare, not by UTF-16 code units', () => {
    vi.spyOn(Intl, 'supportedValuesOf').mockReturnValue([
      'America/Porto_Velho',
      'Etc/GMT+5',
      'America/Port-au-Prince',
      'Etc/GMT-5',
      'America/Port_of_Spain',
    ]);

    const expected = [
      'America/Port-au-Prince',
      'America/Port_of_Spain',
      'America/Porto_Velho',
      'Etc/GMT+5',
      'Etc/GMT-5',
      'Europe/Zurich',
    ].sort((a, b) => a.localeCompare(b));
    expect({ result: timezoneOptions(null), differsFromCodeUnitSort: expected.join() !== [...expected].sort().join() }).toEqual({
      result: expected,
      differsFromCodeUnitSort: true,
    });
  });

  it('without Intl.supportedValuesOf lists just the current zone and Europe/Zurich', () => {
    stubIntl({ supportedValuesOf: undefined });

    expect(timezoneOptions('Asia/Tokyo')).toEqual(['Asia/Tokyo', 'Europe/Zurich']);
  });

  it('without Intl.supportedValuesOf and a null current zone lists only Europe/Zurich', () => {
    stubIntl({ supportedValuesOf: undefined });

    expect(timezoneOptions(null)).toEqual(['Europe/Zurich']);
  });

  it('does not mutate the array Intl returned', () => {
    const supported = ['Europe/Berlin', 'Asia/Tokyo'];
    vi.spyOn(Intl, 'supportedValuesOf').mockReturnValue(supported);

    timezoneOptions('Pacific/Auckland');

    expect(supported).toEqual(['Europe/Berlin', 'Asia/Tokyo']);
  });
});

// --- Code points ------------------------------------------------------------

describe('account codePointLength and instructionsRemaining', () => {
  it.each([
    ['empty', '', 0],
    ['ASCII', 'abc', 3],
    ['one emoji', SMILE, 1],
    ['emoji between letters', `a${SMILE}b`, 3],
    ['e + combining accent', 'é', 2],
  ])('codePointLength counts %s as code points', (_label, text, expected) => {
    expect(codePointLength(text)).toBe(expected);
  });

  it.each([
    ['empty', '', 1500],
    ['1500 ASCII characters (the boundary)', 'x'.repeat(1500), 0],
    ['1500 emoji (3000 UTF-16 units)', SMILE.repeat(1500), 0],
    ['1499 emoji', SMILE.repeat(1499), 1],
    ['1501 characters (over)', 'x'.repeat(1501), -1],
    ['1510 emoji (over)', SMILE.repeat(1510), -10],
  ])('instructionsRemaining for %s is %i', (_label, text, expected) => {
    expect(instructionsRemaining(text)).toBe(expected);
  });
});

// --- Response language choice -------------------------------------------------

describe('account response language choice', () => {
  it('offers the org default first, then de, fr, it, en', () => {
    expect([...RESPONSE_LANGUAGE_OPTIONS]).toEqual(['org_default', 'de', 'fr', 'it', 'en']);
  });

  it('maps null (the org default) to the org_default choice and back', () => {
    expect({ to: toResponseLanguageChoice(null), from: fromResponseLanguageChoice('org_default') }).toEqual({
      to: 'org_default',
      from: null,
    });
  });

  it.each(['de', 'fr', 'it', 'en'] as const)('maps the language %s to itself both ways', (lang) => {
    expect({ to: toResponseLanguageChoice(lang), from: fromResponseLanguageChoice(lang) }).toEqual({
      to: lang,
      from: lang,
    });
  });
});

// --- draftFrom ----------------------------------------------------------------

describe('account draftFrom', () => {
  it('copies the editable fields of a saved account', () => {
    expect(draftFrom(SAVED)).toEqual({
      name: 'Alice Muster',
      response_language: 'fr',
      timezone: 'Europe/Zurich',
      personal_instructions: 'Sign off with Grüsse',
    });
  });

  it("turns a null name into '' and a null timezone into Europe/Zurich", () => {
    expect(draftFrom({ ...SAVED, name: null, timezone: null, response_language: null })).toEqual({
      name: '',
      response_language: null,
      timezone: 'Europe/Zurich',
      personal_instructions: 'Sign off with Grüsse',
    });
  });
});

// --- validateDraft ------------------------------------------------------------

describe('account validateDraft', () => {
  const VALID: AccountDraft = {
    name: 'Alice Muster',
    response_language: null,
    timezone: 'Europe/Zurich',
    personal_instructions: 'Be brief.',
  };

  it.each([
    ['a valid draft', {}, []],
    ['an empty name', { name: '' }, ['name_required']],
    ['a whitespace-only name', { name: ' \t\n ' }, ['name_required']],
    ['a 121 code point name', { name: 'x'.repeat(121) }, ['name_too_long']],
    ['a 120 code point name (the boundary)', { name: 'x'.repeat(120) }, []],
    ['a 120 emoji name (240 UTF-16 units)', { name: SMILE.repeat(120) }, []],
    ['a 120 character name padded with spaces (trimmed first)', { name: `  ${'x'.repeat(120)}  ` }, []],
    ['1501 code points of instructions', { personal_instructions: 'x'.repeat(1501) }, ['instructions_too_long']],
    ['1500 code points of instructions (the boundary)', { personal_instructions: 'x'.repeat(1500) }, []],
    ['1500 emoji of instructions', { personal_instructions: SMILE.repeat(1500) }, []],
    ['1500 characters of instructions plus a space (never trimmed)', { personal_instructions: ` ${'x'.repeat(1500)}` }, ['instructions_too_long']],
    ['empty instructions', { personal_instructions: '' }, []],
    ['an empty name and long instructions', { name: '', personal_instructions: 'x'.repeat(1501) }, ['name_required', 'instructions_too_long']],
    ['a long name and long instructions', { name: 'x'.repeat(121), personal_instructions: 'x'.repeat(1501) }, ['name_too_long', 'instructions_too_long']],
  ] as Array<[string, Partial<AccountDraft>, string[]]>)('reports %s as %j', (_label, change, expected) => {
    expect(validateDraft({ ...VALID, ...change })).toEqual(expected);
  });
});

// --- accountPatch ---------------------------------------------------------------

describe('account accountPatch', () => {
  it('returns null when nothing changed', () => {
    expect(accountPatch(SAVED, draftFrom(SAVED))).toBeNull();
  });

  it.each([
    ['a new name', { name: 'Alice Keller' }, { name: 'Alice Keller' }],
    ['a new name with surrounding spaces (sent trimmed)', { name: '  Alice Keller  ' }, { name: 'Alice Keller' }],
    ['a response language', { response_language: 'it' }, { response_language: 'it' }],
    ['the org default response language', { response_language: null }, { response_language: null }],
    ['a timezone', { timezone: 'America/New_York' }, { timezone: 'America/New_York' }],
    ['instructions with surrounding whitespace (sent verbatim)', { personal_instructions: '  Be brief.\n' }, { personal_instructions: '  Be brief.\n' }],
    ['instructions that only gained a trailing space', { personal_instructions: 'Sign off with Grüsse ' }, { personal_instructions: 'Sign off with Grüsse ' }],
    ['cleared instructions', { personal_instructions: '' }, { personal_instructions: '' }],
    [
      'every editable field',
      { name: 'Alice Keller', response_language: 'en', timezone: 'Asia/Tokyo', personal_instructions: 'Formal tone.' },
      { name: 'Alice Keller', response_language: 'en', timezone: 'Asia/Tokyo', personal_instructions: 'Formal tone.' },
    ],
  ] as Array<[string, Partial<AccountDraft>, Record<string, unknown>]>)('sends only %s', (_label, change, expected) => {
    expect(accountPatch(SAVED, { ...draftFrom(SAVED), ...change })).toStrictEqual(expected);
  });

  it('sends response_language: null as an own key when switched to the org default', () => {
    const patch = accountPatch(SAVED, { ...draftFrom(SAVED), response_language: null });

    expect({ hasKey: patch !== null && Object.hasOwn(patch, 'response_language'), value: patch?.response_language }).toEqual({
      hasKey: true,
      value: null,
    });
  });

  it('does not send a name that is unchanged after trimming', () => {
    expect(accountPatch(SAVED, { ...draftFrom(SAVED), name: '  Alice Muster \t' })).toBeNull();
  });

  it('does not send an unchanged org default response language', () => {
    const saved: MyAccount = { ...SAVED, response_language: null };

    expect(accountPatch(saved, draftFrom(saved))).toBeNull();
  });

  it('sends the timezone when the saved one is null, even if the draft shows the Europe/Zurich default', () => {
    const saved: MyAccount = { ...SAVED, timezone: null };

    expect(accountPatch(saved, draftFrom(saved))).toStrictEqual({ timezone: 'Europe/Zurich' });
  });

  it('never includes ui_language or email, even when the draft object carries them', () => {
    const draft = { ...draftFrom(SAVED), name: 'Alice Keller', ui_language: 'en', email: 'mallory@example.ch' } as AccountDraft;

    expect(accountPatch(SAVED, draft)).toStrictEqual({ name: 'Alice Keller' });
  });

  it('does not mutate the saved account or the draft', () => {
    const saved: MyAccount = { ...SAVED };
    const draft: AccountDraft = { ...draftFrom(SAVED), name: '  Alice Keller ', timezone: 'Asia/Tokyo' };
    const draftCopy = { ...draft };

    accountPatch(saved, draft);

    expect({ saved, draft }).toStrictEqual({ saved: SAVED, draft: draftCopy });
  });
});

// --- describeUserAgent ------------------------------------------------------------

describe('account describeUserAgent', () => {
  it.each([
    [
      'Chrome on macOS',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
      'Chrome',
      'macOS',
    ],
    [
      'Safari on macOS',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
      'Safari',
      'macOS',
    ],
    [
      'Safari on iPhone',
      'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
      'Safari',
      'iOS',
    ],
    [
      'Chrome on iPad (CriOS)',
      'Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/129.0.6668.69 Mobile/15E148 Safari/604.1',
      'Chrome',
      'iOS',
    ],
    [
      'Firefox on Windows',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0',
      'Firefox',
      'Windows',
    ],
    [
      'Firefox on Linux',
      'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0',
      'Firefox',
      'Linux',
    ],
    [
      'Firefox on Android',
      'Mozilla/5.0 (Android 14; Mobile; rv:131.0) Gecko/131.0 Firefox/131.0',
      'Firefox',
      'Android',
    ],
    [
      'Edge on Windows',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0',
      'Edge',
      'Windows',
    ],
    [
      'Opera (OPR) on Windows',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 OPR/114.0.0.0',
      'Opera',
      'Windows',
    ],
    [
      'Opera (OPR) on Linux',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 OPR/114.0.0.0',
      'Opera',
      'Linux',
    ],
    ['classic Opera (Presto)', 'Opera/9.80 (Windows NT 6.1; WOW64) Presto/2.12.388 Version/12.18', 'Opera', 'Windows'],
    [
      'Chrome on Android',
      'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36',
      'Chrome',
      'Android',
    ],
    [
      'Chrome on ChromeOS',
      'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
      'Chrome',
      'ChromeOS',
    ],
  ])('recognizes %s', (_label, ua, browser, os) => {
    expect(describeUserAgent(ua)).toStrictEqual({ kind: 'device', browser, os });
  });

  it('reports a known OS with an unknown browser as a device without a browser', () => {
    expect(describeUserAgent('Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/AP2A.240905.003)')).toStrictEqual({
      kind: 'device',
      browser: null,
      os: 'Android',
    });
  });

  it('reports a known browser with an unknown OS as a device without an OS', () => {
    expect(describeUserAgent('Mozilla/5.0 (rv:131.0) Gecko/20100101 Firefox/131.0')).toStrictEqual({
      kind: 'device',
      browser: 'Firefox',
      os: null,
    });
  });

  it('does not call it Safari without a Version/ token (an in-app web view)', () => {
    expect(
      describeUserAgent(
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari/604.1',
      ),
    ).toStrictEqual({ kind: 'device', browser: null, os: 'iOS' });
  });

  it.each([
    ['curl', 'curl/8.5.0'],
    ['python-httpx', 'python-httpx/0.27.0'],
  ])('reports %s as an agent with its own text', (_label, ua) => {
    expect(describeUserAgent(ua)).toStrictEqual({ kind: 'agent', text: ua });
  });

  it('trims the agent text', () => {
    expect(describeUserAgent('  curl/8.5.0 \n')).toStrictEqual({ kind: 'agent', text: 'curl/8.5.0' });
  });

  it("cuts a 200 character unknown agent to 80 code points plus '…'", () => {
    const ua = `acme-monitor/${'z'.repeat(187)}`;

    expect({ length: ua.length, described: describeUserAgent(ua) }).toStrictEqual({
      length: 200,
      described: { kind: 'agent', text: `${ua.slice(0, 80)}${ELLIPSIS}` },
    });
  });

  it('cuts by code points, never in the middle of an emoji', () => {
    const ua = ROBOT.repeat(100);

    expect(describeUserAgent(ua)).toStrictEqual({ kind: 'agent', text: `${ROBOT.repeat(80)}${ELLIPSIS}` });
  });

  it('keeps an agent of exactly 80 code points whole (no ellipsis)', () => {
    const ua = `acme-monitor/${'z'.repeat(67)}`;

    expect({ length: ua.length, described: describeUserAgent(ua) }).toStrictEqual({
      length: 80,
      described: { kind: 'agent', text: ua },
    });
  });

  it.each([
    ['null', null],
    ['empty', ''],
    ['blank', '  \t\n '],
  ])('reports a %s user agent as unknown', (_label, ua) => {
    expect(describeUserAgent(ua)).toStrictEqual({ kind: 'unknown' });
  });
});

// --- sortSessions -----------------------------------------------------------------

describe('account sortSessions', () => {
  function session(id: string, lastSeen: string, current = false): SessionSummary {
    return {
      id,
      created_at: '2026-09-01T08:00:00Z',
      last_seen_at: lastSeen,
      expires_at: '2026-11-01T08:00:00Z',
      ip: null,
      user_agent: null,
      current,
    };
  }

  const OLD = session('11111111-1111-4111-8111-111111111111', '2026-09-20T10:00:00Z');
  const CURRENT = session('22222222-2222-4222-8222-222222222222', '2026-09-25T10:00:00Z', true);
  const NEWEST = session('33333333-3333-4333-8333-333333333333', '2026-10-03T07:00:00Z');
  const MIDDLE = session('44444444-4444-4444-8444-444444444444', '2026-10-01T12:00:00Z');

  it('puts the current session first, then the rest by last seen, newest first', () => {
    expect(sortSessions([OLD, MIDDLE, CURRENT, NEWEST]).map((s) => s.id)).toEqual([
      CURRENT.id,
      NEWEST.id,
      MIDDLE.id,
      OLD.id,
    ]);
  });

  it('compares last seen as instants (a fractional second is later than the whole second)', () => {
    const whole = session('55555555-5555-4555-8555-555555555555', '2026-10-03T08:00:00Z');
    const fraction = session('66666666-6666-4666-8666-666666666666', '2026-10-03T08:00:00.500000Z');

    expect(sortSessions([whole, fraction]).map((s) => s.id)).toEqual([fraction.id, whole.id]);
  });

  it('does not mutate the input and returns a new array', () => {
    const input = [OLD, CURRENT, NEWEST];
    const before = [...input];

    const sorted = sortSessions(input);

    expect({ sameArray: sorted === input, input }).toEqual({ sameArray: false, input: before });
  });

  it('returns [] for no sessions', () => {
    expect(sortSessions([])).toEqual([]);
  });
});

// --- Message keys -------------------------------------------------------------------

describe('account passwordChangeMessageKey', () => {
  it('maps a 403 (wrong current password) to the current-password message', () => {
    expect(passwordChangeMessageKey(apiError(403))).toBe('account.password.error.current');
  });

  it.each([
    ['too_short', 'auth.password.error.tooShort'],
    ['too_long', 'auth.password.error.tooLong'],
    ['common', 'auth.password.error.common'],
    ['equals_email', 'auth.password.error.equalsEmail'],
    ['not_a_known_reason', 'auth.password.error.generic'],
  ])('maps a 422 with reason %s to %s (the password policy message)', (reason, key) => {
    expect({ key: passwordChangeMessageKey(apiError(422, reason)), policy: policyMessageKey(reason) }).toEqual({
      key,
      policy: key,
    });
  });

  it('maps a 422 without a reason to the generic policy message', () => {
    expect(passwordChangeMessageKey(apiError(422))).toBe('auth.password.error.generic');
  });

  it('maps a 429 to the rate-limit message', () => {
    expect(passwordChangeMessageKey(apiError(429))).toBe('auth.error.rateLimited');
  });

  it.each([
    ['a 500', apiError(500)],
    ['a 404', apiError(404)],
    ['a network TypeError', new TypeError('Failed to fetch')],
    ['a plain Error', new Error('boom')],
    ['a string', '403'],
    ['null', null],
  ])('maps %s to the generic message', (_label, err) => {
    expect(passwordChangeMessageKey(err)).toBe('auth.error.generic');
  });
});

describe('account accountSaveMessageKey', () => {
  it.each([
    ['a 422', apiError(422), 'account.error.invalid'],
    ['a 422 with a reason', apiError(422, 'something'), 'account.error.invalid'],
    ['a 429', apiError(429), 'auth.error.rateLimited'],
    ['a 403', apiError(403), 'account.error.generic'],
    ['a 404', apiError(404), 'account.error.generic'],
    ['a 500', apiError(500), 'account.error.generic'],
    ['a network TypeError', new TypeError('Failed to fetch'), 'account.error.generic'],
    ['undefined', undefined, 'account.error.generic'],
  ])('maps %s to %s', (_label, err, key) => {
    expect(accountSaveMessageKey(err)).toBe(key);
  });
});

describe('account message keys exist', () => {
  it('every key the two mappers return is in the en catalog', () => {
    const errors: unknown[] = [
      apiError(403),
      apiError(404),
      apiError(422),
      apiError(422, 'too_short'),
      apiError(422, 'common'),
      apiError(429),
      apiError(500),
      new TypeError('Failed to fetch'),
    ];
    const keys = new Set(errors.flatMap((err) => [passwordChangeMessageKey(err), accountSaveMessageKey(err)]));

    expect([...keys].filter((key) => !Object.hasOwn(en, key))).toEqual([]);
  });
});

// --- showsChatPreferences -----------------------------------------------------------

describe('account showsChatPreferences', () => {
  it.each(['org_admin', 'editor', 'viewer'] as const)('shows the chat preferences to a member (%s)', (role) => {
    expect(showsChatPreferences(member(role))).toBe(true);
  });

  it('hides them from the Super Admin', () => {
    expect(showsChatPreferences(SUPER_ADMIN)).toBe(false);
  });

  it('hides them when logged out (null)', () => {
    expect(showsChatPreferences(null)).toBe(false);
  });
});

describe('accountMessageParams (security audit follow-up: the {max} placeholders get their limit)', () => {
  it('gives the name limit to the name-too-long message', () => {
    expect(accountMessageParams('account.error.nameTooLong')).toEqual({ max: NAME_MAX });
  });

  it('gives the instructions limit to the instructions-too-long message', () => {
    expect(accountMessageParams('account.error.instructionsTooLong')).toEqual({ max: PERSONAL_INSTRUCTIONS_MAX });
  });

  it('gives no parameters to any other message', () => {
    expect(accountMessageParams('account.error.nameRequired')).toEqual({});
    expect(accountMessageParams('account.password.error.current')).toEqual({});
    expect(accountMessageParams('auth.error.generic')).toEqual({});
  });

  it.each(['en', 'de', 'fr'] as const)('leaves no {max} placeholder in the rendered %s messages', (lang) => {
    setLocale(lang);
    try {
      const name = t('account.error.nameTooLong', accountMessageParams('account.error.nameTooLong'));
      const instructions = t(
        'account.error.instructionsTooLong',
        accountMessageParams('account.error.instructionsTooLong'),
      );
      expect(name).not.toContain('{max}');
      expect(name).toContain('120');
      expect(instructions).not.toContain('{max}');
      expect(instructions).toContain('1500');
    } finally {
      setLocale('en');
    }
  });
});
