/**
 * Emailed-link token tests (issue #155: Reset password and Accept invitation
 * pages, opened from `{public_url}/reset-password#token=<token>` and
 * `{public_url}/accept-invitation#token=<token>`).
 *
 * The token sits in the URL fragment, so it never reaches a server log or a
 * Referer header. `readLinkToken(hash)` parses the fragment (one leading '#'
 * stripped) as URL search params and returns `token` only when it has the
 * shape the backend issues (`secrets.token_urlsafe(32)`, accepted range
 * 16 to 128 characters of `[A-Za-z0-9_-]`). `consumeLinkToken(location,
 * history)` reads it and, whenever there is a fragment, replaces the history
 * entry with the same path and query minus the fragment, so the token leaves
 * the address bar and the history, even when it is invalid.
 *
 * `location` and `history` are passed in as plain objects; the real
 * `window.history` is never touched.
 */
import { describe, it, expect, vi, type Mock } from 'vitest';
import { consumeLinkToken, readLinkToken } from '@/services/linkToken';

/** Shape of `secrets.token_urlsafe(32)`: 43 characters of [A-Za-z0-9_-]. */
const TOKEN = 'k3Jd8_Xq-2mPz7Lw9vRt4NcY6hBf1GsQa5EuWo0TiZy';

type ReplaceState = (data: unknown, unused: string, url?: string | URL | null) => void;

function fakeHistory(): { replaceState: Mock<ReplaceState> } {
  return { replaceState: vi.fn<ReplaceState>() };
}

describe('linkToken readLinkToken', () => {
  it.each([
    ['a fragment with the token', `#token=${TOKEN}`],
    ['a fragment with the token and another param', `#token=${TOKEN}&x=1`],
    ['a fragment with another param first', `#x=1&token=${TOKEN}`],
    ['no leading #', `token=${TOKEN}`],
  ])('returns the token from %s', (_label, hash) => {
    expect(readLinkToken(hash)).toBe(TOKEN);
  });

  it.each([16, 128])('accepts a %i-character token', (length) => {
    const token = 'aB3_-'.repeat(30).slice(0, length);

    expect(readLinkToken(`#token=${token}`)).toBe(token);
  });

  it.each([
    ['an empty string', ''],
    ['a bare #', '#'],
    ['an empty token', '#token='],
    ['no token param', '#foo=bar'],
    ['a short token', '#token=short'],
    ['a 15-character token', `#token=${'a'.repeat(15)}`],
    ['a 129-character token', `#token=${'a'.repeat(129)}`],
    ['an encoded space', '#token=abcdefgh%20ijklmnop'],
    ['a plus (decoded to a space)', '#token=abcdefgh+ijklmnop'],
    ['markup', '#token=<script>alert(1)</script>'],
    ['an encoded NUL', `#token=${TOKEN}%00`],
    ['a dot segment', '#token=../../../api/settings'],
    ['a doubled #', `##token=${TOKEN}`],
    ['a token param with another name case', `#Token=${TOKEN}`],
  ])('returns null for %s', (_label, hash) => {
    expect(readLinkToken(hash)).toBeNull();
  });
});

describe('linkToken consumeLinkToken', () => {
  it('returns the token and strips the fragment from the address bar', () => {
    const history = fakeHistory();

    const token = consumeLinkToken(
      { hash: `#token=${TOKEN}`, pathname: '/reset-password', search: '' },
      history,
    );

    expect({ token, calls: history.replaceState.mock.calls }).toEqual({
      token: TOKEN,
      calls: [[null, '', '/reset-password']],
    });
  });

  it('keeps the path and query when it strips the fragment', () => {
    const history = fakeHistory();

    consumeLinkToken({ hash: `#token=${TOKEN}`, pathname: '/accept-invitation', search: '?lang=de' }, history);

    expect(history.replaceState.mock.calls).toEqual([[null, '', '/accept-invitation?lang=de']]);
  });

  it('strips the fragment even when the token is invalid, and returns null', () => {
    const history = fakeHistory();

    const token = consumeLinkToken(
      { hash: '#token=<script>', pathname: '/accept-invitation', search: '' },
      history,
    );

    expect({ token, calls: history.replaceState.mock.calls }).toEqual({
      token: null,
      calls: [[null, '', '/accept-invitation']],
    });
  });

  it('strips a bare # too', () => {
    const history = fakeHistory();

    consumeLinkToken({ hash: '#', pathname: '/reset-password', search: '' }, history);

    expect(history.replaceState).toHaveBeenCalledTimes(1);
  });

  it('leaves the history alone and returns null when there is no fragment', () => {
    const history = fakeHistory();

    const token = consumeLinkToken({ hash: '', pathname: '/reset-password', search: '?x=1' }, history);

    expect({ token, calls: history.replaceState.mock.calls.length }).toEqual({ token: null, calls: 0 });
  });

  it('uses the history it is given, never window.history', () => {
    const windowReplace = vi.spyOn(window.history, 'replaceState');
    const history = fakeHistory();

    consumeLinkToken({ hash: `#token=${TOKEN}`, pathname: '/reset-password', search: '' }, history);

    expect({ given: history.replaceState.mock.calls.length, window: windowReplace.mock.calls.length }).toEqual({
      given: 1,
      window: 0,
    });
  });
});
