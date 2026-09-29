/**
 * Password policy service (issue #155: password fields show the policy
 * requirements).
 *
 * Mirrors the backend policy (`passwords.py`) for instant feedback on the
 * Reset password and Accept invitation pages; the backend stays
 * authoritative (the common-password list is a server-only check, so
 * `'common'` only ever comes back as a 422 `reason`, never from
 * `checkNewPassword`).
 */
import type { MessageKey } from '@/i18n';

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

export type PasswordIssue = 'too_short' | 'too_long' | 'equals_email' | 'mismatch';

/** Unicode code-point count, like Python's `len()` — an emoji is one character, a combining accent is its own. */
function codePointLength(value: string): number {
  return Array.from(value).length;
}

/** `password` (never trimmed) equals `email` (trimmed), ignoring case; never matches a blank email. */
function equalsEmail(password: string, email: string): boolean {
  const trimmedEmail = email.trim().toLowerCase();
  return trimmedEmail !== '' && password.toLowerCase() === trimmedEmail;
}

/** Problems with `password`/`confirm` for `email`, in the fixed order too_short, too_long, equals_email, mismatch. */
export function checkNewPassword(password: string, confirm: string, email: string): PasswordIssue[] {
  const issues: PasswordIssue[] = [];
  const length = codePointLength(password);
  if (length < PASSWORD_MIN_LENGTH) {
    issues.push('too_short');
  } else if (length > PASSWORD_MAX_LENGTH) {
    issues.push('too_long');
  }
  if (equalsEmail(password, email)) issues.push('equals_email');
  if (password !== confirm) issues.push('mismatch');
  return issues;
}

const POLICY_KEY_MAP: Record<string, MessageKey> = {
  too_short: 'auth.password.error.tooShort',
  too_long: 'auth.password.error.tooLong',
  common: 'auth.password.error.common',
  equals_email: 'auth.password.error.equalsEmail',
};

/** Maps the backend's 422 `reason` to a catalog key; anything unknown (prototype keys included) is the generic key. */
export function policyMessageKey(reason: string | undefined): MessageKey {
  if (reason !== undefined && Object.hasOwn(POLICY_KEY_MAP, reason)) {
    return POLICY_KEY_MAP[reason];
  }
  return 'auth.password.error.generic';
}

const ISSUE_KEY_MAP: Record<PasswordIssue, MessageKey> = {
  too_short: 'auth.password.error.tooShort',
  too_long: 'auth.password.error.tooLong',
  equals_email: 'auth.password.error.equalsEmail',
  mismatch: 'auth.password.error.mismatch',
};

/** Maps a client-side `PasswordIssue` to its catalog key. */
export function issueMessageKey(issue: PasswordIssue): MessageKey {
  return ISSUE_KEY_MAP[issue];
}

/** The requirement texts the password fields show; the length rule takes `{min}` and `{max}`. */
export const PASSWORD_RULE_KEYS: readonly MessageKey[] = [
  'auth.password.rule.length',
  'auth.password.rule.common',
  'auth.password.rule.email',
];
