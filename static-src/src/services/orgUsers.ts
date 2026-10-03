/**
 * Org users pure services (issue #165: Organization console, users and
 * invitations UI).
 *
 * Framework-free logic the Users tab and `stores/orgUsers.ts` share, so it
 * stays unit-testable without mounting anything: role/status vocabularies and
 * their guards, the directory search/filter, seat usage and display text, a
 * client-side mirror of the invitation email rule, the profile-patch diff,
 * the error-message mapping (#139 §5: a backend error's `detail` is never
 * shown — every message here comes from the i18n catalogs) and the confirm
 * sheet copy for every row action.
 *
 * Security notes: nothing here logs, and `orgUserErrorMessage` never returns
 * the backend's `detail`/the error's `message`, however the error was shaped.
 */
import { ApiError } from '@/api/client';
import { t, type MessageKey, type Params } from '@/i18n';
import type { MemberRole, OrgInvitation, OrgSeats, OrgUser, OrgUserPatch } from '@/api/types';

// --- Roles ------------------------------------------------------------------

/** Offered in the invite and role-change UI. Viewer is kept by the API and `access.py`, never offered here in V1. */
export const ASSIGNABLE_ROLES: readonly MemberRole[] = ['org_admin', 'editor'];

const ASSIGNABLE_ROLE_SET: ReadonlySet<string> = new Set(ASSIGNABLE_ROLES);

/** True for exactly `'org_admin'` and `'editor'`; anything else (Viewer, unknown strings, non-strings) is false. */
export function isAssignableRole(role: unknown): role is MemberRole {
  return typeof role === 'string' && ASSIGNABLE_ROLE_SET.has(role);
}

/** Every member role's existing `auth.role.*` catalog key. */
export const ROLE_LABEL_KEYS: Record<MemberRole, MessageKey> = {
  org_admin: 'auth.role.orgAdmin',
  editor: 'auth.role.editor',
  viewer: 'auth.role.viewer',
};

// --- Status filters -----------------------------------------------------------

export type StatusFilter = 'all' | 'active' | 'deactivated' | 'invited';

export const STATUS_FILTERS: readonly StatusFilter[] = ['all', 'active', 'deactivated', 'invited'];

const STATUS_FILTER_SET: ReadonlySet<string> = new Set(STATUS_FILTERS);

export function isStatusFilter(value: unknown): value is StatusFilter {
  return typeof value === 'string' && STATUS_FILTER_SET.has(value);
}

export interface DirectoryFilter {
  query: string;
  status: StatusFilter;
}

/**
 * Users matching `filter`, in input order. `status: 'invited'` never matches
 * a user. Otherwise the query (trimmed, case-insensitive, a literal
 * substring — never a regex) matches the name (a `null` name never matches)
 * or the email; the role, status and id are never searched.
 */
export function filterUsers(users: readonly OrgUser[], filter: DirectoryFilter): OrgUser[] {
  if (filter.status === 'invited') return [];
  const query = filter.query.trim().toLowerCase();
  return users.filter((user) => {
    if (filter.status !== 'all' && user.status !== filter.status) return false;
    if (query === '') return true;
    const nameMatches = user.name !== null && user.name.toLowerCase().includes(query);
    return nameMatches || user.email.toLowerCase().includes(query);
  });
}

/**
 * Invitations matching `filter`, in input order. `status: 'active'` and
 * `'deactivated'` never match an invitation. Otherwise the query matches the
 * invitation's email only (never the role, the id or the expiry).
 */
export function filterInvitations(
  invitations: readonly OrgInvitation[],
  filter: DirectoryFilter,
): OrgInvitation[] {
  if (filter.status === 'active' || filter.status === 'deactivated') return [];
  const query = filter.query.trim().toLowerCase();
  return invitations.filter((invitation) => invitation.email.toLowerCase().includes(query));
}

// --- Seats and display ----------------------------------------------------------

/** "{used} / {limit} seats" (en); `null` seat usage (not loaded yet) reads as `null`, never a placeholder. */
export function seatLabel(seats: OrgSeats | null): string | null {
  return seats === null ? null : t('orgUsers.seats', { used: seats.used, limit: seats.limit });
}

/** True when the org has no free seat left; unknown seat usage is never reported full. */
export function seatsFull(seats: OrgSeats | null): boolean {
  return seats !== null && seats.used >= seats.limit;
}

/** The trimmed name, or the email when the user has none (or only whitespace). */
export function displayName(user: Pick<OrgUser, 'name' | 'email'>): string {
  const trimmed = user.name?.trim() ?? '';
  return trimmed !== '' ? trimmed : user.email;
}

// --- Email plausibility -----------------------------------------------------------

// Whitespace, plus the Unicode categories the backend refuses in an invite email:
// control (Cc), format (Cf: zero-width, direction overrides), line and paragraph
// separators (Zl, Zp) and lone surrogates (Cs).
const EMAIL_FORBIDDEN_RE = /[\s\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/u;

/**
 * Client-side mirror of the backend's invite email rule (the backend stays
 * authoritative): trimmed, 3–254 characters, no whitespace/control/zero-width
 * character inside, exactly one `@` with a non-empty local part, and a `.`
 * inside the domain that is neither its first nor its last character.
 */
export function isPlausibleEmail(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 3 || trimmed.length > 254) return false;
  if (EMAIL_FORBIDDEN_RE.test(trimmed)) return false;

  const at = trimmed.indexOf('@');
  if (at <= 0) return false;
  if (trimmed.indexOf('@', at + 1) !== -1) return false;

  const domain = trimmed.slice(at + 1);
  if (domain === '') return false;
  const dot = domain.indexOf('.');
  return dot > 0 && dot < domain.length - 1;
}

// --- Profile patch ------------------------------------------------------------------

/**
 * Only the name/email fields that actually changed (trimmed, compared with
 * the stored values); an empty trimmed name is never a change (a name is
 * never cleared this way). The email is compared exactly after trimming, so
 * a capitalization-only change still counts. `null` when nothing changed.
 */
export function buildProfilePatch(
  user: OrgUser,
  input: { name: string; email: string },
): OrgUserPatch | null {
  const patch: OrgUserPatch = {};

  const trimmedName = input.name.trim();
  if (trimmedName !== '' && trimmedName !== (user.name ?? '')) {
    patch.name = trimmedName;
  }

  const trimmedEmail = input.email.trim();
  if (trimmedEmail !== user.email) {
    patch.email = trimmedEmail;
  }

  return Object.keys(patch).length > 0 ? patch : null;
}

// --- Error messages -----------------------------------------------------------------

export type ErrorSubject = 'user' | 'invitation';

/**
 * A translated message for any error these flows can throw. The backend's
 * `detail`/the error's `message` is NEVER returned (#139 §5: error responses
 * are never echoed) — only catalog text, chosen by the `ApiError`'s `reason`
 * first, then its `status`, falling back to a generic message for anything
 * else (another ApiError shape, a plain Error, a network failure, a
 * non-Error rejection).
 */
export function orgUserErrorMessage(error: unknown, subject: ErrorSubject = 'user'): string {
  if (!(error instanceof ApiError)) {
    return t('orgUsers.error.generic');
  }

  switch (error.reason) {
    case 'last_admin':
      return t('orgUsers.error.lastAdmin');
    case 'email_taken':
      return t('orgUsers.error.emailTaken');
    case 'seat_limit':
      return t('orgUsers.error.seatLimit');
    case 'invalid_status':
      return t('orgUsers.error.invalidStatus');
    default:
      break;
  }

  switch (error.status) {
    case 404:
      return subject === 'invitation' ? t('orgUsers.error.invitationNotFound') : t('orgUsers.error.userNotFound');
    case 422:
      return t('orgUsers.error.invalidInput');
    case 429:
      return t('orgUsers.error.rateLimited');
    case 403:
      return t('orgUsers.error.forbidden');
    default:
      return t('orgUsers.error.generic');
  }
}

// --- Tabs ------------------------------------------------------------------------------

export type OrgTab = 'users' | 'permissions';

/** The `?tab=` query value mapped to a tab: `'permissions'` only for exactly that string, else `'users'`. */
export function orgTabFrom(value: unknown): OrgTab {
  return value === 'permissions' ? 'permissions' : 'users';
}

// --- Confirm sheet copy ----------------------------------------------------------------

export type PendingKind =
  | 'role'
  | 'deactivate'
  | 'reactivate'
  | 'resetPassword'
  | 'forceLogout'
  | 'delete'
  | 'revokeInvitation';

export interface ConfirmCopy {
  heading: string;
  subtext: string;
  confirmLabel: string;
  destructive: boolean;
}

/** `orgUsers.confirm.<segment>.*` catalog segment for each pending kind (`revokeInvitation` -> `revoke`). */
const CONFIRM_SEGMENT: Record<PendingKind, string> = {
  role: 'role',
  deactivate: 'deactivate',
  reactivate: 'reactivate',
  resetPassword: 'resetPassword',
  forceLogout: 'forceLogout',
  delete: 'delete',
  revokeInvitation: 'revoke',
};

const DESTRUCTIVE_KINDS: ReadonlySet<PendingKind> = new Set([
  'deactivate',
  'forceLogout',
  'delete',
  'revokeInvitation',
]);

/**
 * The confirm sheet copy for a pending action. `subject` is substituted
 * literally for `{name}` (never re-expanded, never treated as a `$`-pattern);
 * `role` (the new role, for `'role'` only) fills `{role}` with its label.
 * When `isSelf` (acting on your own account), the subtext gets the
 * self-warning appended after a single space.
 */
export function confirmCopy(
  kind: PendingKind,
  subject: string,
  opts: { role?: MemberRole; isSelf?: boolean } = {},
): ConfirmCopy {
  const segment = CONFIRM_SEGMENT[kind];
  const params: Params = { name: subject };
  if (opts.role !== undefined) {
    params.role = t(ROLE_LABEL_KEYS[opts.role]);
  }

  const heading = t(`orgUsers.confirm.${segment}.heading` as MessageKey, params);
  const confirmLabel = t(`orgUsers.confirm.${segment}.confirm` as MessageKey, params);
  const baseSubtext = t(`orgUsers.confirm.${segment}.subtext` as MessageKey, params);
  const subtext = opts.isSelf ? `${baseSubtext} ${t('orgUsers.confirm.selfWarning')}` : baseSubtext;

  return { heading, subtext, confirmLabel, destructive: DESTRUCTIVE_KINDS.has(kind) };
}
