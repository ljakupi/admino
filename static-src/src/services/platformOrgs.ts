/**
 * Platform organizations pure services (issue #168: Platform console UI for
 * the Super Admin).
 *
 * Framework-free logic the Organizations tab, the org detail view and
 * `stores/platformOrgs.ts` / `stores/platformOrgDetail.ts` share: tabs and the
 * `?org=` id guard, status labels, which actions an org or user offers (fail
 * closed), unit conversion (GiB, CHF cents), the create and edit-limits form
 * validation and request building, the error-message mapping and the confirm
 * sheet copy.
 *
 * Security notes: nothing here logs. `platformErrorMessage` never returns the
 * backend's `detail` or the error's `message` (#139 §5): every message comes
 * from the i18n catalogs. Only org and user metadata is handled (operator
 * blindness).
 */
import { ApiError } from '@/api/client';
import { UUID_RE } from '@/api/ids';
import { t, type MessageKey } from '@/i18n';
import { ROLE_LABEL_KEYS, isPlausibleEmail, type ConfirmCopy } from '@/services/orgUsers';
import type {
  OrgStatus,
  PlatformOrg,
  PlatformOrgCreateRequest,
  PlatformOrgLimitsPatch,
  PlatformUser,
  PlatformUserStatus,
} from '@/api/types';

// --- Constants -------------------------------------------------------------------

export const GIB = 1024 ** 3;
export const SEATS_MIN = 1;
export const SEATS_MAX = 100000;
export const STORAGE_GIB_MAX = 8388607;
export const CREATE_DEFAULTS = { seats: 10, budgetChf: '100', storageGib: 10 } as const;

const NAME_MAX = 120;
const NAME_FORBIDDEN_RE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/u;
const CHF_RE = /^(\d{1,10})(?:\.(\d{1,2}))?$/;

// --- Tabs and view -----------------------------------------------------------------

export type PlatformTab = 'orgs' | 'defaults';

/** V1: no models, usage or audit tab. */
export const PLATFORM_TABS: readonly PlatformTab[] = ['orgs', 'defaults'];

/** `'defaults'` only for exactly that string, else `'orgs'`. */
export function platformTabFrom(value: unknown): PlatformTab {
  return value === 'defaults' ? 'defaults' : 'orgs';
}

/** The `?org=` value when it is a UUID string, else `null`. */
export function orgIdFrom(value: unknown): string | null {
  return typeof value === 'string' && UUID_RE.test(value) ? value : null;
}

// --- Labels --------------------------------------------------------------------------

export const ORG_STATUS_LABEL_KEYS: Record<OrgStatus, MessageKey> = {
  active: 'platform.orgs.status.active',
  deactivated: 'platform.orgs.status.deactivated',
  pending_deletion: 'platform.orgs.status.pendingDeletion',
};

/** Shown for a status/role the client doesn't know (server-supplied values are never trusted as map keys). */
const UNKNOWN_LABEL = '\u2014';

function lookupLabel(map: Record<string, MessageKey>, value: unknown): string {
  return typeof value === 'string' && Object.hasOwn(map, value) ? t(map[value]) : UNKNOWN_LABEL;
}

/** Translated org status label; a placeholder for an unknown status. */
export function orgStatusLabel(status: unknown): string {
  return lookupLabel(ORG_STATUS_LABEL_KEYS, status);
}

/** Translated user status label; a placeholder for an unknown status. */
export function userStatusLabel(status: unknown): string {
  return lookupLabel(USER_STATUS_LABEL_KEYS, status);
}

/** Translated member role label; a placeholder for an unknown role. */
export function memberRoleLabel(role: unknown): string {
  return lookupLabel(ROLE_LABEL_KEYS, role);
}

export const USER_STATUS_LABEL_KEYS: Record<PlatformUserStatus, MessageKey> = {
  active: 'platform.users.status.active',
  deactivated: 'platform.users.status.deactivated',
  invited: 'platform.users.status.invited',
};

// --- Actions ---------------------------------------------------------------------------

export type OrgAction =
  | 'editLimits'
  | 'deactivate'
  | 'reactivate'
  | 'scheduleDeletion'
  | 'cancelDeletion'
  | 'residency';

/** The actions an org offers in its status, in display order; an unknown status offers none (fail closed). */
export function orgActions(org: Pick<PlatformOrg, 'status'>): OrgAction[] {
  switch (org.status) {
    case 'active':
      return ['editLimits', 'deactivate', 'scheduleDeletion', 'residency'];
    case 'deactivated':
      return ['editLimits', 'reactivate', 'scheduleDeletion', 'residency'];
    case 'pending_deletion':
      return ['cancelDeletion'];
    default:
      return [];
  }
}

export type UserAction = 'deactivate' | 'reactivate' | 'resetPassword' | 'reinvite';

/** The actions a user offers given the org's status and its users; unknown shapes offer none. */
export function userActions(
  user: PlatformUser,
  org: Pick<PlatformOrg, 'status'>,
  users: readonly PlatformUser[],
): UserAction[] {
  switch (user.status) {
    case 'active':
      return org.status === 'active' ? ['deactivate', 'resetPassword'] : ['deactivate'];
    case 'deactivated':
      return org.status === 'pending_deletion' ? [] : ['reactivate'];
    case 'invited': {
      const hasActiveAdmin = users.some((u) => u.role === 'org_admin' && u.status === 'active');
      return user.role === 'org_admin' && org.status === 'active' && !hasActiveAdmin ? ['reinvite'] : [];
    }
    default:
      return [];
  }
}

// --- Units -------------------------------------------------------------------------------

export function bytesToGib(bytes: number): number {
  return bytes / GIB;
}

export function gibToBytes(gib: number): number {
  return gib * GIB;
}

/** Amount in exact integer cents, or `null` unless the trimmed value is digits with at most two decimals. */
export function parseChf(value: string): number | null {
  const match = CHF_RE.exec(value.trim());
  if (match === null) return null;
  const whole = Number(match[1]);
  const fraction = Number((match[2] ?? '').padEnd(2, '0'));
  return whole * 100 + fraction;
}

/** Cents as a two-decimal string, e.g. 1250 -> "12.50". */
export function toChfString(cents: number): string {
  const whole = Math.floor(cents / 100);
  const fraction = cents % 100;
  return `${whole}.${String(fraction).padStart(2, '0')}`;
}

// --- Forms ---------------------------------------------------------------------------------

export interface OrgLimitsInput {
  seats: number;
  budgetChf: string;
  storageGib: number;
}

export interface OrgCreateInput extends OrgLimitsInput {
  name: string;
  email: string;
}

export type OrgFormField = 'name' | 'email' | 'seats' | 'budgetChf' | 'storageGib';

export type FormErrors = Partial<Record<OrgFormField, string>>;

export type FormResult<T> = { ok: true; value: T } | { ok: false; errors: FormErrors };

function isIntegerIn(value: number, min: number, max: number): boolean {
  return Number.isInteger(value) && value >= min && value <= max;
}

function seatsError(seats: number): string | undefined {
  return isIntegerIn(seats, SEATS_MIN, SEATS_MAX) ? undefined : t('platform.orgs.form.error.seats');
}

function budgetError(budgetChf: string): string | undefined {
  return parseChf(budgetChf) === null ? t('platform.orgs.form.error.budget') : undefined;
}

function storageError(storageGib: number): string | undefined {
  return isIntegerIn(storageGib, 0, STORAGE_GIB_MAX) ? undefined : t('platform.orgs.form.error.storage');
}

function nameError(name: string): string | undefined {
  const trimmed = name.trim();
  const valid = trimmed.length >= 1 && trimmed.length <= NAME_MAX && !NAME_FORBIDDEN_RE.test(trimmed);
  return valid ? undefined : t('platform.orgs.form.error.name');
}

function collect(entries: ReadonlyArray<[OrgFormField, string | undefined]>): FormErrors {
  const errors: FormErrors = {};
  for (const [field, message] of entries) {
    if (message !== undefined) errors[field] = message;
  }
  return errors;
}

/** Validates every field at once and builds the create request (exactly five keys). */
export function buildCreateOrgRequest(input: OrgCreateInput): FormResult<PlatformOrgCreateRequest> {
  const errors = collect([
    ['name', nameError(input.name)],
    ['email', isPlausibleEmail(input.email) ? undefined : t('platform.orgs.form.error.email')],
    ['seats', seatsError(input.seats)],
    ['budgetChf', budgetError(input.budgetChf)],
    ['storageGib', storageError(input.storageGib)],
  ]);
  const cents = parseChf(input.budgetChf);
  if (Object.keys(errors).length > 0 || cents === null) return { ok: false, errors };

  return {
    ok: true,
    value: {
      name: input.name.trim(),
      primary_admin_email: input.email.trim(),
      seats: input.seats,
      monthly_budget_chf: toChfString(cents),
      storage_quota: gibToBytes(input.storageGib),
    },
  };
}

/** The edit-limits form's starting values for an org. */
export function limitsInputFrom(org: PlatformOrg): OrgLimitsInput {
  return {
    seats: org.seats,
    budgetChf: org.monthly_budget_chf,
    storageGib: bytesToGib(org.storage_quota),
  };
}

/** Only the changed limits are validated and sent; `value` is `null` when nothing changed. */
export function buildLimitsPatch(
  org: PlatformOrg,
  input: OrgLimitsInput,
): FormResult<PlatformOrgLimitsPatch | null> {
  const seatsChanged = input.seats !== org.seats;
  const cents = parseChf(input.budgetChf);
  const budgetChanged = cents !== parseChf(org.monthly_budget_chf);
  const storageChanged = gibToBytes(input.storageGib) !== org.storage_quota;

  const errors = collect([
    ['seats', seatsChanged ? seatsError(input.seats) : undefined],
    ['budgetChf', budgetChanged ? budgetError(input.budgetChf) : undefined],
    ['storageGib', storageChanged ? storageError(input.storageGib) : undefined],
  ]);
  if (Object.keys(errors).length > 0) return { ok: false, errors };

  const patch: PlatformOrgLimitsPatch = {};
  if (seatsChanged) patch.seats = input.seats;
  if (budgetChanged && cents !== null) patch.monthly_budget_chf = toChfString(cents);
  if (storageChanged) patch.storage_quota = gibToBytes(input.storageGib);

  return { ok: true, value: Object.keys(patch).length > 0 ? patch : null };
}

// --- Error messages ---------------------------------------------------------------------------

export type ErrorSubject = 'org' | 'user' | 'settings';

/**
 * A translated message for any error these flows can throw. The backend's
 * `detail`/the error's `message` is NEVER returned: only catalog text, chosen
 * by the `ApiError`'s `reason` first, then its `status`.
 */
export function platformErrorMessage(error: unknown, subject: ErrorSubject = 'org'): string {
  if (!(error instanceof ApiError)) {
    return t('platform.error.generic');
  }

  switch (error.reason) {
    case 'email_taken':
      return t('platform.error.emailTaken');
    case 'seat_limit':
      return t('platform.error.seatLimit');
    case 'invalid_status':
      return subject === 'user' ? t('platform.error.userInvalidStatus') : t('platform.error.orgInvalidStatus');
    case 'last_admin':
      return t('platform.error.lastAdmin');
    case 'has_active_admin':
      return t('platform.error.hasActiveAdmin');
    case 'residency_confirmation':
      return t('platform.error.residencyConfirmation');
    default:
      break;
  }

  switch (error.status) {
    case 404:
      if (subject === 'user') return t('platform.error.userNotFound');
      return subject === 'org' ? t('platform.error.orgNotFound') : t('platform.error.generic');
    case 400:
    case 422:
      return t('platform.error.invalidInput');
    case 429:
      return t('platform.error.rateLimited');
    case 403:
      return t('platform.error.forbidden');
    default:
      return t('platform.error.generic');
  }
}

// --- Confirm sheet copy ------------------------------------------------------------------------

export type OrgConfirmKind =
  | 'deactivate'
  | 'reactivate'
  | 'scheduleDeletion'
  | 'cancelDeletion'
  | 'residencyOn'
  | 'residencyOff';

const ORG_DESTRUCTIVE: ReadonlySet<OrgConfirmKind> = new Set(['deactivate', 'scheduleDeletion', 'residencyOff']);

/** Confirm copy for an org action; `orgName` is substituted literally for `{name}`. */
export function orgConfirmCopy(kind: OrgConfirmKind, orgName: string): ConfirmCopy {
  const params = { name: orgName };
  return {
    heading: t(`platform.orgs.confirm.${kind}.heading` as MessageKey, params),
    subtext: t(`platform.orgs.confirm.${kind}.subtext` as MessageKey, params),
    confirmLabel: t(`platform.orgs.confirm.${kind}.confirm` as MessageKey, params),
    destructive: ORG_DESTRUCTIVE.has(kind),
  };
}

export type UserConfirmKind = 'deactivate' | 'reactivate' | 'resetPassword';

/** Confirm copy for a user action; `subject` is substituted literally for `{name}`. */
export function userConfirmCopy(kind: UserConfirmKind, subject: string): ConfirmCopy {
  const params = { name: subject };
  return {
    heading: t(`platform.users.confirm.${kind}.heading` as MessageKey, params),
    subtext: t(`platform.users.confirm.${kind}.subtext` as MessageKey, params),
    confirmLabel: t(`platform.users.confirm.${kind}.confirm` as MessageKey, params),
    destructive: kind === 'deactivate',
  };
}
