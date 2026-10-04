/**
 * Organization settings logic (issue #169): draft handling, validation, patch
 * building and error mapping for the Organization -> Settings tab.
 *
 * Pure and framework-free. Error messages are catalog keys only; the server's
 * detail is never shown. Lengths count code points, as the backend does.
 * Also formats the validation issue texts (with their bounds) and the plan
 * storage label so the panel only binds them.
 */
import { ApiError } from '@/api/client';
import { formatNumber, t, type MessageKey } from '@/i18n';
import type { OrgSettingsPatch, OrgSettingsResponse, ResponseLanguage } from '@/api/types';

export const ORG_NAME_MAX = 120;
export const ORG_INSTRUCTIONS_MAX = 8000;
export const IDLE_TIMEOUT_MIN = 15;
export const IDLE_TIMEOUT_MAX = 480;
export const LIFETIME_MIN = 1;
export const LIFETIME_MAX = 72;
export const RESPONSE_LANGUAGES: readonly ResponseLanguage[] = ['de', 'fr', 'it', 'en'];

export interface OrgSettingsDraft {
  display_name: string;
  default_response_language: ResponseLanguage;
  instructions: string;
  session_idle_timeout_minutes: number;
  session_max_lifetime_hours: number;
  trash_retention_days: number;
}

export type OrgSettingsIssue =
  | 'name_required'
  | 'name_too_long'
  | 'instructions_too_long'
  | 'idle_timeout_range'
  | 'lifetime_range'
  | 'trash_retention_range';

export function draftFrom(settings: OrgSettingsResponse): OrgSettingsDraft {
  return {
    display_name: settings.profile.display_name,
    default_response_language: settings.profile.default_response_language,
    instructions: settings.instructions,
    session_idle_timeout_minutes: settings.security.session_idle_timeout_minutes,
    session_max_lifetime_hours: settings.security.session_max_lifetime_hours,
    trash_retention_days: settings.retention.trash_retention_days,
  };
}

function codePoints(text: string): number {
  return Array.from(text).length;
}

function intWithin(value: number, min: number, max: number): boolean {
  return Number.isInteger(value) && value >= min && value <= max;
}

export function validateOrgSettingsDraft(
  draft: OrgSettingsDraft,
  settings: OrgSettingsResponse,
): OrgSettingsIssue[] {
  const issues: OrgSettingsIssue[] = [];
  const name = draft.display_name.trim();
  if (name === '') issues.push('name_required');
  if (codePoints(name) > ORG_NAME_MAX) issues.push('name_too_long');
  if (codePoints(draft.instructions) > ORG_INSTRUCTIONS_MAX) issues.push('instructions_too_long');
  if (!intWithin(draft.session_idle_timeout_minutes, IDLE_TIMEOUT_MIN, IDLE_TIMEOUT_MAX)) {
    issues.push('idle_timeout_range');
  }
  if (!intWithin(draft.session_max_lifetime_hours, LIFETIME_MIN, LIFETIME_MAX)) {
    issues.push('lifetime_range');
  }
  if (
    !intWithin(
      draft.trash_retention_days,
      settings.retention.trash_min_days,
      settings.retention.trash_max_days,
    )
  ) {
    issues.push('trash_retention_range');
  }
  return issues;
}

export function instructionsRemaining(text: string): number {
  return ORG_INSTRUCTIONS_MAX - codePoints(text);
}

/** Only the changed fields; `null` when nothing changed. Never tools, residency, plan or bounds. */
export function buildOrgSettingsPatch(
  settings: OrgSettingsResponse,
  draft: OrgSettingsDraft,
): OrgSettingsPatch | null {
  const patch: OrgSettingsPatch = {};

  const profile: NonNullable<OrgSettingsPatch['profile']> = {};
  const name = draft.display_name.trim();
  if (name !== settings.profile.display_name) profile.display_name = name;
  if (draft.default_response_language !== settings.profile.default_response_language) {
    profile.default_response_language = draft.default_response_language;
  }
  if (Object.keys(profile).length > 0) patch.profile = profile;

  if (draft.instructions !== settings.instructions) patch.instructions = draft.instructions;

  const security: NonNullable<OrgSettingsPatch['security']> = {};
  if (draft.session_idle_timeout_minutes !== settings.security.session_idle_timeout_minutes) {
    security.session_idle_timeout_minutes = draft.session_idle_timeout_minutes;
  }
  if (draft.session_max_lifetime_hours !== settings.security.session_max_lifetime_hours) {
    security.session_max_lifetime_hours = draft.session_max_lifetime_hours;
  }
  if (Object.keys(security).length > 0) patch.security = security;

  if (draft.trash_retention_days !== settings.retention.trash_retention_days) {
    patch.retention = { trash_retention_days: draft.trash_retention_days };
  }

  return Object.keys(patch).length > 0 ? patch : null;
}

export const ORG_SETTINGS_ISSUE_KEYS: Record<OrgSettingsIssue, MessageKey> = {
  name_required: 'organization.settings.issue.nameRequired',
  name_too_long: 'organization.settings.issue.nameTooLong',
  instructions_too_long: 'organization.settings.issue.instructionsTooLong',
  idle_timeout_range: 'organization.settings.issue.idleTimeoutRange',
  lifetime_range: 'organization.settings.issue.lifetimeRange',
  trash_retention_range: 'organization.settings.issue.trashRetentionRange',
};

/** Catalog text for a failed load/save; never the server's detail or the error message. */
export function orgSettingsErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.reason === 'trash_retention_bounds') return t('organization.settings.error.trashBounds');
    if (error.status === 400 || error.status === 422) return t('organization.settings.error.invalid');
    if (error.status === 403) return t('organization.settings.error.forbidden');
    if (error.status === 429) return t('organization.settings.error.rateLimited');
  }
  return t('organization.settings.error.generic');
}

/** Localised text for a validation issue, with the bounds it names. */
export function orgSettingsIssueText(
  issue: OrgSettingsIssue,
  settings: OrgSettingsResponse | null,
): string {
  const key = ORG_SETTINGS_ISSUE_KEYS[issue];
  switch (issue) {
    case 'name_too_long':
      return t(key, { max: ORG_NAME_MAX });
    case 'instructions_too_long':
      return t(key, { max: ORG_INSTRUCTIONS_MAX });
    case 'idle_timeout_range':
      return t(key, { min: IDLE_TIMEOUT_MIN, max: IDLE_TIMEOUT_MAX });
    case 'lifetime_range':
      return t(key, { min: LIFETIME_MIN, max: LIFETIME_MAX });
    case 'trash_retention_range':
      return t(key, {
        min: settings?.retention.trash_min_days ?? 0,
        max: settings?.retention.trash_max_days ?? 90,
      });
    default:
      return t(key);
  }
}

/** Plan storage line, e.g. "Storage: 10 GiB" (bytes rounded to one decimal GiB). */
export function planStorageLabel(storageQuotaBytes: number): string {
  const size = `${formatNumber(storageQuotaBytes / 1024 ** 3, { maximumFractionDigits: 1 })} GiB`;
  return t('organization.settings.data.storage', { size });
}
