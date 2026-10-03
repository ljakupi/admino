/**
 * Settings sections service (issue #166: account self-service; the Super
 * Admin gets the Settings area, showing only the account sections).
 *
 * Pure: decides which sections `SettingsPage` offers for a shell role, in
 * display order, and which one opens by default for a given URL hash.
 */
import type { ShellRole } from './access';

export type SettingsSectionId = 'account' | 'session' | 'appearance' | 'notifications' | 'about' | 'danger';

const MEMBER_SECTIONS: readonly SettingsSectionId[] = [
  'account',
  'session',
  'appearance',
  'notifications',
  'about',
  'danger',
];

const SUPER_ADMIN_SECTIONS: readonly SettingsSectionId[] = ['account', 'about'];

const MEMBER_ROLES: readonly ShellRole[] = ['org_admin', 'editor', 'viewer'];

/** The sections `role` may see, in a fixed order. Logged out (`null`) or an unknown role sees nothing. */
export function settingsSectionsFor(role: ShellRole | null): SettingsSectionId[] {
  if (role === 'super_admin') return [...SUPER_ADMIN_SECTIONS];
  if (role !== null && MEMBER_ROLES.includes(role)) return [...MEMBER_SECTIONS];
  return [];
}

/** Which section opens for `role` given the URL `hash`; `null` when the role has no section at all. */
export function defaultSettingsSection(role: ShellRole | null, hash: string): SettingsSectionId | null {
  const allowed = settingsSectionsFor(role);
  if (allowed.length === 0) return null;
  if (hash === '#danger' && allowed.includes('danger')) return 'danger';
  if (hash === '#account' && allowed.includes('account')) return 'account';
  return allowed[0];
}
