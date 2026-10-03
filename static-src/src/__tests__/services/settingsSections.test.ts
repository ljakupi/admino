/**
 * Settings sections service tests (issue #166: account self-service; the
 * Super Admin gets the Settings area, showing only the account sections).
 *
 * `@/services/settingsSections` is pure: it decides which sections the
 * Settings page offers for a shell role, in display order.
 * - `settingsSectionsFor(role)`: members (Org Admin, Editor, Viewer) get
 *   account, session, appearance, notifications, about, danger; the Super
 *   Admin gets account and about only (no per-user chat settings, no
 *   "Reset my settings"); logged out (`null`) gets nothing. An unknown role
 *   (including prototype keys) gets nothing and never throws.
 * - `defaultSettingsSection(role, hash)`: '#danger' opens the danger zone
 *   when the role has it; '#account' opens the account section; any other
 *   hash opens the first allowed section (the account); `null` when the role
 *   has no section at all.
 *
 * No component is mounted; only the returned data is asserted.
 */
import { describe, it, expect } from 'vitest';
import { defaultSettingsSection, settingsSectionsFor } from '@/services/settingsSections';
import type { ShellRole } from '@/services/access';

const MEMBER_SECTIONS = ['account', 'session', 'appearance', 'notifications', 'about', 'danger'];

describe('settingsSections settingsSectionsFor', () => {
  it.each(['org_admin', 'editor', 'viewer'] as ShellRole[])('gives a member (%s) every section, in order', (role) => {
    expect(settingsSectionsFor(role)).toEqual(MEMBER_SECTIONS);
  });

  it('gives the Super Admin only the account and about sections', () => {
    expect(settingsSectionsFor('super_admin')).toEqual(['account', 'about']);
  });

  it('gives a logged-out user (null) no section', () => {
    expect(settingsSectionsFor(null)).toEqual([]);
  });

  it.each(['owner', '__proto__', 'constructor', 'toString', 'Super_Admin'])(
    'gives the unknown role %j no section without throwing',
    (role) => {
      expect(settingsSectionsFor(role as ShellRole)).toEqual([]);
    },
  );

  it('never offers the Super Admin the per-user settings or the danger zone', () => {
    const sections: string[] = settingsSectionsFor('super_admin');

    expect(['session', 'appearance', 'notifications', 'danger'].filter((id) => sections.includes(id))).toEqual([]);
  });
});

describe('settingsSections defaultSettingsSection', () => {
  it.each([
    ['org_admin', '#danger', 'danger'],
    ['editor', '#danger', 'danger'],
    ['viewer', '#danger', 'danger'],
    ['editor', '#account', 'account'],
    ['super_admin', '#account', 'account'],
    ['editor', '', 'account'],
    ['viewer', '#', 'account'],
    ['super_admin', '', 'account'],
    ['super_admin', '#danger', 'account'],
    ['editor', '#danger-zone', 'account'],
    ['editor', '#session', 'account'],
    ['org_admin', '#unknown', 'account'],
  ] as Array<[ShellRole, string, string]>)('opens %s with hash %j on %s', (role, hash, expected) => {
    expect(defaultSettingsSection(role, hash)).toBe(expected);
  });

  it.each(['', '#account', '#danger'])('opens nothing for a logged-out user (null) with hash %j', (hash) => {
    expect(defaultSettingsSection(null, hash)).toBeNull();
  });

  it('opens nothing for an unknown role', () => {
    expect(defaultSettingsSection('owner' as ShellRole, '#account')).toBeNull();
  });
});
