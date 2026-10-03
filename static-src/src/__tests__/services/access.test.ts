/**
 * Shell access policy tests (issue #155: role-aware app shell).
 *
 * `@/services/access` is the pure frontend mirror of the backend access
 * policy (`access.py`), used by the nav and the route guards. The backend
 * stays authoritative; this only decides what the shell offers.
 *
 * - `shellRole(me)` fails closed like the backend's `principal_role`: a
 *   Super Admin only with kind 'super_admin' and no org and no role; a member
 *   role only with kind 'member', a non-empty org id and a known role.
 *   Anything else, including prototype keys as role names, is `null`.
 * - `canAccessArea(role, area)` (issue #161 moves the Org Admin's permission
 *   editing under Organization and gives Editors and Viewers the read-only
 *   Permissions summary; issue #166 gives the Super Admin the Settings area,
 *   showing only the account sections): Super Admin → Platform and
 *   Settings (still no chat UI); Org Admin → Chat,
 *   Tools, Organization, Settings (no Permissions page); Editor → Chat,
 *   Tools, Permissions, Settings; Viewer → Chat, Permissions, Settings;
 *   `null` → nothing. Unknown areas and unknown roles are always refused
 *   (never a thrown error).
 * - `canSendChat(role)` mirrors `Capability.CHAT_SEND`: Org Admin and Editor.
 * - `homePath(role)`: '/platform' for a Super Admin, '/chat' for members,
 *   '/login' for `null`.
 * - `canManageOrgSettings(role)` (issue #159) mirrors
 *   `Capability.ORG_SETTINGS_MANAGE`: Org Admin only. It gates the Tools
 *   page's service toggles and `/api/org/settings`; every other role, `null`
 *   and unknown or prototype-key strings are refused (never a thrown error).
 * - `canManageOrgPermissions(role)` (issue #161) mirrors
 *   `Capability.ORG_PERMISSIONS_MANAGE`: Org Admin only. It gates the
 *   permission matrix and the critical permissions under Organization; every
 *   other role, `null` and unknown or prototype-key strings are refused.
 * - `canConnectAccounts(role)` (issue #162) mirrors `Capability.OAUTH_CONNECT`:
 *   Org Admin and Editor only (the Tools page's "my connections"). Viewers and
 *   Super Admins can't connect accounts; `null`, `undefined` and unknown or
 *   prototype-key strings are refused (never a thrown error). The area matrix
 *   is unchanged (Tools: Org Admin + Editor).
 */
import { describe, it, expect } from 'vitest';
import * as access from '@/services/access';
import {
  canAccessArea,
  canManageOrgPermissions,
  canManageOrgSettings,
  canSendChat,
  homePath,
  shellRole,
  type Area,
  type ShellRole,
} from '@/services/access';
import type { MeResponse } from '@/api/types';

const ORG_ID = '7d3e2f10-6b4a-4e8c-8f1d-2a9b0c5e6d71';

const ROLES: readonly ShellRole[] = ['super_admin', 'org_admin', 'editor', 'viewer'];
const AREAS: readonly Area[] = ['chat', 'tools', 'permissions', 'organization', 'settings', 'platform'];

const ALLOWED: Record<ShellRole, readonly Area[]> = {
  super_admin: ['platform', 'settings'],
  org_admin: ['chat', 'tools', 'organization', 'settings'],
  editor: ['chat', 'tools', 'permissions', 'settings'],
  viewer: ['chat', 'permissions', 'settings'],
};

function member(role: 'org_admin' | 'editor' | 'viewer'): MeResponse {
  return {
    user_id: '0b9f6c1e-3a52-4c1d-9a8e-5f2d7c3b1a90',
    kind: 'member',
    org_id: ORG_ID,
    role,
    ui_language: 'en',
    response_language: null,
  };
}

function superAdmin(): MeResponse {
  return {
    user_id: '5a1c9e2d-7b3f-4d8a-9c6e-1f0b2a3d4e5f',
    kind: 'super_admin',
    org_id: null,
    role: null,
    ui_language: 'en',
    response_language: null,
  };
}

/** A MeResponse with fields a well-behaved backend never sends (cast on purpose). */
function malformed(overrides: Record<string, unknown>, base: MeResponse = member('editor')): MeResponse {
  return { ...base, ...overrides } as unknown as MeResponse;
}

// --- shellRole ------------------------------------------------------------

describe('access shellRole', () => {
  it('gives super_admin for a Super Admin (no org, no role)', () => {
    expect(shellRole(superAdmin())).toBe('super_admin');
  });

  it.each(['org_admin', 'editor', 'viewer'] as const)('gives %s for a member with that role', (role) => {
    expect(shellRole(member(role))).toBe(role);
  });

  const failClosed: Array<[string, MeResponse | null]> = [
    ['no user', null],
    ['undefined', undefined as unknown as MeResponse],
    ['a string', 'editor' as unknown as MeResponse],
    ['a Super Admin with an org', malformed({ org_id: ORG_ID }, superAdmin())],
    ['a Super Admin with an empty-string org', malformed({ org_id: '' }, superAdmin())],
    ['a Super Admin with a role', malformed({ role: 'org_admin' }, superAdmin())],
    ['a member without a role', malformed({ role: null })],
    ['a member without an org', malformed({ org_id: null })],
    ['a member with an empty-string org', malformed({ org_id: '' })],
    ['a member with a numeric org', malformed({ org_id: 42 })],
    ['a member with the unknown role "owner"', malformed({ role: 'owner' })],
    ['a member with the role "super_admin"', malformed({ role: 'super_admin' })],
    ['a member with the role "Editor" (case)', malformed({ role: 'Editor' })],
    ['a member with the role "__proto__"', malformed({ role: '__proto__' })],
    ['a member with the role "constructor"', malformed({ role: 'constructor' })],
    ['a member with the role "toString"', malformed({ role: 'toString' })],
    ['an unknown kind', malformed({ kind: 'admin' })],
    ['the kind "SUPER_ADMIN" (case)', malformed({ kind: 'SUPER_ADMIN' }, superAdmin())],
    ['a missing kind', malformed({ kind: undefined })],
  ];

  it.each(failClosed)('fails closed (null) for %s', (_label, me) => {
    expect(shellRole(me)).toBeNull();
  });
});

// --- canAccessArea --------------------------------------------------------

describe('access canAccessArea', () => {
  const matrix = ROLES.flatMap((role) =>
    AREAS.map((area): [ShellRole, Area, boolean] => [role, area, ALLOWED[role].includes(area)]),
  );

  it.each(matrix)('%s -> %s is %s', (role, area, expected) => {
    expect(canAccessArea(role, area)).toBe(expected);
  });

  it.each(AREAS)('refuses %s to a logged-out user (null)', (area) => {
    expect(canAccessArea(null, area)).toBe(false);
  });

  it('gives each role exactly its issue #161 / #166 areas', () => {
    expect(Object.fromEntries(ROLES.map((role) => [role, AREAS.filter((area) => canAccessArea(role, area))]))).toEqual({
      super_admin: ['settings', 'platform'],
      org_admin: ['chat', 'tools', 'organization', 'settings'],
      editor: ['chat', 'tools', 'permissions', 'settings'],
      viewer: ['chat', 'permissions', 'settings'],
    });
  });

  it('gives the read-only Permissions page to Editors and Viewers but not to the Org Admin or Super Admin', () => {
    expect(ROLES.filter((role) => canAccessArea(role, 'permissions'))).toEqual(['editor', 'viewer']);
  });

  it('gives a Super Admin nothing but the settings and the platform (no chat UI, issue #166)', () => {
    expect(AREAS.filter((area) => canAccessArea('super_admin', area))).toEqual(['settings', 'platform']);
  });

  it('lets the Super Admin open Settings (issue #166: the account sections)', () => {
    expect(canAccessArea('super_admin', 'settings')).toBe(true);
  });

  it.each(['admin', 'activity', '', '__proto__', 'constructor', 'toString', 'Chat'])(
    'refuses the unknown area %j for every role',
    (area) => {
      expect(ROLES.filter((role) => canAccessArea(role, area as Area))).toEqual([]);
    },
  );

  it.each(['owner', '__proto__', 'constructor', 'toString', 'hasOwnProperty'])(
    'refuses every area to the unknown role %j without throwing',
    (role) => {
      expect(AREAS.filter((area) => canAccessArea(role as ShellRole, area))).toEqual([]);
    },
  );
});

// --- canSendChat ----------------------------------------------------------

describe('access canSendChat', () => {
  it.each([
    ['org_admin', true],
    ['editor', true],
    ['viewer', false],
    ['super_admin', false],
    [null, false],
  ] as Array<[ShellRole | null, boolean]>)('%s may send chat: %s', (role, expected) => {
    expect(canSendChat(role)).toBe(expected);
  });

  it.each(['owner', '__proto__', 'constructor', 'toString'])(
    'refuses chat to the unknown role %j without throwing',
    (role) => {
      expect(canSendChat(role as ShellRole)).toBe(false);
    },
  );
});

// --- canManageOrgSettings (issue #159) ------------------------------------

describe('access canManageOrgSettings', () => {
  it.each([
    ['org_admin', true],
    ['editor', false],
    ['viewer', false],
    ['super_admin', false],
    [null, false],
  ] as Array<[ShellRole | null, boolean]>)('%s may manage the org settings: %s', (role, expected) => {
    expect(canManageOrgSettings(role)).toBe(expected);
  });

  it.each(['owner', 'admin', 'Org_Admin', 'ORG_ADMIN', ' org_admin', '', '__proto__', 'constructor', 'toString', 'hasOwnProperty'])(
    'refuses the org settings to the unknown role %j without throwing',
    (role) => {
      expect(canManageOrgSettings(role as ShellRole)).toBe(false);
    },
  );

  it('grants the org settings only to roles that may open the Tools page', () => {
    expect(ROLES.filter((role) => canManageOrgSettings(role) && !canAccessArea(role, 'tools'))).toEqual([]);
  });
});

// --- canManageOrgPermissions (issue #161) ---------------------------------

describe('access canManageOrgPermissions', () => {
  it.each([
    ['org_admin', true],
    ['editor', false],
    ['viewer', false],
    ['super_admin', false],
    [null, false],
  ] as Array<[ShellRole | null, boolean]>)('%s may manage the org permissions: %s', (role, expected) => {
    expect(canManageOrgPermissions(role)).toBe(expected);
  });

  it.each(['owner', 'admin', 'Org_Admin', 'ORG_ADMIN', ' org_admin', 'org_admin ', '', '__proto__', 'constructor', 'toString', 'hasOwnProperty'])(
    'refuses the org permissions to the unknown role %j without throwing',
    (role) => {
      expect(canManageOrgPermissions(role as ShellRole)).toBe(false);
    },
  );

  it('refuses the org permissions to undefined without throwing', () => {
    expect(canManageOrgPermissions(undefined as unknown as ShellRole | null)).toBe(false);
  });

  it('grants the org permissions only to roles that may open the Organization page', () => {
    const managers = ROLES.filter((role) => canManageOrgPermissions(role));

    expect({ managers, outsideOrganization: managers.filter((role) => !canAccessArea(role, 'organization')) }).toEqual({
      managers: ['org_admin'],
      outsideOrganization: [],
    });
  });

  it('never gives a permission manager the read-only Permissions page as well', () => {
    expect(ROLES.filter((role) => canManageOrgPermissions(role) && canAccessArea(role, 'permissions'))).toEqual([]);
  });
});

// --- canConnectAccounts (issue #162) ---------------------------------------

describe('access canConnectAccounts', () => {
  it.each([
    ['org_admin', true],
    ['editor', true],
    ['viewer', false],
    ['super_admin', false],
    [null, false],
  ] as Array<[ShellRole | null, boolean]>)('%s may connect accounts: %s', (role, expected) => {
    expect(access.canConnectAccounts(role)).toBe(expected);
  });

  it.each([
    'owner',
    'admin',
    'Editor',
    'EDITOR',
    ' editor',
    'editor ',
    'Org_Admin',
    '',
    '__proto__',
    'constructor',
    'toString',
    'hasOwnProperty',
  ])('refuses connections to the unknown role %j without throwing', (role) => {
    expect(access.canConnectAccounts(role as ShellRole)).toBe(false);
  });

  it('refuses connections to undefined without throwing', () => {
    expect(access.canConnectAccounts(undefined as unknown as ShellRole | null)).toBe(false);
  });

  it('grants connections exactly to the roles that may open the Tools page', () => {
    const connectors = ROLES.filter((role) => access.canConnectAccounts(role));

    expect({ connectors, tools: ROLES.filter((role) => canAccessArea(role, 'tools')) }).toEqual({
      connectors: ['org_admin', 'editor'],
      tools: ['org_admin', 'editor'],
    });
  });
});

// --- homePath -------------------------------------------------------------

describe('access homePath', () => {
  it.each([
    ['super_admin', '/platform'],
    ['org_admin', '/chat'],
    ['editor', '/chat'],
    ['viewer', '/chat'],
    [null, '/login'],
  ] as Array<[ShellRole | null, string]>)('%s starts at %s', (role, expected) => {
    expect(homePath(role)).toBe(expected);
  });

  it.each(ROLES)('sends %s home to an area it may access', (role) => {
    const home = homePath(role).slice(1) as Area;

    expect(canAccessArea(role, home)).toBe(true);
  });
});
