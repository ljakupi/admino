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
 * - `canAccessArea(role, area)`: Super Admin → Platform only; Org Admin →
 *   Chat, Tools, Permissions, Organization, Settings; Editor → Chat, Tools,
 *   Settings; Viewer → Chat, Settings; `null` → nothing. Unknown areas and
 *   unknown roles are always refused (never a thrown error).
 * - `canSendChat(role)` mirrors `Capability.CHAT_SEND`: Org Admin and Editor.
 * - `homePath(role)`: '/platform' for a Super Admin, '/chat' for members,
 *   '/login' for `null`.
 * - `canManageOrgSettings(role)` (issue #159) mirrors
 *   `Capability.ORG_SETTINGS_MANAGE`: Org Admin only. It gates the Tools
 *   page's service toggles and `/api/org/settings`; every other role, `null`
 *   and unknown or prototype-key strings are refused (never a thrown error).
 */
import { describe, it, expect } from 'vitest';
import {
  canAccessArea,
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
  super_admin: ['platform'],
  org_admin: ['chat', 'tools', 'permissions', 'organization', 'settings'],
  editor: ['chat', 'tools', 'settings'],
  viewer: ['chat', 'settings'],
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

  it('gives a Super Admin nothing but the platform (no chat UI)', () => {
    expect(AREAS.filter((area) => canAccessArea('super_admin', area))).toEqual(['platform']);
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
