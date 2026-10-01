/**
 * Shell access policy (issue #155: role-aware app shell).
 *
 * Pure frontend mirror of the backend access policy (`access.py`), used by
 * the nav and the route guards. The backend stays authoritative for every
 * actual request; this only decides what the shell *offers*, and fails
 * closed (never throws, never grants on an unknown role/area/profile).
 */
import type { MessageKey } from '@/i18n';
import type { MeResponse } from '@/api/types';

export type ShellRole = 'super_admin' | 'org_admin' | 'editor' | 'viewer';

export type Area = 'chat' | 'tools' | 'permissions' | 'organization' | 'settings' | 'platform';

const MEMBER_ROLES: readonly ShellRole[] = ['org_admin', 'editor', 'viewer'];

/**
 * `principal_role` fails closed like the backend: a Super Admin only with
 * `kind === 'super_admin'`, no org and no role; a member role only with
 * `kind === 'member'`, a non-empty string org id and a known role. Anything
 * else — including prototype keys as a role name — is `null`.
 */
export function shellRole(me: MeResponse | null | undefined): ShellRole | null {
  if (me === null || me === undefined || typeof me !== 'object') return null;

  if (me.kind === 'super_admin') {
    return me.org_id === null && me.role === null ? 'super_admin' : null;
  }

  if (me.kind === 'member') {
    if (typeof me.org_id !== 'string' || me.org_id === '') return null;
    if (typeof me.role !== 'string') return null;
    return MEMBER_ROLES.includes(me.role as ShellRole) ? (me.role as ShellRole) : null;
  }

  return null;
}

// Issue #161: the Org Admin edits the permission matrix and critical
// permissions under Organization (no separate Permissions entry); Editors
// and Viewers get the read-only Permissions summary instead.
const AREA_MATRIX: Record<ShellRole, readonly Area[]> = {
  super_admin: ['platform'],
  org_admin: ['chat', 'tools', 'organization', 'settings'],
  editor: ['chat', 'tools', 'permissions', 'settings'],
  viewer: ['chat', 'permissions', 'settings'],
};

/** Super Admin -> Platform only; Org Admin/Editor/Viewer per the matrix above; `null` -> nothing. */
export function canAccessArea(role: ShellRole | null, area: Area): boolean {
  if (role === null || !Object.hasOwn(AREA_MATRIX, role)) return false;
  return AREA_MATRIX[role].includes(area);
}

const CHAT_SEND_ROLES: readonly ShellRole[] = ['org_admin', 'editor'];

/** Mirrors the backend's `Capability.CHAT_SEND`: Org Admin and Editor only. */
export function canSendChat(role: ShellRole | null): boolean {
  return role !== null && CHAT_SEND_ROLES.includes(role);
}

const ORG_SETTINGS_MANAGE_ROLES: readonly ShellRole[] = ['org_admin'];

/**
 * Mirrors the backend's `Capability.ORG_SETTINGS_MANAGE`: Org Admin only.
 * Gates the Tools page's per-service toggles and `/api/org/settings`.
 */
export function canManageOrgSettings(role: ShellRole | null): boolean {
  return role !== null && ORG_SETTINGS_MANAGE_ROLES.includes(role);
}

const ORG_PERMISSIONS_MANAGE_ROLES: readonly ShellRole[] = ['org_admin'];

/**
 * Mirrors the backend's `Capability.ORG_PERMISSIONS_MANAGE`: Org Admin only.
 * Gates the permission matrix and the critical permissions under
 * Organization (issue #161).
 */
export function canManageOrgPermissions(role: ShellRole | null): boolean {
  return role !== null && ORG_PERMISSIONS_MANAGE_ROLES.includes(role);
}

/** Where a role lands after login: `/platform` for a Super Admin, `/chat` for members, `/login` for `null`. */
export function homePath(role: ShellRole | null): string {
  if (role === 'super_admin') return '/platform';
  if (role === 'org_admin' || role === 'editor' || role === 'viewer') return '/chat';
  return '/login';
}

/** Catalog key for the role offered by an invitation (Accept invitation page). */
export const INVITATION_ROLE_LABEL_KEYS: Record<'org_admin' | 'editor' | 'viewer', MessageKey> = {
  org_admin: 'auth.role.orgAdmin',
  editor: 'auth.role.editor',
  viewer: 'auth.role.viewer',
};
