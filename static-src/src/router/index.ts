/**
 * App router (issue #15: no Activity page; issue #155: auth pages and
 * role-aware route guards).
 *
 * `createAppRouter(history)` builds an independent router on the given
 * history (tests use a memory history); the default export is the app's
 * router, on the web history. Its `beforeEach` awaits the auth store's
 * `ensureLoaded()` (one `GET /api/auth/me` per app load, cached afterwards)
 * and applies `resolveNavigation` (`@/router/guards`), which is pure and unit
 * tested on its own.
 */
import { createRouter, createWebHistory, type Router, type RouteRecordRaw, type RouterHistory } from 'vue-router';
import { resolveNavigation, type NavigationTarget } from './guards';
import { useAuthStore } from '@/stores/auth';
import type { Area } from '@/services/access';

declare module 'vue-router' {
  interface RouteMeta {
    /** Marks an auth page reachable without a session (login, password reset, invitation). */
    public?: boolean;
    /** The shell access area a protected page belongs to; guarded by `resolveNavigation`. */
    area?: Area;
  }
}

const routes: RouteRecordRaw[] = [
  { path: '/', redirect: '/chat' },

  // --- Public auth pages ---------------------------------------------------
  { path: '/login', name: 'login', component: () => import('@/pages/LoginPage.vue'), meta: { public: true } },
  {
    path: '/forgot-password',
    name: 'forgot-password',
    component: () => import('@/pages/ForgotPasswordPage.vue'),
    meta: { public: true },
  },
  {
    path: '/reset-password',
    name: 'reset-password',
    component: () => import('@/pages/ResetPasswordPage.vue'),
    meta: { public: true },
  },
  {
    path: '/accept-invitation',
    name: 'accept-invitation',
    component: () => import('@/pages/AcceptInvitationPage.vue'),
    meta: { public: true },
  },

  // --- Protected areas -------------------------------------------------------
  { path: '/chat', name: 'chat', component: () => import('@/pages/ChatPage.vue'), meta: { area: 'chat' } },
  { path: '/tools', name: 'tools', component: () => import('@/pages/ToolsPage.vue'), meta: { area: 'tools' } },
  {
    path: '/permissions',
    name: 'permissions',
    component: () => import('@/pages/PermissionsPage.vue'),
    meta: { area: 'permissions' },
  },
  {
    path: '/organization',
    name: 'organization',
    component: () => import('@/pages/OrganizationPage.vue'),
    meta: { area: 'organization' },
  },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('@/pages/SettingsPage.vue'),
    meta: { area: 'settings' },
  },
  {
    path: '/platform',
    name: 'platform',
    component: () => import('@/pages/PlatformPage.vue'),
    meta: { area: 'platform' },
  },

  { path: '/:pathMatch(.*)*', redirect: '/chat' },
];

export function createAppRouter(history: RouterHistory): Router {
  const appRouter = createRouter({ history, routes });

  appRouter.beforeEach(async (to) => {
    const auth = useAuthStore();
    await auth.ensureLoaded();
    return resolveNavigation(to as unknown as NavigationTarget, auth.role);
  });

  return appRouter;
}

const router = createAppRouter(createWebHistory());

export default router;
