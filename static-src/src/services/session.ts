/**
 * Global 401 redirect (issue #155: a 401 from any call redirects to login and
 * preserves the target route; a session-expired toast).
 *
 * `installUnauthorizedRedirect(router)` registers the API client's
 * unauthorized handler (`setUnauthorizedHandler`). On a 401 from any
 * non-auth endpoint it calls the auth store's `handleUnauthorized()` (one
 * session-expired toast, user forgotten) and, unless the current route is a
 * public page, navigates to `/login?redirect=<current full path>` — the
 * query is dropped when the current path isn't a safe redirect target.
 */
import type { Router } from 'vue-router';
import { setUnauthorizedHandler } from '@/api/client';
import { safeRedirect } from '@/router/guards';
import { useAuthStore } from '@/stores/auth';

export function installUnauthorizedRedirect(router: Router): void {
  setUnauthorizedHandler(() => {
    const auth = useAuthStore();
    if (!auth.handleUnauthorized()) return;

    const current = router.currentRoute.value;
    if (current.meta.public) return;

    const redirect = safeRedirect(current.fullPath);
    void router.push(redirect === null ? { path: '/login' } : { path: '/login', query: { redirect } });
  });
}
