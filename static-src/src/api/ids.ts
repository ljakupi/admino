/**
 * Shared id format for the API clients and services (issue #168).
 *
 * One UUID pattern so the path-injection guard in `api/platform.ts` and the
 * `?org=` validation in `services/platformOrgs.ts` can't drift apart.
 */
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
