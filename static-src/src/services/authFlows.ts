/**
 * Auth page flow logic (issue #155: "errors are generic where the backend is
 * generic"; error responses are never echoed).
 *
 * Holds the logic the Login, Forgot password, Reset password and Accept
 * invitation pages call. Each flow returns a result object and never throws;
 * a failure carries only a catalog key, never text from the server's body.
 */
import { acceptInvitation, confirmPasswordReset, getInvitation, requestPasswordReset } from '@/api/auth';
import { ApiError } from '@/api/client';
import type { MessageKey } from '@/i18n';
import { policyMessageKey } from './passwordPolicy';
import type { InvitationDetails } from '@/api/types';

export type FlowResult = { ok: true } | { ok: false; messageKey: MessageKey };
export type InvitationResult = { ok: true; invitation: InvitationDetails } | { ok: false; messageKey: MessageKey };

/** A 429 is always "rate limited"; anything else (including a network failure) is the generic key. */
function rateLimitedOrGeneric(err: unknown): MessageKey {
  return err instanceof ApiError && err.status === 429 ? 'auth.error.rateLimited' : 'auth.error.generic';
}

/** Always `{ ok: true }` when accepted — the page shows the same "if an account exists" confirmation for every email. */
export async function requestReset(email: string): Promise<FlowResult> {
  try {
    await requestPasswordReset(email);
    return { ok: true };
  } catch (err) {
    return { ok: false, messageKey: rateLimitedOrGeneric(err) };
  }
}

export async function confirmReset(token: string, newPassword: string): Promise<FlowResult> {
  try {
    await confirmPasswordReset(token, newPassword);
    return { ok: true };
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.status === 400) return { ok: false, messageKey: 'auth.reset.error.invalidLink' };
      if (err.status === 422) return { ok: false, messageKey: policyMessageKey(err.reason) };
    }
    return { ok: false, messageKey: rateLimitedOrGeneric(err) };
  }
}

export async function loadInvitation(token: string): Promise<InvitationResult> {
  try {
    return { ok: true, invitation: await getInvitation(token) };
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      return { ok: false, messageKey: 'auth.invitation.error.invalidLink' };
    }
    return { ok: false, messageKey: rateLimitedOrGeneric(err) };
  }
}

export async function acceptInvite(token: string, name: string, password: string): Promise<FlowResult> {
  try {
    await acceptInvitation(token, name, password);
    return { ok: true };
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.status === 404) return { ok: false, messageKey: 'auth.invitation.error.invalidLink' };
      if (err.status === 422) {
        return { ok: false, messageKey: err.reason ? policyMessageKey(err.reason) : 'auth.invitation.error.invalidName' };
      }
    }
    return { ok: false, messageKey: rateLimitedOrGeneric(err) };
  }
}

export type LoginOutcome = 'invalid' | 'rate_limited' | 'error';

/** Maps the auth store's login outcome to a catalog key; the wrong-credentials text is the backend's generic one. */
export function loginMessageKey(outcome: LoginOutcome): MessageKey {
  if (outcome === 'invalid') return 'auth.login.error.invalid';
  if (outcome === 'rate_limited') return 'auth.error.rateLimited';
  return 'auth.error.generic';
}
