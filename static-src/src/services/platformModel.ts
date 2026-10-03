/**
 * Platform model service (issue #242: V1 model policy; decision D1 — a PATCH
 * that switches the platform's LLM provider to a non-Swiss one needs a
 * residency confirmation naming how many organizations have data residency
 * on; the server enforces it with a 409, #168 renders the dialog).
 *
 * Pure mirror of the backend's `llm_policy.SWISS_PROVIDERS` / residency
 * check, so the UI can ask for confirmation before the server would refuse.
 * Fails closed: anything that isn't exactly (and case-sensitively) a Swiss
 * provider counts as non-Swiss.
 */

/** The same set as the backend's `llm_policy.SWISS_PROVIDERS`. */
export const SWISS_PROVIDERS = ['infomaniak', 'vllm'] as const;

const SWISS_PROVIDER_SET: ReadonlySet<string> = new Set(SWISS_PROVIDERS);

/** True only for an exact, case-sensitive member of `SWISS_PROVIDERS`. */
export function isSwissProvider(provider: string): boolean {
  return SWISS_PROVIDER_SET.has(provider);
}

/** True iff `next` differs from `current` and `next` is not Swiss (mirrors the server's 409 rule). */
export function needsResidencyConfirmation(current: string, next: string): boolean {
  return next !== current && !isSwissProvider(next);
}
