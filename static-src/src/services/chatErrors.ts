/**
 * Chat error code -> i18n key mapping (issue #242: V1 model policy; decision
 * D3 — every chat reply with status "error" shows translated text in the UI,
 * never the backend's English `response` fallback).
 *
 * Pure mapping from a `ChatResponse.error_code` (one of the seven
 * `LLMErrorCode` values, or absent/unknown) to an i18n catalog key. Fails
 * closed to `chat.error.generic` for anything that isn't exactly one of the
 * known codes — including non-string values, boxed `String` objects, arrays
 * and prototype-name strings such as `'__proto__'` or `'toString'` — using an
 * exact own-value match (`Array.prototype.includes`), never an `in` check or
 * a property lookup, so a crafted `error_code` can never resolve to an
 * inherited property or to a key outside `chat.error.*`.
 */
import type { LLMErrorCode } from '@/api/types';

/** The seven codes the backend's `LLMErrorCode` Literal defines (GH-242 §1). */
export const LLM_ERROR_CODES: readonly LLMErrorCode[] = [
  'not_configured',
  'missing_model',
  'provider_unavailable',
  'rate_limited',
  'timeout',
  'residency_blocked',
  'context_too_long',
];

const GENERIC_KEY = 'chat.error.generic';

/** Resolves `code` to its `chat.error.<code>` catalog key, or `chat.error.generic` when it isn't a known one. */
export function chatErrorKey(code: unknown): string {
  return typeof code === 'string' && (LLM_ERROR_CODES as readonly string[]).includes(code)
    ? `chat.error.${code}`
    : GENERIC_KEY;
}
