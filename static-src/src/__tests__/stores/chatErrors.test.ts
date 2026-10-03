/**
 * Chat store: error replies show translated text (issue #242: V1 model
 * policy; decision D3).
 *
 * Contract (GH-242 §6): a `ChatResponse` with `status === 'error'` adds an
 * agent message whose content is `t(chatErrorKey(res.error_code))` — the
 * catalog text `chat.error.<code>` for one of the seven LLM error codes, and
 * `chat.error.generic` when `error_code` is null, missing or anything else —
 * never `res.response` (the backend's English fallback). This holds for
 * `sendMessage` and for the confirm path (`approve` and `deny` both resume
 * the run through `POST /api/confirm/{id}`, i.e. `confirmDecision`). The text
 * follows the active locale (English under en, the different de-catalog
 * string under de). Every other status is unchanged: a `final` or
 * `limit_reached` reply still shows `res.response` verbatim, even when it
 * carries an `error_code`, and tool-call records in an error reply are still
 * mapped to cards.
 *
 * The expected texts are read straight from the en/de catalogs by key (pinned
 * from the contract, not from `@/services/chatErrors`, so this file runs on
 * its own): a missing catalog key or a store that still shows `res.response`
 * both fail here. Every error reply carries a canary English `response` that
 * must never reach the thread. The network layer (`@/api/messages`) is
 * mocked like in `chat.test.ts`. No component is mounted.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { postMessage, confirmDecision } from '@/api/messages';
import { setLocale } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { useChatStore } from '@/stores/chat';
import { useConnectionStore } from '@/stores/connection';
import type { ChatResponse, ChatStatus, PendingConfirmationSummary, ThreadItem, ToolCallRecord } from '@/api/types';

vi.mock('@/api/messages', () => ({
  postMessage: vi.fn(),
  confirmDecision: vi.fn(),
}));

const mockedPostMessage = vi.mocked(postMessage);
const mockedConfirmDecision = vi.mocked(confirmDecision);

type CatalogLocale = 'en' | 'de';

const CATALOGS: Record<CatalogLocale, Record<string, unknown>> = { en, de };

/** The seven backend `LLMErrorCode` values (GH-242 §1). */
const CODES: readonly string[] = [
  'not_configured',
  'missing_model',
  'provider_unavailable',
  'rate_limited',
  'timeout',
  'residency_blocked',
  'context_too_long',
];

const GENERIC_KEY = 'chat.error.generic';

/** English fallback text the backend puts in `response`; it must never be shown for an error. */
const CANARY = 'CANARY-7f3a: Infomaniak API returned HTTP 503 (english fallback)';

/** `error_code` values that are not a known code: each shows the generic text. */
const NOT_A_CODE: ReadonlyArray<[string, unknown]> = [
  ['null', null],
  ['an unknown string', 'quota_exceeded'],
  ['the empty string', ''],
  ['a number', 503],
  ['__proto__', '__proto__'],
  ['toString', 'toString'],
  ['constructor', 'constructor'],
];

// --- Fixtures -------------------------------------------------------------

function makeResponse(overrides: Partial<ChatResponse> = {}): ChatResponse {
  return {
    session_id: 's-test',
    response: 'Done.',
    tool_calls: [],
    status: 'final',
    pending_confirmation: null,
    ...overrides,
  };
}

/**
 * A reply carrying `error_code: code` (any value, also invalid ones the type
 * would refuse — the store must cope with whatever the wire holds).
 */
function withCode(code: unknown, overrides: Partial<ChatResponse> = {}): ChatResponse {
  return { ...makeResponse(overrides), error_code: code } as unknown as ChatResponse;
}

/** An error reply: status 'error', the canary as `response`, and `error_code: code`. */
function errorReply(code: unknown, overrides: Partial<ChatResponse> = {}): ChatResponse {
  return withCode(code, { response: CANARY, status: 'error', ...overrides });
}

/** An error reply without any `error_code` property. */
function errorReplyWithoutCode(): ChatResponse {
  return makeResponse({ response: CANARY, status: 'error' });
}

function makeRecord(overrides: Partial<ToolCallRecord> = {}): ToolCallRecord {
  return {
    tool: 'gmail',
    action: 'search',
    permission: 'allow',
    success: true,
    args: { query: 'from:boss is:unread' },
    duration_ms: 42,
    ...overrides,
  };
}

function makePending(overrides: Partial<PendingConfirmationSummary> = {}): PendingConfirmationSummary {
  return {
    confirmation_id: 'c-1',
    tool: 'gmail',
    action: 'send',
    args: { to: 'boss@example.com', subject: 'Q3 report' },
    expires_at: '2026-10-03T12:05:00Z',
    ...overrides,
  };
}

// --- Helpers --------------------------------------------------------------

/** The catalog's own string for `key` under `locale`, or undefined (a missing key fails the assertion). */
function catalogText(locale: CatalogLocale, key: string): string | undefined {
  const catalog = CATALOGS[locale];
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  return typeof value === 'string' && value.trim() !== '' ? value : undefined;
}

/** Compact, order-preserving description of the thread. */
function summarize(thread: readonly ThreadItem[]): string[] {
  return thread.map((item) => {
    switch (item.type) {
      case 'message':
        return `${item.data.role}:${item.data.content}`;
      case 'tool_call':
        return `tool:${item.data.tool}.${item.data.action}:${item.data.state}`;
      case 'thinking':
        return 'thinking';
    }
  });
}

/** Contents of the agent messages in the thread, in order. */
function agentMessages(): string[] {
  return useChatStore().thread.flatMap((item) =>
    item.type === 'message' && item.data.role === 'agent' ? [item.data.content] : [],
  );
}

/** True when the canary fallback text appears anywhere in the thread. */
function canaryShown(): boolean {
  return summarize(useChatStore().thread).some((line) => line.includes('CANARY-7f3a'));
}

/** Send a message whose reply is `res`. */
async function sendWithReply(res: ChatResponse, content = 'Hello'): Promise<void> {
  mockedPostMessage.mockResolvedValueOnce(res);
  await useChatStore().sendMessage(content);
}

/** Send a message whose reply asks for confirmation; return the pending card's id. */
async function seedPendingCard(): Promise<string> {
  await sendWithReply(
    makeResponse({ response: '', status: 'awaiting_confirmation', pending_confirmation: makePending() }),
    'Email the Q3 report to my boss',
  );
  const card = useChatStore().pendingConfirmation;
  if (!card) throw new Error('test setup: expected a pending confirmation card');
  return card.id;
}

beforeEach(() => {
  localStorage.clear();
  setActivePinia(createPinia());
  mockedPostMessage.mockReset();
  mockedConfirmDecision.mockReset();
  setLocale('en');
  // The connection store starts 'offline' and ignores setters while offline.
  useConnectionStore().state = 'idle';
});

afterEach(() => {
  setLocale('en');
});

// --- sendMessage ----------------------------------------------------------

describe('chatStore error replies to sendMessage (issue #242, D3)', () => {
  it('shows the en residency_blocked text instead of the response, and goes idle', async () => {
    await sendWithReply(errorReply('residency_blocked'));

    expect({
      thread: summarize(useChatStore().thread),
      canaryShown: canaryShown(),
      connection: useConnectionStore().state,
    }).toEqual({
      thread: ['user:Hello', `agent:${catalogText('en', 'chat.error.residency_blocked')}`],
      canaryShown: false,
      connection: 'idle',
    });
  });

  it('shows the de residency_blocked text under de, not the en text nor the response', async () => {
    setLocale('de');

    await sendWithReply(errorReply('residency_blocked'));

    const german = catalogText('de', 'chat.error.residency_blocked');
    expect({
      messages: agentMessages(),
      germanDiffersFromEnglish: german !== undefined && german !== catalogText('en', 'chat.error.residency_blocked'),
      canaryShown: canaryShown(),
    }).toEqual({ messages: [german], germanDiffersFromEnglish: true, canaryShown: false });
  });

  it.each(CODES)('shows the chat.error.%s text for that code, never the response', async (code) => {
    await sendWithReply(errorReply(code));

    const expected = catalogText('en', `chat.error.${code}`);
    expect({ defined: expected !== undefined, messages: agentMessages(), canaryShown: canaryShown() }).toEqual({
      defined: true,
      messages: [expected],
      canaryShown: false,
    });
  });

  it.each(CODES)('shows the de chat.error.%s text under de', async (code) => {
    setLocale('de');

    await sendWithReply(errorReply(code));

    const expected = catalogText('de', `chat.error.${code}`);
    expect({ defined: expected !== undefined, messages: agentMessages() }).toEqual({
      defined: true,
      messages: [expected],
    });
  });

  it.each(NOT_A_CODE)('shows the generic text when error_code is %s', async (_label, code) => {
    await sendWithReply(errorReply(code));

    const generic = catalogText('en', GENERIC_KEY);
    expect({ defined: generic !== undefined, messages: agentMessages(), canaryShown: canaryShown() }).toEqual({
      defined: true,
      messages: [generic],
      canaryShown: false,
    });
  });

  it('shows the generic text when the reply has no error_code at all', async () => {
    await sendWithReply(errorReplyWithoutCode());

    const generic = catalogText('en', GENERIC_KEY);
    expect({ defined: generic !== undefined, messages: agentMessages(), canaryShown: canaryShown() }).toEqual({
      defined: true,
      messages: [generic],
      canaryShown: false,
    });
  });

  it('shows the de generic text under de when error_code is null', async () => {
    setLocale('de');

    await sendWithReply(errorReply(null));

    const german = catalogText('de', GENERIC_KEY);
    expect({
      messages: agentMessages(),
      germanDiffersFromEnglish: german !== undefined && german !== catalogText('en', GENERIC_KEY),
    }).toEqual({ messages: [german], germanDiffersFromEnglish: true });
  });

  it('still adds the translated text when the error reply has an empty response', async () => {
    await sendWithReply(errorReply('timeout', { response: '' }));

    expect(summarize(useChatStore().thread)).toEqual([
      'user:Hello',
      `agent:${catalogText('en', 'chat.error.timeout')}`,
    ]);
  });

  it('keeps mapping tool-call records to cards, then adds the translated text', async () => {
    await sendWithReply(
      errorReply('provider_unavailable', { tool_calls: [makeRecord({ tool: 'gmail', action: 'search' })] }),
    );

    expect(summarize(useChatStore().thread)).toEqual([
      'user:Hello',
      'tool:gmail.search:completed',
      `agent:${catalogText('en', 'chat.error.provider_unavailable')}`,
    ]);
  });
});

// --- Other statuses are unchanged -----------------------------------------

describe('chatStore non-error replies keep their response (issue #242, D3)', () => {
  it.each([
    ['final', 'Here is your summary.'],
    ['limit_reached', 'I stopped after too many steps.'],
  ] as Array<[ChatStatus, string]>)(
    'after an error reply, a %s reply still shows its response verbatim (even with an error_code)',
    async (status, text) => {
      await sendWithReply(errorReply('rate_limited'), 'First');
      await sendWithReply(withCode('timeout', { status, response: text }), 'Second');

      expect(summarize(useChatStore().thread)).toEqual([
        'user:First',
        `agent:${catalogText('en', 'chat.error.rate_limited')}`,
        'user:Second',
        `agent:${text}`,
      ]);
    },
  );
});

// --- Confirm path: approve and deny ---------------------------------------

describe('chatStore error replies on the confirm path (issue #242, D3)', () => {
  it('approve: an error reply shows the code text after the card, never the response', async () => {
    const cardId = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(errorReply('residency_blocked'));

    await useChatStore().approve(cardId);

    // The card's own state after an error reply is not part of this contract: only the text is.
    const lines = summarize(useChatStore().thread);
    expect({
      first: lines[0],
      cards: lines.filter((line) => line.startsWith('tool:gmail.send:')).length,
      last: lines[lines.length - 1],
      messages: agentMessages(),
      canaryShown: canaryShown(),
      connection: useConnectionStore().state,
    }).toEqual({
      first: 'user:Email the Q3 report to my boss',
      cards: 1,
      last: `agent:${catalogText('en', 'chat.error.residency_blocked')}`,
      messages: [catalogText('en', 'chat.error.residency_blocked')],
      canaryShown: false,
      connection: 'idle',
    });
  });

  it.each(CODES)('approve: an error reply with %s shows that code text', async (code) => {
    const cardId = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(errorReply(code));

    await useChatStore().approve(cardId);

    const expected = catalogText('en', `chat.error.${code}`);
    expect({ defined: expected !== undefined, messages: agentMessages(), canaryShown: canaryShown() }).toEqual({
      defined: true,
      messages: [expected],
      canaryShown: false,
    });
  });

  it.each(NOT_A_CODE)('approve: an error reply with error_code %s shows the generic text', async (_label, code) => {
    const cardId = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(errorReply(code));

    await useChatStore().approve(cardId);

    const generic = catalogText('en', GENERIC_KEY);
    expect({ defined: generic !== undefined, messages: agentMessages(), canaryShown: canaryShown() }).toEqual({
      defined: true,
      messages: [generic],
      canaryShown: false,
    });
  });

  it('approve: an error reply without error_code shows the generic text', async () => {
    const cardId = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(errorReplyWithoutCode());

    await useChatStore().approve(cardId);

    expect({ messages: agentMessages(), canaryShown: canaryShown() }).toEqual({
      messages: [catalogText('en', GENERIC_KEY)],
      canaryShown: false,
    });
  });

  it('approve: under de the error reply shows the de text', async () => {
    const cardId = await seedPendingCard();
    setLocale('de');
    mockedConfirmDecision.mockResolvedValueOnce(errorReply('timeout'));

    await useChatStore().approve(cardId);

    const german = catalogText('de', 'chat.error.timeout');
    expect({
      messages: agentMessages(),
      germanDiffersFromEnglish: german !== undefined && german !== catalogText('en', 'chat.error.timeout'),
    }).toEqual({ messages: [german], germanDiffersFromEnglish: true });
  });

  it('approve: a final reply after approval still shows its response verbatim (after an error reply)', async () => {
    const firstCard = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(errorReply('rate_limited'));
    await useChatStore().approve(firstCard);
    const secondCard = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(
      withCode('timeout', { status: 'final', response: 'Email sent to boss@example.com.' }),
    );

    await useChatStore().approve(secondCard);

    expect(agentMessages()).toEqual([
      catalogText('en', 'chat.error.rate_limited'),
      'Email sent to boss@example.com.',
    ]);
  });

  it('deny: an error reply from the resumed run shows the code text, never the response', async () => {
    const cardId = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(errorReply('residency_blocked'));

    await useChatStore().deny(cardId);

    const lines = summarize(useChatStore().thread);
    expect({
      last: lines[lines.length - 1],
      messages: agentMessages(),
      canaryShown: canaryShown(),
    }).toEqual({
      last: `agent:${catalogText('en', 'chat.error.residency_blocked')}`,
      messages: [catalogText('en', 'chat.error.residency_blocked')],
      canaryShown: false,
    });
  });

  it('deny: an error reply without a known code shows the generic text', async () => {
    const cardId = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(errorReply('quota_exceeded'));

    await useChatStore().deny(cardId);

    expect({ messages: agentMessages(), canaryShown: canaryShown() }).toEqual({
      messages: [catalogText('en', GENERIC_KEY)],
      canaryShown: false,
    });
  });
});
