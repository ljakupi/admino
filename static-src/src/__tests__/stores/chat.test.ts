/**
 * Chat store tests (issue #21).
 *
 * Covers the send-message flow, response → thread mapping and ordering, the
 * tool-call confirmation state machine (pending → approved → completed/error,
 * pending → denied) and error handling. Also covers issue #141: clearing the
 * thread is a fresh start, so it rotates (and persists) the session id and
 * every later request uses the new one. Issue #15 removes the Activity page,
 * so the store no longer exposes the `toolCallHistory` getter that only that
 * page used. The tests read tool calls straight from `thread` instead. Issue
 * #144 translates the UI: toast copy comes from the i18n catalogs, so it
 * follows the active locale (asserted as "English under en, a different
 * de-catalog string under de", without depending on the German wording). The
 * network layer (`@/api/messages`) is mocked; error cases use the real
 * `ApiError` class.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { postMessage, confirmDecision } from '@/api/messages';
import { ApiError } from '@/api/client';
import { setLocale } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { useChatStore } from '@/stores/chat';
import { useConnectionStore } from '@/stores/connection';
import { useSettingsStore } from '@/stores/settings';
import { useToastStore, type ToastKind } from '@/stores/toasts';
import type {
  ChatResponse,
  PendingConfirmationSummary,
  ThreadItem,
  ToolCallRecord,
  ToolCallUI,
} from '@/api/types';

vi.mock('@/api/messages', () => ({
  postMessage: vi.fn(),
  confirmDecision: vi.fn(),
}));

const mockedPostMessage = vi.mocked(postMessage);
const mockedConfirmDecision = vi.mocked(confirmDecision);

/** localStorage key the settings store persists the session id under. */
const SESSION_STORAGE_KEY = 'admino_session_id';
/** Shape the backend accepts for a session id. */
const SESSION_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;

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

function makePending(
  overrides: Partial<PendingConfirmationSummary> = {},
): PendingConfirmationSummary {
  return {
    confirmation_id: 'c-1',
    tool: 'gmail',
    action: 'send',
    args: { to: 'boss@example.com', subject: 'Q3 report' },
    expires_at: '2026-09-25T12:05:00Z',
    ...overrides,
  };
}

function awaitingResponse(
  pending: PendingConfirmationSummary = makePending(),
  overrides: Partial<ChatResponse> = {},
): ChatResponse {
  return makeResponse({
    response: '',
    status: 'awaiting_confirmation',
    pending_confirmation: pending,
    ...overrides,
  });
}

/** The resumed run after approving `pending`: its tool call executed. */
function confirmedResponse(
  success: boolean,
  pending: PendingConfirmationSummary = makePending(),
  overrides: Partial<ChatResponse> = {},
): ChatResponse {
  return makeResponse({
    response: success ? 'Email sent to boss@example.com.' : 'Sending the email failed.',
    tool_calls: [
      makeRecord({
        tool: pending.tool,
        action: pending.action,
        permission: 'confirm',
        success,
        args: pending.args,
      }),
    ],
    ...overrides,
  });
}

function deniedResponse(pending: PendingConfirmationSummary = makePending()): ChatResponse {
  return makeResponse({
    response: `Action ${pending.tool}.${pending.action} was denied.`,
    tool_calls: [],
    status: 'final',
    pending_confirmation: null,
  });
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve: (value: T) => void = () => {};
  let reject: (reason: unknown) => void = () => {};
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

// --- Helpers --------------------------------------------------------------

/** Compact, order-preserving description of the thread for assertions. */
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

function toastKinds(): ToastKind[] {
  return useToastStore().toasts.map((t) => t.kind);
}

/** The thread's tool-call cards, in thread order (read straight from `thread`). */
function toolCalls(): ToolCallUI[] {
  return useChatStore().thread.flatMap((item) => (item.type === 'tool_call' ? [item.data] : []));
}

function findCard(id: string): ToolCallUI | undefined {
  return toolCalls().find((tc) => tc.id === id);
}

function indexOfCard(id: string): number {
  return useChatStore().thread.findIndex((i) => i.type === 'tool_call' && i.data.id === id);
}

/** Send a message whose response asks for confirmation; return the pending card. */
async function seedPendingCard(pending: PendingConfirmationSummary = makePending()): Promise<ToolCallUI> {
  mockedPostMessage.mockResolvedValueOnce(awaitingResponse(pending));
  const chat = useChatStore();
  await chat.sendMessage('Email the Q3 report to my boss');
  const card = chat.pendingConfirmation;
  if (!card) throw new Error('test setup: expected a pending confirmation card');
  return card;
}

beforeEach(() => {
  localStorage.clear();
  setActivePinia(createPinia());
  mockedPostMessage.mockReset();
  mockedConfirmDecision.mockReset();
  // The connection store starts 'offline' and ignores setters while offline.
  useConnectionStore().state = 'idle';
});

afterEach(() => {
  setLocale('en');
});

// --- Send flow ------------------------------------------------------------

describe('chatStore sendMessage', () => {
  it('appends the user message with the exact content', async () => {
    mockedPostMessage.mockResolvedValueOnce(makeResponse());
    const chat = useChatStore();

    await chat.sendMessage('  Summarize my **inbox**  ');

    expect(summarize(chat.thread)[0]).toBe('user:  Summarize my **inbox**  ');
  });

  it('calls postMessage once with the content and the session id', async () => {
    mockedPostMessage.mockResolvedValueOnce(makeResponse());
    const chat = useChatStore();
    const sessionId = useSettingsStore().sessionId;

    await chat.sendMessage('What is on my calendar today?');

    expect(mockedPostMessage).toHaveBeenCalledTimes(1);
    expect(mockedPostMessage).toHaveBeenCalledWith('What is on my calendar today?', sessionId);
  });

  it('shows thinking, sets sending and connection working while the request is in flight', async () => {
    const request = deferred<ChatResponse>();
    mockedPostMessage.mockReturnValueOnce(request.promise);
    const chat = useChatStore();

    const sent = chat.sendMessage('Hello');

    expect(summarize(chat.thread)).toEqual(['user:Hello', 'thinking']);
    expect(chat.sending).toBe(true);
    expect(useConnectionStore().state).toBe('working');

    request.resolve(makeResponse({ response: 'Hi there.' }));
    await sent;
  });

  it('replaces thinking with the agent reply, clears sending and goes idle on a final response', async () => {
    const request = deferred<ChatResponse>();
    mockedPostMessage.mockReturnValueOnce(request.promise);
    const chat = useChatStore();
    const sent = chat.sendMessage('Hello');

    request.resolve(makeResponse({ response: 'Hi there.', status: 'final' }));
    await sent;

    expect(summarize(chat.thread)).toEqual(['user:Hello', 'agent:Hi there.']);
    expect(chat.sending).toBe(false);
    expect(useConnectionStore().state).toBe('idle');
  });

  it.each(['', '   ', '\n\t  '])('ignores empty or whitespace-only content %j', async (content) => {
    const chat = useChatStore();

    await chat.sendMessage(content);

    expect(mockedPostMessage).not.toHaveBeenCalled();
    expect(chat.thread).toEqual([]);
  });

  it('ignores a second send while a request is in flight', async () => {
    const request = deferred<ChatResponse>();
    mockedPostMessage.mockReturnValueOnce(request.promise);
    const chat = useChatStore();

    const first = chat.sendMessage('First');
    await chat.sendMessage('Second');
    request.resolve(makeResponse({ response: 'Reply to first.' }));
    await first;

    expect(mockedPostMessage).toHaveBeenCalledTimes(1);
    expect(summarize(chat.thread)).toEqual(['user:First', 'agent:Reply to first.']);
  });
});

// --- Receiving responses / thread ordering --------------------------------

describe('chatStore response handling', () => {
  it('orders user message, tool calls, pending card, then agent message', async () => {
    mockedPostMessage.mockResolvedValueOnce(
      makeResponse({
        response: 'I drafted the reply — approve to send it.',
        status: 'awaiting_confirmation',
        tool_calls: [
          makeRecord({ tool: 'gmail', action: 'search', success: true }),
          makeRecord({ tool: 'google_drive', action: 'download', success: false }),
        ],
        pending_confirmation: makePending(),
      }),
    );
    const chat = useChatStore();

    await chat.sendMessage('Reply to my boss with the Q3 report');

    expect(summarize(chat.thread)).toEqual([
      'user:Reply to my boss with the Q3 report',
      'tool:gmail.search:completed',
      'tool:google_drive.download:error',
      'tool:gmail.send:pending',
      'agent:I drafted the reply — approve to send it.',
    ]);
  });

  it('maps a successful tool call to completed with tool, action, args and duration', async () => {
    mockedPostMessage.mockResolvedValueOnce(
      makeResponse({
        tool_calls: [
          makeRecord({
            tool: 'google_calendar',
            action: 'list',
            success: true,
            args: { date: '2026-09-25', max_results: 10 },
            duration_ms: 137,
          }),
        ],
      }),
    );
    const chat = useChatStore();

    await chat.sendMessage('What is on today?');

    expect(toolCalls()[0]).toMatchObject({
      tool: 'google_calendar',
      action: 'list',
      args: { date: '2026-09-25', max_results: 10 },
      durationMs: 137,
      state: 'completed',
    });
  });

  it('maps a failed tool call to error', async () => {
    mockedPostMessage.mockResolvedValueOnce(
      makeResponse({ tool_calls: [makeRecord({ success: false })] }),
    );
    const chat = useChatStore();

    await chat.sendMessage('Search my mail');

    expect(toolCalls()[0].state).toBe('error');
  });

  it('adds a pending card carrying the confirmation id and expiry', async () => {
    await seedPendingCard(
      makePending({ confirmation_id: 'c-42', expires_at: '2026-09-25T13:00:00Z' }),
    );

    expect(toolCalls()[0]).toMatchObject({
      tool: 'gmail',
      action: 'send',
      state: 'pending',
      confirmationId: 'c-42',
      expiresAt: '2026-09-25T13:00:00Z',
    });
  });

  it('sets the connection to awaiting when the response awaits confirmation', async () => {
    await seedPendingCard();

    expect(useConnectionStore().state).toBe('awaiting');
  });

  it('exposes the pending card via pendingConfirmation', async () => {
    const chat = useChatStore();

    await seedPendingCard(makePending({ confirmation_id: 'c-7' }));

    expect(chat.pendingConfirmation?.confirmationId).toBe('c-7');
  });

  it('pendingConfirmation returns the most recent of several pending cards', async () => {
    const chat = useChatStore();
    await seedPendingCard(makePending({ confirmation_id: 'c-older' }));
    await seedPendingCard(makePending({ confirmation_id: 'c-newer', action: 'draft' }));

    expect(chat.pendingConfirmation?.confirmationId).toBe('c-newer');
  });

  it('keeps items in chronological order across multiple sends', async () => {
    mockedPostMessage
      .mockResolvedValueOnce(
        makeResponse({ response: 'You have 3 unread.', tool_calls: [makeRecord()] }),
      )
      .mockResolvedValueOnce(
        makeResponse({
          response: 'Found it.',
          tool_calls: [makeRecord({ tool: 'google_drive', action: 'search' })],
        }),
      );
    const chat = useChatStore();

    await chat.sendMessage('Any unread mail?');
    await chat.sendMessage('Find the Q3 report');

    expect(summarize(chat.thread)).toEqual([
      'user:Any unread mail?',
      'tool:gmail.search:completed',
      'agent:You have 3 unread.',
      'user:Find the Q3 report',
      'tool:google_drive.search:completed',
      'agent:Found it.',
    ]);
  });
});

// --- Activity page removed (issue #15) ------------------------------------

describe('chatStore without the Activity page', () => {
  it('no longer exposes toolCallHistory (its only consumer, the Activity page, is gone)', () => {
    expect('toolCallHistory' in useChatStore()).toBe(false);
  });
});

// --- Clearing the thread starts a new session (issue #141) ----------------

describe('chatStore clearThread', () => {
  it('clearThread empties the thread', async () => {
    mockedPostMessage.mockResolvedValueOnce(makeResponse({ tool_calls: [makeRecord()] }));
    const chat = useChatStore();
    await chat.sendMessage('Search my mail');

    chat.clearThread();

    expect(chat.thread).toEqual([]);
  });

  it('rotates the session id to a new, valid id', async () => {
    mockedPostMessage.mockResolvedValueOnce(makeResponse());
    const chat = useChatStore();
    const settings = useSettingsStore();
    const before = settings.sessionId;
    await chat.sendMessage('Search my mail');

    chat.clearThread();

    expect(settings.sessionId).not.toBe(before);
    expect(settings.sessionId).toMatch(SESSION_ID_RE);
  });

  it('persists the rotated session id to localStorage', async () => {
    mockedPostMessage.mockResolvedValueOnce(makeResponse());
    const chat = useChatStore();
    const settings = useSettingsStore();
    const before = settings.sessionId;
    await chat.sendMessage('Search my mail');

    chat.clearThread();

    const stored = localStorage.getItem(SESSION_STORAGE_KEY);
    expect(stored).not.toBe(before);
    expect(stored).toBe(settings.sessionId);
  });

  it('does not bring the old session back after a reload', async () => {
    mockedPostMessage.mockResolvedValueOnce(makeResponse());
    const chat = useChatStore();
    const before = useSettingsStore().sessionId;
    await chat.sendMessage('Search my mail');
    chat.clearThread();
    const rotated = useSettingsStore().sessionId;

    // A page reload re-creates every store from localStorage.
    setActivePinia(createPinia());

    expect(useSettingsStore().sessionId).not.toBe(before);
    expect(useSettingsStore().sessionId).toBe(rotated);
  });

  it('sends the next message with the new session id, not the old one', async () => {
    mockedPostMessage
      .mockResolvedValueOnce(makeResponse({ response: 'You have 3 unread.' }))
      .mockResolvedValueOnce(makeResponse({ response: 'Hello again.' }));
    const chat = useChatStore();
    const settings = useSettingsStore();
    const sessionA = settings.sessionId;
    await chat.sendMessage('Any unread mail?');

    chat.clearThread();
    await chat.sendMessage('Start over');

    expect(mockedPostMessage).toHaveBeenCalledTimes(2);
    expect(mockedPostMessage).toHaveBeenNthCalledWith(1, 'Any unread mail?', sessionA);
    const [content, sessionUsed] = mockedPostMessage.mock.calls[1];
    expect(content).toBe('Start over');
    expect(sessionUsed).not.toBe(sessionA);
    expect(sessionUsed).toBe(settings.sessionId);
  });

  it('produces a distinct session id on every clear', async () => {
    mockedPostMessage.mockResolvedValueOnce(makeResponse());
    const chat = useChatStore();
    const settings = useSettingsStore();
    const seen = [settings.sessionId];
    await chat.sendMessage('Search my mail');

    for (let i = 0; i < 3; i++) {
      chat.clearThread();
      seen.push(settings.sessionId);
    }

    expect(new Set(seen).size).toBe(seen.length);
  });

  it('rotates the session id even when the thread is already empty', () => {
    const chat = useChatStore();
    const settings = useSettingsStore();
    const before = settings.sessionId;
    expect(chat.thread).toEqual([]);

    chat.clearThread();

    expect(settings.sessionId).not.toBe(before);
  });

  it.each([
    ['approve', true],
    ['deny', false],
  ] as const)(
    '%s on a confirmation obtained after the clear uses the new session id',
    async (decision, approved) => {
      mockedPostMessage.mockResolvedValueOnce(makeResponse({ response: 'You have 3 unread.' }));
      const chat = useChatStore();
      const settings = useSettingsStore();
      const sessionA = settings.sessionId;
      await chat.sendMessage('Any unread mail?');
      chat.clearThread();
      const card = await seedPendingCard(makePending({ confirmation_id: 'c-after-clear' }));
      mockedConfirmDecision.mockResolvedValueOnce(
        approved ? confirmedResponse(true) : deniedResponse(),
      );

      await chat[decision](card.id);

      expect(mockedConfirmDecision).toHaveBeenCalledTimes(1);
      const [sessionUsed, confirmationId, approvedFlag] = mockedConfirmDecision.mock.calls[0];
      expect(sessionUsed).not.toBe(sessionA);
      expect(sessionUsed).toBe(settings.sessionId);
      expect([confirmationId, approvedFlag]).toEqual(['c-after-clear', approved]);
    },
  );

  it('drops the reply to a message that was in flight when the thread was cleared', async () => {
    const request = deferred<ChatResponse>();
    mockedPostMessage.mockReturnValueOnce(request.promise);
    const chat = useChatStore();
    const sent = chat.sendMessage('Any unread mail?');

    chat.clearThread();
    request.resolve(
      makeResponse({ response: 'You have 3 unread.', tool_calls: [makeRecord()] }),
    );
    await sent;

    expect(chat.thread).toEqual([]);
    expect(chat.sending).toBe(false);
    expect(useConnectionStore().state).toBe('idle');
  });

  it('drops a confirmation request that arrives after the thread was cleared', async () => {
    const request = deferred<ChatResponse>();
    mockedPostMessage.mockReturnValueOnce(request.promise);
    const chat = useChatStore();
    const sent = chat.sendMessage('Email the Q3 report to my boss');

    chat.clearThread();
    request.resolve(awaitingResponse());
    await sent;

    expect(chat.thread).toEqual([]);
    expect(chat.pendingConfirmation).toBeNull();
    expect(useConnectionStore().state).toBe('idle');
  });

  it.each([
    ['approve', confirmedResponse(true)],
    ['deny', deniedResponse()],
  ] as const)(
    'drops the %s result that was in flight when the thread was cleared',
    async (decision, result) => {
      const card = await seedPendingCard();
      const confirm = deferred<ChatResponse>();
      mockedConfirmDecision.mockReturnValueOnce(confirm.promise);
      const chat = useChatStore();
      const decided = chat[decision](card.id);

      chat.clearThread();
      confirm.resolve(result);
      await decided;

      expect(chat.thread).toEqual([]);
      expect(useConnectionStore().state).toBe('idle');
    },
  );
});

// --- sendMessage errors ---------------------------------------------------

describe('chatStore sendMessage errors', () => {
  const failures: Array<[string, () => Error]> = [
    ['401 unauthenticated', () => new ApiError(401, 'Unauthorized')],
    ['429 rate limited', () => new ApiError(429, 'Too Many Requests')],
    ['500 internal error', () => new ApiError(500, 'Internal Server Error')],
    ['network failure', () => new TypeError('Failed to fetch')],
  ];

  it.each(failures)(
    'on %s removes thinking, clears sending, keeps the user message and adds no agent message',
    async (_label, makeError) => {
      mockedPostMessage.mockRejectedValueOnce(makeError());
      const chat = useChatStore();

      await chat.sendMessage('Hello');

      expect(summarize(chat.thread)).toEqual(['user:Hello']);
      expect(chat.sending).toBe(false);
    },
  );

  it.each(failures.slice(0, 3))(
    'on %s returns the connection to idle instead of leaving it working',
    async (_label, makeError) => {
      mockedPostMessage.mockRejectedValueOnce(makeError());

      await useChatStore().sendMessage('Hello');

      expect(useConnectionStore().state).toBe('idle');
    },
  );

  it('on 401 requires authentication and shows an error toast', async () => {
    mockedPostMessage.mockRejectedValueOnce(new ApiError(401, 'Unauthorized'));
    const settings = useSettingsStore();
    settings.needsAuth = false;

    await useChatStore().sendMessage('Hello');

    expect(settings.needsAuth).toBe(true);
    expect(toastKinds()).toContain('error');
  });

  it('on 429 shows a warning toast and keeps the connection online', async () => {
    mockedPostMessage.mockRejectedValueOnce(new ApiError(429, 'Too Many Requests'));

    await useChatStore().sendMessage('Hello');

    expect(toastKinds()).toContain('warning');
    expect(useConnectionStore().state).not.toBe('offline');
  });

  it('on a 500 shows an error toast', async () => {
    mockedPostMessage.mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'));

    await useChatStore().sendMessage('Hello');

    expect(toastKinds()).toContain('error');
  });

  it('on a network failure goes offline and shows an error toast', async () => {
    mockedPostMessage.mockRejectedValueOnce(new TypeError('Failed to fetch'));

    await useChatStore().sendMessage('Hello');

    expect(useConnectionStore().state).toBe('offline');
    expect(toastKinds()).toContain('error');
  });
});

// --- Toast copy follows the locale (issue #144) --------------------------

describe('chatStore toast copy follows the locale', () => {
  /** Title of the warning toast a rate-limited send produces under `locale`. */
  async function rateLimitedToastTitle(locale: string): Promise<string | undefined> {
    setLocale(locale);
    mockedPostMessage.mockRejectedValueOnce(new ApiError(429, 'Too Many Requests'));

    await useChatStore().sendMessage('Hello');

    return useToastStore().toasts.find((toast) => toast.kind === 'warning')?.title;
  }

  it('titles the 429 toast "Slow down" under en', async () => {
    expect(await rateLimitedToastTitle('en')).toBe('Slow down');
  });

  it('titles the 429 toast with the de catalog string under de', async () => {
    const title = await rateLimitedToastTitle('de');

    expect(title).not.toBe('Slow down');
    expect(Object.values(de)).toContain(title);
  });
});

// --- Approve: pending → approved → completed ------------------------------

describe('chatStore approve', () => {
  it('marks the card approved and the connection working before the confirm request resolves', async () => {
    const card = await seedPendingCard();
    const confirm = deferred<ChatResponse>();
    mockedConfirmDecision.mockReturnValueOnce(confirm.promise);

    const approved = useChatStore().approve(card.id);

    expect(findCard(card.id)?.state).toBe('approved');
    expect(useConnectionStore().state).toBe('working');

    confirm.resolve(confirmedResponse(true));
    await approved;
  });

  it('calls confirmDecision with the session id, confirmation id and approved=true', async () => {
    const card = await seedPendingCard(makePending({ confirmation_id: 'c-99' }));
    mockedConfirmDecision.mockResolvedValueOnce(confirmedResponse(true));

    await useChatStore().approve(card.id);

    expect(mockedConfirmDecision).toHaveBeenCalledTimes(1);
    expect(mockedConfirmDecision).toHaveBeenCalledWith(useSettingsStore().sessionId, 'c-99', true);
  });

  it('completes the same card without adding a duplicate when the confirmed call succeeds', async () => {
    const card = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(confirmedResponse(true));
    const chat = useChatStore();

    await chat.approve(card.id);

    expect(toolCalls().map((tc) => ({ id: tc.id, state: tc.state }))).toEqual([
      { id: card.id, state: 'completed' },
    ]);
  });

  it('marks the same card error when the confirmed call fails', async () => {
    const card = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(confirmedResponse(false));
    const chat = useChatStore();

    await chat.approve(card.id);

    expect(toolCalls().map((tc) => ({ id: tc.id, state: tc.state }))).toEqual([
      { id: card.id, state: 'error' },
    ]);
  });

  it('appends the follow-up agent message after the card', async () => {
    const card = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(confirmedResponse(true));
    const chat = useChatStore();

    await chat.approve(card.id);

    const last = chat.thread[chat.thread.length - 1];
    expect(summarize([last])).toEqual(['agent:Email sent to boss@example.com.']);
    expect(indexOfCard(card.id)).toBeLessThan(chat.thread.length - 1);
  });

  it('goes idle after a final confirm response', async () => {
    const card = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(confirmedResponse(true));

    await useChatStore().approve(card.id);

    expect(useConnectionStore().state).toBe('idle');
  });

  it('awaits again with a new pending card when the resumed run needs another confirmation', async () => {
    const card = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(
      confirmedResponse(true, makePending(), {
        response: '',
        status: 'awaiting_confirmation',
        pending_confirmation: makePending({
          confirmation_id: 'c-2',
          tool: 'google_calendar',
          action: 'create',
        }),
      }),
    );
    const chat = useChatStore();

    await chat.approve(card.id);

    expect(findCard(card.id)?.state).toBe('completed');
    expect(chat.pendingConfirmation?.confirmationId).toBe('c-2');
    expect(useConnectionStore().state).toBe('awaiting');
  });

  it('ignores an unknown id', async () => {
    await seedPendingCard();

    await useChatStore().approve('does-not-exist');

    expect(mockedConfirmDecision).not.toHaveBeenCalled();
  });

  it('ignores a card that is no longer pending', async () => {
    const card = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(deniedResponse());
    const chat = useChatStore();
    await chat.deny(card.id);

    await chat.approve(card.id);

    expect(mockedConfirmDecision).toHaveBeenCalledTimes(1);
    expect(findCard(card.id)?.state).toBe('denied');
  });

  it('calls confirmDecision only once when approve is called twice', async () => {
    const card = await seedPendingCard();
    const confirm = deferred<ChatResponse>();
    mockedConfirmDecision.mockReturnValue(confirm.promise);
    const chat = useChatStore();

    const first = chat.approve(card.id);
    const second = chat.approve(card.id);
    confirm.resolve(confirmedResponse(true));
    await Promise.all([first, second]);

    expect(mockedConfirmDecision).toHaveBeenCalledTimes(1);
  });

  it('on 410 marks the card expired with a warning toast', async () => {
    const card = await seedPendingCard();
    mockedConfirmDecision.mockRejectedValueOnce(new ApiError(410, 'Gone'));

    await useChatStore().approve(card.id);

    expect(findCard(card.id)).toMatchObject({ state: 'error', error: 'Expired' });
    expect(toastKinds()).toContain('warning');
  });

  it('on 429 returns the card to pending with a warning toast', async () => {
    const card = await seedPendingCard();
    mockedConfirmDecision.mockRejectedValueOnce(new ApiError(429, 'Too Many Requests'));

    await useChatStore().approve(card.id);

    expect(findCard(card.id)?.state).toBe('pending');
    expect(toastKinds()).toContain('warning');
  });

  it('lets the user retry approval after a 429', async () => {
    const card = await seedPendingCard();
    mockedConfirmDecision
      .mockRejectedValueOnce(new ApiError(429, 'Too Many Requests'))
      .mockResolvedValueOnce(confirmedResponse(true));
    const chat = useChatStore();
    await chat.approve(card.id);

    await chat.approve(card.id);

    expect(mockedConfirmDecision).toHaveBeenCalledTimes(2);
    expect(findCard(card.id)?.state).toBe('completed');
  });

  it('on another error marks the card error with an error toast', async () => {
    const card = await seedPendingCard();
    mockedConfirmDecision.mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'));

    await useChatStore().approve(card.id);

    expect(findCard(card.id)?.state).toBe('error');
    expect(toastKinds()).toContain('error');
  });

  it.each([
    ['410 expired', () => new ApiError(410, 'Gone')],
    ['429 rate limited', () => new ApiError(429, 'Too Many Requests')],
    ['500 internal error', () => new ApiError(500, 'Internal Server Error')],
  ] as Array<[string, () => Error]>)('goes idle after a %s approve error', async (_label, makeError) => {
    const card = await seedPendingCard();
    mockedConfirmDecision.mockRejectedValueOnce(makeError());

    await useChatStore().approve(card.id);

    expect(useConnectionStore().state).toBe('idle');
  });
});

// --- Deny: pending → denied -----------------------------------------------

describe('chatStore deny', () => {
  it('marks the card denied before the confirm request resolves', async () => {
    const card = await seedPendingCard();
    const confirm = deferred<ChatResponse>();
    mockedConfirmDecision.mockReturnValueOnce(confirm.promise);

    const denied = useChatStore().deny(card.id);

    expect(findCard(card.id)?.state).toBe('denied');

    confirm.resolve(deniedResponse());
    await denied;
  });

  it('calls confirmDecision with the session id, confirmation id and approved=false', async () => {
    const card = await seedPendingCard(makePending({ confirmation_id: 'c-13' }));
    mockedConfirmDecision.mockResolvedValueOnce(deniedResponse());

    await useChatStore().deny(card.id);

    expect(mockedConfirmDecision).toHaveBeenCalledTimes(1);
    expect(mockedConfirmDecision).toHaveBeenCalledWith(useSettingsStore().sessionId, 'c-13', false);
  });

  it('appends the denial message after the card and keeps the card denied', async () => {
    const card = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(deniedResponse());
    const chat = useChatStore();

    await chat.deny(card.id);

    expect(summarize(chat.thread)).toEqual([
      'user:Email the Q3 report to my boss',
      'tool:gmail.send:denied',
      'agent:Action gmail.send was denied.',
    ]);
  });

  it('goes idle and clears pendingConfirmation after denying', async () => {
    const card = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(deniedResponse());
    const chat = useChatStore();

    await chat.deny(card.id);

    expect(useConnectionStore().state).toBe('idle');
    expect(chat.pendingConfirmation).toBeNull();
  });

  it('ignores a card that is no longer pending', async () => {
    const card = await seedPendingCard();
    mockedConfirmDecision.mockResolvedValueOnce(confirmedResponse(true));
    const chat = useChatStore();
    await chat.approve(card.id);

    await chat.deny(card.id);

    expect(mockedConfirmDecision).toHaveBeenCalledTimes(1);
    expect(findCard(card.id)?.state).toBe('completed');
  });

  it('on 410 shows an info toast and keeps the card denied', async () => {
    const card = await seedPendingCard();
    mockedConfirmDecision.mockRejectedValueOnce(new ApiError(410, 'Gone'));

    await useChatStore().deny(card.id);

    expect(toastKinds()).toContain('info');
    expect(findCard(card.id)?.state).toBe('denied');
  });
});
