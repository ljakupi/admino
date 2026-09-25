/**
 * ToolCallCard tests (issue #21).
 *
 * Covers the approve/deny actions offered for a pending tool call, the status
 * label per state, the pending → approved and pending → denied transitions
 * (standalone and wired to the real chat store the way ChatPage wires it), and
 * that LLM-supplied tool args render as text. Behavior only — no styling.
 * The network layer (`@/api/messages`) is mocked.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import { createPinia, setActivePinia, type Pinia } from 'pinia';
import { computed, defineComponent, h } from 'vue';
import ToolCallCard from '@/components/ToolCallCard.vue';
import StatusBadge from '@/components/StatusBadge.vue';
import { postMessage, confirmDecision } from '@/api/messages';
import { useChatStore } from '@/stores/chat';
import type { ChatResponse, ToolCallState, ToolCallUI } from '@/api/types';

vi.mock('@/api/messages', () => ({
  postMessage: vi.fn(),
  confirmDecision: vi.fn(),
}));

const mockedPostMessage = vi.mocked(postMessage);
const mockedConfirmDecision = vi.mocked(confirmDecision);

function makeToolCall(overrides: Partial<ToolCallUI> = {}): ToolCallUI {
  return {
    id: 'tc-1',
    tool: 'gmail',
    action: 'send',
    args: { to: 'boss@example.com', subject: 'Q3 report' },
    state: 'pending',
    confirmationId: 'c-1',
    expiresAt: '2026-09-25T12:05:00Z',
    timestamp: new Date(),
    ...overrides,
  };
}

function mountCard(toolCall: ToolCallUI, readonly?: boolean) {
  return mount(ToolCallCard, { props: { toolCall, readonly } });
}

/** Anything rendered — a bare card or a harness wrapping one. */
type Rendered = Pick<ReturnType<typeof mountCard>, 'findAll' | 'findComponent'>;

function buttonsLabelled(wrapper: Rendered, label: 'Approve' | 'Deny') {
  return wrapper.findAll('button').filter((b) => b.text().includes(label));
}

function statusLabel(wrapper: Rendered): string {
  return wrapper.findComponent(StatusBadge).text();
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve: (value: T) => void = () => {};
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

describe('ToolCallCard pending actions', () => {
  it('offers Approve and Deny buttons on a pending card', () => {
    const wrapper = mountCard(makeToolCall());

    expect(buttonsLabelled(wrapper, 'Approve')).toHaveLength(1);
    expect(buttonsLabelled(wrapper, 'Deny')).toHaveLength(1);
  });

  it('emits approve once, and not deny, when Approve is clicked', async () => {
    const wrapper = mountCard(makeToolCall());

    await buttonsLabelled(wrapper, 'Approve')[0].trigger('click');

    expect(wrapper.emitted('approve')).toHaveLength(1);
    expect(wrapper.emitted('deny')).toBeUndefined();
  });

  it('emits deny once, and not approve, when Deny is clicked', async () => {
    const wrapper = mountCard(makeToolCall());

    await buttonsLabelled(wrapper, 'Deny')[0].trigger('click');

    expect(wrapper.emitted('deny')).toHaveLength(1);
    expect(wrapper.emitted('approve')).toBeUndefined();
  });
});

describe('ToolCallCard status label', () => {
  it.each([
    ['pending', 'Awaiting approval'],
    ['approved', 'Approved'],
    ['completed', 'Approved'],
    ['denied', 'Denied'],
    ['error', 'Denied'],
  ] as Array<[ToolCallState, string]>)('labels a %s card "%s"', (state, label) => {
    const wrapper = mountCard(makeToolCall({ state }));

    expect(statusLabel(wrapper)).toBe(label);
  });
});

describe('ToolCallCard state transitions', () => {
  it('pending → approve click → approved shows "Approved" and no action buttons', async () => {
    const toolCall = makeToolCall();
    const wrapper = mountCard(toolCall);

    await buttonsLabelled(wrapper, 'Approve')[0].trigger('click');
    await wrapper.setProps({ toolCall: { ...toolCall, state: 'approved' } });

    expect(statusLabel(wrapper)).toBe('Approved');
    expect(wrapper.findAll('button').filter((b) => /Approve|Deny/.test(b.text()))).toEqual([]);
  });

  it('pending → deny click → denied shows "Denied" and no action buttons', async () => {
    const toolCall = makeToolCall();
    const wrapper = mountCard(toolCall);

    await buttonsLabelled(wrapper, 'Deny')[0].trigger('click');
    await wrapper.setProps({ toolCall: { ...toolCall, state: 'denied' } });

    expect(statusLabel(wrapper)).toBe('Denied');
    expect(wrapper.findAll('button').filter((b) => /Approve|Deny/.test(b.text()))).toEqual([]);
  });
});

describe('ToolCallCard wired to the chat store', () => {
  let pinia: Pinia;

  beforeEach(() => {
    localStorage.clear();
    pinia = createPinia();
    setActivePinia(pinia);
    mockedPostMessage.mockReset();
    mockedConfirmDecision.mockReset();
  });

  /** Seed the real chat store with a pending card via an awaiting response. */
  async function seedPendingCard(): Promise<string> {
    const awaiting: ChatResponse = {
      session_id: 's-test',
      response: '',
      tool_calls: [],
      status: 'awaiting_confirmation',
      pending_confirmation: {
        confirmation_id: 'c-1',
        tool: 'gmail',
        action: 'send',
        args: { to: 'boss@example.com', subject: 'Q3 report' },
        expires_at: '2026-09-25T12:05:00Z',
      },
    };
    mockedPostMessage.mockResolvedValueOnce(awaiting);
    const chat = useChatStore();
    await chat.sendMessage('Email the Q3 report to my boss');
    const card = chat.pendingConfirmation;
    if (!card) throw new Error('test setup: expected a pending confirmation card');
    return card.id;
  }

  /** Mirrors ChatPage: @approve → chatStore.approve(id), @deny → chatStore.deny(id). */
  function mountBoundCard(id: string) {
    const Harness = defineComponent({
      setup() {
        const chat = useChatStore();
        const toolCall = computed(() => chat.toolCallHistory.find((tc) => tc.id === id));
        return () =>
          toolCall.value
            ? h(ToolCallCard, {
                toolCall: toolCall.value,
                onApprove: () => void chat.approve(id),
                onDeny: () => void chat.deny(id),
              })
            : null;
      },
    });
    return mount(Harness, { global: { plugins: [pinia] } });
  }

  function storeState(id: string): ToolCallState | undefined {
    return useChatStore().toolCallHistory.find((tc) => tc.id === id)?.state;
  }

  it('approve click shows "Approved" without actions while in flight, then the card completes', async () => {
    const id = await seedPendingCard();
    const confirm = deferred<ChatResponse>();
    mockedConfirmDecision.mockReturnValueOnce(confirm.promise);
    const wrapper = mountBoundCard(id);

    await buttonsLabelled(wrapper, 'Approve')[0].trigger('click');

    expect(statusLabel(wrapper)).toBe('Approved');
    expect(buttonsLabelled(wrapper, 'Approve')).toEqual([]);
    expect(buttonsLabelled(wrapper, 'Deny')).toEqual([]);

    confirm.resolve({
      session_id: 's-test',
      response: 'Email sent to boss@example.com.',
      tool_calls: [
        {
          tool: 'gmail',
          action: 'send',
          permission: 'confirm',
          success: true,
          args: { to: 'boss@example.com', subject: 'Q3 report' },
          duration_ms: 310,
        },
      ],
      status: 'final',
      pending_confirmation: null,
    });
    await flushPromises();

    expect(storeState(id)).toBe('completed');
  });

  it('deny click shows "Denied" without actions and the store card is denied', async () => {
    const id = await seedPendingCard();
    const confirm = deferred<ChatResponse>();
    mockedConfirmDecision.mockReturnValueOnce(confirm.promise);
    const wrapper = mountBoundCard(id);

    await buttonsLabelled(wrapper, 'Deny')[0].trigger('click');

    expect(statusLabel(wrapper)).toBe('Denied');
    expect(buttonsLabelled(wrapper, 'Approve')).toEqual([]);
    expect(buttonsLabelled(wrapper, 'Deny')).toEqual([]);

    confirm.resolve({
      session_id: 's-test',
      response: 'Action gmail.send was denied.',
      tool_calls: [],
      status: 'final',
      pending_confirmation: null,
    });
    await flushPromises();

    expect(storeState(id)).toBe('denied');
    expect(buttonsLabelled(wrapper, 'Approve')).toEqual([]);
    expect(buttonsLabelled(wrapper, 'Deny')).toEqual([]);
  });
});

describe('ToolCallCard read-only and resolved cards', () => {
  it('shows no Approve/Deny buttons on a readonly pending card', () => {
    const wrapper = mountCard(makeToolCall({ state: 'pending' }), true);

    expect(buttonsLabelled(wrapper, 'Approve')).toEqual([]);
    expect(buttonsLabelled(wrapper, 'Deny')).toEqual([]);
  });

  it.each(['completed', 'error'] as ToolCallState[])(
    'never shows Approve/Deny buttons on a %s card',
    (state) => {
      const wrapper = mountCard(makeToolCall({ state }));

      expect(buttonsLabelled(wrapper, 'Approve')).toEqual([]);
      expect(buttonsLabelled(wrapper, 'Deny')).toEqual([]);
    },
  );

  it('shows the error message on an error card', () => {
    const wrapper = mountCard(makeToolCall({ state: 'error', error: 'Expired' }));

    expect(wrapper.text()).toContain('Expired');
  });
});

describe('ToolCallCard tool args', () => {
  it('renders an HTML-looking arg value as text, not as an element', () => {
    const payload = '<img src=x onerror=alert(1)>';
    const wrapper = mountCard(makeToolCall({ args: { body: payload } }));

    expect(wrapper.find('img').exists()).toBe(false);
    expect(wrapper.text()).toContain(payload);
  });
});
