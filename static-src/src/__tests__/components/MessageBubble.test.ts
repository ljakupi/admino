/**
 * MessageBubble tests (issue #21).
 *
 * Agent messages are markdown rendered to sanitized HTML; user messages are
 * shown literally. Agent content is LLM output and therefore untrusted — the
 * sanitization cases here are security-critical. Assertions cover rendered
 * HTML semantics only (elements, text, attributes), never styling.
 */
import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import MessageBubble from '@/components/MessageBubble.vue';
import type { ChatMessage, MessageRole } from '@/api/types';

function renderMessage(content: string, role: MessageRole = 'agent') {
  const message: ChatMessage = { id: 'm-1', role, content, timestamp: new Date() };
  return mount(MessageBubble, { props: { message } });
}

type Rendered = ReturnType<typeof renderMessage>;

function allElements(wrapper: Rendered): Element[] {
  return Array.from(wrapper.element.querySelectorAll('*'));
}

/** Names of every `on*` attribute on any rendered element. */
function eventHandlerAttributes(wrapper: Rendered): string[] {
  return allElements(wrapper).flatMap((el) =>
    Array.from(el.attributes)
      .map((attr) => attr.name)
      .filter((name) => name.toLowerCase().startsWith('on')),
  );
}

function javascriptHrefs(wrapper: Rendered): string[] {
  return wrapper
    .findAll('a')
    .map((a) => a.attributes('href') ?? '')
    .filter((href) => href.trim().toLowerCase().startsWith('javascript:'));
}

/** Hrefs using a scheme that can run script or smuggle a document. */
function unsafeSchemeHrefs(wrapper: Rendered): string[] {
  return wrapper
    .findAll('a')
    .map((a) => a.attributes('href') ?? '')
    .filter((href) => /^\s*(javascript|vbscript|data):/i.test(href));
}

describe('MessageBubble agent markdown', () => {
  it('renders **bold** as <strong>', () => {
    const wrapper = renderMessage('This is **bold** text');

    expect(wrapper.find('strong').text()).toBe('bold');
  });

  it('renders *em* as <em>', () => {
    const wrapper = renderMessage('This is *em* text');

    expect(wrapper.find('em').text()).toBe('em');
  });

  it('renders # Title as <h1>', () => {
    const wrapper = renderMessage('# Title');

    expect(wrapper.find('h1').text()).toBe('Title');
  });

  it('renders a dash list as <ul> with one <li> per item', () => {
    const wrapper = renderMessage('- a\n- b');

    expect(wrapper.findAll('ul > li').map((li) => li.text())).toEqual(['a', 'b']);
  });
});

describe('MessageBubble agent code', () => {
  const fenced = ['```ts', 'const answer: number = 42;', '<div>x</div>', '```'].join('\n');

  it('renders a fenced code block as <pre><code> containing the code', () => {
    const wrapper = renderMessage(fenced);

    expect(wrapper.find('pre > code').text()).toContain('const answer: number = 42;');
  });

  it('shows HTML inside a code block as text, not as an element', () => {
    const wrapper = renderMessage(fenced);

    expect(wrapper.find('pre div').exists()).toBe(false);
    expect(wrapper.find('pre > code').text()).toContain('<div>x</div>');
  });

  it('renders inline `code` as <code>', () => {
    const wrapper = renderMessage('Run `npm test` now');

    expect(wrapper.find('code').text()).toBe('npm test');
  });
});

describe('MessageBubble agent links', () => {
  it('renders a markdown link as an anchor with the href and text', () => {
    const wrapper = renderMessage('See the [docs](https://example.com/path).');

    const link = wrapper.find('a');
    expect(link.attributes('href')).toBe('https://example.com/path');
    expect(link.text()).toBe('docs');
  });
});

describe('MessageBubble user messages', () => {
  it('shows markdown syntax literally instead of interpreting it', () => {
    const wrapper = renderMessage('please make this **x**', 'user');

    expect(wrapper.find('strong').exists()).toBe(false);
    expect(wrapper.text()).toContain('please make this **x**');
  });

  it('shows HTML literally instead of creating elements', () => {
    const wrapper = renderMessage('<b>hi</b> <img src=x onerror=alert(1)>', 'user');

    expect(wrapper.find('b').exists()).toBe(false);
    expect(wrapper.find('img').exists()).toBe(false);
    expect(wrapper.text()).toContain('<b>hi</b>');
  });
});

describe('MessageBubble sanitization of agent output', () => {
  it('removes <script> elements', () => {
    const wrapper = renderMessage('Hello <script>alert(1)</script> world');

    expect(wrapper.find('script').exists()).toBe(false);
    expect(wrapper.html()).not.toContain('<script');
  });

  it('removes <img> with an onerror handler', () => {
    const wrapper = renderMessage('Look: <img src=x onerror=alert(1)>');

    expect(wrapper.find('img').exists()).toBe(false);
    expect(eventHandlerAttributes(wrapper)).toEqual([]);
    expect(wrapper.html()).not.toContain('onerror');
  });

  it('does not produce a javascript: href from a markdown link', () => {
    const wrapper = renderMessage('[x](javascript:alert(1))');

    expect(javascriptHrefs(wrapper)).toEqual([]);
  });

  it('does not keep a javascript: href on a raw HTML anchor', () => {
    const wrapper = renderMessage('<a href="javascript:alert(1)">click me</a>');

    expect(javascriptHrefs(wrapper)).toEqual([]);
  });

  it('removes <iframe> elements', () => {
    // about:blank, not a remote URL: happy-dom navigates iframes found while
    // DOMPurify parses, which would otherwise make a real network request.
    const wrapper = renderMessage('<iframe src="about:blank" title="embedded"></iframe>');

    expect(wrapper.find('iframe').exists()).toBe(false);
  });

  it('strips inline event handler attributes but keeps the safe content', () => {
    const wrapper = renderMessage(
      '<p onclick="alert(1)" onmouseover="alert(2)">hi</p>' +
        '<a href="https://example.com/" onclick="steal()">link</a>',
    );

    expect(eventHandlerAttributes(wrapper)).toEqual([]);
    expect(wrapper.text()).toContain('hi');
  });

  it('strips style attributes', () => {
    const wrapper = renderMessage(
      '<p style="position:fixed;top:0">overlay</p><strong style="display:none">x</strong>',
    );

    expect(allElements(wrapper).filter((el) => el.hasAttribute('style'))).toEqual([]);
  });

  it('strips data-* attributes', () => {
    const wrapper = renderMessage('<p data-action="send" data-id="1">hi</p><a href="https://example.com/" data-x="y">l</a>');

    // Only the sanitized markdown output — Vue's own scoped-style `data-v-*`
    // attributes on the component's elements are not LLM content.
    const markdownElements = Array.from(
      wrapper.find('.markdown-block').element.querySelectorAll('*'),
    );
    const dataAttrs = markdownElements.flatMap((el) =>
      Array.from(el.attributes)
        .map((attr) => attr.name)
        .filter((name) => name.startsWith('data-')),
    );
    expect(dataAttrs).toEqual([]);
  });

  it('never lets a link open a new tab with access to window.opener', () => {
    // Reverse tabnabbing: a prompt-injected link opening a new tab must not
    // get a handle on the admino tab.
    const wrapper = renderMessage(
      '<a href="https://attacker.example/login" target="_blank">Continue</a>' +
        '<a href="https://attacker.example/2" target="_blank" rel="opener">Again</a>',
    );

    const exposed = wrapper
      .findAll('a[target]')
      .filter((a) => {
        const rel = (a.attributes('rel') ?? '').toLowerCase().split(/\s+/);
        return !(rel.includes('noopener') && rel.includes('noreferrer'));
      })
      .map((a) => a.html());
    expect(exposed).toEqual([]);
  });

  it.each([
    ['a markdown data: link', '[x](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)'],
    ['a raw data: anchor', '<a href="data:text/html,<script>alert(1)</script>">x</a>'],
    ['a raw vbscript: anchor', '<a href="vbscript:msgbox(1)">x</a>'],
    ['an entity-encoded javascript: anchor', '<a href="javascript&#58;alert(1)">x</a>'],
    ['a mixed-case, whitespace-padded javascript: anchor', '<a href=" JaVaScRiPt:alert(1)">x</a>'],
  ])('does not keep an unsafe-scheme href from %s', (_label, content) => {
    const wrapper = renderMessage(content);

    expect(unsafeSchemeHrefs(wrapper)).toEqual([]);
  });

  it.each([
    ['<svg>', '<svg><script>alert(1)</script><a href="https://example.com/">x</a></svg>', 'svg'],
    ['<math> mutation XSS', '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>', 'math'],
    ['<form>', '<form action="https://attacker.example/"><button>go</button></form>', 'form'],
    ['<base>', '<base href="https://attacker.example/">text', 'base'],
  ])('removes %s markup', (_label, content, tag) => {
    const wrapper = renderMessage(content);

    expect(wrapper.find(tag).exists()).toBe(false);
    expect(wrapper.find('script').exists()).toBe(false);
    expect(wrapper.find('img').exists()).toBe(false);
    expect(eventHandlerAttributes(wrapper)).toEqual([]);
  });
});
