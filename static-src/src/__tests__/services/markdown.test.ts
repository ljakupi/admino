/**
 * Markdown rendering service tests (issue #21).
 *
 * `renderMarkdown` turns agent output (untrusted LLM text) into sanitized HTML.
 * These tests assert on the returned HTML string — the service's output — never
 * on how a component displays it. The sanitization cases are security-critical.
 */
import { describe, it, expect } from 'vitest';
import { renderMarkdown } from '@/services/markdown';

/** Parse the service output so assertions can query elements and attributes. */
function parse(markdown: string): HTMLElement {
  const container = document.createElement('div');
  container.innerHTML = renderMarkdown(markdown);
  return container;
}

function allElements(root: HTMLElement): Element[] {
  return Array.from(root.querySelectorAll('*'));
}

function attributeNames(root: HTMLElement, predicate: (name: string) => boolean): string[] {
  return allElements(root).flatMap((el) =>
    Array.from(el.attributes)
      .map((attr) => attr.name)
      .filter(predicate),
  );
}

/** Hrefs using a scheme that can run script or smuggle a document. */
function unsafeSchemeHrefs(root: HTMLElement): string[] {
  return Array.from(root.querySelectorAll('a'))
    .map((a) => a.getAttribute('href') ?? '')
    .filter((href) => /^\s*(javascript|vbscript|data):/i.test(href));
}

describe('renderMarkdown formatting', () => {
  it('renders **bold** as <strong>', () => {
    expect(parse('This is **bold** text').querySelector('strong')?.textContent).toBe('bold');
  });

  it('renders *em* as <em>', () => {
    expect(parse('This is *em* text').querySelector('em')?.textContent).toBe('em');
  });

  it('renders # Title as <h1>', () => {
    expect(parse('# Title').querySelector('h1')?.textContent).toBe('Title');
  });

  it('renders a dash list as <ul> with one <li> per item', () => {
    const items = Array.from(parse('- a\n- b').querySelectorAll('ul > li'));

    expect(items.map((li) => li.textContent)).toEqual(['a', 'b']);
  });
});

describe('renderMarkdown code', () => {
  const fenced = ['```ts', 'const answer: number = 42;', '<div>x</div>', '```'].join('\n');

  it('renders a fenced code block as <pre><code> containing the code', () => {
    expect(parse(fenced).querySelector('pre > code')?.textContent).toContain(
      'const answer: number = 42;',
    );
  });

  it('keeps HTML inside a code block as text, not as an element', () => {
    const root = parse(fenced);

    expect(root.querySelector('pre div')).toBeNull();
    expect(root.querySelector('pre > code')?.textContent).toContain('<div>x</div>');
  });

  it('renders inline `code` as <code>', () => {
    expect(parse('Run `npm test` now').querySelector('code')?.textContent).toBe('npm test');
  });
});

describe('renderMarkdown links', () => {
  it('renders a markdown link as an anchor with the href and text', () => {
    const link = parse('See the [docs](https://example.com/path).').querySelector('a');

    expect(link?.getAttribute('href')).toBe('https://example.com/path');
    expect(link?.textContent).toBe('docs');
  });
});

describe('renderMarkdown sanitization of LLM output', () => {
  it('removes <script> elements', () => {
    const html = renderMarkdown('Hello <script>alert(1)</script> world');

    expect(html).not.toContain('<script');
  });

  it('removes <img> with an onerror handler', () => {
    const root = parse('Look: <img src=x onerror=alert(1)>');

    expect(root.querySelector('img')).toBeNull();
    expect(root.innerHTML).not.toContain('onerror');
  });

  it('removes <iframe> elements', () => {
    // about:blank, not a remote URL: happy-dom navigates iframes found while
    // DOMPurify parses, which would otherwise make a real network request.
    expect(parse('<iframe src="about:blank" title="embedded"></iframe>').querySelector('iframe')).toBeNull();
  });

  it('strips inline event handler attributes but keeps the safe content', () => {
    const root = parse(
      '<p onclick="alert(1)" onmouseover="alert(2)">hi</p>' +
        '<a href="https://example.com/" onclick="steal()">link</a>',
    );

    expect(attributeNames(root, (name) => name.toLowerCase().startsWith('on'))).toEqual([]);
    expect(root.textContent).toContain('hi');
  });

  it('strips style attributes', () => {
    const root = parse(
      '<p style="position:fixed;top:0">overlay</p><strong style="display:none">x</strong>',
    );

    expect(attributeNames(root, (name) => name === 'style')).toEqual([]);
  });

  it('strips data-* attributes', () => {
    const root = parse(
      '<p data-action="send" data-id="1">hi</p><a href="https://example.com/" data-x="y">l</a>',
    );

    expect(attributeNames(root, (name) => name.startsWith('data-'))).toEqual([]);
  });

  it('never lets a link open a new tab with access to window.opener', () => {
    // Reverse tabnabbing: a prompt-injected link opening a new tab must not
    // get a handle on the admino tab.
    const root = parse(
      '<a href="https://attacker.example/login" target="_blank">Continue</a>' +
        '<a href="https://attacker.example/2" target="_blank" rel="opener">Again</a>',
    );

    const exposed = Array.from(root.querySelectorAll('a[target]'))
      .filter((a) => {
        const rel = (a.getAttribute('rel') ?? '').toLowerCase().split(/\s+/);
        return !(rel.includes('noopener') && rel.includes('noreferrer'));
      })
      .map((a) => a.outerHTML);
    expect(exposed).toEqual([]);
  });

  it.each([
    ['a markdown javascript: link', '[x](javascript:alert(1))'],
    ['a raw javascript: anchor', '<a href="javascript:alert(1)">click me</a>'],
    ['a markdown data: link', '[x](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)'],
    ['a raw data: anchor', '<a href="data:text/html,<script>alert(1)</script>">x</a>'],
    ['a raw vbscript: anchor', '<a href="vbscript:msgbox(1)">x</a>'],
    ['an entity-encoded javascript: anchor', '<a href="javascript&#58;alert(1)">x</a>'],
    ['a mixed-case, whitespace-padded javascript: anchor', '<a href=" JaVaScRiPt:alert(1)">x</a>'],
  ])('does not keep an unsafe-scheme href from %s', (_label, markdown) => {
    expect(unsafeSchemeHrefs(parse(markdown))).toEqual([]);
  });

  it.each([
    ['<svg>', '<svg><script>alert(1)</script><a href="https://example.com/">x</a></svg>', 'svg'],
    ['<math> mutation XSS', '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>', 'math'],
    ['<form>', '<form action="https://attacker.example/"><button>go</button></form>', 'form'],
    ['<base>', '<base href="https://attacker.example/">text', 'base'],
  ])('removes %s markup', (_label, markdown, tag) => {
    const root = parse(markdown);

    expect(root.querySelector(tag)).toBeNull();
    expect(root.querySelector('script')).toBeNull();
    expect(root.querySelector('img')).toBeNull();
    expect(attributeNames(root, (name) => name.toLowerCase().startsWith('on'))).toEqual([]);
  });
});
