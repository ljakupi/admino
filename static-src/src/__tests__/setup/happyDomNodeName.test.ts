/**
 * Test-environment self-test for the happy-dom `nodeName` shim (GH-289, Decision 8).
 *
 * DOMPurify >= 3.4.8 names every node through the getter it captures from
 * `Node.prototype`. happy-dom 20.14.5's getter returns '' there, so the
 * sanitizer would let `<script>` through in tests while browsers strip it.
 * `setup/happyDomNodeName.ts` (registered through `test.setupFiles`) restores
 * browser behaviour. This file checks the environment the sanitizer tests run
 * in; it deliberately does not import the shim, so it fails when the setup
 * file is not registered.
 */
import { describe, it, expect } from 'vitest';
import DOMPurify from 'dompurify';

/** The `nodeName` getter as DOMPurify captures it: first own accessor from `Node.prototype` up. */
function capturedNodeNameGetter(): (this: unknown) => unknown {
  let proto: object | null = Node.prototype;
  while (proto !== null) {
    const getter = Object.getOwnPropertyDescriptor(proto, 'nodeName')?.get;
    if (getter !== undefined) {
      return getter as (this: unknown) => unknown;
    }
    proto = Object.getPrototypeOf(proto) as object | null;
  }
  throw new Error('no nodeName getter on the Node.prototype chain');
}

function nodeNameOf(node: Node): unknown {
  return capturedNodeNameGetter().call(node);
}

describe('happy-dom Node.prototype.nodeName getter', () => {
  it.each([
    ['script', 'SCRIPT'],
    ['div', 'DIV'],
  ])('names a <%s> element %s', (tag, expected) => {
    expect(nodeNameOf(document.createElement(tag))).toBe(expected);
  });

  it('names a text node #text', () => {
    expect(nodeNameOf(document.createTextNode('plain'))).toBe('#text');
  });

  it('names a form FORM when an <input name="nodeName"> clobbers form.nodeName', () => {
    const form = document.createElement('form');
    form.innerHTML = '<input name="nodeName">';
    const input = form.querySelector('input');
    // Browsers expose a form's named controls over its own properties
    // ([LegacyOverrideBuiltIns]), so `form.nodeName` is the input there.
    // happy-dom does not, so the shadowing is reproduced as an own property.
    Object.defineProperty(form, 'nodeName', { value: input, configurable: true });

    expect([input?.tagName, Object.is(form.nodeName, input), nodeNameOf(form)]).toEqual([
      'INPUT',
      true,
      'FORM',
    ]);
  });
});

/** Count the elements of the sanitized output that the assertions care about. */
function countElements(html: string): Record<string, number> {
  const container = document.createElement('div');
  container.innerHTML = html;
  return {
    p: container.querySelectorAll('p').length,
    script: container.querySelectorAll('script').length,
    img: container.querySelectorAll('img').length,
    onerror: container.querySelectorAll('[onerror]').length,
  };
}

describe('DOMPurify in the test environment', () => {
  it('removes <script> and onerror while keeping safe markup', () => {
    // Two payloads, not one: happy-dom's NodeIterator ends inside an element
    // removed during iteration, so a sibling after a removed <script> is
    // never visited (browsers continue with it).
    const scriptOutput = countElements(DOMPurify.sanitize('<p>ok</p><script>alert(1)</script>'));
    const imgOutput = countElements(DOMPurify.sanitize('<img src="x" onerror="alert(1)">'));

    expect({ scriptOutput, imgOutput }).toEqual({
      scriptOutput: { p: 1, script: 0, img: 0, onerror: 0 },
      imgOutput: { p: 0, script: 0, img: 1, onerror: 0 },
    });
  });
});
