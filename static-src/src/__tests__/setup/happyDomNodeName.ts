/**
 * Vitest setup: a browser-faithful `Node.prototype.nodeName` for happy-dom.
 *
 * Why: DOMPurify >= 3.4.8 hardens against DOM clobbering by reading each
 * node's name through the getter it captures from `Node.prototype`
 * (`lookupGetter(Node.prototype, 'nodeName')`) instead of `node.nodeName`.
 * In browsers that is the spec getter and returns an element's tag name.
 * happy-dom 20.14.5 (the newest release at the time) returns '' from its
 * `Node.prototype` getter and overrides `nodeName` only on subclasses such as
 * `Element.prototype`, so DOMPurify sees every tag as unnamed and `<script>`
 * survives sanitization in the test DOM. This is a test-environment defect,
 * not a browser one (GH-289, Decision 8).
 *
 * What: the `Node.prototype` accessor is replaced by one that calls the first
 * own `nodeName` getter on the node's prototype chain (for example
 * `Element.prototype`'s for an element), which is the node's own name, as in
 * browsers. It never reads `this.nodeName`: in browsers a `<form>` holding an
 * `<input name="nodeName">` returns that input from the instance property,
 * and resolving through it would undo the clobbering protection DOMPurify
 * adds.
 *
 * Safety: test-only, registered through `test.setupFiles` in vite.config.ts.
 * Feature-detected: nothing changes when the original getter already names a
 * div 'DIV' (or when the test file runs without a DOM). Idempotent: a second
 * run finds a working getter and stops.
 *
 * Remove this file and its `setupFiles` entry once happy-dom's
 * `Node.prototype` getter returns the node name.
 */

type NodeNameGetter = (this: unknown) => string;

function installNodeNameGetter(): void {
  if (typeof Node === 'undefined' || typeof document === 'undefined') {
    return;
  }
  const descriptor = Object.getOwnPropertyDescriptor(Node.prototype, 'nodeName');
  const original = descriptor?.get as NodeNameGetter | undefined;
  if (descriptor === undefined || original === undefined) {
    return;
  }
  if (original.call(document.createElement('div')) === 'DIV') {
    return;
  }

  const nodeName = function nodeName(this: unknown): string {
    if (typeof this === 'object' && this !== null) {
      // Start below the instance: an own (clobbered) property is never read.
      let proto = Object.getPrototypeOf(this) as object | null;
      while (proto !== null) {
        const own = Object.getOwnPropertyDescriptor(proto, 'nodeName')?.get as
          | NodeNameGetter
          | undefined;
        if (own !== undefined && own !== nodeName) {
          return own.call(this);
        }
        proto = Object.getPrototypeOf(proto) as object | null;
      }
    }
    return original.call(this);
  };

  Object.defineProperty(Node.prototype, 'nodeName', { ...descriptor, get: nodeName });
}

installNodeNameGetter();

export {};
