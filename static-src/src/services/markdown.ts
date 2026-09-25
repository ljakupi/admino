import { marked } from 'marked';
import DOMPurify from 'dompurify';

/**
 * Render markdown from the agent (untrusted LLM output) to sanitized HTML.
 *
 * marked passes raw inline HTML through, so DOMPurify is the only XSS gate:
 * the allowlist keeps formatting, code, lists, tables and links, and drops
 * everything else. The result is safe to bind with `v-html`.
 */
export function renderMarkdown(content: string): string {
  const raw = marked.parse(content, { async: false }) as string;
  return DOMPurify.sanitize(raw, {
    ALLOWED_TAGS: [
      'p', 'br', 'strong', 'em', 'code', 'pre', 'ul', 'ol', 'li',
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'blockquote',
      'table', 'thead', 'tbody', 'tr', 'th', 'td', 'hr', 'span',
    ],
    // No `target`: an LLM-authored link opening a new tab could reach
    // window.opener (reverse tabnabbing). No `data-*`: unneeded attack surface.
    ALLOWED_ATTR: ['href', 'rel', 'class'],
    ALLOW_DATA_ATTR: false,
  });
}
