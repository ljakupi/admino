/**
 * admino PWA — application logic
 *
 * Responsibilities:
 * - Session management (generate + persist session_id in localStorage)
 * - Auth token management (prompt on first use, persist in localStorage)
 * - Send messages via POST /api/message
 * - Image upload: base64-encode and embed in message text
 * - SSE connection to GET /api/events for real-time streaming
 * - Render assistant markdown responses (inline parser — no external deps)
 * - Inline confirmation dialogs for `confirm` SSE events
 * - Push notifications via service worker on `done` SSE event
 * - PWA install prompt
 *
 * Security:
 * - User content is always set via textContent, never innerHTML.
 * - Assistant markdown output is rendered through a sanitizing parser that
 *   only produces a safe allowlist of DOM nodes — no innerHTML on raw strings.
 * - Auth token stored in localStorage under a generic key; never logged.
 */

'use strict';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const LS_SESSION_KEY = 'admino_session_id';
// SECURITY NOTE: The Bearer token is stored in localStorage, which is
// accessible to any JS on the same origin. This is an accepted risk for a
// local-only, single-user deployment where the primary threat is XSS — and
// this app prevents XSS via CSP ('self' only), textContent-only rendering,
// and a DOM-based markdown parser that never uses innerHTML on raw strings.
// Browser extensions with host permissions for this origin can also read
// localStorage. For higher-security deployments, consider server-side
// HttpOnly session cookies.
const LS_TOKEN_KEY   = 'admino_auth_token';

// ---------------------------------------------------------------------------
// Session & auth helpers
// ---------------------------------------------------------------------------

/**
 * Generate a random session ID: 16 hex chars prefixed with timestamp.
 * Result matches ^[a-zA-Z0-9_-]+$ (server pattern).
 */
function generateSessionId() {
  const ts   = Date.now().toString(36);
  const rand = Array.from(crypto.getRandomValues(new Uint8Array(8)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `s-${ts}-${rand}`;
}

/** Truncate a session ID for display — show only last 8 chars. */
function truncateSessionId(sid) {
  return sid.length > 8 ? '\u2026' + sid.slice(-8) : sid;
}

/** Load session_id from localStorage or generate+persist a new one. */
function loadSessionId() {
  let sid = localStorage.getItem(LS_SESSION_KEY);
  if (!sid || !/^[a-zA-Z0-9_-]{1,64}$/.test(sid)) {
    sid = generateSessionId();
    localStorage.setItem(LS_SESSION_KEY, sid);
  }
  return sid;
}

/** Load the Bearer token from localStorage (may be null). */
function loadToken() {
  return localStorage.getItem(LS_TOKEN_KEY);
}

/**
 * Validate and persist the Bearer token to localStorage.
 * Rejects tokens that are too short, too long, or contain non-printable chars.
 * Returns true if saved, false if invalid.
 *
 * @param {string|null} token
 * @returns {boolean}
 */
function saveToken(token) {
  if (!token) {
    localStorage.removeItem(LS_TOKEN_KEY);
    return true;
  }
  // Printable ASCII only, 8-512 chars. Prevents excessively long values that
  // would cause 431 errors and non-printable chars that could corrupt headers.
  if (token.length < 8 || token.length > 512 || !/^[\x21-\x7E]+$/.test(token)) {
    return false;
  }
  localStorage.setItem(LS_TOKEN_KEY, token);
  return true;
}

/** Build Authorization header value (or null if no token). */
function authHeader(token) {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// ---------------------------------------------------------------------------
// Minimal Markdown → DOM renderer (no innerHTML on unsanitized strings)
//
// Supported syntax: **bold**, *italic*, `inline code`, ```code blocks```,
// # headings (h1-h4), - / * unordered lists, 1. ordered lists,
// > blockquote, --- horizontal rule, [text](url) links, blank-line paragraphs.
//
// Implementation: tokenize line-by-line, build DOM nodes directly.
// All text is assigned via textContent — never innerHTML.
// ---------------------------------------------------------------------------

/**
 * Render a markdown string into a DocumentFragment.
 * Safe for insertion into the DOM without further sanitization.
 *
 * @param {string} text - Raw markdown text from the assistant.
 * @returns {DocumentFragment}
 */
function renderMarkdown(text) {
  const frag = document.createDocumentFragment();
  const wrapper = document.createElement('div');
  wrapper.className = 'md-content';
  frag.appendChild(wrapper);

  const lines = text.split('\n');
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block: ```[lang]
    if (line.startsWith('```')) {
      const pre  = document.createElement('pre');
      const code = document.createElement('code');
      pre.appendChild(code);
      i++;
      const codeLines = [];
      while (i < lines.length && !lines[i].startsWith('```')) {
        codeLines.push(lines[i]);
        i++;
      }
      i++; // consume closing ```
      code.textContent = codeLines.join('\n');
      wrapper.appendChild(pre);
      continue;
    }

    // Headings
    const headingMatch = line.match(/^(#{1,4})\s+(.+)$/);
    if (headingMatch) {
      const level = Math.min(headingMatch[1].length, 4);
      const h = document.createElement(`h${level}`);
      applyInlineMarkdown(h, headingMatch[2]);
      wrapper.appendChild(h);
      i++;
      continue;
    }

    // Horizontal rule
    if (/^[-*_]{3,}\s*$/.test(line)) {
      wrapper.appendChild(document.createElement('hr'));
      i++;
      continue;
    }

    // Blockquote
    if (line.startsWith('> ')) {
      const bq = document.createElement('blockquote');
      const bqLines = [];
      while (i < lines.length && lines[i].startsWith('> ')) {
        bqLines.push(lines[i].slice(2));
        i++;
      }
      applyInlineMarkdown(bq, bqLines.join(' '));
      wrapper.appendChild(bq);
      continue;
    }

    // Unordered list
    if (/^[-*+]\s/.test(line)) {
      const ul = document.createElement('ul');
      while (i < lines.length && /^[-*+]\s/.test(lines[i])) {
        const li = document.createElement('li');
        applyInlineMarkdown(li, lines[i].replace(/^[-*+]\s/, ''));
        ul.appendChild(li);
        i++;
      }
      wrapper.appendChild(ul);
      continue;
    }

    // Ordered list
    if (/^\d+\.\s/.test(line)) {
      const ol = document.createElement('ol');
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) {
        const li = document.createElement('li');
        applyInlineMarkdown(li, lines[i].replace(/^\d+\.\s/, ''));
        ol.appendChild(li);
        i++;
      }
      wrapper.appendChild(ol);
      continue;
    }

    // Blank line — paragraph separator (skip)
    if (line.trim() === '') {
      i++;
      continue;
    }

    // Paragraph — collect consecutive non-special lines
    const paraLines = [];
    while (
      i < lines.length &&
      lines[i].trim() !== '' &&
      !lines[i].startsWith('```') &&
      !lines[i].startsWith('#') &&
      !/^[-*+]\s/.test(lines[i]) &&
      !/^\d+\.\s/.test(lines[i]) &&
      !lines[i].startsWith('> ') &&
      !/^[-*_]{3,}\s*$/.test(lines[i])
    ) {
      paraLines.push(lines[i]);
      i++;
    }
    if (paraLines.length > 0) {
      const p = document.createElement('p');
      applyInlineMarkdown(p, paraLines.join(' '));
      wrapper.appendChild(p);
    }
  }

  return frag;
}

/**
 * Apply inline markdown (bold, italic, code, links) to a parent element.
 * Text is tokenized via regex, nodes appended directly — no innerHTML.
 *
 * @param {HTMLElement} parent
 * @param {string} text
 */
function applyInlineMarkdown(parent, text) {
  // Regex matches (in priority order):
  // 1. ```code```   (triple backtick)
  // 2. `code`       (inline code)
  // 3. **bold**
  // 4. __bold__
  // 5. *italic*
  // 6. _italic_
  // 7. [text](url)  (link — url validated below)
  const TOKEN_RE = /(`{3}[\s\S]*?`{3}|`[^`]+`|\*\*[^*]+\*\*|__[^_]+__|(?<!\*)\*(?!\*)([^*]+)\*(?!\*)|(?<!_)_(?!_)([^_]+)_(?!_)|\[([^\]]+)\]\((https?:\/\/[^)]{1,2000})\))/g;

  let lastIndex = 0;
  let match;

  while ((match = TOKEN_RE.exec(text)) !== null) {
    // Append any plain text before this match
    if (match.index > lastIndex) {
      parent.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
    }

    const token = match[0];

    if (token.startsWith('```') && token.endsWith('```')) {
      const code = document.createElement('code');
      code.textContent = token.slice(3, -3);
      parent.appendChild(code);
    } else if (token.startsWith('`') && token.endsWith('`')) {
      const code = document.createElement('code');
      code.textContent = token.slice(1, -1);
      parent.appendChild(code);
    } else if (token.startsWith('**') && token.endsWith('**')) {
      const strong = document.createElement('strong');
      strong.textContent = token.slice(2, -2);
      parent.appendChild(strong);
    } else if (token.startsWith('__') && token.endsWith('__')) {
      const strong = document.createElement('strong');
      strong.textContent = token.slice(2, -2);
      parent.appendChild(strong);
    } else if (token.startsWith('*') && token.endsWith('*')) {
      const em = document.createElement('em');
      em.textContent = token.slice(1, -1);
      parent.appendChild(em);
    } else if (token.startsWith('_') && token.endsWith('_')) {
      const em = document.createElement('em');
      em.textContent = token.slice(1, -1);
      parent.appendChild(em);
    } else if (token.startsWith('[')) {
      // Link: [text](url) — match groups 4 and 5
      const linkText = match[4];
      const linkUrl  = match[5];
      const a = document.createElement('a');
      a.textContent = linkText;
      // Only allow http/https (already enforced by regex but double-check)
      if (linkUrl && /^https?:\/\//i.test(linkUrl)) {
        a.href      = linkUrl;
        a.target    = '_blank';
        a.rel       = 'noopener noreferrer';
      }
      parent.appendChild(a);
    } else {
      parent.appendChild(document.createTextNode(token));
    }

    lastIndex = TOKEN_RE.lastIndex;
  }

  // Trailing plain text
  if (lastIndex < text.length) {
    parent.appendChild(document.createTextNode(text.slice(lastIndex)));
  }
}

// ---------------------------------------------------------------------------
// Time formatting
// ---------------------------------------------------------------------------

function formatTime(date) {
  return date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

/**
 * Append a message bubble to the messages list.
 *
 * @param {'user'|'assistant'|'system'} role
 * @param {string|DocumentFragment} content  - string for user/system (textContent), Fragment for assistant
 * @param {Array<{tool:string,action:string,permission:string,success:boolean}>} [toolCalls]
 * @returns {HTMLElement} The message element (for later mutation, e.g. adding confirm card)
 */
function appendMessage(role, content, toolCalls) {
  const msg = document.createElement('div');
  msg.className = `message ${role}`;
  msg.setAttribute('role', 'listitem');

  const bubble = document.createElement('div');
  bubble.className = 'bubble';

  if (role === 'assistant' && content instanceof DocumentFragment) {
    bubble.appendChild(content);
  } else {
    // User / system messages: plain text only
    const span = document.createElement('span');
    span.textContent = /** @type {string} */ (content);
    bubble.appendChild(span);
  }

  msg.appendChild(bubble);

  // Tool call badges
  if (toolCalls && toolCalls.length > 0) {
    const chips = document.createElement('div');
    chips.className = 'tool-calls';
    for (const tc of toolCalls) {
      const badge = document.createElement('span');
      const cls = tc.permission === 'confirm' ? 'confirm' : (tc.success ? 'success' : 'failure');
      badge.className = `tool-badge ${cls}`;
      badge.setAttribute('aria-label', `${tc.tool}.${tc.action} — ${cls}`);

      const dot = document.createElement('span');
      dot.className = 'tool-badge-dot';
      dot.setAttribute('aria-hidden', 'true');
      badge.appendChild(dot);
      badge.appendChild(document.createTextNode(`${tc.tool}.${tc.action}`));
      chips.appendChild(badge);
    }
    msg.appendChild(chips);
  }

  // Timestamp
  const ts = document.createElement('span');
  ts.className = 'message-time';
  ts.setAttribute('aria-label', `Sent at ${formatTime(new Date())}`);
  ts.textContent = formatTime(new Date());
  msg.appendChild(ts);

  const list = document.getElementById('messages');
  // Insert before the typing indicator placeholder
  const typing = document.getElementById('typing-indicator');
  list.insertBefore(msg, typing);

  scrollToBottom();
  return msg;
}

function scrollToBottom() {
  const list = document.getElementById('messages');
  list.scrollTop = list.scrollHeight;
}

/** Show the typing indicator. */
function showTyping() {
  document.getElementById('typing-indicator').classList.add('visible');
  scrollToBottom();
}

/** Hide the typing indicator. */
function hideTyping() {
  document.getElementById('typing-indicator').classList.remove('visible');
}

/** Show a transient toast message. */
function showToast(text, type = '') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast${type ? ` ${type}` : ''}`;
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'polite');
  toast.textContent = text;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 3500);
}

// ---------------------------------------------------------------------------
// Confirmation card
// ---------------------------------------------------------------------------

/**
 * Append an inline confirmation card to the message list.
 *
 * @param {string} confirmationId
 * @param {string} tool
 * @param {string} action
 * @param {string} sessionId
 * @param {string|null} token
 */
function appendConfirmCard(confirmationId, tool, action, sessionId, token) {
  const card = document.createElement('div');
  card.className = 'confirm-card';
  card.setAttribute('role', 'alertdialog');
  card.setAttribute('aria-label', `Confirmation required for ${tool}.${action}`);

  // Header
  const header = document.createElement('div');
  header.className = 'confirm-header';

  // Warning icon (inline SVG, decorative)
  const svgNS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(svgNS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  const triangle = document.createElementNS(svgNS, 'path');
  triangle.setAttribute('d', 'M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z');
  const line1 = document.createElementNS(svgNS, 'line');
  line1.setAttribute('x1', '12'); line1.setAttribute('y1', '9');
  line1.setAttribute('x2', '12'); line1.setAttribute('y2', '13');
  const line2 = document.createElementNS(svgNS, 'line');
  line2.setAttribute('x1', '12'); line2.setAttribute('y1', '17');
  line2.setAttribute('x2', '12.01'); line2.setAttribute('y2', '17');
  svg.appendChild(triangle);
  svg.appendChild(line1);
  svg.appendChild(line2);
  header.appendChild(svg);
  header.appendChild(document.createTextNode('Confirmation required'));
  card.appendChild(header);

  // Body
  const body = document.createElement('div');
  body.className = 'confirm-body';
  body.appendChild(document.createTextNode('Allow action '));
  const codeEl = document.createElement('code');
  codeEl.textContent = `${tool}.${action}`;
  body.appendChild(codeEl);
  body.appendChild(document.createTextNode('?'));
  card.appendChild(body);

  // Buttons
  const actions = document.createElement('div');
  actions.className = 'confirm-actions';

  const approveBtn = document.createElement('button');
  approveBtn.className = 'btn btn-approve';
  approveBtn.textContent = 'Approve';
  approveBtn.setAttribute('aria-label', `Approve ${tool}.${action}`);

  const denyBtn = document.createElement('button');
  denyBtn.className = 'btn btn-deny';
  denyBtn.textContent = 'Deny';
  denyBtn.setAttribute('aria-label', `Deny ${tool}.${action}`);

  actions.appendChild(approveBtn);
  actions.appendChild(denyBtn);
  card.appendChild(actions);

  async function handleConfirm(approved) {
    approveBtn.disabled = true;
    denyBtn.disabled    = true;
    showTyping();

    try {
      const response = await sendConfirm(confirmationId, sessionId, approved, token);
      hideTyping();
      card.remove();

      const fragment = renderMarkdown(response.response || (approved ? 'Action approved.' : 'Action denied.'));
      appendMessage('assistant', fragment, response.tool_calls || []);
    } catch (err) {
      hideTyping();
      showToast(err.message || 'Confirmation failed.', 'error');
      approveBtn.disabled = false;
      denyBtn.disabled    = false;
    }
  }

  approveBtn.addEventListener('click', () => handleConfirm(true));
  denyBtn.addEventListener('click',   () => handleConfirm(false));

  const list = document.getElementById('messages');
  const typing = document.getElementById('typing-indicator');
  list.insertBefore(card, typing);
  scrollToBottom();
  approveBtn.focus();
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

/** Maximum message length matching the server's Pydantic constraint. */
const MAX_MESSAGE_LENGTH = 32768;

/**
 * POST /api/message
 *
 * @param {string} message
 * @param {string} sessionId
 * @param {string|null} token
 * @param {string|null} [imageDataUrl] - base64 data URL to embed in message
 * @returns {Promise<{session_id:string, response:string, tool_calls:Array}>}
 */
async function sendMessage(message, sessionId, token, imageDataUrl) {
  let finalMessage = message;

  if (imageDataUrl) {
    // Embed base64 image reference in message; server/agent handles OCR.
    finalMessage = `${message}\n\n[IMAGE_DATA:${imageDataUrl}]`;

    // Guard: reject client-side if the combined message exceeds the server's
    // max_message_length. Prevents a silent 422 after the UI has already
    // cleared the input and image preview.
    if (finalMessage.length > MAX_MESSAGE_LENGTH) {
      throw new Error(
        `Image is too large to send (message would be ${finalMessage.length} chars, ` +
        `limit is ${MAX_MESSAGE_LENGTH}). Try a smaller or more compressed image.`
      );
    }
  }

  const res = await fetch('/api/message', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...authHeader(token),
    },
    body: JSON.stringify({
      message: finalMessage,
      session_id: sessionId,
    }),
  });

  if (res.status === 401) {
    throw new AuthError('Invalid or missing auth token. Update it in Settings.');
  }
  if (res.status === 429) {
    throw new Error('Rate limit exceeded. Please wait a moment before sending again.');
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.detail || `Server error ${res.status}`);
  }

  return res.json();
}

/**
 * POST /api/confirm/{confirmation_id}
 *
 * @param {string} confirmationId
 * @param {string} sessionId
 * @param {boolean} approved
 * @param {string|null} token
 * @returns {Promise<{session_id:string, response:string, tool_calls:Array}>}
 */
async function sendConfirm(confirmationId, sessionId, approved, token) {
  const res = await fetch(`/api/confirm/${encodeURIComponent(confirmationId)}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...authHeader(token),
    },
    body: JSON.stringify({
      session_id: sessionId,
      confirmation_id: confirmationId,
      approved,
    }),
  });

  if (res.status === 401) {
    throw new AuthError('Unauthorized. Update your token in Settings.');
  }
  if (res.status === 404) {
    throw new Error('Confirmation not found or already expired.');
  }
  if (res.status === 410) {
    throw new Error('Confirmation has expired.');
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.detail || `Server error ${res.status}`);
  }

  return res.json();
}

/** Custom error class for authentication failures. */
class AuthError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AuthError';
  }
}

// ---------------------------------------------------------------------------
// SSE connection (fetch-based — supports Authorization header)
//
// EventSource does not support custom headers, so we use the fetch API with
// a streaming response reader. This avoids leaking the Bearer token in the
// URL query string (which would appear in server access logs, browser
// history, and Referer headers).
// ---------------------------------------------------------------------------

/** @type {AbortController|null} */
let _sseAbort = null;

/** Regex validators for SSE event fields (mirrors server-side Pydantic patterns). */
const _CONFIRM_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const _TOOL_ACTION_RE = /^[a-z][a-z0-9_]{0,62}$/;

/**
 * Open (or re-open) a fetch-based SSE connection for the given session.
 * Sends the Bearer token via the Authorization header — never in the URL.
 *
 * @param {string} sessionId
 * @param {string|null} token
 */
function connectSSE(sessionId, token) {
  // Abort any existing SSE connection.
  if (_sseAbort) {
    _sseAbort.abort();
    _sseAbort = null;
  }

  setStatusDot('connecting');

  const controller = new AbortController();
  _sseAbort = controller;

  const url = new URL('/api/events', window.location.origin);
  url.searchParams.set('session_id', sessionId);
  // Token is sent ONLY in the Authorization header — never in the URL.

  fetch(url.toString(), {
    headers: {
      Accept: 'text/event-stream',
      ...authHeader(token),
    },
    signal: controller.signal,
  })
    .then((response) => {
      if (!response.ok) {
        setStatusDot('disconnected');
        if (response.status === 401) {
          showToast('SSE auth failed. Update your token in Settings.', 'error');
        }
        return;
      }

      setStatusDot('connected');
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      function pump() {
        return reader
          .read()
          .then(({ done, value }) => {
            if (done) {
              setStatusDot('disconnected');
              return;
            }

            buffer += decoder.decode(value, { stream: true });
            // Parse SSE frames: each frame ends with \n\n
            const frames = buffer.split('\n\n');
            // Last element may be an incomplete frame — keep in buffer.
            buffer = frames.pop() || '';

            for (const frame of frames) {
              if (!frame.trim()) continue;
              _handleSSEFrame(frame, sessionId, token);
            }

            return pump();
          })
          .catch((err) => {
            if (err.name !== 'AbortError') {
              setStatusDot('disconnected');
            }
          });
      }

      return pump();
    })
    .catch((err) => {
      if (err.name !== 'AbortError') {
        setStatusDot('disconnected');
      }
    });
}

/**
 * Parse and dispatch a single SSE frame.
 *
 * @param {string} frame - Raw SSE frame text (e.g. "event: status\ndata: {...}")
 * @param {string} sessionId
 * @param {string|null} token
 */
function _handleSSEFrame(frame, sessionId, token) {
  let eventType = 'message';
  let dataStr = '';

  for (const line of frame.split('\n')) {
    if (line.startsWith('event: ')) {
      eventType = line.slice(7).trim();
    } else if (line.startsWith('data: ')) {
      dataStr = line.slice(6);
    }
  }

  let data;
  try {
    data = JSON.parse(dataStr);
  } catch (_) {
    return; // Ignore malformed JSON
  }

  if (eventType === 'status') {
    if (data.status === 'processing') showTyping();
    if (data.status === 'connected') setStatusDot('connected');
  } else if (eventType === 'confirm') {
    // F4: Validate all fields against server-side patterns before use.
    if (
      !_CONFIRM_ID_RE.test(data.confirmation_id || '') ||
      !_TOOL_ACTION_RE.test(data.tool || '') ||
      !_TOOL_ACTION_RE.test(data.action || '')
    ) {
      return; // Discard malformed confirm event
    }
    hideTyping();
    appendConfirmCard(data.confirmation_id, data.tool, data.action, sessionId, token);
  } else if (eventType === 'tool_call') {
    // Validate tool_call fields before any use.
    if (
      !_TOOL_ACTION_RE.test(data.tool || '') ||
      !_TOOL_ACTION_RE.test(data.action || '')
    ) {
      return;
    }
  } else if (eventType === 'error') {
    hideTyping();
    if (typeof data.message === 'string' && data.message.length <= 500) {
      showToast(data.message, 'error');
    }
  } else if (eventType === 'done') {
    hideTyping();
    notifyDone();
  }
}

// ---------------------------------------------------------------------------
// Push notification on task done
// ---------------------------------------------------------------------------

function notifyDone() {
  if (!('serviceWorker' in navigator)) return;

  navigator.serviceWorker.ready
    .then((reg) => {
      if (reg.active) {
        reg.active.postMessage({
          type: 'NOTIFY',
          title: 'admino',
          body: 'Task complete.',
        });
      }
    })
    .catch(() => { /* SW not available */ });
}

// ---------------------------------------------------------------------------
// Status dot
// ---------------------------------------------------------------------------

function setStatusDot(state) {
  const dot = document.getElementById('status-dot');
  dot.className = state;
  const labels = {
    connecting:   'Connecting to server',
    connected:    'Connected to server',
    disconnected: 'Disconnected from server',
  };
  dot.setAttribute('aria-label', labels[state] || state);
  dot.title = labels[state] || state;
}

// ---------------------------------------------------------------------------
// Image upload
// ---------------------------------------------------------------------------

/**
 * Validate file content by checking magic bytes (first few bytes).
 * Accepts PNG, JPEG, GIF, and WebP only. Rejects SVG, HTML, and anything
 * else — regardless of file extension or browser-reported MIME type.
 *
 * @param {Uint8Array} bytes - First 12+ bytes of the file.
 * @returns {boolean}
 */
function _isValidImageMagic(bytes) {
  if (bytes.length < 4) return false;

  // PNG: \x89PNG
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
    return true;
  }
  // JPEG: \xFF\xD8\xFF
  if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
    return true;
  }
  // GIF: GIF87a or GIF89a
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) {
    return true;
  }
  // WebP: RIFF....WEBP (bytes 0-3 = "RIFF", bytes 8-11 = "WEBP")
  if (
    bytes.length >= 12 &&
    bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
    bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50
  ) {
    return true;
  }

  return false;
}

/** @type {string|null} */
let _pendingImageDataUrl = null;

function initImageUpload() {
  const uploadBtn   = document.getElementById('upload-btn');
  const fileInput   = document.getElementById('file-input');
  const preview     = document.getElementById('image-preview');
  const previewImg  = document.getElementById('image-preview-img');
  const previewName = document.getElementById('image-preview-name');
  const removeBtn   = document.getElementById('image-preview-remove');

  uploadBtn.addEventListener('click', () => fileInput.click());

  fileInput.addEventListener('change', () => {
    const file = fileInput.files && fileInput.files[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      showToast('Only image files are supported.', 'error');
      fileInput.value = '';
      return;
    }

    // Base64 encoding expands ~33%. The combined message (text + image marker +
    // base64) must fit within MAX_MESSAGE_LENGTH (32768 chars). A 20 KB file
    // base64-encodes to ~27 KB which leaves room for the text portion.
    // Cap at 20 KB to ensure the message stays within server limits.
    if (file.size > 20 * 1024) {
      showToast('Image must be smaller than 20 KB to fit within message limits.', 'error');
      fileInput.value = '';
      return;
    }

    // Validate image magic bytes before accepting. The browser's file.type
    // is derived from the file extension (not content) and can be spoofed.
    const headerReader = new FileReader();
    headerReader.onload = (evt) => {
      const arr = new Uint8Array(evt.target.result);
      if (!_isValidImageMagic(arr)) {
        showToast('File does not appear to be a valid image (bad magic bytes).', 'error');
        return;
      }

      // Read again as data URL for preview and submission.
      const dataReader = new FileReader();
      dataReader.onload = (evt2) => {
        _pendingImageDataUrl = evt2.target.result;
        previewImg.src       = _pendingImageDataUrl;
        previewName.textContent = file.name;
        preview.classList.add('visible');
      };
      dataReader.readAsDataURL(file);
    };
    // Read just the first 12 bytes for magic byte detection.
    headerReader.readAsArrayBuffer(file.slice(0, 12));
    fileInput.value = '';
  });

  removeBtn.addEventListener('click', () => {
    _pendingImageDataUrl = null;
    preview.classList.remove('visible');
    previewImg.src       = '';
    previewName.textContent = '';
  });
}

// ---------------------------------------------------------------------------
// Settings modal
// ---------------------------------------------------------------------------

function initSettings(onSave) {
  const overlay    = document.getElementById('settings-overlay');
  const gearBtn    = document.getElementById('settings-btn');
  const cancelBtn  = document.getElementById('settings-cancel');
  const saveBtn    = document.getElementById('settings-save');
  const tokenInput = document.getElementById('settings-token');
  const sessionInput = document.getElementById('settings-session');

  gearBtn.addEventListener('click', () => {
    tokenInput.value   = loadToken() || '';
    sessionInput.value = loadSessionId();
    overlay.classList.add('open');
    tokenInput.focus();
  });

  cancelBtn.addEventListener('click', () => {
    overlay.classList.remove('open');
  });

  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) overlay.classList.remove('open');
  });

  overlay.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') overlay.classList.remove('open');
  });

  saveBtn.addEventListener('click', () => {
    const newToken   = tokenInput.value.trim();
    const newSession = sessionInput.value.trim();

    if (newSession && /^[a-zA-Z0-9_-]{1,64}$/.test(newSession)) {
      localStorage.setItem(LS_SESSION_KEY, newSession);
    } else if (newSession) {
      showToast('Session ID must be alphanumeric, hyphens or underscores, max 64 chars.', 'error');
      return;
    }

    if (!saveToken(newToken || null)) {
      showToast('Token must be 8-512 printable ASCII characters.', 'error');
      return;
    }
    overlay.classList.remove('open');
    onSave();
  });
}

// ---------------------------------------------------------------------------
// Token prompt (first-launch)
// ---------------------------------------------------------------------------

function initTokenPrompt(onComplete) {
  const overlay    = document.getElementById('token-prompt-overlay');
  const input      = document.getElementById('token-prompt-input');
  const continueBtn = document.getElementById('token-prompt-continue');
  const skipBtn    = document.getElementById('token-prompt-skip');

  function close() {
    overlay.classList.remove('open');
    onComplete();
  }

  function trySetToken() {
    const t = input.value.trim();
    if (t && !saveToken(t)) {
      showToast('Token must be 8-512 printable ASCII characters.', 'error');
      return;
    }
    if (!t) saveToken(null);
    close();
  }

  continueBtn.addEventListener('click', trySetToken);

  skipBtn.addEventListener('click', () => {
    close();
  });

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') trySetToken();
  });

  // Show if no token saved yet
  if (!loadToken()) {
    overlay.classList.add('open');
    setTimeout(() => input.focus(), 50);
  } else {
    onComplete();
  }
}

// ---------------------------------------------------------------------------
// Main message submission
// ---------------------------------------------------------------------------

function initMessageInput(sessionId, getToken) {
  const input    = document.getElementById('message-input');
  const sendBtn  = document.getElementById('send-btn');

  function setDisabled(disabled) {
    input.disabled   = disabled;
    sendBtn.disabled = disabled;
    document.getElementById('upload-btn').disabled = disabled;
  }

  async function submit() {
    const text = input.value.trim();
    if (!text && !_pendingImageDataUrl) return;

    const token = getToken();
    const displayText = text || '[Image attached]';

    // Capture image state before clearing (restored on error).
    const imageUrl = _pendingImageDataUrl;

    // Clear input immediately for responsive UX.
    input.value = '';
    input.style.height = '';
    _pendingImageDataUrl = null;
    document.getElementById('image-preview').classList.remove('visible');

    // Append user message (plain text)
    appendMessage('user', displayText);
    setDisabled(true);
    showTyping();

    try {
      const data = await sendMessage(text || ' ', sessionId, token, imageUrl);
      hideTyping();

      // Render the assistant message (if any) first so the user sees
      // the explanation above the confirmation card.
      if (data.response) {
        const fragment = renderMarkdown(data.response);
        appendMessage('assistant', fragment, data.tool_calls || []);
      }

      // If the agent is awaiting confirmation, render the inline
      // Approve/Deny card. The server includes pending_confirmation with
      // the confirmation_id, tool, and action in the REST response when
      // status === 'awaiting_confirmation'.
      if (data.status === 'awaiting_confirmation' && data.pending_confirmation) {
        const pc = data.pending_confirmation;
        if (
          typeof pc.confirmation_id === 'string' &&
          _CONFIRM_ID_RE.test(pc.confirmation_id) &&
          typeof pc.tool === 'string' &&
          typeof pc.action === 'string'
        ) {
          appendConfirmCard(pc.confirmation_id, pc.tool, pc.action, sessionId, token);
        }
      }
    } catch (err) {
      hideTyping();
      if (err instanceof AuthError) {
        showToast(err.message, 'error');
        // Open settings to let user update token
        document.getElementById('settings-btn').click();
      } else {
        appendMessage('system', `Error: ${err.message}`);
      }
    } finally {
      setDisabled(false);
      input.focus();
    }
  }

  sendBtn.addEventListener('click', submit);

  input.addEventListener('keydown', (e) => {
    // Send on Enter (not Shift+Enter)
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      submit();
    }
  });

  // Auto-grow textarea
  input.addEventListener('input', () => {
    input.style.height = 'auto';
    input.style.height = `${Math.min(input.scrollHeight, 160)}px`;
  });
}

// ---------------------------------------------------------------------------
// PWA install prompt
// ---------------------------------------------------------------------------

/** @type {Event|null} */
let _installPromptEvent = null;

function initInstallPrompt() {
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    _installPromptEvent = e;
    document.getElementById('install-btn').hidden = false;
  });

  document.getElementById('install-btn').addEventListener('click', async () => {
    if (!_installPromptEvent) return;
    _installPromptEvent.prompt();
    const { outcome } = await _installPromptEvent.userChoice;
    if (outcome === 'accepted') {
      document.getElementById('install-btn').hidden = true;
    }
    _installPromptEvent = null;
  });

  window.addEventListener('appinstalled', () => {
    document.getElementById('install-btn').hidden = true;
    _installPromptEvent = null;
  });
}

// ---------------------------------------------------------------------------
// Service worker registration
// ---------------------------------------------------------------------------

function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;

  navigator.serviceWorker
    .register('/service-worker.js', { scope: '/' })
    .then(() => {
      // Request notification permission (non-blocking, non-intrusive)
      if ('Notification' in window && Notification.permission === 'default') {
        // Defer request until after user interaction (browser best practice)
        document.addEventListener('click', function requestOnce() {
          Notification.requestPermission();
          document.removeEventListener('click', requestOnce);
        }, { once: true });
      }
    })
    .catch(() => { /* Service worker failed — app still works without it */ });
}

// ---------------------------------------------------------------------------
// Application bootstrap
// ---------------------------------------------------------------------------

function bootstrap() {
  registerServiceWorker();

  const sessionId = loadSessionId();

  // Display session ID in header — show only last 8 chars to reduce
  // information leakage in screen-shares. Full ID available via title tooltip.
  const sessionDisplay = document.getElementById('header-session');
  sessionDisplay.textContent = truncateSessionId(sessionId);
  sessionDisplay.title       = sessionId;

  let token = loadToken();

  function getToken() {
    return loadToken();
  }

  // Initialize settings modal
  initSettings(() => {
    token = loadToken();
    // Reconnect SSE with potentially new session/token
    connectSSE(loadSessionId(), token);
    // Update session display
    const newSid = loadSessionId();
    sessionDisplay.textContent = truncateSessionId(newSid);
    sessionDisplay.title       = newSid;
  });

  // Initialize image upload
  initImageUpload();

  // Initialize message input
  initMessageInput(sessionId, getToken);

  // Initialize install prompt
  initInstallPrompt();

  // New session button
  document.getElementById('new-session-btn').addEventListener('click', () => {
    const newSid = generateSessionId();
    localStorage.setItem(LS_SESSION_KEY, newSid);
    sessionDisplay.textContent = truncateSessionId(newSid);
    sessionDisplay.title       = newSid;
    connectSSE(newSid, getToken());
    // Clear messages
    const messages = document.getElementById('messages');
    const typing   = document.getElementById('typing-indicator');
    while (messages.firstChild && messages.firstChild !== typing) {
      messages.removeChild(messages.firstChild);
    }
    appendMessage('system', 'New session started.');
    document.getElementById('message-input').focus();
  });

  // Token prompt — show on first launch, then connect SSE
  initTokenPrompt(() => {
    token = loadToken();
    connectSSE(loadSessionId(), token);
    document.getElementById('message-input').focus();
  });
}

// Run after DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bootstrap);
} else {
  bootstrap();
}
