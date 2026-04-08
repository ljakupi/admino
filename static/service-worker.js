/**
 * admino Service Worker
 *
 * Caches the app shell for offline access and intercepts fetch requests.
 * Push notifications are sent on `done` SSE events from the main thread.
 *
 * Cache strategy:
 * - App shell (HTML, CSS, JS, manifest, icons): cache-first with network fallback.
 * - API requests (/api/*): network-only — never cache sensitive agent responses.
 * - Everything else: network-first with cache fallback.
 */

'use strict';

// Bump this version string whenever static assets change. The activate
// handler deletes all caches that don't match this name, forcing clients
// to re-fetch updated assets. Without a build system, this is the manual
// cache-busting mechanism.
const CACHE_NAME = 'admino-shell-20260408';

/** Static assets that form the offline-capable app shell. */
const SHELL_ASSETS = [
  '/',
  '/index.html',
  '/style.css',
  '/app.js',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
];

// ---------------------------------------------------------------------------
// Install — pre-cache the app shell
// ---------------------------------------------------------------------------

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(SHELL_ASSETS))
      .then(() => self.skipWaiting())
  );
});

// ---------------------------------------------------------------------------
// Activate — clean up stale caches
// ---------------------------------------------------------------------------

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key !== CACHE_NAME)
            .map((key) => caches.delete(key))
        )
      )
      .then(() => self.clients.claim())
  );
});

// ---------------------------------------------------------------------------
// Fetch — routing strategy
// ---------------------------------------------------------------------------

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Never cache API calls — always go to network.
  if (url.pathname.startsWith('/api/') || url.pathname === '/health') {
    event.respondWith(fetch(request));
    return;
  }

  // App shell: cache-first, fallback to network then cache root.
  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) {
        return cached;
      }
      return fetch(request)
        .then((response) => {
          // Only cache successful same-origin GET responses.
          if (
            response.ok &&
            request.method === 'GET' &&
            url.origin === self.location.origin
          ) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          }
          return response;
        })
        .catch(() =>
          // Offline fallback — serve the cached root shell.
          caches.match('/')
        );
    })
  );
});

// ---------------------------------------------------------------------------
// Push notifications — sent by main thread via postMessage
// ---------------------------------------------------------------------------

self.addEventListener('message', (event) => {
  // Defence-in-depth: verify the message comes from a controlled client.
  if (!event.source) return;
  if (!event.data || event.data.type !== 'NOTIFY') {
    return;
  }

  // Validate and bound notification fields to prevent abuse.
  const rawTitle = event.data.title;
  const rawBody = event.data.body;
  const title = (typeof rawTitle === 'string') ? rawTitle.slice(0, 100) : 'admino';
  const body = (typeof rawBody === 'string') ? rawBody.slice(0, 200) : 'Task complete.';

  self.registration.showNotification(title, {
    body,
    icon: '/icons/icon-192.png',
    badge: '/icons/icon-192.png',
    tag: 'admino-done',
    renotify: true,
    requireInteraction: false,
  });
});

// Clicking the notification brings the PWA to the foreground.
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients
      .matchAll({ type: 'window', includeUncontrolled: true })
      .then((clientList) => {
        for (const client of clientList) {
          if ('focus' in client) {
            return client.focus();
          }
        }
        if (self.clients.openWindow) {
          return self.clients.openWindow('/');
        }
      })
  );
});
