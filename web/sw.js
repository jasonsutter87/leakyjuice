// sw.js — the "server", running inside a Service Worker. It loads SQLite-WASM + the
// engine, intercepts the app's API calls, and answers them from the in-browser engine.
// The real frontend (app.js, hack.js) fetches /api/... exactly as before — it just never
// leaves the browser. No backend, no network egress, each visitor fully sandboxed.
importScripts(
  'https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.10.3/sql-wasm.js',
  './engine.js'  // defines self.LJ = { ready, dispatch, ... }
);

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

// Paths the engine owns. Everything else (app.js, styles.css, images…) passes through.
const HANDLED = /^\/(api\/|graphql|jwks|\.well-known\/jwks|internal\/metadata)/;

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return; // CDN, fonts, etc. → network
  if (!HANDLED.test(url.pathname)) return;          // static assets → network/cache
  event.respondWith(handle(event.request, url));
});

async function handle(req, url) {
  try {
    await self.LJ.ready;
    const method = req.method;
    const query = Object.fromEntries(url.searchParams);
    const headers = {
      authorization: req.headers.get('authorization') || '',
      origin: req.headers.get('origin') || '',
      cookie: req.headers.get('cookie') || ''
    };
    let body = {};
    if (method !== 'GET' && method !== 'HEAD') { try { body = await req.clone().json(); } catch { body = {}; } }
    const res = await self.LJ.dispatch(method, url.pathname, query, body, headers);
    const outHeaders = { 'content-type': 'application/json' };
    // reflect CORS the way the Node server does (so the CORS lesson survives)
    if (headers.origin) { outHeaders['access-control-allow-origin'] = headers.origin; outHeaders['access-control-allow-credentials'] = 'true'; }
    return new Response(JSON.stringify(res.body), { status: res.status || 200, headers: outHeaders });
  } catch (e) {
    return new Response(JSON.stringify({ error: 'engine error', detail: String(e) }), { status: 500, headers: { 'content-type': 'application/json' } });
  }
}
