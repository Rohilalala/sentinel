// Sentinel service worker. Same-origin files: stale-while-revalidate, so the app works
// offline after one visit and picks up new code on the next load. Live APIs are never cached.
// Limit: no precache list to maintain; add one if first-visit-offline ever matters.
const CACHE = 'sentinel-v2';
const CDN = 'https://cdnjs.cloudflare.com/';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil((async () => {
  for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k);
  await self.clients.claim();
})()));
self.addEventListener('fetch', e => {
  const req = e.request, url = new URL(req.url);
  const cacheable = req.method === 'GET' && (url.origin === location.origin || url.href.startsWith(CDN)) && !url.pathname.startsWith('/api/')
    && !url.pathname.endsWith('/companion.js'); // carries a per-session token: never serve it stale
  if (!cacheable) return;
  e.respondWith((async () => {
    const cache = await caches.open(CACHE), hit = await cache.match(req);
    const net = fetch(req).then(r => { if (r.ok) cache.put(req, r.clone()); return r; }).catch(() => hit);
    return hit || net;
  })());
});
