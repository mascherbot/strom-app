// Service Worker: App-Shell aus dem Cache, data.enc.json immer zuerst aus dem Netz.
const CACHE = 'strom-app-5c8819210b';
const SHELL = ['./', 'index.html', 'app.css', 'app.js', 'vendor/chart.umd.min.js', 'manifest.json',
  'icons/apple-touch-icon.png', 'icons/icon-192.png', 'icons/icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  if (url.pathname.endsWith('/data.enc.json')) {
    // network-first: neue (verschlüsselte) Daten sofort, offline letzter Stand
    e.respondWith(fetch(e.request, {cache: 'no-store'})
      .then(r => { if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put('data.enc.json', copy)); } return r; })
      .catch(() => caches.match('data.enc.json')));
    return;
  }
  // App-Shell: stale-while-revalidate (sofort aus Cache, im Hintergrund aktualisieren)
  e.respondWith(caches.match(e.request, {ignoreSearch: true}).then(cached => {
    const net = fetch(e.request).then(r => { if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); } return r; }).catch(() => cached);
    return cached || net;
  }));
});
