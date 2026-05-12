const CACHE_NAME = 'smartattend-v2';
const ASSETS = [
  './',
  './index.html',
  './manifest.json'
];

// Install — cache core assets
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS))
  );
  self.skipWaiting();
});

// Activate — clean old caches
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch — network first for API, cache first for assets
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // API calls — always go to network
  const apiRoutes = ['/register','/login','/verify','/resend-otp',
    '/student/','/teacher/','/admin/'];
  if (apiRoutes.some(r => url.pathname.startsWith(r))) {
    e.respondWith(fetch(e.request).catch(() =>
      new Response(JSON.stringify({message:'You are offline'}),
        {headers:{'Content-Type':'application/json'}})
    ));
    return;
  }

  // Static assets — cache first
  e.respondWith(
    caches.match(e.request).then(cached => cached || fetch(e.request).then(res => {
      const clone = res.clone();
      caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
      return res;
    }))
  );
});
