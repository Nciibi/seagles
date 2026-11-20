const CACHE_NAME = 'seagles-static-v2'
const PRECACHE = ['/', '/manifest.json', '/seagles-logo.png']

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  )
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)),
      ))
      .then(() => self.clients.claim())
  )
})

self.addEventListener('fetch', (event) => {
  const { request } = event
  if (request.method !== 'GET') return

  const url = new URL(request.url)
  if (url.origin !== self.location.origin) return

  // API responses are authenticated and tenant-scoped. Never persist them to
  // the SW cache: a shared machine could otherwise serve another user's data
  // offline.
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkOnly(request))
    return
  }

  // Documents must be network-first. Serving a stale index.html after a
  // deploy leaves users referencing hashed asset filenames that no longer
  // exist, which breaks the app until a hard refresh.
  if (request.mode === 'navigate') {
    event.respondWith(networkFirstDocument(request))
    return
  }

  // Hashed build assets are immutable, so cache-first is correct for them.
  event.respondWith(cacheFirst(request))
})

async function networkOnly(request) {
  try {
    return await fetch(request)
  } catch {
    return new Response(JSON.stringify({ data: null, error: 'offline' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    })
  }
}

async function networkFirstDocument(request) {
  try {
    const response = await fetch(request)
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME)
      cache.put(request, response.clone()).catch(() => {})
    }
    return response
  } catch {
    return (await caches.match(request))
      || (await caches.match('/'))
      || new Response('Offline', { status: 503 })
  }
}

async function cacheFirst(request) {
  const cached = await caches.match(request)
  if (cached) return cached
  try {
    const response = await fetch(request)
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME)
      cache.put(request, response.clone()).catch(() => {})
    }
    return response
  } catch {
    return new Response('Offline', { status: 503 })
  }
}
