const CACHE_NAME = 'seagles-v1'
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
]

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS)
    })
  )
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    })
  )
})

self.addEventListener('fetch', (event) => {
  const { request } = event
  const url = new URL(request.url)

  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirst(request))
    return
  }

  event.respondWith(cacheFirst(request))
})

async function cacheFirst(request) {
  const cached = await caches.match(request)
  if (cached) {
    return cached
  }
  try {
    const response = await fetch(request)
    // Cache.put() only accepts GET requests; guard + catch so we never emit
    // unhandled rejections or race the SW shutdown.
    if (request.method === 'GET') {
      const cache = await caches.open(CACHE_NAME)
      cache.put(request, response.clone()).catch(() => {})
    }
    return response
  } catch (error) {
    return new Response('Offline', { status: 503 })
  }
}

// API responses are authenticated and tenant-scoped. Never persist them to
// the SW cache: a shared machine could otherwise serve another user's data
// offline. Always hit the network and fail closed when offline.
async function networkFirst(request) {
  try {
    return await fetch(request)
  } catch (error) {
    return new Response(JSON.stringify({ data: null, error: 'offline' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    })
  }
}
