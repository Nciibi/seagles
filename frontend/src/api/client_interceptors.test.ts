import { beforeEach, describe, expect, it, vi } from 'vitest'

function memoryStorage(): Storage {
  const data = new Map<string, string>()
  return {
    get length() { return data.size },
    clear: () => data.clear(),
    getItem: (key: string) => data.get(key) ?? null,
    key: (index: number) => [...data.keys()][index] ?? null,
    removeItem: (key: string) => { data.delete(key) },
    setItem: (key: string, value: string) => { data.set(key, value) },
  }
}

const responseHandlers: Array<(arg: unknown) => unknown> = []
const requestHandlers: Array<(arg: unknown) => unknown> = []

const mockAxiosInstance = {
  interceptors: {
    request: { use: vi.fn((fn: (arg: unknown) => unknown) => requestHandlers.push(fn)) },
    response: { use: vi.fn((onFulfilled: (arg: unknown) => unknown, onRejected?: (arg: unknown) => unknown) => {
      responseHandlers.push(onFulfilled)
      if (onRejected) responseHandlers.push(onRejected)
    }) },
  },
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
  delete: vi.fn(),
}

vi.mock('axios', () => ({
  default: {
    create: vi.fn(() => mockAxiosInstance),
    post: vi.fn(),
    get: vi.fn(),
  },
}))

vi.stubGlobal('localStorage', memoryStorage())
vi.stubGlobal('sessionStorage', memoryStorage())

describe('API interceptors', () => {
  beforeEach(() => {
    responseHandlers.length = 0
    requestHandlers.length = 0
    localStorage.clear()
    sessionStorage.clear()
    vi.resetModules()
  })

  it('unwraps the {data,error} envelope', async () => {
    await import('./client')
    const onFulfilled = responseHandlers[0] as (r: unknown) => Promise<{ data: unknown }>
    const result = await onFulfilled({ data: { data: { id: 'dev-1' }, error: null }, headers: {} })
    expect(result.data).toEqual({ id: 'dev-1' })
  })

  it('throws when the envelope carries an error', async () => {
    await import('./client')
    const onFulfilled = responseHandlers[0] as (r: unknown) => unknown
    expect(() => onFulfilled({ data: { data: null, error: 'boom' }, headers: {} })).toThrow('boom')
  })

  it('attaches the bearer token and CSRF header on outgoing requests', async () => {
    localStorage.setItem('seagles_token', 'jwt-token')
    sessionStorage.setItem('seagles_csrf', 'csrf-token')
    await import('./client')
    const onRequest = requestHandlers[0] as (c: unknown) => { headers: Record<string, string> }
    const config = onRequest({ headers: {} })
    expect(config.headers.Authorization).toBe('Bearer jwt-token')
    expect(config.headers['X-CSRF-Token']).toBe('csrf-token')
  })

  it('settles every queued request when refresh fails (no hanging promises)', async () => {
    // clearSession redirects on failure; jsdom cannot navigate, so stub it.
    Object.defineProperty(window, 'location', {
      value: { pathname: '/login', href: '' },
      configurable: true,
      writable: true,
    })
    const axios = await import('axios')
    localStorage.setItem('seagles_refresh', 'stale-refresh')
    vi.mocked(axios.default.post).mockRejectedValueOnce(new Error('refresh failed'))

    await import('./client')
    const onRejected = responseHandlers[1] as (e: unknown) => Promise<unknown>

    const first = onRejected({ config: { headers: {}, url: '/devices' }, response: { status: 401 } })
    const second = onRejected({ config: { headers: {}, url: '/alerts' }, response: { status: 401 } })

    await expect(first).rejects.toThrow('refresh failed')
    await expect(second).rejects.toThrow('refresh failed')
  })
})
