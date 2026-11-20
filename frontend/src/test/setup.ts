import '@testing-library/jest-dom'
import { vi } from 'vitest'

// Node 26 exposes an experimental `localStorage` global that is undefined
// without --localstorage-file, shadowing jsdom's implementation. Provide an
// in-memory Storage so auth/session tests behave deterministically.
const store = new Map<string, string>()
const memoryStorage: Storage = {
  get length() { return store.size },
  clear: () => store.clear(),
  getItem: (key) => store.get(key) ?? null,
  key: (index) => Array.from(store.keys())[index] ?? null,
  removeItem: (key) => { store.delete(key) },
  setItem: (key, value) => { store.set(key, String(value)) },
}

if (typeof window !== 'undefined' && !window.localStorage) {
  Object.defineProperty(window, 'localStorage', { configurable: true, value: memoryStorage })
}
vi.stubGlobal('localStorage', memoryStorage)
