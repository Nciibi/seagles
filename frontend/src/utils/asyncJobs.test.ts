import { describe, expect, it, vi } from 'vitest'
import { pollUntil } from './asyncJobs'

describe('pollUntil', () => {
  it('returns as soon as the predicate is satisfied', async () => {
    let calls = 0
    const value = await pollUntil(
      async () => { calls++; return calls },
      (n) => n >= 3,
      { intervalMs: 1, timeoutMs: 1000 },
    )
    expect(value).toBe(3)
    expect(calls).toBe(3)
  })

  it('stops polling when aborted', async () => {
    const controller = new AbortController()
    let calls = 0
    const promise = pollUntil(
      async () => { calls++; return calls },
      () => false,
      { intervalMs: 5, timeoutMs: 5000, signal: controller.signal },
    )
    setTimeout(() => controller.abort(), 15)
    await expect(promise).rejects.toThrow('Aborted')
    expect(calls).toBeLessThan(10)
  })

  it('times out when the operation never finishes', async () => {
    await expect(
      pollUntil(async () => 'running', () => false, { intervalMs: 2, timeoutMs: 20 }),
    ).rejects.toThrow('timeout')
  })
})
