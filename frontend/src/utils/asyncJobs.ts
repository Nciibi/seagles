import { getFirmware, getScan, getScans, type Firmware, type Scan } from '../api/client'

export interface PollOptions {
  intervalMs?: number
  timeoutMs?: number
  signal?: AbortSignal
}

/**
 * Poll `fetcher` until `done` returns true. Unlike a fixed setTimeout this
 * waits for the backend to actually report a terminal state, so the UI never
 * claims success for a scan/analysis that is still running (or has failed).
 */
export async function pollUntil<T>(
  fetcher: () => Promise<T>,
  done: (value: T) => boolean,
  options: PollOptions = {},
): Promise<T> {
  const intervalMs = options.intervalMs ?? 2000
  const deadline = Date.now() + (options.timeoutMs ?? 120_000)

  for (;;) {
    if (options.signal?.aborted) throw new DOMException('Aborted', 'AbortError')
    const value = await fetcher()
    if (done(value)) return value
    if (Date.now() >= deadline) throw new Error('Operation did not finish before the timeout')

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(resolve, intervalMs)
      options.signal?.addEventListener(
        'abort',
        () => {
          clearTimeout(timer)
          reject(new DOMException('Aborted', 'AbortError'))
        },
        { once: true },
      )
    })
  }
}

export function waitForScan(scanId: string, options?: PollOptions): Promise<Scan> {
  return pollUntil(
    async () => (await getScan(scanId)).data!.scan,
    (scan) => scan.status !== 'running',
    options,
  )
}

/** The network-scan endpoint returns no job id, so detect the new scan row. */
export function waitForNetworkScan(knownIds: string[], options?: PollOptions): Promise<Scan[]> {
  const known = new Set(knownIds)
  return pollUntil(
    async () => (await getScans()).data as unknown as Scan[],
    (scans) => scans.some((scan) => !known.has(scan.id) && scan.status !== 'running'),
    options,
  )
}

export function waitForFirmwareAnalysis(firmwareId: string, options?: PollOptions): Promise<Firmware> {
  return pollUntil(
    async () => {
      const list = (await getFirmware()).data as unknown as Firmware[]
      const item = list.find((fw) => fw.id === firmwareId)
      if (!item) throw new Error('Firmware record disappeared during analysis')
      return item
    },
    (fw) => fw.analysis_status === 'complete' || fw.analysis_status === 'failed',
    options,
  )
}
