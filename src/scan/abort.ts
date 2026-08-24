/**
 * Cooperative scan abort (Phase 0). One controller per ScanJob, handed to every
 * lane via LaneContext and wired into the Arsenal so the NEXT arsenal.execute()
 * after an abort short-circuits — Temporal cancellation and the War Room
 * "Emergency Stop" both land on the same controller.
 */

import { ScanAbortedError, type ScanAbortController } from './types.js';

export { ScanAbortedError } from './types.js';

export function createScanAbortController(): ScanAbortController {
  let aborted = false;
  let reason: string | null = null;
  return {
    get aborted() { return aborted; },
    get reason() { return reason; },
    abort(r: string) {
      if (aborted) return;
      aborted = true;
      reason = r;
    },
    throwIfAborted() {
      if (aborted) throw new ScanAbortedError(reason ?? 'unknown');
    },
  };
}
