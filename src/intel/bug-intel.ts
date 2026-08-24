/**
 * Persistent bug-intelligence / corpus memory.
 *
 * Turns one-shot hunts into a compounding program: after each run it distils
 * the current findings into durable signatures and merges them into a store.
 * Subsequent runs load the prior store to tell new findings from known ones
 * and to seed delta scanning — so the system gets measurably better at
 * finding bugs over time.
 *
 * Signature extraction + merge are pure + unit-tested; the server owns
 * persistence (state snapshot).
 *
 * Ported from Shannon's bug-intel-memory (zero-day #10)
 * (AGPL-3.0, (C) 2025 Keygraph, Inc.).
 */

import type { IntelFinding } from './types.js';

export interface IntelRecord {
  readonly signature: string;
  readonly title: string;
  readonly severity: string;
  readonly source: string;
  readonly firstSeen: string;
  lastSeen: string;
  count: number;
}

export interface IntelStore {
  readonly version: 1;
  records: IntelRecord[];
}

/** Stable signature for a finding: normalized title + coarse location. Pure. */
export function signatureOf(f: { title: string; location?: string }): string {
  const title = f.title.trim().toLowerCase().replace(/\s+/g, ' ').slice(0, 120);
  const loc = (f.location ?? '')
    .trim()
    .toLowerCase()
    .replace(/[?#].*$/, '') // drop query/fragment first
    .replace(/\d+/g, '#') // then collapse ids/line numbers so variants coalesce
    .slice(0, 160);
  return `${title}::${loc}`;
}

export interface MergeResult {
  readonly store: IntelStore;
  readonly newCount: number;
  readonly knownCount: number;
}

/** Merge current findings into the prior store, tracking new vs known. Pure. */
export function mergeIntel(
  prior: IntelStore,
  current: ReadonlyArray<{ title: string; severity: string; source: string; location?: string }>,
  now: string,
): MergeResult {
  const bySig = new Map(prior.records.map(r => [r.signature, { ...r }]));
  let newCount = 0;
  let knownCount = 0;
  const seenThisRun = new Set<string>();
  for (const f of current) {
    const sig = signatureOf(f);
    if (seenThisRun.has(sig)) continue;
    seenThisRun.add(sig);
    const existing = bySig.get(sig);
    if (existing) {
      existing.lastSeen = now;
      existing.count += 1;
      knownCount += 1;
    } else {
      bySig.set(sig, {
        signature: sig,
        title: f.title,
        severity: f.severity,
        source: f.source,
        firstSeen: now,
        lastSeen: now,
        count: 1,
      });
      newCount += 1;
    }
  }
  return { store: { version: 1, records: [...bySig.values()] }, newCount, knownCount };
}

/** Adapt an IntelFinding into the merge input shape (location = target). */
export function findingToMergeInput(f: IntelFinding): { title: string; severity: string; source: string; location?: string } {
  return { title: f.title, severity: f.severity, source: f.source, ...(f.target !== undefined ? { location: f.target } : {}) };
}

export function emptyIntelStore(): IntelStore {
  return { version: 1, records: [] };
}

/** Signatures seen more than once across runs — regressions / unfixed issues. */
export function recurringSignatures(store: IntelStore): readonly IntelRecord[] {
  return store.records.filter(r => r.count > 1);
}

/** Render the store as a Markdown summary block (deliverable-side). */
export function renderIntelSummary(store: IntelStore, newCount: number, knownCount: number): string {
  const recurring = recurringSignatures(store).length;
  return [
    '# Bug Intelligence Memory',
    '',
    `- Signatures in store: **${store.records.length}**`,
    `- New this run: **${newCount}**`,
    `- Previously-seen (recurring): **${knownCount}**`,
    `- Signatures seen more than once across runs: **${recurring}**`,
    '',
    'Recurring signatures indicate regressions or unfixed issues; new signatures seed delta scanning on the next run.',
    '',
    ...(store.records.length
      ? ['Top signatures:', ...store.records.slice(-5).map(r => `- ${r.title} (${r.severity}, seen ${r.count}x)`), '']
      : []),
  ].join('\n');
}
