/**
 * Threat-intel-driven severity escalation (F107).
 *
 * Promotes findings whose CVE appears in CISA KEV or ExploitDB up
 * one severity level. Caller is expected to feed a recently-fetched
 * KEV JSON + ExploitDB RSS into `buildIntelIndex()`. There are no
 * network calls in this service — caching policy is the caller's
 * choice (the existing tool-versions service follows the same
 * pattern for the same reason: deterministic, offline-testable).
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

const ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export interface CisaKevEntry {
  readonly cveID: string;
  readonly vendorProject?: string;
  readonly product?: string;
  readonly vulnerabilityName?: string;
  readonly knownRansomwareCampaignUse?: 'Known' | 'Unknown' | string;
  readonly dateAdded?: string;
}

export interface ExploitDbEntry {
  readonly cveId: string;
  readonly title?: string;
  readonly publishedAt?: string;
}

export interface IntelIndex {
  readonly kev: ReadonlyMap<string, CisaKevEntry>;
  readonly exploitDb: ReadonlyMap<string, ExploitDbEntry>;
}

export interface IntelHit {
  readonly cve: string;
  readonly inKev: boolean;
  readonly kevEntry?: CisaKevEntry;
  readonly inExploitDb: boolean;
  readonly exploitDbEntry?: ExploitDbEntry;
  /** ransomware campaign usage from KEV (Known/Unknown). */
  readonly ransomware?: string;
}

/** Build a lookup index from raw KEV + ExploitDB feeds. */
export function buildIntelIndex(kev: readonly CisaKevEntry[], exploitDb: readonly ExploitDbEntry[]): IntelIndex {
  const kevMap = new Map<string, CisaKevEntry>();
  for (const e of kev) {
    if (!e.cveID) continue;
    kevMap.set(e.cveID.toUpperCase(), e);
  }
  const exMap = new Map<string, ExploitDbEntry>();
  for (const e of exploitDb) {
    if (!e.cveId) continue;
    exMap.set(e.cveId.toUpperCase(), e);
  }
  return { kev: kevMap, exploitDb: exMap };
}

/** Look up a CVE in both feeds. */
export function lookupCve(index: IntelIndex, cve: string): IntelHit {
  const norm = cve.toUpperCase();
  const kevEntry = index.kev.get(norm);
  const exploitDbEntry = index.exploitDb.get(norm);
  return {
    cve: norm,
    inKev: !!kevEntry,
    ...(kevEntry ? { kevEntry } : {}),
    inExploitDb: !!exploitDbEntry,
    ...(exploitDbEntry ? { exploitDbEntry } : {}),
    ...(kevEntry?.knownRansomwareCampaignUse ? { ransomware: kevEntry.knownRansomwareCampaignUse } : {}),
  };
}

/**
 * Escalate finding severity if the CVE is in either feed.
 * Bumps one level (low → medium → high → critical).
 * Ransomware-campaign-tagged CVEs bump two levels.
 */
export function escalateSeverity(
  current: Severity,
  hit: IntelHit,
): { readonly to: Severity; readonly bumped: number; readonly reasons: readonly string[] } {
  let level = ORDER.indexOf(current);
  if (level < 0) level = 0;
  const reasons: string[] = [];
  let bumped = 0;

  if (hit.inKev) {
    bumped += 1;
    const detail = hit.kevEntry?.vulnerabilityName ?? hit.cve;
    reasons.push(`CISA KEV: ${detail}`);
  }
  if (hit.ransomware === 'Known') {
    bumped += 1;
    reasons.push('Known ransomware-campaign use');
  } else if (hit.inExploitDb) {
    // ExploitDB without KEV is also worth escalating, but only by 1.
    if (!hit.inKev) {
      bumped += 1;
      reasons.push(`ExploitDB: ${hit.exploitDbEntry?.title ?? hit.cve}`);
    } else {
      reasons.push(`ExploitDB: ${hit.exploitDbEntry?.title ?? hit.cve}`);
    }
  }

  const target = Math.min(ORDER.length - 1, level + bumped);
  return { to: ORDER[target] ?? ORDER[level] ?? 'info', bumped: target - level, reasons };
}
