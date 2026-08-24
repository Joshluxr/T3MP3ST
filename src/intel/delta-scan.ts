/**
 * Delta / incremental scan selection.
 *
 * On a recurring engagement, most of the attack surface is unchanged from the
 * last run — and fresh vulnerabilities live in *new* code/endpoints. Given a
 * baseline set of already-covered locations (from a prior run's findings),
 * `selectNewEndpoints` returns only the endpoints not already covered, so
 * effort concentrates where it matters.
 *
 * Pure and deterministic. When no baseline is provided, everything is "new"
 * (full scan), so behavior is unchanged for first runs.
 *
 * Ported from Shannon's delta-scan (AGPL-3.0, (C) 2025 Keygraph, Inc.).
 */

export interface DeltaEndpoint {
  readonly url: string;
  readonly method?: string;
  readonly params?: readonly string[];
}

/** Normalize a URL to its path-level coverage key (host-qualified when known). */
function coverageKey(urlOrLocation: string): string {
  try {
    const u = new URL(urlOrLocation);
    return `${u.host}${u.pathname}`.toLowerCase();
  } catch {
    // Not an absolute URL — could be a bare path ("/api/v1/users") or a
    // non-URL location (file:line). Return the leading chunk, query-stripped.
    return urlOrLocation.split(/[?\s]/)[0]?.toLowerCase() ?? urlOrLocation.toLowerCase();
  }
}

/** Path-only key (host dropped) so bare-path baselines cover absolute URLs. */
function pathKey(urlOrLocation: string): string {
  try {
    return new URL(urlOrLocation).pathname.toLowerCase();
  } catch {
    return coverageKey(urlOrLocation);
  }
}

/** Build the covered-location set from baseline finding locations. */
export function baselineCoverage(baselineLocations: readonly string[]): Set<string> {
  const set = new Set<string>();
  for (const loc of baselineLocations) {
    if (!loc) continue;
    set.add(coverageKey(loc));
    set.add(pathKey(loc));
  }
  return set;
}

/**
 * Return the endpoints whose coverage key is not present in the baseline. With
 * an empty baseline, returns all endpoints (full scan).
 */
export function selectNewEndpoints(
  endpoints: readonly DeltaEndpoint[],
  covered: ReadonlySet<string>,
): readonly DeltaEndpoint[] {
  if (covered.size === 0) return endpoints;
  return endpoints.filter(ep => !covered.has(coverageKey(ep.url)) && !covered.has(pathKey(ep.url)));
}

/**
 * Split a finding set into new-vs-known against a baseline location list —
 * the report-side companion to selectNewEndpoints.
 */
export function classifyFindingsDelta(
  findings: ReadonlyArray<{ title: string; location?: string }>,
  baselineLocations: readonly string[],
): { fresh: typeof findings; known: typeof findings } {
  const covered = baselineCoverage(baselineLocations);
  const fresh: Array<{ title: string; location?: string }> = [];
  const known: Array<{ title: string; location?: string }> = [];
  for (const f of findings) {
    const key = coverageKey(f.location ?? f.title);
    if (covered.size > 0 && covered.has(key)) known.push(f);
    else fresh.push(f);
  }
  return { fresh, known };
}
