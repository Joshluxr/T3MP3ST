/**
 * Reachability analysis for SCA/static findings.
 *
 * Ported from Shannon `services/reachability.ts` (AGPL-3.0 © Keygraph).
 * SCA scanners flood you with dependency CVEs; the actionable question for a
 * zero-day-grade report is "is the vulnerable code actually reachable from an
 * entrypoint?". This builds a lightweight module import graph (regex-based,
 * no compiler), marks the files reachable from entrypoints, and classifies a
 * finding as reachable when its package/symbol token appears in a reachable
 * file. Reachable findings are escalated for triage; unreachable ones are
 * annotated so they can be de-prioritised.
 *
 * Heuristic by design — it favours recall (don't hide a real bug) over
 * precision, and never downgrades below the original severity.
 */

/** A source file slice used for reachability indexing. */
export interface SourceFileSlice {
  readonly path: string;
  readonly content: string;
}

const IMPORT_RE =
  /(?:import\s[^'"]*from\s*['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\)|from\s+([\w.]+)\s+import)/g;
const ENTRYPOINT_RE = /(^|\/)(index|main|server|app|cmd|handler|route|routes|api|wsgi|asgi|manage)\.[a-z]+$/i;

export interface ReachabilityIndex {
  /** Files reachable from an entrypoint (absolute or repo-relative paths). */
  readonly reachableFiles: ReadonlySet<string>;
  /** Basenames of reachable files (for location-based matching). */
  readonly reachableBasenames: ReadonlySet<string>;
  /** Concatenated content of reachable files (for token search). */
  readonly reachableContent: string;
}

/** Normalize a module specifier to a comparable basename token. */
function specifierToken(spec: string): string {
  const noQuery = spec.split('?')[0] ?? spec;
  const base = noQuery.replace(/\\/g, '/').split('/').pop() ?? noQuery;
  return base.replace(/\.(ts|tsx|js|jsx|mjs|cjs|py|go|java|php|rb|rs)$/i, '').toLowerCase();
}

function fileToken(filePath: string): string {
  const base = filePath.replace(/\\/g, '/').split('/').pop() ?? filePath;
  return base.replace(/\.(ts|tsx|js|jsx|mjs|cjs|py|go|java|php|rb|rs)$/i, '').toLowerCase();
}

/**
 * Build the reachability index from collected source files. Reachability is
 * approximated by a BFS over local imports starting from entrypoint files;
 * files with no detectable importers are treated as reachable too (favouring
 * recall — an unimported file may be an entrypoint we didn't recognise).
 */
export function buildReachabilityIndex(files: readonly SourceFileSlice[]): ReachabilityIndex {
  // token → file paths that define it (by filename)
  const byToken = new Map<string, SourceFileSlice[]>();
  for (const f of files) {
    const tok = fileToken(f.path);
    const list = byToken.get(tok) ?? [];
    list.push(f);
    byToken.set(tok, list);
  }

  // adjacency: file → imported file tokens
  const importsOf = new Map<string, Set<string>>();
  const importedTokens = new Set<string>();
  for (const f of files) {
    const targets = new Set<string>();
    IMPORT_RE.lastIndex = 0;
    let m: RegExpExecArray | null = IMPORT_RE.exec(f.content);
    while (m !== null) {
      const spec = m[1] ?? m[2] ?? m[3];
      if (spec) {
        const tok = specifierToken(spec);
        targets.add(tok);
        importedTokens.add(tok);
      }
      m = IMPORT_RE.exec(f.content);
    }
    importsOf.set(f.path, targets);
  }

  // entrypoints: filename match OR files never imported by anyone.
  const entrypoints = files.filter((f) => ENTRYPOINT_RE.test(f.path) || !importedTokens.has(fileToken(f.path)));

  const reachable = new Set<string>();
  const queue: SourceFileSlice[] = [...entrypoints];
  while (queue.length > 0) {
    const f = queue.shift();
    if (!f || reachable.has(f.path)) continue;
    reachable.add(f.path);
    for (const tok of importsOf.get(f.path) ?? []) {
      for (const target of byToken.get(tok) ?? []) {
        if (!reachable.has(target.path)) queue.push(target);
      }
    }
  }

  const reachableFilesArr = files.filter((f) => reachable.has(f.path));
  const reachableContent = reachableFilesArr
    .map((f) => f.content)
    .join('\n')
    .toLowerCase();
  const reachableBasenames = new Set(
    reachableFilesArr.map((f) => (f.path.replace(/\\/g, '/').split('/').pop() ?? f.path).toLowerCase()),
  );

  return { reachableFiles: reachable, reachableBasenames, reachableContent };
}

export interface ReachableFinding {
  readonly title: string;
  readonly severity: string;
  readonly description: string;
  readonly location?: string;
}

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'] as const;

/** Extract candidate package/symbol tokens from a finding's text. */
function findingTokens(finding: ReachableFinding): string[] {
  const text = `${finding.title} ${finding.description} ${finding.location ?? ''}`;
  const tokens = new Set<string>();
  // package@version, CVE component names, dotted symbols, bare identifiers
  for (const m of text.matchAll(/[A-Za-z][\w.\-/]{2,}/g)) {
    const t = m[0].toLowerCase();
    if (t.length >= 3 && !['the', 'and', 'for', 'with', 'via', 'cve'].includes(t)) tokens.add(t.split('@')[0] ?? t);
  }
  return [...tokens];
}

/**
 * Annotate findings with reachability. Reachable findings are escalated one
 * level (favouring action); unreachable findings keep their severity but are
 * tagged so reviewers can de-prioritise.
 */
export function annotateReachability(
  findings: readonly ReachableFinding[],
  index: ReachabilityIndex,
): ReachableFinding[] {
  return findings.map((finding) => {
    const tokens = findingTokens(finding);
    const locationBasename = finding.location
      ? (finding.location.split(':')[0] ?? '').replace(/\\/g, '/').split('/').pop()?.toLowerCase()
      : undefined;
    const reachableByLocation = locationBasename !== undefined && index.reachableBasenames.has(locationBasename);
    const reachable = reachableByLocation || tokens.some((t) => index.reachableContent.includes(t));
    if (reachable) {
      const idx = SEVERITY_ORDER.indexOf(finding.severity.toLowerCase() as (typeof SEVERITY_ORDER)[number]);
      const bumped =
        idx >= 0
          ? (SEVERITY_ORDER[Math.min(SEVERITY_ORDER.length - 1, idx + 1)] ?? finding.severity)
          : finding.severity;
      return {
        ...finding,
        severity: bumped,
        description: `${finding.description}${finding.description ? ' ' : ''}[reachability: REACHABLE from an entrypoint — prioritise]`,
      };
    }
    return {
      ...finding,
      description: `${finding.description}${finding.description ? ' ' : ''}[reachability: not obviously reachable — verify before de-prioritising]`,
    };
  });
}
