/**
 * Findings deduplication + cross-tool correlation (F15).
 *
 * Multiple scanners frequently flag the same underlying vulnerability —
 * e.g. nuclei, wapiti, and sqlmap can all surface the same SQL-injection
 * sink on the same parameter. The raw `ToolFinding[]` from the registry
 * therefore contains a lot of duplicate signal that the report agent
 * has to wade through.
 *
 * This service collapses findings that share a fingerprint (target +
 * normalized evidence). The collapsed entry preserves every contributing
 * tool's evidence so the operator can see "this was found by N
 * independent tools" at a glance.
 *
 * Pure function over the registry's outputs. No I/O, no globals.
 */

import type { AnalysisFinding as ToolFinding } from './finding.js';

export interface CorrelatedFinding extends ToolFinding {
  /** Distinct tools that contributed evidence for this finding. */
  readonly sources: readonly string[];
  /** Every evidence string contributed, in arrival order. */
  readonly evidenceParts: readonly string[];
  /** Number of raw `ToolFinding` entries that collapsed into this one. */
  readonly occurrences: number;
}

/**
 * Normalize a target string into a comparable form:
 *   - URL: scheme + host + path + sorted-query-keys; drops fragments
 *   - Bare host or path: trim + lowercase
 *
 * Two findings whose targets normalize to the same string are
 * candidates for dedup; further fingerprinting on evidence does the
 * final match.
 */
export function normalizeTarget(target: string): string {
  const trimmed = target.trim();
  if (trimmed.length === 0) return '';

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      const url = new URL(trimmed);
      const sortedParams = [...url.searchParams.keys()].sort();
      // Re-emit only the keys (not the values) so two findings against
      // ?q=foo and ?q=bar fingerprint to the same path.
      const queryKeys = sortedParams.join(',');
      const path = url.pathname.replace(/\/$/, '');
      return `${url.protocol}//${url.hostname.toLowerCase()}${path}${queryKeys ? `?${queryKeys}` : ''}`;
    } catch {
      return trimmed.toLowerCase();
    }
  }

  return trimmed.toLowerCase();
}

/**
 * Extract a "shape" from a free-form evidence string. We deliberately
 * keep structural keys (param=, sink=, endpoint=, login=, port=,
 * service=) but mask their values so two findings that differ only in
 * the specific payload / port / login still collapse:
 *
 *   "param=id payload=' OR 1=1--"
 *   "param=id payload=' OR 2=2--"
 *
 * both fingerprint to "param=id payload=<value>". This is the right
 * primitive for cross-tool dedup — what's "the same finding" is the
 * sink + parameter, not the specific payload.
 *
 * Additional collapses on top of the keyed masking:
 *   - long hex strings  -> <hex>
 *   - long opaque tokens -> <token>
 *   - percent-encoded escapes -> %
 *   - whitespace runs   -> single space
 */
export function evidenceFingerprint(evidence: string | undefined): string {
  if (!evidence) return '';
  return evidence
    .toLowerCase()
    .replace(/(payload|value|data|body)=[^\s]+/g, '$1=<value>')
    .replace(/(port|status)=\d+/g, '$1=<num>')
    .replace(/[0-9a-f]{8,}/g, '<hex>')
    .replace(/%[0-9a-f]{2}/g, '%')
    .replace(/[a-z0-9_-]{16,}/g, '<token>')
    .replace(/\b\d+\b/g, '<n>')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Build the dedup key for a finding. Two findings with the same key
 * collapse. The key intentionally ignores tool name and severity so
 * the same vulnerability flagged by different scanners and rated
 * differently still merges.
 */
export function dedupKey(finding: ToolFinding): string {
  const tgt = normalizeTarget(finding.target);
  const titleShape = finding.title
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/[0-9a-f]{8,}/g, '<hex>')
    .trim();
  const evidence = evidenceFingerprint(finding.evidence);
  return `${tgt}||${titleShape}||${evidence}`;
}

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'] as const;
type Severity = (typeof SEVERITY_ORDER)[number];

function maxSeverity(a: Severity, b: Severity): Severity {
  const ai = SEVERITY_ORDER.indexOf(a);
  const bi = SEVERITY_ORDER.indexOf(b);
  return ai >= bi ? a : b;
}

/**
 * Collapse duplicate findings.
 *
 *   - Findings whose `dedupKey()` matches merge into a single entry.
 *   - The merged severity is the maximum of all contributors.
 *   - `sources` is the distinct, ordered list of tool names that
 *     contributed.
 *   - `evidenceParts` preserves every original evidence string so the
 *     report can render them as a stacked list.
 *   - Order is stable: the first occurrence wins for non-merged fields
 *     (`tool`, `target`, `title`).
 */
export function dedupeFindings(findings: readonly ToolFinding[]): CorrelatedFinding[] {
  const byKey = new Map<string, CorrelatedFinding>();
  for (const finding of findings) {
    const key = dedupKey(finding);
    const existing = byKey.get(key);
    if (existing === undefined) {
      byKey.set(key, {
        ...finding,
        sources: [finding.tool],
        evidenceParts: finding.evidence !== undefined ? [finding.evidence] : [],
        occurrences: 1,
      });
      continue;
    }

    const nextSources = existing.sources.includes(finding.tool)
      ? existing.sources
      : [...existing.sources, finding.tool];
    const nextEvidenceParts =
      finding.evidence !== undefined && !existing.evidenceParts.includes(finding.evidence)
        ? [...existing.evidenceParts, finding.evidence]
        : existing.evidenceParts;
    byKey.set(key, {
      ...existing,
      severity: maxSeverity(existing.severity as Severity, finding.severity as Severity),
      sources: nextSources,
      evidenceParts: nextEvidenceParts,
      occurrences: existing.occurrences + 1,
    });
  }
  return [...byKey.values()];
}
