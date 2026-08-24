/**
 * Shared shapes for the intel modules (bug-intel memory, delta scanning,
 * CVSS scoring, ATT&CK/STIX/MISP exports, custody + report gate, and the
 * authorization-matrix / flow-attack lanes).
 *
 * `IntelFinding` is the lowest common denominator every intel consumer works
 * against — the server adapts its FindingRecord ledger rows into this shape,
 * and hand-authored findings from tests or the panel use it directly.
 */

export type IntelSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface EvidenceEntry {
  readonly type: string;
  readonly content: string;
}

export interface VerifyGate {
  readonly passed: boolean;
  readonly reasons: readonly string[];
}

export interface IntelFinding {
  readonly id: string;
  readonly title: string;
  readonly severity: IntelSeverity;
  /** Where the finding lives — URL, host, or file location. */
  readonly target: string;
  /** What produced it (tool name, engine id, operator id). */
  readonly source: string;
  /** Coarse location for signature/delta math (path-level URL, host, or file:line). */
  readonly location?: string;
  readonly description?: string;
  readonly evidence?: string;
  /** Structured multi-item evidence (preferred over the single `evidence` string). */
  readonly evidenceEntries?: readonly EvidenceEntry[];
  /** Kind of the single `evidence` string (e.g. 'http-response', 'command-output'). */
  readonly evidenceType?: string;
  /** Engine that synthesized the finding (authz-matrix, flow-attacks, operator…). */
  readonly engine?: string;
  /** Live-verification gate result; failed gates block the report. */
  readonly verifyGate?: VerifyGate;
  /** Kill-chain phase tag used as an ATT&CK mapping hint. */
  readonly phase?: string;
}

export const INTEL_SEVERITY_ORDER: readonly IntelSeverity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function intelSeverityRank(s: IntelSeverity): number {
  return INTEL_SEVERITY_ORDER.indexOf(s);
}
