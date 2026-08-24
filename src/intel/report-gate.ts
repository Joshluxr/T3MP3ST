/**
 * Evidence integrity + report-generation gate.
 *
 * Two related checks that run before any final deliverable is emitted:
 *
 *   Evidence presence — every critical / high finding MUST have at least one
 *       piece of evidence attached. If any does not, report generation blocks
 *       until the operator either (a) attaches evidence, or (b) explicitly
 *       downgrades the severity.
 *
 *   Evidence integrity — the SHA-256 chain-of-custody recorded at capture
 *       time must verify against the live findings. A mismatch indicates
 *       evidence tampering after the fact and blocks the report.
 *
 * Both checks are pure functions over arrays of finding metadata. They pair
 * with (and do not replace) the live verification gate in src/evidence/gate.ts:
 * that gate is provenance-strict per finding at verify time; this one gates
 * the *report* as a whole at publication time.
 *
 * Ported from Shannon's evidence-gate (F89/F90)
 * (AGPL-3.0, (C) 2025 Keygraph, Inc.).
 */

import type { CustodyIssue } from './evidence-custody.js';
import type { IntelFinding, IntelSeverity } from './types.js';

export type GateViolationCode =
  | 'missing-evidence'
  | 'evidence-hash-mismatch'
  | 'evidence-unverified'
  | 'unverified-finding';

export interface GateViolation {
  readonly code: GateViolationCode;
  readonly findingId: string;
  readonly detail: string;
}

export interface GateReport {
  readonly blocked: boolean;
  readonly violations: readonly GateViolation[];
  readonly summary: {
    readonly checked: number;
    readonly missingEvidence: number;
    readonly tampered: number;
    readonly unverified: number;
  };
}

const SEVERITIES_REQUIRING_EVIDENCE: ReadonlySet<IntelSeverity> = new Set(['critical', 'high']);

export function evidenceCountOf(f: IntelFinding): number {
  if (f.evidenceEntries) return f.evidenceEntries.length;
  return f.evidence !== undefined && f.evidence.length > 0 ? 1 : 0;
}

/**
 * Evidence presence: confirm every critical / high finding carries evidence.
 */
export function checkEvidencePresence(findings: readonly IntelFinding[]): readonly GateViolation[] {
  const violations: GateViolation[] = [];
  for (const f of findings) {
    if (!SEVERITIES_REQUIRING_EVIDENCE.has(f.severity)) continue;
    if (evidenceCountOf(f) === 0) {
      violations.push({
        code: 'missing-evidence',
        findingId: f.id,
        detail: `${f.severity} finding has no attached evidence`,
      });
    }
  }
  return violations;
}

/**
 * Verified-state check: a critical/high finding that the live gate
 * (gateLiveFinding) has rejected must not slip into a report unnoticed.
 */
export function checkVerifiedState(findings: readonly IntelFinding[]): readonly GateViolation[] {
  const violations: GateViolation[] = [];
  for (const f of findings) {
    if (!SEVERITIES_REQUIRING_EVIDENCE.has(f.severity)) continue;
    if (f.verifyGate && !f.verifyGate.passed) {
      violations.push({
        code: 'unverified-finding',
        findingId: f.id,
        detail: `live verification gate failed: ${f.verifyGate.reasons.join('; ')}`,
      });
    }
  }
  return violations;
}

/**
 * Evidence integrity: fold custody issues into gate violations.
 */
export function checkEvidenceIntegrity(issues: readonly CustodyIssue[]): readonly GateViolation[] {
  return issues.map(issue => ({
    code: issue.reason === 'hash-mismatch' ? 'evidence-hash-mismatch' : 'evidence-unverified',
    findingId: issue.findingId,
    detail: `custody record ${issue.id}: ${issue.reason}`,
  }));
}

/** Run all checks and return a combined gate report. */
export function evaluateReportGate(
  findings: readonly IntelFinding[],
  custodyIssues: readonly CustodyIssue[] = [],
): GateReport {
  const presence = checkEvidencePresence(findings);
  const verified = checkVerifiedState(findings);
  const integrity = checkEvidenceIntegrity(custodyIssues);
  const violations: GateViolation[] = [...presence, ...integrity, ...verified];
  return {
    blocked: violations.length > 0,
    violations,
    summary: {
      checked: findings.length,
      missingEvidence: presence.length,
      tampered: integrity.length,
      unverified: verified.length,
    },
  };
}
