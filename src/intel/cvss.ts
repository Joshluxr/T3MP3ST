/**
 * CVSS auto-scoring.
 *
 * Promotes a finding to a scored finding by attaching a CVSS v3.1 base score.
 * The score is derived from a small ruleset rather than an external NVD lookup
 * so the function stays deterministic and offline-safe: severity tag + finding
 * category + source map to a representative vector + score. Findings whose
 * evidence contains a `CVE-YYYY-NNNN` identifier keep the CVE in the output
 * for manual cross-reference but do not trigger an online lookup.
 *
 * The reasoning trail (`scoreReason`) records which rule fired so the operator
 * can sanity-check the assigned score.
 *
 * Ported from Shannon's cvss-scoring (F24) (AGPL-3.0, (C) 2025 Keygraph, Inc.).
 */

import type { IntelFinding, IntelSeverity } from './types.js';

export interface ScoredFinding extends IntelFinding {
  readonly cvss: {
    readonly baseScore: number;
    readonly severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
    readonly vector: string;
    readonly scoreReason: string;
    readonly cve?: string;
  };
}

const CVE_PATTERN = /CVE-\d{4}-\d{4,7}/i;

/** Evidence text for scanning: legacy inline string, else composed entries. */
function evidenceTextOf(finding: IntelFinding): string {
  if (finding.evidence !== undefined) return finding.evidence;
  return (finding.evidenceEntries ?? []).map(e => String(e.content ?? '')).join('\n');
}

/** Map the qualitative finding severity onto an indicative CVSS base score. */
function severityToScore(severity: IntelSeverity): {
  baseScore: number;
  cvssSeverity: ScoredFinding['cvss']['severity'];
} {
  switch (severity) {
    case 'critical':
      return { baseScore: 9.5, cvssSeverity: 'critical' };
    case 'high':
      return { baseScore: 7.8, cvssSeverity: 'high' };
    case 'medium':
      return { baseScore: 5.5, cvssSeverity: 'medium' };
    case 'low':
      return { baseScore: 3.4, cvssSeverity: 'low' };
    default:
      return { baseScore: 0.0, cvssSeverity: 'none' };
  }
}

/**
 * Pick a representative CVSS v3.1 vector based on the finding's source/category.
 * - Network-exploitable (most web/active scans): AV:N
 * - Local-only (SAST/secret scanners): AV:L
 * - Recon findings: AV:N but Confidentiality-only impact
 */
function pickVector(finding: IntelFinding): { vector: string; reason: string } {
  const lowerTitle = finding.title.toLowerCase();
  const source = finding.source.toLowerCase();

  if (source === 'trufflehog' || source === 'gitleaks' || source === 'semgrep') {
    return {
      vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      reason: 'local-only SAST/secret finding; AV:L because exploitation needs repo access',
    };
  }
  if (
    lowerTitle.includes('rce') ||
    lowerTitle.includes('remote code execution') ||
    lowerTitle.includes('command injection')
  ) {
    return {
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      reason: 'remote code execution → AV:N + full CIA impact',
    };
  }
  if (lowerTitle.includes('sql injection') || lowerTitle.includes('sqli')) {
    return {
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
      reason: 'SQLi → AV:N + C:H/I:H typical for data exfil & write',
    };
  }
  if (lowerTitle.includes('xss')) {
    return {
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
      reason: 'XSS → user interaction required, scope changed',
    };
  }
  if (['amass', 'subfinder', 'dnsx', 'cloud_enum', 'gau'].includes(source)) {
    return {
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
      reason: 'recon disclosure → confidentiality-only low impact',
    };
  }
  return {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
    reason: 'generic network-exploitable finding',
  };
}

export function scoreFinding(finding: IntelFinding): ScoredFinding {
  const { baseScore, cvssSeverity } = severityToScore(finding.severity);
  const { vector, reason } = pickVector(finding);

  const evidence = evidenceTextOf(finding);
  const cveMatch = `${finding.title} ${evidence} ${finding.description ?? ''}`.match(CVE_PATTERN);

  return {
    ...finding,
    cvss: {
      baseScore,
      severity: cvssSeverity,
      vector,
      scoreReason: `${reason}; mapped from severity=${finding.severity}`,
      ...(cveMatch ? { cve: cveMatch[0].toUpperCase() } : {}),
    },
  };
}

export function scoreFindings(findings: readonly IntelFinding[]): ScoredFinding[] {
  return findings.map(scoreFinding);
}
