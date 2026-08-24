/**
 * F24 — CVSS auto-scoring.
 *
 * Promotes a `ToolFinding` to a `ScoredFinding` by attaching a CVSS
 * v3.1 base score. The score is derived from a small ruleset rather
 * than an external NVD lookup so the function stays deterministic and
 * offline-safe: severity tag + finding category + tool category map to
 * a representative vector + score. Findings whose evidence string
 * contains a `CVE-YYYY-NNNN` identifier keep the CVE in the output for
 * manual cross-reference but do not trigger an online lookup.
 *
 * The reasoning trail (`scoreReason`) records which rule fired so the
 * operator can sanity-check the assigned score.
 */

import type { AnalysisFinding as ToolFinding } from './finding.js';

export interface ScoredFinding extends ToolFinding {
  readonly cvss: {
    readonly baseScore: number;
    readonly severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
    readonly vector: string;
    readonly scoreReason: string;
    readonly cve?: string;
  };
}

const CVE_PATTERN = /CVE-\d{4}-\d{4,7}/i;

/** Map the qualitative ToolFinding severity onto an indicative CVSS base score. */
function severityToScore(severity: ToolFinding['severity']): {
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
 * Pick a representative CVSS v3.1 vector based on the tool's category.
 * - Network-exploitable (most web/active scans): AV:N
 * - Local-only (SAST/secret scanners): AV:L
 * - Recon findings: AV:N but Confidentiality-only impact
 */
function pickVector(finding: ToolFinding): { vector: string; reason: string } {
  const lowerTitle = finding.title.toLowerCase();
  const tool = finding.tool.toLowerCase();

  if (tool === 'trufflehog' || tool === 'gitleaks' || tool === 'semgrep') {
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
  if (tool === 'amass' || tool === 'subfinder' || tool === 'dnsx' || tool === 'cloud_enum' || tool === 'gau') {
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

export function scoreFinding(finding: ToolFinding): ScoredFinding {
  const { baseScore, cvssSeverity } = severityToScore(finding.severity);
  const { vector, reason } = pickVector(finding);

  const evidence = finding.evidence ?? '';
  const cveMatch = evidence.match(CVE_PATTERN) ?? finding.title.match(CVE_PATTERN);

  return {
    ...finding,
    cvss: {
      baseScore,
      severity: cvssSeverity,
      vector,
      scoreReason: `${reason}; mapped from finding.severity=${finding.severity}`,
      ...(cveMatch ? { cve: cveMatch[0].toUpperCase() } : {}),
    },
  };
}

export function scoreFindings(findings: readonly ToolFinding[]): ScoredFinding[] {
  return findings.map(scoreFinding);
}
