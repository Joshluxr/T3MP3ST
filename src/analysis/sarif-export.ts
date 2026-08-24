/**
 * SARIF 2.1.0 export (Tier 1).
 *
 * Ported from Shannon's `report-export.ts` — but ONLY the pure SARIF-assembly
 * core (`severityToLevel` + `buildSarifResult` + `buildSarifDocument`). Shannon's
 * surrounding machinery (zx, Temporal `ActivityInput`, a `ReportOutputProvider`,
 * and reads of on-disk `*_exploitation_queue.json` sidecars) is deliberately left
 * behind — it fights T3MP3ST's in-process, evidence-first architecture.
 *
 * This turns T3MP3ST from Markdown-only into a producer of a CI/GitHub-ingestible
 * artifact (GitHub code-scanning, Azure DevOps, and most SAST dashboards read
 * SARIF). It is a purely additive output: it never replaces `exportToMarkdown()`.
 *
 * Input is the flat `AnalysisFinding` (via the Shannon adapter), so scored/deduped
 * findings flow straight in. No I/O, no env reads — assembly only; the caller
 * serializes and writes.
 */

import type { AnalysisFinding } from './finding.js';

const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const SARIF_VERSION = '2.1.0';
const DRIVER_NAME = 'T3MP3ST';
const DRIVER_INFORMATION_URI = 'https://github.com/Joshluxr/T3MP3ST';

/** SARIF result levels per the 2.1.0 spec. */
export type SarifLevel = 'error' | 'warning' | 'note';

/** Normalized finding shape the SARIF assembler consumes. */
export interface NormalizedFinding {
  /** SARIF rule bucket: a vuln class, or a scanner source ('nuclei', 'tier-e', …). */
  readonly ruleId: string;
  readonly title: string;
  readonly severity: string;
  readonly description: string;
  readonly location?: string;
}

interface SarifMessage {
  readonly text: string;
}

interface SarifLocation {
  readonly physicalLocation: {
    readonly artifactLocation: {
      readonly uri: string;
    };
  };
}

export interface SarifResult {
  readonly ruleId: string;
  readonly level: SarifLevel;
  readonly message: SarifMessage;
  readonly locations?: readonly SarifLocation[];
}

export interface SarifDocument {
  readonly $schema: string;
  readonly version: string;
  readonly runs: ReadonlyArray<{
    readonly tool: {
      readonly driver: {
        readonly name: string;
        readonly informationUri: string;
      };
    };
    readonly results: readonly SarifResult[];
  }>;
}

// === Severity → SARIF Level Mapping ===

/** Map a free-form severity string onto a SARIF result level. */
export function severityToLevel(severity: string): SarifLevel {
  const normalized = severity.trim().toLowerCase();
  switch (normalized) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    default:
      return 'note';
  }
}

// === SARIF Assembly ===

export function buildSarifResult(finding: NormalizedFinding): SarifResult {
  const text = finding.description ? `${finding.title} — ${finding.description}` : finding.title;
  const base: SarifResult = {
    ruleId: finding.ruleId,
    level: severityToLevel(finding.severity),
    message: { text },
  };

  if (finding.location === undefined) return base;

  const locations: readonly SarifLocation[] = [
    { physicalLocation: { artifactLocation: { uri: finding.location } } },
  ];
  return { ...base, locations };
}

export function buildSarifDocument(findings: readonly NormalizedFinding[]): SarifDocument {
  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: DRIVER_NAME,
            informationUri: DRIVER_INFORMATION_URI,
          },
        },
        results: findings.map(buildSarifResult),
      },
    ],
  };
}

// === Adapter: AnalysisFinding → NormalizedFinding ===

/**
 * Normalize a flat `AnalysisFinding` into the SARIF assembler's input. `ruleId`
 * buckets by producing tool (SARIF groups results by rule); the target becomes
 * the artifact location so scans point at a host/URL.
 */
export function toNormalizedFinding(f: AnalysisFinding): NormalizedFinding {
  const description = (f.evidence ?? '').trim();
  const location = f.target.trim();
  return {
    ruleId: f.tool && f.tool.trim().length > 0 ? f.tool.trim() : 't3mp3st',
    title: f.title,
    severity: f.severity,
    ...(description.length > 0 ? { description } : { description: '' }),
    ...(location.length > 0 ? { location } : {}),
  };
}

/** Convenience: assemble a SARIF document straight from adapter findings. */
export function exportSarif(findings: readonly AnalysisFinding[]): SarifDocument {
  return buildSarifDocument(findings.map(toNormalizedFinding));
}
