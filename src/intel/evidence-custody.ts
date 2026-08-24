/**
 * Evidence preservation + chain of custody.
 *
 * When a finding carries evidence (response bodies, command output, exploit
 * output, etc.) we want a defensible chain of custody so the finding survives
 * review:
 *
 *   - SHA-256 of the evidence content at capture time
 *   - ISO-8601 capture timestamp
 *   - Source tool / operator / target
 *   - Append-only chain-log semantics (one record per evidence item; the
 *     server persists records in its state snapshot)
 *
 * `verifyCustody()` re-hashes every recorded evidence item against the live
 * findings and flags mismatches — useful before publishing a report or
 * handing the engagement off to another operator. Because T3MP3ST evidence
 * lives as inline content strings (not files), custody records hold the hash
 * of the content captured at preserve time; verification re-derives the hash
 * from the live finding evidence.
 *
 * Ported from Shannon's evidence-preservation (F72)
 * (AGPL-3.0, (C) 2025 Keygraph, Inc.).
 */

import { createHash } from 'node:crypto';
import type { IntelFinding } from './types.js';

export interface CustodyRecord {
  readonly id: string;
  readonly capturedAt: string;
  readonly findingId: string;
  readonly evidenceType: string;
  readonly sha256: string;
  readonly sizeBytes: number;
  readonly source: string;
  readonly target?: string;
  readonly notes?: string;
}

/** SHA-256 a content string and return the lowercase hex digest. */
export function sha256Content(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

function recordId(findingId: string, index: number): string {
  return `${findingId}#${index}`;
}

/**
 * Build custody records for every evidence entry on a finding. Pure — the
 * caller (server) appends them to the custody log.
 */
export function preserveFindingEvidence(
  finding: IntelFinding,
  now: string,
): CustodyRecord[] {
  const records: CustodyRecord[] = [];
  const evidence = finding.evidenceEntries ?? (finding.evidence !== undefined ? [{ type: finding.evidenceType ?? 'output', content: finding.evidence }] : []);
  evidence.forEach((e, i) => {
    const content = String(e.content ?? '');
    records.push({
      id: recordId(finding.id, i),
      capturedAt: now,
      findingId: finding.id,
      evidenceType: String(e.type ?? 'output'),
      sha256: sha256Content(content),
      sizeBytes: Buffer.byteLength(content, 'utf8'),
      source: finding.source,
      ...(finding.target !== undefined ? { target: finding.target } : {}),
    });
  });
  return records;
}

export interface CustodyIssue {
  readonly id: string;
  readonly findingId: string;
  readonly reason: 'missing' | 'hash-mismatch' | 'size-mismatch' | 'orphan-record';
  readonly expectedSha256?: string;
  readonly actualSha256?: string;
}

export interface CustodyVerification {
  readonly ok: boolean;
  readonly checked: number;
  readonly issues: readonly CustodyIssue[];
}

/**
 * Re-hash every recorded evidence item against the live findings and confirm
 * the digest still matches what was logged at capture time. Catches tampering,
 * corruption, and post-hoc edits. Pure.
 */
export function verifyCustody(
  records: readonly CustodyRecord[],
  findings: readonly IntelFinding[],
): CustodyVerification {
  const byId = new Map(findings.map(f => [f.id, f]));
  const issues: CustodyIssue[] = [];

  for (const rec of records) {
    const finding = byId.get(rec.findingId);
    if (!finding) {
      issues.push({ id: rec.id, findingId: rec.findingId, reason: 'orphan-record' });
      continue;
    }
    const evidence = finding.evidenceEntries ?? (finding.evidence !== undefined ? [{ type: finding.evidenceType ?? 'output', content: finding.evidence }] : []);
    const index = Number(rec.id.split('#')[1] ?? '0');
    const entry = evidence[index];
    if (!entry) {
      issues.push({ id: rec.id, findingId: rec.findingId, reason: 'missing' });
      continue;
    }
    const content = String(entry.content ?? '');
    const actual = sha256Content(content);
    if (actual !== rec.sha256) {
      issues.push({
        id: rec.id,
        findingId: rec.findingId,
        reason: 'hash-mismatch',
        expectedSha256: rec.sha256,
        actualSha256: actual,
      });
      continue;
    }
    if (Buffer.byteLength(content, 'utf8') !== rec.sizeBytes) {
      issues.push({ id: rec.id, findingId: rec.findingId, reason: 'size-mismatch' });
    }
  }

  return { ok: issues.length === 0, checked: records.length, issues };
}
