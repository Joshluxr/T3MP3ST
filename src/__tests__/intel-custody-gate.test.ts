import { describe, it, expect } from 'vitest';
import * as custody from '../intel/evidence-custody.js';
import * as reportGate from '../intel/report-gate.js';
import type { IntelFinding } from '../intel/types.js';

const NOW = '2026-08-24T00:00:00.000Z';

function finding(overrides: Partial<IntelFinding> = {}): IntelFinding {
  return {
    id: 'f-1',
    title: 'SQL Injection',
    severity: 'high',
    target: 'https://app.example.com/users',
    source: 'nuclei',
    evidenceEntries: [{ type: 'http-response', content: 'SQL syntax error near…' }],
    ...overrides,
  } as IntelFinding;
}

describe('evidence custody', () => {
  it('hashes evidence at capture time with size + provenance', () => {
    const records = custody.preserveFindingEvidence(finding(), NOW);
    expect(records).toHaveLength(1);
    const r = records[0];
    expect(r.id).toBe('f-1#0');
    expect(r.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(r.sizeBytes).toBe(Buffer.byteLength('SQL syntax error near…', 'utf8'));
    expect(r.source).toBe('nuclei');
    expect(r.target).toBe('https://app.example.com/users');
    expect(r.capturedAt).toBe(NOW);
  });

  it('verifies cleanly when nothing changed', () => {
    const f = finding();
    const records = custody.preserveFindingEvidence(f, NOW);
    expect(custody.verifyCustody(records, [f]).ok).toBe(true);
  });

  it('flags hash mismatch when evidence was edited after capture', () => {
    const records = custody.preserveFindingEvidence(finding(), NOW);
    const tampered = finding({
      evidenceEntries: [{ type: 'http-response', content: 'SQL syntax error near… EDITED' }],
    });
    const v = custody.verifyCustody(records, [tampered]);
    expect(v.ok).toBe(false);
    expect(['size-mismatch', 'hash-mismatch']).toContain(v.issues[0].reason);
    expect(v.issues[0].actualSha256).not.toBe(v.issues[0].expectedSha256);
  });

  it('flags missing evidence and orphan records', () => {
    const records = custody.preserveFindingEvidence(finding(), NOW);
    const v = custody.verifyCustody(records, []);
    expect(v.issues[0].reason).toBe('orphan-record');

    const stripped = custody.preserveFindingEvidence(finding(), NOW);
    const v2 = custody.verifyCustody(stripped, [finding({ evidenceEntries: [] })]);
    expect(v2.issues[0].reason).toBe('missing');
  });
});

describe('report gate', () => {
  it('blocks findings with no evidence', () => {
    const gate = reportGate.evaluateReportGate([finding({ evidenceEntries: [], evidence: undefined })]);
    expect(gate.blocked).toBe(true);
    expect(gate.summary.missingEvidence).toBe(1);
    expect(gate.violations[0].code).toMatch(/missing-evidence|evidence-missing/);
  });

  it('blocks custody integrity failures', () => {
    const records = custody.preserveFindingEvidence(finding(), NOW);
    const issues = custody.verifyCustody(records, [
      finding({ evidenceEntries: [{ type: 'http-response', content: 'changed' }] }),
    ]).issues;
    const gate = reportGate.evaluateReportGate([finding()], issues);
    expect(gate.blocked).toBe(true);
    expect(gate.summary.tampered).toBe(1);
  });

  it('passes a fully evidenced, untampered finding', () => {
    const gate = reportGate.evaluateReportGate([finding()], []);
    expect(gate.blocked).toBe(false);
    expect(gate.summary.checked).toBe(1);
  });
});
