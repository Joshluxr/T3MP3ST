import { describe, it, expect } from 'vitest';
import * as bugIntel from '../intel/bug-intel.js';
import * as deltaScan from '../intel/delta-scan.js';
import * as cvss from '../intel/cvss.js';
import * as custody from '../intel/evidence-custody.js';
import * as reportGate from '../intel/report-gate.js';
import type { IntelFinding } from '../intel/types.js';

const finding = (over: Partial<IntelFinding>): IntelFinding => ({
  id: 'f1', title: 'SQL injection', severity: 'high', target: 'https://x.com/search?q=1',
  source: 'sqli-tool', ...over,
});

describe('bug-intel memory', () => {
  it('separates new signatures from known ones across runs', () => {
    let store = bugIntel.emptyIntelStore();
    const run1 = bugIntel.mergeIntel(store, [
      { title: 'SQL injection', severity: 'high', source: 't', location: 'https://x.com/search?q=1' },
    ], '2026-08-24T00:00:00Z');
    expect(run1.newCount).toBe(1);
    expect(run1.knownCount).toBe(0);

    const run2 = bugIntel.mergeIntel(run1.store, [
      { title: 'SQL injection', severity: 'high', source: 't', location: 'https://x.com/search?q=999' }, // same signature (id collapsed)
      { title: 'New XSS', severity: 'medium', source: 't', location: 'https://x.com/?q=2' },
    ], '2026-08-25T00:00:00Z');
    expect(run2.newCount).toBe(1);
    expect(run2.knownCount).toBe(1);
    store = run2.store;

    const rec = store.records.find(r => r.title === 'SQL injection');
    expect(rec?.count).toBe(2);
    expect(rec?.lastSeen).toBe('2026-08-25T00:00:00Z');
  });

  it('collapses id variants into one signature', () => {
    expect(bugIntel.signatureOf({ title: 'SQL Injection', location: 'https://x.com/a/12?x=1' }))
      .toBe(bugIntel.signatureOf({ title: 'sql   injection', location: 'https://x.com/a/99' }));
  });

  it('surfaces recurring signatures and renders a summary', () => {
    const store = bugIntel.emptyIntelStore();
    const merged = bugIntel.mergeIntel(store, [
      { title: 'A', severity: 'low', source: 't' },
      { title: 'B', severity: 'low', source: 't' },
    ], '2026-08-24T00:00:00Z').store;
    const again = bugIntel.mergeIntel(merged, [
      { title: 'A', severity: 'low', source: 't' },
    ], '2026-08-25T00:00:00Z').store;
    expect(bugIntel.recurringSignatures(again).map(r => r.title)).toContain('A');
    expect(bugIntel.renderIntelSummary(again, 0, 1)).toMatch(/Previously-seen \(recurring\): \*\*1\*\*/);
  });
});

describe('delta scan', () => {
  it('selects only endpoints absent from the baseline', () => {
    const covered = deltaScan.baselineCoverage(['https://x.com/a', 'https://x.com/b#frag?x=1']);
    const fresh = deltaScan.selectNewEndpoints([
      { url: 'https://x.com/a' }, { url: 'https://x.com/c' },
    ], covered);
    expect(fresh.map(e => e.url)).toEqual(['https://x.com/c']);
  });

  it('empty baseline degrades to a full scan', () => {
    const fresh = deltaScan.selectNewEndpoints([{ url: 'https://x.com/a' }], deltaScan.baselineCoverage([]));
    expect(fresh).toHaveLength(1);
  });

  it('classifies findings into fresh vs known by coverage key', () => {
    const { fresh, known } = deltaScan.classifyFindingsDelta(
      [
        { title: 'old bug', location: 'https://x.com/a' },
        { title: 'new bug', location: 'https://x.com/z' },
      ],
      ['https://x.com/a'],
    );
    expect(known.map(f => f.title)).toEqual(['old bug']);
    expect(fresh.map(f => f.title)).toEqual(['new bug']);
  });
});

describe('CVSS v3.1 scoring', () => {
  it('scores by severity band and extracts CVE ids', () => {
    const scored = cvss.scoreFindings([
      finding({ description: 'patch per CVE-2024-3094' }),
      finding({ severity: 'low' as const, title: 'info leak' }),
    ]);
    const [sqli, leak] = scored;
    expect(sqli.cvss.baseScore).toBeGreaterThan(leak.cvss.baseScore);
    expect(sqli.cvss.severity).toBe('high');
    expect(sqli.cvss.vector).toMatch(/^CVSS:3\.1\/AV:/);
    expect(sqli.cvss.cve).toBe('CVE-2024-3094');
    expect(leak.cvss.cve).toBeUndefined();
  });
});

describe('evidence custody + report gate', () => {
  const withEvidence: IntelFinding = {
    ...finding({ id: 'cust-1' }),
    evidenceEntries: [{ type: 'http-response', content: 'HTTP/1.1 200 OK\n\nroot:x:0:0' }],
  };

  it('preserves evidence with a sha-256 digest and verifies it cleanly', () => {
    const records = custody.preserveFindingEvidence(withEvidence, '2026-08-24T00:00:00Z');
    expect(records).toHaveLength(1);
    expect(records[0].sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(records[0].sizeBytes).toBeGreaterThan(0);
    const verification = custody.verifyCustody(records, [withEvidence]);
    expect(verification.ok).toBe(true);
    expect(verification.issues).toHaveLength(0);
  });

  it('flags tampering when live evidence no longer matches the record', () => {
    const records = custody.preserveFindingEvidence(withEvidence, '2026-08-24T00:00:00Z');
    const tampered: IntelFinding = {
      ...withEvidence,
      evidenceEntries: [{ type: 'http-response', content: 'HTTP/1.1 200 OK\n\nhacker:x:0:0' }],
    };
    const verification = custody.verifyCustody(records, [tampered]);
    expect(verification.ok).toBe(false);
    expect(['size-mismatch', 'hash-mismatch']).toContain(verification.issues[0].reason);
  });

  it('flags orphaned custody records for deleted findings', () => {
    const records = custody.preserveFindingEvidence(withEvidence, '2026-08-24T00:00:00Z');
    const verification = custody.verifyCustody(records, []);
    expect(verification.issues[0].reason).toBe('orphan-record');
  });

  it('report gate blocks findings without evidence and fails on integrity issues', () => {
    const gate = reportGate.evaluateReportGate([withEvidence, finding({ id: 'bare-1' })]);
    expect(gate.blocked).toBe(true);
    expect(gate.summary.missingEvidence).toBe(1);

    const records = custody.preserveFindingEvidence(withEvidence, '2026-08-24T00:00:00Z');
    const tamperedGate = reportGate.evaluateReportGate(
      [withEvidence],
      custody.verifyCustody(records, [{ ...withEvidence, evidenceEntries: [{ type: 'http-response', content: 'swapped' }] }]).issues,
    );
    expect(tamperedGate.blocked).toBe(true);
    expect(tamperedGate.summary.tampered).toBe(1);
  });

  it('gate passes clean, evidence-backed, verified findings', () => {
    const verified: IntelFinding = { ...withEvidence, verifyGate: { passed: true, reasons: [] } };
    const gate = reportGate.evaluateReportGate([verified]);
    expect(gate.blocked).toBe(false);
    expect(gate.summary).toEqual({ checked: 1, missingEvidence: 0, tampered: 0, unverified: 0 });
  });
});
