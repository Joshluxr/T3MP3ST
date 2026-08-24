import { describe, it, expect } from 'vitest';
import * as bugIntel from '../intel/bug-intel.js';
import * as deltaScan from '../intel/delta-scan.js';
import * as cvss from '../intel/cvss.js';
import type { IntelFinding } from '../intel/types.js';

const NOW = '2026-08-24T00:00:00.000Z';

function finding(partial: Partial<IntelFinding>): IntelFinding {
  return {
    id: 'f1',
    title: ' finding ',
    severity: 'high',
    target: 'https://app.example.com/users/12',
    source: 'nuclei',
    ...partial,
  } as IntelFinding;
}

describe('bug-intel memory', () => {
  it('signatures collapse id variants of the same finding', () => {
    const a = bugIntel.signatureOf({ title: 'SQL Injection', location: '/users/12' });
    const b = bugIntel.signatureOf({ title: 'sql   injection', location: '/users/987?q=1' });
    expect(a).toBe(b);
  });

  it('merges runs into new vs known records', () => {
    const first = bugIntel.mergeIntel(bugIntel.emptyIntelStore(), [
      { title: 'SQL Injection', severity: 'high', source: 'nuclei', location: '/users/12' },
    ], NOW);
    expect(first.newCount).toBe(1);
    expect(first.knownCount).toBe(0);

    const second = bugIntel.mergeIntel(first.store, [
      { title: 'SQL Injection', severity: 'high', source: 'nuclei', location: '/users/44' },
      { title: 'Open Redirect', severity: 'medium', source: 'operator', location: '/logout' },
    ], NOW);
    expect(second.newCount).toBe(1); // open redirect
    expect(second.knownCount).toBe(1); // sqli variant coalesced by signature
    expect(second.store.records).toHaveLength(2);

    const recurring = bugIntel.recurringSignatures(second.store);
    expect(recurring.map(r => r.title)).toContain('SQL Injection'); // count 2 across runs
  });

  it('renders an operator summary', () => {
    const merged = bugIntel.mergeIntel(bugIntel.emptyIntelStore(), [
      { title: 'SQL Injection', severity: 'high', source: 'nuclei' },
      { title: 'XSS', severity: 'medium', source: 'operator' },
    ], NOW);
    const summary = bugIntel.renderIntelSummary(merged.store, 2, 0);
    expect(summary).toMatch(/New this run: \*\*2\*\*/);
    expect(summary).toMatch(/Signatures in store: \*\*2\*\*/);
  });
});

describe('delta scan', () => {
  it('selects only endpoints not covered by the baseline', () => {
    const covered = deltaScan.baselineCoverage(['/api/v1/users', '/api/v1/orders']);
    const selected = deltaScan.selectNewEndpoints(
      [{ url: 'https://x.example/api/v1/users?id=1' }, { url: 'https://x.example/api/v2/users' }],
      covered,
    );
    expect(selected.map(e => e.url)).toEqual(['https://x.example/api/v2/users']);
  });

  it('empty baseline selects everything (full scan)', () => {
    const selected = deltaScan.selectNewEndpoints(
      [{ url: '/a' }, { url: '/b' }],
      deltaScan.baselineCoverage([]),
    );
    expect(selected).toHaveLength(2);
  });

  it('splits findings into fresh vs known by location coverage', () => {
    const { fresh, known } = deltaScan.classifyFindingsDelta(
      [
        { title: 'new bug', location: '/fresh/path' },
        { title: 'old bug', location: '/api/v1/users' },
      ],
      ['/api/v1/users'],
    );
    expect(fresh.map(f => f.title)).toEqual(['new bug']);
    expect(known.map(f => f.title)).toEqual(['old bug']);
  });
});

describe('cvss scoring', () => {
  it('assigns monotone base scores by severity with a valid vector', () => {
    const scored = cvss.scoreFindings([
      finding({ severity: 'info' }),
      finding({ severity: 'low' }),
      finding({ severity: 'medium' }),
      finding({ severity: 'high' }),
      finding({ severity: 'critical' }),
    ]);
    const scores = scored.map(s => s.cvss.baseScore);
    expect([...scores].sort((a, b) => a - b)).toEqual(scores);
    for (const s of scored) {
      expect(s.cvss.vector).toMatch(/^CVSS:3\.1\/AV:[NAL]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[HL]\/I:[HL]\/A:[HL]$/);
      expect(s.cvss.scoreReason).toBeTruthy();
    }
  });

  it('surfaces CVE references found in descriptions', () => {
    const s = cvss.scoreFinding(finding({ description: 'Matches CVE-2024-3094 behavior.' }));
    expect(s.cvss.cve).toBe('CVE-2024-3094');
  });
});
