import { describe, it, expect } from 'vitest';
import * as navigatorExport from '../intel/attack-navigator.js';
import * as attack from '../intel/attack.js';
import * as stixMisp from '../intel/stix-misp.js';
import type { IntelFinding } from '../intel/types.js';

function finding(overrides: Partial<IntelFinding> = {}): IntelFinding {
  return {
    id: 'f-1',
    title: 'SQL injection in search',
    severity: 'high',
    target: 'https://app.example.com/search',
    source: 'nuclei',
    description: 'Union-based SQLi. See CVE-2024-3094.',
    ...overrides,
  } as IntelFinding;
}

describe('ATT&CK mapping', () => {
  it('maps vuln-class keywords from titles', () => {
    expect(attack.vulnClassFromTitle('Blind SQL Injection')).toBe('injection');
    expect(attack.vulnClassFromTitle('Reflected XSS')).toBe('xss');
    expect(attack.vulnClassFromTitle('SSRF in webhook')).toBe('ssrf');
    expect(attack.vulnClassFromTitle('IDOR on invoices')).toBe('authz');
    expect(attack.vulnClassFromTitle('nothing here')).toBeUndefined();
  });

  it('produces tactic/technique/procedure for each class', () => {
    const m = attack.attackForVulnClass('injection');
    expect(m.tactic).toMatch(/^TA\d{4}$/);
    expect(m.technique).toMatch(/^T\d{4}$/);
    expect(attack.renderAttackSummary(m)).toContain(m.tactic);
  });
});

describe('ATT&CK Navigator export', () => {
  it('aggregates findings into a Navigator layer with scored techniques', () => {
    const layer = navigatorExport.exportNavigatorLayer(
      [finding(), finding({ id: 'f-2', title: 'Stored XSS', severity: 'critical', source: 'operator' })],
      { name: 'Test engagement' },
    );
    expect(layer.name).toBe('Test engagement');
    expect(layer.versions.attack).toBe('14');
    expect(layer.versions.navigator).toBe('4.9.0');
    expect(layer.domain).toBe('enterprise-attack');
    expect(layer.techniques.length).toBeGreaterThan(0);
    for (const t of layer.techniques) {
      expect(t.techniqueID).toMatch(/^T\d{4}$/);
      expect(t.score).toBeGreaterThan(0);
      expect(t.comment ?? '').not.toBe('');
    }
    // severity weights: critical > high aggregates to a higher comment score list
    expect(layer.legendItems.length).toBeGreaterThan(0);
  });

  it('falls back to tool-name hints for non-vuln findings', () => {
    const layer = navigatorExport.exportNavigatorLayer(
      [finding({ title: 'nmap scan complete', source: 'nmap', severity: 'info' })],
    );
    expect(layer.techniques.length).toBeGreaterThan(0);
  });
});

describe('STIX/MISP export', () => {
  const input = {
    findings: [finding(), finding({
      id: 'f-2',
      title: 'Attacker host referenced',
      severity: 'medium',
      description: 'Payload fetched from http://evil.example/payload.js from 203.0.113.9',
    })],
    engagementId: 'eng-1',
    now: '2026-08-24T00:00:00.000Z',
  };

  it('builds a STIX 2.1 bundle with identity, vulnerabilities, indicators, relationships', () => {
    const bundle = stixMisp.exportStixBundle(input);
    expect(bundle.type).toBe('bundle');
    const ids = bundle.objects.filter(o => o.type === 'identity');
    expect(ids).toHaveLength(1);

    const vulns = bundle.objects.filter(o => o.type === 'vulnerability');
    expect(vulns).toHaveLength(2);
    expect(vulns[0].name).toContain('SQL injection');

    const indicators = bundle.objects.filter(o => o.type === 'indicator');
    expect(indicators.length).toBeGreaterThan(0); // CVE-2024-3094 + IOCs detected

    const rels = bundle.objects.filter(o => o.type === 'relationship');
    expect(rels.length).toBeGreaterThan(0);
  });

  it('detects CVEs and IOCs from finding text', () => {
    expect(stixMisp.detectCves('see CVE-2024-3094 and cve-2019-0708')).toEqual(
      expect.arrayContaining(['CVE-2024-3094', 'CVE-2019-0708']),
    );
    const iocs = stixMisp.detectIocs('http://evil.example/x from 203.0.113.9');
    expect(iocs).toEqual(expect.arrayContaining([
      { kind: 'url', value: 'http://evil.example/x' },
      { kind: 'ipv4', value: '203.0.113.9' },
    ]));
  });

  it('builds a MISP event with attributes per finding', () => {
    const event = stixMisp.exportMispEvent(input);
    expect(event.Event.info).toContain('eng-1');
    expect(event.Event.Attribute.length).toBeGreaterThan(0);
    expect(event.Event.Attribute.every((a: stixMisp.MispAttribute) => Boolean(a.type && a.value) && (a.to_ids === true || a.to_ids === false))).toBe(true);
  });
});
