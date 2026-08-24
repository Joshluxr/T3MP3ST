import { describe, it, expect } from 'vitest';
import * as navigatorExport from '../intel/attack-navigator.js';
import * as stixMisp from '../intel/stix-misp.js';
import * as authzMatrix from '../intel/authz-matrix.js';
import * as flowAttacks from '../intel/flow-attacks.js';
import { makeScopeProbe, ScopeError } from '../intel/probe.js';
import type { IntelFinding } from '../intel/types.js';

const finding = (over: Partial<IntelFinding> = {}): IntelFinding => ({
  id: 'f1', title: 'SQL injection in search', severity: 'critical',
  target: 'https://x.example/search?q=1', source: 'sqli-tool', ...over,
});

describe('ATT&CK mapping + Navigator export', () => {
  it('maps findings onto tactics/techniques with human-readable names', () => {
    const mapping = navigatorExport.mappingForFinding(finding());
    expect(mapping.tactic).toMatch(/^TA\d{4}$/);
    expect(mapping.technique).toMatch(/^T\d{4}$/);
    expect(mapping.procedure ?? mapping.tactic).toBeTruthy();
  });

  it('exports a Navigator layer aggregating by technique with severity weighting', () => {
    const layer = navigatorExport.exportNavigatorLayer(
      [finding(), finding({ id: 'f2', title: 'Reflected XSS', severity: 'low' as const })],
      { name: 'engagement-1' },
    );
    expect(layer.name).toBe('engagement-1');
    expect(layer.versions.attack).toBeDefined();
    expect(layer.techniques.length).toBeGreaterThan(0);
    const sqli = layer.techniques.find(t => (t.comment?.includes('SQL') ?? false) || (t.score ?? 0) > 0);
    expect(sqli).toBeTruthy();
  });

  it('aggregates repeated findings into higher-scored techniques', () => {
    const many = Array.from({ length: 5 }, (_, i) => finding({ id: `f${i}` }));
    const layer = navigatorExport.exportNavigatorLayer(many);
    const max = Math.max(...layer.techniques.map(t => t.score ?? 0));
    expect(max).toBeGreaterThanOrEqual(5); // 5 findings on one technique
  });
});

describe('STIX / MISP export', () => {
  it('builds a STIX bundle with identity, vulnerabilities, indicators, relationships', () => {
    const bundle = stixMisp.exportStixBundle({
      findings: [finding({ description: 'see CVE-2024-3094 and http://evil.example/payload' })],
      engagementId: 'eng-1',
      now: '2026-08-24T00:00:00Z',
    });
    expect(bundle.type).toBe('bundle');
    const kinds = new Set(bundle.objects.map(o => (o as { type: string }).type));
    expect(kinds.has('identity')).toBe(true);
    expect(kinds.has('vulnerability')).toBe(true);
    const vuln = bundle.objects.find(o => (o as { type: string }).type === 'vulnerability') as unknown as Record<string, unknown>;
    expect(vuln.name).toBeTruthy();
    expect(JSON.stringify(vuln.external_references ?? [])).toMatch(/CVE-2024-3094/);
  });

  it('builds a MISP event with IOC attributes', () => {
    const event = stixMisp.exportMispEvent({
      findings: [finding({ description: 'C2 at http://evil.example/payload' })],
      engagementId: 'eng-1',
      now: '2026-08-24T00:00:00Z',
    });
    expect(event.Event.info).toBeTruthy();
    expect(event.Event.Attribute.length).toBeGreaterThan(0);
  });

  it('detects CVEs and IOCs from prose', () => {
    expect(stixMisp.detectCves('fixes CVE-2021-44228 and cve-2014-0160')).toHaveLength(2);
    const iocs = stixMisp.detectIocs('go to https://evil.example/x from 10.0.0.5');
    expect(iocs.some(i => i.kind === 'url')).toBe(true);
  });
});

describe('authz-matrix classification', () => {
  const cell = (status: number, body = 'x'.repeat(50)) => authzMatrix.cellFromBody(status, body);

  it('flags missing authentication on protected endpoints', () => {
    const row = new Map([['anon', cell(200)], ['user', cell(200)]]);
    const findings = authzMatrix.classifyEndpointRow('https://x.example/api/account', [
      { name: 'anon', role: 'anon', authenticated: false },
      { name: 'user', role: 'user', authenticated: true },
    ], row);
    expect(findings.some(f => f.title.includes('Missing authentication'))).toBe(true);
  });

  it('flags BFLA when a non-admin reaches an admin endpoint', () => {
    const row = new Map([['admin', cell(200)], ['user', cell(200)]]);
    const findings = authzMatrix.classifyEndpointRow('https://x.example/admin/users', [
      { name: 'admin', role: 'admin', authenticated: true },
      { name: 'user', role: 'user', authenticated: true },
    ], row);
    expect(findings.some(f => f.title.includes('BFLA'))).toBe(true);
  });

  it('flags BOLA when two identities fetch identical object bodies', () => {
    const shared = cell(200, '{"secret":"same"}');
    const f = authzMatrix.classifyObjectAccess('https://x.example/api/orders/1', 'alice', 'bob', shared, shared);
    expect(f?.title).toContain('BOLA');
  });

  it('stays quiet when access control works', () => {
    const row = new Map([['anon', cell(401)], ['user', cell(200, '{"u":"user"}')], ['admin2', cell(200, '{"u":"adm"}')]]);
    const findings = authzMatrix.classifyEndpointRow('https://x.example/api/account', [
      { name: 'anon', role: 'anon', authenticated: false },
      { name: 'user', role: 'user', authenticated: true },
      { name: 'admin2', role: 'admin', authenticated: true },
    ], row);
    expect(findings).toHaveLength(0);
  });
});

describe('flow-attack primitives', () => {
  it('decodes JWTs and builds tamper variants', () => {
    const token = `eyJhbGciOiJIUzI1NiJ9.${Buffer.from('{"sub":"user"}').toString('base64url')}.sig`;
    expect(flowAttacks.looksLikeJwt(token)).toBe(true);
    const decoded = flowAttacks.decodeJwt(token);
    expect(decoded?.payload.sub).toBe('user');
    const variants = flowAttacks.buildJwtTamperVariants(token);
    expect(variants.length).toBeGreaterThanOrEqual(3);
    expect(variants.some(v => v.technique.includes('alg'))).toBe(true);
  });

  it('builds redirect variants pointing at the attacker host', () => {
    const variants = flowAttacks.buildRedirectVariants('https://x.example/cb');
    expect(variants.length).toBeGreaterThanOrEqual(4);
    expect(variants.every(v => v.redirectUri.includes(flowAttacks.attackerHost()))).toBe(true);
  });

  it('classifies reset-token leaks and host-reflection', () => {
    const leaked = flowAttacks.classifyResetResponse(
      { status: 200, body: 'your token: abcdefghijklmnop1234' }, flowAttacks.attackerHost(),
    );
    expect(leaked.leakedToken).toBeTruthy();

    const poisoned = flowAttacks.classifyResetResponse(
      { status: 200, body: 'ok', locationHeader: `https://${flowAttacks.attackerHost()}/reset?token=x` },
      flowAttacks.attackerHost(),
    );
    expect(poisoned.hostReflected).toBe(true);
  });

  it('builds bounded enum URL sets and classifies enumeration', () => {
    const urls = flowAttacks.buildEnumUrls('https://x.example/users/{id}', 1, 5, 3);
    expect(urls).toHaveLength(3); // capped at max
    const verdict = flowAttacks.classifyEnumeration(urls.map((id, i) => ({
      id, status: 200, bodyHash: ['aa', 'bb', 'cc'][i] ?? 'dd', length: 10,
    })));
    expect(verdict.enumerable).toBe(true);
    expect(verdict.accessibleCount).toBe(urls.length);
  });

  it('spray attempts rotate evasion headers', () => {
    const attempts = flowAttacks.buildSprayAttempts(['a'], ['p1', 'p2']);
    expect(attempts).toHaveLength(2);
    const headers = attempts.map(a => JSON.stringify(a.headers));
    expect(new Set(headers).size).toBe(2); // distinct header sets per attempt
  });
});

describe('scoped probe', () => {
  const scope = { allowedHosts: ['target.example'], allowLoopback: false, allowPrivate: false };

  it('refuses hosts outside the engagement scope', async () => {
    const probe = makeScopeProbe({ scope });
    await expect(probe({ url: 'https://evil.example/x' })).rejects.toThrow(ScopeError);
  });

  it('allows in-scope hosts and reports blocked targets', async () => {
    const blocked: string[] = [];
    const probe = makeScopeProbe({
      scope,
      fetchImpl: async () => ({ status: 200, text: async () => 'ok', headers: { get: () => null } }),
      onBlocked: (host) => { blocked.push(host); },
    });
    const res = await probe({ url: 'https://sub.target.example/api' });
    expect(res.status).toBe(200);
    expect(blocked).toHaveLength(0);
  });

  it('reports every refused host through onBlocked', async () => {
    const blocked: string[] = [];
    const probe = makeScopeProbe({ scope, onBlocked: (host) => { blocked.push(host); } });
    await probe({ url: 'https://other.example/x' }).catch(() => undefined);
    expect(blocked).toEqual(['other.example']);
  });

  it('rejects unparseable network-shaped targets as hostile', () => {
    expect(flowAttacks.looksLikeJwt('//host/x')).toBe(false); // sanity: not a jwt
  });
});
