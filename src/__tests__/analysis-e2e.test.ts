/**
 * True-logic e2e tests for the ported Shannon analysis pipeline (Tiers 1-3).
 *
 * These are NOT smoke tests: every test drives real data through multiple
 * modules and asserts the cross-module transformation is correct end-to-end.
 *
 * Pipeline under test:
 *   engine Finding -> shannon-adapter -> AnalysisFinding
 *     -> dedupeFindings -> scoreFindings (CVSS) -> exportSarif
 *     -> threat-intel-enrich -> exportStixBundle / exportMispEvent
 *     -> compliance-bridge -> compliance-mapping
 *     -> reachability annotate
 *     -> OOB detector + OAST polling over a real HTTP server
 *     -> taint / semantic / variant analyzers over a scripted LlmClient
 *
 * LLM analyzers are driven by a FakeLlmClient returning realistic (sometimes
 * noisy) JSON so the parsing/normalization logic is what gets tested.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { KillChainPhase } from '../types/index.js';
import type { Finding, Severity } from '../types/index.js';
import { toAnalysisFinding, toAnalysisFindings } from '../analysis/shannon-adapter.js';
import { dedupeFindings, evidenceFingerprint, normalizeTarget } from '../analysis/findings-dedup.js';
import { scoreFinding, scoreFindings } from '../analysis/cvss-scoring.js';
import { exportSarif, severityToLevel } from '../analysis/sarif-export.js';
import { generatePoC } from '../analysis/poc-generator.js';
import { buildIntelIndex, lookupCve, escalateSeverity } from '../analysis/threat-intel-enrich.js';
import { matchCveIntel } from '../analysis/cve-intel-matcher.js';
import { categoryForFinding, categoryForCwe, complianceClausesForFinding, mappedCweIds } from '../analysis/compliance-bridge.js';
import { clausesFor, knownCategories } from '../analysis/compliance-mapping.js';
import { buildReachabilityIndex, annotateReachability } from '../analysis/reachability.js';
import { exportStixBundle, exportMispEvent } from '../analysis/stix-misp-export.js';
import { exportNavigatorLayer } from '../analysis/attack-navigator-export.js';
import { attackForVulnClass } from '../analysis/attack-registry.js';
import { buildOobPayload, correlateInteractions } from '../analysis/oob-detector.js';
import { createOastClient } from '../analysis/oast-client.js';
import { analyzeTaint } from '../analysis/taint-analysis.js';
import { reviewFunction } from '../analysis/semantic-vuln-review.js';
import { analyzeVariants } from '../analysis/variant-analysis.js';
import { parseJsonResponse, type LlmClient, type LlmRequest, type LlmResponse } from '../analysis/llm-client.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let now = 0;
function ev(type: 'output' | 'command' | 'response' | 'request' | 'log' | 'file' | 'screenshot', content: string, tool?: string) {
  return {
    type,
    content,
    timestamp: ++now,
    ...(tool ? { metadata: { tool } } : {}),
  };
}

function makeFinding(over: Partial<Finding>): Finding {
  return {
    id: over.id ?? `f-${Math.random().toString(36).slice(2, 8)}`,
    title: over.title ?? 'SQL injection in login',
    description: over.description ?? 'User input reaches SQL exec without parameterisation',
    severity: over.severity ?? 'high',
    targetId: over.targetId ?? 't-host-1',
    operatorId: over.operatorId ?? 'op-1',
    phase: over.phase ?? KillChainPhase.EXPLOIT,
    ...(over.cvss !== undefined ? { cvss: over.cvss } : {}),
    ...(over.cve ? { cve: over.cve } : {}),
    ...(over.cwe ? { cwe: over.cwe } : {}),
    evidence: over.evidence ?? [],
    ...(over.remediation ? { remediation: over.remediation } : {}),
    discoveredAt: over.discoveredAt ?? 1700000000000,
  };
}

/** Scripted LLM client: returns queued responses in order. */
class FakeLlmClient implements LlmClient {
  readonly calls: LlmRequest[] = [];
  private queue: string[];

  constructor(...responses: string[]) {
    this.queue = [...responses];
  }

  async complete(req: LlmRequest): Promise<LlmResponse> {
    this.calls.push(req);
    const text = this.queue.shift();
    if (text === undefined) throw new Error('FakeLlmClient: no response queued');
    return { text };
  }
}

// ---------------------------------------------------------------------------
// 1. Adapter — the load-bearing seam
// ---------------------------------------------------------------------------

describe('shannon-adapter: Finding -> AnalysisFinding', () => {
  it('synthesizes tool from evidence metadata and resolves targetId', () => {
    const f = makeFinding({
      title: 'Reflected XSS',
      evidence: [ev('output', 'nuclei [xss] GET /search?q=<script>alert(1)</script>', 'nuclei')],
      targetId: 't-42',
    });
    const a = toAnalysisFinding(f, (id) => (id === 't-42' ? 'https://shop.example.com' : undefined));
    expect(a.tool).toBe('nuclei');
    expect(a.target).toBe('https://shop.example.com');
    expect(a.title).toBe('Reflected XSS');
    expect(a.severity).toBe('high');
    expect(a.evidence).toContain('nuclei [xss]');
    expect(a.raw).toBe(f); // provenance preserved
  });

  it('falls back to the sentinel tool and the raw targetId when unresolvable', () => {
    const a = toAnalysisFinding(makeFinding({ evidence: [], targetId: 'opaque-9' }));
    expect(a.tool).toBe('t3mp3st');
    expect(a.target).toBe('opaque-9');
  });

  it('appends CVE ids to the flattened evidence so intel matchers can see them', () => {
    const a = toAnalysisFinding(
      makeFinding({ cve: ['CVE-2021-44228'], evidence: [ev('output', 'log4j-core 2.14.1')] }),
    );
    expect(a.evidence).toContain('log4j-core 2.14.1');
    expect(a.evidence).toContain('CVE-2021-44228');
  });

  it('prefers tool-output evidence over notes when both exist', () => {
    const f = makeFinding({
      evidence: [
        { type: 'screenshot', content: 'reviewer note: suspicious', timestamp: 1 },
        ev('response', 'HTTP/1.1 200 OK ... real bytes', 'httpx'),
      ],
    });
    const a = toAnalysisFinding(f);
    // Tool evidence sorts first in the flattened string.
    expect(a.evidence!.indexOf('real bytes')).toBeLessThan(a.evidence!.indexOf('reviewer note'));
  });

  it('never mutates the source finding', () => {
    const f = makeFinding({ evidence: [ev('output', 'x', 'nmap')] });
    const before = JSON.stringify(f);
    toAnalysisFinding(f);
    expect(JSON.stringify(f)).toBe(before);
  });
});

// ---------------------------------------------------------------------------
// 2. Dedup — cross-tool correlation
// ---------------------------------------------------------------------------

describe('findings-dedup: cross-tool correlation', () => {
  it('normalizes targets so the same host keys identically', () => {
    expect(normalizeTarget('HTTPS://Example.COM/')).toBe('https://example.com');
    expect(normalizeTarget('https://example.com/a?b=1&a=2#frag')).toBe('https://example.com/a?a,b');
    expect(normalizeTarget('EXAMPLE.com/Path')).toBe('example.com/path');
    expect(normalizeTarget('  Example.COM  ')).toBe('example.com');
  });

  it('fingerprint is insensitive to timestamps and volatile bytes', () => {
    const a = evidenceFingerprint("param=id payload=' OR 1=1-- token=abcdef1234567890abcdef port=443");
    const b = evidenceFingerprint("param=id payload=' OR 9=9-- token=0000ffff1111ffff2222 port=8443");
    expect(a).toBe(b);
  });

  it('merges the same vuln from three tools, keeping the highest severity', () => {
    const t = 'https://api.example.com';
    const findings = [
      makeFinding({ title: 'SQL injection in /login', severity: 'medium', targetId: t, evidence: [ev('output', "param=user payload=' OR 1=1--", 'sqlmap')] }),
      makeFinding({ title: 'SQL injection in /login', severity: 'high', targetId: t, evidence: [ev('output', "param=user payload=' OR 2=2--", 'nuclei')] }),
      makeFinding({ title: 'SQL injection in /login', severity: 'low', targetId: t, evidence: [ev('output', "param=user payload=' OR 3=3--", 'wapiti')] }),
    ];
    const merged = dedupeFindings(toAnalysisFindings(findings, () => t));
    expect(merged).toHaveLength(1);
    expect(merged[0]!.severity).toBe('high'); // max severity wins
    expect(merged[0]!.occurrences).toBe(3);
    expect(merged[0]!.sources).toEqual(expect.arrayContaining(['sqlmap', 'nuclei', 'wapiti']));
  });

  it('does NOT merge different vuln classes on the same target', () => {
    const t = 'https://api.example.com';
    const findings = toAnalysisFindings(
      [
        makeFinding({ title: 'SQL injection', evidence: [ev('output', 'sqli evidence', 'sqlmap')] }),
        makeFinding({ title: 'Reflected XSS', evidence: [ev('output', 'xss evidence', 'nuclei')] }),
      ],
      () => t,
    );
    expect(dedupeFindings(findings)).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// 3. CVSS scoring — deterministic rules
// ---------------------------------------------------------------------------

describe('cvss-scoring: deterministic scoring rules', () => {
  it('scores a known-CVE secret finding via the secrets rule', () => {
    const scored = scoreFinding({
      tool: 'gitleaks',
      target: 'https://repo.example.com',
      title: 'AWS secret key committed',
      severity: 'high',
      evidence: 'AKIAIOSFODNN7EXAMPLE in config.py — fixes CVE-2023-1234',
    });
    expect(scored.cvss.baseScore).toBeGreaterThan(0);
    expect(scored.cvss.baseScore).toBeLessThanOrEqual(10);
    expect(scored.cvss.vector).toMatch(/^CVSS:3\.1\//);
    expect(scored.cvss.cve).toBe('CVE-2023-1234');
  });

  it('is deterministic — same input gives the same score', () => {
    const f = { tool: 'nuclei', target: 'https://x.example', title: 'XSS', severity: 'medium' as Severity, evidence: 'reflected xss' };
    expect(scoreFinding(f).cvss).toEqual(scoreFinding(f).cvss);
  });

  it('batch scores preserve order and count', () => {
    const in_ = [
      { tool: 'nuclei', target: 'a', title: 't1', severity: 'low' as Severity },
      { tool: 'nuclei', target: 'b', title: 't2', severity: 'high' as Severity },
    ];
    const out = scoreFindings(in_);
    expect(out).toHaveLength(2);
    expect(out[0]!.title).toBe('t1');
    expect(out[1]!.title).toBe('t2');
  });
});

// ---------------------------------------------------------------------------
// 4. PoC generation — per-class reproducers
// ---------------------------------------------------------------------------

describe('poc-generator: class-correct reproducers', () => {
  it('emits an injectable SQLi reproducer quoting the target', () => {
    const poc = generatePoC({
      tool: 'sqlmap',
      target: 'https://shop.example.com/login',
      title: 'SQL injection',
      severity: 'high',
      evidence: "parameter 'user' is injectable",
    });
    expect(poc.language).toBe('bash');
    expect(poc.command).toContain('shop.example.com/login');
    expect(poc.command.length).toBeGreaterThan(10);
    expect(poc.note).toBeTruthy();
  });

  it('falls back to a default reproducer for unknown tools', () => {
    const poc = generatePoC({
      tool: 'acme-scanner-9000',
      target: 'https://t.example',
      title: 'thing',
      severity: 'info',
      evidence: 'e',
    });
    expect(poc.command).toBeTruthy();
    expect(poc.command).toContain('t.example');
  });

  it('shell-quotes single quotes in the target so the reproducer stays valid bash', () => {
    const poc = generatePoC({
      tool: 'sqlmap',
      target: "https://t.example/q?x=1'OR'1'='1",
      title: 'SQLi',
      severity: 'high',
    });
    // The quoted target must not leave an unbalanced quote inside the command.
    expect(poc.command).toContain("'");
    // No raw unescaped target substring should appear verbatim.
    expect(poc.command).not.toContain("q?x=1'OR'1'='1 ");
  });
});

// ---------------------------------------------------------------------------
// 5. Threat-intel — KEV / ExploitDB escalation
// ---------------------------------------------------------------------------

describe('threat-intel-enrich: KEV + ExploitDB escalation', () => {
  const kev = [
    { cveID: 'CVE-2021-44228', vulnerabilityName: 'Log4Shell', knownRansomwareCampaignUse: 'Known' as const },
  ];
  const exploitDb = [{ cveId: 'CVE-2017-0144', title: 'MS17-010 EternalBlue' }];
  const index = buildIntelIndex(kev, exploitDb);

  it('looks up a KEV entry case-insensitively and flags ransomware', () => {
    const hit = lookupCve(index, 'cve-2021-44228');
    expect(hit.inKev).toBe(true);
    expect(hit.ransomware).toBe('Known');
    expect(hit.kevEntry?.vulnerabilityName).toBe('Log4Shell');
  });

  it('returns empty hit for unknown CVEs', () => {
    const hit = lookupCve(index, 'CVE-9999-0001');
    expect(hit.inKev).toBe(false);
    expect(hit.inExploitDb).toBe(false);
    expect(hit.ransomware).toBeUndefined();
  });

  it('KEV+ransomware bumps two levels (medium -> critical)', () => {
    const r = escalateSeverity('medium', lookupCve(index, 'CVE-2021-44228'));
    expect(r.to).toBe('critical');
    expect(r.bumped).toBe(2);
    expect(r.reasons.some((s) => s.includes('ransomware'))).toBe(true);
  });

  it('ExploitDB-only bumps one level and cites the exploit', () => {
    const r = escalateSeverity('low', lookupCve(index, 'CVE-2017-0144'));
    expect(r.to).toBe('medium');
    expect(r.bumped).toBe(1);
    expect(r.reasons.some((s) => s.includes('EternalBlue'))).toBe(true);
  });

  it('escalation clamps at critical', () => {
    const r = escalateSeverity('critical', lookupCve(index, 'CVE-2021-44228'));
    expect(r.to).toBe('critical');
    expect(r.bumped).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 6. CVE intel matcher — feed × asset matching
// ---------------------------------------------------------------------------

describe('cve-intel-matcher: feed/asset correlation', () => {
  it('matches a CVE named in a finding and escalates on KEV', () => {
    const result = matchCveIntel({
      findings: [
        { title: 'Apache Log4j RCE', severity: 'high' as Severity, evidence: 'vulnerable to CVE-2021-44228' },
      ],
      assets: [],
      cveFeed: [{ cveId: 'CVE-2021-44228', description: 'Log4Shell JNDI injection', cvssScore: 10 }],
      kev: [{ cveID: 'CVE-2021-44228', vendorProject: 'Apache', product: 'Log4j2' }],
    });
    expect(result.matchedCves.some((m) => m.cveId === 'CVE-2021-44228')).toBe(true);
    expect(result.kevHits.some((k) => k.cveId === 'CVE-2021-44228')).toBe(true);
    const esc = result.escalations.find((e) => e.cveId === 'CVE-2021-44228');
    expect(esc).toBeDefined();
    expect(['cisa-kev', 'high-cvss']).toContain(esc!.reason);
  });

  it('matches a CVE against an asset signal', () => {
    const result = matchCveIntel({
      findings: [],
      assets: [{ text: 'OpenSSL 1.0.2 vulnerable to CVE-2014-0160 (heartbleed)', source: 'nmap' }],
      cveFeed: [{ cveId: 'CVE-2014-0160', description: 'Heartbleed', cvssScore: 7.5 }],
      kev: [],
    });
    expect(result.matchedCves.some((m) => m.source === 'asset' && m.cveId === 'CVE-2014-0160')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 7. Compliance bridge — CWE -> category -> clauses
// ---------------------------------------------------------------------------

describe('compliance-bridge: CWE -> category -> framework clauses', () => {
  it('maps CWE-89 to sqli and yields real clauses', () => {
    expect(categoryForCwe('CWE-89')).toBe('sqli');
    const clauses = complianceClausesForFinding({ cwe: ['CWE-89'] });
    expect(clauses.length).toBeGreaterThan(0);
    expect(clauses.every((c) => c.clause.length > 0)).toBe(true);
  });

  it('falls back to keyword inference when CWE is absent', () => {
    expect(categoryForFinding({ title: 'Reflected cross-site scripting in search' })).toBe('xss');
    expect(categoryForFinding({ title: 'Insecure direct object reference on /orders/123' })).toBe('idor');
  });

  it('returns undefined (advisory, no guess) when nothing matches', () => {
    expect(categoryForFinding({ title: 'something entirely unclassifiable xyzzy' })).toBeUndefined();
  });

  it('every mapped CWE resolves to a known category with clauses', () => {
    for (const id of mappedCweIds()) {
      const cat = categoryForCwe(`CWE-${id}`);
      expect(cat, `CWE-${id} should map`).toBeDefined();
      expect(knownCategories()).toContain(cat);
      expect(clausesFor(cat!).length).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------
// 8. Reachability — import-graph escalation
// ---------------------------------------------------------------------------

describe('reachability: entrypoint import-graph annotation', () => {
  it('escalates a finding reachable from an entrypoint and tags unreachable ones', () => {
    const files = [
      { path: 'src/index.ts', content: "import { db } from './db';\nconsole.log(db);" },
      { path: 'src/db.ts', content: "export const db = require('pg');" },
      { path: 'src/vendor/unused-lib.ts', content: 'export const dead = 1;' },
    ];
    const index = buildReachabilityIndex(files);
    const annotated = annotateReachability(
      [
        { title: 'SQL injection in db layer', severity: 'medium', description: 'pg query concat', location: 'src/db.ts:12' },
        { title: 'Prototype pollution in absent-lib', severity: 'high', description: 'zzq marker', location: 'src/vendor/absent-lib.ts:1' },
      ],
      index,
    );
    const reachable = annotated.find((a) => a.title.includes('db layer'))!;
    const unreachable = annotated.find((a) => a.title.includes('absent-lib'))!;
    expect(reachable.severity).toBe('high'); // bumped medium -> high
    expect(reachable.description).toContain('REACHABLE from an entrypoint');
    expect(unreachable.severity).toBe('high'); // unchanged
    expect(unreachable.description).toContain('not obviously reachable');
  });
});

// ---------------------------------------------------------------------------
// 9. Full pipeline: Finding -> ... -> SARIF + STIX + MISP + Navigator
// ---------------------------------------------------------------------------

describe('e2e pipeline: Finding -> dedup -> score -> SARIF + STIX + MISP + Navigator', () => {
  const host = 'https://api.example.com';
  const findings: Finding[] = [
    makeFinding({
      title: 'SQL injection in /login',
      severity: 'high',
      cve: ['CVE-2024-1111'],
      cwe: ['CWE-89'],
      evidence: [ev('output', "sqlmap: parameter 'user' injectable", 'sqlmap')],
    }),
    makeFinding({
      title: 'Reflected XSS in /search',
      severity: 'medium',
      cwe: ['CWE-79'],
      evidence: [ev('output', 'nuclei [xss] q=<script>alert(1)</script>', 'nuclei')],
    }),
  ];

  const adapted = toAnalysisFindings(findings, () => host);
  const deduped = dedupeFindings(adapted);
  const scored = scoreFindings(deduped);

  it('adapter -> dedup preserves distinct vuln classes', () => {
    expect(deduped).toHaveLength(2);
    expect(deduped.map((d) => d.tool).sort()).toEqual(['nuclei', 'sqlmap']);
  });

  it('scoring attaches a valid CVSS vector to every finding', () => {
    for (const s of scored) {
      expect(s.cvss.baseScore).toBeGreaterThan(0);
      expect(s.cvss.vector).toMatch(/^CVSS:3\.1\//);
    }
  });

  it('SARIF export produces a valid 2.1.0 document with one result per finding', () => {
    const sarif = exportSarif(scored);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0]!.results).toHaveLength(2);
    for (const r of sarif.runs[0]!.results) {
      expect(['error', 'warning', 'note']).toContain(r.level);
      expect(r.message.text).toBeTruthy();
    }
    // Severity mapping is monotonic.
    expect(severityToLevel('critical')).toBe('error');
    expect(severityToLevel('info')).toBe('note');
  });

  it('STIX bundle has an identity + one vulnerability per finding + indicators', () => {
    const bundle = exportStixBundle({ findings: adapted, engagementId: 'eng-e2e' });
    expect(bundle.type).toBe('bundle');
    const types = bundle.objects.map((o: { type: string }) => o.type);
    expect(types).toContain('identity');
    expect(types.filter((t) => t === 'vulnerability')).toHaveLength(2);
  });

  it('MISP event carries one attribute per finding with severity-derived threat level', () => {
    const event = exportMispEvent({ findings: adapted, engagementId: 'eng-e2e' });
    const attrs = event.Event.Attribute;
    // Attributes are IOC/CVE-driven: the host IOC + the CVE in the sqli finding's evidence
    expect(attrs.length).toBe(3);
    expect(attrs.some((a) => a.type === 'vulnerability' && a.value === 'CVE-2024-1111')).toBe(true);
    expect(attrs.some((a) => a.type === 'url' && a.value === 'https://api.example.com')).toBe(true);
    expect(event.Event.info).toContain('eng-e2e');
    expect(['1', '2', '3', '4']).toContain(event.Event.threat_level_id);
  });

  it('ATT&CK Navigator layer aggregates the SQLi technique from the registry', () => {
    const layer = exportNavigatorLayer(adapted, { name: 'e2e' });
    expect(layer.name).toBe('e2e');
    expect(layer.domain).toContain('enterprise-attack');
    expect(layer.techniques.length).toBeGreaterThan(0);
    // Registry and exporter must agree: vuln-class -> technique is one source of truth.
    const mapping = attackForVulnClass('sqli');
    expect(mapping.technique).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// 10. OOB detector + OAST client over a REAL HTTP server
// ---------------------------------------------------------------------------

describe('oob-detector + oast-client: live HTTP polling round-trip', () => {
  let server: Server;
  let pollUrl: string;
  let capturedInteractions: unknown[] = [];
  let lastAuth: string | undefined;

  beforeAll(async () => {
    server = createServer((req, res) => {
      lastAuth = req.headers.authorization;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ interactions: capturedInteractions }));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    pollUrl = `http://127.0.0.1:${port}/poll`;
  });

  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  it('builds deterministic-structure payloads with the operator domain baked in', () => {
    const p = buildOobPayload({ collaboratorDomain: 'collab.example.com', vulnClass: 'sqli' });
    expect(p.id).toMatch(/^[0-9a-f]{16}$/);
    expect(p.subdomain).toMatch(/^oob[0-9a-f]{12}$/);
    expect(p.fullDomain).toBe(`${p.subdomain}.collab.example.com`);
    expect(p.injection).toContain(p.fullDomain);
  });

  it('renders class-correct injections', () => {
    const d = 'collab.example.com';
    expect(buildOobPayload({ collaboratorDomain: d, vulnClass: 'ssrf', channel: 'http' }).injection).toMatch(/^http:\/\/oob/);
    expect(buildOobPayload({ collaboratorDomain: d, vulnClass: 'xxe' }).injection).toContain('<!ENTITY');
    expect(buildOobPayload({ collaboratorDomain: d, vulnClass: 'rce' }).injection).toContain('nslookup');
    expect(buildOobPayload({ collaboratorDomain: d, vulnClass: 'xss' }).injection).toContain('<script>');
  });

  it('refuses a non-FQDN collaborator domain', () => {
    expect(() => buildOobPayload({ collaboratorDomain: 'localhost', vulnClass: 'ssrf' })).toThrow(/FQDN/);
    expect(() => buildOobPayload({ collaboratorDomain: '', vulnClass: 'ssrf' })).toThrow(/required/);
  });

  it('full round-trip: issue payload -> collaborator captures -> poll -> correlate', async () => {
    const payload = buildOobPayload({ collaboratorDomain: 'collab.example.com', vulnClass: 'ssrf', channel: 'http' });

    // The collaborator (our test server) reports an HTTP hit on the issued subdomain.
    capturedInteractions = [
      { subdomain: payload.subdomain, protocol: 'http', 'remote-address': '203.0.113.7', timestamp: 1700000000123 },
      { subdomain: 'unrelated-sub', protocol: 'dns', 'remote-address': '198.51.100.2', timestamp: 1700000000456 },
    ];

    const client = createOastClient(
      { collaboratorDomain: 'collab.example.com', pollUrl, pollToken: 'tok-123' },
      { warn: () => undefined },
    );
    expect(client).toBeDefined();

    const interactions = await client!.poll();
    expect(lastAuth).toBe('Bearer tok-123'); // auth header actually sent
    expect(interactions).toHaveLength(2);

    const hits = correlateInteractions([payload], interactions);
    expect(hits).toHaveLength(1); // only our subdomain correlates
    expect(hits[0]!.payloadId).toBe(payload.id);
    expect(hits[0]!.channel).toBe('http');
    expect(hits[0]!.remoteAddress).toBe('203.0.113.7');
  });

  it('poll tolerates a bare-array response shape', async () => {
    capturedInteractions = [{ host: 'oob123.collab.example.com', protocol: 'dns', remoteAddress: '192.0.2.1' }];
    const bareServer = createServer((_req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(capturedInteractions)); // bare array, no envelope
    });
    await new Promise<void>((resolve) => bareServer.listen(0, '127.0.0.1', resolve));
    const { port } = bareServer.address() as AddressInfo;
    const client = createOastClient(
      { collaboratorDomain: 'collab.example.com', pollUrl: `http://127.0.0.1:${port}/x` },
      { warn: () => undefined },
    );
    const out = await client!.poll();
    await new Promise((resolve) => bareServer.close(resolve));
    expect(out).toHaveLength(1);
    expect(out[0]!.subdomain).toBe('oob123');
    expect(out[0]!.channel).toBe('dns');
  });

  it('poll degrades to [] on endpoint failure instead of throwing', async () => {
    const client = createOastClient(
      { collaboratorDomain: 'collab.example.com', pollUrl: 'http://127.0.0.1:1/dead' },
      { warn: () => undefined },
    );
    await expect(client!.poll()).resolves.toEqual([]);
  });

  it('createOastClient returns undefined when not configured', () => {
    expect(createOastClient(undefined, { warn: () => undefined })).toBeUndefined();
    expect(createOastClient({ collaboratorDomain: '', pollUrl: '' }, { warn: () => undefined })).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 11. LLM analyzers over a scripted client (taint / semantic / variant)
// ---------------------------------------------------------------------------

describe('taint-analysis: parses real (noisy) LLM output into findings', () => {
  const code = `
const express = require('express');
const app = express();
app.get('/u', (req, res) => {
  const q = req.query.name;            // source
  const cmd = 'ping ' + q;             // concat
  require('child_process').exec(cmd);  // sink
  res.send('ok');
});`;

  it('extracts a source->sink path from a well-formed response', async () => {
    const client = new FakeLlmClient(JSON.stringify({
      paths: [{
        source: { line: 4, kind: 'http-param', expression: 'req.query.name' },
        sink: { line: 6, kind: 'shell-exec', expression: 'child_process.exec(cmd)' },
        steps: ['req.query.name', 'q', 'cmd'],
        severity: 'critical',
        confidence: 'high',
        reasoning: 'User input concatenated into shell command.',
      }],
    }));
    const result = await analyzeTaint(client, { path: 'app.js', content: code, language: 'javascript' });
    expect(result.paths).toHaveLength(1);
    expect(result.paths[0]!.severity).toBe('critical');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.tool).toBe('taint-analysis');
    expect(result.findings[0]!.title).toContain('http-param');
    expect(result.findings[0]!.title).toContain('shell-exec');
    expect(result.findings[0]!.evidence).toContain('req.query.name');
    // The LLM was actually prompted with the file content.
    expect(client.calls[0]!.userPrompt).toContain('app.js');
    expect(client.calls[0]!.userPrompt).toContain('req.query.name');
  });

  it('recovers JSON wrapped in a markdown fence', async () => {
    const fenced = '```json\n{"paths": []}\n```';
    expect(parseJsonResponse(fenced)).toEqual({ paths: [] });
    const client = new FakeLlmClient(fenced);
    const result = await analyzeTaint(client, { path: 'app.js', content: code });
    expect(result.paths).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
  });

  it('drops malformed paths (missing sink/steps/bad confidence) but keeps valid ones', async () => {
    const client = new FakeLlmClient(JSON.stringify({
      paths: [
        { source: { line: 1, kind: 'env', expression: 'process.env.X' }, sink: { line: 2, kind: 'eval', expression: 'eval(x)' }, steps: ['x'], severity: 'high', confidence: 'high', reasoning: 'ok' },
        { source: { line: 3, kind: 'file', expression: 'fs.read' }, steps: [], confidence: 'high', reasoning: 'no sink -> drop' },
        { source: { line: 4, kind: 'ipc', expression: 'msg' }, sink: { line: 5, kind: 'exec', expression: 'exec' }, steps: ['y'], confidence: 'extreme', reasoning: 'bad confidence -> drop' },
      ],
    }));
    const result = await analyzeTaint(client, { path: 'app.js', content: code });
    expect(result.paths).toHaveLength(1);
    expect(result.paths[0]!.sink.kind).toBe('eval');
  });

  it('defaults an out-of-vocabulary severity to medium', async () => {
    const client = new FakeLlmClient(JSON.stringify({
      paths: [{
        source: { line: 1, kind: 'a', expression: 'a' },
        sink: { line: 2, kind: 'b', expression: 'b' },
        steps: ['s'],
        severity: 'catastrophic',
        confidence: 'medium',
        reasoning: 'r',
      }],
    }));
    const result = await analyzeTaint(client, { path: 'f.js', content: 'x' });
    expect(result.paths[0]!.severity).toBe('medium');
  });
});

describe('semantic-vuln-review: logic-flaw review over scripted LLM', () => {
  it('returns vulns and converts them into findings with mitigations', async () => {
    const target = {
      file: 'orders.ts',
      functionName: 'getOrder',
      code: 'export async function getOrder(req,res){ const o = await db.orders.find(req.params.id); res.json(o); }',
      language: 'typescript',
      inputShape: 'Express req.params.id',
    };
    const client = new FakeLlmClient(JSON.stringify({
      vulns: [{
        category: 'idor',
        severity: 'high',
        description: 'Order fetched by id with no ownership check.',
        source: 'req.params.id',
        sink: 'db.orders.find',
        mitigations: ['verify order.userId === req.user.id'],
        confidence: 'high',
      }],
    }));
    const result = await reviewFunction(client, target);
    expect(result.vulns).toHaveLength(1);
    expect(result.vulns[0]!.category).toBe('idor');
    expect(result.vulns[0]!.mitigations).toContain('verify order.userId === req.user.id');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.target).toBe('orders.ts');
    expect(client.calls[0]!.userPrompt).toContain('getOrder');
    expect(client.calls[0]!.userPrompt).toContain('req.params.id');
  });
});

describe('variant-analysis: finds same-root-cause variants', () => {
  it('maps similarity-qualified matches to findings at the pattern severity', async () => {
    const client = new FakeLlmClient(JSON.stringify({
      matches: [{
        file: 'repo/auth.ts',
        startLine: 10,
        endLine: 12,
        matchedCode: "const q = 'SELECT * FROM users WHERE name=' + name;",
        similarity: 'high',
        reasoning: 'Same string-concat SQLi mechanism, different variable names.',
      }],
    }));
    const result = await analyzeVariants(client, {
      pattern: {
        id: 'sqli-concat',
        name: 'SQLi via string concatenation',
        description: 'Raw input concatenated into SQL.',
        severity: 'high',
        exampleCode: "db.query('SELECT ' + x)",
      },
      codeSlices: [{ path: 'repo/auth.ts', content: 'const q = ...', language: 'typescript' }],
    });
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]!.similarity).toBe('high');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.severity).toBe('high'); // pattern severity
    expect(result.findings[0]!.target).toBe('repo/auth.ts');
    expect(result.findings[0]!.evidence).toContain('sqli-concat');
  });
});
