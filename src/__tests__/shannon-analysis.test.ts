import { describe, expect, it } from 'vitest';
import { AnalysisEngine } from '../analysis/index.js';
import { annotateReachability, buildReachabilityIndex } from '../analysis/reachability.js';
import { toAnalysisFinding } from '../analysis/shannon-adapter.js';
import { EvidenceVault } from '../evidence/index.js';
import type { MissionControl } from '../mission/index.js';
import type { OpsecController } from '../opsec/index.js';
import { TargetEnvironment } from '../target/index.js';
import { KillChainPhase } from '../types/index.js';
import type { Finding } from '../types/index.js';

function makeEngine(): { engine: AnalysisEngine; vault: EvidenceVault; targetEnv: TargetEnvironment } {
  const vault = new EvidenceVault();
  const targetEnv = new TargetEnvironment();
  const engine = new AnalysisEngine(
    vault,
    targetEnv,
    {} as unknown as MissionControl,
    {} as unknown as OpsecController
  );
  return { engine, vault, targetEnv };
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: overrides.id ?? 'finding-1',
    title: overrides.title ?? 'SQL injection in login form',
    description: overrides.description ?? 'The username parameter is injectable',
    severity: overrides.severity ?? 'high',
    targetId: overrides.targetId ?? 'target-1',
    operatorId: overrides.operatorId ?? 'operator-1',
    phase: overrides.phase ?? KillChainPhase.EXPLOIT,
    evidence: overrides.evidence ?? [],
    remediation: overrides.remediation,
    cwe: overrides.cwe,
    exploitedAt: overrides.exploitedAt,
    discoveredAt: overrides.discoveredAt ?? 123,
  };
}

describe('shannon adapter (Finding -> AnalysisFinding)', () => {
  it('resolves targetId to the target address and synthesizes tool from evidence metadata', () => {
    const targetEnv = new TargetEnvironment();
    const target = targetEnv.addTarget({
      name: 'web', type: 'web_application', zone: 'dmz', address: 'https://app.example.test',
    });
    const finding = makeFinding({
      targetId: target.id,
      evidence: [
        { type: 'output', content: 'sqlmap identified the following injection point', timestamp: 1, metadata: { tool: 'sqlmap' } },
      ],
    });
    const af = toAnalysisFinding(finding, (id) => targetEnv.getTarget(id)?.address);
    expect(af.target).toBe('https://app.example.test');
    expect(af.tool).toBe('sqlmap');
    expect(af.title).toBe(finding.title);
    expect(af.severity).toBe(finding.severity);
  });

  it('falls back to raw id and engine provenance when resolver misses', () => {
    const af = toAnalysisFinding(makeFinding({ targetId: 'missing' }), () => undefined);
    expect(af.target).toBe('missing');
    expect(af.tool).toBe('t3mp3st');
    expect(af.evidence).toContain('username parameter');
  });
});

describe('engine wiring (Tiers 1-3)', () => {
  it('getAnalysisFindings bridges vault findings through the adapter', () => {
    const { engine, vault, targetEnv } = makeEngine();
    const target = targetEnv.addTarget({ name: 'web', type: 'web_application', zone: 'dmz', address: '10.0.0.5' });
    vault.addFinding(makeFinding({ targetId: target.id, evidence: [{ type: 'output', content: 'nuclei: CVE-2021-41773', timestamp: 1, metadata: { tool: 'nuclei' } }] }));
    const findings = engine.getAnalysisFindings();
    expect(findings).toHaveLength(1);
    expect(findings[0]?.target).toBe('10.0.0.5');
    expect(findings[0]?.tool).toBe('nuclei');
  });

  it('scoreFindingsCvss attaches a deterministic cvss block ordered by severity', () => {
    const { engine, vault, targetEnv } = makeEngine();
    const target = targetEnv.addTarget({ name: 'web', type: 'web_application', zone: 'dmz', address: 'https://app.example.test' });
    vault.addFinding(makeFinding({ id: 'f1', severity: 'critical', title: 'RCE via command injection', targetId: target.id }));
    vault.addFinding(makeFinding({ id: 'f2', severity: 'low', title: 'Missing X-Frame-Options header', targetId: target.id }));
    const scored = engine.scoreFindingsCvss();
    expect(scored).toHaveLength(2);
    const critical = scored.find((s) => s.title.includes('RCE'));
    const low = scored.find((s) => s.title.includes('X-Frame'));
    expect(critical?.cvss.baseScore).toBeGreaterThan(low?.cvss.baseScore ?? 99);
    expect(critical?.cvss.vector).toMatch(/^CVSS:3\.1\//);
    expect(critical?.cvss.scoreReason.length).toBeGreaterThan(0);
  });

  it('correlateFindings collapses duplicate fingerprints across tools', () => {
    const { engine, vault, targetEnv } = makeEngine();
    const target = targetEnv.addTarget({ name: 'web', type: 'web_application', zone: 'dmz', address: 'https://app.example.test' });
    const evidence = 'SQL injection in /login?u=admin';
    vault.addFinding(makeFinding({ id: 'f1', title: 'sqli', targetId: target.id, evidence: [{ type: 'output', content: evidence, timestamp: 1, metadata: { tool: 'nuclei' } }] }));
    vault.addFinding(makeFinding({ id: 'f2', title: 'sqli', targetId: target.id, evidence: [{ type: 'output', content: evidence, timestamp: 2, metadata: { tool: 'sqlmap' } }] }));
    const correlated = engine.correlateFindings();
    expect(correlated).toHaveLength(1);
    expect(correlated[0]?.occurrences).toBe(2);
    expect([...(correlated[0]?.sources ?? [])].sort()).toEqual(['nuclei', 'sqlmap']);
  });

  it('generateReproducers emits copy-paste commands', () => {
    const { engine, vault, targetEnv } = makeEngine();
    const target = targetEnv.addTarget({ name: 'web', type: 'web_application', zone: 'dmz', address: 'https://app.example.test/login?u=1' });
    vault.addFinding(makeFinding({ targetId: target.id, title: 'SQL injection', evidence: [{ type: 'output', content: 'sqlmap identified injection', timestamp: 1, metadata: { tool: 'sqlmap' } }] }));
    const reproducers = engine.generateReproducers();
    expect(reproducers).toHaveLength(1);
    expect(reproducers[0]?.reproducer.command).toContain('sqlmap');
    expect(reproducers[0]?.reproducer.command).toContain('app.example.test');
  });

  it('exportSarif emits schema-2.1.0 with a rule and result per finding', () => {
    const { engine, vault, targetEnv } = makeEngine();
    const target = targetEnv.addTarget({ name: 'web', type: 'web_application', zone: 'dmz', address: 'https://app.example.test' });
    vault.addFinding(makeFinding({ targetId: target.id, evidence: [{ type: 'output', content: 'x', timestamp: 1, metadata: { tool: 'nuclei' } }] }));
    const sarif = engine.exportSarif();
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-2.1.0');
    const run = sarif.runs[0];
    expect(run?.tool.driver.name).toBe('T3MP3ST');
    expect(run?.results).toHaveLength(1);
    expect(run?.results[0]?.ruleId).toBe('nuclei');
  });

  it('exportNavigatorLayer aggregates findings into ATT&CK techniques', () => {
    const { engine, vault, targetEnv } = makeEngine();
    const target = targetEnv.addTarget({ name: 'web', type: 'web_application', zone: 'dmz', address: 'https://app.example.test' });
    vault.addFinding(makeFinding({ title: 'SQL injection in login form', targetId: target.id }));
    vault.addFinding(makeFinding({ id: 'f2', title: 'SQL injection in search', targetId: target.id }));
    const layer = engine.exportNavigatorLayer({ name: 'Test Engagement' });
    expect(layer.name).toBe('Test Engagement');
    expect(layer.versions.layer).toBe('4.5');
    const sqli = layer.techniques.find((t) => t.techniqueID === 'T1190');
    expect(sqli).toBeDefined();
    expect(sqli?.score).toBe(2);
  });

  it('exportStixBundle is deterministic for fixed now/bundleId and links IOC indicators', () => {
    const { engine, vault, targetEnv } = makeEngine();
    const target = targetEnv.addTarget({ name: 'web', type: 'web_application', zone: 'dmz', address: 'https://app.example.test' });
    vault.addFinding(makeFinding({
      title: 'Apache path traversal CVE-2021-41773',
      targetId: target.id,
      evidence: [{ type: 'output', content: 'vulnerable at http://10.0.0.5/cgi-bin/', timestamp: 1 }],
    }));
    const a = engine.exportStixBundle('mission-1', { now: '2026-01-01T00:00:00.000Z', bundleId: 'bundle--fixed' });
    const b = engine.exportStixBundle('mission-1', { now: '2026-01-01T00:00:00.000Z', bundleId: 'bundle--fixed' });
    expect(a.id).toBe('bundle--fixed');
    expect(a.objects.length).toBe(b.objects.length);
    const types = a.objects.map((o) => o.type);
    expect(types).toContain('identity');
    expect(types).toContain('vulnerability');
    expect(types).toContain('indicator');
    expect(types).toContain('relationship');
    const vuln = a.objects.find((o) => o.type === 'vulnerability');
    expect(JSON.stringify(vuln)).toContain('CVE-2021-41773');
  });

  it('exportMispEvent sets threat level from the worst severity', () => {
    const { engine, vault, targetEnv } = makeEngine();
    const target = targetEnv.addTarget({ name: 'web', type: 'web_application', zone: 'dmz', address: 'https://app.example.test' });
    vault.addFinding(makeFinding({ severity: 'high', targetId: target.id }));
    const event = engine.exportMispEvent('mission-1', { now: '2026-01-01T00:00:00.000Z' });
    expect(event.Event.date).toBe('2026-01-01');
    expect(event.Event.threat_level_id).toBe('1');
    expect(event.Event.info).toContain('mission-1');
  });

  it('enrichWithIntel escalates KEV-listed CVE findings (advisory)', () => {
    const { engine, vault, targetEnv } = makeEngine();
    const target = targetEnv.addTarget({ name: 'web', type: 'web_application', zone: 'dmz', address: 'https://app.example.test' });
    vault.addFinding(makeFinding({
      severity: 'low',
      title: 'Outdated Apache (CVE-2021-41773)',
      targetId: target.id,
    }));
    const escalations = engine.enrichWithIntel([
      {
        cveID: 'CVE-2021-41773',
        vendorProject: 'Apache',
        product: 'HTTP Server',
        vulnerabilityName: 'Path Traversal',
        dateAdded: '2021-11-03',
      },
    ]);
    expect(escalations).toHaveLength(1);
    expect(escalations[0]?.cve).toBe('CVE-2021-41773');
    expect(escalations[0]?.from).toBe('low');
    expect(['medium', 'high', 'critical']).toContain(escalations[0]?.to);
    expect(escalations[0]?.reasons.join(' ')).toContain('CISA KEV');
  });

  it('complianceForFinding maps CWE-89 findings to framework clauses via the CWE bridge', () => {
    const { engine } = makeEngine();
    const clauses = engine.complianceForFinding(toAnalysisFinding(makeFinding({ cwe: ['CWE-89'] })));
    expect(clauses.length).toBeGreaterThan(0);
    expect(clauses.some((c) => c.framework === 'asvs-v4')).toBe(true);
  });
});

describe('reachability (pure module)', () => {
  it('escalates findings whose tokens appear in reachable source', () => {
    const index = buildReachabilityIndex([
      { path: 'src/index.ts', content: 'import { handler } from "./handler"; handler();' },
      { path: 'src/handler.ts', content: 'import lodash from "lodash"; export const handler = () => lodash.merge({}, {});' },
      { path: 'src/unused.ts', content: 'export const dead = 1;' },
    ]);
    expect(index.reachableFiles.has('src/index.ts')).toBe(true);
    expect(index.reachableFiles.has('src/handler.ts')).toBe(true);

    const [reachable] = annotateReachability(
      [{ title: 'lodash prototype pollution', severity: 'medium', description: 'CVE-2020-8203 in lodash.merge' }],
      index
    );
    expect(reachable?.severity).toBe('high');
    expect(reachable?.description).toContain('REACHABLE');
  });
});
