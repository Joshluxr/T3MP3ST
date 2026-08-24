/**
 * Phase-0 (Shannon port plan) — real-logic tests, not smoke tests:
 *  - profile validation accepts/rejects real shape differences
 *  - autonomous unlock mutates gates/auth-doc/targets exactly as Shannon does
 *  - abort short-circuits Arsenal.execute() mid-scan (no more tool calls fire)
 *  - an empty PHASE A scan completes end-to-end and persists job.json
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, readFile, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { Arsenal } from '../arsenal/index.js';
import { ApprovalController } from '../arsenal/approval.js';
import { EvidenceVault } from '../evidence/index.js';
import type { CustomTool, ToolResult } from '../types/index.js';
import {
  createScanAbortController,
  ScanAbortedError,
} from '../scan/abort.js';
import {
  applyAutonomousFullAuthorization,
  isAutonomous,
} from '../scan/autonomous.js';
import { validateScanProfile } from '../scan/profile.js';
import { createDefaultLaneRegistry, LaneRegistry } from '../scan/lane-registry.js';
import { ScanWorkflow } from '../scan/workflow.js';
import {
  AUTONOMOUS_AUTH_DOC_PLACEHOLDER,
  PHASE_ORDER,
  type LaneResult,
  type ScanProfile,
} from '../scan/types.js';
import { createServer } from 'http';

function baseProfile(overrides: Partial<ScanProfile> = {}): ScanProfile {
  return {
    target: { urls: ['https://app.example.test'], hosts: ['app.example.test'] },
    lanes: { recon: { enabled: true } },
    ...overrides,
  };
}

const okTool: CustomTool = {
  name: 'ok_tool',
  description: 'test tool',
  category: 'recon',
  parameters: [],
  handler: async (): Promise<ToolResult> => ({ success: true, output: 'ok' }),
};

describe('scan profile validation', () => {
  it('accepts a minimal valid profile', () => {
    const r = validateScanProfile(baseProfile());
    expect(r.ok).toBe(true);
    expect(r.errors).toEqual([]);
  });

  it('accepts placeholder authorizationDocPath without complaint', () => {
    const r = validateScanProfile(baseProfile({ authorizationDocPath: AUTONOMOUS_AUTH_DOC_PLACEHOLDER }));
    expect(r.ok).toBe(true);
  });

  it('rejects a profile with an unknown lane id', () => {
    const r = validateScanProfile({ ...baseProfile(), lanes: { bogus_lane: { enabled: true } } });
    expect(r.ok).toBe(false);
    expect(r.errors.join(' ')).toMatch(/bogus_lane|additional/i);
  });

  it('rejects a profile missing target', () => {
    const r = validateScanProfile({ lanes: {} });
    expect(r.ok).toBe(false);
  });

  it('rejects malformed approval gate values', () => {
    const r = validateScanProfile(baseProfile({ approvalGates: { recon: 'yes' as never } }));
    expect(r.ok).toBe(false);
  });
});

describe('autonomous unlock', () => {
  it('flips every approval gate to auto, stamps the auth-doc placeholder, and widens empty targets', () => {
    const p = baseProfile({ target: { urls: [], hosts: [] }, approvalGates: { credential: 'manual' } });
    applyAutonomousFullAuthorization(p);
    expect(p.autonomous).toBe(true);
    expect(p.authorizationDocPath).toBe(AUTONOMOUS_AUTH_DOC_PLACEHOLDER);
    for (const g of ['recon', 'vulnerability-analysis', 'exploitation', 'credential', 'privesc', 'lateral', 'reporting'] as const) {
      expect(p.approvalGates?.[g]).toBe('auto');
    }
    expect(p.target.hosts).toContain('*');
  });

  it('leaves a non-autonomous profile untouched', () => {
    const p = baseProfile({ approvalGates: { credential: 'manual' } });
    expect(isAutonomous(p)).toBe(false);
    expect(p.approvalGates?.credential).toBe('manual');
  });

  it('keeps an operator-supplied authorization doc path', () => {
    const p = baseProfile({ authorizationDocPath: '/roe/acme.pdf', autonomous: true });
    applyAutonomousFullAuthorization(p);
    expect(p.authorizationDocPath).toBe('/roe/acme.pdf');
  });
});

describe('arsenal abort integration', () => {
  let arsenal: Arsenal;
  beforeEach(() => {
    arsenal = new Arsenal();
    arsenal.register(okTool);
  });

  it('executes normally before abort and throws ScanAbortedError after', async () => {
    const abort = createScanAbortController();
    arsenal.setAbortController(abort);
    const r = await arsenal.execute('ok_tool', { parameters: {} });
    expect(r.success).toBe(true);
    abort.abort('operator');
    await expect(arsenal.execute('ok_tool', { parameters: {} })).rejects.toBeInstanceOf(ScanAbortedError);
    await expect(arsenal.execute('ok_tool', { parameters: {} })).rejects.toThrow(/operator/);
  });

  it('auto-passes scope + approval gates only under the autonomous unlock', async () => {
    const gatedTool: CustomTool = { ...okTool, name: 'spicy', riskTier: 'dangerous' };
    arsenal.register(gatedTool);
    arsenal.setScope({ allowedHosts: ['allowed.test'], allowPrivate: false, allowLoopback: false });
    arsenal.setApprovalController(new ApprovalController({}));

    // Interactive: scope denies an out-of-scope host.
    const denied = await arsenal.execute('spicy', { parameters: { target: 'evil.test' } });
    expect(denied.success).toBe(false);
    expect(denied.error).toMatch(/SCOPE DENIED/);

    // Autonomous: same call passes, and the approval gate auto-approves the dangerous tier.
    arsenal.setAutonomous(true);
    const passed = await arsenal.execute('spicy', { parameters: { target: 'evil.test' } });
    expect(passed.success).toBe(true);
    expect(arsenal.getApprovalController()?.isApproved('spicy')).toBe(true);
  });
});

describe('scan workflow (in-process)', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 't3-scan-test-'));
  });

  it('completes an empty PHASE A scan and persists job.json', async () => {
    const arsenal = new Arsenal();
    const vault = new EvidenceVault();
    const wf = new ScanWorkflow({
      arsenal,
      vault,
      registry: createDefaultLaneRegistry(),
      reportsDir: dir,
    });
    const job = wf.start(baseProfile());
    const done = await wf.waitForJob(job.id, 10000);
    expect(done.status).toBe('completed');
    const persisted = JSON.parse(await readFile(join(done.deliverablesDir, 'job.json'), 'utf8'));
    expect(persisted.id).toBe(job.id);
    expect(persisted.status).toBe('completed');
    await rm(dir, { recursive: true, force: true });
  });

  it('real default recon lane calls the live Arsenal HTTP primitive and persists artifacts', async () => {
    const server = createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain', 'x-test-route': req.url ?? '/' });
      res.end('live-recon-ok');
    });
    await new Promise<void>((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('test server did not bind a TCP port');

    try {
      const arsenal = new Arsenal();
      const realHttpTool: CustomTool = {
        name: 'http_request',
        description: 'real HTTP probe for the default recon lane',
        category: 'recon',
        parameters: [],
        handler: async (context): Promise<ToolResult> => {
          const url = String(context.parameters.url);
          const response = await fetch(url);
          return { success: response.ok, output: `${response.status} ${await response.text()}` };
        },
      };
      arsenal.register(realHttpTool);
      const vault = new EvidenceVault();
      const wf = new ScanWorkflow({ arsenal, vault, registry: createDefaultLaneRegistry(), reportsDir: dir });
      const target = `http://127.0.0.1:${address.port}/recon`;
      const job = wf.start(baseProfile({ target: { urls: [target], hosts: [] } }));
      const done = await wf.waitForJob(job.id, 10000);

      expect(done.status).toBe('completed');
      expect(done.lanes.recon?.status).toBe('succeeded');
      expect(done.lanes.recon?.summary).toMatch(/probed 1\/1 target/);
      const persisted = JSON.parse(await readFile(join(done.deliverablesDir, 'job.json'), 'utf8'));
      expect(persisted.lanes.recon.summary).toMatch(/real Arsenal HTTP primitive/);
    } finally {
      await new Promise<void>((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()));
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('report lane exports a real SARIF 2.1.0 artifact from recorded scan findings', async () => {
    const arsenal = new Arsenal();
    arsenal.register({
      ...okTool,
      name: 'http_request',
      handler: async () => ({
        success: true,
        output: 'HTTP 200',
        findings: [{
          title: 'Exposed debug endpoint',
          severity: 'high',
          details: 'GET /debug returned diagnostics',
          cwe: ['CWE-200'],
          provenance: 'tool',
          toolName: 'http_request',
          toolOutput: 'HTTP/1.1 200 OK\\nserver: test',
        }],
      }),
    });
    const vault = new EvidenceVault();
    const wf = new ScanWorkflow({ arsenal, vault, registry: createDefaultLaneRegistry(), reportsDir: dir });
    const job = wf.start(baseProfile({ lanes: { recon: { enabled: true }, report: { enabled: true } } }));
    const done = await wf.waitForJob(job.id, 10000);
    expect(done.status).toBe('completed');
    expect(done.findingRecords).toHaveLength(1);
    const sarif = JSON.parse(await readFile(join(done.deliverablesDir, 'report.sarif.json'), 'utf8'));
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].results[0].message.text).toMatch(/Exposed debug endpoint/);
    await rm(dir, { recursive: true, force: true });
  });

  it('abort mid-lane stops further arsenal.execute calls and marks the job aborted', async () => {
    const arsenal = new Arsenal();
    let calls = 0;
    arsenal.register({
      ...okTool,
      name: 'counter',
      handler: async () => { calls += 1; return { success: true }; },
    });
    const vault = new EvidenceVault();
    const registry = new LaneRegistry();
    registry.register({
      id: 'recon',
      phase: 'A',
      async run(ctx): Promise<LaneResult> {
        await ctx.arsenal.execute('counter', { parameters: {} }); // fires once
        ctx.abort.abort('operator');
        // The very next execute must short-circuit — that's the whole point of the wiring.
        await expect(ctx.arsenal.execute('counter', { parameters: {} })).rejects.toBeInstanceOf(ScanAbortedError);
        return { lane: 'recon', status: 'aborted', reason: 'operator', findings: [], artifacts: [] };
      },
    });
    const wf = new ScanWorkflow({ arsenal, vault, registry, reportsDir: dir });
    const events: string[] = [];
    wf.on('event', (e) => events.push(e.type));
    const job = wf.start(baseProfile({ autonomous: true }));
    const done = await wf.waitForJob(job.id, 10000);
    expect(done.status).toBe('aborted');
    expect(done.abortReason).toBe('operator');
    expect(calls).toBe(1); // exactly one tool call made it through
    expect(events).toContain('scan:created');
    expect(events).toContain('scan:lane_started');
    expect(events.some((e) => e === 'scan:aborted' || e === 'scan:lane_finished')).toBe(true);
    expect(PHASE_ORDER).toEqual(['A', 'B', 'C', 'report']);
    await rm(dir, { recursive: true, force: true });
  });

  it('autonomous scan auto-approves gated tools during the run, then restores the arsenal', async () => {
    const arsenal = new Arsenal();
    arsenal.register({ ...okTool, name: 'hydra_bruteforce', riskTier: 'credential' });
    arsenal.setApprovalController(new ApprovalController({}));
    const vault = new EvidenceVault();
    const registry = new LaneRegistry();
    registry.register({
      id: 'credential',
      phase: 'B',
      async run(ctx): Promise<LaneResult> {
        const r = await ctx.arsenal.execute('hydra_bruteforce', { parameters: {} });
        return { lane: 'credential', status: 'completed', findings: [], artifacts: [], reason: r.success ? 'ran' : r.error };
      },
    });
    const wf = new ScanWorkflow({ arsenal, vault, registry, reportsDir: dir });
    const job = wf.start(baseProfile({ autonomous: true, lanes: { credential: { enabled: true } } }));
    const done = await wf.waitForJob(job.id, 10000);
    expect(done.status).toBe('completed');
    // Autonomous state is scoped to the job — the shared arsenal is restored afterward.
    expect(arsenal.isAutonomous()).toBe(false);
    expect(arsenal.getAbortController()).toBeNull();
    await rm(dir, { recursive: true, force: true });
  });
});
