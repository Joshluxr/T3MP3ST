/**
 * In-process scan workflow runner (Shannon plan Phase 0/1 fallback).
 *
 * Executes the lane pipeline PHASE A → B → C → report with the same ordering a
 * Temporal `scanPipelineWorkflow` would, so the Temporal worker (when enabled via
 * profile.temporal / T3MP3ST_SCAN_TEMPORAL) can reuse the LaneRegistry verbatim.
 *
 * Lanes within a phase run concurrently (Promise.all). An abort short-circuits
 * the pipeline at the next phase boundary — and immediately inside Arsenal
 * (every execute() checks the same controller).
 *
 * Job state + deliverables persist under <reportsDir>/<jobId>/job.json.
 */

import { EventEmitter } from 'eventemitter3';
import { mkdir, writeFile } from 'fs/promises';
import { join, resolve } from 'path';
import { randomUUID } from 'crypto';
import type { Arsenal } from '../arsenal/index.js';
import type { EvidenceVault } from '../evidence/index.js';
import type { LLMBackbone } from '../llm/index.js';
import type { Finding } from '../types/index.js';
import { KillChainPhase } from '../types/index.js';
import { createScanAbortController, ScanAbortedError } from './abort.js';
import { applyAutonomousFullAuthorization } from './autonomous.js';
import { LaneRegistry } from './lane-registry.js';
import type {
  LaneContext,
  LaneId,
  LaneResult,
  ScanJob,
  ScanPhase,
  ScanProgressEvent,
  ScanProfile,
  ScanSummary,
} from './types.js';
import { laneIdsForPhase, PHASE_ORDER } from './types.js';

export interface ScanWorkflowDeps {
  arsenal: Arsenal;
  vault: EvidenceVault;
  llm?: LLMBackbone;
  registry: LaneRegistry;
  reportsDir: string;
}

export type ScanWorkflowEvents = {
  event: (e: ScanProgressEvent) => void;
};

export class ScanWorkflow extends EventEmitter<ScanWorkflowEvents> {
  private readonly jobs = new Map<string, ScanJob>();
  private readonly aborts = new Map<string, ReturnType<typeof createScanAbortController>>();
  private executionChain: Promise<void> = Promise.resolve();

  constructor(private readonly deps: ScanWorkflowDeps) {
    super();
  }

  listJobs(): ScanJob[] {
    return [...this.jobs.values()].sort((a, b) => b.createdAt - a.createdAt);
  }

  getJob(id: string): ScanJob | undefined {
    return this.jobs.get(id);
  }

  async waitForJob(id: string, timeoutMs = 30_000): Promise<ScanJob> {
    const startedAt = Date.now();
    while (true) {
      const job = this.jobs.get(id);
      if (!job) throw new Error(`Scan job not found: ${id}`);
      if (job.status === 'completed' || job.status === 'aborted' || job.status === 'failed') {
        await this.persistJob(job);
        return job;
      }
      if (Date.now() - startedAt >= timeoutMs) {
        throw new Error(`Timed out waiting for scan job ${id}`);
      }
      await new Promise<void>((resolveDelay) => setTimeout(resolveDelay, 10));
    }
  }

  abortJob(id: string, reason: string): boolean {
    const abort = this.aborts.get(id);
    const job = this.jobs.get(id);
    if (!job || job.status !== 'running') return false;
    abort?.abort(reason);
    return true;
  }

  private emitScan(e: ScanProgressEvent): void {
    this.emit('event', e);
  }

  private setPhase(job: ScanJob, phase: ScanPhase): void {
    job.phase = phase;
    this.emitScan({ type: 'scan:phase', jobId: job.id, phase, at: Date.now() });
  }

  /** Persist the job record to the deliverables dir (best-effort, never throws). */
  private async persistJob(job: ScanJob): Promise<void> {
    try {
      await mkdir(job.deliverablesDir, { recursive: true });
      await writeFile(join(job.deliverablesDir, 'job.json'), JSON.stringify(job, null, 2));
    } catch {
      // persistence is receipt-grade convenience, not a gate
    }
  }

  /**
   * Run a scan job end-to-end. Registers the job immediately, then drives it
   * asynchronously; callers can also `await` the returned promise for the final job.
   */
  start(profile: ScanProfile): ScanJob {
    const id = randomUUID();
    const deliverablesDir = resolve(join(this.deps.reportsDir, id));
    const job: ScanJob = {
      id,
      name: profile.name,
      status: 'queued',
      phase: 'A',
      profile,
      lanes: {},
      findingRecords: [],
      findings: [],
      createdAt: Date.now(),
      deliverablesDir,
    };
    this.jobs.set(id, job);
    const abort = createScanAbortController();
    this.aborts.set(id, abort);
    const runPromise = this.executionChain.then(() => this.run(job, abort));
    this.executionChain = runPromise.then(() => undefined, () => undefined);
    void runPromise.finally(() => void this.persistJob(job));
    return job;
  }

  private async run(job: ScanJob, abort: ReturnType<typeof createScanAbortController>): Promise<ScanJob> {
    const { arsenal, vault, llm, registry } = this.deps;
    const profile = job.profile;
    const prevAbort = arsenal.getAbortController();
    const prevAutonomous = arsenal.isAutonomous();

    job.status = 'running';
    job.startedAt = Date.now();
    arsenal.setAbortController(abort);

    this.emitScan({
      type: 'scan:created',
      jobId: job.id,
      at: Date.now(),
      detail: `autonomous=${Boolean(profile.autonomous)} lanes=${Object.keys(profile.lanes ?? {}).filter((l) => profile.lanes?.[l as LaneId]?.enabled).join(',') || '(none)'}`,
    });

    try {
      if (profile.autonomous) applyAutonomousFullAuthorization(profile);
      if (profile.autonomous) arsenal.setAutonomous(true);
      await mkdir(job.deliverablesDir, { recursive: true });

      const emit = (e: ScanProgressEvent): void => this.emitScan(e);
      const recordFindings = (result: LaneResult): void => {
        for (const partial of result.findings ?? []) {
          const target = partial.target || profile.target.urls[0] || profile.target.hosts[0] || 'scan';
          const finding: Finding = {
            id: randomUUID(),
            title: partial.title || 'Untitled finding',
            description: partial.evidence || '',
            severity: partial.severity,
            targetId: target,
            operatorId: `scan/${job.id}/${result.lane}`,
            phase: KillChainPhase.EXPLOIT,
            cwe: partial.cwe ? [...partial.cwe] : undefined,
            evidence: partial.evidence
              ? [{ type: 'output', content: partial.evidence, timestamp: Date.now(), metadata: { tool: partial.tool } }]
              : [],
            discoveredAt: Date.now(),
          };
          const stored = vault.addFinding(finding);
          job.findingRecords.push(stored);
          job.findings.push(stored.id);
        }
      };

      let abortedBy: string | undefined;

      for (const phase of PHASE_ORDER) {
        abort.throwIfAborted();
        this.setPhase(job, phase);
        const laneIds = laneIdsForPhase(profile, registry, phase);
        if (phase === 'report') await this.writeSummary(job);
        const runLane = async (laneId: LaneId): Promise<void> => {
            const lane = registry.get(laneId);
            if (!lane) return;
            const startedAt = Date.now();
            job.lanes[laneId] = { status: 'running', startedAt };
            this.emitScan({ type: 'scan:lane_started', jobId: job.id, lane: laneId, phase, at: startedAt });
            const ctx: LaneContext = {
              jobId: job.id,
              profile,
              arsenal,
              vault,
              llm,
              abort,
              deliverablesDir: job.deliverablesDir,
              findings: job.findingRecords,
              emit,
            };
            try {
              const result = await lane.run(ctx);
              job.lanes[laneId] = { status: 'succeeded', startedAt, finishedAt: Date.now(), summary: result.summary };
              if (laneId !== 'report' && laneId !== 'integrations') recordFindings(result);
              if (result.aborted) abortedBy = abortedBy ?? abort.reason ?? 'lane';
              this.emitScan({
                type: 'scan:lane_finished',
                jobId: job.id,
                lane: laneId,
                phase,
                status: 'succeeded',
                at: Date.now(),
                detail: result.summary,
              });
            } catch (err) {
              if (err instanceof ScanAbortedError) {
                job.lanes[laneId] = { status: 'aborted', startedAt, finishedAt: Date.now() };
                abortedBy = abortedBy ?? abort.reason ?? 'operator';
                this.emitScan({ type: 'scan:lane_finished', jobId: job.id, lane: laneId, phase, status: 'aborted', at: Date.now() });
                return;
              }
              const message = err instanceof Error ? err.message : String(err);
              job.lanes[laneId] = { status: 'failed', startedAt, finishedAt: Date.now(), error: message };
              this.emitScan({ type: 'scan:lane_finished', jobId: job.id, lane: laneId, phase, status: 'failed', at: Date.now(), detail: message });
            }
        };
        for (const laneId of laneIds) {
          await runLane(laneId);
          if (abortedBy) break;
        }
        if (abortedBy) abort.throwIfAborted();
      }

      job.status = 'completed';
      job.phase = 'done';
      job.completedAt = Date.now();
      this.emitScan({ type: 'scan:completed', jobId: job.id, at: job.completedAt });
    } catch (err) {
      job.completedAt = Date.now();
      if (err instanceof ScanAbortedError) {
        job.status = 'aborted';
        job.phase = 'done';
        job.abortedBy = abort.reason ?? 'operator';
        job.abortReason = job.abortedBy;
        this.emitScan({ type: 'scan:aborted', jobId: job.id, at: job.completedAt, detail: job.abortedBy });
      } else {
        job.status = 'failed';
        job.error = err instanceof Error ? err.message : String(err);
        this.emitScan({ type: 'scan:aborted', jobId: job.id, at: job.completedAt, detail: `failed: ${job.error}` });
      }
    } finally {
      arsenal.setAbortController(prevAbort);
      arsenal.setAutonomous(prevAutonomous);
      this.aborts.delete(job.id);
    }
    return job;
  }

  private async writeSummary(job: ScanJob): Promise<void> {
    const findings = job.findings
      .map((fid) => this.deps.vault.getFinding(fid))
      .filter((f): f is Finding => Boolean(f));
    const bySeverity: Record<string, number> = {};
    for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    const laneCounts: Record<string, number> = {};
    for (const s of Object.values(job.lanes)) laneCounts[s.status] = (laneCounts[s.status] ?? 0) + 1;
    const summary: ScanSummary = {
      jobId: job.id,
      name: job.name,
      status: job.status,
      startedAt: job.startedAt,
      completedAt: job.completedAt,
      findingCount: findings.length,
      bySeverity,
      lanes: laneCounts,
      deliverablesDir: job.deliverablesDir,
    };
    await mkdir(job.deliverablesDir, { recursive: true });
    await writeFile(join(job.deliverablesDir, 'summary.json'), JSON.stringify(summary, null, 2));
    await writeFile(join(job.deliverablesDir, 'findings.json'), JSON.stringify(findings, null, 2));
  }
}
