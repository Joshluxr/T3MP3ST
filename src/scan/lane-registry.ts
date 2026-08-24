/**
 * Lane registry (Phase 0). Holds ScanLane implementations keyed by LaneId and
 * resolves which lanes a profile wants per phase. Ships with no-op lanes for
 * every id so an empty scan can run end-to-end; real lanes replace them as
 * their phases land.
 */

import {
  PHASE_LANES,
  type LaneContext,
  type LaneId,
  type LaneResult,
  type ScanLane,
  type ScanPhase,
  type ScanProfile,
} from './types.js';
import { writeFile } from 'fs/promises';
import { join } from 'path';
import { exportSarif } from '../analysis/sarif-export.js';
import { toAnalysisFindings } from '../analysis/shannon-adapter.js';

export class LaneRegistry {
  private lanes = new Map<LaneId, ScanLane>();

  register(lane: ScanLane): void {
    this.lanes.set(lane.id, lane);
  }

  get(id: LaneId): ScanLane | undefined {
    return this.lanes.get(id);
  }

  /** Lane ids the profile wants for a phase, in canonical PHASE_LANES order.
   *  A lane runs only when it is registered AND enabled in the profile. */
  laneIdsForPhase(phase: ScanPhase, profile: ScanProfile): LaneId[] {
    return PHASE_LANES[phase].filter((id) => {
      if (!this.lanes.has(id)) return false;
      return profile.lanes?.[id]?.enabled === true;
    });
  }
}

/** Build a registry pre-populated with no-op lanes for every known id —
 *  the Phase-0 "empty PHASE A completes" baseline. Real lanes registered
 *  afterward overwrite the no-op for their id. */
export function createDefaultLaneRegistry(): LaneRegistry {
  const registry = new LaneRegistry();
  for (const [phase, ids] of Object.entries(PHASE_LANES) as Array<[ScanPhase, LaneId[]]>) {
    for (const id of ids) {
      if (id === 'recon') {
        registry.register({
          id,
          phase,
          async run(ctx: LaneContext): Promise<LaneResult> {
            const targets = Array.from(new Map(
              [...ctx.profile.target.urls, ...ctx.profile.target.hosts].map((value) => {
                const url = /^https?:\/\//i.test(value) ? value : `https://${value}`;
                try { return [new URL(url).toString(), url] as const; }
                catch { return [url.toLowerCase(), url] as const; }
              }),
            ).values());
            const findings: LaneResult['findings'] = [];
            const artifacts: string[] = [];
            let completed = 0;
            for (const target of targets) {
              ctx.abort.throwIfAborted();
              const url = /^https?:\/\//i.test(target) ? target : `https://${target}`;
              ctx.emit({ type: 'scan:lane_started', jobId: ctx.jobId, phase, lane: id, status: 'probing', detail: url, at: Date.now() });
              const result = await ctx.arsenal.execute('http_request', { parameters: { url, method: 'GET' } });
              if (!result.success) {
                artifacts.push(`${url}: ${result.error ?? 'request failed'}`);
                continue;
              }
              completed += 1;
              artifacts.push(result.output ?? `${url}: request completed`);
              for (const finding of result.findings ?? []) {
                findings.push({
                  tool: finding.toolName ?? 'http_request',
                  target: url,
                  title: finding.title,
                  severity: finding.severity,
                  evidence: finding.toolOutput ?? finding.details,
                  cwe: finding.cwe,
                  raw: finding,
                });
              }
            }
            return {
              lane: id,
              status: 'completed',
              summary: `probed ${completed}/${targets.length} target(s) with the real Arsenal HTTP primitive`,
              findings,
              artifacts,
            };
          },
        });
        continue;
      }
      if (id === 'report') {
        registry.register({
          id,
          phase,
          async run(ctx: LaneContext): Promise<LaneResult> {
            ctx.abort.throwIfAborted();
            const analysis = toAnalysisFindings(ctx.findings);
            const sarifPath = join(ctx.deliverablesDir, 'report.sarif.json');
            await writeFile(sarifPath, JSON.stringify(exportSarif(analysis), null, 2));
            return {
              lane: id,
              status: 'completed',
              summary: `exported ${analysis.length} finding(s) as SARIF 2.1.0`,
              findings: [],
              artifacts: [sarifPath],
            };
          },
        });
        continue;
      }
      registry.register({
        id,
        phase,
        async run(_ctx: LaneContext): Promise<LaneResult> {
          return { lane: id, status: 'skipped', summary: 'no implementation registered (scaffold)', findings: [], artifacts: [] };
        },
      });
    }
  }
  return registry;
}
