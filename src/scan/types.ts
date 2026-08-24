/**
 * Scan orchestration — shared types (Phase 0 of the Shannon port plan).
 *
 * A ScanJob is a durable, lane-driven engagement run: the operator submits a
 * ScanProfile, the ScanWorkflow walks PHASE A/B/C/report, and each pluggable
 * ScanLane does its work against the existing Arsenal / EvidenceVault /
 * LLMBackbone. Abort is cooperative: a ScanAbortController wired into the
 * Arsenal short-circuits every subsequent tool call.
 */

import type { RulesOfEngagement } from '../types/index.js';
import type { Arsenal } from '../arsenal/index.js';
import type { EvidenceVault } from '../evidence/index.js';
import type { LLMBackbone } from '../llm/index.js';
import type { AnalysisFinding } from '../analysis/finding.js';
import type { Finding } from '../types/index.js';

/** Pluggable scan lanes. The 'recon' lane is always available; others self-skip
 *  when their preconditions (binaries, sources, sessions) are absent. */
export type LaneId =
  | 'recon'
  | 'tier_e'
  | 'browser_dast'
  | 'authz_matrix'
  | 'flow_attacks'
  | 'credential'
  | 'sol_audit'
  | 'chain_sim'
  | 'greybox_fuzz'
  | 'api_fuzz'
  | 'protocol_tests'
  | 'report'
  | 'integrations';

export type ScanPhase = 'A' | 'B' | 'C' | 'report';
export type ScanJobStatus = 'queued' | 'running' | 'completed' | 'aborted' | 'failed';
export type ApprovalGateMode = 'auto' | 'manual';

/** Canonical lane universe, in registration order. */
export const LANE_IDS: readonly LaneId[] = [
  'recon',
  'tier_e',
  'browser_dast',
  'authz_matrix',
  'flow_attacks',
  'credential',
  'sol_audit',
  'chain_sim',
  'greybox_fuzz',
  'api_fuzz',
  'protocol_tests',
  'report',
  'integrations',
];

/** Which lanes belong to which phase (Temporal workflow ordering parity). */
export const PHASE_LANES: Record<ScanPhase, readonly LaneId[]> = {
  A: ['recon', 'tier_e', 'browser_dast'],
  B: ['authz_matrix', 'flow_attacks', 'credential', 'sol_audit', 'chain_sim', 'api_fuzz', 'protocol_tests'],
  C: ['greybox_fuzz'],
  report: ['report', 'integrations'],
};

/** Phase execution order (Shannon pentestPipelineWorkflow PHASE A/B/C). */
export const PHASE_ORDER: readonly ScanPhase[] = ['A', 'B', 'C', 'report'];

/** Resolve which enabled lanes run for a phase, in canonical order. */
export function laneIdsForPhase(
  profile: ScanProfile,
  registry: { get(id: LaneId): ScanLane | undefined },
  phase: ScanPhase,
): LaneId[] {
  return PHASE_LANES[phase].filter((id) => {
    if (!registry.get(id)) return false;
    return profile.lanes?.[id]?.enabled === true;
  });
}

export const AUTONOMOUS_AUTH_DOC_PLACEHOLDER = 'operator-authorized-target';

export interface ScanProfile {
  name?: string;
  target: { urls: string[]; hosts: string[] };
  roe?: RulesOfEngagement;
  /** Placeholder strings like "operator-authorized-target" are allowed. */
  authorizationDocPath?: string;
  /** Shannon-compatible: unlock RoE, auto-approve gates, skip evidence hard gates. */
  autonomous?: boolean;
  approvalGates?: Partial<Record<
    'recon' | 'vulnerability-analysis' | 'exploitation' | 'credential' | 'privesc' | 'lateral' | 'reporting',
    ApprovalGateMode
  >>;
  docker?: { enabled: boolean; image?: string; network?: string };
  temporal?: { enabled: boolean; address?: string; taskQueue?: string };
  lanes?: Partial<Record<LaneId, { enabled: boolean; [k: string]: unknown }>>;
}

export interface ScanAbortController {
  readonly aborted: boolean;
  readonly reason: string | null;
  abort(reason: string): void;
  throwIfAborted(): void;
}

export class ScanAbortedError extends Error {
  constructor(readonly abortReason: string) {
    super(`Scan aborted: ${abortReason}`);
    this.name = 'ScanAbortedError';
  }
}

export interface ScanProgressEvent {
  type:
    | 'scan:created'
    | 'scan:phase'
    | 'scan:lane_started'
    | 'scan:lane_finished'
    | 'scan:aborted'
    | 'scan:completed';
  jobId: string;
  phase?: ScanPhase;
  lane?: LaneId;
  status?: string;
  detail?: string;
  at: number;
}

/** Per-lane runtime status recorded on the job. */
export interface LaneRunState {
  status: 'running' | 'succeeded' | 'failed' | 'skipped' | 'aborted';
  startedAt: number;
  finishedAt?: number;
  summary?: string;
  error?: string;
}

/** End-of-run rollup persisted as summary.json. */
export interface ScanSummary {
  jobId: string;
  name?: string;
  status: ScanJobStatus;
  startedAt?: number;
  completedAt?: number;
  findingCount: number;
  bySeverity: Record<string, number>;
  lanes: Record<string, number>;
  deliverablesDir: string;
}

export interface LaneResult {
  lane: LaneId;
  status: 'completed' | 'skipped' | 'failed' | 'aborted';
  summary?: string;
  reason?: string;
  /** Set when the lane noticed the abort controller mid-run. */
  aborted?: boolean;
  findings: AnalysisFinding[];
  artifacts: string[];
}

export interface LaneContext {
  jobId: string;
  profile: ScanProfile;
  arsenal: Arsenal;
  vault: EvidenceVault;
  llm?: LLMBackbone;
  abort: ScanAbortController;
  deliverablesDir: string;
  findings: readonly Finding[];
  emit: (event: ScanProgressEvent) => void;
}

export interface ScanLane {
  id: LaneId;
  phase: ScanPhase;
  run(ctx: LaneContext): Promise<LaneResult>;
}

export interface ScanJob {
  id: string;
  name?: string;
  createdAt: number;
  startedAt?: number;
  completedAt?: number;
  status: ScanJobStatus;
  profile: ScanProfile;
  /** Current phase while running; 'done' once finished. */
  phase: ScanPhase | 'done';
  lanes: Record<string, LaneRunState>;
  /** The scan's complete finding records, used by report/export lanes. */
  findingRecords: Finding[];
  /** Vault finding ids produced by this scan. */
  findings: string[];
  abortedBy?: string;
  abortReason?: string;
  error?: string;
  deliverablesDir: string;
}
