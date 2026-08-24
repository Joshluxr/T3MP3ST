/**
 * The Shannon-integration seam — shared types.
 *
 * Shannon's pure analysis modules (CVSS scoring, dedup, PoC, SARIF/STIX/HTML
 * export, intel enrichment, LLM analyzers) all consume one flat finding shape.
 * Rather than couple every ported module to T3MP3ST's rich `Finding`, they all
 * consume `AnalysisFinding` — a minimal, flat, tool-centric view. The adapter
 * that bridges the engine's `Finding` to it lives in `shannon-adapter.ts`.
 *
 * Two differences from T3MP3ST's `Finding` make that adapter more than a
 * rename (see `shannon-adapter.ts`):
 *  - **No top-level `tool` string.** Provenance lives in evidence metadata
 *    (`{ tool }`); the adapter synthesizes `tool` because
 *    `cvss-scoring.pickVector()` and PoC generation key on it.
 *  - **`targetId` is an opaque id, not a host.** The adapter resolves it via a
 *    caller-supplied `TargetResolver`, or exporters emit meaningless targets.
 */

import type { Severity } from '../types/index.js';

/**
 * Flat, tool-centric finding view consumed by every ported Shannon module.
 * Structurally identical to Shannon's `ToolFinding` (apps/worker/src/tools/tool.ts),
 * except `severity` reuses T3MP3ST's `Severity` (the identical `info|low|medium|
 * high|critical` set), so the port is lossless.
 */
export interface AnalysisFinding {
  /** Producing tool, e.g. "nuclei". Synthesized by the adapter when absent. */
  readonly tool: string;
  /** Host / URL string (resolved from targetId by the adapter). */
  readonly target: string;
  readonly title: string;
  readonly severity: Severity;
  readonly evidence?: string;
  /** CWE ids (e.g. "CWE-89") when the source finding carries them. */
  readonly cwe?: readonly string[];
  readonly raw?: unknown;
}

/**
 * Resolves an opaque `targetId` to a host/URL string. Returning `undefined`
 * (or empty) makes the adapter fall back to the raw id, keeping it total.
 */
export type TargetResolver = (targetId: string) => string | undefined;
