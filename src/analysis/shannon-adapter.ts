/**
 * The integration seam: engine `Finding` → flat `AnalysisFinding`.
 *
 * Shannon's pure analysis modules consume a flat, tool-centric finding
 * (`AnalysisFinding`, mirroring Shannon's `ToolFinding`). T3MP3ST's engine
 * `Finding` (src/types) is a superset in most fields but differs in two ways
 * that make this adapter slightly more than a rename:
 *
 *  1. No top-level `tool` string. Provenance lives in the tool-evidence
 *     `metadata.tool` (set by the operator's recordFinding path). The adapter
 *     synthesizes `tool` (evidence metadata → 't3mp3st') because
 *     `cvss-scoring.pickVector()` and `poc-generator` key on `finding.tool`.
 *  2. `targetId` is an opaque id, NOT a host string. The adapter takes a
 *     `resolveTarget` fn (id → host/URL) so exporters emit meaningful targets.
 *
 * The flattened evidence string prefers real tool output (the honesty-gate
 * evidence types) so the fingerprint/PoC logic sees the same bytes the gate
 * verified. This module never mutates the source finding and never asserts
 * provenance it doesn't have.
 */

import type { Finding } from '../types/index.js';
import type { AnalysisFinding, TargetResolver } from './finding.js';

/** Evidence types that represent real machine/tool output (mirrors evidence/gate.ts). */
const TOOL_EVIDENCE = new Set(['output', 'command', 'response', 'request', 'log', 'file']);

/**
 * Pull the producing tool name from a finding. The operator's recordFinding
 * path stamps `metadata.tool` on tool-backed evidence; fall back to any
 * evidence metadata tool, then to a stable sentinel.
 */
function synthesizeTool(finding: Finding): string {
  const evidence = Array.isArray(finding.evidence) ? finding.evidence : [];
  for (const e of evidence) {
    const tool = e?.metadata?.['tool'];
    if (typeof tool === 'string' && tool.trim().length > 0) return tool.trim();
  }
  return 't3mp3st';
}

/**
 * Flatten a finding's evidence into a single string, preferring real tool
 * output over human/context notes so downstream fingerprinting keys on the
 * verified bytes. Appends CVE ids so the intel/CVSS matchers can see them.
 */
function flattenEvidence(finding: Finding): string | undefined {
  const evidence = Array.isArray(finding.evidence) ? finding.evidence : [];
  const toolParts: string[] = [];
  const otherParts: string[] = [];
  for (const e of evidence) {
    const content = String(e?.content ?? '').trim();
    if (content.length === 0) continue;
    if (TOOL_EVIDENCE.has(e.type)) toolParts.push(content);
    else otherParts.push(content);
  }
  const cve = Array.isArray(finding.cve) ? finding.cve.filter((c) => typeof c === 'string' && c.length > 0) : [];
  const parts = [...toolParts, ...otherParts];
  if (cve.length > 0) parts.push(cve.join(' '));
  if (finding.description && parts.length === 0) parts.push(finding.description);
  const joined = parts.join('\n').trim();
  return joined.length > 0 ? joined : undefined;
}

/**
 * Convert an engine `Finding` to the flat `AnalysisFinding` the ported Shannon
 * modules consume. `resolveTarget` maps the opaque `targetId` to a host/URL
 * string; when it returns empty/undefined the adapter falls back to the raw id.
 */
export function toAnalysisFinding(
  finding: Finding,
  resolveTarget: TargetResolver = () => undefined,
): AnalysisFinding {
  const resolved = resolveTarget(finding.targetId);
  const target = resolved && resolved.trim().length > 0 ? resolved.trim() : finding.targetId;
  const evidence = flattenEvidence(finding);
  return {
    tool: synthesizeTool(finding),
    target,
    title: finding.title,
    severity: finding.severity,
    ...(evidence !== undefined ? { evidence } : {}),
    ...(Array.isArray(finding.cwe) && finding.cwe.length > 0 ? { cwe: finding.cwe } : {}),
    raw: finding,
  };
}

/** Batch helper — convert every finding with the same resolver. */
export function toAnalysisFindings(
  findings: readonly Finding[],
  resolveTarget: TargetResolver = () => undefined,
): AnalysisFinding[] {
  return findings.map((f) => toAnalysisFinding(f, resolveTarget));
}
