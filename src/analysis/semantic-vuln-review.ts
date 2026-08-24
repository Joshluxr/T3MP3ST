/**
 * Semantic vulnerability review (Shannon F36, Tier E3).
 *
 * Given a function (or small module slice) plus the input shape it accepts,
 * asks the LLM to identify semantic/logic vulnerabilities — auth-bypass
 * mistakes, missing checks, confused-deputy patterns — that pure pattern
 * matching misses. This is where the LLM adds the most value over grep-style
 * analysis.
 *
 * Advisory only: output feeds the evidence gate as hypotheses; nothing here
 * asserts verified provenance.
 */

import type { AnalysisFinding } from './finding.js';
import type { Severity } from '../types/index.js';
import type { LlmClient } from './llm-client.js';
import { parseJsonResponse } from './llm-client.js';

export interface SemanticReviewTarget {
  readonly file: string;
  readonly functionName: string;
  readonly code: string;
  readonly language?: string;
  /** e.g. "Express req.body" — grounds the review in how input arrives. */
  readonly inputShape?: string;
}

export interface SemanticVuln {
  readonly category: string;
  readonly severity: Severity;
  readonly description: string;
  readonly sink: string;
  readonly mitigations: readonly string[];
  readonly confidence: 'low' | 'medium' | 'high';
}

export interface SemanticReviewResult {
  readonly target: SemanticReviewTarget;
  readonly vulns: readonly SemanticVuln[];
  readonly findings: readonly AnalysisFinding[];
}

/** Review a single function for semantic vulnerabilities. */
export async function reviewFunction(
  client: LlmClient,
  target: SemanticReviewTarget,
): Promise<SemanticReviewResult> {
  const user = buildReviewPrompt(target);
  const raw = await client.complete({ systemPrompt: SYSTEM_PROMPT, userPrompt: user });
  const vulns = parseVulns(parseJsonResponse(raw.text));
  const findings = vulns.map((v) => vulnToFinding(target, v));
  return { target, vulns, findings };
}

/** Review many functions sequentially (rate-limit friendly). */
export async function reviewFunctions(
  client: LlmClient,
  targets: readonly SemanticReviewTarget[],
): Promise<readonly SemanticReviewResult[]> {
  const results: SemanticReviewResult[] = [];
  for (const target of targets) {
    results.push(await reviewFunction(client, target));
  }
  return results;
}

function buildReviewPrompt(t: SemanticReviewTarget): string {
  const lang = t.language ?? 'unknown';
  return `Review this ${lang} function for semantic vulnerabilities.

File: ${t.file}
Function: ${t.functionName}
Input shape: ${t.inputShape ?? 'unknown'}

\`\`\`${lang}
${t.code}
\`\`\`

Look for: missing authorization checks, auth-bypass logic errors, confused
deputy, TOCTOU, insecure defaults, business-logic flaws, missing input
validation at trust boundaries, unsafe error handling that leaks state.

Respond with a single JSON object:
{
  "vulns": [
    {
      "category": "...",
      "severity": "critical" | "high" | "medium" | "low" | "info",
      "description": "...",
      "inputShape": "...",
      "sink": "...",
      "mitigations": ["..."],
      "confidence": "high" | "medium" | "low"
    }
  ]
}

Only report issues you can justify from the visible code. Return
{ "vulns": [] } if the function looks safe.`;
}

function vulnToFinding(target: SemanticReviewTarget, v: SemanticVuln): AnalysisFinding {
  return {
    tool: 'semantic-vuln-review',
    target: target.file,
    title: `${v.category} in ${target.functionName} (${target.file})`,
    severity: v.severity,
    evidence: [
      `Sink: ${v.sink}`,
      `Confidence: ${v.confidence}`,
      `Description: ${v.description}`,
      v.mitigations.length > 0 ? `Mitigations: ${v.mitigations.join('; ')}` : '',
    ]
      .filter(Boolean)
      .join('\n'),
  };
}

// === System prompt + parsing ===

const SYSTEM_PROMPT = `You are a security code reviewer specializing in semantic and logic vulnerabilities.

Rules:
1. Only report issues visible in the provided code — never assume hidden behavior.
2. Distinguish confirmed logic errors from style concerns; report only the former.
3. Severity reflects worst-case impact; confidence reflects certainty the issue is real and exploitable.
4. Always respond with a single JSON object matching the requested schema.`;

const SEVERITIES: readonly string[] = ['critical', 'high', 'medium', 'low', 'info'];
const CONFIDENCES = new Set(['low', 'medium', 'high']);

function parseVulns(raw: unknown): readonly SemanticVuln[] {
  const obj = raw as { vulns?: unknown };
  const candidates = Array.isArray(obj?.vulns) ? obj.vulns : [];
  const vulns: SemanticVuln[] = [];

  for (const c of candidates) {
    const v = c as {
      category?: unknown;
      severity?: unknown;
      description?: unknown;
      sink?: unknown;
      mitigations?: unknown;
      confidence?: unknown;
    };
    if (typeof v?.category !== 'string' || typeof v?.description !== 'string') continue;
    if (typeof v.confidence !== 'string' || !CONFIDENCES.has(v.confidence)) continue;

    const sev: Severity =
      typeof v.severity === 'string' && SEVERITIES.includes(v.severity)
        ? (v.severity as Severity)
        : 'medium';

    vulns.push({
      category: v.category,
      severity: sev,
      description: v.description,
      sink: String(v.sink ?? ''),
      mitigations: Array.isArray(v.mitigations) ? v.mitigations.map(String) : [],
      confidence: v.confidence as SemanticVuln['confidence'],
    });
  }
  return vulns;
}
