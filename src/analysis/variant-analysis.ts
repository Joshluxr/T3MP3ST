/**
 * Variant analysis (Shannon F32, Tier E2).
 *
 * Given a known vulnerability pattern (e.g. "SQL injection via string
 * concatenation"), asks the LLM to scan a codebase slice for *variants* of
 * the same flaw. This is the "if it happened here, where else?" pass —
 * critical for bug-bounty-style comprehensive coverage.
 *
 * Advisory only: matches are hypotheses for the evidence gate.
 */

import type { AnalysisFinding } from './finding.js';
import type { Severity } from '../types/index.js';
import type { LlmClient } from './llm-client.js';
import { parseJsonResponse } from './llm-client.js';

export interface VulnPattern {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  /** Representative vulnerable code the variants should resemble. */
  readonly exampleCode?: string;
  readonly severity?: Severity;
}

export interface CodeSlice {
  readonly path: string;
  readonly content: string;
  readonly language?: string;
}

export interface VariantMatch {
  readonly file: string;
  readonly startLine: number;
  readonly endLine: number;
  readonly matchedCode: string;
  readonly similarity: 'high' | 'medium' | 'low';
  readonly reasoning: string;
}

export interface VariantAnalysisRequest {
  readonly pattern: VulnPattern;
  readonly codeSlices: readonly CodeSlice[];
}

export interface VariantAnalysisResult {
  readonly pattern: VulnPattern;
  readonly matches: readonly VariantMatch[];
  readonly findings: readonly AnalysisFinding[];
}

/** Scan code slices for variants of a known vulnerability pattern. */
export async function analyzeVariants(
  client: LlmClient,
  request: VariantAnalysisRequest,
): Promise<VariantAnalysisResult> {
  const user = buildVariantPrompt(request);
  const raw = await client.complete({ systemPrompt: SYSTEM_PROMPT, userPrompt: user });
  const matches = parseMatches(parseJsonResponse(raw.text));
  const findings = matches.map((m) => matchToFinding(request.pattern, m));
  return { pattern: request.pattern, matches, findings };
}

function buildVariantPrompt(req: VariantAnalysisRequest): string {
  const slices = req.codeSlices
    .map(
      (s) => `--- ${s.path} (${s.language ?? 'unknown'}) ---
\`\`\`${s.language ?? ''}
${s.content}
\`\`\``,
    )
    .join('\n\n');

  return `Known vulnerability pattern: ${req.pattern.name}

Description: ${req.pattern.description}
${req.pattern.exampleCode ? `\nReference vulnerable code:\n\`\`\`\n${req.pattern.exampleCode}\n\`\`\`\n` : ''}
Scan the following code for VARIANTS of this pattern — the same class of flaw
expressed differently (different variable names, different APIs, same root
cause). Do not report stylistic similarities; report the same vulnerability
mechanism.

${slices}

Respond with a single JSON object:
{
  "matches": [
    {
      "file": "...",
      "startLine": 1,
      "endLine": 2,
      "matchedCode": "...",
      "similarity": "high" | "medium" | "low",
      "reasoning": "..."
    }
  ]
}

Return { "matches": [] } when no variants exist.`;
}

function matchToFinding(pattern: VulnPattern, match: VariantMatch): AnalysisFinding {
  return {
    tool: 'variant-analysis',
    target: match.file,
    title: `Variant of ${pattern.name} (${match.file}:${match.startLine})`,
    severity: pattern.severity ?? 'medium',
    evidence: [
      `Pattern: ${pattern.id}`,
      `Location: ${match.file}:${match.startLine}-${match.endLine}`,
      `Similarity: ${match.similarity}`,
      `Reasoning: ${match.reasoning}`,
      '',
      match.matchedCode,
    ].join('\n'),
  };
}

// === System prompt + parsing ===

const SYSTEM_PROMPT = `You are a security researcher performing variant analysis: finding new instances of a known vulnerability pattern.

Rules:
1. Report only matches sharing the pattern's root-cause mechanism, not superficial similarity.
2. "high" similarity = same mechanism, minor renaming. "medium" = same flaw class via a different API. "low" = plausible but needs human confirmation.
3. Never report matches in code you cannot see fully.
4. Always respond with a single JSON object matching the requested schema.`;

const SIMILARITIES = new Set(['high', 'medium', 'low']);

function parseMatches(raw: unknown): readonly VariantMatch[] {
  const obj = raw as { matches?: unknown };
  const candidates = Array.isArray(obj?.matches) ? obj.matches : [];
  const matches: VariantMatch[] = [];

  for (const c of candidates) {
    const m = c as {
      file?: unknown;
      startLine?: unknown;
      endLine?: unknown;
      matchedCode?: unknown;
      similarity?: unknown;
      reasoning?: unknown;
    };
    if (typeof m?.file !== 'string') continue;
    if (typeof m.startLine !== 'number' || typeof m.endLine !== 'number') continue;
    if (typeof m.matchedCode !== 'string') continue;
    if (typeof m.similarity !== 'string' || !SIMILARITIES.has(m.similarity)) continue;
    if (typeof m.reasoning !== 'string') continue;

    matches.push({
      file: m.file,
      startLine: m.startLine,
      endLine: m.endLine,
      matchedCode: m.matchedCode,
      similarity: m.similarity as VariantMatch['similarity'],
      reasoning: m.reasoning,
    });
  }
  return matches;
}
