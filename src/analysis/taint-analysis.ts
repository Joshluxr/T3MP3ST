/**
 * LLM-assisted taint analysis (Shannon F31, Tier E1).
 *
 * Given a source code file (or function slice), uses the LLM to trace
 * source → sink data flows and report potential injection vulnerabilities.
 * The LLM acts as the static-analysis engine; we parse its structured
 * findings and convert them into `AnalysisFinding` records.
 *
 * This is a best-effort static-analysis aid. Every finding is advisory:
 * it lands at 'medium' severity and is consumed downstream as a hypothesis
 * for the evidence gate, never as a verified result.
 */

import type { AnalysisFinding } from './finding.js';
import type { Severity } from '../types/index.js';
import type { LlmClient } from './llm-client.js';
import { parseJsonResponse } from './llm-client.js';

// === Types ===

export interface SourceFile {
  readonly path: string;
  readonly content: string;
  readonly language?: string;
}

export interface TaintSource {
  readonly line: number;
  readonly kind: string;
  readonly expression: string;
}

export interface TaintSink {
  readonly line: number;
  readonly kind: string;
  readonly expression: string;
}

export interface TaintPath {
  readonly source: TaintSource;
  readonly sink: TaintSink;
  readonly steps: readonly string[];
  readonly severity: Severity;
  readonly confidence: 'low' | 'medium' | 'high';
  readonly reasoning: string;
}

export interface TaintAnalysisResult {
  readonly file: string;
  readonly paths: readonly TaintPath[];
  readonly findings: readonly AnalysisFinding[];
}

// === Analysis ===

/** Run taint analysis over a single source file. */
export async function analyzeTaint(
  client: LlmClient,
  file: SourceFile,
): Promise<TaintAnalysisResult> {
  const user = buildTaintPrompt(file);
  const raw = await client.complete({ systemPrompt: SYSTEM_PROMPT, userPrompt: user });
  const paths = parseTaintPaths(parseJsonResponse(raw.text));
  const findings = paths.map((p) => pathToFinding(file.path, p));
  return { file: file.path, paths, findings };
}

function buildTaintPrompt(file: SourceFile): string {
  const lang = file.language ?? 'unknown';
  return `Perform taint analysis on the following ${lang} source file.

File: ${file.path}

\`\`\`${lang}
${file.content}
\`\`\`

Trace every data flow from user-controlled sources (request input, env vars,
file reads, IPC args) to dangerous sinks (SQL exec, shell exec, eval, SSRF,
deserialization, template rendering, file writes). For each flow report the
source, sink, intermediate steps, severity, and confidence.

Respond with a single JSON object:
{
  "paths": [
    {
      "source": { "line": 1, "kind": "...", "expression": "..." },
      "sink": { "line": 2, "kind": "...", "expression": "..." },
      "steps": ["..."],
      "severity": "critical" | "high" | "medium" | "low" | "info",
      "confidence": "high" | "medium" | "low",
      "reasoning": "..."
    }
  ]
}

Only report flows you can justify from the code. If there are none, return
{ "paths": [] }.`;
}

function pathToFinding(file: string, path: TaintPath): AnalysisFinding {
  return {
    tool: 'taint-analysis',
    target: file,
    title: `Taint: ${path.source.kind} → ${path.sink.kind} (${file}:${path.sink.line})`,
    severity: 'medium',
    evidence: `Source: line ${path.source.line} (${path.source.kind})\nSink: line ${path.sink.line} (${path.sink.kind})\nChain: ${path.steps.join(' → ')}\nConfidence: ${path.confidence}\n\nReasoning: ${path.reasoning}`,
  };
}

// === System prompt ===

const SYSTEM_PROMPT = `You are a security-focused static analysis engine performing taint analysis.

Rules:
1. Only report data flows you can trace through the provided code.
2. Do not speculate about code you cannot see (external functions, framework internals).
3. Prefer precision over recall — a false positive wastes triage time.
4. Severity reflects worst-case impact at the sink; confidence reflects how certain the flow is real.
5. Always respond with a single JSON object matching the requested schema.`;

// === Response parsing ===

const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const CONFIDENCES = new Set(['low', 'medium', 'high']);

function parseTaintPaths(raw: unknown): readonly TaintPath[] {
  const obj = raw as { paths?: unknown };
  const candidates = Array.isArray(obj?.paths) ? obj.paths : [];
  const paths: TaintPath[] = [];

  for (const c of candidates) {
    const p = c as {
      source?: { line?: unknown; kind?: unknown; expression?: unknown };
      sink?: { line?: unknown; kind?: unknown; expression?: unknown };
      steps?: unknown;
      severity?: unknown;
      confidence?: unknown;
      reasoning?: unknown;
    };
    if (!p || typeof p.source !== 'object' || typeof p.sink !== 'object') continue;
    if (!Array.isArray(p.steps)) continue;
    if (typeof p.confidence !== 'string' || !CONFIDENCES.has(p.confidence)) continue;

    const sev: Severity =
      typeof p.severity === 'string' && (SEVERITIES as readonly string[]).includes(p.severity)
        ? (p.severity as Severity)
        : 'medium';

    paths.push({
      source: {
        line: typeof p.source.line === 'number' ? p.source.line : 0,
        kind: String(p.source.kind ?? 'unknown'),
        expression: String(p.source.expression ?? ''),
      },
      sink: {
        line: typeof p.sink.line === 'number' ? p.sink.line : 0,
        kind: String(p.sink.kind ?? 'unknown'),
        expression: String(p.sink.expression ?? ''),
      },
      steps: p.steps.map(String),
      severity: sev,
      confidence: p.confidence as TaintPath['confidence'],
      reasoning: String(p.reasoning ?? ''),
    });
  }
  return paths;
}
