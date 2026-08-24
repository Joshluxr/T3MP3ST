/**
 * LLM client seam for the ported cognitive analyzers (taint / semantic / variant).
 *
 * Shannon's Tier E analyzers all consume a tiny `LlmClient` interface
 * (`complete(req) -> { text }`) plus `parseJsonResponse`. Rather than couple
 * them to T3MP3ST's `LLMBackbone`, they keep consuming `LlmClient` and a single
 * shim (`fromLLMBackbone`) adapts the engine's backbone to it. That keeps the
 * analyzers provider-agnostic and unit-testable via `FakeLlmClient`.
 *
 * The interfaces + parse helpers are ports of Shannon's `llm-client.ts`
 * (apps/worker/src/services/llm-client.ts); the `fromLLMBackbone` adapter is
 * T3MP3ST-specific.
 */

import type { LLMBackbone } from '../llm/index.js';
import type { LLMMessage } from '../types/index.js';

export interface LlmRequest {
  /** Required system prompt that frames the task. */
  readonly systemPrompt: string;
  /** Required user-side payload (often JSON-encoded inputs). */
  readonly userPrompt: string;
  /** Soft output cap. Backends may exceed this if needed. */
  readonly maxTokens?: number;
  /** Free-form label for audit logs. */
  readonly label?: string;
}

export interface LlmResponse {
  readonly text: string;
}

export interface LlmClient {
  complete(req: LlmRequest): Promise<LlmResponse>;
}

/**
 * Deterministic in-memory client used by tests and dry-run mode. Each entry is
 * keyed by `req.label`; an entry with label `default` is returned when no
 * label-specific response is registered.
 */
export class FakeLlmClient implements LlmClient {
  private readonly responses = new Map<string, string>();
  private readonly calls: LlmRequest[] = [];

  set(label: string, text: string): this {
    this.responses.set(label, text);
    return this;
  }

  setDefault(text: string): this {
    this.responses.set('default', text);
    return this;
  }

  /** Returns the requests received in arrival order, for assertion. */
  get history(): readonly LlmRequest[] {
    return this.calls;
  }

  async complete(req: LlmRequest): Promise<LlmResponse> {
    this.calls.push(req);
    const labelled = req.label ? this.responses.get(req.label) : undefined;
    const fallback = this.responses.get('default');
    const text = labelled ?? fallback;
    if (text === undefined) {
      throw new Error(
        `FakeLlmClient: no response registered for label "${req.label ?? '<none>'}" and no default set`,
      );
    }
    return { text };
  }
}

/**
 * Adapt T3MP3ST's `LLMBackbone` to the analyzers' `LlmClient`. The backbone's
 * `chat(messages, options)` returns `{ content }`; this maps a `LlmRequest`
 * onto a system+user message pair and unwraps the content.
 *
 * The analyzers only *read* — they never assert provenance — so this stays a
 * pure formatting shim with no side effects beyond the underlying chat call.
 */
export function fromLLMBackbone(backbone: LLMBackbone): LlmClient {
  return {
    async complete(req: LlmRequest): Promise<LlmResponse> {
      const messages: LLMMessage[] = [
        { role: 'system', content: req.systemPrompt },
        { role: 'user', content: req.userPrompt },
      ];
      const response = await backbone.chat(messages, {
        ...(req.maxTokens !== undefined ? { maxTokens: req.maxTokens } : {}),
        temperature: 0,
      });
      return { text: response.content };
    },
  };
}

/**
 * Strip a single fenced code block, returning its inner body. Non-fenced text
 * is returned trimmed.
 */
export function stripFence(text: string): string {
  const trimmed = text.trim();
  const fence = trimmed.match(/^```[a-zA-Z0-9_-]*\n([\s\S]*?)\n```$/);
  if (fence?.[1]) return fence[1].trim();
  return trimmed;
}

/**
 * Strip leading reasoning/thinking blocks emitted by chain-of-thought models
 * (`<think>…</think>`, `<thinking>…</thinking>`). Returns the remainder
 * trimmed; unchanged input when no thinking block is present.
 */
export function stripThinking(text: string): string {
  return text
    .replace(/<think(?:ing)?>[\s\S]*?<\/think(?:ing)?>/gi, '')
    .replace(/<think(?:ing)?>[\s\S]*$/i, '')
    .trim();
}

/**
 * Parse a JSON payload from an LLM response, tolerating leading prose, a single
 * fenced code block, and reasoning-model thinking blocks. Throws a descriptive
 * error if no parseable JSON object/array is found.
 */
export function parseJsonResponse<T>(text: string): T {
  const fenced = stripFence(stripThinking(text));
  try {
    return JSON.parse(fenced) as T;
  } catch {
    // Fall through to extract the first balanced JSON object or array.
  }
  const objStart = fenced.indexOf('{');
  const arrStart = fenced.indexOf('[');
  const start = [objStart, arrStart].filter((idx) => idx >= 0).sort((a, b) => a - b)[0];
  if (start === undefined) {
    throw new Error('LLM response did not contain JSON');
  }
  const opener = fenced[start];
  if (opener === undefined) {
    throw new Error('LLM response did not contain JSON');
  }
  const closer = opener === '{' ? '}' : ']';
  let depth = 0;
  for (let i = start; i < fenced.length; i++) {
    const ch = fenced[i];
    if (ch === opener) depth++;
    else if (ch === closer) {
      depth--;
      if (depth === 0) {
        const slice = fenced.slice(start, i + 1);
        return JSON.parse(slice) as T;
      }
    }
  }
  throw new Error('LLM response had unbalanced JSON brackets');
}
