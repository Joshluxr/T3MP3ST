/**
 * Engagement manifest — YAML-subset parser + schema + scope derivation
 * (ported from Shannon's engagement.yaml model, adapted to T3MP3ST).
 *
 * The manifest is the single source of truth an operator signs before any
 * active intel lane runs: authorized targets, hard "never touch" exclusions,
 * per-phase approval gates, and the operator identity stamped on findings and
 * evidence. Parsing needs no YAML dependency — the manifest subset (nested
 * maps, lists of scalars/maps, quoted strings, comments) is handled by a
 * small strict parser so the server runtime keeps zero new dependencies.
 */

import { hostFromTargetValue, type ArsenalScope } from '../arsenal/index.js';

// =============================================================================
// SCHEMA
// =============================================================================

export type ApprovalMode = 'manual' | 'auto';

export interface EngagementScope {
  authorizedTargets: string[];
  excludedTargets: string[];
  allowPrivateRanges: boolean;
  allowLoopback: boolean;
}

export interface EngagementApprovals {
  defaultMode: ApprovalMode;
  destructiveMode: ApprovalMode;
  phaseModes: Record<string, ApprovalMode>;
}

export interface EngagementRules {
  maxRuntimeSeconds: number;
  maxConcurrentRequests: number;
  stopOnCritical: boolean;
}

export interface Engagement {
  name: string;
  operator: string;
  client: string;
  authorization: string;
  scope: EngagementScope;
  approvals: EngagementApprovals;
  rules: EngagementRules;
}

// =============================================================================
// YAML-SUBSET PARSER (strict — unknown structure is an error, not a guess)
// =============================================================================

export class YamlParseError extends Error {
  constructor(message: string, public readonly atLine: number) {
    super(`engagement YAML parse error (line ${atLine}): ${message}`);
  }
}

interface Line {
  readonly indent: number;
  readonly text: string;
  readonly number: number;
}

function stripComment(raw: string): string {
  // Respect quoted '#' — a comment starts at a '#' preceded by whitespace or line start.
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === '#' && !inSingle && !inDouble && (i === 0 || /\s/.test(raw[i - 1] ?? ''))) {
      return raw.slice(0, i);
    }
  }
  return raw;
}

function splitLines(source: string): Line[] {
  const out: Line[] = [];
  const rawLines = source.split(/\r?\n/);
  for (let i = 0; i < rawLines.length; i += 1) {
    const noComment = stripComment(rawLines[i] ?? '');
    if (!noComment.trim()) continue;
    const indent = noComment.match(/^ */)?.[0].length ?? 0;
    out.push({ indent, text: noComment.trim(), number: i + 1 });
  }
  return out;
}

function unquote(value: string): string {
  const s = value.trim();
  if (s.length >= 2 && ((s[0] === '"' && s.at(-1) === '"') || (s[0] === "'" && s.at(-1) === "'"))) {
    const inner = s.slice(1, -1);
    return s[0] === '"' ? inner.replace(/\\"/g, '"').replace(/\\n/g, '\n').replace(/\\\\/g, '\\') : inner.replace(/''/g, "'");
  }
  return s;
}

function parseScalar(raw: string, line: number): string | number | boolean {
  const trimmed = raw.trim();
  const q = trimmed[0];
  if ((q === '"' || q === "'") && (trimmed.length < 2 || trimmed.at(-1) !== q)) {
    throw new YamlParseError('unterminated quoted string', line);
  }
  const s = unquote(raw);
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (/^-?\d+$/.test(s)) return parseInt(s, 10);
  if (/^-?\d+\.\d+$/.test(s)) return parseFloat(s);
  if (/^["']/.test(raw.trim())) return s; // quoted → always string, even if numeric-looking
  return s;
}

type YamlNode = string | number | boolean | YamlNode[] | { [key: string]: YamlNode };

/** Parse the value block that starts at lines[start] with the given indent. */
function parseBlock(lines: Line[], start: number, indent: number): { value: YamlNode; next: number } {
  const first = lines[start];
  if (!first || first.indent < indent) return { value: null as unknown as YamlNode, next: start };

  if (first.text.startsWith('- ') || first.text === '-') {
    const items: YamlNode[] = [];
    let i = start;
    while (i < lines.length) {
      const line = lines[i];
      if (!line || line.indent !== first.indent || !(line.text.startsWith('- ') || line.text === '-')) break;
      const rest = line.text === '-' ? '' : line.text.slice(2).trim();
      if (!rest) {
        // "- " alone → nested block on following deeper lines
        const nested = parseBlock(lines, i + 1, first.indent + 2);
        if (nested.next === i + 1) throw new YamlParseError('empty list item', line.number);
        items.push(nested.value);
        i = nested.next;
        continue;
      }
      // Inline "- key: value" → map item whose deeper siblings belong to it.
      const kvMatch = rest.match(/^([A-Za-z0-9_.-]+):(?:\s+(.*))?$/);
      if (kvMatch) {
        const itemIndent = first.indent + 2;
        const inlineValue = kvMatch[2] ?? '';
        const item: Record<string, YamlNode> = {};
        if (inlineValue) {
          item[kvMatch[1] ?? ''] = parseScalar(inlineValue, line.number);
          items.push(item);
          i += 1;
        } else {
          const nested = parseBlock(lines, i + 1, itemIndent);
          if (nested.next === i + 1) {
            item[kvMatch[1] ?? ''] = null as unknown as YamlNode;
            items.push(item);
            i += 1;
          } else {
            item[kvMatch[1] ?? ''] = nested.value;
            items.push(item);
            i = nested.next;
          }
        }
        // Sibling keys of the same map item at itemIndent.
        while (i < lines.length && lines[i] && lines[i].indent === itemIndent && !lines[i].text.startsWith('- ')) {
          const sibling = lines[i].text.match(/^([A-Za-z0-9_.-]+):(?:\s+(.*))?$/);
          if (!sibling) throw new YamlParseError(`expected "key: value" in list item`, lines[i].number);
          const siblingValue = sibling[2] ?? '';
          if (siblingValue) {
            item[sibling[1] ?? ''] = parseScalar(siblingValue, lines[i].number);
            i += 1;
          } else {
            const nested2 = parseBlock(lines, i + 1, itemIndent + 2);
            item[sibling[1] ?? ''] = nested2.next === i + 1 ? (null as unknown as YamlNode) : nested2.value;
            i = nested2.next === i + 1 ? i + 1 : nested2.next;
          }
        }
        continue;
      }
      items.push(parseScalar(rest, line.number));
      i += 1;
    }
    return { value: items, next: i };
  }

  const map: Record<string, YamlNode> = {};
  let i = start;
  while (i < lines.length) {
    const line = lines[i];
    if (!line || line.indent !== indent) break;
    if (line.text.startsWith('- ')) break;
    const kv = line.text.match(/^([A-Za-z0-9_.-]+):(?:\s+(.*))?$/);
    if (!kv) throw new YamlParseError(`expected "key: value"`, line.number);
    const inline = kv[2] ?? '';
    if (inline) {
      map[kv[1] ?? ''] = parseScalar(inline, line.number);
      i += 1;
    } else {
      const nested = parseBlock(lines, i + 1, indent + 2);
      if (nested.next === i + 1) {
        map[kv[1] ?? ''] = null as unknown as YamlNode;
        i += 1;
      } else {
        map[kv[1] ?? ''] = nested.value;
        i = nested.next;
      }
    }
  }
  if (i === start) throw new YamlParseError(`could not parse value block`, lines[start]?.number ?? 0);
  return { value: map, next: i };
}

export function parseYamlSubset(source: string): Record<string, YamlNode> {
  const lines = splitLines(source);
  if (!lines.length) return {};
  const parsed = parseBlock(lines, 0, lines[0].indent);
  if (parsed.next !== lines.length) {
    const stray = lines[parsed.next];
    throw new YamlParseError(`unexpected content (bad indent?)`, stray?.number ?? 0);
  }
  if (!parsed.value || typeof parsed.value !== 'object' || Array.isArray(parsed.value)) {
    throw new YamlParseError('top level must be a map', lines[0]?.number ?? 0);
  }
  return parsed.value as Record<string, YamlNode>;
}

// =============================================================================
// MANIFEST VALIDATION → Engagement
// =============================================================================

export class EngagementValidationError extends Error {
  constructor(message: string) {
    super(`engagement validation error: ${message}`);
  }
}

function asRecord(node: YamlNode | undefined, path: string): Record<string, YamlNode> {
  if (node === undefined || node === null) return {};
  if (typeof node !== 'object' || Array.isArray(node)) {
    throw new EngagementValidationError(`${path} must be a map`);
  }
  return node as Record<string, YamlNode>;
}

function asStringList(node: YamlNode | undefined, path: string): string[] {
  if (node === undefined || node === null) return [];
  if (!Array.isArray(node)) throw new EngagementValidationError(`${path} must be a list`);
  return node.map(item => {
    if (typeof item !== 'string') throw new EngagementValidationError(`${path} entries must be strings`);
    return item;
  });
}

function asString(node: YamlNode | undefined, path: string, fallback?: string): string {
  if (node === undefined || node === null) {
    if (fallback !== undefined) return fallback;
    throw new EngagementValidationError(`${path} is required`);
  }
  if (typeof node !== 'string') throw new EngagementValidationError(`${path} must be a string`);
  return node;
}

function asBool(node: YamlNode | undefined, path: string, fallback: boolean): boolean {
  if (node === undefined || node === null) return fallback;
  if (typeof node !== 'boolean') throw new EngagementValidationError(`${path} must be true/false`);
  return node;
}

function asNumber(node: YamlNode | undefined, path: string, fallback: number): number {
  if (node === undefined || node === null) return fallback;
  if (typeof node !== 'number' || Number.isNaN(node)) throw new EngagementValidationError(`${path} must be a number`);
  return node;
}

function asApprovalMode(node: YamlNode | undefined, path: string, fallback: ApprovalMode): ApprovalMode {
  const value = asString(node, path, fallback);
  if (value !== 'manual' && value !== 'auto') {
    throw new EngagementValidationError(`${path} must be "manual" or "auto"`);
  }
  return value;
}

export interface ParseEngagementResult {
  engagement: Engagement;
  /** Non-fatal notes about defaults that were applied (surfaced to the operator). */
  warnings: string[];
}

/**
 * Parse + validate engagement YAML into an Engagement. Throws YamlParseError /
 * EngagementValidationError on malformed input — callers map those to HTTP 400.
 */
export function parseEngagementYaml(source: string): ParseEngagementResult {
  const warnings: string[] = [];
  const root = parseYamlSubset(source);

  const name = asString(root.name, 'name', 'Unnamed engagement');
  const operator = asString(root.operator, 'operator', 'unknown-operator');
  const client = asString(root.client, 'client', 'unspecified');
  const authorization = asString(root.authorization, 'authorization', 'Verbal authorization only — confirm written scope before active testing.');

  const scopeRaw = asRecord(root.scope, 'scope');
  const authorizedTargets = asStringList(scopeRaw.authorized_targets, 'scope.authorized_targets')
    .map(t => t.trim()).filter(Boolean);
  if (authorizedTargets.length === 0) {
    throw new EngagementValidationError('scope.authorized_targets must list at least one target');
  }
  const excludedTargets = asStringList(scopeRaw.excluded_targets, 'scope.excluded_targets');
  const allowPrivateRanges = asBool(scopeRaw.allow_private_ranges, 'scope.allow_private_ranges', false);
  const allowLoopback = asBool(scopeRaw.allow_loopback, 'scope.allow_loopback', true);

  const approvalsRaw = asRecord(root.approvals, 'approvals');
  const defaultMode = asApprovalMode(approvalsRaw.default, 'approvals.default', 'manual');
  const destructiveMode = asApprovalMode(approvalsRaw.destructive, 'approvals.destructive', 'manual');
  const phaseModesRaw = asRecord(approvalsRaw.phases, 'approvals.phases');
  const phaseModes: Record<string, ApprovalMode> = {};
  for (const [phase, mode] of Object.entries(phaseModesRaw)) {
    phaseModes[phase] = asApprovalMode(mode, `approvals.phases.${phase}`, 'manual');
  }

  const rulesRaw = asRecord(root.rules, 'rules');
  const maxRuntimeSeconds = asNumber(rulesRaw.max_runtime_seconds, 'rules.max_runtime_seconds', 3600);
  const maxConcurrentRequests = asNumber(rulesRaw.max_concurrent_requests, 'rules.max_concurrent_requests', 4);
  const stopOnCritical = asBool(rulesRaw.stop_on_critical, 'rules.stop_on_critical', true);

  if (authorization === 'Verbal authorization only — confirm written scope before active testing.') {
    warnings.push('authorization not specified — defaulted to verbal-only; confirm written scope before active testing');
  }
  if (!/written|email|ticket|contract|signed/i.test(authorization)) {
    warnings.push('authorization reference does not mention a written record (contract/ticket/email)');
  }

  return {
    engagement: {
      name,
      operator,
      client,
      authorization,
      scope: { authorizedTargets, excludedTargets, allowPrivateRanges, allowLoopback },
      approvals: { defaultMode, destructiveMode, phaseModes },
      rules: { maxRuntimeSeconds, maxConcurrentRequests, stopOnCritical },
    },
    warnings,
  };
}

// =============================================================================
// SCOPE DERIVATION
// =============================================================================

/**
 * Derive the egress scope the intel lanes enforce. Same host math as the
 * arsenal gate: exact hosts / registrable domains (subdomains allowed),
 * optional loopback, optional private ranges. Exclusions always win over
 * authorizations.
 */
export function scopeFromEngagement(engagement: Engagement): ArsenalScope {
  const excludedHosts = new Set(
    engagement.scope.excludedTargets
      .map(t => hostFromTargetValue(t))
      .filter((h): h is string => !!h),
  );
  const allowedHosts = engagement.scope.authorizedTargets
    .map(t => hostFromTargetValue(t))
    .filter((h): h is string => !!h && !excludedHosts.has(h));
  return {
    allowedHosts,
    allowLoopback: engagement.scope.allowLoopback,
    allowPrivate: engagement.scope.allowPrivateRanges,
  };
}

/** Human-readable scope summary for UIs and audit events. */
export function describeScope(scope: ArsenalScope): string {
  const hosts = scope.allowedHosts.length ? scope.allowedHosts.join(', ') : '(no authorized hosts)';
  return [
    `authorized: ${hosts}`,
    `loopback: ${scope.allowLoopback ? 'allowed' : 'denied'}`,
    `private ranges: ${scope.allowPrivate ? 'allowed' : 'denied'}`,
  ].join(' | ');
}
