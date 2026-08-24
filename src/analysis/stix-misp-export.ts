/**
 * STIX 2.1 + MISP event export.
 *
 * Ported from Shannon `services/stix-misp-export.ts` (AGPL-3.0 © Keygraph).
 * Confirmed findings are converted into both:
 *   - STIX 2.1 bundle (https://oasis-open.github.io/cti-documentation/stix/intro)
 *   - MISP event JSON (https://www.misp-project.org/)
 *
 * The two share a single internal model so they always represent the
 * same finding set. We map a finding to:
 *   - one `vulnerability` SDO (the finding itself)
 *   - one `indicator` SDO per recognized IOC (url / domain / ipv4 / cve)
 *   - relationships linking indicators to the vulnerability
 *
 * Output is deterministic given a fixed `now` and `bundleId` so tests
 * can snapshot the JSON.
 */

import { randomBytes } from 'node:crypto';
import type { Severity } from '../types/index.js';

export interface FindingForExport {
  readonly tool: string;
  readonly target: string;
  readonly title: string;
  readonly severity: Severity;
  readonly evidence?: string;
  readonly confidence?: number;
}

export interface StixExportInput {
  readonly findings: readonly FindingForExport[];
  readonly engagementId: string;
  readonly now?: string;
  readonly bundleId?: string;
}

export interface StixBundle {
  readonly type: 'bundle';
  readonly id: string;
  readonly objects: readonly StixObject[];
}

export type StixObject = StixIdentity | StixVulnerability | StixIndicator | StixRelationship;

interface StixIdentity {
  readonly type: 'identity';
  readonly spec_version: '2.1';
  readonly id: string;
  readonly created: string;
  readonly modified: string;
  readonly name: string;
  readonly identity_class: 'organization' | 'individual';
}

interface StixVulnerability {
  readonly type: 'vulnerability';
  readonly spec_version: '2.1';
  readonly id: string;
  readonly created: string;
  readonly modified: string;
  readonly name: string;
  readonly description: string;
  readonly labels: readonly string[];
  readonly external_references?: readonly { source_name: string; external_id: string }[];
}

interface StixIndicator {
  readonly type: 'indicator';
  readonly spec_version: '2.1';
  readonly id: string;
  readonly created: string;
  readonly modified: string;
  readonly name: string;
  readonly pattern: string;
  readonly pattern_type: 'stix';
  readonly valid_from: string;
  readonly labels: readonly string[];
}

interface StixRelationship {
  readonly type: 'relationship';
  readonly spec_version: '2.1';
  readonly id: string;
  readonly created: string;
  readonly modified: string;
  readonly relationship_type: 'indicates' | 'related-to';
  readonly source_ref: string;
  readonly target_ref: string;
}

// === STIX builders ===

function uuid(): string {
  // RFC 4122 v4-ish: 16 random bytes, set variant bits.
  const b = randomBytes(16);
  b[6] = ((b[6] ?? 0) & 0x0f) | 0x40;
  b[8] = ((b[8] ?? 0) & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function detectCves(text: string): string[] {
  const re = /CVE-\d{4}-\d{4,7}/gi;
  const matches = text.match(re);
  return matches ? Array.from(new Set(matches.map((m) => m.toUpperCase()))) : [];
}

function detectIocs(text: string): { kind: 'url' | 'domain' | 'ipv4'; value: string }[] {
  const out: { kind: 'url' | 'domain' | 'ipv4'; value: string }[] = [];
  const urls = text.match(/\bhttps?:\/\/[^\s"'<>)]+/gi) ?? [];
  for (const u of urls) out.push({ kind: 'url', value: u });
  const ipv4 = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [];
  for (const ip of ipv4) out.push({ kind: 'ipv4', value: ip });
  const domains = text.match(/\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z]{2,})+\b/gi) ?? [];
  for (const d of domains) {
    // Skip URLs / IPs already captured.
    if (!out.some((o) => o.value.includes(d))) out.push({ kind: 'domain', value: d.toLowerCase() });
  }
  return out;
}

function stixPatternFor(kind: 'url' | 'domain' | 'ipv4', value: string): string {
  if (kind === 'url') return `[url:value = '${value.replace(/'/g, "\\'")}']`;
  if (kind === 'domain') return `[domain-name:value = '${value}']`;
  return `[ipv4-addr:value = '${value}']`;
}

/** Build a STIX 2.1 bundle from a set of findings. */
export function exportStixBundle(input: StixExportInput): StixBundle {
  const now = input.now ?? new Date().toISOString();
  const bundleId = input.bundleId ?? `bundle--${uuid()}`;

  const objects: StixObject[] = [];
  const identityId = `identity--${uuid()}`;
  objects.push({
    type: 'identity',
    spec_version: '2.1',
    id: identityId,
    created: now,
    modified: now,
    name: `T3MP3ST engagement ${input.engagementId}`,
    identity_class: 'organization',
  });

  for (const f of input.findings) {
    const vulnId = `vulnerability--${uuid()}`;
    const evidence = f.evidence ?? '';
    const cves = detectCves(`${f.title} ${evidence}`);
    objects.push({
      type: 'vulnerability',
      spec_version: '2.1',
      id: vulnId,
      created: now,
      modified: now,
      name: f.title,
      description: `tool=${f.tool} target=${f.target} severity=${f.severity}${evidence ? ` evidence=${evidence}` : ''}`,
      labels: [f.severity, f.tool],
      ...(cves.length > 0
        ? {
            external_references: cves.map((id) => ({ source_name: 'cve', external_id: id })),
          }
        : {}),
    });

    for (const ioc of detectIocs(`${f.target} ${evidence}`)) {
      const indId = `indicator--${uuid()}`;
      objects.push({
        type: 'indicator',
        spec_version: '2.1',
        id: indId,
        created: now,
        modified: now,
        name: `${ioc.kind}: ${ioc.value}`,
        pattern: stixPatternFor(ioc.kind, ioc.value),
        pattern_type: 'stix',
        valid_from: now,
        labels: ['malicious-activity'],
      });
      objects.push({
        type: 'relationship',
        spec_version: '2.1',
        id: `relationship--${uuid()}`,
        created: now,
        modified: now,
        relationship_type: 'indicates',
        source_ref: indId,
        target_ref: vulnId,
      });
    }
  }

  return { type: 'bundle', id: bundleId, objects };
}

// === MISP export ===

export interface MispAttribute {
  readonly type: string;
  readonly category: string;
  readonly value: string;
  readonly to_ids: boolean;
  readonly comment?: string;
}

export interface MispEvent {
  readonly Event: {
    readonly info: string;
    readonly date: string;
    readonly threat_level_id: '1' | '2' | '3' | '4';
    readonly analysis: '0' | '1' | '2';
    readonly distribution: '0' | '1' | '2' | '3';
    readonly Attribute: readonly MispAttribute[];
  };
}

function mispThreatLevel(severity: Severity): '1' | '2' | '3' | '4' {
  if (severity === 'critical' || severity === 'high') return '1';
  if (severity === 'medium') return '2';
  if (severity === 'low') return '3';
  return '4';
}

function mispAttributeFor(kind: 'url' | 'domain' | 'ipv4', value: string, comment: string): MispAttribute {
  if (kind === 'url') return { type: 'url', category: 'Network activity', value, to_ids: true, comment };
  if (kind === 'domain') return { type: 'domain', category: 'Network activity', value, to_ids: true, comment };
  return { type: 'ip-dst', category: 'Network activity', value, to_ids: true, comment };
}

/** Build a MISP event JSON from a set of findings. */
export function exportMispEvent(input: StixExportInput): MispEvent {
  const now = input.now ?? new Date().toISOString();
  const date = now.slice(0, 10);

  let worstSeverity: Severity = 'info';
  const sevRank: Record<Severity, number> = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  };
  for (const f of input.findings) {
    if (sevRank[f.severity] > sevRank[worstSeverity]) worstSeverity = f.severity;
  }

  const attrs: MispAttribute[] = [];
  for (const f of input.findings) {
    const evidence = f.evidence ?? '';
    const comment = `[${f.severity}] ${f.tool}: ${f.title}`;
    for (const ioc of detectIocs(`${f.target} ${evidence}`)) {
      attrs.push(mispAttributeFor(ioc.kind, ioc.value, comment));
    }
    for (const cve of detectCves(`${f.title} ${evidence}`)) {
      attrs.push({
        type: 'vulnerability',
        category: 'External analysis',
        value: cve,
        to_ids: false,
        comment,
      });
    }
  }

  return {
    Event: {
      info: `T3MP3ST engagement ${input.engagementId}`,
      date,
      threat_level_id: mispThreatLevel(worstSeverity),
      analysis: '2',
      distribution: '0',
      Attribute: attrs,
    },
  };
}
