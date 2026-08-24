/**
 * ATT&CK Navigator layer export.
 *
 * Ported from Shannon `services/attack-navigator-export.ts` (AGPL-3.0
 * © Keygraph). Turns the mission's findings into a JSON layer that loads
 * directly into the MITRE ATT&CK Navigator
 * (https://mitre-attack.github.io/attack-navigator/) for a visual heatmap
 * of which techniques the engagement touched.
 *
 * Output conforms to layer format v4.5
 * (https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5_Layer_Format.md).
 *
 * Pure function. No I/O.
 */

import type { AnalysisFinding } from './finding.js';
import { ATTACK_TECHNIQUE_NAMES, type ATTACKMapping, attackForVulnClass } from './attack-registry.js';

/** Subset of the layer-format spec we need to populate. */
export interface NavigatorTechnique {
  readonly techniqueID: string;
  readonly tactic?: string;
  readonly color?: string;
  readonly comment?: string;
  readonly enabled: boolean;
  readonly metadata: ReadonlyArray<{ readonly name: string; readonly value: string }>;
  readonly score?: number;
}

export interface NavigatorLayer {
  readonly name: string;
  readonly versions: {
    readonly attack: string;
    readonly navigator: string;
    readonly layer: string;
  };
  readonly domain: 'enterprise-attack';
  readonly description: string;
  readonly techniques: readonly NavigatorTechnique[];
  readonly gradient: {
    readonly colors: readonly string[];
    readonly minValue: number;
    readonly maxValue: number;
  };
  readonly legendItems: ReadonlyArray<{ readonly label: string; readonly color: string }>;
}

const SEVERITY_WEIGHT: Readonly<Record<string, number>> = Object.freeze({
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
});

interface Aggregated {
  readonly mapping: ATTACKMapping;
  count: number;
  weight: number;
  readonly tools: Set<string>;
  readonly samples: string[];
}

/**
 * Map a finding's title to a vuln-class hint via simple keyword matching.
 * Returns undefined when nothing matches so callers can fall back.
 */
function vulnClassFromTitle(title: string): string | undefined {
  const t = title.toLowerCase();
  if (/(sql\s*injection|sqli|sql\s+inject)/.test(t)) return 'injection';
  if (/(command\s+injection|os\s+command|cmd\s+inject)/.test(t)) return 'injection';
  if (/(template\s+injection|ssti)/.test(t)) return 'injection';
  if (/(xss|cross[\s-]?site\s+script)/.test(t)) return 'xss';
  if (/(ssrf|server[\s-]?side\s+request)/.test(t)) return 'ssrf';
  if (/(xxe|xml\s+external)/.test(t)) return 'injection';
  if (/(idor|insecure\s+direct\s+object|broken\s+access|authoriz)/.test(t)) return 'authz';
  if (/(authentication|weak\s+credential|default\s+password|brute|spray)/.test(t)) return 'auth';
  return undefined;
}

/** Hard-coded mapping for tool names that don't slot into the vuln-class registry. */
const TOOL_ATTACK_HINTS: Readonly<Record<string, ATTACKMapping>> = Object.freeze({
  hydra: { tactic: 'TA0006', technique: 'T1110', procedure: 'Online brute-force / spray' },
  sqlmap: { tactic: 'TA0001', technique: 'T1190', procedure: 'SQL injection against public-facing app' },
  nuclei: { tactic: 'TA0007', technique: 'T1595', procedure: 'Template-driven active scanning' },
  nikto: { tactic: 'TA0007', technique: 'T1595', procedure: 'Web server misconfig scanning' },
  wapiti: { tactic: 'TA0001', technique: 'T1190', procedure: 'Web vulnerability fuzzing' },
  dalfox: { tactic: 'TA0001', technique: 'T1185', procedure: 'XSS detection' },
  nmap: { tactic: 'TA0007', technique: 'T1046', procedure: 'Network service scanning' },
  masscan: { tactic: 'TA0007', technique: 'T1046', procedure: 'Network service scanning' },
  naabu: { tactic: 'TA0007', technique: 'T1046', procedure: 'Network service scanning' },
  subfinder: { tactic: 'TA0043', technique: 'T1590', procedure: 'Gather victim network information' },
  dnsx: { tactic: 'TA0043', technique: 'T1590', procedure: 'Gather DNS records' },
  gau: { tactic: 'TA0043', technique: 'T1593', procedure: 'Search open websites/historical archives' },
  katana: { tactic: 'TA0043', technique: 'T1595', procedure: 'Active web crawling' },
  httpx: { tactic: 'TA0007', technique: 'T1595', procedure: 'HTTP service fingerprinting' },
  trufflehog: { tactic: 'TA0006', technique: 'T1552', procedure: 'Unsecured credentials in code' },
  gitleaks: { tactic: 'TA0006', technique: 'T1552', procedure: 'Unsecured credentials in code' },
  semgrep: { tactic: 'TA0007', technique: 'T1595', procedure: 'Static analysis discovery' },
  trivy: { tactic: 'TA0007', technique: 'T1595', procedure: 'Dependency / IaC vulnerability scan' },
  slither: { tactic: 'TA0007', technique: 'T1595', procedure: 'Solidity static analysis' },
  mythril: { tactic: 'TA0007', technique: 'T1595', procedure: 'EVM symbolic execution' },
  echidna: { tactic: 'TA0007', technique: 'T1595', procedure: 'Smart-contract property fuzzing' },
});

/**
 * Map a finding to its ATT&CK technique using, in order:
 *   1. an explicit `mitre_attack=T####` tag in evidence,
 *   2. a title-keyword match against well-known vuln classes,
 *   3. a tool-name hint for tools that don't slot into a vuln class,
 *   4. `attackForVulnClass(tool)` as a final fallback.
 */
function mappingForFinding(f: AnalysisFinding): ATTACKMapping {
  if (f.evidence) {
    const match = f.evidence.match(/mitre_attack=(T\d{4}(?:\.\d{3})?)/);
    if (match?.[1]) {
      return { tactic: 'TA0001', technique: match[1] };
    }
  }
  const cls = vulnClassFromTitle(f.title);
  if (cls !== undefined) return attackForVulnClass(cls);
  const toolHint = TOOL_ATTACK_HINTS[f.tool];
  if (toolHint !== undefined) return toolHint;
  return attackForVulnClass(f.tool);
}

export interface NavigatorExportOptions {
  readonly name?: string;
  readonly description?: string;
  /** Override the gradient color stops. */
  readonly gradientColors?: readonly string[];
}

export function exportNavigatorLayer(
  findings: readonly AnalysisFinding[],
  options: NavigatorExportOptions = {},
): NavigatorLayer {
  const byTechnique = new Map<string, Aggregated>();

  for (const f of findings) {
    const mapping = mappingForFinding(f);
    const key = mapping.technique;
    const weight = SEVERITY_WEIGHT[f.severity] ?? 1;
    const existing = byTechnique.get(key);
    if (!existing) {
      byTechnique.set(key, {
        mapping,
        count: 1,
        weight,
        tools: new Set([f.tool]),
        samples: [f.title],
      });
      continue;
    }
    existing.count += 1;
    existing.weight = Math.max(existing.weight, weight);
    existing.tools.add(f.tool);
    if (existing.samples.length < 3) existing.samples.push(f.title);
  }

  const maxScore = [...byTechnique.values()].reduce((m, e) => Math.max(m, e.count), 1);

  const techniques: NavigatorTechnique[] = [...byTechnique.values()].map((entry) => {
    const name = ATTACK_TECHNIQUE_NAMES[entry.mapping.technique] ?? 'Unknown Technique';
    return {
      techniqueID: entry.mapping.technique,
      tactic: entry.mapping.tactic,
      enabled: true,
      score: entry.count,
      comment: `${name}: ${entry.count} finding(s) from ${[...entry.tools].sort().join(', ')}.\nTop: ${entry.samples.join(' | ')}`,
      metadata: [
        { name: 'count', value: String(entry.count) },
        { name: 'max-severity', value: weightLabel(entry.weight) },
        { name: 'tools', value: [...entry.tools].sort().join(', ') },
      ],
    };
  });

  return {
    name: options.name ?? 'T3MP3ST Coverage',
    versions: {
      attack: '14',
      navigator: '4.9.0',
      layer: '4.5',
    },
    domain: 'enterprise-attack',
    description:
      options.description ??
      'Auto-generated ATT&CK coverage layer for a T3MP3ST engagement. Score = number of findings.',
    techniques,
    gradient: {
      colors: options.gradientColors ?? ['#ffe0e0', '#ff6b6b', '#c92a2a'],
      minValue: 0,
      maxValue: Math.max(1, maxScore),
    },
    legendItems: [
      { label: '1 finding', color: '#ffe0e0' },
      { label: 'multiple findings', color: '#ff6b6b' },
      { label: 'heavy coverage', color: '#c92a2a' },
    ],
  };
}

function weightLabel(w: number): string {
  for (const [name, value] of Object.entries(SEVERITY_WEIGHT)) {
    if (value === w) return name;
  }
  return 'info';
}
