/**
 * MITRE ATT&CK mapping tables for the intel lanes.
 *
 * Ported from Shannon (dijjal-kimi-review) `types/campaign.ts`
 * (AGPL-3.0, Copyright (C) 2025 Keygraph, Inc.). A small frozen registry:
 * technique/tactic display names plus the default vuln-class → ATT&CK
 * mapping used by the Navigator export and report summaries.
 */

export interface AttackMapping {
  readonly tactic: string;
  readonly technique: string;
  readonly procedure?: string;
}

export const ATTACK_TECHNIQUE_NAMES: Readonly<Record<string, string>> = Object.freeze({
  T1190: 'Exploit Public-Facing Application',
  T1078: 'Valid Accounts',
  T1110: 'Brute Force',
  T1185: 'Browser Session Hijacking',
  T1059: 'Command and Scripting Interpreter',
  T1068: 'Exploitation for Privilege Escalation',
  T1071: 'Application Layer Protocol',
  T1499: 'Endpoint Denial of Service',
  T1003: 'OS Credential Dumping',
  T1090: 'Proxy',
  T1595: 'Active Scanning',
  T1046: 'Network Service Discovery',
  T1590: 'Gather Victim Network Information',
  T1593: 'Search Open Websites/Domains',
  T1552: 'Unsecured Credentials',
});

export const ATTACK_TACTIC_NAMES: Readonly<Record<string, string>> = Object.freeze({
  TA0001: 'Initial Access',
  TA0002: 'Execution',
  TA0003: 'Persistence',
  TA0004: 'Privilege Escalation',
  TA0006: 'Credential Access',
  TA0007: 'Discovery',
  TA0008: 'Lateral Movement',
  TA0009: 'Collection',
  TA0011: 'Command and Control',
  TA0043: 'Reconnaissance',
});

/**
 * Default mapping from vulnerability classes to ATT&CK. Each class can be
 * over-ridden per-finding via a `mitre_attack=T####` tag in the finding's
 * evidence string.
 */
export const VULN_CLASS_TO_ATTACK: Readonly<Record<string, AttackMapping>> = Object.freeze({
  injection: {
    tactic: 'TA0001',
    technique: 'T1190',
    procedure: 'Exploit injection sink in public-facing application',
  },
  xss: {
    tactic: 'TA0001',
    technique: 'T1185',
    procedure: 'Hijack authenticated session via reflected/stored XSS',
  },
  auth: {
    tactic: 'TA0006',
    technique: 'T1078',
    procedure: 'Abuse authentication gap to obtain or reuse valid credentials',
  },
  authz: {
    tactic: 'TA0004',
    technique: 'T1068',
    procedure: 'Exploit missing authorization check to act with elevated privilege',
  },
  ssrf: {
    tactic: 'TA0001',
    technique: 'T1190',
    procedure: 'Force vulnerable server to reach into internal network',
  },
});

/**
 * Map a finding title to a vuln-class hint via simple keyword matching.
 * Returns undefined when nothing matches so callers can fall back.
 */
export function vulnClassFromTitle(title: string): string | undefined {
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

/**
 * Resolve the canonical ATT&CK mapping for a vuln class, falling back to a
 * recon-flavoured default when the class isn't recognised. The fallback is
 * deliberately conservative so the report still renders.
 */
export function attackForVulnClass(vulnClass: string): AttackMapping {
  return (
    VULN_CLASS_TO_ATTACK[vulnClass] ?? {
      tactic: 'TA0043',
      technique: 'T1595',
      procedure: `Reconnaissance against ${vulnClass} surface`,
    }
  );
}

/** Format an ATT&CK mapping for inclusion as a Markdown summary row. */
export function renderAttackSummary(mapping: AttackMapping): string {
  const tacticName = ATTACK_TACTIC_NAMES[mapping.tactic] ?? 'Unknown Tactic';
  const techniqueName = ATTACK_TECHNIQUE_NAMES[mapping.technique] ?? 'Unknown Technique';
  const procedure = mapping.procedure ? ` — ${mapping.procedure}` : '';
  return `${mapping.tactic} (${tacticName}) / ${mapping.technique} (${techniqueName})${procedure}`;
}
