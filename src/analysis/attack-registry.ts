/**
 * MITRE ATT&CK registry for analysis/reporting.
 *
 * Ported from Shannon's `types/campaign.ts` (AGPL-3.0 © Keygraph) — the
 * technique-name table and vuln-class→ATT&CK map the Navigator layer export
 * and campaign reporting key on. Kept dependency-free and immutable.
 */

export interface ATTACKMapping {
  readonly tactic: string;
  readonly technique: string;
  readonly procedure?: string;
}

export const ATTACK_TECHNIQUE_NAMES: Readonly<Record<string, string>> = Object.freeze({
  // Recon
  T1590: 'Gather Victim Network Information',
  T1592: 'Gather Victim Host Information',
  T1593: 'Search Open Websites/Domains',
  T1595: 'Active Scanning',
  // Resource Development
  T1583: 'Acquire Infrastructure',
  T1587: 'Develop Capabilities',
  // Initial Access
  T1185: 'Browser Session Cookie Theft',
  T1189: 'Drive-by Compromise',
  T1190: 'Exploit Public-Facing Application',
  // Execution
  T1059: 'Command and Scripting Interpreter',
  T1203: 'Exploitation for Client Execution',
  // Persistence
  T1078: 'Valid Accounts',
  T1098: 'Account Manipulation',
  T1505: 'Server Software Component',
  // Privilege Escalation
  T1068: 'Exploitation for Privilege Escalation',
  // Defense Evasion
  T1027: 'Obfuscated Files or Information',
  T1553: 'Subvert Trust Controls',
  // Credential Access
  T1110: 'Brute Force',
  T1552: 'Unsecured Credentials',
  // Discovery
  T1018: 'Remote System Discovery',
  T1046: 'Network Service Discovery',
  T1083: 'File and Directory Discovery',
  // Lateral Movement
  T1021: 'Remote Services',
  // Collection
  T1005: 'Data from Local System',
  T1114: 'Email Collection',
  // Exfiltration
  T1041: 'Exfiltration Over C2 Channel',
  T1567: 'Exfiltration Over Web Service',
  // Impact
  T1485: 'Data Destruction',
  T1486: 'Data Encrypted for Impact',
  T1490: 'Inhibit System Recovery',
  T1498: 'Network Denial of Service',
  T1499: 'Endpoint Denial of Service',
});

/**
 * Canonical vuln-class → ATT&CK mapping used across reporting so the same
 * class of finding lands on the same technique in every export format.
 */
export const VULN_CLASS_TO_ATTACK: Readonly<Record<string, ATTACKMapping>> = Object.freeze({
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
 * Resolve the canonical ATT&CK mapping for a vuln class, falling back
 * to a recon-flavoured default when the class isn't recognised. The
 * fallback is deliberately conservative so the report still renders.
 */
export function attackForVulnClass(vulnClass: string): ATTACKMapping {
  return (
    VULN_CLASS_TO_ATTACK[vulnClass] ?? {
      tactic: 'TA0043',
      technique: 'T1595',
      procedure: `Active scanning for ${vulnClass}`,
    }
  );
}
