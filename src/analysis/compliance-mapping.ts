/**
 * Compliance mapping (F106).
 *
 * Maps Shannon finding categories to PCI-DSS v4, OWASP ASVS v4, and
 * GDPR articles. Same shape as the ATT&CK + OWASP API mappers — pure
 * lookup, no LLM, runs offline. Used by report assembly to render
 * compliance-cross-reference tables for regulated customers.
 */

export type ComplianceFramework = 'pci-dss-v4' | 'asvs-v4' | 'gdpr' | 'soc2' | 'iso-27001';

export type FindingCategory =
  | 'sqli'
  | 'xss'
  | 'idor'
  | 'broken-authn'
  | 'broken-authz'
  | 'ssrf'
  | 'xxe'
  | 'sensitive-data-exposure'
  | 'misconfiguration'
  | 'crypto-weakness'
  | 'session-fixation'
  | 'csrf'
  | 'open-redirect'
  | 'rate-limit-absent'
  | 'logging-gap';

export interface ComplianceClause {
  readonly framework: ComplianceFramework;
  readonly clause: string;
  readonly title: string;
  readonly summary: string;
}

const TABLE: Readonly<Record<FindingCategory, readonly ComplianceClause[]>> = {
  sqli: [
    {
      framework: 'pci-dss-v4',
      clause: '6.2.4',
      title: 'Bespoke software protection from injection',
      summary: 'Software is developed using techniques that prevent or mitigate common attacks including injection.',
    },
    {
      framework: 'asvs-v4',
      clause: 'V5.3.4',
      title: 'Parameterised queries',
      summary: 'Output encoding / parameterised queries protect against SQL injection.',
    },
    {
      framework: 'gdpr',
      clause: 'Art. 32',
      title: 'Security of processing',
      summary: 'Personal-data store reachable via SQLi violates appropriate security measures.',
    },
    {
      framework: 'soc2',
      clause: 'CC6.1 / CC8.1',
      title: 'Logical access & secure change',
      summary: 'Injection enabling unauthorized data access undermines the CC6.1 logical-access control.',
    },
    {
      framework: 'iso-27001',
      clause: 'A.8.28',
      title: 'Secure coding',
      summary: 'ISO 27001:2022 A.8.28 requires secure coding practices that prevent injection.',
    },
  ],
  xss: [
    {
      framework: 'pci-dss-v4',
      clause: '6.2.4',
      title: 'Bespoke software protection from injection',
      summary: 'XSS is enumerated in the PCI-DSS injection class.',
    },
    {
      framework: 'asvs-v4',
      clause: 'V5.3.3',
      title: 'Context-aware output encoding',
      summary: 'Context-aware encoding is the primary mitigation for XSS.',
    },
    {
      framework: 'gdpr',
      clause: 'Art. 32',
      title: 'Security of processing',
      summary: 'XSS that exfiltrates session tokens compromises personal-data confidentiality.',
    },
    {
      framework: 'soc2',
      clause: 'CC6.1',
      title: 'Logical access controls',
      summary: 'Session-stealing XSS defeats logical-access controls protecting user accounts.',
    },
    {
      framework: 'iso-27001',
      clause: 'A.8.28',
      title: 'Secure coding',
      summary: 'Context-aware output encoding is required under the A.8.28 secure-coding control.',
    },
  ],
  idor: [
    {
      framework: 'pci-dss-v4',
      clause: '7.2.2',
      title: 'Access control role-based on need-to-know',
      summary: 'Direct object reference exposure violates need-to-know access.',
    },
    {
      framework: 'asvs-v4',
      clause: 'V4.2.1',
      title: 'Authorization decisions cannot be bypassed',
      summary: 'IDOR is a direct ASVS V4.2.1 finding.',
    },
    {
      framework: 'gdpr',
      clause: 'Art. 5(1)(f)',
      title: 'Integrity and confidentiality',
      summary: 'IDOR-exposed personal data violates the confidentiality principle.',
    },
  ],
  'broken-authn': [
    {
      framework: 'pci-dss-v4',
      clause: '8.3',
      title: 'Strong authentication for users and admins',
      summary: 'Broken authentication directly contradicts §8 authentication requirements.',
    },
    {
      framework: 'asvs-v4',
      clause: 'V2.1',
      title: 'Password security',
      summary: 'ASVS V2 lays out the authentication requirements.',
    },
    {
      framework: 'gdpr',
      clause: 'Art. 32',
      title: 'Security of processing',
      summary: 'Unauthenticated access to personal data is a §32 violation.',
    },
    {
      framework: 'soc2',
      clause: 'CC6.1',
      title: 'Logical access controls',
      summary: 'Broken authentication is a direct CC6.1 logical-access-control failure.',
    },
    {
      framework: 'iso-27001',
      clause: 'A.5.17 / A.8.5',
      title: 'Authentication information & secure authentication',
      summary: 'ISO 27001 A.8.5 requires secure authentication technologies and processes.',
    },
  ],
  'broken-authz': [
    {
      framework: 'pci-dss-v4',
      clause: '7.2',
      title: 'Access control system',
      summary: 'Authorisation bypass is a §7 access-control failure.',
    },
    {
      framework: 'asvs-v4',
      clause: 'V4.1',
      title: 'General access control design',
      summary: 'ASVS V4.1 prescribes the deny-by-default access-control posture.',
    },
    {
      framework: 'gdpr',
      clause: 'Art. 32',
      title: 'Security of processing',
      summary: 'Unauthorised personal-data access is a §32 violation.',
    },
    {
      framework: 'soc2',
      clause: 'CC6.3',
      title: 'Role-based access enforcement',
      summary: 'Authorization bypass violates the CC6.3 least-privilege access requirement.',
    },
    {
      framework: 'iso-27001',
      clause: 'A.8.3',
      title: 'Information access restriction',
      summary: 'ISO 27001 A.8.3 requires access to information be restricted per policy.',
    },
  ],
  ssrf: [
    {
      framework: 'pci-dss-v4',
      clause: '1.4',
      title: 'Network controls between trust zones',
      summary: 'SSRF crosses trust zones via the server — §1.4 control failure.',
    },
    {
      framework: 'asvs-v4',
      clause: 'V12.6.1',
      title: 'Server-side request forgery defence',
      summary: 'ASVS V12.6.1 explicitly addresses SSRF.',
    },
    {
      framework: 'gdpr',
      clause: 'Art. 32',
      title: 'Security of processing',
      summary: 'SSRF that reads internal personal-data services is a §32 violation.',
    },
    {
      framework: 'soc2',
      clause: 'CC6.6',
      title: 'Boundary protection',
      summary: 'SSRF crossing internal trust boundaries violates the CC6.6 boundary-protection control.',
    },
    {
      framework: 'iso-27001',
      clause: 'A.8.22',
      title: 'Segregation of networks',
      summary: 'SSRF reaching internal services undermines the A.8.22 network-segregation control.',
    },
  ],
  xxe: [
    {
      framework: 'pci-dss-v4',
      clause: '6.2.4',
      title: 'Bespoke software protection from injection',
      summary: 'XXE falls under the §6.2.4 injection class.',
    },
    {
      framework: 'asvs-v4',
      clause: 'V5.5.2',
      title: 'XML parsing safety',
      summary: 'ASVS V5.5.2 — external entities disabled.',
    },
    {
      framework: 'gdpr',
      clause: 'Art. 32',
      title: 'Security of processing',
      summary: 'XXE-driven file read of personal data is a §32 violation.',
    },
  ],
  'sensitive-data-exposure': [
    {
      framework: 'pci-dss-v4',
      clause: '3.5',
      title: 'PAN protection',
      summary: 'Sensitive-data exposure that touches PAN data is a §3.5 failure.',
    },
    {
      framework: 'asvs-v4',
      clause: 'V9.1',
      title: 'Data protection in transit',
      summary: 'ASVS V9.1 / V9.2 cover at-rest + in-transit data protection.',
    },
    {
      framework: 'gdpr',
      clause: 'Art. 5(1)(f)',
      title: 'Integrity and confidentiality',
      summary: 'Direct violation of the confidentiality principle.',
    },
  ],
  misconfiguration: [
    {
      framework: 'pci-dss-v4',
      clause: '2.2',
      title: 'System components configured securely',
      summary: 'Misconfiguration is a §2.2 hardening failure.',
    },
    {
      framework: 'asvs-v4',
      clause: 'V14.1',
      title: 'Build and deploy',
      summary: 'ASVS V14 covers configuration hardening.',
    },
    {
      framework: 'gdpr',
      clause: 'Art. 32',
      title: 'Security of processing',
      summary: 'Misconfiguration that exposes personal data is a §32 violation.',
    },
  ],
  'crypto-weakness': [
    {
      framework: 'pci-dss-v4',
      clause: '4.2',
      title: 'Strong cryptography in transit',
      summary: 'Weak TLS / cipher choice is a §4.2 failure.',
    },
    { framework: 'asvs-v4', clause: 'V9', title: 'Communications', summary: 'ASVS V9 — strong cryptography.' },
    {
      framework: 'gdpr',
      clause: 'Art. 32',
      title: 'Security of processing',
      summary: 'Weak crypto on personal-data transport is a §32 violation.',
    },
  ],
  'session-fixation': [
    {
      framework: 'pci-dss-v4',
      clause: '8.3.4',
      title: 'Account lockout / session rotation',
      summary: '§8.3.4 mandates session rotation on authentication.',
    },
    {
      framework: 'asvs-v4',
      clause: 'V3.2.1',
      title: 'Session token generation',
      summary: 'ASVS V3.2 requires session-token rotation on login.',
    },
    {
      framework: 'gdpr',
      clause: 'Art. 32',
      title: 'Security of processing',
      summary: 'Session-fixation enabling personal-data access is a §32 violation.',
    },
  ],
  csrf: [
    {
      framework: 'pci-dss-v4',
      clause: '6.2.4',
      title: 'Bespoke software protection',
      summary: 'CSRF is included in the §6.2.4 protected attack class.',
    },
    {
      framework: 'asvs-v4',
      clause: 'V4.2.2',
      title: 'CSRF token verification',
      summary: 'ASVS V4.2.2 requires anti-CSRF tokens for state-changing requests.',
    },
    {
      framework: 'gdpr',
      clause: 'Art. 32',
      title: 'Security of processing',
      summary: 'CSRF that mutates personal-data records is a §32 violation.',
    },
  ],
  'open-redirect': [
    {
      framework: 'pci-dss-v4',
      clause: '6.2.4',
      title: 'Bespoke software protection',
      summary: 'Open redirect is in the §6.2.4 protected attack class.',
    },
    {
      framework: 'asvs-v4',
      clause: 'V5.1.5',
      title: 'Validate URL redirect destinations',
      summary: 'ASVS V5.1.5 — validate redirect targets.',
    },
    {
      framework: 'gdpr',
      clause: 'Art. 32',
      title: 'Security of processing',
      summary: 'Open redirect used in phishing is a §32 violation.',
    },
  ],
  'rate-limit-absent': [
    {
      framework: 'pci-dss-v4',
      clause: '8.3.4',
      title: 'Account lockout',
      summary: 'No rate limit on auth endpoints violates §8.3.4 lockout requirement.',
    },
    {
      framework: 'asvs-v4',
      clause: 'V11.1.1',
      title: 'Business-logic abuse defence',
      summary: 'ASVS V11.1.1 — rate-limit business-critical functions.',
    },
    {
      framework: 'gdpr',
      clause: 'Art. 32',
      title: 'Security of processing',
      summary: 'No rate-limit enables credential-stuffing → §32 violation.',
    },
  ],
  'logging-gap': [
    {
      framework: 'pci-dss-v4',
      clause: '10.2',
      title: 'Audit logs',
      summary: '§10.2 mandates user-action and access logging.',
    },
    {
      framework: 'asvs-v4',
      clause: 'V7.1',
      title: 'Log content',
      summary: 'ASVS V7.1 — log security-relevant events.',
    },
    {
      framework: 'gdpr',
      clause: 'Art. 33',
      title: 'Notification of personal-data breach',
      summary: 'Without logs, §33 72-hour breach notification is impossible.',
    },
  ],
};

/** Look up compliance clauses for a finding category. */
export function clausesFor(category: FindingCategory): readonly ComplianceClause[] {
  return TABLE[category] ?? [];
}

/** Filter clauses to a single framework. */
export function clausesByFramework(
  category: FindingCategory,
  framework: ComplianceFramework,
): readonly ComplianceClause[] {
  return clausesFor(category).filter((c) => c.framework === framework);
}

/** List every category covered by the mapping. */
export function knownCategories(): readonly FindingCategory[] {
  return Object.keys(TABLE) as FindingCategory[];
}
