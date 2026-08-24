/**
 * CWE → FindingCategory bridge (Tier 2).
 *
 * `compliance-mapping.ts` keys on a `FindingCategory` (sqli, xss, idor, …), but
 * T3MP3ST's engine `Finding` has no category field — only `cwe?: string[]`. This
 * bridge derives the category from a finding, so compliance clauses can be
 * attached without adding a field to the core `Finding` type.
 *
 * Resolution order:
 *   1. CWE id map (authoritative — a CWE pins the class precisely).
 *   2. Title/description keyword fallback (for findings that carry no CWE).
 *   3. `undefined` when nothing matches (caller emits no compliance clauses —
 *      never a wrong mapping).
 *
 * This is deliberately advisory: it annotates findings with framework clauses;
 * it never changes a finding's verification state or severity.
 */

import type { FindingCategory, ComplianceClause } from './compliance-mapping.js';
import { clausesFor } from './compliance-mapping.js';

export type { ComplianceClause } from './compliance-mapping.js';

/**
 * Authoritative CWE-id → FindingCategory map. Covers the CWEs T3MP3ST's arsenal
 * and recon actually emit; extend as new detectors land. Keyed by the numeric id
 * (as a string) so both "CWE-89" and "89" resolve.
 */
const CWE_TO_CATEGORY: Readonly<Record<string, FindingCategory>> = {
  // Injection
  '89': 'sqli', // SQL Injection
  '564': 'sqli', // SQL Injection: Hibernate
  '79': 'xss', // Cross-site Scripting
  '80': 'xss', // Improper Neutralization of Script-Related HTML Tags
  // Access control
  '639': 'idor', // Authorization Bypass Through User-Controlled Key (IDOR)
  '566': 'idor', // Authorization Bypass Through User-Controlled SQL Primary Key
  '284': 'broken-authz', // Improper Access Control
  '285': 'broken-authz', // Improper Authorization
  '862': 'broken-authz', // Missing Authorization
  '863': 'broken-authz', // Incorrect Authorization
  '287': 'broken-authn', // Improper Authentication
  '306': 'broken-authn', // Missing Authentication for Critical Function
  '798': 'broken-authn', // Use of Hard-coded Credentials
  '308': 'broken-authn', // Use of Single-factor Authentication
  // SSRF / XXE
  '918': 'ssrf', // Server-Side Request Forgery
  '611': 'xxe', // Improper Restriction of XML External Entity Reference
  '827': 'xxe', // Improper Control of Document Type Definition
  // Sensitive data
  '200': 'sensitive-data-exposure', // Exposure of Sensitive Information
  '201': 'sensitive-data-exposure', // Insertion of Sensitive Info Into Sent Data
  '532': 'sensitive-data-exposure', // Insertion of Sensitive Information into Log File
  '312': 'sensitive-data-exposure', // Cleartext Storage of Sensitive Information
  // Crypto
  '327': 'crypto-weakness', // Use of a Broken or Risky Cryptographic Algorithm
  '326': 'crypto-weakness', // Inadequate Encryption Strength
  '328': 'crypto-weakness', // Use of Weak Hash
  '319': 'crypto-weakness', // Cleartext Transmission of Sensitive Information
  // Session
  '384': 'session-fixation', // Session Fixation
  '613': 'session-fixation', // Insufficient Session Expiration
  // CSRF / redirect
  '352': 'csrf', // Cross-Site Request Forgery
  '601': 'open-redirect', // URL Redirection to Untrusted Site
  // Misconfig
  '16': 'misconfiguration', // Configuration
  '2': 'misconfiguration', // Environmental (config)
  '15': 'misconfiguration', // External Control of System or Config Setting
  '756': 'misconfiguration', // Missing Custom Error Page
  // Rate limit / logging
  '770': 'rate-limit-absent', // Allocation of Resources Without Limits or Throttling
  '799': 'rate-limit-absent', // Improper Control of Interaction Frequency
  '307': 'rate-limit-absent', // Improper Restriction of Excessive Authentication Attempts
  '778': 'logging-gap', // Insufficient Logging
  '223': 'logging-gap', // Omission of Security-relevant Information
};

/** Keyword fallback patterns, tried in order when no CWE resolves. */
const KEYWORD_FALLBACK: ReadonlyArray<readonly [RegExp, FindingCategory]> = [
  [/\bsql\s*injection\b|\bsqli\b|\bunion\s+select\b/i, 'sqli'],
  [/\bcross[- ]site\s+scripting\b|\bxss\b/i, 'xss'],
  [/\bidor\b|insecure\s+direct\s+object|user[- ]controlled\s+key/i, 'idor'],
  [/\bssrf\b|server[- ]side\s+request\s+forgery/i, 'ssrf'],
  [/\bxxe\b|xml\s+external\s+entit/i, 'xxe'],
  [/\bcsrf\b|cross[- ]site\s+request\s+forgery/i, 'csrf'],
  [/open\s+redirect|url\s+redirect/i, 'open-redirect'],
  [/session\s+fixation/i, 'session-fixation'],
  [/broken\s+auth(entication)?|missing\s+auth(entication)?|weak\s+password|default\s+cred/i, 'broken-authn'],
  [/broken\s+access\s+control|missing\s+authoriz|privilege\s+escalation|forced\s+brows/i, 'broken-authz'],
  [/sensitive\s+data|information\s+(disclosure|exposure|leak)|pii\b/i, 'sensitive-data-exposure'],
  [/weak\s+(crypto|cipher|hash)|broken\s+crypto|insecure\s+(tls|ssl)|cleartext/i, 'crypto-weakness'],
  [/misconfig|security\s+header|directory\s+listing|default\s+config/i, 'misconfiguration'],
  [/rate[- ]limit|throttl|brute[- ]force/i, 'rate-limit-absent'],
  [/insufficient\s+logging|no\s+audit|logging\s+gap/i, 'logging-gap'],
];

/** Normalize a raw CWE token ("CWE-89", "cwe89", "89") to its numeric id. */
function cweId(raw: string): string | undefined {
  const m = raw.match(/(\d+)/);
  return m?.[1];
}

/**
 * Derive a `FindingCategory` from a finding. CWE ids win; otherwise the title +
 * description are scanned for a known keyword. Returns `undefined` when nothing
 * matches (never guess a category).
 */
/**
 * Minimal structural view of a finding for compliance mapping. Accepts both the
 * engine's `Finding` and the flat `AnalysisFinding` — only `cwe`, `title` and
 * `description` are ever read, and all are optional so neither shape is
 * privileged. Advisory only: no category is ever guessed when nothing matches.
 */
export interface ComplianceFindingLike {
  readonly cwe?: readonly string[];
  readonly title?: string;
  readonly description?: string;
}

export function categoryForFinding(finding: ComplianceFindingLike): FindingCategory | undefined {
  const cwes = Array.isArray(finding.cwe) ? finding.cwe : [];
  for (const raw of cwes) {
    if (typeof raw !== 'string') continue;
    const id = cweId(raw);
    if (id && CWE_TO_CATEGORY[id]) return CWE_TO_CATEGORY[id];
  }

  const haystack = `${finding.title ?? ''}\n${finding.description ?? ''}`;
  for (const [pattern, category] of KEYWORD_FALLBACK) {
    if (pattern.test(haystack)) return category;
  }
  return undefined;
}

/** Category for a single CWE id/token, or undefined if unmapped. */
export function categoryForCwe(cwe: string): FindingCategory | undefined {
  const id = cweId(cwe);
  return id ? CWE_TO_CATEGORY[id] : undefined;
}

/**
 * Resolve compliance clauses for a finding via its derived category. Empty array
 * when the category can't be determined — advisory, never fabricated.
 */
export function complianceClausesForFinding(finding: ComplianceFindingLike): readonly ComplianceClause[] {
  const category = categoryForFinding(finding);
  return category ? clausesFor(category) : [];
}

/** All CWE ids the bridge maps (for coverage tests / diagnostics). */
export function mappedCweIds(): readonly string[] {
  return Object.keys(CWE_TO_CATEGORY);
}
