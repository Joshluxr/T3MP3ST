/**
 * Authorization-matrix lane (ported from Shannon, adapted to T3MP3ST).
 *
 * Logs in as several identities (by default including an anonymous one),
 * replays the discovered endpoint inventory as each, and diffs the responses
 * to prove authorization flaws with high confidence:
 *   - missing authentication (anonymous reads a protected endpoint),
 *   - broken function-level authorization (a non-admin identity reaches an
 *     admin-only endpoint),
 *   - broken object-level authorization (the same object id returns identical
 *     content to two different identities — not owner-scoped).
 *
 * The pure classifier is separated from the network runner: the runner only
 * produces response cells (status/length/hash), and classification is fully
 * deterministic and unit-tested. Sessions are cookie/bearer injected by the
 * operator — no credential guessing happens here.
 */

import { createHash } from 'node:crypto';
import type { IntelFinding, IntelSeverity } from './types.js';
import type { Probe } from './probe.js';

export interface MatrixEndpoint {
  readonly url: string;
  /** Only GET endpoints are replayed — replaying writes across identities is unsafe. */
  readonly method?: string;
}

export type MatrixRole = 'anon' | 'user' | 'admin';

export interface MatrixIdentity {
  readonly name: string;
  readonly role: MatrixRole;
  /** Raw Cookie header value for this identity (pre-authenticated session). */
  readonly cookie?: string;
  /** Bearer token for this identity. */
  readonly bearerToken?: string;
}

/** One observed response cell in the matrix. */
export interface Cell {
  readonly status: number;
  readonly length: number;
  readonly hash: string;
}

export interface IdentityRuntime {
  readonly name: string;
  readonly role: MatrixRole;
  /** True when the identity carries credentials (cookie or token). */
  readonly authenticated: boolean;
}

export function cellFromBody(status: number, body: string): Cell {
  return { status, length: body.length, hash: createHash('sha256').update(body).digest('hex').slice(0, 16) };
}

const ADMIN_PATTERN = /\/(admin|manage|management|internal|superuser|root|config|settings|users?)\b/i;
const PROTECTED_PATTERN = /\/(api|account|me|profile|dashboard|orders?|invoices?|documents?|billing|private)\b/i;

function isOk(cell: Cell | undefined): boolean {
  return cell !== undefined && cell.status >= 200 && cell.status < 300 && cell.length > 0;
}

export function looksAdmin(url: string): boolean {
  return ADMIN_PATTERN.test(url);
}

export function looksProtected(url: string): boolean {
  return PROTECTED_PATTERN.test(url) || looksAdmin(url);
}

/**
 * Classify one endpoint's response row (identity → cell) into findings.
 * Requires at least one authenticated identity to have succeeded so we know the
 * endpoint is real and reachable — anonymous hits on dead endpoints are noise.
 */
function urlHash(url: string): string {
  return createHash('sha256').update(url, 'utf8').digest('hex').slice(0, 12);
}

export function classifyEndpointRow(
  url: string,
  identities: readonly IdentityRuntime[],
  row: ReadonlyMap<string, Cell>,
): IntelFinding[] {
  const findings: IntelFinding[] = [];
  const authedOk = identities.some(i => i.authenticated && isOk(row.get(i.name)));

  const anon = identities.find(i => i.role === 'anon');
  if (anon && isOk(row.get(anon.name)) && authedOk && looksProtected(url)) {
    findings.push({
      id: `authz-anon-${urlHash(url)}`,
      source: 'authz-matrix',
      target: url,
      title: 'Missing authentication on protected endpoint',
      severity: looksAdmin(url) ? 'high' : 'medium',
      location: url,
      description: 'The endpoint returns content to an unauthenticated client while also serving authenticated identities, indicating the access control is missing or client-side only.',
    });
  }

  if (looksAdmin(url)) {
    const adminOk = identities.some(i => i.role === 'admin' && isOk(row.get(i.name)));
    for (const id of identities) {
      if (id.role === 'user' && id.authenticated && isOk(row.get(id.name)) && adminOk) {
        findings.push({
          id: `authz-bfla-${urlHash(url)}-${id.name}`,
          source: 'authz-matrix',
          target: url,
          title: 'Broken function-level authorization (BFLA)',
          severity: 'high',
          location: url,
          description: `Non-admin identity "${id.name}" reached an admin-only endpoint that the admin identity can also reach — function-level authorization is not enforced.`,
        });
      }
    }
  }

  return findings;
}

/** Cross-identity object-access check: same object id, identical body, two identities. */
export function classifyObjectAccess(
  url: string,
  ownerName: string,
  otherName: string,
  ownerCell: Cell,
  otherCell: Cell,
): IntelFinding | null {
  if (!isOk(ownerCell) || !isOk(otherCell)) return null;
  if (ownerCell.hash !== otherCell.hash) return null;
  return {
    id: `authz-bola-${urlHash(url)}`,
    source: 'authz-matrix',
    target: url,
    title: 'Broken object-level authorization (BOLA)',
    severity: 'high',
    location: url,
    description: `Identity "${otherName}" retrieved the exact object served to "${ownerName}" (identical response body), so objects are not scoped to their owner — cross-tenant/cross-user data access.`,
  };
}

export interface AuthzMatrixRunInput {
  readonly target: string;
  /** GET endpoints to replay; when empty, sensible defaults are derived from the target. */
  readonly endpoints?: readonly MatrixEndpoint[];
  readonly identities: readonly MatrixIdentity[];
  readonly probe: Probe;
  /** Cap on replayed endpoints per run. Default 60. */
  readonly maxEndpoints?: number;
  /** Abort signal checked between requests. */
  readonly aborted?: () => boolean;
  /** Called with per-request progress for the operator feed. */
  readonly onProgress?: (message: string) => void;
}

export interface AuthzMatrixRunResult {
  readonly findings: IntelFinding[];
  readonly endpointsTested: number;
  readonly identitiesAuthed: number;
  readonly durationMs: number;
}

function defaultEndpoints(target: string): MatrixEndpoint[] {
  const base = target.replace(/\/+$/, '');
  return [
    '/api/user',
    '/api/users',
    '/api/me',
    '/api/profile',
    '/api/account',
    '/api/orders',
    '/api/invoices',
    '/api/documents',
    '/api/admin',
    '/api/admin/users',
    '/api/settings',
    '/dashboard',
    '/account',
    '/profile',
    '/admin',
    '/admin/users',
  ].map(path => ({ url: `${base}${path}` }));
}

function headersFor(identity: MatrixIdentity): Record<string, string> | undefined {
  const headers: Record<string, string> = {};
  if (identity.cookie) headers.cookie = identity.cookie;
  if (identity.bearerToken) headers.authorization = `Bearer ${identity.bearerToken}`;
  return Object.keys(headers).length ? headers : undefined;
}

/**
 * Run the matrix: replay every GET endpoint as every identity, classify each
 * row, then run the cross-identity object-access comparison per endpoint.
 */
export async function runAuthzMatrix(input: AuthzMatrixRunInput): Promise<AuthzMatrixRunResult> {
  const startedAt = Date.now();
  const max = input.maxEndpoints ?? 60;
  const endpoints = (input.endpoints?.length ? input.endpoints : defaultEndpoints(input.target))
    .filter(e => (e.method ?? 'GET').toUpperCase() === 'GET')
    .slice(0, max);

  const runtimes: IdentityRuntime[] = input.identities.map(i => ({
    name: i.name,
    role: i.role,
    authenticated: Boolean(i.cookie || i.bearerToken),
  }));
  const identitiesAuthed = runtimes.filter(r => r.authenticated).length;

  const findings: IntelFinding[] = [];
  let tested = 0;

  for (const endpoint of endpoints) {
    if (input.aborted?.()) break;
    const row = new Map<string, Cell>();
    for (const identity of input.identities) {
      if (input.aborted?.()) break;
      try {
        const resp = await input.probe({ url: endpoint.url, headers: headersFor(identity) });
        row.set(identity.name, cellFromBody(resp.status, resp.body));
      } catch {
        row.set(identity.name, { status: 0, length: 0, hash: '' });
      }
    }
    tested += 1;
    input.onProgress?.(`[authz-matrix] ${endpoint.url} — ${[...row.values()].map(c => c.status || 'x').join('/')}`);
    findings.push(...classifyEndpointRow(endpoint.url, runtimes, row));

    // Object-level comparison between the first two authenticated identities on 200s.
    const authed = input.identities.filter(i => i.cookie || i.bearerToken);
    if (authed.length >= 2) {
      const [owner, other] = authed;
      const ownerCell = row.get(owner.name);
      const otherCell = row.get(other.name);
      if (ownerCell && otherCell) {
        const bola = classifyObjectAccess(endpoint.url, owner.name, other.name, ownerCell, otherCell);
        if (bola) findings.push(bola);
      }
    }
  }

  return {
    findings,
    endpointsTested: tested,
    identitiesAuthed,
    durationMs: Date.now() - startedAt,
  };
}

export type { IntelSeverity };
