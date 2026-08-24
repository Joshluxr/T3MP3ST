/**
 * Scope-gated HTTP probing for the intel lanes (authz-matrix, flow-attacks,
 * remediation verification).
 *
 * Every intel network probe funnels through a single choke-point that:
 *   1. resolves the target host (hostFromTargetValue — same math as the arsenal gate),
 *   2. FAILS CLOSED when a value looks like a network target but yields no host
 *      (the '//evil.com' / 'file://…' bypass class),
 *   3. refuses any host outside the engagement scope (hostAllowed).
 *
 * A probe function is injected so unit tests drive the lanes with synthetic
 * responses and the server can swap in undici with whatever proxy policy it
 * wants — the lanes never import fetch machinery themselves.
 */

import { hostAllowed } from '../arsenal/index.js';
import type { ArsenalScope } from '../arsenal/index.js';

export interface ProbeRequest {
  readonly url: string;
  readonly method?: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string;
  /** Milliseconds before the probe is abandoned. */
  readonly timeoutMs?: number;
}

export interface ProbeResponse {
  readonly status: number;
  readonly body: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly elapsedMs: number;
}

export type Probe = (req: ProbeRequest) => Promise<ProbeResponse>;

export class ScopeError extends Error {
  constructor(public readonly target: string) {
    super(`probe target out of engagement scope: ${target}`);
  }
}

/** One fetch-shaped primitive the server adapter implements; tests fake it. */
export type FetchLike = (url: string, init: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<{
  status: number;
  text: () => Promise<string>;
  headers: { get(name: string): string | null };
}>;

export interface MakeProbeOptions {
  readonly scope: ArsenalScope;
  readonly fetchImpl?: FetchLike;
  /** Hard cap per request regardless of the caller's timeoutMs. Default 15s. */
  readonly maxTimeoutMs?: number;
  /** Called for every refused host — lets the server audit blocked probes. */
  readonly onBlocked?: (target: string, url: string) => void;
}

const NETWORK_SHAPED = /^[a-z][a-z0-9+.-]*:\/\//i;

/** True when a URL-looking value has no parseable host — treat as hostile. */
export function looksLikeUnparseableNetworkTarget(url: string): boolean {
  if (!url.startsWith('//') && !NETWORK_SHAPED.test(url)) return false;
  try {
    new URL(url);
    return false;
  } catch {
    return true;
  }
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Build a scope-enforcing probe. Throws ScopeError (does not silently skip) so
 * callers surface policy violations instead of mistaking them for dead targets.
 */
export function makeScopeProbe(options: MakeProbeOptions): Probe {
  const fetchImpl = options.fetchImpl ?? ((globalThis as { fetch?: FetchLike }).fetch as FetchLike | undefined);
  if (!fetchImpl) throw new Error('no fetch implementation available');
  const maxTimeout = options.maxTimeoutMs ?? 15_000;

  return async (req: ProbeRequest): Promise<ProbeResponse> => {
    const host = hostOf(req.url);
    if (!host || looksLikeUnparseableNetworkTarget(req.url)) {
      options.onBlocked?.(req.url, req.url);
      throw new ScopeError(req.url);
    }
    if (!hostAllowed(options.scope, host)) {
      options.onBlocked?.(host, req.url);
      throw new ScopeError(host);
    }

    const timeout = Math.min(req.timeoutMs ?? maxTimeout, maxTimeout);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const startedAt = Date.now();
    try {
      const resp = await fetchImpl(req.url, {
        method: req.method ?? 'GET',
        ...(req.headers ? { headers: { ...req.headers } } : {}),
        ...(req.body !== undefined ? { body: req.body } : {}),
        signal: controller.signal,
      });
      const body = await resp.text();
      const headers: Record<string, string> = {};
      for (const name of ['location', 'content-type', 'set-cookie', 'retry-after']) {
        const v = resp.headers.get(name);
        if (v) headers[name] = v;
      }
      return {
        status: resp.status,
        body,
        headers,
        elapsedMs: Date.now() - startedAt,
      };
    } finally {
      clearTimeout(timer);
    }
  };
}
