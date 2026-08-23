import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Static regression invariants for the second hardening pass on src/server.ts:
//  1. persistState write race — debounced async snapshot writes could overlap and
//     complete out of order (older snapshot overwriting a newer one), and a crash
//     mid-write could leave a truncated state.json.
//  2. SSRF DNS gap — sanitizeLocalBaseUrl vetted the hostname STRING only; a
//     hostile LAN name could still resolve to metadata/public space at fetch time.
//  3. task:dispatched broadcast fired BEFORE target validation, announcing a
//     phantom task on the SSE stream for dispatches that then 400'd.
const serverSource = readFileSync(join(process.cwd(), 'src/server.ts'), 'utf8');

describe('persistState serializes writes and persists atomically', () => {
  const start = serverSource.indexOf('let persistChain');
  const end = serverSource.indexOf('// Debounced full-snapshot writer', start);
  const block = serverSource.slice(start, end);

  it('serializes snapshot writes through a promise chain', () => {
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    expect(block).toContain('persistChain.then(');
    // The chain must survive a failed write so later snapshots are not wedged.
    expect(block).toContain('persistChain = run.catch(');
  });

  it('writes via a tmp file + atomic rename instead of truncating in place', () => {
    expect(block).toContain('`${file}.tmp`');
    expect(block).toContain('await rename(tmp, file)');
    expect(block).not.toContain('await writeFile(file,');
  });
});

describe('local baseUrl SSRF guard resolves DNS before fetching', () => {
  it('defines the DNS-resolution check with fail-closed semantics', () => {
    expect(serverSource).toContain('async function validateLocalBaseUrlDns(');
    expect(serverSource).toContain("from 'dns/promises'");
    // IPv4-mapped IPv6 answers must be unwrapped before vetting.
    expect(serverSource).toContain("addr.startsWith('::ffff:')");
    expect(serverSource).toContain('could not be resolved');
  });

  it('routes every outbound-fetch call site through the DNS-checked variant', () => {
    expect(serverSource).toContain('async function sanitizeLocalBaseUrlChecked(');
    // The only remaining sync-variant call is inside the Checked wrapper itself.
    const syncCalls = serverSource
      .split('\n')
      .filter((l) => l.includes('= sanitizeLocalBaseUrl(') || l.includes('=sanitizeLocalBaseUrl('));
    expect(syncCalls).toHaveLength(1);
    expect(syncCalls[0]).toContain('const sync = sanitizeLocalBaseUrl(raw);');
  });

  it('makes resolveGeneralLLMConfig async and awaits it at every call site', () => {
    expect(serverSource).toContain('async function resolveGeneralLLMConfig(');
    expect(serverSource).not.toContain('= resolveGeneralLLMConfig(');
    expect(serverSource).not.toContain(': resolveGeneralLLMConfig(provider, model, apiKey, baseUrl);');
  });
});

describe('task:dispatched broadcast fires only after validation', () => {
  it('announces the dispatch after the no-targets 400, not before', () => {
    const noTargets = serverSource.indexOf('No targets available for task dispatch');
    const broadcast = serverSource.indexOf("broadcastEvent('task:dispatched'");
    expect(noTargets).toBeGreaterThanOrEqual(0);
    expect(broadcast).toBeGreaterThan(noTargets);
  });
});
