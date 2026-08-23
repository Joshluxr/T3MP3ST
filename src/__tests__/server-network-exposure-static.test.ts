import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Static regression invariants for the two high-severity exposure findings:
//  1. An explicit non-loopback T3MP3ST_HOST must require Bearer auth or refuse the bind.
//  2. Client-supplied LLM baseUrl values must be restricted against SSRF
//     (link-local cloud metadata, public literal IPs, URL-embedded credentials).
const serverSource = readFileSync(join(process.cwd(), 'src/server.ts'), 'utf8');

function sourceBlock(startMarker: string, endMarker: string): string {
  const start = serverSource.indexOf(startMarker);
  expect(start, `missing source marker ${startMarker}`).toBeGreaterThanOrEqual(0);
  const end = serverSource.indexOf(endMarker, start);
  expect(end, `missing end marker ${endMarker}`).toBeGreaterThan(start);
  return serverSource.slice(start, end);
}

describe('non-loopback bind requires bearer auth', () => {
  it('derives the exposure mode from an explicit T3MP3ST_HOST and reads T3MP3ST_TOKEN', () => {
    expect(serverSource).toContain("const EXPLICIT_NON_LOOPBACK_HOST = Boolean(process.env.T3MP3ST_HOST?.trim()) && !HOST_IS_LOOPBACK;");
    expect(serverSource).toContain("const API_BEARER_TOKEN = process.env.T3MP3ST_TOKEN?.trim() || '';");
  });

  it('refuses to start on an explicit non-loopback bind without a token', () => {
    const startup = sourceBlock('async function startServer()', 'startServer().catch');
    expect(startup).toContain('if (EXPLICIT_NON_LOOPBACK_HOST && !API_BEARER_TOKEN)');
    expect(startup).toContain('REFUSING TO START');
    expect(startup).toContain('process.exit(1)');
    // The refusal must come BEFORE the listener is installed.
    expect(startup.indexOf('REFUSING TO START')).toBeLessThan(startup.indexOf('app.listen('));
  });

  it('enforces a timing-safe Bearer check on /api when exposed, exempting /api/health', () => {
    const guard = sourceBlock('Bearer auth for an explicitly exposed', "app.use(express.json({ limit: '10mb' }));");
    expect(guard).toContain('if (EXPLICIT_NON_LOOPBACK_HOST && API_BEARER_TOKEN)');
    expect(guard).toContain("app.use('/api'");
    expect(guard).toContain("if (req.path === '/health') return next();");
    expect(guard).toContain('timingSafeEqual(candidate, expected)');
    expect(guard).toContain('candidate.length !== expected.length');
    expect(guard).toContain('res.status(401)');
  });
});

describe('LLM baseUrl SSRF hardening', () => {
  const sanitize = sourceBlock('const LOCAL_BASE_URL_ALLOWLIST', 'function createTempestCommandInstance(');

  it('supports an explicit operator allowlist via env', () => {
    expect(sanitize).toContain('T3MP3ST_LOCAL_BASE_URL_ALLOWLIST');
    expect(sanitize).toContain('LOCAL_BASE_URL_ALLOWLIST.has(host)');
  });

  it('names well-known cloud metadata hostnames and the link-local metadata IP', () => {
    expect(sanitize).toContain('BLOCKED_METADATA_HOSTNAMES');
    expect(sanitize).toContain("'metadata.google.internal'");
    expect(sanitize).toContain("'169.254.169.254'");
  });

  it('restricts literal IPv4 destinations to loopback and RFC1918 space', () => {
    expect(sanitize).toContain('function isPrivateOrLoopbackIPv4');
    expect(sanitize).toContain('a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)');
  });

  it('rejects IPv6 link-local while allowing ULA (fc00::/7)', () => {
    expect(sanitize).toContain("host.startsWith('fc') || host.startsWith('fd')");
  });

  it('rejects credentials embedded in the URL and non-http(s) schemes', () => {
    expect(sanitize).toContain('parsed.username || parsed.password');
    expect(sanitize).toContain("parsed.protocol !== 'http:' && parsed.protocol !== 'https:'");
  });

  it('rejects disallowed hosts inside sanitizeLocalBaseUrl', () => {
    expect(sanitize).toContain('!parsed.hostname || !isAllowedLocalBaseUrlHost(parsed.hostname)');
  });

  it('routes the /api/models caller-supplied baseUrl through the same SSRF guard', () => {
    const models = sourceBlock("app.post('/api/models'", 'TOOL EXECUTION ENDPOINTS');
    expect(models).toContain('sanitizeLocalBaseUrl(rawBodyBaseUrl)');
    expect(models).toContain('res.status(400).json({ error: buCheck.error })');
  });
});
