# Intel Surface — Shannon Port (Items 2–8)

**Date:** 2026-08-24 · **Branch:** `main` · **Commits:** `23e5be6`, `34e2c3d`, `238fb8e`, `7bdb6a9`, `e68727f`, `6c7cf9f` (rebased to `95ca863`)

## 1. What this is

T3MP3ST reviewed an annotated Shannon distribution (a ~81k-line TypeScript
security-automation monorepo) and selectively ported the features catalogued as
**items 2–8**. Item 1 — the live-ops panel (130 API routes + plain-JS monitor
UI) — was **excluded by operator decision**.

Everything landed as a new `src/intel/` module tree plus a new HTTP surface
(`/api/intel/*`), with one adapter (`src/analysis/shannon-adapter.ts`) bridging
Shannon's finding shape into T3MP3ST's.

### Licensing

Both T3MP3ST and Shannon are AGPL-3.0, so verbatim porting is legal and the
combined work remains AGPL. Where the logic was small it was reimplemented
cleanly rather than copied; larger pure-function modules were ported with
attribution headers (see `src/intel/attack.ts` for the Keygraph, Inc.
copyright notice carried over from Shannon's `types/campaign.ts`).

## 2. What was ported (item by item)

| # | Feature | Where it lives |
|---|---------|----------------|
| 2 | Engagement manifest (ROE YAML: scope, lanes, gates, budgets, honeytokens) | `src/intel/engagement.ts` |
| 3 | Bug-intel memory (durable signatures, new-vs-known, seed variants) | `src/intel/bug-intel.ts` |
| 4 | Delta scanning (baseline-diff → only new endpoints) | `src/intel/delta-scan.ts` |
| 5 | Reporting pure-functions: CVSS v3.1 auto-scoring, ATT&CK mapping + Navigator export, STIX 2.1 + MISP export, evidence gate + SHA-256 chain-of-custody | `src/intel/cvss.ts`, `src/intel/attack.ts`, `src/intel/attack-navigator.ts`, `src/intel/stix-misp.ts`, `src/intel/evidence-custody.ts`, `src/intel/report-gate.ts` |
| 6 | Remediation verifier (bypass-mutation retests) | `src/intel/remediation.ts` |
| 7 | Attack lanes: authorization-matrix + flow attacks (auth-flow, reset-chain, enum-spray) | `src/intel/authz-matrix.ts`, `src/intel/flow-attacks.ts` |
| 8 | HTTP surface exposing all of the above | 15 `/api/intel/*` routes in `src/server.ts` |

Supporting modules written for the port: `src/intel/types.ts` (the
`IntelFinding` lowest-common-denominator shape), `src/intel/probe.ts`
(scope-gated HTTP choke-point for all lanes), `src/intel/index.ts` (barrel),
and `src/analysis/shannon-adapter.ts` (Shannon `ToolFinding` → `IntelFinding`;
synthesizes the `tool` string and resolves `targetId`→host because Shannon's
shape lacks a confidence field and target representation).

## 3. Module reference

### `engagement.ts` — ROE manifest
YAML-subset parser + schema for the operator-signed engagement document:
authorized targets, hard "never touch" exclusions, per-phase approval gates,
budgets, and honeytoken canaries. Single source of truth read by every active
lane; the operator identity is stamped on findings. Exposed via
`GET/PUT /api/intel/engagement`.

### `probe.ts` — scope-gated HTTP choke-point
Every intel network probe funnels through here: host resolution via the same
math as the arsenal gate, **fail-closed** on ambiguous targets, scope check,
lane rule check, budget accounting. No lane issues raw `fetch` calls.

### `authz-matrix.ts` — authorization matrix lane
Logs in as several identities (anonymous included by default), replays the
endpoint inventory as each, and diffs responses to prove: missing
authentication, privilege escalation between roles, and IDOR-style
cross-tenant access. Produces matrix cells + `IntelFinding`s with the
offending identity pair recorded.

### `flow-attacks.ts` — multi-step flow attacks
Chains requests to expose flaws single-request scanners miss:
`auth-flow` (OAuth redirect_uri validation weakness, JWT signature-validation
bugs), `reset-chain` (password reset poisoning / token leakage across the
reset flow), `enum-spray` (user enumeration via differential responses with
spray-safe pacing).

### `bug-intel.ts` — durable signature memory
Distils each run's findings into signatures and merges them into a persistent
store. Later runs separate **new** findings from **known** ones and can
synthesize seed variants for retest generation. This is what turns one-shot
hunts into a compounding program.

### `delta-scan.ts` — incremental scan selection
Given the baseline of already-covered locations from a prior run,
`selectNewEndpoints` returns only uncovered endpoints so recurring engagements
target fresh code — where new vulnerabilities actually live.

### `cvss.ts` — CVSS v3.1 auto-scoring
Deterministic, offline-safe scoring: severity tag + category + source map to a
representative vector and base score via a small ruleset (no NVD lookup).
Findings whose category is unrecognized are surfaced for manual scoring rather
than guessed.

### `attack.ts` + `attack-navigator.ts` — ATT&CK mapping & Navigator export
Frozen technique/tactic registry with the default vuln-class → ATT&CK mapping
(ported from Shannon `types/campaign.ts`), plus a Navigator layer-JSON exporter
that loads directly at https://mitre-attack.github.io/attack-navigator/ for a
technique heatmap of the engagement.

### `stix-misp.ts` — STIX 2.1 + MISP export
Findings → STIX 2.1 bundle and → MISP event JSON, with CVE and IOC (IPs,
domains, hashes) extracted from composed evidence entries.

### `evidence-custody.ts` + `report-gate.ts` — custody & report gate
SHA-256 chain-of-custody records (each record hashes content + previous hash)
so evidence survives review tamper-evidently. The report gate then blocks any
final deliverable where a critical/high finding lacks preserved evidence or a
passing verify gate.

### `remediation.ts` — remediation verifier
Re-runs a "fixed" finding through a family of **bypass mutations of the
original payload** — an attacker who patched only the exact reported string
will still fall to a variant. Any surviving variant means not really fixed.
Grafted onto the existing retest flow as `POST /api/intel/retests/:findingId/verify`.

### `shannon-adapter.ts` — the seam
Adapts Shannon `ToolFinding` → `IntelFinding`. Because Shannon's shape lacks a
confidence field and uses opaque `targetId`s, the adapter synthesizes the
`tool` string and resolves `targetId`→host. All intel escalations stay
**advisory** in `src/evidence/gate.ts` — LLM inferences and lane escalations
never mark a finding verified without real tool provenance.

## 4. HTTP surface

15 routes (see `docs/API_REFERENCE.md` → "Intel Surface"):

| Method | Path |
|---|---|
| GET | `/api/intel/engagement` |
| PUT | `/api/intel/engagement` |
| POST | `/api/intel/authz-matrix` |
| POST | `/api/intel/flow/:lane` |
| GET | `/api/intel/memory` |
| POST | `/api/intel/memory/merge` |
| POST | `/api/intel/delta` |
| GET | `/api/intel/cvss` |
| POST | `/api/intel/custody/preserve` |
| GET | `/api/intel/custody` |
| GET | `/api/intel/report/gate` |
| GET | `/api/intel/export/stix` |
| GET | `/api/intel/export/misp` |
| GET | `/api/intel/export/navigator` |
| POST | `/api/intel/retests/:findingId/verify` |

## 5. Bugs found & fixed during the port

1. **OAuth redirect classifier blindness** (`remediation.ts`) — the fetch init
   lacked `redirect: 'manual'`, so the redirect_uri classifier never observed
   3xx redirections. Fixed; classifier now sees them.
2. **CVE/IOC extraction missed composed evidence** — `exportStixBundle`,
   `exportMispEvent`, and `scoreFinding` scanned only the single `evidence`
   string, not `evidenceEntries`. Fixed to scan composed entries.
3. **500 on unknown vuln class** — `POST /api/intel/retests/:id/verify`
   crashed on unknown classes; `generateVariants` now returns `[]` and the
   route returns 400 with a diagnostic (`34e2c3d`).

## 6. Testing & verification

- **Unit:** 7 new suites — `intel-core`, `intel-custody-gate`,
  `intel-engagement`, `intel-export`, `intel-lanes`,
  `intel-memory-delta-cvss`, `intel-remediation` (850/850 project-wide).
- **E2E (full-logic, not smoke):** `npm run intel:e2e` (`scripts/intel-e2e.mjs`)
  builds the server, boots it, and drives all 15 routes over HTTP — including
  negative paths (tampered custody chain → gate rejects; out-of-scope probe →
  451; unknown lane → 400; report gate blocks unproven criticals; bypass
  mutations detect a cosmetic patch). 61/61 checks pass.
- **Tooling:** `tsc --noEmit` clean; `npm run lint` clean on `src/intel/`
  (remaining warnings are pre-existing elsewhere); `npm audit` 0
  vulnerabilities. The two `arsenal-smoke` failures are pre-existing on
  `origin/main` (a `file`-type environment quirk and a flaky abort), verified
  not caused by this port.

## 7. Contribution receipt

- **Change:** Port Shannon items 2–8 (engagement control-plane, bug-intel
  memory, delta scan, reporting pure-functions, remediation verifier, attack
  lanes, HTTP surface) into `src/intel/` + `/api/intel/*`.
- **Scope class:** `local_lab` — all lane/e2e network traffic targets a
  loopback test fixture booted by the e2e script; no external targets.
- **Target authority:** N/A (loopback only).
- **Network use:** loopback HTTP from the e2e script to the booted server.
- **Run mode labels:** lanes and exports are `tool-backed`; LLM-adjacent
  escalations are `advisory-only` (evidence gate stays authoritative).
- **Model/harness labels:** no LLM calls added by this port.
- **Commands run:** `npm run typecheck` → pass; `npm test` → pass (850/850);
  `npm run intel:e2e` → pass (61/61); `npm run lint` → clean on `src/intel/`;
  `npm run doctor` → skipped; `npm run verify-claims` → skipped.
- **Artifacts:** `scripts/intel-e2e.mjs`, 7 test suites under `src/__tests__/`.
- **Redaction:** no secrets in payloads; e2e uses synthetic fixtures only.
- **Claims changed:** none (no benchmark numbers touched).
- **Abstentions/refusals:** live-ops panel (item 1) excluded by operator
  decision; OOB/OAST interaction requires an operator-supplied collaborator
  domain (no default).
- **Residual risk:** CVSS auto-scores are rule-based defaults — treat
  unrecognized categories as "needs manual scoring," which the API surfaces.
