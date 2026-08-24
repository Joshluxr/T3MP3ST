# Shannon → T3MP3ST Port Plan

Full context and code implementation plan to bring selected Shannon
(Keygraph / `dijjal-kimi-review` extract) capabilities into T3MP3ST
(`github.com/Joshluxr/T3MP3ST`).

**Status:** planning document only. No production lanes from this plan are
live until each phase’s acceptance criteria pass.

**License note:** Shannon (Keygraph) and T3MP3ST are both AGPL-3.0-family.
Prefer **reimplementation against T3 interfaces** over wholesale file copies.
When adapting Shannon modules, preserve copyright headers and document
provenance in `THIRD-PARTY.md` / PR description.

**Autonomous mode (in scope):** Port Shannon-style autonomous engagement
behavior, including ROE unlock (`applyAutonomousFullAuthorization` equivalent),
auto approval gates, and accepting placeholder `authorization_doc` values such
as `operator-authorized-target`. When `autonomous: true`, lanes may bypass or
auto-satisfy T3 RoE / scope / approval / evidence gates as Shannon does.

---

## 0. Context: what exists today

### T3MP3ST (this repo)

| Layer | Reality | Paths |
| --- | --- | --- |
| Process model | In-process EventEmitter + tick/queue | `src/index.ts` (`TempestCommand`) |
| Missions / RoE | Real | `src/mission/`, `src/types/index.ts` |
| Arsenal + approval + egress | Real | `src/arsenal/{index,approval,catalog,adapter-tools}.ts` |
| Operators (8 archetypes) | Real ReAct loops; swarm exploit unproven | `src/operators/` |
| White-box ingest | Real, experimental limits | `src/recon/{code-ingest,whitebox,ts-parse}.ts` |
| Decomposition orchestrator | Real (objective → benign queries) | `src/orchestration/` |
| War Room UI | Static UI + SSE | `src/server.ts`, `docs/index.html` |
| Op Admiral | NL intake/planner only | `src/admiral/` |
| Evidence vault | Real | `src/evidence/` |
| MCP | Single tool `security_recon` | `src/mcp-server.ts` |
| Docker | Long-lived API container + optional Kali+ tools image | `Dockerfile`, `docker-compose.yml`, `tools/Dockerfile` |
| Stubs still attached | BrowserAutomation, ProtocolFuzzer, WorkflowOrchestrator, ExploitEngine, ScannerOrchestrator, … | `src/stubs/index.ts` |
| Stack | Node ≥22.19, npm, Vitest, ESLint, TypeScript ESM | `package.json` |

### Shannon extract (reference)

| Layer | Reality | Paths (under extract) |
| --- | --- | --- |
| Durable workflow | Temporal `pentestPipelineWorkflow` PHASE A/B/C | `apps/worker/src/temporal/workflows.ts` |
| Tool gate | `registry.runTool()` → scope → approval → rate → abort → audit | `apps/worker/src/tools/registry.ts` |
| Docker-per-scan | CLI `docker run --rm` + unique Temporal task queue | `apps/cli/src/docker.ts` |
| Tier-E | Opt-in LLM source analysis lanes | `apps/worker/src/services/tier-e-*.ts`, `taint-analysis.ts`, … |
| Browser DAST | Playwright crawl + login/TOTP | `services/browser-crawl.ts`, `session-login.ts` |
| Authz / flows / creds | Matrix + flow-attacks + hydra lane | `services/authz-matrix.ts`, `flow-attacks/`, `credential-scan.ts` |
| Smart contract | Pattern audits + Foundry `chain-sim` | `services/sol-*.ts`, `chain-sim.ts` |
| Fuzz orchestration | Greybox / concolic / crash triage | `services/greybox-fuzz.ts`, `fuzz-runner.ts`, … |
| Panel + NL | Separate Express app + chat tools | `apps/panel/` |
| Exports / sinks | SARIF/HTML/STIX + DefectDojo/Jira/… | `services/report-export.ts`, `integrations.ts` |
| Continuous / API / protocols | Diff scope + OpenAPI fuzz + WS/gRPC probes | `services/continuous.ts`, `api-fuzz.ts`, `protocol-tests.ts` |

### Mapping principle

```text
Shannon Temporal activity  →  T3 ScanLane (pluggable) under ScanWorkflow
Shannon runTool()          →  Arsenal.execute() / adapter tools (+ autonomous bypass)
Shannon deliverables JSON  →  EvidenceVault + Finding[] + optional export providers
Shannon panel              →  extend War Room + /api/* (not a second product)
Shannon engagement.yaml    →  extend RulesOfEngagement + ScanProfile YAML/JSON
Shannon autonomous ROE     →  ScanProfile.autonomous + applyAutonomousFullAuthorization
```

**Port Shannon autonomous defaults:** when `ScanProfile.autonomous` is true,
apply an `applyAutonomousFullAuthorization`-style unlock (force allow-\* flags,
auto approval gates, accept placeholder `authorization_doc`, optionally widen
empty targets). Interactive mode may keep existing T3 gate behavior.

---

## 1. Target architecture (T3-shaped)

### 1.1 New packages / modules (proposed tree)

```text
src/
  scan/                         # NEW — durable scan orchestration
    types.ts                    # ScanJob, ScanPhase, LaneId, ScanAbortController
    workflow.ts                 # ScanWorkflow (Temporal-backed when enabled)
    temporal/                   # NEW — optional Temporal worker/client
      client.ts
      worker.ts
      activities.ts
      workflows.ts
    docker-runner.ts            # ephemeral per-scan container
    abort.ts                    # abort token registered into Arsenal
    lane-registry.ts            # register/run lanes
    lanes/
      tier-e.ts
      browser-dast.ts
      authz-matrix.ts
      flow-attacks.ts
      credential.ts
      sol-audit.ts
      chain-sim.ts
      greybox-fuzz.ts
      concolic.ts
      api-fuzz.ts
      protocol-tests.ts
      continuous.ts
    profile.ts                  # ScanProfile parse/validate (zod or ajv)
  browser/                      # NEW — replace BrowserAutomation stub
    playwright-runner.ts
    session.ts                  # cookie jar, TOTP, SSO bootstrap
    crawl.ts
  authz/                        # NEW
    matrix.ts
    session-identity.ts
  flow/                         # NEW
    chains.ts                   # auth-flow, reset, upload-export, enum-spray
  fuzz/                         # NEW — orchestration over existing binaries
    campaign.ts
    greybox.ts
    concolic.ts
    crash-triage.ts
  contract/                     # NEW
    sol-audit.ts
    sol-multistep.ts
    chain-sim.ts
    harness-gen.ts
  export/                       # NEW
    sarif.ts
    html.ts
    stix.ts
    attack-navigator.ts
    composite.ts
  integrations/                 # EXTEND (today: bounty.ts only)
    sinks/
      defectdojo.ts
      jira.ts
      slack.ts
      teams.ts
      github.ts
      webhook.ts
    dispatcher.ts
  assistant/                    # NEW — NL ops copilot over War Room state
    tools.ts                    # read-only + gated write tools
    chat.ts
```

### 1.2 Control plane sketch

```ts
// src/scan/types.ts
export type LaneId =
  | 'recon'
  | 'tier_e'
  | 'browser_dast'
  | 'authz_matrix'
  | 'flow_attacks'
  | 'credential'
  | 'sol_audit'
  | 'chain_sim'
  | 'greybox_fuzz'
  | 'api_fuzz'
  | 'protocol_tests'
  | 'report'
  | 'integrations';

export interface ScanProfile {
  target: { urls: string[]; hosts: string[] };
  roe: RulesOfEngagement;           // existing T3 type
  /** Placeholder strings like "operator-authorized-target" are allowed. */
  authorizationDocPath?: string;
  /** Shannon-compatible: unlock ROE, auto-approve gates, skip evidence hard gates. */
  autonomous?: boolean;
  approvalGates?: Partial<Record<
    'recon' | 'vulnerability-analysis' | 'exploitation' | 'credential' | 'privesc' | 'lateral' | 'reporting',
    'auto' | 'manual'
  >>;
  docker?: { enabled: boolean; image?: string; network?: string };
  temporal?: { enabled: boolean; address?: string; taskQueue?: string };
  lanes: Partial<Record<LaneId, { enabled: boolean; [k: string]: unknown }>>;
}

export interface ScanAbortController {
  readonly aborted: boolean;
  abort(reason: string): void;
  throwIfAborted(): void;
}

export interface LaneContext {
  jobId: string;
  profile: ScanProfile;
  arsenal: Arsenal;                 // existing
  vault: EvidenceVault;             // existing
  llm: LLMBackbone;                 // existing
  abort: ScanAbortController;
  deliverablesDir: string;          // e.g. reports/scans/<jobId>/
  emit: (event: ScanProgressEvent) => void;
}

export interface ScanLane {
  id: LaneId;
  phase: 'A' | 'B' | 'C' | 'report';
  run(ctx: LaneContext): Promise<LaneResult>;
}
```

### 1.3 Abort wired into tools

Extend Arsenal so every `execute()` checks an optional abort signal:

```ts
// src/arsenal/index.ts (patch concept)
export interface ArsenalOptions {
  // existing...
  abort?: ScanAbortController;
}

async execute(name: string, context: ToolContext): Promise<ToolResult> {
  this.abort?.throwIfAborted();
  // When autonomous: skip or auto-pass scopeViolation + ApprovalController
  // (Shannon applyAutonomousFullAuthorization behavior).
  // When interactive: keep existing scope + approval checks.
  const result = await tool.handler(context);
  this.abort?.throwIfAborted();
  return result;
}
```

Temporal activity cancellation and War Room “Emergency Stop” both call
`abort.abort('operator')`, which flips the same controller the Arsenal holds.

### 1.4 Autonomous ROE unlock

Add `src/scan/autonomous.ts` modeled on Shannon’s
`applyAutonomousFullAuthorization`:

- Set all approval gates to `auto`
- Force allow-\* engagement flags true when modeled
- Accept `authorizationDocPath` of `operator-authorized-target` (or missing)
- Optionally treat empty target lists as wildcard when autonomous
- Auto-approve Arsenal credential/intrusive/dangerous tiers
- Soft-pass or skip `gateLiveFinding` hard failures for progressive lanes

Wire from profile load: `if (profile.autonomous) applyAutonomousFullAuthorization(profile)`.

### 1.5 Feature flags / config

Add to `.env.example` and `src/config/index.ts`:

```bash
T3MP3ST_SCAN_TEMPORAL=0
T3MP3ST_SCAN_TEMPORAL_ADDRESS=localhost:7233
T3MP3ST_SCAN_DOCKER=0
T3MP3ST_SCAN_DOCKER_IMAGE=t3mp3st-scan:local
T3MP3ST_SCAN_AUTONOMOUS=0       # default off at env level; profile.autonomous overrides per job
T3MP3ST_PLAYWRIGHT=0
T3MP3ST_FULL_ARSENAL=0          # already exists
T3MP3ST_EXPORT_SARIF=1
T3MP3ST_INTEGRATIONS=0
```

Scan profiles live as JSON under `engagements/` (new) or passed to
`POST /api/scans`.

---

## 2. Phased implementation plan

Each phase is independently mergeable. Do not enable the next phase’s
defaults until the previous phase’s tests are green.

Effort is described by **invasiveness** and **new subsystems**, not calendar
time.

---

### Phase 0 — Foundations (required before all lanes)

**Goal:** ScanJob model, profile schema, abort controller, deliverables dir,
autonomous unlock helper, API skeleton.

**Work**

1. Add `src/scan/types.ts`, `profile.ts` (AJV validate against JSON Schema).
2. Add `src/scan/abort.ts` + wire into `Arsenal` constructor/`TempestCommand`.
3. Add `src/scan/autonomous.ts` (`applyAutonomousFullAuthorization`) and call
   it when `profile.autonomous` or `T3MP3ST_SCAN_AUTONOMOUS=1`.
4. Add `src/scan/lane-registry.ts` with no-op lanes for testing.
5. Add `POST /api/scans`, `GET /api/scans/:id`, `POST /api/scans/:id/abort`,
   SSE progress on existing `/api/events` (new event names).
6. Persist job state under `reports/scans/<id>/job.json`.
7. Allow missing or placeholder `authorizationDocPath` (e.g.
   `operator-authorized-target`); do not hard-fail.
8. Unit tests: profile validation, autonomous unlock, abort short-circuit in
   Arsenal mock.

**Acceptance**

- [ ] Can create a scan that runs empty PHASE A and completes.
- [ ] Abort mid-lane stops further `arsenal.execute` calls.
- [ ] `autonomous: true` auto-passes approval/scope checks in unit tests.
- [ ] `npm test` + `npm run typecheck` pass.

**Invasiveness:** low–medium (touches Arsenal + server).

---

### Phase 1 — Temporal durable workflow + Docker-per-scan

**Goal:** Optional Temporal backend and ephemeral scan containers.

#### 1A. Temporal (opt-in)

**Dependencies:** `@temporalio/client`, `@temporalio/worker`,
`@temporalio/workflow`, `@temporalio/activity` (pin compatible set).

**Files**

- `src/scan/temporal/workflows.ts` — `scanPipelineWorkflow`
- `src/scan/temporal/activities.ts` — thin wrappers calling `LaneRegistry`
- `src/scan/temporal/worker.ts` — worker process entry (`npm run scan:worker`)
- `src/scan/temporal/client.ts` — start/signal/query from API
- `docker-compose.yml` — add optional `temporal` + `temporal-ui` profiles

**Workflow sketch**

```ts
// src/scan/temporal/workflows.ts
export async function scanPipelineWorkflow(input: ScanProfile): Promise<ScanSummary> {
  const phases = ['A', 'B', 'C', 'report'] as const;
  for (const phase of phases) {
    const lanes = laneIdsForPhase(phase, input);
    await Promise.all(lanes.map((id) => runLaneActivity(id, input)));
    // workflow-level abort signal handling
  }
  return summarize();
}
```

**In-process fallback:** when `T3MP3ST_SCAN_TEMPORAL=0`, `ScanWorkflow.run()`
executes lanes in-process with the same ordering (dev default).

#### 1B. Docker-per-scan

**Files:** `src/scan/docker-runner.ts`, extend `tools/Dockerfile` or add
`Dockerfile.scan`.

**Behavior**

```ts
// docker-runner.ts concept
await execFile('docker', [
  'run', '--rm',
  '--network', profile.docker.network ?? 't3-scan',
  '-e', `T3MP3ST_JOB_ID=${jobId}`,
  '-v', `${deliverables}:/out`,
  '-v', `${authorizationDoc}:/roe/auth.pdf:ro`,
  image,
  'node', 'dist/scan/temporal/worker.js', '--once', jobId,
]);
```

Reuse `/workspace/tools/Dockerfile` binaries via `PATH` inside the image.
Mount repo / target sources read-only when white-box lanes enabled.

**Acceptance**

- [ ] Temporal profile: workflow history shows phase transitions; abort signal
      cancels activities.
- [ ] Docker profile: container exits; deliverables persist on host.
- [ ] Default install unchanged (Temporal/Docker off).

**Invasiveness:** medium–high (new runtime deps + compose).

**Shannon reference:** `apps/cli/src/docker.ts`,
`apps/worker/src/temporal/workflows.ts`,
`engagement-control-registry.ts`.

---

### Phase 2 — Source-guided white-box → live validation (Tier-E)

**Goal:** LLM-assisted source lanes that emit findings + generated artifacts
consumed by later fuzz/nuclei lanes.

**Reuse T3:** `src/recon/code-ingest.ts`, `whitebox.ts`,
`orchestration/context-pack.ts`, `DecompositionOrchestrator`.

**New files:** `src/scan/lanes/tier-e.ts` plus service modules under
`src/recon/tier-e/`:

| Service | Input | Output |
| --- | --- | --- |
| `taint-analysis` | ingested ASTs / slices | taint paths → `Finding[]` |
| `variant-analysis` | pattern + corpus | variant hit list |
| `semantic-vuln-review` | packed context | hypothesized vulns (needs live confirm later) |
| `fuzz-harness-gen` | risky sinks | harness sources under `deliverables/harnesses/` |
| `nuclei-template-gen` | confirmed patterns | YAML templates under `deliverables/nuclei/` |

**Config (`ScanProfile.lanes.tier_e`)**

```json
{
  "enabled": true,
  "max_files": 200,
  "max_bytes_per_file": 200000,
  "services": ["taint", "variant", "semantic_review", "fuzz_harness", "nuclei_template"],
  "variant_pattern": "innerHTML\\s*="
}
```

**Implementation steps**

1. Source collector wrapping `ingestCodebase()` with byte/file caps.
2. Each service = pure function + LLM call via existing `LLMBackbone`.
3. Lane writes `tier_e_findings.json` and registers evidence.
4. Hook: if `lanes.greybox_fuzz` enabled, prefer generated harnesses.
5. Hook: if nuclei adapter present, allow generated templates via explicit
   allowlisted path (no arbitrary template URLs).

**Tests:** fixture mini-repo under `src/__tests__/fixtures/tier-e-app/`;
mock LLM; assert JSON schema of outputs.

**Acceptance**

- [ ] Tier-E on fixture produces ≥1 structured finding without network.
- [ ] Harness/template files land in deliverables.
- [ ] Disabled when no source mount / `enabled:false`.

**Shannon reference:** `services/tier-e-scan.ts`, `taint-analysis.ts`,
`fuzz-harness-gen.ts`, `nuclei-template-gen.ts`.

**Invasiveness:** medium (builds on existing white-box).

---

### Phase 3 — Authenticated browser DAST (Playwright) + TOTP/SSO

**Goal:** Replace `BrowserAutomation` stub with real crawl + session handling.

**Dependencies:** `playwright` (opt-in install); document
`npx playwright install chromium`.

**Files**

- Delete stub usage path: implement real class in `src/browser/` and re-export
  from a thin adapter so `TempestCommand` gains a real engine when
  `T3MP3ST_PLAYWRIGHT=1`.
- `src/browser/session.ts` — form login, cookie jar export
  (`storageState.json`), TOTP via `otpauth` or small helper.
- `src/browser/crawl.ts` — depth/page caps, same-origin scope check against RoE.
- `src/scan/lanes/browser-dast.ts`

**Session profile**

```json
{
  "login": {
    "type": "form",
    "login_url": "https://app.example.test/login",
    "username_selector": "#email",
    "password_selector": "#password",
    "submit_selector": "button[type=submit]",
    "totp_secret_env": "T3_TARGET_TOTP",
    "success_url_regex": "/dashboard"
  },
  "crawl": { "max_pages": 50, "max_depth": 3, "authenticated": true }
}
```

**SSO:** support “operator-provided storage state” first (upload
`auth-state.json`); automated SSO is phase-3b after form+TOTP works.

**Gates:** every request host must pass `scopeViolation`; no crawl outside
`authorized_targets`.

**Acceptance**

- [ ] Against local fixture app (`scripts/fixtures` or existing vuln fixture):
      login + crawl returns URL inventory JSON.
- [ ] Without Playwright installed, lane self-skips with clear reason.
- [ ] Stub `BrowserAutomation` either removed or becomes wrapper.

**Shannon reference:** `browser-crawl.ts`, `session-login.ts`,
`generate-totp.ts`, `validate-authentication.ts`.

**Invasiveness:** medium.

---

### Phase 4 — Authz matrix, flow-attack chains, credential lane

**Goal:** Multi-identity access testing + sequenced flow checks + gated
credential attacks.

#### 4A. Authz matrix (BOLA/BFLA)

**Files:** `src/authz/matrix.ts`, `src/scan/lanes/authz-matrix.ts`

**Algorithm (product-level, not exploit recipe)**

1. Build endpoint inventory from browser crawl / OpenAPI / recon.
2. For each identity (anonymous, user, admin, …) obtain session
   (cookie/token via `session.ts`).
3. For each endpoint×identity, issue **read-oriented** probes first;
   classify likely BOLA/BFLA/missing-auth from status/body differentials.
4. Emit `Finding` with evidence references; do not auto-weaponize.

**Config:** identities array with `login_url` / token env refs — never commit
secrets.

#### 4B. Flow-attack chains

**Files:** `src/flow/chains.ts`

Implement as **state machines** with explicit step lists:

- `auth_flow` — register/login/logout sequence integrity
- `reset_chain` — password reset token lifecycle checks
- `upload_export` — upload then access/export path checks
- `enum_spray` — bounded enumeration with hard caps

Each step calls Arsenal/`targetFetch` with abort + scope.

#### 4C. Credential lane

**Reuse:** catalog `hydra` adapter. When `autonomous` (or
`approvalGates.credential: "auto"`), auto-approve credential-tier tools.
In interactive mode, keep `ApprovalController` prompts. Prefer
`import_only` replay of operator-supplied credential lists before live spray
when not autonomous.

**Acceptance**

- [ ] Matrix on fixture with 2 roles flags intentional IDOR fixture.
- [ ] Flow caps enforced (`max_enum_probes`).
- [ ] Credential lane auto-runs under `autonomous: true`; prompts when not.

**Shannon reference:** `authz-matrix.ts`, `flow-attacks/*`, `credential-scan.ts`.

**Invasiveness:** medium–high.

---

### Phase 5 — Smart-contract depth + Foundry chain-sim

**Goal:** Orchestrate existing `slither` / `mythril` / `echidna` / `forge`
catalog entries into audit + simulation lanes.

**Files:** `src/contract/{sol-audit,sol-multistep,chain-sim,harness-gen}.ts`

**Lane A — static/pattern audit:** run adapters via Arsenal; normalize to
`Finding[]`; optional pure-TS check catalog (reentrancy patterns, etc.) on
Solidity sources from ingest.

**Lane B — multistep sequence checks:** analyze call sequences / invariants
suggestions (LLM-assisted optional).

**Lane C — `chain-sim`:** if `forge` on PATH and `foundry.toml` present:

```ts
// concept
await arsenal.execute('foundry_test', {
  args: ['test', '--match-test', profile.match_test, '--fork-url', rpcUrl],
});
```

Parse forge JSON output → findings. Optional harness generation writes into
a **scratch dir**, never mutating the target repo by default
(`write_harnesses: false` default).

**Acceptance**

- [ ] Without forge: self-skip.
- [ ] With tiny Foundry fixture: failing invariant becomes a Finding.
- [ ] No mainnet RPC calls in unit tests (mock exec).

**Shannon reference:** `sol-audit.ts`, `sol-multistep.ts`, `chain-sim.ts`,
`invariant-harness-gen.ts`.

**Invasiveness:** medium (mostly orchestration).

---

### Phase 6 — Zero-day / greybox fuzz orchestration

**Goal:** Campaign runner over `afl-fuzz` / libFuzzer-style binaries + optional
concolic assist — T3 already lists binaries in the install matrix.

**Files:** `src/fuzz/{campaign,greybox,concolic,crash-triage}.ts`,
`src/scan/lanes/greybox-fuzz.ts`

**Pipeline**

```text
Tier-E harnesses (or operator-supplied) 
  → corpus init
  → greybox runner (timeout, mem caps)
  → crash dedup / triage
  → (optional) concolic seed expand via SHANNON-like command template
  → Finding[] + crash artifacts in vault
```

**Config**

```json
{
  "enabled": true,
  "fuzzer": "afl",
  "max_runtime_seconds": 120,
  "max_targets": 5,
  "corpus_dir": ".t3/fuzz-corpus",
  "concolic": { "enabled": false, "command_env": "T3_CONCOLIC_CMD" }
}
```

**Safety:** local-only by default; no network fuzz targets unless host in RoE.
Resource caps mandatory (CPU affinity optional).

**Acceptance**

- [ ] Fixture harness + fake fuzzer binary in tests produces triage JSON.
- [ ] Runtime cap kills process tree.
- [ ] Integrates artifacts from Phase 2 when present.

**Shannon reference:** `greybox-fuzz.ts`, `fuzz-runner.ts`, `concolic-assist.ts`,
`crash-triage-exploit.ts`, `zeroday-loop.ts`.

**Invasiveness:** medium–high (process supervision).

---

### Phase 7 — Control panel + NL assistant

**Goal:** Elevate War Room + Op Admiral into an ops copilot that can
configure/monitor scans — not a second Shannon panel app.

**Approach**

1. Extend `docs/index.html` War Room with a **Scans** view (job list, phase
   timeline, abort button, deliverables links, autonomous toggle).
2. Add `src/assistant/` with tool definitions that call existing HTTP handlers
   (`/api/scans`, `/api/approvals`, `/api/evidence`, `/api/status`).
3. Extend `/api/admiral/converse` or add `/api/assistant/chat` with:
   - read tools always available
   - write tools (`start_scan`, `abort_scan`, `set_lane`, `enable_autonomous`)
4. System prompt: port Shannon panel guidance — prefer enabling useful lanes,
   allow `autonomous: true`, accept placeholder `authorization_doc` when the
   operator requests hands-off runs.

**Acceptance**

- [ ] Assistant can start an autonomous scan profile and abort it.
- [ ] Assistant can start scans with placeholder `authorizationDocPath`.
- [ ] UI shows live phase via SSE and an autonomous indicator.

**Shannon reference:** `apps/panel/src/{server,chat}.ts` (including autonomous
lane-enable guidance).

**Invasiveness:** medium (UI + API).

---

### Phase 8 — Integrations + SARIF/HTML/STIX exports

**Goal:** Machine-readable exports and optional push sinks.

**Files:** `src/export/*`, `src/integrations/sinks/*`,
`src/integrations/dispatcher.ts`

**Export providers** (compose like Shannon’s composite reporter):

| Provider | Output |
| --- | --- |
| SARIF 2.1.0 | `report.sarif.json` |
| HTML | `report.html` (self-contained) |
| STIX 2.1 bundle | `report.stix.json` |
| ATT&CK Navigator | `navigator.json` |
| Markdown (existing AnalysisEngine) | keep |

Normalize from `EvidenceVault` + `Finding[]` once — sinks consume the same
normalized set.

**Sinks:** DefectDojo, Jira, Slack, Teams, GitHub Issues, generic webhook.
Each sink: `type`, `url`, `token_env`, `min_severity`. Dispatcher runs
post-report when `T3MP3ST_INTEGRATIONS=1`.

**API:** `GET /api/reports/:id/sarif`, `POST /api/integrations/test`.

**Acceptance**

- [ ] SARIF validates against public schema in CI fixture test.
- [ ] Webhook sink hit with mock server.
- [ ] No tokens in logs (`redact.ts`).

**Shannon reference:** `report-export.ts`, `stix-misp-export.ts`,
`integrations.ts`.

**Invasiveness:** low–medium.

---

### Phase 9 — CI/diff continuous mode + schema API fuzz + protocol tests

#### 9A. Continuous / diff-driven

**Files:** `src/scan/lanes/continuous.ts`, `src/scan/delta.ts`

- `git diff --name-only <baseline_ref>` → restrict Tier-E / SAST file set.
- `fail_on: [high, critical]` → non-zero exit for `scripts/ci-scan.mjs`.
- GitHub Action workflow `scan-pr.yml` (opt-in).

#### 9B. Schema API fuzz

**Files:** `src/scan/lanes/api-fuzz.ts`, `src/fuzz/openapi.ts`

- Parse OpenAPI/Postman → sequenced requests with caps
  (`max_sequences`, `max_requests_per_sequence`).
- Use `targetFetch` + scope; auth from Phase 3 session.

#### 9C. GraphQL / gRPC / WebSocket probes

**Files:** `src/scan/lanes/protocol-tests.ts`

- Replace `ProtocolFuzzer` stub with bounded protocol checks:
  - GraphQL: introspection opt-in + basic abuse differentials
  - WebSocket: connect + limited message corpus
  - gRPC-web: reflection/HTTP probe only unless grpcurl adapter present

**Acceptance**

- [ ] PR diff mode scans only changed paths in fixture git repo.
- [ ] OpenAPI fixture produces bounded request count == cap.
- [ ] Protocol lane self-skips when endpoints absent.

**Shannon reference:** `continuous.ts`, `delta-scan.ts`, `api-fuzz.ts`,
`protocol-tests.ts`.

**Invasiveness:** medium.

---

## 3. Cross-cutting work

### 3.1 Types & events

Extend `CommandEvents` / `ScanProgressEvent` in `src/types/index.ts`:

```ts
'scan:created' | 'scan:phase' | 'scan:lane_started' | 'scan:lane_finished'
| 'scan:aborted' | 'scan:completed'
```

### 3.2 Testing strategy

| Layer | Approach |
| --- | --- |
| Unit | Vitest per module; mock Arsenal/LLM |
| Lane contract | Each lane: enable/disable/skip/abort tests |
| Fixture apps | `src/__tests__/fixtures/scan-apps/*` (HTTP, IDOR, OpenAPI, Foundry) |
| Fake binaries | Mirror Shannon fakes pattern under `scripts/scan-fakes/` |
| CI | New job `scan-lanes` only on label `run-scan-tests` (heavy) |

### 3.3 Docs to update as phases merge

- `docs/API_REFERENCE.md` — new `/api/scans*`
- `docs/GETTING_STARTED.md` — optional Temporal/Playwright
- `docs/INSTALL_MATRIX.md` — Playwright, forge, afl
- `FEATURES.md` — flip stubs → implemented with honesty notes
- `docs/SCOPE_AND_AUTHORIZATION.md` — document autonomous mode + placeholder
  `authorization_doc` behavior
- `THIRD-PARTY.md` — Shannon provenance if code adapted

### 3.4 Package.json scripts (additive)

```json
{
  "scan:worker": "tsx src/scan/temporal/worker.ts",
  "scan:worker:prod": "node dist/scan/temporal/worker.js",
  "test:scan": "vitest run src/scan src/browser src/authz src/flow src/fuzz src/contract src/export",
  "scan:ci": "node scripts/ci-scan.mjs"
}
```

---

## 4. Suggested merge order (dependency graph)

```text
Phase 0 Foundations
   ├─► Phase 1 Temporal/Docker
   ├─► Phase 2 Tier-E ──────────────┐
   ├─► Phase 3 Browser/Session ─────┼─► Phase 4 Authz/Flows/Creds
   │                                └─► Phase 6 Fuzz (harnesses)
   ├─► Phase 5 Contracts (parallel)
   ├─► Phase 8 Exports/Integrations (parallel early OK)
   ├─► Phase 7 Assistant (needs 0 + API)
   └─► Phase 9 Continuous/API/Protocols (needs 2–4)
```

Recommended PR slicing: **one phase per PR** (or 0+1a, 1b separate).

---

## 5. Explicit non-goals / anti-patterns

1. **No committed live customer host engagements in default samples** — ship
   lab fixtures; operator-supplied profiles may target authorized hosts.
2. **No hardcoded panel passwords** in committed defaults for shared deploys.
3. **Honesty:** mark lanes experimental until fixture coverage exists; keep
   `verify-claims` style receipts where applicable.

**In scope (formerly excluded):** Shannon autonomous ROE unlock, placeholder
`authorization_doc`, auto approval gates, and optional gate bypass when
`autonomous: true`.

---

## 6. Resource / risk summary

| Phase | New deps | External binaries | Main risk |
| --- | --- | --- | --- |
| 0 | none | none | API surface growth; autonomous unlock surface |
| 1 | Temporal SDK | Docker, Temporal server | Ops complexity |
| 2 | none | LLM provider | False-positive findings |
| 3 | playwright | Chromium | Auth session secret handling |
| 4 | none | hydra (opt) | Credential-lane aggression under autonomous |
| 5 | none | forge/slither/… | RPC costs / repo writes |
| 6 | none | afl-fuzz/libFuzzer | CPU runaway |
| 7 | none | none | Assistant enabling autonomous by default |
| 8 | none | none | Token leakage in sinks |
| 9 | none | git, grpcurl opt | CI flakiness |

---

## 7. First concrete PR checklist (Phase 0)

1. Create `src/scan/{types,profile,abort,autonomous,lane-registry,workflow}.ts`.
2. Patch `Arsenal` for abort checks + autonomous auto-approve path + unit tests.
3. Add `/api/scans` CRUD + abort in `server.ts` with origin guard.
4. Add Vitest coverage for placeholder `authorizationDocPath` acceptance and
   `applyAutonomousFullAuthorization` effects.
5. Update `FEATURES.md` with “Scan workflow (scaffolding)” experimental row.
6. No Temporal/Docker yet — in-process only.

---

## 8. Traceability matrix (request → phase)

| Requested capability | Phase |
| --- | --- |
| Temporal durable workflow + Docker-per-scan + abort wired into tools | 0 (abort), 1 (Temporal/Docker) |
| Source-guided white-box → live validation (Tier-E …) | 2 (+ consume in 6) |
| Authenticated browser DAST (Playwright), TOTP/SSO | 3 |
| Authz matrix (BOLA/BFLA), flow-attack chains, credential lane | 4 |
| Smart-contract depth + Foundry fork/chain-sim | 5 |
| Zero-day / greybox fuzz orchestration | 6 |
| Control panel + NL assistant | 7 |
| Integrations + SARIF/HTML/STIX/… | 8 |
| CI/diff-driven mode; schema API fuzz; GraphQL/gRPC/WebSocket | 9 |

---

## 9. Reference pointers (Shannon extract)

When implementing, consult these paths in the Shannon tree (local extract or
upstream Keygraph/shannon as appropriate):

- Temporal + abort: `apps/worker/src/temporal/`, `tools/registry.ts`
- Tier-E: `services/tier-e-scan.ts`, `taint-analysis.ts`, …
- Browser: `services/browser-crawl.ts`, `session-login.ts`
- Authz/flows/creds: `services/authz-matrix.ts`, `flow-attacks/`, `credential-scan.ts`
- Contracts: `services/sol-audit.ts`, `chain-sim.ts`
- Fuzz: `services/greybox-fuzz.ts`, `fuzz-runner.ts`
- Panel: `apps/panel/src/`
- Export/sinks: `services/report-export.ts`, `integrations.ts`
- Continuous/API/protocols: `services/continuous.ts`, `api-fuzz.ts`, `protocol-tests.ts`
- Docs: `docs/wiring-guide.md`, `docs/integration-status.md`

T3 counterparts to prefer extending first:
`src/arsenal/`, `src/recon/`, `src/orchestration/`, `src/evidence/`,
`src/admiral/`, `src/server.ts`, `src/stubs/index.ts` (replace stubs
in-place where possible).
