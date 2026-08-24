/**
 * Auto-PoC generator (F16).
 *
 * Turns a structured `ToolFinding` into a copy-paste reproducer command.
 *
 * The generated reproducer is intentionally minimal: just enough for an
 * operator to confirm the finding in their own terminal without having
 * to dig through the tool's raw output. Per-tool generators produce
 * the most natural form for that tool's surface:
 *
 *   sqlmap  -> `sqlmap --batch -u <url> -p <param>`
 *   hydra   -> `hydra -l <user> -p <pass> <proto>://<host>:<port>`
 *   dalfox  -> `curl <url-with-payload>`
 *   nuclei  -> `curl <matched-url>`
 *   nikto   -> `curl -I <url>`
 *   ffuf    -> `curl <url>` for each result row
 *   subfinder -> `dig <subdomain>`
 *   gau     -> `curl <url>`
 *   default -> manual reproducer template
 *
 * Pure function over a `ToolFinding`. No I/O, no env reads.
 */

import type { AnalysisFinding as ToolFinding } from './finding.js';

export type ReproducerLanguage = 'bash' | 'http' | 'sql' | 'manual';

export interface Reproducer {
  /** The reproducer kind, used by downstream renderers to pick a code fence. */
  readonly language: ReproducerLanguage;
  /** The full command string the operator should run. */
  readonly command: string;
  /** Free-text human note about what to look for in the output. */
  readonly note?: string;
}

function safeShellArg(value: string): string {
  // Single-quote and escape internal single-quotes for /bin/sh.
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function pickParam(evidence: string | undefined): string | undefined {
  if (!evidence) return undefined;
  const m = evidence.match(/\bparam(?:eter)?=([A-Za-z0-9_-]+)/i);
  return m?.[1];
}

function pickUrlFromEvidence(evidence: string | undefined): string | undefined {
  if (!evidence) return undefined;
  const m = evidence.match(/https?:\/\/[^\s'"<>]+/);
  return m?.[0];
}

function pickPortFromEvidence(evidence: string | undefined): string | undefined {
  if (!evidence) return undefined;
  const m = evidence.match(/\bport=(\d+)/);
  return m?.[1];
}

function pickServiceFromEvidence(evidence: string | undefined): string | undefined {
  if (!evidence) return undefined;
  const m = evidence.match(/\bservice=([A-Za-z0-9_-]+)/);
  return m?.[1];
}

function pickLoginFromEvidence(evidence: string | undefined): string | undefined {
  if (!evidence) return undefined;
  const m = evidence.match(/\blogin=([^\s]+)/);
  return m?.[1];
}

// === Per-tool generators ===

function reproducerForSqlmap(f: ToolFinding): Reproducer {
  const url = pickUrlFromEvidence(f.evidence) ?? f.target;
  const param = pickParam(f.evidence);
  const paramFlag = param ? ` -p ${safeShellArg(param)}` : '';
  return {
    language: 'bash',
    command: `sqlmap --batch -u ${safeShellArg(url)}${paramFlag}`,
    note: 'Confirm the same injection point reports as exploitable. Add --dump only with allow_data_exfiltration.',
  };
}

function reproducerForHydra(f: ToolFinding): Reproducer {
  const service = pickServiceFromEvidence(f.evidence) ?? 'ssh';
  const port = pickPortFromEvidence(f.evidence);
  const login = pickLoginFromEvidence(f.evidence) ?? '<login>';
  const host = f.target;
  const portFlag = port ? ` -s ${port}` : '';
  return {
    language: 'bash',
    command:
      `# Password is redacted to a sha256 prefix; supply the cracked value from your secure store.\n` +
      `hydra -l ${safeShellArg(login)} -p '<PASSWORD>'${portFlag} ${service}://${host}`,
    note: 'Use the same password the scan found. The wrapper redacts it; retrieve from your engagement vault.',
  };
}

function reproducerForDalfox(f: ToolFinding): Reproducer {
  const url = pickUrlFromEvidence(f.evidence) ?? f.target;
  return {
    language: 'bash',
    command: `curl -sS ${safeShellArg(url)} | head -c 2000`,
    note: 'Open the URL in a sandboxed browser and confirm the XSS payload fires.',
  };
}

function reproducerForNuclei(f: ToolFinding): Reproducer {
  const url = pickUrlFromEvidence(f.evidence) ?? f.target;
  return {
    language: 'bash',
    command: `curl -sSI ${safeShellArg(url)}`,
    note: 'Re-run the matching template (-id <id>) to confirm the finding survives a retry.',
  };
}

function reproducerForNikto(f: ToolFinding): Reproducer {
  const url = pickUrlFromEvidence(f.evidence) ?? f.target;
  return {
    language: 'bash',
    command: `curl -sSI ${safeShellArg(url)}`,
    note: 'Compare the headers reported in the finding against the live response.',
  };
}

function reproducerForHttpProbe(f: ToolFinding): Reproducer {
  const url = pickUrlFromEvidence(f.evidence) ?? f.target;
  return {
    language: 'bash',
    command: `curl -sSI ${safeShellArg(url)}`,
  };
}

function reproducerForSubfinder(f: ToolFinding): Reproducer {
  return {
    language: 'bash',
    command: `dig +short ${safeShellArg(f.target)}`,
    note: 'Verify the subdomain still resolves before treating it as in-scope attack surface.',
  };
}

function reproducerForNmap(f: ToolFinding): Reproducer {
  const port = pickPortFromEvidence(f.evidence);
  const portFlag = port ? ` -p ${port}` : '';
  return {
    language: 'bash',
    command: `nmap -sV${portFlag} ${safeShellArg(f.target)}`,
  };
}

function reproducerForMasscan(f: ToolFinding): Reproducer {
  const port = pickPortFromEvidence(f.evidence) ?? '0-65535';
  return {
    language: 'bash',
    command: `masscan ${safeShellArg(f.target)} -p ${port} --rate 1000`,
  };
}

function reproducerForSecret(f: ToolFinding): Reproducer {
  return {
    language: 'manual',
    command:
      `# Open the source file referenced in the evidence and rotate the credential.\n` +
      `# Evidence: ${f.evidence ?? '<no evidence>'}`,
    note: 'Treat as compromised. Rotate immediately and audit recent uses of the credential.',
  };
}

function reproducerForSemgrep(f: ToolFinding): Reproducer {
  return {
    language: 'manual',
    command: `# Open the file referenced in the evidence and review the flagged code path.\n# Evidence: ${f.evidence ?? '<no evidence>'}`,
  };
}

function reproducerForTrivy(f: ToolFinding): Reproducer {
  return {
    language: 'bash',
    command: `trivy fs --severity HIGH,CRITICAL ${safeShellArg(f.target)}`,
  };
}

function defaultReproducer(f: ToolFinding): Reproducer {
  return {
    language: 'manual',
    command:
      `# Tool: ${f.tool}\n` +
      `# Target: ${f.target}\n` +
      `# Evidence: ${f.evidence ?? '<no evidence>'}\n` +
      `# Re-run the wrapper with the same args to reproduce.`,
  };
}

const GENERATORS: Readonly<Record<string, (f: ToolFinding) => Reproducer>> = Object.freeze({
  sqlmap: reproducerForSqlmap,
  hydra: reproducerForHydra,
  dalfox: reproducerForDalfox,
  nuclei: reproducerForNuclei,
  nikto: reproducerForNikto,
  httpx: reproducerForHttpProbe,
  ffuf: reproducerForHttpProbe,
  wapiti: reproducerForHttpProbe,
  arjun: reproducerForHttpProbe,
  katana: reproducerForHttpProbe,
  gau: reproducerForHttpProbe,
  subfinder: reproducerForSubfinder,
  dnsx: reproducerForSubfinder,
  nmap: reproducerForNmap,
  naabu: reproducerForNmap,
  masscan: reproducerForMasscan,
  trufflehog: reproducerForSecret,
  gitleaks: reproducerForSecret,
  semgrep: reproducerForSemgrep,
  trivy: reproducerForTrivy,
});

/**
 * Build a reproducer for a finding. Returns the default manual
 * reproducer for unknown tools rather than null so the report
 * always has something to show.
 */
export function generatePoC(finding: ToolFinding): Reproducer {
  const generator = GENERATORS[finding.tool] ?? defaultReproducer;
  return generator(finding);
}
