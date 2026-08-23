const BLOCKED_LONG_FLAGS = new Set([
  '--abstract-unix-socket', '--cacert', '--cert', '--config', '--connect-to', '--cookie',
  '--interface', '--key', '--location', '--location-trusted', '--next', '--preproxy',
  '--proxy', '--resolve', '--socks4', '--socks4a', '--socks5', '--socks5-hostname',
  '--unix-socket', '--upload-file', '--url',
]);
const BLOCKED_SHORT_FLAGS = new Set(['b', 'K', 'L', 'T', 'x']);
const LONG_VALUE_FLAGS = new Set([
  '--connect-timeout', '--data', '--data-ascii', '--data-binary', '--data-raw',
  '--data-urlencode', '--form', '--form-string', '--header', '--max-time', '--output',
  '--request', '--request-target', '--retry', '--user', '--user-agent',
]);
const LONG_BOOLEAN_FLAGS = new Set([
  '--compressed', '--fail', '--fail-with-body', '--head', '--http1.0', '--http1.1',
  '--http2', '--http2-prior-knowledge', '--include', '--insecure', '--no-location',
  '--no-progress-meter', '--remote-name', '--show-error', '--silent', '--verbose',
]);
const SHORT_VALUE_FLAGS = new Set(['A', 'd', 'F', 'H', 'm', 'o', 'u', 'X']);
const SHORT_BOOLEAN_FLAGS = new Set(['#', '0', '1', '2', '3', '4', '6', 'f', 'i', 'I', 'k', 'O', 's', 'S', 'v']);

function blockedFlagError(flag: string): string {
  if (flag === '--location' || flag === '--location-trusted' || flag === '-L') {
    return `curl flag ${flag} follows redirects outside the approved target and is not allowed.`;
  }
  if (flag === '--upload-file' || flag === '-T') {
    return `curl flag ${flag} uploads a local file and is not allowed.`;
  }
  return `curl flag ${flag} changes the effective destination or reads a local configuration/credential file and is not allowed.`;
}

function validateValue(flag: string, value: string): string | undefined {
  if (['--data', '--data-ascii', '--data-binary', '-d'].includes(flag) && /^[@<]/.test(value)) {
    return `curl flag ${flag} may not read request data from a local file or stdin.`;
  }
  if ((flag === '--data-urlencode') && (/^@/.test(value) || /^[^=]+@/.test(value))) {
    return `curl flag ${flag} may not read request data from a local file.`;
  }
  if ((flag === '--form' || flag === '-F') && /(?:^|=)[@<]/.test(value)) {
    return `curl flag ${flag} may not upload a local file or read from stdin.`;
  }
  if ((flag === '--header' || flag === '-H') && value.startsWith('@')) {
    return `curl flag ${flag} may not read headers from a local file.`;
  }
  return undefined;
}

function normalizeHttpTarget(value: string): string | null {
  try {
    const parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `http://${value}`);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    if (!parsed.hostname) return null;
    return value;
  } catch {
    return null;
  }
}

export type CurlInspectionResult = { target: string } | { error: string };

/** Parse the fail-closed curl subset exposed by the generic command endpoint. */
export function inspectCurlArgs(args: readonly string[]): CurlInspectionResult {
  const operands: string[] = [];
  let endOfOptions = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!endOfOptions && arg === '--') {
      endOfOptions = true;
      continue;
    }

    if (!endOfOptions && arg.startsWith('--')) {
      const separator = arg.indexOf('=');
      const flag = separator >= 0 ? arg.slice(0, separator) : arg;
      if (BLOCKED_LONG_FLAGS.has(flag)) return { error: blockedFlagError(flag) };
      if (LONG_BOOLEAN_FLAGS.has(flag)) {
        if (separator >= 0) return { error: `curl flag ${flag} does not accept a value.` };
        continue;
      }
      if (!LONG_VALUE_FLAGS.has(flag)) return { error: `curl flag ${flag} is not supported by /api/tools/execute.` };
      const value = separator >= 0 ? arg.slice(separator + 1) : args[++index];
      if (value === undefined || value === '') return { error: `curl flag ${flag} requires a value.` };
      const validationError = validateValue(flag, value);
      if (validationError) return { error: validationError };
      continue;
    }

    if (!endOfOptions && arg.startsWith('-') && arg !== '-') {
      for (let offset = 1; offset < arg.length; offset += 1) {
        const short = arg[offset];
        const flag = `-${short}`;
        if (BLOCKED_SHORT_FLAGS.has(short)) return { error: blockedFlagError(flag) };
        if (SHORT_BOOLEAN_FLAGS.has(short)) continue;
        if (!SHORT_VALUE_FLAGS.has(short)) return { error: `curl flag ${flag} is not supported by /api/tools/execute.` };
        const attached = arg.slice(offset + 1);
        const value = attached || args[++index];
        if (value === undefined || value === '') return { error: `curl flag ${flag} requires a value.` };
        const validationError = validateValue(flag, value);
        if (validationError) return { error: validationError };
        break;
      }
      continue;
    }

    operands.push(arg);
  }

  if (operands.length !== 1) {
    return { error: operands.length
      ? 'curl commands with multiple URL operands are not allowed; submit one transfer per approved target.'
      : 'curl requires one explicit HTTP(S) URL operand so the approval can bind to its destination.' };
  }
  const target = normalizeHttpTarget(operands[0]);
  return target ? { target } : { error: 'curl URL operand must be a valid HTTP(S) target.' };
}
