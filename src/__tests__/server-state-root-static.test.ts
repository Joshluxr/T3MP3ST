import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Static regression invariant for the stateRoot() branch-ordering bug: the old
// code re-tested T3MP3ST_STATE_DIR on a path where it was already falsy, so
// T3MP3ST_MODE=t3mp3st silently ran with ephemeral in-memory state while
// currentMode() reported 't3mp3st'. The mode must map to a real on-disk root.
const serverSource = readFileSync(join(process.cwd(), 'src/server.ts'), 'utf8');

describe('stateRoot() honors T3MP3ST_MODE', () => {
  const start = serverSource.indexOf('function stateRoot()');
  const end = serverSource.indexOf('function stateFilePath()', start);
  const block = serverSource.slice(start, end);

  it('is defined and does not re-test T3MP3ST_STATE_DIR in its fallback', () => {
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    expect(block).not.toContain("(process.env.T3MP3ST_STATE_DIR ?");
  });

  it('persists t3mp3st mode under the conventional ~/.t3mp3st dir', () => {
    expect(block).toContain("process.env.T3MP3ST_MODE === 't3mp3st'");
    expect(block).toContain("join(homedir(), '.t3mp3st', 'organs', 't3mp3st')");
  });

  it('keeps standalone mode memory-only', () => {
    expect(block).toContain(": 'memory'");
  });

  it('stays consistent with currentMode()', () => {
    const modeStart = serverSource.indexOf('function currentMode()');
    const modeEnd = serverSource.indexOf('function stateRoot()', modeStart);
    const modeBlock = serverSource.slice(modeStart, modeEnd);
    // currentMode() and stateRoot() must key off the same mode signal so the
    // reported mode and the persistence driver can never disagree again.
    expect(modeBlock).toContain("process.env.T3MP3ST_MODE === 't3mp3st'");
  });
});
