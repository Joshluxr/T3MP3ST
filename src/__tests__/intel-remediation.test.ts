import { describe, it, expect } from 'vitest';
import * as remediation from '../intel/remediation.js';

const finding: remediation.OriginalFinding = {
  id: 'f-1',
  vulnClass: 'sqli',
  originalPayload: "' UNION SELECT user(),database()--",
};

describe('remediation verifier', () => {
  it('generates an ordered mutation set per vuln class', () => {
    const variants = remediation.generateVariants(finding);
    expect(variants.length).toBeGreaterThanOrEqual(4);
    expect(variants.every(v => v.label && v.mutated && v.rationale)).toBe(true);
    expect(variants.some(v => v.label.includes('time-delay'))).toBe(true);
  });

  it('covers every supported vuln class', () => {
    for (const vulnClass of ['sqli', 'xss', 'open-redirect', 'ssrf', 'idor', 'path-traversal'] as const) {
      const variants = remediation.generateVariants({ id: 'f', vulnClass, originalPayload: 'x' });
      expect(variants.length).toBeGreaterThanOrEqual(3);
    }
  });

  it('verdicts fully-remediated when no variant is reflected', () => {
    const variants = remediation.generateVariants(finding);
    const responses = variants.map(v => ({
      findingId: finding.id, label: v.label, status: 403, responseBody: 'blocked', elapsedMs: 12,
    }));
    const result = remediation.classifyResults(finding, responses);
    expect(result.verdict).toBe('fully-remediated');
    expect(result.bypassedVariants).toHaveLength(0);
  });

  it('verdicts not-remediated when the original class of payload still lands', () => {
    const variants = remediation.generateVariants(finding);
    const responses = variants.map(v => ({
      findingId: finding.id, label: v.label,
      status: v.label === 'time-delay' ? 200 : 403,
      responseBody: v.label === 'time-delay' ? 'took 6 seconds' : 'blocked',
      elapsedMs: v.label === 'time-delay' ? 6100 : 10,
    }));
    const result = remediation.classifyResults(finding, responses);
    expect(result.verdict).toBe('partial-bypass');
    expect(result.bypassedVariants).toContain('time-delay');
  });
});
