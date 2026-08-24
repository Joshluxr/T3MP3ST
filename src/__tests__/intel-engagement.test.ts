import { describe, it, expect } from 'vitest';
import {
  parseEngagementYaml, scopeFromEngagement, describeScope,
  YamlParseError, EngagementValidationError,
} from '../intel/engagement.js';

const VALID_YAML = `
# engagement manifest
name: ltomedical-external
operator: josh
client: LTO Medical
authorization: "Signed contract C-2026-118, email on file"
scope:
  authorized_targets:
    - https://app.ltomedical.example
    - staging.ltomedical.example
  excluded_targets:
    - mail.ltomedical.example
  allow_private_ranges: false
  allow_loopback: true
approvals:
  default: manual
  destructive: manual
  phases:
    exploit: manual
rules:
  max_runtime_seconds: 7200
  max_concurrent_requests: 4
  stop_on_critical: true
`;

describe('engagement manifest', () => {
  it('parses the YAML subset into a validated engagement', () => {
    const { engagement, warnings } = parseEngagementYaml(VALID_YAML);
    expect(engagement.name).toBe('ltomedical-external');
    expect(engagement.scope.authorizedTargets).toHaveLength(2);
    expect(engagement.scope.excludedTargets).toEqual(['mail.ltomedical.example']);
    expect(engagement.approvals.phaseModes.exploit).toBe('manual');
    expect(engagement.rules.maxRuntimeSeconds).toBe(7200);
    expect(warnings).toHaveLength(0); // authorization mentions signed/email
  });

  it('derives an egress scope where exclusions override authorizations', () => {
    const { engagement } = parseEngagementYaml(VALID_YAML);
    const scope = scopeFromEngagement(engagement);
    expect(scope.allowedHosts).toContain('app.ltomedical.example');
    expect(scope.allowedHosts).toContain('staging.ltomedical.example');
    expect(scope.allowedHosts).not.toContain('mail.ltomedical.example');
    expect(scope.allowLoopback).toBe(true);
    expect(scope.allowPrivate).toBe(false);
    expect(describeScope(scope)).toContain('authorized: app.ltomedical.example');
  });

  it('requires at least one authorized target', () => {
    expect(() => parseEngagementYaml('name: x\nscope:\n  authorized_targets: []\n'))
      .toThrow(EngagementValidationError);
  });

  it('rejects malformed YAML with a line number', () => {
    expect(() => parseEngagementYaml('name: "unterminated')).toThrow(YamlParseError);
    expect(() => parseEngagementYaml('scope: [unclosed')).toThrow(); // scalar fallback still fails validation
  });

  it('warns when authorization lacks a written record', () => {
    const { warnings } = parseEngagementYaml(
      'name: x\nauthorization: verbal only\nscope:\n  authorized_targets:\n    - a.example\n',
    );
    expect(warnings.join(' ')).toMatch(/written record/);
  });

  it('applies documented defaults for omitted optional fields', () => {
    const { engagement } = parseEngagementYaml('scope:\n  authorized_targets:\n    - a.example\n');
    expect(engagement.rules.maxRuntimeSeconds).toBe(3600);
    expect(engagement.approvals.defaultMode).toBe('manual');
    expect(engagement.scope.allowLoopback).toBe(true);
    expect(engagement.scope.allowPrivateRanges).toBe(false);
  });
});
