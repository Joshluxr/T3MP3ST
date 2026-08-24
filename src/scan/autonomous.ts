/**
 * Autonomous ROE unlock (Phase 0) — modeled on Shannon's
 * applyAutonomousFullAuthorization.
 *
 * When a ScanProfile carries `autonomous: true` (or T3MP3ST_SCAN_AUTONOMOUS=1),
 * this normalizes the profile in place for a hands-off run:
 *  - every approval gate flips to `auto`
 *  - a missing/placeholder authorizationDocPath is accepted and stamped with
 *    the canonical `operator-authorized-target` placeholder
 *  - an empty target list is widened to an explicit wildcard marker
 *
 * Interactive profiles (autonomous absent/false) are returned untouched —
 * the existing T3 scope + approval gates keep their fail-closed behavior.
 */

import {
  AUTONOMOUS_AUTH_DOC_PLACEHOLDER,
  type ScanProfile,
} from './types.js';

/** True when the env-level autonomous default is on. A profile's own
 *  `autonomous` flag, when present, always wins (per-job override). */
export function envAutonomousDefault(): boolean {
  return /^(1|true|yes|on)$/i.test((process.env.T3MP3ST_SCAN_AUTONOMOUS ?? '').trim());
}

/** True when this profile should run hands-off. */
export function isAutonomous(profile: ScanProfile): boolean {
  if (typeof profile.autonomous === 'boolean') return profile.autonomous;
  return envAutonomousDefault();
}

const ALL_GATES = [
  'recon',
  'vulnerability-analysis',
  'exploitation',
  'credential',
  'privesc',
  'lateral',
  'reporting',
] as const;

/**
 * Apply the Shannon-style full-authorization unlock to a profile in place.
 * Idempotent. Returns the same profile for chaining.
 */
export function applyAutonomousFullAuthorization(profile: ScanProfile): ScanProfile {
  // 1. Auto every approval gate.
  const gates: Record<string, 'auto' | 'manual'> = { ...(profile.approvalGates ?? {}) };
  for (const g of ALL_GATES) gates[g] = 'auto';
  profile.approvalGates = gates;

  // 2. Accept a missing or placeholder authorization doc.
  if (!profile.authorizationDocPath || !profile.authorizationDocPath.trim()) {
    profile.authorizationDocPath = AUTONOMOUS_AUTH_DOC_PLACEHOLDER;
  }

  // 3. Widen an empty target list to an explicit wildcard marker. (Scope
  //    enforcement itself stays on unless the lane sets a wildcard Arsenal
  //    scope — this marker records the intent on the profile.)
  const t = profile.target;
  if (t && t.urls.length === 0 && t.hosts.length === 0) {
    t.hosts.push('*');
  }

  profile.autonomous = true;
  return profile;
}
