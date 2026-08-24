/**
 * Scan profile JSON Schema + AJV validation (Shannon plan Phase 0).
 */

import Ajv, { type ValidateFunction } from 'ajv';
import type { ScanProfile } from './types.js';
import { LANE_IDS } from './types.js';

export const SCAN_PROFILE_SCHEMA = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  $id: 'https://t3mp3st.dev/schemas/scan-profile.json',
  title: 'T3MP3ST ScanProfile',
  type: 'object',
  required: ['target', 'lanes'],
  additionalProperties: false,
  properties: {
    name: { type: 'string', minLength: 1, maxLength: 200 },
    target: {
      type: 'object',
      additionalProperties: false,
      properties: {
        urls: { type: 'array', items: { type: 'string', minLength: 1 }, maxItems: 500 },
        hosts: { type: 'array', items: { type: 'string', minLength: 1 }, maxItems: 500 },
      },
    },
    roe: {
      type: 'object',
      additionalProperties: false,
      properties: {
        scope: { type: 'array', items: { type: 'string' } },
        excludedTargets: { type: 'array', items: { type: 'string' } },
        allowedTechniques: { type: 'array', items: { type: 'string' } },
        forbiddenTechniques: { type: 'array', items: { type: 'string' } },
        maxDetectionEvents: { type: 'integer', minimum: 0 },
        requireManualApproval: { type: 'array', items: { type: 'string' } },
        timeWindow: {
          type: 'object',
          additionalProperties: false,
          properties: { start: { type: 'number' }, end: { type: 'number' } },
          required: ['start', 'end'],
        },
      },
    },
    authorizationDocPath: { type: 'string', maxLength: 500 },
    autonomous: { type: 'boolean' },
    approvalGates: {
      type: 'object',
      additionalProperties: false,
      properties: {
        recon: { enum: ['auto', 'manual'] },
        'vulnerability-analysis': { enum: ['auto', 'manual'] },
        exploitation: { enum: ['auto', 'manual'] },
        credential: { enum: ['auto', 'manual'] },
        privesc: { enum: ['auto', 'manual'] },
        lateral: { enum: ['auto', 'manual'] },
        reporting: { enum: ['auto', 'manual'] },
      },
    },
    docker: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        image: { type: 'string' },
        network: { type: 'string' },
      },
    },
    temporal: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        address: { type: 'string' },
        taskQueue: { type: 'string' },
      },
    },
    lanes: {
      type: 'object',
      additionalProperties: false,
      properties: Object.fromEntries(
        LANE_IDS.map((id) => [
          id,
          {
            type: 'object',
            required: ['enabled'],
            properties: { enabled: { type: 'boolean' } },
          },
        ]),
      ),
    },
  },
} as const;

let validator: ValidateFunction | null = null;
function getValidator(): ValidateFunction {
  if (!validator) {
    validator = new Ajv({ allErrors: true, strict: false }).compile(SCAN_PROFILE_SCHEMA);
  }
  return validator;
}

export interface ProfileValidationResult {
  ok: boolean;
  errors: string[];
  profile?: ScanProfile;
}

/** Validate untrusted input against the ScanProfile JSON Schema. Never throws. */
export function validateScanProfile(input: unknown): ProfileValidationResult {
  const validate = getValidator();
  const ok = validate(input);
  if (!ok) {
    const errors = (validate.errors ?? []).map(
      (e) => `${e.instancePath || '/'} ${e.message ?? 'invalid'}`,
    );
    return { ok: false, errors };
  }
  return { ok: true, errors: [], profile: input as ScanProfile };
}
