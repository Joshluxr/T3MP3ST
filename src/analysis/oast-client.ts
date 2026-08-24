// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * OAST (out-of-band application security testing) client.
 *
 * Confirms blind injection classes (blind SQLi, SSRF, XXE, blind RCE/XSS)
 * by giving the OOB detector a collaborator domain to embed in payloads and
 * a way to poll for captured DNS/HTTP/SMTP interactions.
 *
 * T3MP3ST does not host the collaborator. The operator runs any
 * collaborator (interactsh-client, Burp Collaborator, a custom catcher) that
 * exposes captured interactions as JSON at a poll URL. This keeps the
 * engine free of collaborator crypto/transport while still closing the OOB
 * loop.
 *
 * SECURITY GATE: there is no default collaborator domain. The OOB sub-lane
 * stays disabled until the operator supplies one, so payloads never point at
 * a third-party domain by accident.
 */

import type { CollaboratorInteraction, OobChannel } from './oob-detector.js';

/** Minimal logger shape — anything with warn/error satisfies it. */
export interface OastLogger {
  warn(message: string): void;
}

export interface OastClient {
  /** The operator-controlled collaborator FQDN embedded in payloads. */
  readonly collaboratorDomain: string;
  /** Fetch interactions captured since the engagement started. */
  poll(): Promise<readonly CollaboratorInteraction[]>;
}

export interface OastConfig {
  readonly collaboratorDomain: string;
  /** URL returning captured interactions as JSON. */
  readonly pollUrl: string;
  /** Optional bearer token for the poll endpoint. */
  readonly pollToken?: string;
}

interface RawInteraction {
  readonly subdomain?: string;
  readonly host?: string;
  readonly 'full-id'?: string;
  readonly protocol?: string;
  readonly channel?: string;
  readonly 'remote-address'?: string;
  readonly remoteAddress?: string;
  readonly timestamp?: string | number;
}

/** Map a raw poll-endpoint record onto the typed CollaboratorInteraction. */
function normalizeInteraction(raw: RawInteraction, collaboratorDomain: string): CollaboratorInteraction | null {
  const rawHost = raw.subdomain ?? raw.host ?? raw['full-id'];
  if (!rawHost) return null;
  // Reduce a full host (oobXXXX.collab.example.com) to the leading label.
  const subdomain = rawHost.replace(`.${collaboratorDomain}`, '').split('.')[0];
  if (!subdomain) return null;

  const channelRaw = (raw.protocol ?? raw.channel ?? 'dns').toLowerCase();
  const channel: OobChannel = channelRaw === 'http' || channelRaw === 'smtp' ? channelRaw : 'dns';
  const remoteAddress = raw['remote-address'] ?? raw.remoteAddress ?? 'unknown';
  const capturedAt =
    typeof raw.timestamp === 'number' ? raw.timestamp : Date.parse(String(raw.timestamp ?? '')) || Date.now();

  return { subdomain, channel, remoteAddress, capturedAt };
}

/**
 * Polls a JSON HTTP endpoint for captured interactions. Tolerant of both a
 * bare array and a `{ interactions: [...] }` envelope.
 */
export class HttpPollingOastClient implements OastClient {
  readonly collaboratorDomain: string;
  private readonly pollUrl: string;
  private readonly pollToken: string | undefined;
  private readonly logger: OastLogger;

  constructor(config: OastConfig, logger: OastLogger) {
    this.collaboratorDomain = config.collaboratorDomain;
    this.pollUrl = config.pollUrl;
    this.pollToken = config.pollToken;
    this.logger = logger;
  }

  async poll(): Promise<readonly CollaboratorInteraction[]> {
    try {
      const response = await fetch(this.pollUrl, {
        headers: this.pollToken ? { authorization: `Bearer ${this.pollToken}` } : {},
      });
      if (!response.ok) {
        this.logger.warn(`[oast] poll endpoint returned ${response.status}`);
        return [];
      }
      const data = (await response.json()) as RawInteraction[] | { interactions?: RawInteraction[] };
      const raw = Array.isArray(data) ? data : (data.interactions ?? []);
      const out: CollaboratorInteraction[] = [];
      for (const item of raw) {
        const normalized = normalizeInteraction(item, this.collaboratorDomain);
        if (normalized) out.push(normalized);
      }
      return out;
    } catch (error) {
      this.logger.warn(`[oast] poll failed: ${(error as Error).message}`);
      return [];
    }
  }
}

/** Build an OAST client from config, or undefined when not configured. */
export function createOastClient(config: OastConfig | undefined, logger: OastLogger): OastClient | undefined {
  if (!config || !config.collaboratorDomain || !config.pollUrl) return undefined;
  return new HttpPollingOastClient(config, logger);
}
