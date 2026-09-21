// Remote-IP geolocation for the "网络详情" connection detail table.
//
// The frontend now calls the third-party GEO API (https://api.090227.xyz)
// DIRECTLY from the browser as its PRIMARY path: that endpoint reflects the
// request Origin (CORS-readable) and the page CSP lists that one origin in
// `connect-src`. THIS module backs our own same-origin `GET /api/geo?ip=...`,
// which the frontend calls only as a FALLBACK when the direct call fails — the
// Worker then performs the upstream request from inside the isolate.
//
// The upstream endpoint (`https://api.090227.xyz/api/ipsb`) rejects requests
// that carry a default `curl` User-Agent with `403 Forbidden`, so every request
// MUST send a browser-like User-Agent. Its response shape is IP-dependent: a
// domestic (CN) address carries country/region/city/isp while a foreign address
// may only carry country_code/organization/asn. Every field is therefore
// optional and missing fields are reported as `undefined`, never fabricated.
//
// Caching: one GeoService lives at Worker-module scope, so its cache is per
// isolate (each Cloudflare isolate warms its own copy). That is intentional and
// bounded — the TTL + LRU caps below keep memory flat and a failed upstream can
// never spin the isolate.

import { classifyIp } from '../shared/ip-classify.ts';

// Re-exported so existing consumers (`src/worker.ts` and the test suite) keep
// importing `classifyIp` / `IpKind` from this module unchanged. The
// implementation now lives in `src/shared/ip-classify.ts` and is shared with the
// browser so the frontend can never be weaker than the Worker.
export { classifyIp };
export type { IpKind } from '../shared/ip-classify.ts';

/** Upstream geolocation endpoint. */
export const GEO_ENDPOINT = 'https://api.090227.xyz/api/ipsb';

/**
 * Browser User-Agent. Required: the upstream returns `403 Forbidden` to the
 * default fetch/curl UA, so this is not cosmetic.
 */
export const GEO_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const DEFAULT_MAX_ENTRIES = 4096;
const DEFAULT_FAILURE_BLACKLIST_MS = 5 * 60 * 1000; // 5min
const DEFAULT_FAILURE_BLACKLIST_THRESHOLD = 3;
const DEFAULT_MAX_RETRIES = 1;
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_FIELD_LENGTH = 128;

/** Why a lookup could not be resolved. */
export type GeoFailureReason = 'private' | 'invalid' | 'blocked' | 'error';

/**
 * Result of a GEO lookup. `resolved: true` carries whatever upstream fields were
 * present (others are `undefined`); `resolved: false` carries a reason.
 */
export interface GeoResult {
  resolved: boolean;
  reason?: GeoFailureReason;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  isp?: string;
  organization?: string;
  asn_organization?: string;
  asn?: number;
}

/** Injectable dependencies + tuning knobs (all optional; defaults are production values). */
export interface GeoServiceOptions {
  fetcher?: (url: string, init?: RequestInit) => Promise<Response>;
  ttlMs?: number;
  maxEntries?: number;
  failureBlacklistMs?: number;
  failureBlacklistThreshold?: number;
  maxRetries?: number;
  timeoutMs?: number;
}

interface CacheEntry {
  result: GeoResult;
  expiresAt: number;
}

function positiveInt(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : fallback;
}

function nonNegativeInt(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : fallback;
}

function boundedString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (trimmed === '' || trimmed.length > MAX_FIELD_LENGTH) return undefined;
  return trimmed;
}

function boundedAsn(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^\d{1,10}$/.test(value)) return Number(value);
  return undefined;
}

/**
 * Normalizes an upstream payload into a {@link GeoResult}. Returns null when the
 * payload carries no usable geo field, which the caller treats as a failure.
 */
export function normalizeGeoPayload(payload: unknown): GeoResult | null {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const raw = payload as Record<string, unknown>;
  const country = boundedString(raw.country);
  const countryCode = boundedString(raw.country_code);
  const region = boundedString(raw.region);
  const city = boundedString(raw.city);
  const isp = boundedString(raw.isp);
  const organization = boundedString(raw.organization);
  const asnOrganization = boundedString(raw.asn_organization);
  const asn = boundedAsn(raw.asn);
  const hasAny = country !== undefined || countryCode !== undefined || isp !== undefined
    || organization !== undefined || asnOrganization !== undefined || asn !== undefined
    || region !== undefined || city !== undefined;
  if (!hasAny) return null;
  return {
    resolved: true,
    country,
    country_code: countryCode,
    region,
    city,
    isp,
    organization,
    asn_organization: asnOrganization,
    asn,
  };
}

function createTimeoutSignal(ms: number): AbortSignal | undefined {
  if (ms <= 0) return undefined;
  const signalFactory = (globalThis as { AbortSignal?: { timeout?: (ms: number) => AbortSignal } }).AbortSignal;
  if (signalFactory && typeof signalFactory.timeout === 'function') return signalFactory.timeout(ms);
  return undefined;
}

/**
 * Resolves remote IPs to a coarse location with an in-memory TTL+LRU cache,
 * in-flight de-duplication, and a failure blacklist that opens after
 * `failureBlacklistThreshold` consecutive failures for `failureBlacklistMs`.
 */
export class GeoService {
  private readonly fetcher: (url: string, init?: RequestInit) => Promise<Response>;
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private readonly failureBlacklistMs: number;
  private readonly failureBlacklistThreshold: number;
  private readonly maxRetries: number;
  private readonly timeoutMs: number;

  /** Insertion-ordered map doubling as the LRU (oldest key evicted first). */
  private readonly cache = new Map<string, CacheEntry>();
  private readonly inflight = new Map<string, Promise<GeoResult>>();
  private readonly failures = new Map<string, number>();
  private readonly blacklist = new Map<string, number>();

  constructor(options: GeoServiceOptions = {}) {
    this.fetcher = options.fetcher ?? ((url, init) => fetch(url, init));
    this.ttlMs = positiveInt(options.ttlMs, DEFAULT_TTL_MS);
    this.maxEntries = positiveInt(options.maxEntries, DEFAULT_MAX_ENTRIES);
    this.failureBlacklistMs = positiveInt(options.failureBlacklistMs, DEFAULT_FAILURE_BLACKLIST_MS);
    this.failureBlacklistThreshold = positiveInt(options.failureBlacklistThreshold, DEFAULT_FAILURE_BLACKLIST_THRESHOLD);
    this.maxRetries = nonNegativeInt(options.maxRetries, DEFAULT_MAX_RETRIES);
    this.timeoutMs = nonNegativeInt(options.timeoutMs, DEFAULT_TIMEOUT_MS);
  }

  /** Number of cached (unexpired or not-yet-evicted) entries. Exposed for tests. */
  size(): number {
    return this.cache.size;
  }

  /**
   * Resolves a single IP. Private/reserved and malformed addresses never touch
   * the network; failures are retried then blacklisted.
   */
  async lookup(rawIp: string): Promise<GeoResult> {
    const ip = typeof rawIp === 'string' ? rawIp.trim() : '';
    const kind = classifyIp(ip);
    if (kind === 'invalid') return { resolved: false, reason: 'invalid' };
    if (kind === 'private') return { resolved: false, reason: 'private' };

    const now = Date.now();
    const blockedUntil = this.blacklist.get(ip);
    if (blockedUntil !== undefined) {
      if (blockedUntil > now) return { resolved: false, reason: 'blocked' };
      this.blacklist.delete(ip);
    }

    const cached = this.cache.get(ip);
    if (cached) {
      if (cached.expiresAt > now) {
        // Move to the most-recently-used end of the insertion order.
        this.cache.delete(ip);
        this.cache.set(ip, cached);
        return cached.result;
      }
      this.cache.delete(ip);
    }

    const pending = this.inflight.get(ip);
    if (pending) return pending;

    const task = this.resolveOverNetwork(ip);
    this.inflight.set(ip, task);
    try {
      return await task;
    } finally {
      if (this.inflight.get(ip) === task) this.inflight.delete(ip);
    }
  }

  private async resolveOverNetwork(ip: string): Promise<GeoResult> {
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        const result = await this.fetchOnce(ip);
        this.failures.delete(ip);
        this.store(ip, result);
        return result;
      } catch {
        // Retry until attempts are exhausted, then fall through to blacklisting.
      }
    }
    const failures = (this.failures.get(ip) ?? 0) + 1;
    if (failures >= this.failureBlacklistThreshold) {
      this.failures.delete(ip);
      this.blacklist.set(ip, Date.now() + this.failureBlacklistMs);
    } else {
      this.failures.set(ip, failures);
    }
    return { resolved: false, reason: 'error' };
  }

  private async fetchOnce(ip: string): Promise<GeoResult> {
    const url = `${GEO_ENDPOINT}?ip=${encodeURIComponent(ip)}`;
    const init: RequestInit = {
      headers: { 'User-Agent': GEO_USER_AGENT, Accept: 'application/json' },
    };
    const signal = createTimeoutSignal(this.timeoutMs);
    if (signal) init.signal = signal;
    const response = await this.fetcher(url, init);
    if (!response || response.status !== 200) {
      throw new Error(`Geo lookup failed with status ${response ? response.status : 'none'}`);
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw new Error('Geo lookup response was not valid JSON');
    }
    const normalized = normalizeGeoPayload(payload);
    if (!normalized) throw new Error('Geo lookup response is missing key fields');
    return normalized;
  }

  private store(ip: string, result: GeoResult): void {
    this.cache.delete(ip);
    this.cache.set(ip, { result, expiresAt: Date.now() + this.ttlMs });
    while (this.cache.size > this.maxEntries) {
      const oldest = this.cache.keys().next();
      if (oldest.done) break;
      this.cache.delete(oldest.value);
    }
  }
}
