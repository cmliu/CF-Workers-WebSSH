// Network detail panel — the "网络详情" workspace tab.
//
// Renders the per-PID aggregate table streamed by the backend network monitor
// (`NETWORK_MONITOR_COMMAND` in src/backend/session.ts, decoded by
// src/backend/network-parser.ts):
//   PID | 名称 | 监听IP | 端口 | IP数 | 连接数 | 上传 | 下载
//
// Selecting a row reveals that process's individual connections in a second
// table (IP | 端口 | 上传 | 下载 | 位置). The connection rows come from the
// monitor's CONNECTIONS block (one row per non-LISTEN TCP socket, port = the
// REMOTE port, bytes = that socket's own cumulative counters).
//
// Presentation is responsive: on wide viewports the detail table renders into
// the right-hand column; on narrow viewports (max-width: 768px, matching the
// project's mobile toolbar breakpoint) it renders into a <dialog>. The detail
// is rendered into BOTH targets at once so crossing the breakpoint is a pure
// show/hide, and no selection ever opens the dialog on a wide viewport.
//
// The 位置 column resolves the remote IP by calling the third-party GEO API
// (https://api.090227.xyz/api/ipsb) DIRECTLY from the browser. That endpoint
// reflects the request Origin (so it is CORS-readable from the page) and the
// page CSP explicitly allows this one origin in `connect-src`. The browser must
// NOT set a User-Agent — it is a forbidden header — and does not need to: the
// browser's own UA already passes the provider's filter (the opposite of the
// Worker path, which must send a browser-like UA explicitly). If the direct
// call fails (network error, non-2xx, non-JSON, or a payload with no usable geo
// field) we retry the SAME IP once against our own same-origin `GET /api/geo`
// (the Worker proxy, kept as a fallback); only when BOTH fail is the failure
// state shown. Lookups are de-duplicated, cached in a Map, capped per render
// (40 unique IPs) and rate-limited to a small concurrency so a process with
// hundreds of peers cannot stampede either the provider or the Worker.
//
// This class is intentionally isomorphic to ProcessManager: same connect /
// reset / reconnect / render lifecycle so the two auxiliary channels behave
// identically from the user's point of view.

// Literal-IP classification is shared verbatim with the Worker so the frontend
// decision "may this address be sent to the third-party provider?" is never
// weaker than the server's. Re-exported so the parity test can exercise the
// exact classifier the runtime uses.
import { classifyIp } from '../../src/shared/ip-classify.ts';

export { classifyIp };

export interface NetworkManagerElements {
  panel: HTMLElement;
  tableBody: HTMLTableSectionElement;
  status: HTMLElement;
  empty: HTMLElement;
  error: HTMLElement;
  updated: HTMLElement;
  host: HTMLElement;
  connectionsTitle: HTMLElement;
  connectionsBody: HTMLTableSectionElement;
  connectionsEmpty: HTMLElement;
  connectionsDialog: HTMLDialogElement;
  connectionsDialogTitle: HTMLElement;
  connectionsDialogBody: HTMLTableSectionElement;
  connectionsDialogEmpty: HTMLElement;
  toastRegion: HTMLElement;
}

export interface NetworkAggregateRow {
  pid: number;
  name: string;
  user: string;
  listen_ip: string;
  /** Listening transport (`tcp` / `udp` / `tcp/udp`); empty when unknown. */
  proto: string;
  listen_port: number;
  remote_ip_count: number;
  connection_count: number;
  bytes_sent: number;
  bytes_recv: number;
}

export interface NetworkConnectionRow {
  pid: number;
  proto: string;
  local_addr: string;
  local_port: number;
  remote_addr: string;
  remote_port: number;
  state: string;
  bytes_sent: number;
  bytes_recv: number;
}

export interface NetworkBytesTotals {
  txBytes: number;
  rxBytes: number;
}

interface NetworkSnapshot {
  type: 'network_snapshot';
  timestamp: number;
  host: string;
  aggregate: NetworkAggregateRow[];
  connections: NetworkConnectionRow[];
  bytesTotals: NetworkBytesTotals | null;
  errorMessage: string | null;
}

/** Decoded `GET /api/geo` payload. */
export interface GeoResult {
  resolved: boolean;
  reason?: string;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  isp?: string;
  organization?: string;
  asn_organization?: string;
  asn?: number;
}

interface GeoCacheEntry {
  status: 'pending' | 'ok' | 'error';
  result?: GeoResult;
}

type NetworkSortKey =
  | 'pid'
  | 'name'
  | 'listen_ip'
  | 'listen_port'
  | 'remote_ip_count'
  | 'connection_count'
  | 'bytes_sent'
  | 'bytes_recv';
type SortDirection = 'ascending' | 'descending';

interface NetworkManagerOptions {
  elements: NetworkManagerElements;
  getLanguage: () => 'zh-CN' | 'en';
  onError: (message: string) => void;
  onReconnect?: (zh: string, en: string) => void;
  onToast?: (zh: string, en: string, kind: 'info' | 'error') => void;
}

// Mirrors the backend aggregate cap so a hostile host cannot flood the panel.
const MAX_AGGREGATE_ROWS = 4096;
const MAX_CONNECTIONS_ROWS = 4096;
const MAX_TEXT_LENGTH = 512;
// GEO lookup budget: at most this many distinct remote IPs are queried per
// render, with at most GEO_CONCURRENCY requests in flight at any moment.
const MAX_GEO_LOOKUPS_PER_RENDER = 40;
const GEO_CONCURRENCY = 4;
// Upper bound on the in-memory GEO cache so a long session that sees thousands
// of distinct peers cannot grow the Map without bound. Insertion-ordered, so the
// oldest (least recently queried) entries are evicted first.
const MAX_GEO_CACHE_ENTRIES = 1024;
const NARROW_QUERY = '(max-width: 768px)';
// Auto-reconnect for the network monitor after an unexpected drop.
const RECONNECT_MAX_ATTEMPTS = 3;
const RECONNECT_DELAYS: readonly number[] = [1000, 2000, 4000];

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isBoundedString(value: unknown): value is string {
  return typeof value === 'string' && value.length <= MAX_TEXT_LENGTH;
}

function isAggregateRow(value: unknown): value is NetworkAggregateRow {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const row = value as Partial<NetworkAggregateRow>;
  return isNonNegativeInteger(row.pid) && row.pid > 0
    && isBoundedString(row.name)
    && isBoundedString(row.user)
    && isBoundedString(row.listen_ip)
    && isBoundedString(row.proto)
    && isNonNegativeInteger(row.listen_port)
    && isNonNegativeInteger(row.remote_ip_count)
    && isNonNegativeInteger(row.connection_count)
    && isNonNegativeInteger(row.bytes_sent)
    && isNonNegativeInteger(row.bytes_recv);
}

function isConnectionRow(value: unknown): value is NetworkConnectionRow {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const row = value as Partial<NetworkConnectionRow>;
  return isNonNegativeInteger(row.pid) && row.pid > 0
    && isBoundedString(row.proto)
    && isBoundedString(row.local_addr)
    && isNonNegativeInteger(row.local_port)
    && isBoundedString(row.remote_addr)
    && isNonNegativeInteger(row.remote_port)
    && isBoundedString(row.state)
    && isNonNegativeInteger(row.bytes_sent)
    && isNonNegativeInteger(row.bytes_recv);
}

function isBytesTotals(value: unknown): value is NetworkBytesTotals {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const totals = value as Partial<NetworkBytesTotals>;
  return isNonNegativeInteger(totals.txBytes) && isNonNegativeInteger(totals.rxBytes);
}

function isSnapshot(value: unknown): value is NetworkSnapshot {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const snapshot = value as Partial<NetworkSnapshot>;
  return snapshot.type === 'network_snapshot'
    && typeof snapshot.timestamp === 'number' && Number.isFinite(snapshot.timestamp)
    && Array.isArray(snapshot.aggregate) && snapshot.aggregate.length <= MAX_AGGREGATE_ROWS
    && snapshot.aggregate.every(isAggregateRow)
    && Array.isArray(snapshot.connections) && snapshot.connections.length <= MAX_CONNECTIONS_ROWS
    && snapshot.connections.every(isConnectionRow)
    && (snapshot.bytesTotals === null || isBytesTotals(snapshot.bytesTotals))
    && (snapshot.errorMessage === null || typeof snapshot.errorMessage === 'string');
}

function formatBytes(bytes: number): string {
  const units = ['B', 'K', 'M', 'G', 'T', 'P'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  const precision = value >= 100 || unit === 0 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(precision)}${units[unit]}`;
}

// Display-only normalization of the listening IP to the shapes FinalShell
// shows: a wildcard listener (`*`) renders as `0.0.0.0` and the IPv6 any-address
// `[::]` renders as `::`. The wire format is intentionally left untouched so the
// shell/parser contract (which the tests assert) keeps emitting `*`.
function normalizeListenIp(value: string): string {
  if (value === '*') return '0.0.0.0';
  if (value === '[::]') return '::';
  return value || '--';
}

/**
 * Renders the listening transport as an uppercase label. The collector emits
 * `tcp` / `udp` / `tcp/udp` (or an empty field when the transport is unknown,
 * which the front-end shows as `--`).
 */
function formatProto(value: string): string {
  const label = value.trim().toUpperCase();
  return label === '' ? '--' : label;
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

function firstNonEmpty(values: ReadonlyArray<unknown>): string | undefined {
  for (const value of values) {
    const text = nonEmptyString(value);
    if (text !== undefined) return text;
  }
  return undefined;
}

function parseGeoResult(value: unknown): GeoResult | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  if (raw.resolved !== true) return { resolved: false, reason: nonEmptyString(raw.reason) };
  return {
    resolved: true,
    country: nonEmptyString(raw.country),
    country_code: nonEmptyString(raw.country_code),
    region: nonEmptyString(raw.region),
    city: nonEmptyString(raw.city),
    isp: nonEmptyString(raw.isp),
    organization: nonEmptyString(raw.organization),
    asn_organization: nonEmptyString(raw.asn_organization),
    asn: typeof raw.asn === 'number' && Number.isInteger(raw.asn) ? raw.asn : undefined,
  };
}

/** Upstream geolocation endpoint, called directly from the browser. */
export const GEO_DIRECT_ENDPOINT = 'https://api.090227.xyz/api/ipsb';
/** Same-origin Worker proxy, used only as a fallback. */
export const GEO_SAME_ORIGIN_ENDPOINT = '/api/geo';

// Field bounds mirror `src/backend/geo-service.ts` so the direct (raw) and the
// same-origin (normalized) shapes normalize identically.
const GEO_FIELD_MAX_LENGTH = 128;

function boundedGeoField(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (trimmed === '' || trimmed.length > GEO_FIELD_MAX_LENGTH) return undefined;
  return trimmed;
}

function boundedGeoAsn(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^\d{1,10}$/.test(value)) return Number(value);
  return undefined;
}

/**
 * Normalizes one RAW provider payload (the shape `https://api.090227.xyz/api/ipsb`
 * returns — IP-dependent, every field optional) into a {@link GeoResult}. Rule
 * set is equivalent to the backend's `normalizeGeoPayload`: missing/blank fields
 * become `undefined`, never fabricated, and a payload with no usable field
 * returns null.
 */
export function normalizeRawGeoPayload(payload: unknown): GeoResult | null {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const raw = payload as Record<string, unknown>;
  const country = boundedGeoField(raw.country);
  const countryCode = boundedGeoField(raw.country_code);
  const region = boundedGeoField(raw.region);
  const city = boundedGeoField(raw.city);
  const isp = boundedGeoField(raw.isp);
  const organization = boundedGeoField(raw.organization);
  const asnOrganization = boundedGeoField(raw.asn_organization);
  const asn = boundedGeoAsn(raw.asn);
  const hasAny = country !== undefined || countryCode !== undefined
    || region !== undefined || city !== undefined || isp !== undefined
    || organization !== undefined || asnOrganization !== undefined || asn !== undefined;
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

/**
 * Accepts EITHER response shape and returns a {@link GeoResult}:
 *  - the same-origin `/api/geo` shape is already normalized and carries the
 *    `resolved` discriminator → parsed as-is;
 *  - the third-party API returns raw provider fields (no `resolved`) → run
 *    through {@link normalizeRawGeoPayload}.
 * Returns null when nothing usable can be parsed.
 */
export function normalizeGeoResponse(value: unknown): GeoResult | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  if ('resolved' in raw) return parseGeoResult(value);
  return normalizeRawGeoPayload(value);
}

/** Injectable fetchers so the resolution flow can be exercised without the DOM. */
export interface GeoFetchers {
  /** Fetches the third-party API directly from the browser (cross-origin). */
  fetchDirect: (url: string) => Promise<Response>;
  /** Fetches our same-origin `/api/geo` fallback. */
  fetchSameOrigin: (url: string) => Promise<Response>;
}

/** Builds the direct provider URL. IPv6 literals MUST be percent-encoded. */
export function buildGeoDirectUrl(ip: string): string {
  return `${GEO_DIRECT_ENDPOINT}?ip=${encodeURIComponent(ip)}`;
}

/** Builds the same-origin fallback URL. */
export function buildGeoSameOriginUrl(ip: string): string {
  return `${GEO_SAME_ORIGIN_ENDPOINT}?ip=${encodeURIComponent(ip)}`;
}

/** Reads a Response body as JSON, tolerating a non-JSON body (returns undefined). */
async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

/**
 * Resolves one remote IP. Private/reserved and malformed addresses are answered
 * locally — NEITHER the direct provider NOR the same-origin fallback is
 * contacted. Otherwise the direct provider call is attempted first; on any
 * failure (reject / non-2xx / non-JSON / no usable field) the SAME IP is retried
 * once against the same-origin `/api/geo`. Returns null only when both paths
 * fail, which the caller renders as the retryable failure state.
 */
export async function resolveGeoForIp(ip: string, fetchers: GeoFetchers): Promise<GeoResult | null> {
  const kind = classifyIp(ip);
  if (kind === 'private') return { resolved: false, reason: 'private' };
  if (kind === 'invalid') return { resolved: false, reason: 'invalid' };

  // Attempt 1 — the third-party API, called straight from the browser. No
  // custom headers: a browser cannot set User-Agent anyway, and omitting every
  // header keeps this a CORS "simple" GET (no preflight).
  try {
    const response = await fetchers.fetchDirect(buildGeoDirectUrl(ip));
    if (response.ok) {
      const direct = normalizeGeoResponse(await readJson(response));
      if (direct && direct.resolved === true) return direct;
    }
  } catch {
    // Network error / CORS rejection / parse failure — fall through to the fallback.
  }

  // Attempt 2 — our own same-origin `/api/geo`, at most once per IP. This path
  // never loops back into the direct call.
  try {
    const response = await fetchers.fetchSameOrigin(buildGeoSameOriginUrl(ip));
    if (!response.ok) return null;
    return parseGeoResult(await readJson(response));
  } catch {
    return null;
  }
}

/**
 * Builds the visible location string: `country_code region city` joined by
 * spaces (missing parts skipped), combined with the best organization string
 * via ` · `. When the provider supplies no `country_code` we fall back to the
 * full `country` name; `--` is returned when nothing usable is present.
 */
export function buildLocationLabel(geo: GeoResult): string {
  const country = firstNonEmpty([geo.country_code, geo.country]);
  const geoText = [country, geo.region, geo.city]
    .map((part) => nonEmptyString(part))
    .filter((part): part is string => part !== undefined)
    .join(' ');
  const org = firstNonEmpty([geo.isp, geo.organization, geo.asn_organization]);
  const parts = [geoText, org].filter((part): part is string => part !== undefined && part !== '');
  return parts.length > 0 ? parts.join(' · ') : '--';
}

/**
 * Raw provider fields for the cell tooltip, de-duplicated and joined by ` / `:
 * `country_code / country / AS<asn> / asn_organization / isp / organization`.
 */
export function buildLocationTooltip(geo: GeoResult): string {
  const parts: string[] = [];
  const push = (value: string | undefined): void => {
    if (value !== undefined && !parts.includes(value)) parts.push(value);
  };
  push(nonEmptyString(geo.country_code));
  push(nonEmptyString(geo.country));
  if (geo.asn !== undefined) push(`AS${geo.asn}`);
  push(nonEmptyString(geo.asn_organization));
  push(nonEmptyString(geo.isp));
  push(nonEmptyString(geo.organization));
  return parts.join(' / ');
}

export class NetworkManager {
  private readonly elements: NetworkManagerElements;
  private readonly getLanguage: () => 'zh-CN' | 'en';
  private readonly onError: (message: string) => void;
  private readonly onReconnect: ((zh: string, en: string) => void) | undefined;
  private readonly onToast: ((zh: string, en: string, kind: 'info' | 'error') => void) | undefined;
  private readonly narrowQuery: MediaQueryList;
  private socket: WebSocket | null = null;
  private generation = 0;
  private snapshot: NetworkSnapshot | null = null;
  private sortKey: NetworkSortKey = 'connection_count';
  private sortDirection: SortDirection = 'descending';
  private selectedPid: number | null = null;
  /** remote IP -> resolved location (or pending/error marker). Never re-queried. */
  private readonly geoCache = new Map<string, GeoCacheEntry>();
  private readonly geoQueue: string[] = [];
  private geoActive = 0;
  private wantConnection = false;
  private url: string | null = null;
  private reconnectTimer: number | null = null;
  private reconnectAttempts = 0;

  constructor(options: NetworkManagerOptions) {
    this.elements = options.elements;
    this.getLanguage = options.getLanguage;
    this.onError = options.onError;
    this.onReconnect = options.onReconnect;
    this.onToast = options.onToast;
    this.narrowQuery = window.matchMedia(NARROW_QUERY);
    this.narrowQuery.addEventListener('change', () => this.syncPresentation());
    this.elements.panel.addEventListener('click', (event) => {
      const target = event.target as HTMLElement;
      const sortButton = target.closest<HTMLButtonElement>('[data-network-sort]');
      if (sortButton) {
        this.changeSort(sortButton.dataset.networkSort as NetworkSortKey);
        return;
      }
      const copyCell = target.closest<HTMLTableCellElement>('[data-network-copy-value]');
      if (copyCell && this.elements.tableBody.contains(copyCell)) {
        const value = copyCell.dataset.networkCopyValue ?? '';
        if (!value) return;
        void this.copyValue(value, copyCell.dataset.networkCopyKind as 'pid' | 'name' | undefined);
        return;
      }
      const row = target.closest<HTMLTableRowElement>('tr[data-network-pid]');
      if (row && this.elements.tableBody.contains(row)) {
        this.selectRow(Number(row.dataset.networkPid));
      }
    });
    // Copyable PID / name cells are keyboard-focusable (tabIndex=0); mirror the
    // click-to-copy behaviour for Enter/Space so the interaction is operable
    // without a mouse. Rows themselves are focusable and select on Enter/Space.
    this.elements.panel.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter' && event.key !== ' ' && event.key !== 'Spacebar') return;
      if (event.ctrlKey || event.metaKey || event.altKey) return;
      const target = event.target as HTMLElement;
      const copyCell = target.closest<HTMLTableCellElement>('[data-network-copy-value]');
      if (copyCell && this.elements.tableBody.contains(copyCell)) {
        const value = copyCell.dataset.networkCopyValue ?? '';
        if (!value) return;
        event.preventDefault();
        void this.copyValue(value, copyCell.dataset.networkCopyKind as 'pid' | 'name' | undefined);
        return;
      }
      const row = target.closest<HTMLTableRowElement>('tr[data-network-pid]');
      if (row && this.elements.tableBody.contains(row)) {
        event.preventDefault();
        this.selectRow(Number(row.dataset.networkPid));
      }
    });
    this.render();
  }

  attach(url: string): void {
    this.wantConnection = true;
    this.url = url;
    this.reconnectAttempts = 0;
    this.resetSocket();
    const target = new URL(url, window.location.href);
    if (target.origin !== window.location.origin || target.pathname !== '/api/network') {
      throw new Error('Network WebSocket must use the current origin');
    }
    target.protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const generation = ++this.generation;
    const socket = new WebSocket(target);
    this.socket = socket;
    this.setStatus('正在启动网络监控…', 'Starting network monitor…');
    socket.addEventListener('open', () => {
      if (!this.isCurrent(socket, generation)) return;
      if (this.reconnectAttempts > 0) {
        console.log(
          `[WS-Reconnect] ${new Date().toISOString()} | Network | reconnect_success | attempt=${this.reconnectAttempts}/${RECONNECT_MAX_ATTEMPTS}`,
        );
      }
      this.reconnectAttempts = 0;
      socket.send(JSON.stringify({ type: 'network_start' }));
    });
    socket.addEventListener('message', (event) => {
      if (!this.isCurrent(socket, generation) || typeof event.data !== 'string') return;
      this.handleMessage(event.data);
    });
    socket.addEventListener('error', () => {
      if (!this.isCurrent(socket, generation)) return;
      this.showError('网络监控连接错误。', 'Network monitor connection error.');
    });
    socket.addEventListener('close', (event) => {
      if (!this.isCurrent(socket, generation)) return;
      console.log(
        `[WS-Reconnect] ${new Date().toISOString()} | Network | disconnect | code=${event.code} | reason="${event.reason}"`,
      );
      this.socket = null;
      if (event.code !== 1000 && event.code !== 1005) {
        // Unexpected drop. Auto-reconnect unless the user intentionally tore
        // the session down.
        if (this.wantConnection) {
          this.scheduleReconnect();
        } else {
          this.showError('网络监控已意外停止。', 'Network monitor stopped unexpectedly.');
        }
      }
    });
  }

  reset(): void {
    this.wantConnection = false;
    this.clearReconnectTimer();
    this.resetSocket();
    this.snapshot = null;
    this.selectedPid = null;
    this.render();
  }

  setLanguage(): void {
    this.updateSortHeaders();
    this.render();
  }

  private changeSort(key: NetworkSortKey): void {
    if (this.sortKey === key) {
      this.sortDirection = this.sortDirection === 'ascending' ? 'descending' : 'ascending';
    } else {
      this.sortKey = key;
      this.sortDirection = key === 'name' || key === 'listen_ip' ? 'ascending' : 'descending';
    }
    this.updateSortHeaders();
    this.render();
  }

  private updateSortHeaders(): void {
    for (const button of this.elements.panel.querySelectorAll<HTMLButtonElement>('[data-network-sort]')) {
      const key = button.dataset.networkSort as NetworkSortKey;
      const header = button.closest<HTMLTableCellElement>('th');
      const active = key === this.sortKey;
      header?.setAttribute('aria-sort', active ? this.sortDirection : 'none');
      const label = button.dataset[this.getLanguage() === 'zh-CN' ? 'i18nZh' : 'i18nEn'] ?? button.textContent ?? '';
      button.setAttribute('aria-label', active
        ? this.getLanguage() === 'zh-CN'
          ? `${label}，当前${this.sortDirection === 'ascending' ? '升序' : '降序'}，点击切换排序`
          : `${label}, currently ${this.sortDirection}; activate to reverse`
        : this.getLanguage() === 'zh-CN'
          ? `按 ${label} 排序`
          : `Sort by ${label}`);
    }
  }

  private sortedRows(rows: NetworkAggregateRow[]): NetworkAggregateRow[] {
    const key = this.sortKey;
    const direction = this.sortDirection === 'ascending' ? 1 : -1;
    return rows.map((row, index) => ({ row, index })).sort((left, right) => {
      const a = left.row[key];
      const b = right.row[key];
      const compared = typeof a === 'number' && typeof b === 'number'
        ? a - b
        : String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
      return compared === 0 ? left.index - right.index : compared * direction;
    }).map(({ row }) => row);
  }

  private handleMessage(serialized: string): void {
    let message: unknown;
    try { message = JSON.parse(serialized); } catch { return; }
    if (isSnapshot(message)) {
      this.snapshot = message;
      this.render();
      return;
    }
    if (!message || typeof message !== 'object' || Array.isArray(message)) return;
    const value = message as Record<string, unknown>;
    if (value.type === 'network_ready') {
      this.setStatus('正在等待首个网络快照…', 'Waiting for the first network snapshot…');
    } else if (value.type === 'network_error' && typeof value.message === 'string') {
      this.showError(value.message, value.message);
    }
  }

  private render(): void {
    const snapshot = this.snapshot;
    if (!snapshot) {
      this.elements.tableBody.replaceChildren();
      this.elements.empty.hidden = true;
      this.elements.error.hidden = true;
      this.elements.updated.textContent = '--';
      this.elements.host.textContent = '--';
      this.setStatus('连接 SSH 后即可查看实时网络连接', 'Connect to SSH to view live network connections');
      this.selectedPid = null;
      this.renderDetail();
      return;
    }

    const fragment = document.createDocumentFragment();
    for (const row of this.sortedRows(snapshot.aggregate)) {
      const tr = document.createElement('tr');
      tr.tabIndex = 0;
      tr.dataset.networkPid = String(row.pid);
      tr.setAttribute('aria-selected', this.selectedPid === row.pid ? 'true' : 'false');
      const values = [
        String(row.pid),
        row.name || '--',
        normalizeListenIp(row.listen_ip),
        formatProto(row.proto),
        row.listen_port > 0 ? String(row.listen_port) : '--',
        String(row.remote_ip_count),
        String(row.connection_count),
        formatBytes(row.bytes_sent),
        formatBytes(row.bytes_recv),
      ];
      values.forEach((value, index) => {
        const cell = document.createElement('td');
        cell.textContent = value;
        const isCopyable = index === 0 || index === 1;
        if (isCopyable) {
          cell.className = 'network-copyable';
          cell.tabIndex = 0;
          cell.dataset.networkCopyValue = index === 0 ? String(row.pid) : (row.name || '');
          cell.dataset.networkCopyKind = index === 0 ? 'pid' : 'name';
          cell.title = `${value} — 点击复制 / Click to copy`;
          cell.setAttribute('aria-label', `${value} — 点击复制 / Click to copy`);
        } else if (index === 2 || index === 8) {
          cell.title = value;
        }
        tr.append(cell);
      });
      fragment.append(tr);
    }
    this.elements.tableBody.replaceChildren(fragment);
    this.elements.empty.hidden = snapshot.aggregate.length !== 0;
    this.elements.error.hidden = true;
    const updated = new Date(snapshot.timestamp).toLocaleTimeString([], { hour12: false });
    this.elements.updated.textContent = updated;
    this.elements.host.textContent = snapshot.host || '--';
    const totals = snapshot.bytesTotals;
    const traffic = totals
      ? ` · 网卡 ↑${formatBytes(totals.txBytes)} ↓${formatBytes(totals.rxBytes)}`
      : '';
    this.setStatus(
      `共 ${snapshot.aggregate.length} 个进程 · 更新于 ${updated}${traffic}`,
      `${snapshot.aggregate.length} processes · Updated ${updated}${traffic}`,
    );
    this.renderDetail();
  }

  private translate(zh: string, en: string): string {
    return this.getLanguage() === 'zh-CN' ? zh : en;
  }

  private applySelection(): void {
    for (const row of this.elements.tableBody.querySelectorAll<HTMLTableRowElement>('tr[data-network-pid]')) {
      row.setAttribute('aria-selected', Number(row.dataset.networkPid) === this.selectedPid ? 'true' : 'false');
    }
  }

  private selectRow(pid: number): void {
    if (!Number.isSafeInteger(pid) || pid <= 0) return;
    if (!this.snapshot?.aggregate.some((row) => row.pid === pid)) return;
    this.selectedPid = pid;
    this.applySelection();
    this.renderDetail();
    if (this.isNarrow()) this.openDetailDialog();
  }

  private isNarrow(): boolean {
    return this.narrowQuery.matches;
  }

  private syncPresentation(): void {
    if (this.isNarrow()) {
      if (this.selectedPid !== null) this.openDetailDialog();
    } else {
      this.closeDetailDialog();
    }
  }

  private openDetailDialog(): void {
    if (this.selectedPid === null) return;
    const dialog = this.elements.connectionsDialog;
    if (typeof dialog.showModal !== 'function') return;
    if (!dialog.open) dialog.showModal();
  }

  private closeDetailDialog(): void {
    const dialog = this.elements.connectionsDialog;
    if (dialog.open) dialog.close();
  }

  private setDetailTitle(process: NetworkAggregateRow | null): void {
    const title = this.elements.connectionsTitle;
    const dialogTitle = this.elements.connectionsDialogTitle;
    if (!process) {
      const fallback = this.translate('连接明细', 'Connections');
      title.textContent = fallback;
      dialogTitle.textContent = fallback;
      return;
    }
    const label = `${process.pid} ${process.name || '--'}`;
    const text = this.translate(`${label} 的连接`, `Connections of ${label}`);
    title.textContent = text;
    dialogTitle.textContent = text;
  }

  private setEmptyText(element: HTMLElement, text: string): void {
    element.textContent = text;
  }

  /** Re-renders the selected process's connection list into both targets. */
  private renderDetail(): void {
    const paneEmpty = this.elements.connectionsEmpty;
    const dialogEmpty = this.elements.connectionsDialogEmpty;
    const snapshot = this.snapshot;
    const pid = this.selectedPid;
    const process = pid !== null && snapshot ? snapshot.aggregate.find((row) => row.pid === pid) : undefined;

    if (pid === null || !snapshot || process === undefined) {
      // No selection, or the selected process disappeared: reset to the prompt.
      this.selectedPid = null;
      this.applySelection();
      this.elements.connectionsBody.replaceChildren();
      this.elements.connectionsDialogBody.replaceChildren();
      this.setDetailTitle(null);
      const prompt = this.translate('选择左侧进程查看详细连接', 'Select a process on the left to view its connections');
      this.setEmptyText(paneEmpty, prompt);
      this.setEmptyText(dialogEmpty, prompt);
      paneEmpty.hidden = false;
      dialogEmpty.hidden = false;
      this.closeDetailDialog();
      return;
    }

    const connections = snapshot.connections.filter((row) => row.pid === pid && row.remote_addr.trim() !== '');
    this.setDetailTitle(process);

    // Resolve the per-render lookup budget once, then build both tables.
    const seen = new Set<string>();
    const allowed = new Set<string>();
    for (const connection of connections) {
      const ip = connection.remote_addr;
      if (seen.has(ip)) continue;
      seen.add(ip);
      if (seen.size <= MAX_GEO_LOOKUPS_PER_RENDER || this.geoCache.has(ip)) allowed.add(ip);
    }
    for (const ip of allowed) {
      if (classifyIp(ip) === 'public') this.enqueueGeo(ip);
    }

    this.elements.connectionsBody.replaceChildren(this.buildConnectionFragment(connections, allowed));
    this.elements.connectionsDialogBody.replaceChildren(this.buildConnectionFragment(connections, allowed));

    const isEmpty = connections.length === 0;
    paneEmpty.hidden = !isEmpty;
    dialogEmpty.hidden = !isEmpty;
    if (isEmpty) {
      const message = this.translate('该进程当前没有已建立的连接', 'This process has no established connections');
      this.setEmptyText(paneEmpty, message);
      this.setEmptyText(dialogEmpty, message);
    }
  }

  private buildConnectionFragment(connections: NetworkConnectionRow[], allowed: ReadonlySet<string>): DocumentFragment {
    const fragment = document.createDocumentFragment();
    for (const connection of connections) {
      const tr = document.createElement('tr');
      const locationCell = document.createElement('td');
      if (allowed.has(connection.remote_addr)) {
        this.renderLocationCell(locationCell, connection.remote_addr);
      } else {
        locationCell.textContent = '--';
        locationCell.title = this.translate('超出本次解析上限', 'Exceeds this lookup limit');
      }
      const ipCell = document.createElement('td');
      ipCell.textContent = connection.remote_addr;
      ipCell.title = connection.remote_addr;
      const portCell = document.createElement('td');
      portCell.textContent = connection.remote_port > 0 ? String(connection.remote_port) : '--';
      const uploadCell = document.createElement('td');
      uploadCell.textContent = formatBytes(connection.bytes_sent);
      uploadCell.title = String(connection.bytes_sent);
      const downloadCell = document.createElement('td');
      downloadCell.textContent = formatBytes(connection.bytes_recv);
      downloadCell.title = String(connection.bytes_recv);
      tr.append(ipCell, portCell, uploadCell, downloadCell, locationCell);
      fragment.append(tr);
    }
    return fragment;
  }

  private renderLocationCell(cell: HTMLTableCellElement, ip: string): void {
    const kind = classifyIp(ip);
    if (kind === 'private') {
      cell.textContent = this.translate('内网', 'Private');
      cell.classList.add('network-location-private');
      cell.title = ip;
      return;
    }
    if (kind === 'invalid') {
      cell.textContent = '--';
      return;
    }
    const entry = this.geoCache.get(ip);
    if (!entry || entry.status === 'pending') {
      cell.textContent = this.translate('解析中…', 'Resolving…');
      cell.classList.add('network-location-pending');
      return;
    }
    if (entry.status === 'error' || !entry.result) {
      cell.classList.add('network-location-error');
      const label = document.createElement('span');
      label.textContent = this.translate('解析失败', 'Failed');
      const retry = document.createElement('button');
      retry.type = 'button';
      retry.className = 'network-location-retry';
      retry.textContent = this.translate('重试', 'Retry');
      retry.setAttribute('aria-label', this.translate(`重试解析 ${ip}`, `Retry resolving ${ip}`));
      retry.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        this.retryGeo(ip);
      });
      cell.append(label, retry);
      return;
    }
    if (entry.result.resolved !== true) {
      // The backend classified this address as private/reserved even though the
      // client-side heuristic did not: show the same label instead of retrying.
      cell.textContent = entry.result.reason === 'private' ? this.translate('内网', 'Private') : '--';
      cell.classList.add('network-location-private');
      cell.title = ip;
      return;
    }
    cell.textContent = buildLocationLabel(entry.result);
    cell.title = buildLocationTooltip(entry.result);
  }

  private retryGeo(ip: string): void {
    this.geoCache.delete(ip);
    this.enqueueGeo(ip);
    this.renderDetail();
  }

  private enqueueGeo(ip: string): void {
    if (this.geoCache.has(ip)) return;
    this.setGeoCacheEntry(ip, { status: 'pending' });
    this.geoQueue.push(ip);
    this.pumpGeoQueue();
  }

  /** Stores a GEO entry, evicting the oldest once the cache exceeds its cap. */
  private setGeoCacheEntry(ip: string, entry: GeoCacheEntry): void {
    this.geoCache.delete(ip);
    this.geoCache.set(ip, entry);
    while (this.geoCache.size > MAX_GEO_CACHE_ENTRIES) {
      const oldest = this.geoCache.keys().next();
      if (oldest.done) break;
      this.geoCache.delete(oldest.value);
    }
  }

  private pumpGeoQueue(): void {
    while (this.geoActive < GEO_CONCURRENCY && this.geoQueue.length > 0) {
      const ip = this.geoQueue.shift()!;
      this.geoActive++;
      void this.fetchGeo(ip).finally(() => {
        this.geoActive--;
        this.pumpGeoQueue();
      });
    }
  }

  private async fetchGeo(ip: string): Promise<void> {
    // Direct provider call first, same-origin `/api/geo` as the single fallback.
    // `resolveGeoForIp` never throws and never sends more than one request per
    // path, so no retry loop can form here.
    const result = await resolveGeoForIp(ip, {
      fetchDirect: (url) => fetch(url),
      fetchSameOrigin: (url) => fetch(url, { headers: { Accept: 'application/json' } }),
    });
    if (result && (result.resolved === true || result.reason === 'private' || result.reason === 'invalid')) {
      // A definitive answer (resolved, or a terminal private/invalid verdict)
      // is cached; only retryable failures fall through to the error state.
      this.setGeoCacheEntry(ip, { status: 'ok', result });
    } else {
      this.setGeoCacheEntry(ip, { status: 'error' });
    }
    this.renderDetail();
  }

  private copyValue(value: string, kind: 'pid' | 'name' | undefined): void {
    const isPid = kind === 'pid' || /^\d+$/.test(value);
    void navigator.clipboard.writeText(value).then(
      () => {
        const truncated = value.length > 64 ? `${value.slice(0, 64)}…` : value;
        const display = isPid ? `已复制 PID ${value}` : `已复制进程名：${truncated}`;
        const displayEn = isPid ? `Copied PID ${value}` : `Copied process name: ${truncated}`;
        this.bilingualToast(display, displayEn, 'info');
      },
      () => this.bilingualToast('无法访问剪贴板。', 'Could not access the clipboard.', 'error'),
    );
  }

  private bilingualToast(zh: string, en: string, kind: 'info' | 'error' = 'info'): void {
    if (this.onToast) {
      this.onToast(zh, en, kind);
      return;
    }
    const region = this.elements.toastRegion;
    if (!region) return;
    const item = document.createElement('div');
    item.className = `toast${kind === 'error' ? ' error' : ''}`;
    item.textContent = this.getLanguage() === 'zh-CN' ? zh : en;
    region.append(item);
    window.setTimeout(() => item.remove(), 4_500);
  }

  private setStatus(zh: string, en: string): void {
    this.elements.status.textContent = this.getLanguage() === 'zh-CN' ? zh : en;
  }

  private showError(zh: string, en: string): void {
    const message = this.getLanguage() === 'zh-CN' ? zh : en;
    this.elements.error.textContent = message;
    this.elements.error.hidden = false;
    this.elements.empty.hidden = true;
    this.setStatus(zh, en);
    this.onError(message);
  }

  private resetSocket(): void {
    const socket = this.socket;
    this.socket = null;
    this.generation++;
    if (!socket) return;
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'network_stop' }));
    if (socket.readyState < WebSocket.CLOSING) socket.close(1000, 'Network monitor reset');
  }

  private scheduleReconnect(): void {
    if (!this.wantConnection || !this.url || this.reconnectTimer !== null) return;
    this.reconnectAttempts++;
    if (this.reconnectAttempts > RECONNECT_MAX_ATTEMPTS) {
      console.log(
        `[WS-Reconnect] ${new Date().toISOString()} | Network | give_up | attempt=${this.reconnectAttempts - 1}/${RECONNECT_MAX_ATTEMPTS}`,
      );
      this.reconnectAttempts = 0;
      this.showError('网络监控已意外停止。', 'Network monitor stopped unexpectedly.');
      return;
    }
    const delayIndex = this.reconnectAttempts - 1;
    const delay = delayIndex < RECONNECT_DELAYS.length
      ? RECONNECT_DELAYS[delayIndex]
      : RECONNECT_DELAYS[RECONNECT_DELAYS.length - 1];
    console.log(
      `[WS-Reconnect] ${new Date().toISOString()} | Network | reconnect_attempt | attempt=${this.reconnectAttempts}/${RECONNECT_MAX_ATTEMPTS}`,
    );
    if (this.reconnectAttempts === 1 && this.onReconnect) {
      this.onReconnect('网络监控已意外停止，正在尝试自动重连…', 'Network monitor stopped unexpectedly; attempting to reconnect automatically…');
    }
    this.setStatus('网络监控连接已断开，正在重连…', 'Network monitor disconnected; reconnecting…');
    const attempts = this.reconnectAttempts;
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      if (!this.wantConnection || !this.url) return;
      try {
        this.attach(this.url);
      } catch {
        console.log(
          `[WS-Reconnect] ${new Date().toISOString()} | Network | reconnect_failed | attempt=${attempts}/${RECONNECT_MAX_ATTEMPTS}`,
        );
        // attach() zeroed the counter; restore so the retry chain continues
        // where it left off instead of restarting from attempt 1.
        if (this.wantConnection) {
          this.reconnectAttempts = attempts;
        }
        this.scheduleReconnect();
        return;
      }
      // Successful attach() zeros reconnectAttempts; restore so the open
      // handler can log reconnect_success and the back-off chain continues if
      // close fires before open confirms.
      if (this.wantConnection) {
        this.reconnectAttempts = attempts;
      }
    }, delay);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private isCurrent(socket: WebSocket, generation: number): boolean {
    return this.socket === socket && this.generation === generation;
  }
}

function getElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing network manager element #${id}`);
  return element as T;
}

export function collectNetworkManagerElements(): NetworkManagerElements {
  return {
    panel: getElement('network-detail-panel'),
    tableBody: getElement<HTMLTableSectionElement>('network-table-body'),
    status: getElement('network-manager-status'),
    empty: getElement('network-manager-empty'),
    error: getElement('network-manager-error'),
    updated: getElement('network-updated'),
    host: getElement('network-host'),
    connectionsTitle: getElement('network-connections-title'),
    connectionsBody: getElement<HTMLTableSectionElement>('network-connections-body'),
    connectionsEmpty: getElement('network-connections-empty'),
    connectionsDialog: getElement<HTMLDialogElement>('network-connections-dialog'),
    connectionsDialogTitle: getElement('network-connections-dialog-title'),
    connectionsDialogBody: getElement<HTMLTableSectionElement>('network-connections-dialog-body'),
    connectionsDialogEmpty: getElement('network-connections-dialog-empty'),
    toastRegion: getElement('toast-region'),
  };
}
