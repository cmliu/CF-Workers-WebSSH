// Network detail panel — the "网络详情" workspace tab.
//
// Renders the per-PID aggregate table streamed by the backend network monitor
// (`NETWORK_MONITOR_COMMAND` in src/backend/session.ts, decoded by
// src/backend/network-parser.ts). The panel is aggregate-only in P0:
//   PID | 名称 | 监听IP | 端口 | IP数 | 连接数 | 上传 | 下载
//
// Semantics (see docs/finalshell-network-monitor-feasibility.md):
//   * IP数   – distinct remote IPs observed for the process.
//   * 连接数 – number of connection rows for the process.
//   * 上传/下载 – socket-lifetime cumulative bytes taken from `ss -tinp`
//     tcp_info (bytes_acked = upload, bytes_received = download). These are
//     TCP-only and can DECREASE when a socket closes; a non-root host emits no
//     rows at all, so the panel shows the shell's error line instead.
//
// This class is intentionally isomorphic to ProcessManager: same connect /
// reset / reconnect / render lifecycle so the two auxiliary channels behave
// identically from the user's point of view.

export interface NetworkManagerElements {
  panel: HTMLElement;
  tableBody: HTMLTableSectionElement;
  status: HTMLElement;
  empty: HTMLElement;
  error: HTMLElement;
  updated: HTMLElement;
  host: HTMLElement;
  toastRegion: HTMLElement;
}

export interface NetworkAggregateRow {
  pid: number;
  name: string;
  user: string;
  listen_ip: string;
  listen_port: number;
  remote_ip_count: number;
  connection_count: number;
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
  connections: unknown[];
  bytesTotals: NetworkBytesTotals | null;
  errorMessage: string | null;
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
const MAX_TEXT_LENGTH = 512;
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
    && isNonNegativeInteger(row.listen_port)
    && isNonNegativeInteger(row.remote_ip_count)
    && isNonNegativeInteger(row.connection_count)
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

export class NetworkManager {
  private readonly elements: NetworkManagerElements;
  private readonly getLanguage: () => 'zh-CN' | 'en';
  private readonly onError: (message: string) => void;
  private readonly onReconnect: ((zh: string, en: string) => void) | undefined;
  private readonly onToast: ((zh: string, en: string, kind: 'info' | 'error') => void) | undefined;
  private socket: WebSocket | null = null;
  private generation = 0;
  private snapshot: NetworkSnapshot | null = null;
  private sortKey: NetworkSortKey = 'connection_count';
  private sortDirection: SortDirection = 'descending';
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
      }
    });
    // Copyable PID / name cells are keyboard-focusable (tabIndex=0); mirror the
    // click-to-copy behaviour for Enter/Space so the interaction is operable
    // without a mouse.
    this.elements.panel.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter' && event.key !== ' ' && event.key !== 'Spacebar') return;
      if (event.ctrlKey || event.metaKey || event.altKey) return;
      const target = event.target as HTMLElement;
      const copyCell = target.closest<HTMLTableCellElement>('[data-network-copy-value]');
      if (!copyCell || !this.elements.tableBody.contains(copyCell)) return;
      const value = copyCell.dataset.networkCopyValue ?? '';
      if (!value) return;
      event.preventDefault();
      void this.copyValue(value, copyCell.dataset.networkCopyKind as 'pid' | 'name' | undefined);
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
      return;
    }

    const fragment = document.createDocumentFragment();
    for (const row of this.sortedRows(snapshot.aggregate)) {
      const tr = document.createElement('tr');
      const values = [
        String(row.pid),
        row.name || '--',
        normalizeListenIp(row.listen_ip),
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
        } else if (index === 2 || index === 7) {
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
    toastRegion: getElement('toast-region'),
  };
}
