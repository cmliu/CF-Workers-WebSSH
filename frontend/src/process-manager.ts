export interface ProcessManagerElements {
  panel: HTMLElement;
  tableBody: HTMLTableSectionElement;
  status: HTMLElement;
  empty: HTMLElement;
  error: HTMLElement;
  updated: HTMLElement;
  cpuValue: HTMLElement;
  cpuProgress: HTMLProgressElement;
  cpuLoad: HTMLElement;
  memoryValue: HTMLElement;
  memoryAmount: HTMLElement;
  memoryProgress: HTMLProgressElement;
  swapValue: HTMLElement;
  swapAmount: HTMLElement;
  swapProgress: HTMLProgressElement;
  killDialog: HTMLDialogElement;
  killDialogPid: HTMLElement;
  killDialogCommand: HTMLElement;
  killDialogResult: HTMLElement;
  killConfirmButton: HTMLButtonElement;
  killRejectButton: HTMLButtonElement;
  toastRegion: HTMLElement;
}

interface ResourceUsage {
  usedBytes: number;
  totalBytes: number;
  percent: number;
}

interface ProcessEntry {
  pid: number;
  user: string;
  memoryBytes: number | null;
  memoryPercent: number | null;
  cpuPercent: number | null;
  state: string;
  time: string;
  command: string;
}

type ProcessSortKey = 'pid' | 'user' | 'memoryBytes' | 'memoryPercent' | 'cpuPercent' | 'state' | 'time' | 'command';
type SortDirection = 'ascending' | 'descending';

interface ProcessSnapshot {
  type: 'process_snapshot';
  metrics: {
    cpuPercent: number | null;
    loadAverage: [number, number, number] | null;
    memory: ResourceUsage | null;
    swap: ResourceUsage | null;
    network: NetworkSample[] | null;
  };
  processes: ProcessEntry[];
  timestamp: number;
}

// Per-interface cumulative-byte network samples for the current tick. The
// server forwards the raw counters for every non-virtual interface (capped at
// MAX_NETWORK_INTERFACES); the frontend differentiates two successive samples
// of the selected interface with a local clock to compute the upload /
// download rate that drives the sparkline.
export interface NetworkSample {
  iface: string;
  rxBytes: number;
  txBytes: number;
}

interface PendingKillContext {
  pid: number;
  command: string;
}

interface ProcessKillResult {
  type: 'process_kill_result';
  pid: number;
  requestId: string;
  ok: boolean;
  exitStatus: number | null;
  stdout: string;
  stderr: string;
}

interface ProcessManagerOptions {
  elements: ProcessManagerElements;
  getLanguage: () => 'zh-CN' | 'en';
  onError: (message: string) => void;
  onReconnect?: (zh: string, en: string) => void;
  onToast?: (zh: string, en: string, kind: 'info' | 'error') => void;
  // Fired once per validated snapshot, even when the server didn't return a
  // network sample. The frontend uses the local clock + successive samples to
  // derive the per-interface upload / download rate; the first sample of the
  // selected interface is the baseline (rate shows zero) and the next one
  // starts drawing the sparkline.
  onNetworkSample?: (samples: NetworkSample[] | null, timestamp: number) => void;
}

const MAX_PROCESSES = 512;
// Upper bound on the number of network interface samples the backend may emit
// per tick. Mirrors the shell/parser cap (src/backend) so a hostile or
// misbehaving host cannot flood the frontend with rows.
const MAX_NETWORK_INTERFACES = 32;
// Auto-reconnect backoff for the process monitor after an unexpected drop.
const RECONNECT_BASE_MS = 1_000;
const RECONNECT_MAX_MS = 15_000;
const RECONNECT_MAX_ATTEMPTS = 10;
// Hard cap on the stdout/stderr text we render from a kill result. Backend already truncates
// the wire payload, but the frontend keeps its own ceiling so a malformed payload cannot fill
// the dialog / toast with megabytes of text.
const KILL_RESULT_TEXT_LIMIT = 2048;

function finitePercent(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 10_000;
}

function isUsage(value: unknown): value is ResourceUsage {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const usage = value as Partial<ResourceUsage>;
  return typeof usage.usedBytes === 'number' && Number.isFinite(usage.usedBytes) && usage.usedBytes >= 0
    && typeof usage.totalBytes === 'number' && Number.isFinite(usage.totalBytes) && usage.totalBytes >= usage.usedBytes
    && finitePercent(usage.percent) && usage.percent <= 100;
}

function isNetworkSample(value: unknown): value is NetworkSample {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const sample = value as Partial<NetworkSample>;
  return typeof sample.iface === 'string' && sample.iface.length > 0 && sample.iface.length <= 64
    && typeof sample.rxBytes === 'number' && Number.isSafeInteger(sample.rxBytes) && sample.rxBytes >= 0
    && typeof sample.txBytes === 'number' && Number.isSafeInteger(sample.txBytes) && sample.txBytes >= 0;
}

// Guards a validated list of network samples: an array of at most
// MAX_NETWORK_INTERFACES entries, each passing the single-sample guard.
// The length cap mirrors the backend's shell/parser cap.
export function isNetworkSampleList(value: unknown): value is NetworkSample[] {
  return Array.isArray(value)
    && value.length <= MAX_NETWORK_INTERFACES
    && value.every(isNetworkSample);
}

function isProcess(value: unknown): value is ProcessEntry {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const process = value as Partial<ProcessEntry>;
  return typeof process.pid === 'number' && Number.isSafeInteger(process.pid) && process.pid > 0
    && typeof process.user === 'string' && process.user.length <= 256
    && (process.memoryBytes === null || (typeof process.memoryBytes === 'number' && Number.isFinite(process.memoryBytes) && process.memoryBytes >= 0))
    && (process.memoryPercent === null || finitePercent(process.memoryPercent))
    && (process.cpuPercent === null || finitePercent(process.cpuPercent))
    && typeof process.state === 'string' && process.state.length <= 32
    && typeof process.time === 'string' && process.time.length <= 64
    && typeof process.command === 'string' && process.command.length <= 4096;
}

function isSnapshot(value: unknown): value is ProcessSnapshot {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const snapshot = value as Partial<ProcessSnapshot>;
  const metrics = snapshot.metrics;
  return snapshot.type === 'process_snapshot'
    && typeof snapshot.timestamp === 'number' && Number.isFinite(snapshot.timestamp)
    && Array.isArray(snapshot.processes) && snapshot.processes.length <= MAX_PROCESSES && snapshot.processes.every(isProcess)
    && Boolean(metrics) && typeof metrics === 'object'
    && (metrics!.cpuPercent === null || finitePercent(metrics!.cpuPercent))
    && (metrics!.loadAverage === null || (Array.isArray(metrics!.loadAverage) && metrics!.loadAverage.length === 3 && metrics!.loadAverage.every(finitePercent)))
    && (metrics!.memory === null || isUsage(metrics!.memory))
    && (metrics!.swap === null || isUsage(metrics!.swap))
    && (metrics!.network === null || isNetworkSampleList(metrics!.network));
}

function formatPercent(value: number | null): string {
  if (value === null) return '--';
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)}%`;
}

function formatBytes(bytes: number | null): string {
  if (bytes === null) return '--';
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

function usageColor(percent: number): string {
  const value = Math.min(100, Math.max(0, percent));
  const stops = [
    { value: 0, hue: 150 },
    { value: 50, hue: 125 },
    { value: 65, hue: 55 },
    { value: 80, hue: 30 },
    { value: 100, hue: 0 },
  ];
  const upperIndex = stops.findIndex((stop) => value <= stop.value);
  if (upperIndex <= 0) return `hsl(${stops[0].hue} 82% 58%)`;
  const lower = stops[upperIndex - 1];
  const upper = stops[upperIndex];
  const position = (value - lower.value) / (upper.value - lower.value);
  const hue = lower.hue + ((upper.hue - lower.hue) * position);
  return `hsl(${hue.toFixed(1)} 82% 58%)`;
}

export class ProcessManager {
  private readonly elements: ProcessManagerElements;
  private readonly getLanguage: () => 'zh-CN' | 'en';
  private readonly onError: (message: string) => void;
  private readonly onReconnect: ((zh: string, en: string) => void) | undefined;
  private readonly onToast: ((zh: string, en: string, kind: 'info' | 'error') => void) | undefined;
  private readonly onNetworkSample: ((samples: NetworkSample[] | null, timestamp: number) => void) | undefined;
  private socket: WebSocket | null = null;
  private generation = 0;
  private snapshot: ProcessSnapshot | null = null;
  private sortKey: ProcessSortKey = 'cpuPercent';
  private sortDirection: SortDirection = 'descending';
  private readonly progressAnimations = new Map<HTMLProgressElement, number>();
  // Whether the process monitor should stay connected for the current SSH session. Set false
  // when the user tears the session down (reset) so an unexpected drop is not mistaken for one.
  private wantConnection = false;
  private url: string | null = null;
  private reconnectTimer: number | null = null;
  private reconnectAttempts = 0;
  // requestId -> pending kill request context. The backend matches by requestId, so the map is
  // keyed that way; we keep the PID alongside so the dialog can render against the right row.
  private readonly pendingKills = new Map<string, PendingKillContext>();
  // pid -> requestId for the kill that is currently awaiting an SSH response. Used to dedupe
  // accidental repeat clicks on the same row while a previous request is still in flight.
  private readonly pendingKillsByPid = new Map<number, string>();

  constructor(options: ProcessManagerOptions) {
    this.elements = options.elements;
    this.getLanguage = options.getLanguage;
    this.onError = options.onError;
    this.onReconnect = options.onReconnect;
    this.onToast = options.onToast;
    this.onNetworkSample = options.onNetworkSample;
    this.elements.panel.addEventListener('click', (event) => {
      const target = event.target as HTMLElement;
      const sortButton = target.closest<HTMLButtonElement>('[data-process-sort]');
      if (sortButton) {
        this.changeSort(sortButton.dataset.processSort as ProcessSortKey);
        return;
      }
      const killButton = target.closest<HTMLButtonElement>('[data-process-kill-pid]');
      if (killButton) {
        const pid = Number.parseInt(killButton.dataset.processKillPid ?? '', 10);
        if (!Number.isSafeInteger(pid) || pid <= 0) return;
        // Reuse the command text already stored on the button's title attribute (set in render()).
        // Avoids depending on the table's column order via children.item(N), which breaks when
        // columns are added or rearranged.
        const command = killButton.title || '--';
        this.openKillDialog(pid, command);
        return;
      }
      const copyCell = target.closest<HTMLTableCellElement>('[data-process-copy-value]');
      if (copyCell && this.elements.tableBody.contains(copyCell)) {
        const value = copyCell.dataset.processCopyValue ?? '';
        if (!value) return;
        void this.copyProcessValue(value, copyCell.dataset.processCopyKind as 'pid' | 'command' | undefined);
        return;
      }
    });
    // Copyable PID/command cells are keyboard-focusable (tabIndex=0); mirror the click-to-copy
    // behavior for Enter/Space so the interaction is operable without a mouse.
    this.elements.panel.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter' && event.key !== ' ' && event.key !== 'Spacebar') return;
      if (event.ctrlKey || event.metaKey || event.altKey) return;
      const target = event.target as HTMLElement;
      const copyCell = target.closest<HTMLTableCellElement>('[data-process-copy-value]');
      if (!copyCell || !this.elements.tableBody.contains(copyCell)) return;
      const value = copyCell.dataset.processCopyValue ?? '';
      if (!value) return;
      event.preventDefault();
      void this.copyProcessValue(value, copyCell.dataset.processCopyKind as 'pid' | 'command' | undefined);
    });
    this.bindKillDialog();
    this.render();
  }

  attach(url: string): void {
    this.wantConnection = true;
    this.url = url;
    this.resetSocket();
    const target = new URL(url, window.location.href);
    if (target.origin !== window.location.origin || target.pathname !== '/api/processes') {
      throw new Error('Process WebSocket must use the current origin');
    }
    target.protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const generation = ++this.generation;
    const socket = new WebSocket(target);
    this.socket = socket;
    this.setStatus('正在启动进程监控…', 'Starting process monitor…');
    socket.addEventListener('open', () => {
      if (!this.isCurrent(socket, generation)) return;
      this.reconnectAttempts = 0;
      socket.send(JSON.stringify({ type: 'process_start' }));
    });
    socket.addEventListener('message', (event) => {
      if (!this.isCurrent(socket, generation) || typeof event.data !== 'string') return;
      this.handleMessage(event.data);
    });
    socket.addEventListener('error', () => {
      if (!this.isCurrent(socket, generation)) return;
      this.showError('进程监控连接错误。', 'Process monitor connection error.');
    });
    socket.addEventListener('close', (event) => {
      if (!this.isCurrent(socket, generation)) return;
      this.socket = null;
      if (event.code !== 1000 && event.code !== 1005) {
        // Unexpected drop. Auto-reconnect unless the user intentionally tore the session down.
        if (this.wantConnection) {
          this.scheduleReconnect();
        } else {
          this.showError('进程监控已意外停止。', 'Process monitor stopped unexpectedly.');
        }
      }
    });
  }

  reset(): void {
    this.wantConnection = false;
    this.clearReconnectTimer();
    this.resetSocket();
    this.snapshot = null;
    for (const requestId of this.pendingKills.keys()) {
      this.pendingKillsByPid.delete(this.pendingKills.get(requestId)!.pid);
    }
    this.pendingKills.clear();
    if (this.elements.killDialog.open) this.elements.killDialog.close('reject');
    this.elements.killDialogResult.hidden = true;
    this.elements.killDialogResult.removeAttribute('data-state');
    this.elements.killDialogResult.textContent = '';
    this.elements.killDialog.removeAttribute('data-state');
    this.elements.killDialog.removeAttribute('data-request-id');
    this.elements.killDialog.removeAttribute('data-pid');
    this.elements.killDialog.removeAttribute('data-command');
    this.render();
  }

  setLanguage(): void {
    this.updateSortHeaders();
    this.render();
  }

  private changeSort(key: ProcessSortKey): void {
    if (this.sortKey === key) {
      this.sortDirection = this.sortDirection === 'ascending' ? 'descending' : 'ascending';
    } else {
      this.sortKey = key;
      this.sortDirection = key === 'user' || key === 'state' || key === 'command' ? 'ascending' : 'descending';
    }
    this.updateSortHeaders();
    this.render();
  }

  private updateSortHeaders(): void {
    for (const button of this.elements.panel.querySelectorAll<HTMLButtonElement>('[data-process-sort]')) {
      const key = button.dataset.processSort as ProcessSortKey;
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

  private sortedProcesses(processes: ProcessEntry[]): ProcessEntry[] {
    const key = this.sortKey;
    const direction = this.sortDirection === 'ascending' ? 1 : -1;
    const value = (process: ProcessEntry): string | number | null => {
      if (key === 'time') return this.processTimeSeconds(process.time);
      return process[key];
    };
    return processes.map((process, index) => ({ process, index })).sort((left, right) => {
      const a = value(left.process);
      const b = value(right.process);
      if (a === null && b === null) return left.index - right.index;
      if (a === null) return 1;
      if (b === null) return -1;
      const compared = typeof a === 'number' && typeof b === 'number'
        ? a - b
        : String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
      return compared === 0 ? left.index - right.index : compared * direction;
    }).map(({ process }) => process);
  }

  private processTimeSeconds(value: string): number | null {
    const parts = value.replace(',', '.').split(':').map(Number);
    if (parts.some((part) => !Number.isFinite(part))) return null;
    if (parts.length === 3) return (parts[0] * 3600) + (parts[1] * 60) + parts[2];
    if (parts.length === 2) return (parts[0] * 60) + parts[1];
    return parts.length === 1 ? parts[0] : null;
  }

  private handleMessage(serialized: string): void {
    let message: unknown;
    try { message = JSON.parse(serialized); } catch { return; }
    if (isSnapshot(message)) {
      this.snapshot = message;
      this.render();
      // Fire after render so the parent can update dependent UI (sparkline
      // canvas, network block visibility) using a fresh, validated sample.
      // The callback is invoked even when network is null so the frontend
      // can decide whether to hide the block on its own.
      this.onNetworkSample?.(message.metrics.network, message.timestamp);
      return;
    }
    if (!message || typeof message !== 'object' || Array.isArray(message)) return;
    const value = message as Record<string, unknown>;
    if (value.type === 'process_ready') {
      this.setStatus('正在等待首个 top 快照…', 'Waiting for the first top snapshot…');
    } else if (value.type === 'process_error' && typeof value.message === 'string') {
      this.showError(value.message, value.message);
    } else if (value.type === 'process_kill_result') {
      this.handleKillResult(value);
    }
  }

  private handleKillResult(value: Record<string, unknown>): void {
    const requestId = typeof value.requestId === 'string' ? value.requestId : '';
    const context = requestId ? this.pendingKills.get(requestId) : undefined;
    if (!context) return;
    this.pendingKills.delete(requestId);
    this.pendingKillsByPid.delete(context.pid);
    const result: ProcessKillResult = {
      type: 'process_kill_result',
      pid: typeof value.pid === 'number' ? value.pid : context.pid,
      requestId,
      ok: value.ok === true,
      exitStatus: typeof value.exitStatus === 'number' && Number.isFinite(value.exitStatus) ? value.exitStatus : null,
      stdout: typeof value.stdout === 'string' ? value.stdout : '',
      stderr: typeof value.stderr === 'string' ? value.stderr : '',
    };
    if (this.elements.killDialog.open && this.elements.killDialog.dataset.requestId === requestId) {
      this.renderKillDialogResult(result);
    } else {
      this.toastKillResult(result);
    }
  }

  private bindKillDialog(): void {
    const dialog = this.elements.killDialog;
    // Native <dialog method="dialog"> form submissions will close the dialog. We intercept the
    // confirm button so we can flip it into a pending state, fire the WebSocket message, and
    // keep the dialog open until the server responds.
    this.elements.killConfirmButton.addEventListener('click', (event) => {
      const dataset = dialog.dataset;
      if (dataset.state === 'pending') {
        // The user clicked again while waiting for the server; ignore the repeat.
        event.preventDefault();
        return;
      }
      if (dataset.state === 'done') {
        // After a result, the same button acts as "Close" — let the form submit normally.
        return;
      }
      const pid = Number.parseInt(dataset.pid ?? '', 10);
      if (!Number.isSafeInteger(pid) || pid <= 0) {
        event.preventDefault();
        dialog.close('reject');
        return;
      }
      if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
        event.preventDefault();
        this.bilingualToast('进程监控尚未就绪，无法发送请求。', 'The process monitor is not ready yet; cannot send the request.', 'error');
        dialog.close('reject');
        return;
      }
      if (this.pendingKillsByPid.has(pid)) {
        event.preventDefault();
        this.bilingualToast(`PID ${pid} 的结束请求仍在处理中。`, `A kill request for PID ${pid} is already in progress.`, 'error');
        dialog.close('reject');
        return;
      }
      event.preventDefault();
      const requestId = this.generateRequestId();
      dataset.state = 'pending';
      dataset.requestId = requestId;
      this.pendingKills.set(requestId, { pid, command: dataset.command ?? '' });
      this.pendingKillsByPid.set(pid, requestId);
      this.setKillConfirmPending(true);
      try {
        this.socket.send(JSON.stringify({ type: 'process_kill', pid, requestId }));
      } catch (error) {
        // Synchronous failure (closed socket, etc.) — roll back and surface to the user.
        const detail = error instanceof Error ? error.message : String(error);
        this.pendingKills.delete(requestId);
        this.pendingKillsByPid.delete(pid);
        dataset.state = '';
        delete dataset.requestId;
        this.setKillConfirmPending(false);
        this.bilingualToast(`无法发送结束请求：${detail}`, `Could not send the kill request: ${detail}`, 'error');
        dialog.close('reject');
        this.render();
      }
    });
    dialog.addEventListener('close', () => {
      const dataset = dialog.dataset;
      const pendingRequestId = dataset.state === 'pending' ? dataset.requestId ?? '' : '';
      // If the user dismissed the dialog while a kill was still pending, keep the request
      // alive on the wire so the result still flows back as a toast. Only the local UI state
      // resets here.
      dataset.state = '';
      delete dataset.requestId;
      this.elements.killDialogResult.hidden = true;
      this.elements.killDialogResult.removeAttribute('data-state');
      this.elements.killDialogResult.textContent = '';
      this.setKillConfirmPending(false);
      // If the dialog closed with the cancel button (or Esc) before confirmation, no
      // requestId was ever registered, so this is a no-op.
      if (pendingRequestId) {
        // The result handler will fall back to a toast because the dialog is no longer open.
      }
      this.render();
    });
  }

  private openKillDialog(pid: number, command: string): void {
    const existing = this.pendingKillsByPid.get(pid);
    if (existing) {
      this.bilingualToast(`PID ${pid} 的结束请求仍在处理中。`, `A kill request for PID ${pid} is already in progress.`, 'error');
      return;
    }
    const dialog = this.elements.killDialog;
    const dataset = dialog.dataset;
    dataset.pid = String(pid);
    dataset.command = command;
    dataset.state = '';
    delete dataset.requestId;
    this.elements.killDialogPid.textContent = String(pid);
    this.elements.killDialogCommand.textContent = command || '--';
    this.elements.killDialogResult.hidden = true;
    this.elements.killDialogResult.removeAttribute('data-state');
    this.elements.killDialogResult.textContent = '';
    this.setKillConfirmPending(false);
    if (typeof dialog.showModal === 'function') {
      if (dialog.open) dialog.close('reject');
      dialog.showModal();
    }
  }

  private setKillConfirmPending(pending: boolean): void {
    const button = this.elements.killConfirmButton;
    const labelPending = this.getLanguage() === 'zh-CN' ? '发送中…' : 'Sending…';
    const labelDone = this.getLanguage() === 'zh-CN' ? '完成' : 'Done';
    const labelIdle = this.getLanguage() === 'zh-CN' ? '确定结束' : 'Terminate';
    if (pending) {
      button.disabled = true;
      button.dataset.pendingLabel = labelPending;
      button.textContent = labelPending;
      button.dataset.state = 'pending';
    } else {
      button.disabled = false;
      delete button.dataset.pendingLabel;
      delete button.dataset.state;
      if (this.elements.killDialog.dataset.requestId && this.elements.killDialog.dataset.state === 'done') {
        button.textContent = labelDone;
      } else {
        button.textContent = labelIdle;
      }
    }
  }

  private renderKillDialogResult(result: ProcessKillResult): void {
    const dialog = this.elements.killDialog;
    const target = this.elements.killDialogResult;
    const language = this.getLanguage();
    dialog.dataset.state = 'done';
    const lines: string[] = [];
    if (result.ok) {
      target.dataset.state = 'success';
      lines.push(language === 'zh-CN'
        ? `已向远端发送 SIGTERM 信号 (PID ${result.pid})。`
        : `Sent SIGTERM to PID ${result.pid} on the remote host.`);
    } else {
      target.dataset.state = 'error';
      const reason = result.stderr.trim() || result.stdout.trim() || (language === 'zh-CN' ? '远端未返回原因' : 'No reason returned by the remote host');
      lines.push(language === 'zh-CN' ? `结束失败：${reason}` : `Terminate failed: ${reason}`);
    }
    if (result.stdout.trim()) {
      lines.push('--- stdout ---');
      lines.push(this.truncateForDisplay(result.stdout));
    }
    if (result.stderr.trim()) {
      lines.push('--- stderr ---');
      lines.push(this.truncateForDisplay(result.stderr));
    }
    target.textContent = lines.join('\n');
    target.hidden = false;
    this.setKillConfirmPending(false);
    // After the result arrives, let the user close the dialog with a click on the confirm
    // button (which now reads "Done").
  }

  private toastKillResult(result: ProcessKillResult): void {
    const reason = result.stderr.trim() || result.stdout.trim();
    let zh: string;
    let en: string;
    if (result.ok) {
      zh = `已结束 PID ${result.pid}`;
      en = `Terminated PID ${result.pid}`;
    } else if (reason) {
      zh = `结束 PID ${result.pid} 失败：${reason.slice(0, 240)}`;
      en = `Failed to terminate PID ${result.pid}: ${reason.slice(0, 240)}`;
    } else {
      zh = `结束 PID ${result.pid} 失败`;
      en = `Failed to terminate PID ${result.pid}`;
    }
    const kind: 'info' | 'error' = result.ok ? 'info' : 'error';
    this.bilingualToast(zh, en, kind);
  }

  private bilingualToast(zh: string, en: string, kind: 'info' | 'error' = 'info'): void {
    if (this.onToast) {
      this.onToast(zh, en, kind);
      return;
    }
    // Fallback for environments where the parent didn't inject a toast handler.
    const region = this.elements.toastRegion;
    if (!region) return;
    const item = document.createElement('div');
    item.className = `toast${kind === 'error' ? ' error' : ''}`;
    item.textContent = this.getLanguage() === 'zh-CN' ? zh : en;
    region.append(item);
    window.setTimeout(() => item.remove(), 4_500);
  }

  private copyProcessValue(value: string, kind: 'pid' | 'command' | undefined): void {
    const isPid = kind === 'pid' || /^\d+$/.test(value);
    void navigator.clipboard.writeText(value).then(
      () => {
        const truncated = value.length > 64 ? `${value.slice(0, 64)}…` : value;
        const display = isPid ? `已复制 PID ${value}` : `已复制命令：${truncated}`;
        const displayEn = isPid ? `Copied PID ${value}` : `Copied command: ${truncated}`;
        this.bilingualToast(display, displayEn, 'info');
      },
      () => this.bilingualToast('无法访问剪贴板。', 'Could not access the clipboard.', 'error'),
    );
  }

  private truncateForDisplay(text: string): string {
    if (text.length <= KILL_RESULT_TEXT_LIMIT) return text;
    return `${text.slice(0, KILL_RESULT_TEXT_LIMIT)}\n…`;
  }

  private generateRequestId(): string {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
    // Fallback for environments without crypto.randomUUID — still unique enough for a short
    // session, and bounded to 64 characters to satisfy the backend validator.
    const random = Math.random().toString(36).slice(2, 10);
    return `req-${Date.now().toString(36)}-${random}`;
  }

  private render(): void {
    const snapshot = this.snapshot;
    if (!snapshot) {
      this.elements.tableBody.replaceChildren();
      this.elements.empty.hidden = true;
      this.elements.error.hidden = true;
      this.elements.updated.textContent = '--';
      this.resetMetric(this.elements.cpuValue, this.elements.cpuProgress);
      this.elements.cpuLoad.textContent = '-- / -- / --';
      this.resetUsage(this.elements.memoryValue, this.elements.memoryAmount, this.elements.memoryProgress);
      this.resetUsage(this.elements.swapValue, this.elements.swapAmount, this.elements.swapProgress);
      this.setStatus('连接 SSH 后即可查看实时进程', 'Connect to SSH to view live processes');
      return;
    }

    const fragment = document.createDocumentFragment();
    const language = this.getLanguage();
    const killLabelZh = '结束进程';
    const killLabelEn = 'Terminate process';
    for (const process of this.sortedProcesses(snapshot.processes)) {
      const row = document.createElement('tr');
      const values = [
        String(process.pid),
        process.user || '--',
        formatBytes(process.memoryBytes),
        formatPercent(process.memoryPercent),
        formatPercent(process.cpuPercent),
        process.state || '--',
        process.time || '--',
        process.command || '--',
      ];
      values.forEach((value, index) => {
        const cell = document.createElement('td');
        cell.textContent = value;
        const isCopyable = index === 0 || index === 7;
        if (isCopyable) {
          cell.className = 'process-copyable';
          cell.tabIndex = 0;
          cell.dataset.processCopyValue = value;
          cell.dataset.processCopyKind = index === 0 ? 'pid' : 'command';
          cell.title = `${value} — 点击复制 / Click to copy`;
          cell.setAttribute('aria-label', `${value} — 点击复制 / Click to copy`);
        } else if (index === values.length - 1) {
          cell.title = value;
        }
        row.append(cell);
      });
      const killCell = document.createElement('td');
      killCell.className = 'process-kill-cell';
      const killButton = document.createElement('button');
      killButton.className = 'process-kill-button';
      killButton.type = 'button';
      killButton.dataset.processKillPid = String(process.pid);
      const inFlight = this.pendingKillsByPid.has(process.pid);
      killButton.disabled = inFlight;
      killButton.dataset.i18nZh = killLabelZh;
      killButton.dataset.i18nEn = killLabelEn;
      killButton.textContent = language === 'zh-CN' ? killLabelZh : killLabelEn;
      killButton.title = process.command || '--';
      killButton.dataset.i18nAriaLabelZh = `结束进程 ${process.pid}`;
      killButton.dataset.i18nAriaLabelEn = `Terminate process ${process.pid}`;
      killButton.setAttribute('aria-label', language === 'zh-CN'
        ? `结束进程 ${process.pid}`
        : `Terminate process ${process.pid}`);
      killCell.append(killButton);
      row.append(killCell);
      fragment.append(row);
    }
    this.elements.tableBody.replaceChildren(fragment);
    this.elements.empty.hidden = snapshot.processes.length !== 0;
    this.elements.error.hidden = true;
    const updated = new Date(snapshot.timestamp).toLocaleTimeString([], { hour12: false });
    this.elements.updated.textContent = updated;
    this.setStatus(
      `共 ${snapshot.processes.length} 个进程 · 更新于 ${updated}`,
      `${snapshot.processes.length} processes · Updated ${updated}`,
    );
    this.setMetric(this.elements.cpuValue, this.elements.cpuProgress, snapshot.metrics.cpuPercent);
    this.elements.cpuLoad.textContent = snapshot.metrics.loadAverage?.map((value) => value.toFixed(2)).join(' / ') ?? '-- / -- / --';
    this.setUsage(this.elements.memoryValue, this.elements.memoryAmount, this.elements.memoryProgress, snapshot.metrics.memory);
    this.setUsage(this.elements.swapValue, this.elements.swapAmount, this.elements.swapProgress, snapshot.metrics.swap);
  }

  private setMetric(valueElement: HTMLElement, progress: HTMLProgressElement, value: number | null): void {
    valueElement.textContent = formatPercent(value);
    if (value === null) {
      this.resetProgress(progress);
      valueElement.style.removeProperty('--usage-color');
      progress.style.removeProperty('--usage-color');
      return;
    }
    this.animateProgress(progress, Math.min(100, value));
    const color = usageColor(value);
    valueElement.style.setProperty('--usage-color', color);
    progress.style.setProperty('--usage-color', color);
  }

  private resetMetric(valueElement: HTMLElement, progress: HTMLProgressElement): void {
    valueElement.textContent = '--';
    this.resetProgress(progress);
    valueElement.style.removeProperty('--usage-color');
    progress.style.removeProperty('--usage-color');
  }

  private resetProgress(progress: HTMLProgressElement): void {
    const animation = this.progressAnimations.get(progress);
    if (animation !== undefined) cancelAnimationFrame(animation);
    this.progressAnimations.delete(progress);
    progress.value = 0;
  }

  private animateProgress(progress: HTMLProgressElement, target: number): void {
    const previousAnimation = this.progressAnimations.get(progress);
    if (previousAnimation !== undefined) cancelAnimationFrame(previousAnimation);
    const startValue = progress.value;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || Math.abs(target - startValue) < 0.1) {
      progress.value = target;
      this.progressAnimations.delete(progress);
      return;
    }
    const startedAt = performance.now();
    const duration = 520;
    const step = (now: number): void => {
      const elapsed = Math.min(1, (now - startedAt) / duration);
      const eased = 1 - ((1 - elapsed) ** 3);
      progress.value = startValue + ((target - startValue) * eased);
      if (elapsed < 1) {
        this.progressAnimations.set(progress, requestAnimationFrame(step));
      } else {
        this.progressAnimations.delete(progress);
      }
    };
    this.progressAnimations.set(progress, requestAnimationFrame(step));
  }

  private resetUsage(valueElement: HTMLElement, amountElement: HTMLElement, progress: HTMLProgressElement): void {
    this.resetMetric(valueElement, progress);
    amountElement.textContent = '--/--';
  }

  private setUsage(valueElement: HTMLElement, amountElement: HTMLElement, progress: HTMLProgressElement, usage: ResourceUsage | null): void {
    if (!usage) {
      this.resetUsage(valueElement, amountElement, progress);
      return;
    }
    this.setMetric(valueElement, progress, usage.percent);
    amountElement.textContent = `${formatBytes(usage.usedBytes)}/${formatBytes(usage.totalBytes)}`;
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
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'process_stop' }));
    if (socket.readyState < WebSocket.CLOSING) socket.close(1000, 'Process monitor reset');
  }

  private scheduleReconnect(): void {
    if (!this.wantConnection || !this.url || this.reconnectTimer !== null) return;
    this.reconnectAttempts++;
    if (this.reconnectAttempts > RECONNECT_MAX_ATTEMPTS) {
      this.reconnectAttempts = 0;
      this.showError('进程监控已意外停止。', 'Process monitor stopped unexpectedly.');
      return;
    }
    const delay = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * (2 ** (this.reconnectAttempts - 1)));
    if (this.reconnectAttempts === 1 && this.onReconnect) {
      this.onReconnect('进程监控已意外停止，正在尝试自动重连…', 'Process monitor stopped unexpectedly; attempting to reconnect automatically…');
    }
    this.setStatus('进程监控连接已断开，正在重连…', 'Process monitor disconnected; reconnecting…');
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      if (!this.wantConnection || !this.url) return;
      try {
        this.attach(this.url);
      } catch {
        this.scheduleReconnect();
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
  if (!element) throw new Error(`Missing process manager element #${id}`);
  return element as T;
}

export function collectProcessManagerElements(): ProcessManagerElements {
  return {
    panel: getElement('process-manager-panel'),
    tableBody: getElement<HTMLTableSectionElement>('process-table-body'),
    status: getElement('process-manager-status'),
    empty: getElement('process-manager-empty'),
    error: getElement('process-manager-error'),
    updated: getElement('process-updated'),
    cpuValue: getElement('resource-cpu-value'),
    cpuProgress: getElement<HTMLProgressElement>('resource-cpu-progress'),
    cpuLoad: getElement('resource-cpu-load'),
    memoryValue: getElement('resource-memory-value'),
    memoryAmount: getElement('resource-memory-amount'),
    memoryProgress: getElement<HTMLProgressElement>('resource-memory-progress'),
    swapValue: getElement('resource-swap-value'),
    swapAmount: getElement('resource-swap-amount'),
    swapProgress: getElement<HTMLProgressElement>('resource-swap-progress'),
    killDialog: getElement<HTMLDialogElement>('process-kill-dialog'),
    killDialogPid: getElement('process-kill-target-pid'),
    killDialogCommand: getElement('process-kill-target-command'),
    killDialogResult: getElement('process-kill-result'),
    killConfirmButton: getElement<HTMLButtonElement>('confirm-process-kill'),
    killRejectButton: getElement<HTMLButtonElement>('reject-process-kill'),
    toastRegion: getElement('toast-region'),
  };
}
