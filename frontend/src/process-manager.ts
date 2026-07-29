export interface ProcessManagerElements {
  panel: HTMLElement;
  tableBody: HTMLTableSectionElement;
  status: HTMLElement;
  empty: HTMLElement;
  error: HTMLElement;
  updated: HTMLElement;
  cpuValue: HTMLElement;
  cpuProgress: HTMLProgressElement;
  loadValue: HTMLElement;
  memoryValue: HTMLElement;
  memoryProgress: HTMLProgressElement;
  swapValue: HTMLElement;
  swapProgress: HTMLProgressElement;
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

interface ProcessSnapshot {
  type: 'process_snapshot';
  metrics: {
    cpuPercent: number | null;
    loadAverage: [number, number, number] | null;
    memory: ResourceUsage | null;
    swap: ResourceUsage | null;
  };
  processes: ProcessEntry[];
  timestamp: number;
}

interface ProcessManagerOptions {
  elements: ProcessManagerElements;
  getLanguage: () => 'zh-CN' | 'en';
  onError: (message: string) => void;
}

const MAX_PROCESSES = 512;

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
    && (metrics!.swap === null || isUsage(metrics!.swap));
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

export class ProcessManager {
  private readonly elements: ProcessManagerElements;
  private readonly getLanguage: () => 'zh-CN' | 'en';
  private readonly onError: (message: string) => void;
  private socket: WebSocket | null = null;
  private generation = 0;
  private snapshot: ProcessSnapshot | null = null;

  constructor(options: ProcessManagerOptions) {
    this.elements = options.elements;
    this.getLanguage = options.getLanguage;
    this.onError = options.onError;
    this.render();
  }

  attach(url: string): void {
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
        this.showError('进程监控已意外停止。', 'Process monitor stopped unexpectedly.');
      }
    });
  }

  reset(): void {
    this.resetSocket();
    this.snapshot = null;
    this.render();
  }

  setLanguage(): void {
    this.render();
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
    if (value.type === 'process_ready') {
      this.setStatus('正在等待首个 top 快照…', 'Waiting for the first top snapshot…');
    } else if (value.type === 'process_error' && typeof value.message === 'string') {
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
      this.resetMetric(this.elements.cpuValue, this.elements.cpuProgress);
      this.elements.loadValue.textContent = '--';
      this.resetMetric(this.elements.memoryValue, this.elements.memoryProgress);
      this.resetMetric(this.elements.swapValue, this.elements.swapProgress);
      this.setStatus('连接 SSH 后即可查看实时进程', 'Connect to SSH to view live processes');
      return;
    }

    const fragment = document.createDocumentFragment();
    for (const process of snapshot.processes) {
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
        if (index === values.length - 1) cell.title = value;
        row.append(cell);
      });
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
    this.elements.loadValue.textContent = snapshot.metrics.loadAverage?.map((value) => value.toFixed(2)).join(' / ') ?? '--';
    this.setUsage(this.elements.memoryValue, this.elements.memoryProgress, snapshot.metrics.memory);
    this.setUsage(this.elements.swapValue, this.elements.swapProgress, snapshot.metrics.swap);
  }

  private setMetric(valueElement: HTMLElement, progress: HTMLProgressElement, value: number | null): void {
    valueElement.textContent = formatPercent(value);
    progress.value = value === null ? 0 : Math.min(100, value);
  }

  private resetMetric(valueElement: HTMLElement, progress: HTMLProgressElement): void {
    valueElement.textContent = '--';
    progress.value = 0;
  }

  private setUsage(valueElement: HTMLElement, progress: HTMLProgressElement, usage: ResourceUsage | null): void {
    if (!usage) {
      this.resetMetric(valueElement, progress);
      return;
    }
    valueElement.textContent = `${formatPercent(usage.percent)} ${formatBytes(usage.usedBytes)}/${formatBytes(usage.totalBytes)}`;
    progress.value = usage.percent;
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
    tableBody: getElement('process-table-body'),
    status: getElement('process-manager-status'),
    empty: getElement('process-manager-empty'),
    error: getElement('process-manager-error'),
    updated: getElement('process-updated'),
    cpuValue: getElement('resource-cpu-value'),
    cpuProgress: getElement('resource-cpu-progress'),
    loadValue: getElement('resource-load-value'),
    memoryValue: getElement('resource-memory-value'),
    memoryProgress: getElement('resource-memory-progress'),
    swapValue: getElement('resource-swap-value'),
    swapProgress: getElement('resource-swap-progress'),
  };
}
