export const MAX_SFTP_FILE_SIZE = 64 * 1024 * 1024;
export const SFTP_UPLOAD_CHUNK_SIZE = 64 * 1024;

export interface FileManagerElements {
  panel: HTMLElement;
  path: HTMLInputElement;
  back: HTMLButtonElement;
  up: HTMLButtonElement;
  home: HTMLButtonElement;
  refresh: HTMLButtonElement;
  upload: HTMLButtonElement;
  download: HTMLButtonElement;
  mkdir: HTMLButtonElement;
  rename: HTMLButtonElement;
  delete: HTMLButtonElement;
  uploadInput: HTMLInputElement;
  tableBody: HTMLTableSectionElement;
  loading: HTMLElement;
  empty: HTMLElement;
  error: HTMLElement;
  status: HTMLElement;
  progress: HTMLElement;
  progressLabel: HTMLElement;
  progressBar: HTMLProgressElement;
  progressCancel: HTMLButtonElement;
}

export interface FileManagerOptions {
  elements: FileManagerElements;
  getLanguage?: () => string;
  confirm?: (message: string) => boolean | Promise<boolean>;
  prompt?: (message: string, defaultValue?: string) => string | null | Promise<string | null>;
  onError?: (message: string) => void;
  onStatus?: (message: string) => void;
}

export interface SFTPEntry {
  name: string;
  type: 'file' | 'directory' | 'symlink' | 'other';
  size: number | string;
  mtime: string | number;
  permissions: string | number;
  uid?: string | number;
  gid?: string | number;
  owner?: string;
  group?: string;
}

/** Listener invoked whenever the FileManager's current working directory changes. */
export type CwdChangeListener = (cwd: string) => void;

interface LocalizedText {
  zh: string;
  en: string;
}

interface PendingRequest {
  generation: number;
  operation: string;
  path: string;
  historyMode?: 'push' | 'none' | 'index';
  historyIndex?: number;
}

interface UploadState {
  generation: number;
  requestId: string;
  file: File;
  path: string;
  sent: number;
  acknowledged: number;
  awaitingAck: boolean;
  endSent: boolean;
  readyForData: boolean;
  cancelling: boolean;
  cancelSent: boolean;
}

interface DownloadState {
  generation: number;
  requestId: string;
  path: string;
  name: string;
  expectedSize: number | null;
  received: number;
  chunks: ArrayBuffer[];
  started: boolean;
  cancelling: boolean;
  cancelSent: boolean;
}

type SocketData = string | ArrayBuffer | ArrayBufferView | Blob;
type JsonRecord = Record<string, unknown>;

const DISCONNECTED: LocalizedText = {
  zh: '连接 SSH 后即可管理文件',
  en: 'Connect to SSH to manage files',
};

const DISCONNECTED_CHANNEL: LocalizedText = {
  zh: '文件管理连接已断开',
  en: 'File management connection lost',
};

// Auto-reconnect for the file manager after an unexpected drop.
const RECONNECT_MAX_ATTEMPTS = 3;
const RECONNECT_DELAYS: readonly number[] = [1000, 2000, 4000];

function requiredElement<T extends Element>(root: ParentNode, id: string): T {
  const node = root.querySelector<T>(`#${id}`);
  if (!node) throw new Error(`Missing file manager element #${id}`);
  return node;
}

export function collectFileManagerElements(root: ParentNode = document): FileManagerElements {
  return {
    panel: requiredElement(root, 'file-manager-panel'),
    path: requiredElement(root, 'file-manager-path'),
    back: requiredElement(root, 'file-back'),
    up: requiredElement(root, 'file-up'),
    home: requiredElement(root, 'file-home'),
    refresh: requiredElement(root, 'file-refresh'),
    upload: requiredElement(root, 'file-upload'),
    download: requiredElement(root, 'file-download'),
    mkdir: requiredElement(root, 'file-mkdir'),
    rename: requiredElement(root, 'file-rename'),
    delete: requiredElement(root, 'file-delete'),
    uploadInput: requiredElement(root, 'file-upload-input'),
    tableBody: requiredElement(root, 'file-table-body'),
    loading: requiredElement(root, 'file-manager-loading'),
    empty: requiredElement(root, 'file-manager-empty'),
    error: requiredElement(root, 'file-manager-error'),
    status: requiredElement(root, 'file-manager-status'),
    progress: requiredElement(root, 'file-manager-progress'),
    progressLabel: requiredElement(root, 'file-manager-progress-label'),
    progressBar: requiredElement(root, 'file-manager-progress-bar'),
    progressCancel: requiredElement(root, 'file-manager-progress-cancel'),
  };
}

function normalizePath(input: string): string {
  if (typeof input !== 'string' || input.length === 0 || new TextEncoder().encode(input).length > 4096) throw new Error('Invalid path');
  if (!input.startsWith('/') || /[\0-\x1f\x7f]/.test(input)) throw new Error('Invalid path');
  return input;
}

function validateName(input: string): string {
  const name = input;
  if (!name || name === '.' || name === '..' || name.length > 255 || name.includes('/') || /[\0-\x1f\x7f]/.test(name)) {
    throw new Error('Invalid file name');
  }
  return name;
}

function joinPath(parent: string, name: string): string {
  return normalizePath(`${parent.endsWith('/') ? parent : `${parent}/`}${validateName(name)}`);
}

function parentPath(path: string): string {
  let normalized = normalizePath(path);
  while (normalized.length > 1 && normalized.endsWith('/')) normalized = normalized.slice(0, -1);
  if (normalized === '/') return '/';
  return normalized.slice(0, normalized.lastIndexOf('/')) || '/';
}

function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function numberValue(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function fileSizeValue(value: unknown): number | string | null {
  const numeric = numberValue(value);
  if (numeric !== null) return numeric;
  if (typeof value !== 'string' || !/^\d+$/.test(value)) return null;
  return value.replace(/^0+(?=\d)/, '');
}

function sizeExceedsLimit(value: number | string): boolean {
  if (typeof value === 'number') return value > MAX_SFTP_FILE_SIZE;
  const limit = String(MAX_SFTP_FILE_SIZE);
  return value.length > limit.length || (value.length === limit.length && value > limit);
}

function transferSize(value: unknown): number | null {
  const size = fileSizeValue(value);
  if (size === null || sizeExceedsLimit(size)) return null;
  return typeof size === 'number' ? size : Number(size);
}

export class FileManager {
  private readonly elements: FileManagerElements;
  private readonly getLanguage: () => string;
  private readonly confirmAction: NonNullable<FileManagerOptions['confirm']>;
  private readonly promptAction: NonNullable<FileManagerOptions['prompt']>;
  private readonly onError?: FileManagerOptions['onError'];
  private readonly onStatus?: FileManagerOptions['onStatus'];
  private readonly bindings = new AbortController();

  private socket: WebSocket | null = null;
  private generation = 0;
  private requestSequence = 0;
  private ready = false;
  private cwd = '/';
  private homePath = '/';
  private history = ['/'];
  private historyIndex = 0;
  private entries: SFTPEntry[] = [];
  private selectedIndex = -1;
  private pending = new Map<string, PendingRequest>();
  private activeListRequest: string | null = null;
  private uploadState: UploadState | null = null;
  private downloadState: DownloadState | null = null;
  private uploadConfirmationPending = false;
  private messageQueue: Promise<void> = Promise.resolve();
  private statusCopy: LocalizedText = DISCONNECTED;
  /** Auto-reconnect state: true while the SSH session is alive and we want a file channel. */
  private wantConnection = false;
  /** Last attach URL, saved for reconnection. */
  private url: string | null = null;
  /** Pending reconnect timer id, null when idle. */
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  /** Current reconnect attempt count (0 = no attempt). */
  private reconnectAttempts = 0;
  /** Pending tree-view directory fetch promises, keyed by `tree-` prefixed requestId. */
  private treeLists = new Map<string, {
    resolve: (value: { path: string; entries: SFTPEntry[]; isTruncated: boolean }) => void;
    reject: (error: Error) => void;
    generation: number;
  }>();
  /** Registered cwd-change listeners, notified on every successful cwd mutation. */
  private cwdListeners = new Set<CwdChangeListener>();

  constructor(options: FileManagerOptions) {
    this.elements = options.elements;
    this.getLanguage = options.getLanguage ?? (() => document.documentElement.lang || 'zh-CN');
    this.confirmAction = options.confirm ?? ((message) => window.confirm(message));
    this.promptAction = options.prompt ?? ((message, value) => window.prompt(message, value));
    this.onError = options.onError;
    this.onStatus = options.onStatus;
    this.bindControls();
    this.renderDisconnected();
  }

  attach(url: string): void {
    this.clearReconnectTimer();
    this.reset();
    this.wantConnection = true;
    this.url = url;
    let target: URL;
    try {
      target = new URL(url, window.location.href);
      if (target.protocol === 'http:') target.protocol = 'ws:';
      if (target.protocol === 'https:') target.protocol = 'wss:';
      const expectedProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      if (target.host !== window.location.host || target.protocol !== expectedProtocol || target.username || target.password) {
        throw new Error('SFTP WebSocket must use the current origin');
      }
      target.hash = '';
    } catch (error) {
      this.showError(this.localize({ zh: '文件传输地址无效。', en: 'The file transfer address is invalid.' }));
      throw error;
    }

    const generation = this.generation;
    const socket = new WebSocket(target);
    socket.binaryType = 'arraybuffer';
    this.socket = socket;
    this.setStatus({ zh: '正在连接文件服务…', en: 'Connecting to file service…' });

    socket.addEventListener('open', () => {
      if (!this.isCurrent(socket, generation)) return;
      if (this.reconnectAttempts > 0) {
        console.log(
          `[WS-Reconnect] ${new Date().toISOString()} | SFTP | reconnect_success | attempt=${this.reconnectAttempts}/${RECONNECT_MAX_ATTEMPTS}`,
        );
      }
      this.reconnectAttempts = 0;
      this.init();
    });
    socket.addEventListener('message', (event: MessageEvent<SocketData>) => {
      this.messageQueue = this.messageQueue
        .then(() => this.handleSocketData(event.data, generation))
        .catch((error: unknown) => this.showError(error instanceof Error ? error.message : String(error)));
    });
    socket.addEventListener('error', () => {
      if (this.isCurrent(socket, generation)) {
        this.showError(this.localize({ zh: '文件服务连接失败。', en: 'The file service connection failed.' }));
      }
    });
    socket.addEventListener('close', (event: CloseEvent) => {
      if (!this.isCurrent(socket, generation)) return;
      console.log(
        `[WS-Reconnect] ${new Date().toISOString()} | SFTP | disconnect | code=${event.code} | reason="${event.reason}"`,
      );
      this.socket = null;
      this.ready = false;
      this.abortTransfers(false);
      this.pending.clear();
      this.activeListRequest = null;
      this.rejectTreeLists(new Error('SFTP connection closed'));
      if (event.code !== 1000 && event.code !== 1005) {
        // Unexpected drop. Auto-reconnect unless the user intentionally tore the session down.
        if (this.wantConnection) {
          this.scheduleReconnect();
        } else {
          this.renderDisconnected(true, this.describeClose(event));
        }
      } else {
        this.renderDisconnected(true, this.describeClose(event));
      }
    });
  }

  init(): void {
    if (!this.isSocketOpen()) return;
    this.send({ type: 'sftp_init' });
    this.setStatus({ zh: '正在初始化 SFTP…', en: 'Initializing SFTP…' });
  }

  reset(): void {
    this.wantConnection = false;
    this.clearReconnectTimer();
    this.reconnectAttempts = 0;
    this.generation++;
    const socket = this.socket;
    this.socket = null;
    this.ready = false;
    this.uploadConfirmationPending = false;
    this.pending.clear();
    this.activeListRequest = null;
    this.rejectTreeLists(new Error('SFTP session reset'));
    this.abortTransfers(false);
    if (socket) {
      if (socket.readyState === WebSocket.OPEN) {
        try { socket.send(JSON.stringify({ type: 'sftp_close' })); } catch { /* Socket is already unusable. */ }
      }
      if (socket.readyState < WebSocket.CLOSING) socket.close(1000, 'SFTP client reset');
    }
    this.cwd = '/';
    this.homePath = '/';
    this.history = ['/'];
    this.historyIndex = 0;
    this.entries = [];
    this.selectedIndex = -1;
    this.renderDisconnected();
  }

  destroy(): void {
    this.reset();
    this.cwdListeners.clear();
    this.bindings.abort();
  }

  list(path = this.cwd): string | null {
    return this.requestList(path, 'push');
  }

  navigate(path: string): void {
    try {
      this.requestList(normalizePath(path), 'push');
    } catch {
      this.showError(this.localize({ zh: '请输入有效的绝对路径。', en: 'Enter a valid absolute path.' }));
    }
  }

  back(): void {
    if (!this.ready || this.historyIndex <= 0) return;
    this.requestList(this.history[this.historyIndex - 1], 'index', this.historyIndex - 1);
  }

  up(): void {
    if (this.ready) this.requestList(parentPath(this.cwd), 'push');
  }

  home(): void {
    if (this.ready) this.requestList(this.homePath, 'push');
  }

  refresh(): void {
    if (this.ready) this.requestList(this.cwd, 'none');
  }

  setLanguage(): void {
    this.updateStatusText(this.statusCopy);
    this.renderEntries();
    this.updateProgressLanguage();
  }

  /**
   * Fetch directory entries for the tree view **without** disturbing the
   * right-side panel (cwd, history, activeListRequest, or rendered entries).
   * Uses a `tree-` prefixed requestId so handleListResult / handleServerError
   * route the response to the tree channel instead of the normal list flow.
   */
  fetchDirectoryEntries(path: string): Promise<{ path: string; entries: SFTPEntry[]; isTruncated: boolean }> {
    if (!this.ready || !this.isSocketOpen()) {
      return Promise.reject(new Error(this.localize({ zh: 'SFTP 尚未就绪。', en: 'SFTP is not ready.' })));
    }
    let normalized: string;
    try {
      normalized = normalizePath(path);
    } catch {
      return Promise.reject(new Error(this.localize({ zh: '路径无效。', en: 'Invalid path.' })));
    }
    const requestId = `tree-${this.generation}-${++this.requestSequence}`;
    return new Promise((resolve, reject) => {
      this.treeLists.set(requestId, { resolve, reject, generation: this.generation });
      this.send({ type: 'sftp_list', requestId, path: normalized });
    });
  }

  /**
   * Register a listener that fires whenever the current working directory
   * changes (after a successful list navigation or sftp_ready). Returns an
   * unsubscribe function.
   */
  onCwdChange(listener: CwdChangeListener): () => void {
    this.cwdListeners.add(listener);
    return () => { this.cwdListeners.delete(listener); };
  }

  async upload(file: File, destination?: string): Promise<void> {
    if (!this.ready || this.hasTransfer() || this.uploadConfirmationPending) return;
    if (file.size > MAX_SFTP_FILE_SIZE) {
      this.showError(this.localize({ zh: '文件不能超过 64 MiB。', en: 'Files cannot exceed 64 MiB.' }));
      return;
    }
    let path: string;
    try { path = normalizePath(destination ?? joinPath(this.cwd, file.name)); } catch {
      this.showError(this.localize({ zh: '上传文件名无效。', en: 'The upload file name is invalid.' }));
      return;
    }
    const existing = this.entries.find((entry) => joinPath(this.cwd, entry.name) === path);
    const generation = this.generation;
    let overwrite = false;
    if (existing) {
      this.uploadConfirmationPending = true;
      this.updateControls();
      try {
        overwrite = await this.confirmAction(this.localize({
          zh: `“${existing.name}”已存在。是否覆盖？此操作无法撤销。`,
          en: `“${existing.name}” already exists. Overwrite it? This cannot be undone.`,
        }));
      } catch {
        if (generation === this.generation) {
          this.showError(this.localize({ zh: '无法确认是否覆盖文件。', en: 'Could not confirm whether to overwrite the file.' }));
        }
        return;
      } finally {
        if (generation === this.generation) {
          this.uploadConfirmationPending = false;
          this.updateControls();
        }
      }
      if (!overwrite) return;
    }
    if (generation !== this.generation || !this.ready || this.hasTransfer() || !this.isSocketOpen()) return;
    const requestId = this.createRequest('upload', path);
    this.uploadState = {
      generation: this.generation,
      requestId,
      file,
      path,
      sent: 0,
      acknowledged: 0,
      awaitingAck: false,
      endSent: false,
      readyForData: false,
      cancelling: false,
      cancelSent: false,
    };
    this.showProgress('upload', file.name, 0);
    this.send({ type: 'sftp_upload_start', requestId, path, size: file.size, overwrite });
    this.updateControls();
  }

  downloadSelected(): void {
    const entry = this.selectedEntry();
    if (!this.ready || !entry || entry.type !== 'file' || this.hasTransfer()) return;
    if (sizeExceedsLimit(entry.size)) {
      this.showError(this.localize({ zh: '文件不能超过 64 MiB。', en: 'Files cannot exceed 64 MiB.' }));
      return;
    }
    const path = joinPath(this.cwd, entry.name);
    const requestId = this.createRequest('download', path);
    this.downloadState = {
      generation: this.generation,
      requestId,
      path,
      name: entry.name,
      expectedSize: transferSize(entry.size),
      received: 0,
      chunks: [],
      started: false,
      cancelling: false,
      cancelSent: false,
    };
    this.showProgress('download', entry.name, 0);
    this.send({ type: 'sftp_download', requestId, path });
    this.updateControls();
  }

  cancelTransfer(): void {
    this.requestTransferCancel();
  }

  async handle(data: SocketData): Promise<void> {
    await this.handleSocketData(data, this.generation);
  }

  private bindControls(): void {
    const signal = this.bindings.signal;
    this.elements.path.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      this.navigate(this.elements.path.value);
    }, { signal });
    this.elements.back.addEventListener('click', () => this.back(), { signal });
    this.elements.up.addEventListener('click', () => this.up(), { signal });
    this.elements.home.addEventListener('click', () => this.home(), { signal });
    this.elements.refresh.addEventListener('click', () => this.refresh(), { signal });
    this.elements.upload.addEventListener('click', () => this.elements.uploadInput.click(), { signal });
    this.elements.uploadInput.addEventListener('change', () => {
      const file = this.elements.uploadInput.files?.[0];
      this.elements.uploadInput.value = '';
      if (file) void this.upload(file);
    }, { signal });
    this.elements.download.addEventListener('click', () => this.downloadSelected(), { signal });
    this.elements.progressCancel.addEventListener('click', () => this.cancelTransfer(), { signal });
    this.elements.mkdir.addEventListener('click', () => void this.createDirectory(), { signal });
    this.elements.rename.addEventListener('click', () => void this.renameSelected(), { signal });
    this.elements.delete.addEventListener('click', () => void this.deleteSelected(), { signal });
    this.elements.tableBody.addEventListener('click', (event) => {
      const target = this.rowFromEvent(event);
      if (target) this.selectRow(target, true);
    }, { signal });
    this.elements.tableBody.addEventListener('focusin', (event) => {
      const target = this.rowFromEvent(event);
      if (target) this.selectRow(target, false);
    }, { signal });
    this.elements.tableBody.addEventListener('dblclick', (event) => {
      const target = this.rowFromEvent(event);
      if (!target) return;
      const entry = this.selectRow(target, true);
      this.activateEntry(entry);
    }, { signal });
    this.elements.tableBody.addEventListener('keydown', (event) => {
      const target = this.rowFromEvent(event);
      if (!target) return;
      if (event.key === 'Enter') {
        event.preventDefault();
        this.activateEntry(this.selectRow(target, false));
        return;
      }
      if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const current = Number(target.dataset.index);
      const next = event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? this.entries.length - 1
          : Math.max(0, Math.min(this.entries.length - 1, current + (event.key === 'ArrowUp' ? -1 : 1)));
      const nextRow = this.elements.tableBody.rows.item(next);
      if (nextRow) this.selectRow(nextRow, true);
    }, { signal });
  }

  private async handleSocketData(data: SocketData, generation: number): Promise<void> {
    if (generation !== this.generation) return;
    if (typeof data !== 'string') {
      await this.handleBinary(data, generation);
      return;
    }
    let message: JsonRecord;
    try {
      const parsed: unknown = JSON.parse(data);
      if (!isRecord(parsed)) throw new Error('Invalid SFTP response');
      message = parsed;
    } catch {
      this.showError(this.localize({ zh: '文件服务返回了无效响应。', en: 'The file service returned an invalid response.' }));
      return;
    }
    const type = typeof message.type === 'string' ? message.type : '';
    if (type === 'pong') return;
    if (type === 'sftp_ready') {
      this.handleReady(message);
      return;
    }
    if (type === 'sftp_list_result') {
      this.handleListResult(message);
      return;
    }
    if (type === 'sftp_upload_ready') {
      await this.handleUploadReady(message);
      return;
    }
    if (type === 'sftp_upload_progress') {
      await this.handleUploadProgress(message);
      return;
    }
    if (type === 'sftp_upload_complete') {
      this.handleUploadComplete(message);
      return;
    }
    if (type === 'sftp_download_start') {
      this.handleDownloadStart(message);
      return;
    }
    if (type === 'sftp_download_progress') {
      this.handleDownloadProgress(message);
      return;
    }
    if (type === 'sftp_download_done') {
      this.handleDownloadDone(message);
      return;
    }
    if (type === 'sftp_upload_cancelled' || type === 'sftp_download_cancelled') {
      this.handleTransferCancelled(message, type === 'sftp_upload_cancelled' ? 'upload' : 'download');
      return;
    }
    if (type === 'sftp_error') {
      this.handleServerError(message);
      return;
    }
    if (type === 'sftp_closed') {
      this.socket?.close(1000, 'SFTP service closed');
      return;
    }
    if (type.endsWith('_result')) this.handleMutationResult(message);
  }

  private handleReady(message: JsonRecord): void {
    if (this.ready) return;
    let cwd: string;
    try { cwd = normalizePath(typeof message.cwd === 'string' ? message.cwd : '/'); } catch { cwd = '/'; }
    this.ready = true;
    this.cwd = cwd;
    this.emitCwdChange(cwd);
    this.homePath = cwd;
    this.history = [cwd];
    this.historyIndex = 0;
    this.elements.path.value = cwd;
    this.updateControls();
    this.requestList(cwd, 'none');
  }

  private requestList(path: string, historyMode: PendingRequest['historyMode'], historyIndex?: number): string | null {
    if (!this.ready || !this.isSocketOpen()) return null;
    let normalized: string;
    try { normalized = normalizePath(path); } catch {
      this.showError(this.localize({ zh: '请输入有效的绝对路径。', en: 'Enter a valid absolute path.' }));
      return null;
    }
    if (this.activeListRequest) this.pending.delete(this.activeListRequest);
    const requestId = this.createRequest('list', normalized, { historyMode, historyIndex });
    this.activeListRequest = requestId;
    this.elements.loading.hidden = false;
    this.elements.empty.hidden = true;
    this.elements.error.hidden = true;
    this.setStatus({ zh: `正在读取 ${normalized}`, en: `Loading ${normalized}` });
    this.send({ type: 'sftp_list', requestId, path: normalized });
    return requestId;
  }

  private handleListResult(message: JsonRecord): void {
    const requestId = typeof message.requestId === 'string' ? message.requestId : '';
    // === Tree-view fetch: route to tree channel, never enter right-side rendering ===
    if (requestId.startsWith('tree-')) {
      this.resolveTreeList(message, requestId);
      return;
    }
    const pending = this.pending.get(requestId);
    if (!pending || pending.generation !== this.generation || pending.operation !== 'list') return;
    this.pending.delete(requestId);
    if (requestId !== this.activeListRequest) return;
    this.activeListRequest = null;
    let path: string;
    try { path = normalizePath(typeof message.path === 'string' ? message.path : pending.path); } catch {
      this.showError(this.localize({ zh: '文件服务返回了无效路径。', en: 'The file service returned an invalid path.' }));
      return;
    }
    if (!Array.isArray(message.entries)) {
      this.showError(this.localize({ zh: '文件服务返回了无效目录列表。', en: 'The file service returned an invalid directory listing.' }));
      return;
    }
    const entries = message.entries.map((entry) => this.parseEntry(entry)).filter((entry): entry is SFTPEntry => entry !== null);
    entries.sort((left, right) => {
      if (left.type === 'directory' && right.type !== 'directory') return -1;
      if (left.type !== 'directory' && right.type === 'directory') return 1;
      return left.name.localeCompare(right.name, this.isChinese() ? 'zh-CN' : 'en', { numeric: true, sensitivity: 'base' });
    });
    this.cwd = path;
    this.emitCwdChange(path);
    if (pending.historyMode === 'push' && this.history[this.historyIndex] !== path) {
      this.history = this.history.slice(0, this.historyIndex + 1);
      this.history.push(path);
      this.historyIndex = this.history.length - 1;
    } else if (pending.historyMode === 'index' && pending.historyIndex !== undefined) {
      this.historyIndex = pending.historyIndex;
    }
    this.entries = entries;
    this.selectedIndex = -1;
    this.elements.path.value = path;
    this.elements.loading.hidden = true;
    this.elements.error.hidden = true;
    this.elements.empty.hidden = entries.length !== 0;
    this.renderEntries();
    const truncated = message.isTruncated === true;
    this.setStatus({
      zh: `${entries.length} 个项目${truncated ? '（列表已截断）' : ''}`,
      en: `${entries.length} item${entries.length === 1 ? '' : 's'}${truncated ? ' (list truncated)' : ''}`,
    });
    this.updateControls();
  }

  private parseEntry(value: unknown): SFTPEntry | null {
    if (!isRecord(value) || typeof value.name !== 'string') return null;
    let name: string;
    try { name = validateName(value.name); } catch { return null; }
    const rawType = typeof value.type === 'string' ? value.type.toLowerCase() : 'other';
    const type: SFTPEntry['type'] = rawType === 'dir' || rawType === 'directory'
      ? 'directory'
      : rawType === 'file' || rawType === 'regular'
        ? 'file'
        : rawType === 'link' || rawType === 'symlink'
          ? 'symlink'
          : 'other';
    return {
      name,
      type,
      size: fileSizeValue(value.size) ?? 0,
      mtime: typeof value.mtime === 'string' || typeof value.mtime === 'number' ? value.mtime : '',
      permissions: typeof value.permissions === 'string' || typeof value.permissions === 'number' ? value.permissions : '',
      uid: typeof value.uid === 'string' || typeof value.uid === 'number' ? value.uid : undefined,
      gid: typeof value.gid === 'string' || typeof value.gid === 'number' ? value.gid : undefined,
      owner: typeof value.owner === 'string' ? value.owner : undefined,
      group: typeof value.group === 'string' ? value.group : undefined,
    };
  }

  private renderEntries(): void {
    this.elements.tableBody.replaceChildren();
    const fragment = document.createDocumentFragment();
    this.entries.forEach((entry, index) => {
      const row = document.createElement('tr');
      row.dataset.index = String(index);
      row.tabIndex = index === this.rovingIndex() ? 0 : -1;
      row.setAttribute('aria-selected', String(index === this.selectedIndex));

      const nameCell = document.createElement('td');
      const nameWrap = document.createElement('span');
      nameWrap.className = 'file-name-cell';
      const icon = document.createElement('span');
      icon.className = `file-kind-icon ${entry.type}`;
      icon.setAttribute('aria-hidden', 'true');
      icon.textContent = entry.type === 'directory' ? '\u25a0' : entry.type === 'symlink' ? '\u2197' : '\u25a1';
      const name = document.createElement('span');
      name.textContent = entry.name;
      nameWrap.append(icon, name);
      nameCell.append(nameWrap);
      row.append(
        nameCell,
        this.cell(entry.type === 'directory' ? '' : this.formatSize(entry.size)),
        this.localizedCell(this.typeLabel(entry.type)),
        this.cell(this.formatDate(entry.mtime)),
        this.cell(String(entry.permissions ?? '')),
        this.cell(entry.owner ?? String(entry.uid ?? '')),
        this.cell(entry.group ?? String(entry.gid ?? '')),
      );
      fragment.append(row);
    });
    this.elements.tableBody.append(fragment);
  }

  private cell(text: string): HTMLTableCellElement {
    const cell = document.createElement('td');
    cell.textContent = text;
    cell.title = text;
    return cell;
  }

  private localizedCell(copy: LocalizedText): HTMLTableCellElement {
    const cell = this.cell(this.localize(copy));
    cell.dataset.i18nZh = copy.zh;
    cell.dataset.i18nEn = copy.en;
    return cell;
  }

  private rowFromEvent(event: Event): HTMLTableRowElement | null {
    const target = event.target instanceof Element ? event.target.closest<HTMLTableRowElement>('tr[data-index]') : null;
    if (!target || !this.elements.tableBody.contains(target)) return null;
    return target;
  }

  private selectRow(target: HTMLTableRowElement, focus: boolean): SFTPEntry | null {
    const index = Number(target.dataset.index);
    if (!Number.isInteger(index) || !this.entries[index]) return null;
    this.selectedIndex = index;
    for (const row of this.elements.tableBody.rows) {
      const selected = row === target;
      row.setAttribute('aria-selected', String(selected));
      row.tabIndex = selected ? 0 : -1;
    }
    if (focus) target.focus();
    this.updateControls();
    return this.entries[index];
  }

  private rovingIndex(): number {
    if (this.entries.length === 0) return -1;
    return this.selectedIndex >= 0 && this.selectedIndex < this.entries.length ? this.selectedIndex : 0;
  }

  private activateEntry(entry: SFTPEntry | null): void {
    if (!entry) return;
    if (entry.type === 'directory' || entry.type === 'symlink') {
      this.navigate(joinPath(this.cwd, entry.name));
    } else {
      this.downloadSelected();
    }
  }

  private async createDirectory(): Promise<void> {
    if (!this.ready || this.hasTransfer()) return;
    const input = await this.promptAction(this.localize({ zh: '新文件夹名称', en: 'New folder name' }), '');
    if (input === null) return;
    let path: string;
    try { path = joinPath(this.cwd, input); } catch {
      this.showError(this.localize({ zh: '文件夹名称无效。', en: 'The folder name is invalid.' }));
      return;
    }
    const requestId = this.createRequest('mkdir', path);
    this.send({ type: 'sftp_mkdir', requestId, path });
    this.setStatus({ zh: '正在新建文件夹…', en: 'Creating folder…' });
  }

  private async renameSelected(): Promise<void> {
    const entry = this.selectedEntry();
    if (!this.ready || !entry || this.hasTransfer()) return;
    const input = await this.promptAction(this.localize({ zh: '输入新名称', en: 'Enter a new name' }), entry.name);
    if (input === null || input === entry.name) return;
    let newPath: string;
    try { newPath = joinPath(this.cwd, input); } catch {
      this.showError(this.localize({ zh: '文件名无效。', en: 'The file name is invalid.' }));
      return;
    }
    const oldPath = joinPath(this.cwd, entry.name);
    const requestId = this.createRequest('rename', oldPath);
    this.send({ type: 'sftp_rename', requestId, oldPath, newPath });
    this.setStatus({ zh: '正在重命名…', en: 'Renaming…' });
  }

  private async deleteSelected(): Promise<void> {
    const entry = this.selectedEntry();
    if (!this.ready || !entry || this.hasTransfer()) return;
    const confirmed = await this.confirmAction(this.localize({
      zh: `确定要删除“${entry.name}”吗？此操作无法撤销。`,
      en: `Delete “${entry.name}”? This cannot be undone.`,
    }));
    if (!confirmed) return;
    const path = joinPath(this.cwd, entry.name);
    const operation = entry.type === 'directory' ? 'rmdir' : 'delete';
    const requestId = this.createRequest(operation, path);
    this.send({ type: operation === 'rmdir' ? 'sftp_rmdir' : 'sftp_delete', requestId, path });
    this.setStatus({ zh: '正在删除…', en: 'Deleting…' });
  }

  private handleMutationResult(message: JsonRecord): void {
    const requestId = typeof message.requestId === 'string' ? message.requestId : '';
    const pending = this.pending.get(requestId);
    if (!pending || pending.generation !== this.generation || !['mkdir', 'rename', 'delete', 'rmdir'].includes(pending.operation)) return;
    this.pending.delete(requestId);
    this.setStatus({ zh: '操作完成', en: 'Operation completed' });
    this.refresh();
  }

  private async handleUploadReady(message: JsonRecord): Promise<void> {
    const state = this.matchUpload(message);
    if (!state || state.sent !== 0) return;
    state.readyForData = true;
    if (state.cancelling) {
      this.sendUploadCancel(state);
      return;
    }
    await this.sendNextUploadChunk(state);
  }

  private async handleUploadProgress(message: JsonRecord): Promise<void> {
    const state = this.matchUpload(message);
    if (!state) return;
    const acknowledged = numberValue(message.loaded) ?? numberValue(message.transferred) ?? numberValue(message.received) ?? numberValue(message.bytes) ?? state.sent;
    state.acknowledged = Math.min(state.file.size, Math.max(state.acknowledged, acknowledged));
    state.awaitingAck = false;
    this.showProgress('upload', state.file.name, state.file.size === 0 ? 100 : (state.acknowledged / state.file.size) * 100);
    if (state.cancelling) {
      this.sendUploadCancel(state);
      return;
    }
    await this.sendNextUploadChunk(state);
  }

  private async sendNextUploadChunk(state: UploadState): Promise<void> {
    if (state !== this.uploadState || state.generation !== this.generation || !state.readyForData
      || state.cancelling || state.awaitingAck || state.endSent || !this.isSocketOpen()) return;
    if (state.sent >= state.file.size) {
      state.endSent = true;
      this.updateProgressLanguage();
      this.send({ type: 'sftp_upload_end', requestId: state.requestId });
      return;
    }
    const end = Math.min(state.file.size, state.sent + SFTP_UPLOAD_CHUNK_SIZE);
    const chunk = await state.file.slice(state.sent, end).arrayBuffer();
    if (state !== this.uploadState || state.generation !== this.generation || state.cancelling || !this.isSocketOpen()) return;
    this.socket!.send(chunk);
    state.sent = end;
    state.awaitingAck = true;
  }

  private handleUploadComplete(message: JsonRecord): void {
    const state = this.matchUpload(message);
    if (!state) return;
    this.pending.delete(state.requestId);
    this.uploadState = null;
    this.hideProgress();
    this.setStatus({ zh: `已上传 ${state.file.name}`, en: `Uploaded ${state.file.name}` });
    this.updateControls();
    this.refresh();
  }

  private handleDownloadStart(message: JsonRecord): void {
    const state = this.matchDownload(message);
    if (!state) return;
    state.started = true;
    const size = numberValue(message.size);
    state.expectedSize = size;
    if (state.cancelling) {
      this.sendDownloadCancel(state);
      return;
    }
    if (state.expectedSize !== null && state.expectedSize > MAX_SFTP_FILE_SIZE) {
      state.cancelling = true;
      this.setStatus({ zh: '正在取消传输…', en: 'Cancelling transfer…' });
      this.updateProgressLanguage();
      this.sendDownloadCancel(state);
    }
  }

  private handleDownloadProgress(message: JsonRecord): void {
    const state = this.matchDownload(message);
    if (!state || state.cancelling) return;
    const received = numberValue(message.loaded) ?? numberValue(message.transferred) ?? numberValue(message.sent) ?? numberValue(message.bytes) ?? state.received;
    const total = numberValue(message.total) ?? numberValue(message.size) ?? state.expectedSize;
    const percent = total && total > 0 ? Math.min(100, (received / total) * 100) : 0;
    this.showProgress('download', state.name, percent);
  }

  private async handleBinary(data: Exclude<SocketData, string>, generation: number): Promise<void> {
    const state = this.downloadState;
    if (!state || state.generation !== generation || generation !== this.generation) return;
    let buffer: ArrayBuffer;
    if (data instanceof Blob) buffer = await data.arrayBuffer();
    else if (ArrayBuffer.isView(data)) buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
    else buffer = data;
    if (state !== this.downloadState || state.generation !== this.generation) return;
    if (state.cancelling) return;
    if (state.received + buffer.byteLength > MAX_SFTP_FILE_SIZE) {
      state.cancelling = true;
      this.setStatus({ zh: '正在取消传输…', en: 'Cancelling transfer…' });
      this.updateProgressLanguage();
      this.sendDownloadCancel(state);
      return;
    }
    state.chunks.push(buffer);
    state.received += buffer.byteLength;
    const total = state.expectedSize;
    this.showProgress('download', state.name, total && total > 0 ? (state.received / total) * 100 : 0);
  }

  private handleDownloadDone(message: JsonRecord): void {
    const state = this.matchDownload(message);
    if (!state) return;
    if (state.cancelling) {
      this.completeCancelledTransfer(state);
      return;
    }
    const doneSize = numberValue(message.size);
    const expectedSize = doneSize ?? state.expectedSize;
    if (expectedSize !== null && state.received !== expectedSize) {
      this.failTransfer(this.localize({ zh: '下载未完成，文件大小不匹配。', en: 'The download is incomplete: file size mismatch.' }));
      return;
    }
    this.pending.delete(state.requestId);
    this.downloadState = null;
    this.saveBlob(new Blob(state.chunks), state.name);
    this.hideProgress();
    this.setStatus({ zh: `已下载 ${state.name}`, en: `Downloaded ${state.name}` });
    this.updateControls();
  }

  private handleServerError(message: JsonRecord): void {
    const requestId = typeof message.requestId === 'string' ? message.requestId : '';
    // === Tree-view fetch error: route to tree channel, never enter right-side error handling ===
    if (requestId.startsWith('tree-')) {
      this.rejectTreeList(message, requestId);
      return;
    }
    const pending = requestId ? this.pending.get(requestId) : undefined;
    if (requestId && (!pending || pending.generation !== this.generation)) return;
    if (requestId) this.pending.delete(requestId);
    if (pending?.operation === 'list' && requestId !== this.activeListRequest) return;
    if (requestId === this.activeListRequest) {
      this.activeListRequest = null;
      this.elements.loading.hidden = true;
    }
    const fallback = this.localize({ zh: '文件操作失败。', en: 'The file operation failed.' });
    const serverMessage = typeof message.message === 'string' && message.message ? message.message : fallback;
    const transfer = requestId === this.uploadState?.requestId
      ? this.uploadState
      : requestId === this.downloadState?.requestId
        ? this.downloadState
        : null;
    if (transfer) {
      this.abortTransfers(true);
    }
    this.showError(serverMessage);
  }

  /** Resolve a pending tree-view fetch promise with parsed, sorted entries. */
  private resolveTreeList(message: JsonRecord, requestId: string): void {
    const entry = this.treeLists.get(requestId);
    if (!entry || entry.generation !== this.generation) return;
    this.treeLists.delete(requestId);
    let path: string;
    try { path = normalizePath(typeof message.path === 'string' ? message.path : ''); }
    catch {
      entry.reject(new Error(
        this.localize({ zh: '目录列表数据异常。', en: 'The directory listing response was malformed.' }),
        { cause: 'invalid path in tree list result' },
      ));
      return;
    }
    if (!Array.isArray(message.entries)) {
      entry.reject(new Error(
        this.localize({ zh: '目录列表数据异常。', en: 'The directory listing response was malformed.' }),
        { cause: 'invalid entries in tree list result' },
      ));
      return;
    }
    const entries = message.entries
      .map((raw) => this.parseEntry(raw))
      .filter((item): item is SFTPEntry => item !== null);
    entries.sort((left, right) => {
      if (left.type === 'directory' && right.type !== 'directory') return -1;
      if (left.type !== 'directory' && right.type === 'directory') return 1;
      return left.name.localeCompare(right.name, this.isChinese() ? 'zh-CN' : 'en', { numeric: true, sensitivity: 'base' });
    });
    entry.resolve({ path, entries, isTruncated: message.isTruncated === true });
  }

  /** Reject a single pending tree-view fetch promise with the server error message. */
  private rejectTreeList(message: JsonRecord, requestId: string): void {
    const entry = this.treeLists.get(requestId);
    if (!entry || entry.generation !== this.generation) return;
    this.treeLists.delete(requestId);
    const fallback = this.localize({ zh: '文件操作失败。', en: 'The file operation failed.' });
    const serverMessage = typeof message.message === 'string' && message.message ? message.message : fallback;
    entry.reject(new Error(serverMessage));
  }

  /** Reject all pending tree-view fetch promises (used on reset / close / destroy). */
  private rejectTreeLists(error: Error): void {
    this.treeLists.forEach((entry) => {
      entry.reject(error);
    });
    this.treeLists.clear();
  }

  /** Notify all registered cwd-change listeners. Listener errors are swallowed. */
  private emitCwdChange(cwd: string): void {
    this.cwdListeners.forEach((listener) => {
      try { listener(cwd); } catch { /* listener errors are non-fatal */ }
    });
  }

  private handleTransferCancelled(message: JsonRecord, operation: 'upload' | 'download'): void {
    const requestId = typeof message.requestId === 'string' ? message.requestId : '';
    const state = operation === 'upload' ? this.uploadState : this.downloadState;
    if (!state || state.requestId !== requestId || state.generation !== this.generation || !state.cancelling) return;
    this.completeCancelledTransfer(state);
  }

  private completeCancelledTransfer(state: UploadState | DownloadState): void {
    if (state !== this.uploadState && state !== this.downloadState) return;
    this.pending.delete(state.requestId);
    this.abortTransfers(true);
    this.setStatus({ zh: '传输已取消', en: 'Transfer cancelled' });
  }

  private requestTransferCancel(): void {
    const upload = this.uploadState;
    const transfer = upload ?? this.downloadState;
    if (!transfer || transfer.cancelling || upload?.endSent) return;
    transfer.cancelling = true;
    this.setStatus({ zh: '正在取消传输…', en: 'Cancelling transfer…' });
    this.updateProgressLanguage();
    if (upload) this.sendUploadCancel(upload);
    else this.sendDownloadCancel(transfer as DownloadState);
  }

  private sendUploadCancel(state: UploadState): void {
    if (state !== this.uploadState || state.cancelSent || !state.readyForData || !this.isSocketOpen()) return;
    state.cancelSent = true;
    this.send({ type: 'sftp_upload_cancel', requestId: state.requestId });
  }

  private sendDownloadCancel(state: DownloadState): void {
    if (state !== this.downloadState || state.cancelSent || !state.started || !this.isSocketOpen()) return;
    state.cancelSent = true;
    this.send({ type: 'sftp_download_cancel', requestId: state.requestId });
  }

  private createRequest(operation: string, path: string, extra: Partial<PendingRequest> = {}): string {
    const requestId = `${this.generation}-${++this.requestSequence}`;
    this.pending.set(requestId, { generation: this.generation, operation, path, ...extra });
    return requestId;
  }

  private matchUpload(message: JsonRecord): UploadState | null {
    const requestId = typeof message.requestId === 'string' ? message.requestId : '';
    const state = this.uploadState;
    return state && state.requestId === requestId && state.generation === this.generation ? state : null;
  }

  private matchDownload(message: JsonRecord): DownloadState | null {
    const requestId = typeof message.requestId === 'string' ? message.requestId : '';
    const state = this.downloadState;
    return state && state.requestId === requestId && state.generation === this.generation ? state : null;
  }

  private send(message: JsonRecord): void {
    if (this.isSocketOpen()) this.socket!.send(JSON.stringify(message));
  }

  private isSocketOpen(): boolean {
    return this.socket?.readyState === WebSocket.OPEN;
  }

  private isCurrent(socket: WebSocket, generation: number): boolean {
    return this.socket === socket && this.generation === generation;
  }

  private hasTransfer(): boolean {
    return this.uploadState !== null || this.downloadState !== null;
  }

  private selectedEntry(): SFTPEntry | null {
    return this.selectedIndex >= 0 ? this.entries[this.selectedIndex] ?? null : null;
  }

  private abortTransfers(updateControls: boolean): void {
    this.uploadState = null;
    this.downloadState = null;
    this.hideProgress();
    if (updateControls) this.updateControls();
  }

  private failTransfer(message: string): void {
    const requestId = this.uploadState?.requestId ?? this.downloadState?.requestId;
    if (requestId) this.pending.delete(requestId);
    this.abortTransfers(true);
    this.showError(message);
  }

  private updateControls(): void {
    const selected = this.selectedEntry();
    const idle = this.ready && !this.hasTransfer() && !this.uploadConfirmationPending;
    this.elements.path.disabled = !this.ready;
    this.elements.back.disabled = !this.ready || this.historyIndex <= 0;
    this.elements.up.disabled = !this.ready || this.cwd === '/';
    this.elements.home.disabled = !this.ready || this.cwd === this.homePath;
    this.elements.refresh.disabled = !this.ready;
    this.elements.upload.disabled = !idle;
    this.elements.mkdir.disabled = !idle;
    this.elements.download.disabled = !idle || !selected || selected.type !== 'file' || sizeExceedsLimit(selected.size);
    this.elements.rename.disabled = !idle || !selected;
    this.elements.delete.disabled = !idle || !selected;
  }

  private renderDisconnected(channelLost = false, detail?: LocalizedText): void {
    this.entries = [];
    this.selectedIndex = -1;
    this.elements.tableBody.replaceChildren();
    this.elements.loading.hidden = true;
    this.elements.empty.hidden = true;
    this.elements.error.hidden = true;
    this.elements.path.value = '/';
    this.hideProgress();
    if (channelLost) this.setStatus(detail ?? DISCONNECTED_CHANNEL);
    else this.updateStatusText(DISCONNECTED);
    this.updateControls();
  }

  private describeClose(event: CloseEvent): LocalizedText | undefined {
    if (event.code === 1000) return undefined;
    const codeInfo = this.isChinese()
      ? `代码 ${event.code}${event.reason ? `：${event.reason}` : ''}`
      : `code ${event.code}${event.reason ? `: ${event.reason}` : ''}`;
    const base = DISCONNECTED_CHANNEL;
    return { zh: `${base.zh}（${codeInfo}）`, en: `${base.en} (${codeInfo})` };
  }

  private showError(message: string): void {
    this.elements.loading.hidden = true;
    this.elements.empty.hidden = true;
    this.elements.error.textContent = message;
    this.elements.error.hidden = false;
    this.updateStatusText({ zh: message, en: message });
    this.onError?.(message);
    this.updateControls();
  }

  private scheduleReconnect(): void {
    if (!this.wantConnection || !this.url || this.reconnectTimer !== null) return;
    this.reconnectAttempts++;
    if (this.reconnectAttempts > RECONNECT_MAX_ATTEMPTS) {
      console.log(
        `[WS-Reconnect] ${new Date().toISOString()} | SFTP | give_up | attempt=${this.reconnectAttempts - 1}/${RECONNECT_MAX_ATTEMPTS}`,
      );
      this.reconnectAttempts = 0;
      this.renderDisconnected(true, { zh: '文件管理重连失败。', en: 'File manager reconnect failed.' });
      return;
    }
    const delayIndex = this.reconnectAttempts - 1;
    const delay = delayIndex < RECONNECT_DELAYS.length
      ? RECONNECT_DELAYS[delayIndex]
      : RECONNECT_DELAYS[RECONNECT_DELAYS.length - 1];
    console.log(
      `[WS-Reconnect] ${new Date().toISOString()} | SFTP | reconnect_attempt | attempt=${this.reconnectAttempts}/${RECONNECT_MAX_ATTEMPTS}`,
    );
    this.setStatus({
      zh: '文件管理连接已断开，正在重连…',
      en: 'File manager disconnected; reconnecting…',
    });
    const attempts = this.reconnectAttempts;
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      if (!this.wantConnection || !this.url) return;
      try {
        this.attach(this.url);
      } catch {
        console.log(
          `[WS-Reconnect] ${new Date().toISOString()} | SFTP | reconnect_failed | attempt=${attempts}/${RECONNECT_MAX_ATTEMPTS}`,
        );
        // attach() → reset() zeroed the counter; restore so the next
        // close handler's scheduleReconnect() continues accumulating.
        if (this.wantConnection) {
          this.reconnectAttempts = attempts;
        }
        this.scheduleReconnect();
        return;
      }
      // Successful attach(). The open handler will log reconnect_success
      // once the WebSocket actually connects; for now restore the counter
      // so that if a close fires before open confirms, back-off continues.
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

  private setStatus(copy: LocalizedText): void {
    this.updateStatusText(copy);
    this.onStatus?.(this.localize(copy));
  }

  private updateStatusText(copy: LocalizedText): void {
    this.statusCopy = copy;
    this.elements.status.dataset.i18nZh = copy.zh;
    this.elements.status.dataset.i18nEn = copy.en;
    this.elements.status.textContent = this.localize(copy);
  }

  private showProgress(operation: 'upload' | 'download', name: string, percent: number): void {
    this.elements.progress.dataset.operation = operation;
    this.elements.progress.dataset.name = name;
    this.elements.progress.hidden = false;
    this.elements.progressCancel.disabled = false;
    this.elements.progressBar.value = Math.max(0, Math.min(100, percent));
    this.updateProgressLanguage();
  }

  private updateProgressLanguage(): void {
    if (this.elements.progress.hidden) return;
    const transfer = this.uploadState ?? this.downloadState;
    const operation = this.elements.progress.dataset.operation;
    const name = this.elements.progress.dataset.name ?? '';
    const verb = operation === 'upload'
      ? this.localize({ zh: '上传', en: 'Uploading' })
      : this.localize({ zh: '下载', en: 'Downloading' });
    this.elements.progressLabel.textContent = transfer?.cancelling
      ? this.localize({ zh: `正在取消 ${name}…`, en: `Cancelling ${name}…` })
      : `${verb} ${name} ${Math.round(this.elements.progressBar.value)}%`;
    this.elements.progressCancel.disabled = Boolean(transfer?.cancelling || this.uploadState?.endSent);
    this.elements.progressCancel.textContent = transfer?.cancelling
      ? this.localize({ zh: '取消中…', en: 'Cancelling…' })
      : this.localize({ zh: '取消', en: 'Cancel' });
  }

  private hideProgress(): void {
    this.elements.progress.hidden = true;
    this.elements.progressBar.value = 0;
    this.elements.progressLabel.textContent = '';
    this.elements.progressCancel.disabled = false;
    this.elements.progressCancel.textContent = this.localize({ zh: '取消', en: 'Cancel' });
    delete this.elements.progress.dataset.operation;
    delete this.elements.progress.dataset.name;
  }

  private formatSize(bytes: number | string): string {
    if (typeof bytes === 'string') return sizeExceedsLimit(bytes) ? '> 64 MiB' : this.formatSize(Number(bytes));
    if (bytes < 1024) return `${bytes} B`;
    const units = ['KiB', 'MiB', 'GiB'];
    let value = bytes;
    let unit = -1;
    do { value /= 1024; unit++; } while (value >= 1024 && unit < units.length - 1);
    return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
  }

  private formatDate(value: string | number): string {
    if (value === '') return '';
    const numeric = typeof value === 'number' ? (value < 10_000_000_000 ? value * 1000 : value) : value;
    const date = new Date(numeric);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat(this.isChinese() ? 'zh-CN' : 'en', {
      year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false,
    }).format(date);
  }

  private typeLabel(type: SFTPEntry['type']): LocalizedText {
    if (type === 'directory') return { zh: '文件夹', en: 'Folder' };
    if (type === 'file') return { zh: '文件', en: 'File' };
    if (type === 'symlink') return { zh: '链接', en: 'Link' };
    return { zh: '其他', en: 'Other' };
  }

  private saveBlob(blob: Blob, name: string): void {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  private localize(copy: LocalizedText): string {
    return this.isChinese() ? copy.zh : copy.en;
  }

  private isChinese(): boolean {
    return this.getLanguage().toLowerCase().startsWith('zh');
  }
}
