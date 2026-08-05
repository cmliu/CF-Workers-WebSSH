import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { historyKey, historyLabel, normalizeHistory, upsertHistoryIfNewer, type HistoryEntry } from './history';
import { getHistoryPasswordKey } from './history-key';
import { decryptPasswordResult, encryptPassword, isEncryptedPassword } from './password-crypto';
import { resolveConnectionControl, resolveConnectionPanel } from './ui-state';
import { classifyHostKey, SSH_FINGERPRINT_RE, type HostKeyPrompt } from './host-key';
import { FileManager, collectFileManagerElements } from './file-manager';
import { FileTree } from './file-tree';
import { ProcessManager, collectProcessManagerElements, type NetworkSample } from './process-manager';
import { resetTerminalForConnection } from './terminal-session';
import { WebSocketReconnectManager } from './ws-reconnect';
import type { ReconnectLogEntry } from './ws-reconnect';
import './style.css';

type AuthMethod = 'password' | 'publickey';
type ConnectionState = 'idle' | 'connecting' | 'connected' | 'disconnecting' | 'error';
type Language = 'zh-CN' | 'en';
type Translation = readonly [zh: string, en: string];

interface LocalizedMessage {
  zh: string;
  en: string;
}

type SavedProfile = HistoryEntry;

interface LegacySavedProfile extends Omit<SavedProfile, 'passwordEncrypted'> {
  name?: string;
  passwordBase64?: string;
}

interface StoredSavedProfile extends Omit<SavedProfile, 'passwordEncrypted'> {
  passwordEncrypted?: unknown;
}

interface PendingHistory {
  generation: number;
  target: string;
  profile: Promise<SavedProfile>;
}

type HistoryMutation =
  | { kind: 'upsert'; profile: SavedProfile }
  | { kind: 'delete'; target: string };

interface HistoryMutationResult {
  persisted: boolean;
  applied: boolean;
}

interface ConnectionConfig {
  type: 'connect';
  host: string;
  port: number;
  username: string;
  password?: string;
  authMethod: AuthMethod;
  privateKey?: string;
  cols: number;
  rows: number;
  term: string;
  expectedFingerprint?: string;
}

interface ServerMessage {
  type?: string;
  event?: string;
  message?: string;
  fingerprint?: string;
  expectedFingerprint?: string;
  keyType?: string;
  trusted?: boolean;
  latency?: number;
  colo?: string;
  ts?: number;
  algorithms?: Record<string, string>;
  url?: string;
}

interface WSSHOptions {
  hostname?: string;
  host?: string;
  port?: string | number;
  username?: string;
  password?: string;
  privatekey?: string;
  privateKey?: string;
  command?: string;
  term?: string;
  encoding?: string;
  fingerprint?: string;
}

interface WSSHCompatibilityAPI {
  connect: ((options?: WSSHOptions) => Promise<void>) &
    ((host: string, port?: string | number, username?: string, password?: string, privateKey?: string) => Promise<void>);
  send: (data: string) => void;
  resize: () => void;
  set_encoding: (encoding: string) => void;
  reset_encoding: () => void;
  disconnect: () => void;
}

declare global {
  interface Window {
    wssh: WSSHCompatibilityAPI;
  }
}

const PROFILE_STORAGE_KEY = 'workers-webssh.profiles.v2';
const LEGACY_PROFILE_STORAGE_KEY = 'workers-webssh.profiles.v1';
const HOST_KEY_STORAGE_KEY = 'workers-webssh.hostkeys.v1';
const THEME_STORAGE_KEY = 'workers-webssh.theme';
const LANGUAGE_STORAGE_KEY = 'workers-webssh.language';
const MAX_KEY_BYTES = 65_536;
const MAX_LEGACY_PASSWORD_BASE64_LENGTH = 16_384;
const PING_INTERVAL_MS = 25_000;
const CLIENT_CLOSE_SESSION_ERROR = 4000;
const CLIENT_CLOSE_PROTOCOL_ERROR = 4002;

function loadLanguage(): Language {
  try {
    const stored = localStorage.getItem(LANGUAGE_STORAGE_KEY);
    if (stored === 'zh-CN' || stored === 'en') return stored;
  } catch {
    // Fall back to the browser language when storage is unavailable.
  }
  return navigator.language.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en';
}

let currentLanguage = loadLanguage();
const generatedTranslations = new Map<string, LocalizedMessage>();

function bilingual(zh: string, en: string): string {
  const translation = localized(zh, en);
  generatedTranslations.set(zh, translation);
  generatedTranslations.set(en, translation);
  return currentLanguage === 'zh-CN' ? zh : en;
}

function localized(zh: string, en: string): LocalizedMessage {
  return { zh, en };
}

function localize(message: LocalizedMessage): string {
  return bilingual(message.zh, message.en);
}

const STATIC_MESSAGE_TRANSLATIONS: Record<string, string> = {
  '请输入有效的主机名或 IP 地址。': 'Enter a valid hostname or IP address.',
  '端口必须介于 1 和 65535 之间。': 'Port must be between 1 and 65535.',
  '请输入有效的 SSH 用户名。': 'Enter a valid SSH username.',
  '主机指纹必须使用 SHA256:base64 格式。': 'Host fingerprint must use the SHA256:base64 format.',
  '请粘贴或选择未加密的 OpenSSH 私钥。': 'Paste or choose an unencrypted OpenSSH private key.',
  '私钥大于 64 KiB。': 'The private key is larger than 64 KiB.',
  '仅支持未加密的 OpenSSH 私钥。': 'Only unencrypted OpenSSH private keys are supported.',
  '请检查必填项和字段格式。': 'Check the required fields and their formats.',
};

function messageTranslation(message: string, alternate?: string): LocalizedMessage {
  if (alternate) return currentLanguage === 'zh-CN' ? localized(message, alternate) : localized(alternate, message);
  const generated = generatedTranslations.get(message);
  if (generated) return generated;
  const english = STATIC_MESSAGE_TRANSLATIONS[message];
  if (english) return localized(message, english);
  const staticChinese = Object.entries(STATIC_MESSAGE_TRANSLATIONS).find(([, value]) => value === message)?.[0];
  if (staticChinese) return localized(staticChinese, message);
  const chinese = SERVER_MESSAGE_TRANSLATIONS[message];
  if (chinese) return localized(chinese, message);
  const serverEnglish = Object.entries(SERVER_MESSAGE_TRANSLATIONS).find(([, value]) => value === message)?.[0];
  if (serverEnglish) return localized(message, serverEnglish);
  return localized(message, message);
}

function translate([zh, en]: Translation): string {
  return bilingual(zh, en);
}

const EVENT_LABELS: Record<string, Translation> = {
  session: ['会话', 'session'],
  connect: ['连接', 'connect'],
  transport: ['传输', 'transport'],
  authorization: ['授权', 'authorization'],
  disconnect: ['断开', 'disconnect'],
  protocol: ['协议', 'protocol'],
  status: ['状态', 'status'],
  ready: ['就绪', 'ready'],
  error: ['错误', 'error'],
  debug: ['调试', 'debug'],
  'host-key': ['主机密钥', 'host key'],
  sftp: ['文件管理', 'files'],
};

const SERVER_EVENT_MESSAGES: Record<string, Translation> = {
  version_exchange: ['正在交换 SSH 协议版本', 'Exchanging SSH protocol versions'],
  version_ready: ['版本交换完成，正在协商密钥', 'Version exchange complete; negotiating keys'],
  tcp_connecting: ['正在连接 SSH 服务器', 'Connecting to the SSH server'],
  authenticating: ['加密传输已建立，正在认证', 'Encrypted transport established; authenticating'],
  host_key_confirmation: ['发送凭据前请确认此主机密钥', 'Confirm this host key before credentials are sent'],
  auth_success: ['SSH 认证成功，正在打开终端', 'SSH authentication succeeded; opening terminal'],
  shell_ready: ['Shell 已就绪', 'Shell is ready'],
  ready: ['交互式 Shell 已就绪', 'Interactive shell ready'],
  remote_closed: ['SSH 服务器已关闭连接', 'The SSH server closed the connection'],
  remote_eof: ['SSH 服务器已结束输出', 'SSH server finished sending output'],
  session_ended: ['SSH 会话已结束', 'SSH session ended'],
  keepalive_timeout: ['SSH 保活响应超时', 'SSH keepalive timed out'],
};

const SERVER_MESSAGE_TRANSLATIONS: Record<string, string> = {
  'Invalid request origin': '请求来源无效',
  'Expected application/json': '请求必须使用 application/json',
  'Unable to create a session ticket': '无法创建会话票据',
  'Invalid SSH host': 'SSH 主机无效',
  'Invalid SSH port': 'SSH 端口无效',
  'Invalid SSH username': 'SSH 用户名无效',
  'Invalid authentication method': '身份认证方式无效',
  'Unsupported connection field': '包含不支持的连接字段',
  'Invalid terminal size': '终端尺寸无效',
  'Invalid host key fingerprint': '主机密钥指纹无效',
  'SSH authentication failed': 'SSH 认证失败',
  'Host key was not accepted': '主机密钥未被接受',
  'SSH host key signature verification failed': 'SSH 主机密钥签名验证失败',
  'The server does not support SSH 2.0': '服务器不支持 SSH 2.0',
  'SSH compression is not supported': '不支持 SSH 压缩',
  'Server-initiated SSH rekey is not supported': '不支持由服务器发起的 SSH 重新密钥交换',
  'SSH rekey is not supported by this terminal session': '当前终端会话不支持 SSH 重新密钥交换',
  'The SSH server closed the connection': 'SSH 服务器已关闭连接',
  'SSH session ended': 'SSH 会话已结束',
  'Shell is ready': 'Shell 已就绪',
  'Terminal is not ready': '终端尚未就绪',
  'Terminal input queue limit exceeded': '终端输入队列已超出限制',
  'SSH keepalive timed out': 'SSH 保活响应超时',
  'Session closed': '会话已关闭',
  'SSH session failed': 'SSH 会话失败',
};

function bilingualServerMessage(message: string | undefined, eventName?: string, fallback?: string, summary = 'SSH 状态更新'): string {
  const english = message?.trim() || fallback || eventName || 'SSH status';
  const eventText = eventName ? SERVER_EVENT_MESSAGES[eventName] : undefined;
  if (eventText && (!message || message === eventName || eventText[1] === english)) return translate(eventText);
  if (currentLanguage === 'en') return english;
  if (/[\u3400-\u9fff]/.test(english)) return english;
  const chinese = SERVER_MESSAGE_TRANSLATIONS[english];
  return chinese ?? english ?? summary;
}

function element<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error(`Missing UI element #${id}`);
  return node as T;
}

const ui = {
  panel: element<HTMLElement>('connection-panel'),
  panelToggle: element<HTMLButtonElement>('panel-toggle'),
  panelScrim: element<HTMLButtonElement>('panel-scrim'),
  profileList: element<HTMLElement>('profile-list'),
  profileCount: element<HTMLElement>('profile-count'),
  form: element<HTMLFormElement>('connection-form'),
  profileId: element<HTMLInputElement>('profile-id'),
  host: element<HTMLInputElement>('host'),
  port: element<HTMLInputElement>('port'),
  username: element<HTMLInputElement>('username'),
  password: element<HTMLInputElement>('password'),
  passwordField: element<HTMLElement>('password-field'),
  revealPassword: element<HTMLButtonElement>('reveal-password'),
  keyField: element<HTMLElement>('key-field'),
  privateKey: element<HTMLTextAreaElement>('private-key'),
  keyFile: element<HTMLInputElement>('key-file'),
  keyFileName: element<HTMLElement>('key-file-name'),
  initialCommand: element<HTMLInputElement>('initial-command'),
  termType: element<HTMLSelectElement>('term-type'),
  encoding: element<HTMLSelectElement>('encoding'),
  fingerprint: element<HTMLInputElement>('fingerprint'),
  formError: element<HTMLElement>('form-error'),
  connect: element<HTMLButtonElement>('connect-button'),
  shareLink: element<HTMLButtonElement>('share-link'),
  languageToggle: element<HTMLButtonElement>('language-toggle'),
  themeToggle: element<HTMLButtonElement>('theme-toggle'),
  sessionTitle: element<HTMLElement>('session-title'),
  sessionSubtitle: element<HTMLElement>('session-subtitle'),
  liveOrb: element<HTMLElement>('live-orb'),
  liveOrbLabel: element<HTMLElement>('live-orb-label'),
  metricUptime: element<HTMLElement>('metric-uptime'),
  metricHostKey: element<HTMLElement>('metric-host-key'),
  resourceNetwork: element<HTMLElement>('resource-network'),
  resourceNetworkIface: element<HTMLElement>('resource-network-iface'),
  resourceNetworkSelect: element<HTMLSelectElement>('resource-network-select'),
  resourceNetworkRateUp: element<HTMLElement>('resource-network-rate-up'),
  resourceNetworkRateDown: element<HTMLElement>('resource-network-rate-down'),
  resourceNetworkSparkline: element<HTMLCanvasElement>('resource-network-sparkline'),
  terminalCard: element<HTMLElement>('terminal-card'),
  terminalStage: element<HTMLElement>('terminal-stage'),
  terminalElement: element<HTMLElement>('terminal'),
  terminalEmpty: element<HTMLElement>('terminal-empty'),
  emptyConnect: element<HTMLButtonElement>('empty-connect'),
  clearTerminal: element<HTMLButtonElement>('clear-terminal'),
  fullscreenTerminal: element<HTMLButtonElement>('fullscreen-terminal'),
  eventMessage: element<HTMLElement>('event-message'),
  fileManagerTab: element<HTMLButtonElement>('file-manager-tab'),
  fileManagerPanel: element<HTMLElement>('file-manager-panel'),
  fileTree: element<HTMLElement>('file-tree'),
  processManagerTab: element<HTMLButtonElement>('process-manager-tab'),
  processManagerPanel: element<HTMLElement>('process-manager-panel'),
  eventToggle: element<HTMLButtonElement>('event-toggle'),
  eventLog: element<HTMLElement>('event-log'),
  toastRegion: element<HTMLElement>('toast-region'),
  hostKeyDialog: element<HTMLDialogElement>('host-key-dialog'),
  hostKeyIcon: element<HTMLElement>('host-key-icon'),
  hostKeyEyebrow: element<HTMLElement>('host-key-eyebrow'),
  hostKeyTitle: element<HTMLElement>('host-key-title'),
  hostKeyDescription: element<HTMLElement>('host-key-description'),
  hostKeyTarget: element<HTMLElement>('host-key-target'),
  hostKeyType: element<HTMLElement>('host-key-type'),
  hostKeyExpectedRow: element<HTMLElement>('host-key-expected-row'),
  hostKeyExpectedFingerprint: element<HTMLElement>('host-key-expected-fingerprint'),
  hostKeyFingerprint: element<HTMLElement>('host-key-fingerprint'),
  rememberHostKey: element<HTMLInputElement>('remember-host-key'),
  rememberHostKeyLabel: element<HTMLElement>('remember-host-key-label'),
  rejectHostKey: element<HTMLButtonElement>('reject-host-key'),
  acceptHostKey: element<HTMLButtonElement>('accept-host-key'),
};

function updateRevealPasswordButton(): void {
  const revealed = ui.password.type === 'text';
  ui.revealPassword.setAttribute('aria-pressed', revealed ? 'true' : 'false');
  ui.revealPassword.setAttribute('aria-label', revealed
    ? bilingual('隐藏密码', 'Hide password')
    : bilingual('显示密码', 'Show password'));
}

function applyLanguage(language: Language, persist = false): void {
  currentLanguage = language;
  document.documentElement.lang = language;
  document.documentElement.dataset.language = language;

  for (const node of document.querySelectorAll<HTMLElement>('[data-i18n-zh][data-i18n-en]')) {
    node.textContent = language === 'zh-CN' ? node.dataset.i18nZh! : node.dataset.i18nEn!;
  }
  for (const node of document.querySelectorAll<HTMLElement>('[data-i18n-placeholder-zh][data-i18n-placeholder-en]')) {
    node.setAttribute('placeholder', language === 'zh-CN' ? node.dataset.i18nPlaceholderZh! : node.dataset.i18nPlaceholderEn!);
  }
  for (const node of document.querySelectorAll<HTMLElement>('[data-i18n-aria-label-zh][data-i18n-aria-label-en]')) {
    node.setAttribute('aria-label', language === 'zh-CN' ? node.dataset.i18nAriaLabelZh! : node.dataset.i18nAriaLabelEn!);
  }
  for (const node of document.querySelectorAll<HTMLElement>('[data-i18n-title-zh][data-i18n-title-en]')) {
    node.setAttribute('title', language === 'zh-CN' ? node.dataset.i18nTitleZh! : node.dataset.i18nTitleEn!);
  }
  for (const node of document.querySelectorAll<HTMLElement>('[data-i18n-content-zh][data-i18n-content-en]')) {
    node.setAttribute('content', language === 'zh-CN' ? node.dataset.i18nContentZh! : node.dataset.i18nContentEn!);
  }

  const toggleLabel = language === 'zh-CN' ? '切换到英文' : 'Switch to Chinese';
  ui.languageToggle.dataset.language = language;
  ui.languageToggle.setAttribute('aria-label', toggleLabel);
  ui.languageToggle.title = toggleLabel;
  updateRevealPasswordButton();
  if (!ui.keyFile.files?.length) ui.keyFileName.textContent = bilingual('未选择文件', 'No file selected');
  ui.sessionSubtitle.textContent = localize(currentSessionSubtitle);
  ui.eventMessage.textContent = localize(currentEventMessage);
  if (currentFormError && !ui.formError.hidden) ui.formError.textContent = localize(currentFormError);
  for (const line of ui.eventLog.querySelectorAll<HTMLElement>('.event-line')) {
    const category = line.dataset.category ?? 'session';
    const label = line.querySelector<HTMLElement>('strong');
    const copy = line.querySelector<HTMLElement>('span');
    if (label) label.textContent = EVENT_LABELS[category] ? translate(EVENT_LABELS[category]) : bilingual('SSH 事件', category);
    if (copy?.dataset.messageZh && copy.dataset.messageEn) {
      copy.textContent = bilingual(copy.dataset.messageZh, copy.dataset.messageEn);
    }
  }
  if (fileManager) fileManager.setLanguage();
  if (fileTree) fileTree.setLanguage();
  if (processManager) processManager.setLanguage();

  if (persist) {
    try { localStorage.setItem(LANGUAGE_STORAGE_KEY, language); } catch { /* Language still applies for this page. */ }
  }
}

let profiles: SavedProfile[] = [];
let hostKeys = loadHostKeys();
let socket: WebSocket | null = null;
let connectionState: ConnectionState = 'idle';
let sessionStartedAt = 0;
let uptimeTimer: number | null = null;
let pingTimer: number | null = null;
let pendingHostKey: HostKeyPrompt | null = null;
let currentTargetKey = '';
let currentTargetLabel = '';
let currentInitialCommand = '';
let initialCommandSent = false;
let decoder = new TextDecoder('utf-8');
let resizeFrame = 0;
let awaitingHostKeyDecision = false;
let connectGeneration = 0;
let authorizationAbort: AbortController | null = null;
let currentExpectedFingerprint = '';
let currentRememberedFingerprint = '';
let currentSessionSubtitle: LocalizedMessage = { zh: '选择目标并连接', en: 'Choose a target and connect' };
let currentSessionId = '';
let currentEventMessage: LocalizedMessage = { zh: 'Worker 运行时待命', en: 'Worker runtime standing by' };
let currentFormError: LocalizedMessage | null = null;
let passwordDirty = false;
let pendingHistory: PendingHistory | null = null;
let historyPasswordLoading = false;
let historyPasswordLoadGeneration = 0;
let historyMutationSequence = 0;
let keyFileReadGeneration = 0;
const latestHistoryMutation = new Map<string, number>();
let panelOpen = false;
let fileManager: FileManager;
let fileTree: FileTree;
let processManager: ProcessManager;
let sshReconnectManager: WebSocketReconnectManager | null = null;
let reconnectParams: {
  host: string; port: number; username: string; authMethod: string;
  password?: string; privateKey?: string; pinnedKey?: string;
  term: string; encoding: string;
} | null = null;

// Network rate state. The backend sends cumulative byte counters per interface
// per tick; we keep a per-interface baseline (counters + local clock timestamp)
// so switching the selected interface — or the server reporting a different
// set — never produces a bogus one-shot rate spike. `netIfaceList` is the
// deduplicated, order-preserving list of interfaces present in the latest tick;
// `netSelectedIface` stays null until the first tick resolves a default.
// 60-point ring buffer of the per-tick throughput magnitude (max of rx/tx).
// The newest sample lives at `netSparkIdx - 1`; the oldest at `netSparkIdx`
// once the buffer wraps, or at index 0 while it is still filling.
const NET_SPARK_POINTS = 60;
const netSpark = new Float32Array(NET_SPARK_POINTS);
let netSparkIdx = 0;
let netSparkFilled = 0;
const netBaselines = new Map<string, { rx: number; tx: number; ts: number }>();
let netIfaceList: string[] = [];
let netSelectedIface: string | null = null;

const NET_RATE_UNITS = ['B', 'KB', 'MB', 'GB'] as const;

function formatNetworkRate(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return '0 B/s';
  let v = value;
  let unitIndex = 0;
  while (v >= 1024 && unitIndex < NET_RATE_UNITS.length - 1) {
    v /= 1024;
    unitIndex += 1;
  }
  const text = v < 10 ? v.toFixed(1) : v.toFixed(0);
  return `${text}${NET_RATE_UNITS[unitIndex]}/s`;
}

function drawNetworkSparkline(): void {
  const canvas = ui.resourceNetworkSparkline;
  const dpr = window.devicePixelRatio && window.devicePixelRatio > 0 ? window.devicePixelRatio : 1;
  // Use clientWidth (CSS px) scaled by DPR for the backing store, so the
  // bitmap stays crisp on Hi-DPI displays without forcing the parent layout.
  const cssWidth = canvas.clientWidth || 184;
  const cssHeight = canvas.clientHeight || 22;
  const width = Math.max(1, Math.round(cssWidth * dpr));
  const height = Math.max(1, Math.round(cssHeight * dpr));
  if (canvas.width !== width) canvas.width = width;
  if (canvas.height !== height) canvas.height = height;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  ctx.clearRect(0, 0, width, height);
  if (netSparkFilled === 0) return;
  // Build a chronological copy so the rest of the math is index-stable.
  const data = new Array<number>(NET_SPARK_POINTS).fill(0);
  const start = netSparkFilled < NET_SPARK_POINTS ? 0 : netSparkIdx;
  for (let i = 0; i < NET_SPARK_POINTS; i += 1) {
    data[i] = netSpark[(start + i) % NET_SPARK_POINTS];
  }
  let minimum = data[0];
  let maximum = data[0];
  for (const v of data) {
    if (v < minimum) minimum = v;
    if (v > maximum) maximum = v;
  }
  // `span = max(mx - mn, 1)` keeps the bar heights defined even when every
  // sample is identical (all bars collapse to the zero-line without div-by-zero).
  const span = Math.max(maximum - minimum, 1);
  const slot = width / NET_SPARK_POINTS;
  // Leave a small gap between bars; floor so a 1px slot still draws a visible bar.
  const barWidth = Math.max(1, Math.floor(slot * 0.7));
  ctx.fillStyle = '#69e6b4';
  for (let i = 0; i < NET_SPARK_POINTS; i += 1) {
    const value = data[i];
    const normalized = (value - minimum) / span;
    const barHeight = Math.max(1, Math.round(normalized * (height - 1)));
    const x = Math.round(i * slot + ((slot - barWidth) / 2));
    const y = height - barHeight;
    ctx.fillRect(x, y, barWidth, barHeight);
  }
}

// Rebuilds the `<select>` options only when the interface list changed, so a
// rapid tick cannot recreate the element under an open dropdown (which would
// drop focus). The iface label always follows the currently selected interface.
function syncNetworkSelectOptions(): void {
  const select = ui.resourceNetworkSelect;
  const existing = Array.from(select.options).map((option) => option.value);
  const unchanged = existing.length === netIfaceList.length
    && existing.every((value, index) => value === netIfaceList[index]);
  if (unchanged) return;
  select.replaceChildren();
  for (const iface of netIfaceList) {
    const option = document.createElement('option');
    option.value = iface;
    option.textContent = iface;
    select.append(option);
  }
}

// Reflects the current interface list / selection in the toolbar: a single
// interface keeps the plain-text label, two or more reveal the native select
// (which itself displays the chosen interface name, so the redundant
// plain-text label is hidden while the select is shown).
function updateNetworkIfaceLabel(): void {
  const select = ui.resourceNetworkSelect;
  const multi = netIfaceList.length > 1;
  ui.resourceNetworkIface.textContent = netSelectedIface ?? '-';
  ui.resourceNetworkIface.hidden = multi;
  select.hidden = !multi;
  if (multi) {
    syncNetworkSelectOptions();
    select.value = netSelectedIface ?? '';
  }
}

// Sole entry point for resetting the rate baseline. Called on interface
// switch (manual or automatic fallback) and on full teardown; do NOT clear
// baseline state by hand anywhere else.
function resetNetworkBaseline(): void {
  netBaselines.clear();
  netSpark.fill(0);
  netSparkIdx = 0;
  netSparkFilled = 0;
  drawNetworkSparkline();
  ui.resourceNetworkRateUp.textContent = `↑ ${formatNetworkRate(0)}`;
  ui.resourceNetworkRateDown.textContent = `↓ ${formatNetworkRate(0)}`;
}

function updateNetworkMetric(samples: NetworkSample[] | null, timestamp: number): void {
  if (!samples || samples.length === 0) {
    // The server may briefly stop sending a network section (e.g. busybox
    // sh without /sys/class/net). Don't tear down the toolbar block on a
    // single missing tick — only reset on a full teardown. The next valid
    // sample will overwrite the UI state.
    return;
  }
  if (ui.resourceNetwork.hidden) ui.resourceNetwork.hidden = false;

  // Deduplicated, order-preserving interface list for this tick. A tick may
  // carry the same interface twice (server fallback); only the first
  // occurrence is kept so the selector stays stable.
  const list: string[] = [];
  const seen = new Set<string>();
  for (const sample of samples) {
    if (seen.has(sample.iface)) continue;
    seen.add(sample.iface);
    list.push(sample.iface);
  }
  netIfaceList = list;

  // Resolve the selected interface: keep the user's choice while it is still
  // present, otherwise fall back to eth0 (or the first interface in order).
  const previousSelection = netSelectedIface;
  if (netSelectedIface === null || !netIfaceList.includes(netSelectedIface)) {
    netSelectedIface = netIfaceList.includes('eth0') ? 'eth0' : netIfaceList[0];
  }
  if (netSelectedIface !== previousSelection) {
    // Interface changed (user switch or automatic fallback): a fresh baseline
    // prevents a bogus one-shot rate spike across different counters.
    resetNetworkBaseline();
  }

  // Prune baselines for interfaces that disappeared (e.g. cable unplugged).
  for (const iface of netBaselines.keys()) {
    if (!netIfaceList.includes(iface)) netBaselines.delete(iface);
  }

  const selected = netSelectedIface;
  const sample = samples.find((entry) => entry.iface === selected);
  if (!sample) {
    // The selected interface is absent from this tick (mid-switch); keep the
    // current UI until the next tick provides it again.
    return;
  }

  const baseline = netBaselines.get(selected);
  if (!baseline) {
    // First sample for the selected interface: stash the counters and
    // timestamp; rate and sparkline both show zero until we have a second
    // sample to diff against.
    netBaselines.set(selected, { rx: sample.rxBytes, tx: sample.txBytes, ts: timestamp });
    drawNetworkSparkline();
    ui.resourceNetworkRateUp.textContent = `↑ ${formatNetworkRate(0)}`;
    ui.resourceNetworkRateDown.textContent = `↓ ${formatNetworkRate(0)}`;
    updateNetworkIfaceLabel();
    return;
  }

  // `timestamp` is in milliseconds; clamp to a tiny positive value so a
  // pathological zero/negative delta (rare clock skew) cannot divide-by-zero
  // or produce an infinite rate.
  const deltaSeconds = Math.max(0.001, (timestamp - baseline.ts) / 1000);
  const deltaRx = Math.max(0, sample.rxBytes - baseline.rx);
  const deltaTx = Math.max(0, sample.txBytes - baseline.tx);
  const rxRate = deltaRx / deltaSeconds;
  const txRate = deltaTx / deltaSeconds;
  netBaselines.set(selected, { rx: sample.rxBytes, tx: sample.txBytes, ts: timestamp });
  // Use the larger of the two rates as the sparkline magnitude so a
  // quiescent direction doesn't make the chart look half-dead.
  const magnitude = Math.max(rxRate, txRate);
  netSpark[netSparkIdx] = magnitude;
  netSparkIdx = (netSparkIdx + 1) % NET_SPARK_POINTS;
  if (netSparkFilled < NET_SPARK_POINTS) netSparkFilled += 1;
  drawNetworkSparkline();
  // `↑` = upload (tx), `↓` = download (rx) — match the toolbar arrow convention.
  ui.resourceNetworkRateUp.textContent = `↑ ${formatNetworkRate(txRate)}`;
  ui.resourceNetworkRateDown.textContent = `↓ ${formatNetworkRate(rxRate)}`;
  updateNetworkIfaceLabel();
}

function resetNetworkMetric(): void {
  // Idempotent: only touch the DOM / state if the block is currently visible
  // or still carries live state, so repeated resets (one per
  // processManager.reset() call site) are cheap.
  if (ui.resourceNetwork.hidden && netSelectedIface === null && netBaselines.size === 0) return;
  ui.resourceNetwork.hidden = true;
  netIfaceList = [];
  netSelectedIface = null;
  const select = ui.resourceNetworkSelect;
  select.replaceChildren();
  select.hidden = true;
  // Restore the default single-card presentation: the plain-text label is
  // visible again and the select is hidden, so a fresh session starts from a
  // clean state regardless of the previous multi-card visibility toggle.
  ui.resourceNetworkIface.hidden = false;
  ui.resourceNetworkIface.textContent = '-';
  resetNetworkBaseline();
}

const terminal = new Terminal({
  allowProposedApi: false,
  convertEol: false,
  cursorBlink: true,
  cursorStyle: 'block',
  fontFamily: 'Cascadia Code, SFMono-Regular, Consolas, Liberation Mono, monospace',
  fontSize: 13,
  lineHeight: 1.18,
  letterSpacing: 0,
  scrollback: 10_000,
  tabStopWidth: 8,
  theme: terminalTheme(),
});
const fitAddon = new FitAddon();
terminal.loadAddon(fitAddon);
terminal.loadAddon(new WebLinksAddon());
terminal.open(ui.terminalElement);
fileManager = new FileManager({
  elements: collectFileManagerElements(),
  getLanguage: () => currentLanguage,
  onError: (message) => event(message, 'sftp', true),
  onStatus: (message) => event(message, 'sftp'),
});
fileTree = new FileTree({
  container: ui.fileTree,
  fetchEntries: (path) => fileManager.fetchDirectoryEntries(path),
  getLanguage: () => currentLanguage,
  onNavigate: (path) => fileManager.navigate(path),
  onError: (message) => event(message, 'sftp', true),
  initialRoot: '/',
});
fileManager.onCwdChange((cwd) => fileTree.setCwd(cwd));
processManager = new ProcessManager({
  elements: collectProcessManagerElements(),
  getLanguage: () => currentLanguage,
  onError: (message) => event(message, 'process', true),
  onReconnect: (zh, en) => event(bilingual(zh, en), 'process'),
  onToast: (zh, en, kind) => toast(bilingual(zh, en), kind),
  onNetworkSample: (sample, timestamp) => updateNetworkMetric(sample, timestamp),
});

function terminalTheme(): Record<string, string> {
  return {
    background: '#080d12',
    foreground: '#d7e2e6',
    cursor: '#69e6b4',
    cursorAccent: '#080d12',
    selectionBackground: '#294b43',
    black: '#121b22',
    red: '#ff7b82',
    green: '#69e6b4',
    yellow: '#f5c76b',
    blue: '#70b7ff',
    magenta: '#c69cff',
    cyan: '#67d8e7',
    white: '#d7e2e6',
    brightBlack: '#647782',
    brightRed: '#ff9a9f',
    brightGreen: '#94f2ca',
    brightYellow: '#ffe09b',
    brightBlue: '#a4d2ff',
    brightMagenta: '#ddc1ff',
    brightCyan: '#99edf5',
    brightWhite: '#f7fbfc',
  };
}

function isStoredSavedProfile(value: unknown): value is StoredSavedProfile {
  if (!value || typeof value !== 'object') return false;
  const item = value as Partial<StoredSavedProfile>;
  return (
    typeof item.id === 'string' &&
    typeof item.host === 'string' &&
    item.host.length >= 1 && item.host.length <= 253 && !/[\s/?#]/.test(item.host) &&
    typeof item.port === 'number' &&
    Number.isInteger(item.port) &&
    item.port >= 1 &&
    item.port <= 65_535 &&
    typeof item.username === 'string' &&
    item.username.length >= 1 && item.username.length <= 128 && !/[\r\n\0]/.test(item.username) &&
    (item.authMethod === 'password' || item.authMethod === 'publickey') &&
    typeof item.initialCommand === 'string' &&
    item.initialCommand.length <= 4096 &&
    typeof item.termType === 'string' &&
    /^[A-Za-z0-9._+-]{1,64}$/.test(item.termType) &&
    typeof item.encoding === 'string' &&
    ['utf-8', 'gb18030', 'big5'].includes(item.encoding) &&
    typeof item.fingerprint === 'string' &&
    (item.fingerprint === '' || SSH_FINGERPRINT_RE.test(item.fingerprint)) &&
    typeof item.updatedAt === 'number' &&
    Number.isFinite(item.updatedAt) &&
    item.updatedAt >= 0 &&
    item.updatedAt <= 8_640_000_000_000_000
  );
}

function sanitizeSavedProfile(value: unknown): SavedProfile | null {
  if (!isStoredSavedProfile(value)) return null;
  const profile: SavedProfile = {
    id: value.id,
    host: value.host,
    port: value.port,
    username: value.username,
    authMethod: value.authMethod,
    initialCommand: value.initialCommand,
    termType: value.termType,
    encoding: value.encoding,
    fingerprint: value.fingerprint,
    updatedAt: value.updatedAt,
  };
  if (value.authMethod === 'password' && isEncryptedPassword(value.passwordEncrypted)) {
    profile.passwordEncrypted = value.passwordEncrypted;
  }
  return profile;
}

function isLegacySavedProfile(value: unknown): value is LegacySavedProfile {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const item = value as Partial<LegacySavedProfile>;
  return typeof item.id === 'string'
    && typeof item.host === 'string' && item.host.length >= 1 && item.host.length <= 253 && !/[\s/?#]/.test(item.host)
    && typeof item.port === 'number' && Number.isInteger(item.port) && item.port >= 1 && item.port <= 65_535
    && typeof item.username === 'string' && item.username.length >= 1 && item.username.length <= 128 && !/[\r\n\0]/.test(item.username)
    && (item.authMethod === 'password' || item.authMethod === 'publickey')
    && (item.passwordBase64 === undefined || (
      typeof item.passwordBase64 === 'string'
      && item.passwordBase64.length <= MAX_LEGACY_PASSWORD_BASE64_LENGTH
      && /^[A-Za-z0-9+/]*={0,2}$/.test(item.passwordBase64)
    ))
    && typeof item.initialCommand === 'string' && item.initialCommand.length <= 4096
    && typeof item.termType === 'string' && /^[A-Za-z0-9._+-]{1,64}$/.test(item.termType)
    && typeof item.encoding === 'string' && ['utf-8', 'gb18030', 'big5'].includes(item.encoding)
    && typeof item.fingerprint === 'string' && (item.fingerprint === '' || SSH_FINGERPRINT_RE.test(item.fingerprint))
    && typeof item.updatedAt === 'number' && Number.isFinite(item.updatedAt)
    && item.updatedAt >= 0 && item.updatedAt <= 8_640_000_000_000_000;
}

function decodeLegacyPassword(encoded: string): string | null {
  try {
    const binary = atob(encoded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    const password = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (password.length > 4096) return null;
    let canonical = '';
    for (const byte of new TextEncoder().encode(password)) canonical += String.fromCharCode(byte);
    return btoa(canonical) === encoded ? password : null;
  } catch {
    return null;
  }
}

function passwordContext(profile: Pick<SavedProfile, 'host' | 'port' | 'username'>): string {
  return historyKey(profile.host, profile.port, profile.username);
}

function mergeSavedProfiles(preferred: SavedProfile[], fallback: SavedProfile[]): SavedProfile[] {
  // Credentials are part of an atomic profile revision. Inheriting a password
  // from an older revision could revive a deliberately cleared credential.
  return normalizeHistory([...preferred, ...fallback]);
}

async function migrateLegacyProfiles(values: unknown[]): Promise<SavedProfile[]> {
  const key = await getHistoryPasswordKey();
  const migrated = await Promise.all(values.map(async (value): Promise<SavedProfile | null> => {
    if (!isLegacySavedProfile(value)) return null;
    const profile: SavedProfile = {
      id: value.id,
      host: value.host,
      port: value.port,
      username: value.username,
      authMethod: value.authMethod,
      initialCommand: value.initialCommand,
      termType: value.termType,
      encoding: value.encoding,
      fingerprint: value.fingerprint,
      updatedAt: value.updatedAt,
    };
    const hasStoredPassword = value.authMethod === 'password' && value.passwordBase64 !== undefined;
    const password = hasStoredPassword ? decodeLegacyPassword(value.passwordBase64!) : null;
    if (password !== null) {
      if (key) {
        try {
          profile.passwordEncrypted = await encryptPassword(password, key, passwordContext(profile));
        } catch { /* Preserve metadata and discard the reversible password below. */ }
      }
    }
    return profile;
  }));
  return normalizeHistory(migrated.filter((profile): profile is SavedProfile => profile !== null));
}

interface StoredArray {
  present: boolean;
  values: unknown[];
}

function readStoredArray(storageKey: string): StoredArray {
  let serialized: string | null;
  try {
    serialized = localStorage.getItem(storageKey);
  } catch {
    return { present: false, values: [] };
  }
  if (serialized === null) return { present: false, values: [] };
  try {
    const parsed: unknown = JSON.parse(serialized);
    return { present: true, values: Array.isArray(parsed) ? parsed : [] };
  } catch {
    return { present: true, values: [] };
  }
}

async function loadProfilesWithoutLock(): Promise<SavedProfile[]> {
  const currentStorage = readStoredArray(PROFILE_STORAGE_KEY);
  const current = normalizeHistory(currentStorage.values
      .map(sanitizeSavedProfile)
      .filter((profile): profile is SavedProfile => profile !== null));
  const legacyStorage = readStoredArray(LEGACY_PROFILE_STORAGE_KEY);
  if (!legacyStorage.present) return current;

  const migrated = await migrateLegacyProfiles(legacyStorage.values);
  const merged = mergeSavedProfiles(current, migrated);

  try {
    localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify(merged));
    // v1 contains reversible passwords. Once v2 metadata is durable, never keep
    // an unencrypted fallback; failed credentials intentionally become empty.
    localStorage.removeItem(LEGACY_PROFILE_STORAGE_KEY);
  } catch {
    // Keep the in-memory migration result and retry cleanup on a later load.
  }
  return merged;
}

function loadCurrentProfiles(): SavedProfile[] {
  return normalizeHistory(readStoredArray(PROFILE_STORAGE_KEY).values
    .map(sanitizeSavedProfile)
    .filter((profile): profile is SavedProfile => profile !== null));
}

async function loadProfiles(): Promise<SavedProfile[]> {
  // Local Storage has no cross-tab transaction primitive. In browsers without
  // Web Locks, migrate only when v2 is absent; once it exists, prefer a safe
  // read over an unlocked merge that can lose another tab's changes.
  if (!('locks' in navigator)) {
    return readStoredArray(PROFILE_STORAGE_KEY).present
      ? loadCurrentProfiles()
      : loadProfilesWithoutLock();
  }
  try {
    return await navigator.locks.request('workers-webssh.profiles.v2', loadProfilesWithoutLock);
  } catch {
    // A rejected lock request must not keep the entire application hidden.
    // Avoid an unlocked v1 migration here because it could overwrite another tab.
    return loadCurrentProfiles();
  }
}

function loadHostKeys(): Record<string, string> {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(HOST_KEY_STORAGE_KEY) ?? '{}');
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return Object.fromEntries(
      Object.entries(parsed).filter(([key, value]) => key.length <= 512 && typeof value === 'string' && SSH_FINGERPRINT_RE.test(value)),
    );
  } catch {
    return {};
  }
}

function persistProfileSnapshot(): boolean {
  try {
    localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify(profiles));
    return true;
  } catch {
    return false;
  }
}

async function persistHistoryMutation(mutation: HistoryMutation): Promise<HistoryMutationResult> {
  const write = (): HistoryMutationResult => {
    const snapshot = readStoredArray(PROFILE_STORAGE_KEY);
    const stored = snapshot.values
      .map(sanitizeSavedProfile)
      .filter((profile): profile is SavedProfile => profile !== null);
    const base = snapshot.present ? normalizeHistory(stored) : profiles;
    if (mutation.kind === 'upsert') {
      const update = upsertHistoryIfNewer(base, mutation.profile);
      profiles = update.entries;
      if (!update.applied) return { persisted: true, applied: false };
    } else {
      profiles = base.filter((profile) => passwordContext(profile) !== mutation.target);
      if (profiles.length === base.length) return { persisted: true, applied: false };
    }
    if (!persistProfileSnapshot()) {
      profiles = base;
      return { persisted: false, applied: false };
    }
    return { persisted: true, applied: true };
  };
  if (!('locks' in navigator)) {
    // Older browsers have no serializable local-storage transaction. A fresh
    // read still minimizes the conflict window while preserving functionality.
    return write();
  }
  try {
    return await navigator.locks.request('workers-webssh.profiles.v2', write);
  } catch {
    // If Web Locks exists but rejects the request, an unlocked read-modify-write
    // could silently discard another tab's history.
    return { persisted: false, applied: false };
  }
}

function persistHostKeys(): boolean {
  try {
    localStorage.setItem(HOST_KEY_STORAGE_KEY, JSON.stringify(hostKeys));
    return true;
  } catch {
    toast(bilingual('此浏览器无法保存主机指纹。', 'Host fingerprints could not be saved in this browser.'), 'error');
    return false;
  }
}

async function replaceRememberedHostKey(target: string, fingerprint: string): Promise<void> {
  const write = (): boolean => {
    const snapshot = readStoredArray(PROFILE_STORAGE_KEY);
    const stored = snapshot.values
      .map(sanitizeSavedProfile)
      .filter((profile): profile is SavedProfile => profile !== null);
    const base = snapshot.present ? normalizeHistory(stored) : profiles;
    const baseHostKeys = loadHostKeys();
    const updated = base.map((profile) => passwordContext(profile) === target
      ? { ...profile, fingerprint }
      : profile);
    try {
      localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify(updated));
      hostKeys = { ...baseHostKeys, [target]: fingerprint };
      if (!persistHostKeys()) throw new Error('Host key persistence failed');
      profiles = updated;
      return true;
    } catch {
      hostKeys = baseHostKeys;
      try { localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify(base)); } catch { /* Best-effort rollback. */ }
      return false;
    }
  };
  let persisted = false;
  try {
    persisted = 'locks' in navigator
      ? await navigator.locks.request('workers-webssh.profiles.v2', write)
      : write();
  } catch {
    persisted = false;
  }
  if (!persisted) toast(bilingual(
    '当前连接已接受新指纹，但无法在此浏览器中记住。',
    'The new fingerprint was accepted for this connection but could not be remembered in this browser.',
  ), 'error');
  renderProfiles();
}

function authMethod(): AuthMethod {
  const checked = ui.form.querySelector<HTMLInputElement>('input[name="authMethod"]:checked');
  return checked?.value === 'publickey' ? 'publickey' : 'password';
}

function setAuthMethod(method: AuthMethod): void {
  const radio = ui.form.querySelector<HTMLInputElement>(`input[name="authMethod"][value="${method}"]`);
  if (radio) radio.checked = true;
  ui.passwordField.hidden = method !== 'password';
  ui.keyField.hidden = method !== 'publickey';
}

function cancelHistoryPasswordLoad(): void {
  if (!historyPasswordLoading) return;
  historyPasswordLoadGeneration++;
  historyPasswordLoading = false;
  setState(connectionState);
}

function resetPasswordField(): void {
  ui.password.value = '';
  ui.password.type = 'password';
  passwordDirty = false;
  updateRevealPasswordButton();
}

function clearPrivateKeyFields(): void {
  keyFileReadGeneration++;
  ui.privateKey.value = '';
  ui.keyFile.value = '';
  ui.keyFileName.textContent = bilingual('未选择文件', 'No file selected');
}

function clearCredentials(): void {
  resetPasswordField();
  clearPrivateKeyFields();
}

// A stale async history-password decrypt must never overwrite the form. The
// connection lifecycle keeps the entered credentials in place (history can
// restore them anyway), so only the in-flight load is invalidated here.
function invalidateHistoryPasswordLoad(): void {
  historyPasswordLoadGeneration++;
  historyPasswordLoading = false;
}

function normalizeHost(host: string): string {
  const trimmed = host.trim();
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) return trimmed.slice(1, -1);
  return trimmed;
}

function targetKey(host = normalizeHost(ui.host.value), port = Number(ui.port.value), username = ui.username.value.trim()): string {
  return historyKey(host, port, username);
}

function targetLabel(host: string, port: number, username: string): string {
  return historyLabel(host, port, username);
}

function applyFormDefaults(): void {
  if (!ui.username.value.trim()) ui.username.value = 'root';
  if (!ui.port.value.trim() && !ui.port.validity.badInput) ui.port.value = '22';
}

function readProfileFromForm(password: string): Promise<SavedProfile> {
  applyFormDefaults();
  if (password.length > 4096) throw new Error(bilingual('密码不能超过 4096 个字符。', 'Password cannot exceed 4096 characters.'));
  const host = normalizeHost(ui.host.value);
  const port = Number(ui.port.value);
  const username = ui.username.value.trim();
  const existing = profiles.find((item) => targetKey(item.host, item.port, item.username) === targetKey(host, port, username));
  const profile: SavedProfile = {
    id: existing?.id ?? crypto.randomUUID(),
    host,
    port,
    username,
    authMethod: authMethod(),
    initialCommand: ui.initialCommand.value,
    termType: ui.termType.value,
    encoding: ui.encoding.value,
    fingerprint: ui.fingerprint.value.trim(),
    updatedAt: Date.now(),
  };
  if (profile.authMethod !== 'password') return Promise.resolve(profile);
  return getHistoryPasswordKey().then(async (key) => {
    if (!key) return profile;
    try { profile.passwordEncrypted = await encryptPassword(password, key, passwordContext(profile)); } catch { /* Save metadata without a password. */ }
    return profile;
  }).catch(() => profile);
}

function validateProfileFields(): string | null {
  applyFormDefaults();
  const host = normalizeHost(ui.host.value);
  const port = Number(ui.port.value);
  const username = ui.username.value.trim();
  if (!host || host.length > 253 || /[\s/?#]/.test(host)) return bilingual('请输入有效的主机名或 IP 地址。', 'Enter a valid hostname or IP address.');
  if (!Number.isInteger(port) || port < 1 || port > 65_535) return bilingual('端口必须介于 1 和 65535 之间。', 'Port must be between 1 and 65535.');
  if (!username || username.length > 128 || /[\r\n\0]/.test(username)) return bilingual('请输入有效的 SSH 用户名。', 'Enter a valid SSH username.');
  const fingerprint = ui.fingerprint.value.trim();
  if (fingerprint && !SSH_FINGERPRINT_RE.test(fingerprint)) return bilingual('主机指纹必须使用 SHA256:base64 格式。', 'Host fingerprint must use the SHA256:base64 format.');
  return null;
}

function validateConnection(): string | null {
  const profileError = validateProfileFields();
  if (profileError) return profileError;
  if (authMethod() === 'publickey') {
    const key = ui.privateKey.value.trim();
    if (!key) return bilingual('请粘贴或选择未加密的 OpenSSH 私钥。', 'Paste or choose an unencrypted OpenSSH private key.');
    if (new TextEncoder().encode(key).length > MAX_KEY_BYTES) return bilingual('私钥大于 64 KiB。', 'The private key is larger than 64 KiB.');
    if (!key.includes('BEGIN OPENSSH PRIVATE KEY')) return bilingual('仅支持未加密的 OpenSSH 私钥。', 'Only unencrypted OpenSSH private keys are supported.');
  }
  return null;
}

function validateConnectForm(): string | null {
  applyFormDefaults();
  const browserInvalid = [...ui.form.elements].find((control): control is HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement =>
    control instanceof HTMLInputElement || control instanceof HTMLSelectElement || control instanceof HTMLTextAreaElement
      ? !control.validity.valid
      : false);
  if (browserInvalid) return bilingual('请检查必填项和字段格式。', 'Check the required fields and their formats.');
  return validateConnection();
}

async function applyProfile(profile: SavedProfile): Promise<void> {
  const loadGeneration = ++historyPasswordLoadGeneration;
  const context = passwordContext(profile);
  clearCredentials();
  ui.profileId.value = profile.id;
  ui.host.value = profile.host;
  ui.port.value = String(profile.port);
  ui.username.value = profile.username;
  ui.initialCommand.value = profile.initialCommand;
  ui.termType.value = profile.termType;
  ui.encoding.value = profile.encoding;
  ui.fingerprint.value = profile.fingerprint || hostKeys[targetKey(profile.host, profile.port, profile.username)] || '';
  setAuthMethod(profile.authMethod);
  passwordDirty = false;
  historyPasswordLoading = profile.authMethod === 'password'
    && Boolean(profile.passwordEncrypted);
  setState(connectionState);
  renderProfiles();
  if (!historyPasswordLoading) return;
  const key = await getHistoryPasswordKey();
  const decrypted = key
    ? await decryptPasswordResult(profile.passwordEncrypted, key, context)
    : null;
  if (loadGeneration !== historyPasswordLoadGeneration) return;
  historyPasswordLoading = false;
  const selectionUnchanged = ui.profileId.value === profile.id
    && targetKey() === context
    && authMethod() === profile.authMethod
    && !passwordDirty;
  if (selectionUnchanged) {
    ui.password.value = decrypted?.password ?? '';
    if (decrypted && !decrypted.ok) {
      toast(bilingual(
        '历史记录中的密码无法使用此浏览器配置解密，请重新输入。',
        'The history password could not be decrypted by this browser profile. Enter it again.',
      ), 'error');
    }
  }
  setState(connectionState);
}

function clearForm(): void {
  historyPasswordLoadGeneration++;
  historyPasswordLoading = false;
  ui.form.reset();
  clearCredentials();
  ui.profileId.value = '';
  ui.port.value = '22';
  ui.username.value = 'root';
  ui.termType.value = 'xterm-256color';
  ui.encoding.value = 'utf-8';
  ui.fingerprint.value = '';
  ui.formError.hidden = true;
  currentFormError = null;
  setAuthMethod('password');
  setState(connectionState);
  renderProfiles();
  ui.host.focus();
}

async function saveConnectedProfile(): Promise<void> {
  if (!pendingHistory || pendingHistory.generation !== connectGeneration) return;
  const operation = pendingHistory;
  pendingHistory = null;
  const connectedAt = Date.now();
  const mutation = ++historyMutationSequence;
  latestHistoryMutation.set(operation.target, mutation);
  let profile: SavedProfile;
  try {
    profile = await operation.profile;
  } catch {
    return;
  }
  if (passwordContext(profile) !== operation.target || latestHistoryMutation.get(operation.target) !== mutation) return;
  const key = targetKey(profile.host, profile.port, profile.username);
  const rememberedFingerprint = key === currentTargetKey && currentRememberedFingerprint
    ? currentRememberedFingerprint
    : hostKeys[key] || profile.fingerprint || '';
  const saved: SavedProfile = {
    ...profile,
    fingerprint: rememberedFingerprint,
    updatedAt: connectedAt,
  };
  if (historyPasswordLoading && targetKey() === operation.target) {
    historyPasswordLoadGeneration++;
    historyPasswordLoading = false;
    setState(connectionState);
  }
  const result = await persistHistoryMutation({ kind: 'upsert', profile: saved });
  if (!result.persisted) {
    renderProfiles();
    throw new Error('History persistence failed');
  }
  const retained = profiles.find((item) => passwordContext(item) === operation.target);
  if (targetKey() === operation.target && retained) ui.profileId.value = retained.id;
  renderProfiles();
  if (!result.applied) return;
  toast(saved.passwordEncrypted
    ? bilingual('连接已加入历史记录，密码已使用当前浏览器配置密钥加密。', 'Connection added to history; the password is encrypted with this browser profile\'s key.')
    : bilingual('连接已加入此浏览器的历史记录。', 'Connection added to this browser\'s history.'));
}

async function deleteProfile(id: string): Promise<void> {
  const removed = profiles.find((profile) => profile.id === id);
  if (!removed) return;
  const target = passwordContext(removed);
  latestHistoryMutation.set(target, ++historyMutationSequence);
  const result = await persistHistoryMutation({ kind: 'delete', target });
  if (!result.persisted) {
    renderProfiles();
    toast(bilingual('无法删除此历史记录。', 'This history entry could not be deleted.'), 'error');
    return;
  }
  if (targetKey() === target) clearForm();
  else renderProfiles();
}

function renderProfiles(): void {
  ui.profileList.replaceChildren();
  ui.profileCount.textContent = String(profiles.length);
  if (profiles.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'empty-list';
    empty.textContent = bilingual('暂无历史记录', 'No connection history yet.');
    ui.profileList.append(empty);
    return;
  }

  for (const profile of profiles) {
    const card = document.createElement('div');
    card.className = `profile-card${profile.id === ui.profileId.value ? ' active' : ''}`;

    const main = document.createElement('button');
    main.className = 'profile-main';
    main.type = 'button';
    main.dataset.profileId = profile.id;
    const avatar = document.createElement('span');
    avatar.className = 'profile-avatar';
    avatar.textContent = profile.username.slice(0, 2).toUpperCase();
    const copy = document.createElement('span');
    copy.className = 'profile-copy';
    const title = document.createElement('strong');
    const label = targetLabel(profile.host, profile.port, profile.username);
    title.textContent = label;
    const lastConnected = document.createElement('time');
    const connectedAt = new Date(Math.min(profile.updatedAt, Date.now()));
    lastConnected.dateTime = connectedAt.toISOString();
    const formattedTime = new Intl.DateTimeFormat(currentLanguage, { dateStyle: 'medium', timeStyle: 'short' }).format(connectedAt);
    lastConnected.textContent = bilingual(`最后连接：${formattedTime}`, `Last connected: ${formattedTime}`);
    copy.append(title, lastConnected);
    main.append(avatar, copy);

    const remove = document.createElement('button');
    remove.className = 'profile-delete';
    remove.type = 'button';
    remove.dataset.deleteProfile = profile.id;
    remove.setAttribute('aria-label', bilingual(`删除 ${label}`, `Delete ${label}`));
    remove.textContent = '\u00d7';
    card.append(main, remove);
    ui.profileList.append(card);
  }
}

function showFormError(message: string, alternate?: string): void {
  currentFormError = messageTranslation(message, alternate);
  ui.formError.textContent = localize(currentFormError);
  ui.formError.hidden = false;
}

function toast(message: string, kind: 'info' | 'error' = 'info'): void {
  const item = document.createElement('div');
  item.className = `toast${kind === 'error' ? ' error' : ''}`;
  item.textContent = message;
  ui.toastRegion.append(item);
  window.setTimeout(() => item.remove(), 4_500);
}

function updateConnectionStatus(message: LocalizedMessage): void {
  currentSessionSubtitle = message;
  const text = localize(message);
  ui.sessionSubtitle.textContent = text;
  if (connectionState === 'connecting') {
    const btnSpan = ui.connect.querySelector<HTMLElement>('span:last-child');
    if (btnSpan) btnSpan.textContent = text;
  }
}

function setState(state: ConnectionState, label?: string): void {
  connectionState = state;
  const stateLabel = label ?? ({
    idle: bilingual('离线', 'Offline'),
    connecting: bilingual('连接中', 'Connecting'),
    connected: bilingual('在线', 'Online'),
    disconnecting: bilingual('正在断开', 'Disconnecting'),
    error: bilingual('错误', 'Error'),
  } satisfies Record<ConnectionState, string>)[state];
  ui.liveOrb.className = `live-orb ${state}`;
  ui.liveOrbLabel.textContent = stateLabel;
  ui.liveOrb.title = stateLabel;
  const control = resolveConnectionControl(state, historyPasswordLoading);
  const controlLabel = control.action === 'cancel'
    ? bilingual('取消连接', 'Cancel connection')
    : control.action === 'disconnect'
      ? bilingual('断开', 'Disconnect')
      : control.action === 'disconnecting'
        ? bilingual('断开中...', 'Disconnecting...')
        : bilingual('连接', 'Connect');
  ui.connect.disabled = control.disabled;
  ui.connect.classList.toggle('is-danger', control.danger);
  ui.connect.dataset.action = control.action;
  ui.connect.querySelector<HTMLElement>('.button-icon')!.textContent = control.danger ? 'x' : '>_';
  ui.connect.querySelector<HTMLElement>('span:last-child')!.textContent = controlLabel;
  ui.connect.setAttribute('aria-label', controlLabel);
  ui.connect.title = currentSessionId || controlLabel;
  updateMobileToolbarVisibility();
}

function event(message: string, category = 'session', error = false, alternate?: string): void {
  const eventTranslation = messageTranslation(message, alternate);
  currentEventMessage = eventTranslation;
  ui.eventMessage.textContent = localize(currentEventMessage);
  const line = document.createElement('div');
  line.className = `event-line${error ? ' error' : ''}`;
  line.dataset.category = category;
  const time = document.createElement('time');
  time.textContent = new Date().toLocaleTimeString([], { hour12: false });
  const type = document.createElement('strong');
  type.textContent = EVENT_LABELS[category] ? translate(EVENT_LABELS[category]) : bilingual('SSH 事件', category);
  const copy = document.createElement('span');
  copy.textContent = message;
  copy.dataset.messageZh = eventTranslation.zh;
  copy.dataset.messageEn = eventTranslation.en;
  line.append(time, type, copy);
  ui.eventLog.append(line);
  while (ui.eventLog.childElementCount > 100) ui.eventLog.firstElementChild?.remove();
  ui.eventLog.scrollTop = ui.eventLog.scrollHeight;
}

function fitTerminal(send = true): void {
  cancelAnimationFrame(resizeFrame);
  resizeFrame = requestAnimationFrame(() => {
    try {
      fitAddon.fit();
      if (send && socket?.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'resize', cols: terminal.cols, rows: terminal.rows }));
      }
    } catch {
      // The terminal can be temporarily dimensionless during a panel drawer transition.
    }
  });
}

function setPanelOpen(open: boolean): void {
  const view = resolveConnectionPanel(open);
  panelOpen = view.expanded;
  if (!view.expanded && (connectionState === 'connecting' || connectionState === 'connected' || connectionState === 'disconnecting')) {
    invalidateHistoryPasswordLoad();
  }
  if (!view.expanded && ui.panel.contains(document.activeElement)) ui.panelToggle.focus();
  ui.panel.classList.toggle('open', view.drawerOpen);
  ui.panel.inert = !view.expanded;
  ui.panel.setAttribute('aria-hidden', String(!view.expanded));
  ui.panelToggle.setAttribute('aria-expanded', String(view.expanded));
  const toggleLabel = view.expanded
    ? bilingual('折叠连接面板', 'Collapse connection panel')
    : bilingual('展开连接面板', 'Expand connection panel');
  ui.panelToggle.setAttribute('aria-label', toggleLabel);
  ui.panelToggle.title = toggleLabel;
  ui.panelScrim.hidden = !view.scrimVisible;
  requestAnimationFrame(() => fitTerminal(true));
}

function updateUptime(): void {
  if (!sessionStartedAt) {
    ui.metricUptime.textContent = '00:00';
    return;
  }
  const seconds = Math.max(0, Math.floor((Date.now() - sessionStartedAt) / 1000));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainder = seconds % 60;
  ui.metricUptime.textContent = hours > 0
    ? `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(remainder).padStart(2, '0')}`
    : `${String(minutes).padStart(2, '0')}:${String(remainder).padStart(2, '0')}`;
}

function startTimers(): void {
  stopTimers();
  sessionStartedAt = Date.now();
  updateUptime();
  uptimeTimer = window.setInterval(updateUptime, 1_000);
  pingTimer = window.setInterval(() => {
    if (socket?.readyState !== WebSocket.OPEN) return;
    socket.send(JSON.stringify({ type: 'ping' }));
  }, PING_INTERVAL_MS);
}

function stopTimers(): void {
  if (uptimeTimer !== null) window.clearInterval(uptimeTimer);
  if (pingTimer !== null) window.clearInterval(pingTimer);
  uptimeTimer = null;
  pingTimer = null;
  sessionStartedAt = 0;
}

function markReady(message = bilingual('交互式 Shell 已就绪', 'Interactive shell ready')): void {
  if (connectionState === 'connected') return;
  invalidateHistoryPasswordLoad();
  setState('connected');
  setPanelOpen(false);
  void saveConnectedProfile().catch(() => {
    toast(bilingual('连接成功，但无法更新历史记录。', 'Connected, but the history could not be updated.'), 'error');
  });
  startTimers();
  updateConnectionStatus(messageTranslation(message));
  event(message, 'ready');
  if (currentInitialCommand && !initialCommandSent) {
    initialCommandSent = true;
    const command = currentInitialCommand;
    const activeSocket = socket;
    const generation = connectGeneration;
    window.setTimeout(() => {
      if (socket !== activeSocket || generation !== connectGeneration) return;
      sendTerminalData(`${command}\r`);
    }, 120);
  }
  terminal.focus();
}

function sendHostKeyDecision(accept: boolean): void {
  if (!awaitingHostKeyDecision || !pendingHostKey || socket?.readyState !== WebSocket.OPEN) return;
  const hostKey = pendingHostKey;
  awaitingHostKeyDecision = false;
  pendingHostKey = null;
  socket.send(JSON.stringify({
    type: 'host_key_decision',
    accept,
    fingerprint: hostKey.fingerprint,
  }));
  if (accept && ui.rememberHostKey.checked && currentTargetKey) {
    currentRememberedFingerprint = hostKey.fingerprint;
    void replaceRememberedHostKey(currentTargetKey, hostKey.fingerprint);
    if (targetKey() === currentTargetKey) ui.fingerprint.value = hostKey.fingerprint;
  }
  event(accept
    ? hostKey.trust === 'changed'
      ? bilingual('新的主机密钥已明确接受，可以继续认证。', 'The new host key was explicitly accepted; authentication may continue.')
      : bilingual('主机密钥已接受，可以继续认证。', 'Host key accepted; authentication may continue.')
    : bilingual('主机密钥已拒绝。', 'Host key rejected.'), 'host-key', !accept);
}

type WorkspaceTab = 'files' | 'processes' | 'log';
let activeWorkspaceTab: WorkspaceTab | null = null;

function setWorkspaceTab(tab: WorkspaceTab | null, focus = false, rovingTab = tab ?? activeWorkspaceTab ?? 'files'): void {
  const filesActive = tab === 'files';
  const processesActive = tab === 'processes';
  const logActive = tab === 'log';
  activeWorkspaceTab = tab;
  ui.terminalCard.classList.toggle('workspace-panel-open', tab !== null);
  ui.fileManagerPanel.hidden = !filesActive;
  ui.processManagerPanel.hidden = !processesActive;
  ui.eventLog.hidden = !logActive;
  ui.fileManagerTab.setAttribute('aria-selected', String(filesActive));
  ui.processManagerTab.setAttribute('aria-selected', String(processesActive));
  ui.eventToggle.setAttribute('aria-selected', String(logActive));
  ui.fileManagerTab.setAttribute('aria-expanded', String(filesActive));
  ui.processManagerTab.setAttribute('aria-expanded', String(processesActive));
  ui.eventToggle.setAttribute('aria-expanded', String(logActive));
  ui.fileManagerTab.tabIndex = rovingTab === 'files' ? 0 : -1;
  ui.processManagerTab.tabIndex = rovingTab === 'processes' ? 0 : -1;
  ui.eventToggle.tabIndex = rovingTab === 'log' ? 0 : -1;
  if (logActive) requestAnimationFrame(() => { ui.eventLog.scrollTop = ui.eventLog.scrollHeight; });
  if (focus) ({ files: ui.fileManagerTab, processes: ui.processManagerTab, log: ui.eventToggle })[rovingTab].focus();
  requestAnimationFrame(() => fitTerminal(true));
}

function toggleWorkspaceTab(tab: WorkspaceTab): void {
  setWorkspaceTab(activeWorkspaceTab === tab ? null : tab, false, tab);
}

function handleWorkspaceTabKey(event: KeyboardEvent): void {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
  event.preventDefault();
  const tabs: WorkspaceTab[] = ['files', 'processes', 'log'];
  const current = tabs.findIndex((tab) => ({ files: ui.fileManagerTab, processes: ui.processManagerTab, log: ui.eventToggle })[tab] === event.currentTarget);
  const next = event.key === 'Home' ? 0
    : event.key === 'End' ? tabs.length - 1
      : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
  setWorkspaceTab(tabs[next], true);
}

function configureHostKeyDialog(hostKey: HostKeyPrompt): void {
  const changed = hostKey.trust === 'changed';
  ui.hostKeyDialog.classList.toggle('changed', changed);
  ui.hostKeyIcon.textContent = changed ? bilingual('警告', 'ALERT') : bilingual('密钥', 'KEY');
  ui.hostKeyEyebrow.textContent = changed
    ? bilingual('主机身份已变化', 'HOST IDENTITY CHANGED')
    : bilingual('主机身份', 'HOST IDENTITY');
  ui.hostKeyTitle.textContent = changed
    ? bilingual('SSH 主机密钥不匹配', 'SSH host key mismatch')
    : bilingual('信任此 SSH 主机？', 'Trust this SSH host?');
  ui.hostKeyDescription.textContent = changed
    ? bilingual(
      '服务器密钥与之前保存的指纹不同。这可能是正常换钥，也可能是中间人攻击。仅在通过可信渠道确认新指纹后继续。',
      'The server key differs from the saved fingerprint. This can be a legitimate rotation or a man-in-the-middle attack. Continue only after verifying the new fingerprint through a trusted channel.',
    )
    : bilingual(
      '服务器提供了尚未为此目标固定的密钥。继续前，请通过可信渠道核验。',
      'The server presented a key that has not been pinned for this target. Verify it through a trusted channel before continuing.',
    );
  ui.hostKeyExpectedRow.hidden = !changed;
  ui.hostKeyExpectedFingerprint.textContent = changed ? hostKey.expectedFingerprint : '--';
  ui.rememberHostKeyLabel.textContent = changed
    ? bilingual('替换并记住这个新指纹', 'Replace the saved fingerprint with this new one')
    : bilingual('下次记住并验证此指纹', 'Remember and verify this fingerprint next time');
  ui.acceptHostKey.textContent = changed
    ? bilingual('我已核验，替换并继续', 'Verified: replace & continue')
    : bilingual('信任并继续', 'Trust & continue');
}

function clearHostKeyPrompt(): void {
  awaitingHostKeyDecision = false;
  pendingHostKey = null;
  if (ui.hostKeyDialog.open) ui.hostKeyDialog.close('reject');
  ui.hostKeyDialog.returnValue = '';
}

function handleServerMessage(message: ServerMessage): void {
  const type = message.type ?? 'status';
  if (type === 'sftp_attach') {
    if (typeof message.url !== 'string' || !message.url.startsWith('/api/sftp?')) {
      event(bilingual('收到无效的文件管理连接信息。', 'Received invalid file-management connection details.'), 'protocol', true);
      return;
    }
    try {
      fileManager.attach(message.url);
    } catch {
      event(bilingual('无法打开文件管理连接。', 'Could not open the file-management connection.'), 'sftp', true);
      return;
    }
    fileTree.setReady(true);
    event(bilingual('文件管理通道已可用。', 'File management channel is available.'), 'sftp');
    return;
  }
  if (type === 'process_attach') {
    if (typeof message.url !== 'string' || !message.url.startsWith('/api/processes?')) {
      event(bilingual('收到无效的进程监控连接信息。', 'Received invalid process-monitor connection details.'), 'protocol', true);
      return;
    }
    try {
      processManager.attach(message.url);
    } catch {
      event(bilingual('无法打开进程监控连接。', 'Could not open the process-monitor connection.'), 'process', true);
      return;
    }
    event(bilingual('进程监控通道已可用。', 'Process monitor channel is available.'), 'process');
    return;
  }
  if (type === 'host_key') {
    const fingerprint = message.fingerprint ?? '';
    const keyType = message.keyType ?? '';
    const expected = message.expectedFingerprint ?? currentExpectedFingerprint;
    if (!SSH_FINGERPRINT_RE.test(fingerprint)
      || !/^[A-Za-z0-9@._+-]{1,128}$/.test(keyType)
      || typeof message.trusted !== 'boolean'
      || (expected !== '' && !SSH_FINGERPRINT_RE.test(expected))
      || (message.expectedFingerprint !== undefined && message.expectedFingerprint !== currentExpectedFingerprint)) {
      event(bilingual('收到无效的主机密钥消息。', 'Received an invalid host key message.'), 'protocol', true);
      socket?.close(CLIENT_CLOSE_PROTOCOL_ERROR, 'Invalid host key message');
      return;
    }
    ui.metricHostKey.textContent = keyType.replace('ssh-', '').replace('ecdsa-sha2-', '');
    ui.metricHostKey.title = fingerprint;
    const trust = classifyHostKey(expected, fingerprint);
    if (message.trusted !== (trust === 'matched')) {
      event(bilingual('收到不一致的主机密钥信任消息。', 'Received an inconsistent trusted host key message.'), 'protocol', true);
      socket?.close(CLIENT_CLOSE_PROTOCOL_ERROR, 'Invalid trusted host key message');
      return;
    }
    if (trust === 'matched') {
      event(bilingual('已固定的主机密钥匹配。', 'Pinned host key matched.'), 'host-key');
      return;
    }
    pendingHostKey = { fingerprint, keyType, expectedFingerprint: expected, trust };
    awaitingHostKeyDecision = true;
    configureHostKeyDialog(pendingHostKey);
    ui.hostKeyTarget.textContent = ui.sessionTitle.textContent ?? currentTargetKey;
    ui.hostKeyType.textContent = keyType;
    ui.hostKeyFingerprint.textContent = fingerprint;
    ui.rememberHostKey.checked = true;
    event(trust === 'changed'
      ? bilingual(`认证已暂停：主机密钥从 ${expected} 变为 ${fingerprint}`, `Authentication paused: host key changed from ${expected} to ${fingerprint}`)
      : bilingual(`认证已暂停，请确认首次见到的主机密钥 ${fingerprint}`, `Authentication paused for first-seen host key ${fingerprint}`), 'host-key', trust === 'changed');
    if (!ui.hostKeyDialog.open) {
      ui.hostKeyDialog.returnValue = '';
      ui.hostKeyDialog.showModal();
    }
    return;
  }
  if (type === 'ready') {
    markReady(bilingualServerMessage(message.message, message.event ?? 'ready', 'Interactive shell ready'));
    return;
  }
  if (type === 'error') {
    const text = bilingualServerMessage(message.message, message.event, 'The SSH session failed.', 'SSH 错误');
    const failedSocket = socket;
    event(text, message.event ?? 'error', true);
    showFormError(text);
    toast(text, 'error');
    failActiveConnection(failedSocket, 'SSH session failed', messageTranslation(text));
    return;
  }
  if (type === 'debug') {
    event(bilingualServerMessage(message.message, message.event, 'Debug event'), 'debug');
    return;
  }
  if (type === 'status') {
    const text = bilingualServerMessage(message.message, message.event, 'SSH handshake in progress');
    event(text, message.event ?? 'status');
    updateConnectionStatus(messageTranslation(text));
    if (message.event === 'shell_ready' || message.event === 'ready') markReady(text);
  }
}

async function handleSocketData(data: string | ArrayBuffer | Blob, activeSocket: WebSocket, generation: number): Promise<void> {
  if (socket !== activeSocket || generation !== connectGeneration) return;
  if (typeof data === 'string') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch {
      event(bilingual('已忽略无效的控制帧。', 'Ignored an invalid control frame.'), 'protocol', true);
      return;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      event(bilingual('已忽略无效的控制帧。', 'Ignored an invalid control frame.'), 'protocol', true);
      return;
    }
    try {
      handleServerMessage(parsed as ServerMessage);
    } catch {
      event(bilingual('处理服务器控制消息时发生错误。', 'Failed to process the server control message.'), 'protocol', true);
      if (activeSocket.readyState < WebSocket.CLOSING) {
        activeSocket.close(CLIENT_CLOSE_PROTOCOL_ERROR, 'Control message handling failed');
      }
    }
    return;
  }
  const bytes = data instanceof Blob ? new Uint8Array(await data.arrayBuffer()) : new Uint8Array(data);
  if (socket !== activeSocket || generation !== connectGeneration) return;
  if (decoder.encoding === 'utf-8') terminal.write(bytes);
  else terminal.write(decoder.decode(bytes, { stream: true }));
}

function sendTerminalData(data: string): void {
  if (socket?.readyState !== WebSocket.OPEN || connectionState !== 'connected' || !data) return;
  socket.send(JSON.stringify({ type: 'input', data }));
}

function failActiveConnection(activeSocket: WebSocket | null, closeReason: string, displayReason: LocalizedMessage): void {
  if (activeSocket && socket === activeSocket) socket = null;
  connectGeneration++;
  currentSessionId = '';
  pendingHistory = null;
  authorizationAbort?.abort();
  authorizationAbort = null;
  currentExpectedFingerprint = '';
  currentRememberedFingerprint = '';
  stopTimers();
  fileManager.reset();
  fileTree?.setReady(false);
  processManager.reset();
  resetNetworkMetric();
  clearHostKeyPrompt();
  invalidateHistoryPasswordLoad();
  updateConnectionStatus(displayReason);
  setState('error');
  if (activeSocket && activeSocket.readyState < WebSocket.CLOSING) activeSocket.close(CLIENT_CLOSE_SESSION_ERROR, closeReason);
}

async function issueTicket(signal: AbortSignal): Promise<{ ticket: string; sessionId: string }> {
  const response = await fetch('/api/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({}),
    signal,
  });
  let payload: { ticket?: string; sessionId?: string; error?: string } = {};
  try {
    payload = await response.json() as { ticket?: string; sessionId?: string; error?: string };
  } catch {
    // The HTTP status still gives a useful fallback below.
  }
  if (!response.ok || !payload.ticket || !payload.sessionId) {
    throw new Error(payload.error
      ? bilingualServerMessage(payload.error, undefined, undefined, '请求失败')
      : bilingual(`会话授权失败（HTTP ${response.status}）。`, `Session authorization failed (HTTP ${response.status}).`));
  }
  return { ticket: payload.ticket, sessionId: payload.sessionId };
}

/** Factory that builds a fresh SSH WebSocket for reconnection attempts. */
function createSshReconnectFactory(): (attempt: number) => Promise<WebSocket> {
  return async (attempt: number): Promise<WebSocket> => {
    const params = reconnectParams!;
    const abortController = new AbortController();
    const { ticket, sessionId } = await issueTicket(abortController.signal);
    currentSessionId = sessionId;

    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = new URL('/api/ssh', location.href);
    url.protocol = protocol;
    url.searchParams.set('ticket', ticket);
    url.searchParams.set('session', sessionId);

    const generation = ++connectGeneration;
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';

    ws.addEventListener('open', () => {
      if (generation !== connectGeneration) {
        ws.close(1000, 'Connection superseded');
        return;
      }
      // Reset terminal for the new session.
      resetTerminalForConnection(terminal);
      fitTerminal(true);

      const config: ConnectionConfig = {
        type: 'connect',
        host: params.host,
        port: params.port,
        username: params.username,
        authMethod: params.authMethod as AuthMethod,
        cols: terminal.cols,
        rows: terminal.rows,
        term: params.term,
      };
      if (params.authMethod === 'password') config.password = params.password;
      else config.privateKey = params.privateKey;
      if (params.pinnedKey) config.expectedFingerprint = params.pinnedKey;

      ws.send(JSON.stringify(config));
      updateConnectionStatus(localized('正在打开 TCP 连接...', 'Opening TCP connection...'));
      event(bilingual('WebSocket 已建立，正在打开 SSH 传输（自动重连）。', 'WebSocket established; opening SSH transport (auto-reconnect).'), 'transport');
    }, { once: true });

    ws.addEventListener('message', (socketEvent) => {
      void handleSocketData(socketEvent.data as string | ArrayBuffer | Blob, ws, generation);
    });

    ws.addEventListener('error', () => {
      if (socket !== ws) return;
      const message = localized('WebSocket 传输错误。', 'WebSocket transport error.');
      event(localize(message), 'transport', true);
    });

    socket = ws;
    currentExpectedFingerprint = params.pinnedKey ?? '';
    decoder = createDecoder(params.encoding);
    return ws;
  };
}

/** Handles reconnect lifecycle events and updates the SSH UI accordingly. */
function handleSshReconnectLog(entry: ReconnectLogEntry): void {
  if (entry.event === 'give_up') {
    // Reconnect exhausted — perform full cleanup that was deferred.
    const reason = bilingual('SSH 重连失败，已达最大重试次数。', 'SSH reconnect failed; maximum retries reached.');
    event(reason, 'disconnect', true);
    updateConnectionStatus(messageTranslation(reason));
    setState('error');
    toast(reason, 'error');
    fileManager.reset();
    fileTree?.setReady(false);
    processManager.reset();
  } else if (entry.event === 'reconnect_attempt') {
    updateConnectionStatus(localized(
      `正在重连 SSH（${entry.attempt}/${entry.maxAttempts}）…`,
      `Reconnecting SSH (${entry.attempt}/${entry.maxAttempts})…`,
    ));
  } else if (entry.event === 'reconnect_success') {
    event(bilingual('SSH 重连成功。', 'SSH reconnected successfully.'), 'connect');
  }
}

async function connect(): Promise<void> {
  if (connectionState === 'connecting' || connectionState === 'connected' || connectionState === 'disconnecting') return;
  if (socket || authorizationAbort) return;
  if (historyPasswordLoading) return;
  historyPasswordLoadGeneration++;
  historyPasswordLoading = false;
  // Fresh baseline for a new session: the previous run may have left network
  // state (interface list, baselines) if the user navigated away uncleanly.
  resetNetworkMetric();
  applyFormDefaults();
  const validationError = validateConnectForm();
  if (validationError) {
    showFormError(validationError);
    return;
  }
  if (location.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname)) {
    showFormError(bilingual('发送 SSH 凭据前必须使用 HTTPS。', 'HTTPS is required before SSH credentials can be sent.'));
    return;
  }

  ui.formError.hidden = true;
  currentFormError = null;
  const generation = ++connectGeneration;
  const abortController = new AbortController();
  authorizationAbort = abortController;
  setState('connecting');
  ui.terminalEmpty.hidden = true;
  resetTerminalForConnection(terminal);
  fitTerminal(false);

  const host = normalizeHost(ui.host.value);
  const port = Number(ui.port.value);
  const username = ui.username.value.trim();
  currentTargetKey = targetKey(host, port, username);
  currentTargetLabel = targetLabel(host, port, username);
  const pinnedKey = ui.fingerprint.value.trim() || hostKeys[currentTargetKey] || '';
  currentExpectedFingerprint = pinnedKey;
  currentRememberedFingerprint = '';
  if (pinnedKey) ui.fingerprint.value = pinnedKey;
  currentInitialCommand = ui.initialCommand.value;
  initialCommandSent = false;
  pendingHostKey = null;
  awaitingHostKeyDecision = false;
  decoder = createDecoder(ui.encoding.value);
  ui.sessionTitle.textContent = currentTargetLabel;
  updateConnectionStatus(localized('正在授权 Worker 会话...', 'Authorizing Worker session...'));
  ui.metricHostKey.textContent = '--';
  event(bilingual(`正在连接 ${currentTargetLabel}`, `Starting ${currentTargetLabel}`), 'connect');

  try {
    const password = ui.password.value;
    const privateKey = ui.privateKey.value.trim();
    const method = authMethod();
    const term = ui.termType.value;
    const historyProfile = readProfileFromForm(password);
    // Resolve encryption during the SSH handshake so ready can usually save synchronously.
    void historyProfile.catch(() => undefined);
    pendingHistory = { generation, target: currentTargetKey, profile: historyProfile };
    const ticketRequest = issueTicket(abortController.signal);
    const { ticket, sessionId } = await ticketRequest;
    currentSessionId = sessionId;
    if (authorizationAbort === abortController) authorizationAbort = null;
    if (generation !== connectGeneration) return;
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = new URL('/api/ssh', location.href);
    url.protocol = protocol;
    url.searchParams.set('ticket', ticket);
    url.searchParams.set('session', sessionId);

    const activeSocket = new WebSocket(url);
    socket = activeSocket;
    activeSocket.binaryType = 'arraybuffer';

    // Persist connection parameters so the reconnect factory can reuse them.
    reconnectParams = { host, port, username, authMethod: method, term, encoding: ui.encoding.value };
    if (method === 'password') reconnectParams.password = password;
    else reconnectParams.privateKey = privateKey;
    if (pinnedKey) reconnectParams.pinnedKey = pinnedKey;

    // Set up (or replace) the SSH reconnect manager.
    sshReconnectManager?.reset();
    sshReconnectManager = new WebSocketReconnectManager({
      id: 'SSH',
      onConnect: createSshReconnectFactory(),
      onLog: handleSshReconnectLog,
    });
    sshReconnectManager.attach(activeSocket);

    activeSocket.addEventListener('open', () => {
      if (socket !== activeSocket || generation !== connectGeneration) {
        activeSocket.close(1000, 'Connection attempt superseded');
        return;
      }
      fitTerminal(false);
      const config: ConnectionConfig = {
        type: 'connect',
        host,
        port,
        username,
        authMethod: method,
        cols: terminal.cols,
        rows: terminal.rows,
        term,
      };
      if (method === 'password') config.password = password;
      else config.privateKey = privateKey;
      if (pinnedKey) config.expectedFingerprint = pinnedKey;
      activeSocket.send(JSON.stringify(config));
      updateConnectionStatus(localized('正在打开 TCP 连接...', 'Opening TCP connection...'));
      event(bilingual('WebSocket 已建立，正在打开 SSH 传输。', 'WebSocket established; opening SSH transport.'), 'transport');
    }, { once: true });
    activeSocket.addEventListener('message', (socketEvent) => {
      void handleSocketData(socketEvent.data as string | ArrayBuffer | Blob, activeSocket, generation);
    });
    activeSocket.addEventListener('error', () => {
      if (socket !== activeSocket) return;
      const message = localized('WebSocket 传输错误。', 'WebSocket transport error.');
      event(localize(message), 'transport', true);
      showFormError(localize(message));
      toast(localize(message), 'error');
      failActiveConnection(activeSocket, 'WebSocket transport error', message);
    });
    activeSocket.addEventListener('close', (closeEvent) => {
      if (socket !== activeSocket) return;
      socket = null;
      currentSessionId = '';
      pendingHistory = null;
      currentExpectedFingerprint = '';
      currentRememberedFingerprint = '';
      const wasActive = connectionState === 'connected';
      const isUnexpected = closeEvent.code !== 1000 && closeEvent.code !== 1005;

      if (isUnexpected && sshReconnectManager) {
        // The reconnect manager will attempt reconnection autonomously.
        // Skip tearing down child connections — they each have their own
        // reconnect logic that fires independently.
        stopTimers();
        resetNetworkMetric();
        clearHostKeyPrompt();
        invalidateHistoryPasswordLoad();
        const reason = bilingual('SSH 连接断开，正在重连…', 'SSH connection lost; reconnecting…');
        event(reason, 'disconnect', true);
        updateConnectionStatus(messageTranslation(reason));
        setState('connecting');
        if (wasActive) toast(reason, 'error');
        return;
      }

      // Normal close or reconnect not available — full cleanup.
      stopTimers();
      fileManager.reset();
      fileTree?.setReady(false);
      processManager.reset();
      resetNetworkMetric();
      clearHostKeyPrompt();
      invalidateHistoryPasswordLoad();
      const reason = closeEvent.reason
        ? bilingualServerMessage(closeEvent.reason)
        : closeEvent.code === 1000
          ? bilingual('会话已关闭。', 'Session closed.')
          : bilingual(`会话已关闭（${closeEvent.code}）。`, `Session closed (${closeEvent.code}).`);
      event(reason, 'disconnect', isUnexpected);
      updateConnectionStatus(messageTranslation(reason));
      setState(isUnexpected ? 'error' : 'idle');
      if (wasActive) toast(reason, isUnexpected ? 'error' : 'info');
    });
  } catch (error) {
    if (authorizationAbort === abortController) authorizationAbort = null;
    if (generation !== connectGeneration) return;
    pendingHistory = null;
    invalidateHistoryPasswordLoad();
    clearHostKeyPrompt();
    const message = error instanceof DOMException && error.name === 'AbortError'
      ? bilingual('连接授权已取消。', 'Connection authorization was cancelled.')
      : error instanceof Error
        ? bilingualServerMessage(error.message, undefined, undefined, '连接失败')
        : bilingualServerMessage(String(error), undefined, undefined, '连接失败');
    showFormError(message);
    event(message, 'authorization', true);
    toast(message, 'error');
    setState('error');
  }
}

function disconnect(reason = bilingual('已由用户断开连接', 'Disconnected by user')): void {
  if (connectionState === 'disconnecting') return;
  const generation = ++connectGeneration;
  setState('disconnecting');
  currentSessionId = '';
  pendingHistory = null;
  authorizationAbort?.abort();
  authorizationAbort = null;
  const activeSocket = socket;
  socket = null;
  sshReconnectManager?.reset();
  sshReconnectManager = null;
  reconnectParams = null;
  stopTimers();
  fileManager.reset();
  fileTree?.setReady(false);
  processManager.reset();
  resetNetworkMetric();
  clearHostKeyPrompt();
  invalidateHistoryPasswordLoad();
  currentExpectedFingerprint = '';
  currentRememberedFingerprint = '';
  updateConnectionStatus(messageTranslation(reason));
  event(reason, 'disconnect');
  let settled = false;
  const finish = (): void => {
    if (settled) return;
    settled = true;
    if (generation === connectGeneration && connectionState === 'disconnecting') setState('idle');
  };
  if (activeSocket && activeSocket.readyState < WebSocket.CLOSED) {
    activeSocket.addEventListener('close', finish, { once: true });
    if (activeSocket.readyState < WebSocket.CLOSING) activeSocket.close(1000, 'Disconnected by user');
    window.setTimeout(finish, 1_000);
  } else {
    window.setTimeout(finish, 180);
  }
}

function createDecoder(encoding: string): TextDecoder {
  try {
    return new TextDecoder(encoding, { fatal: false });
  } catch {
    ui.encoding.value = 'utf-8';
    toast(bilingual(`此浏览器不支持 ${encoding} 编码，将使用 UTF-8。`, `Encoding ${encoding} is not supported by this browser; using UTF-8.`), 'error');
    return new TextDecoder('utf-8');
  }
}

// UTF-8 -> Base64, matching the decoder in applyURLParameters (and the
// canonical form enforced by decodeLegacyPassword).
function encodePasswordForURL(password: string): string {
  let binary = '';
  for (const byte of new TextEncoder().encode(password)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function copySafeLink(): void {
  applyFormDefaults();
  const error = validateProfileFields();
  if (error) {
    showFormError(error);
    return;
  }
  const url = new URL(location.origin + location.pathname);
  url.searchParams.set('hostname', normalizeHost(ui.host.value));
  url.searchParams.set('port', ui.port.value || '22');
  url.searchParams.set('username', ui.username.value.trim());
  url.searchParams.set('term', ui.termType.value);
  if (ui.initialCommand.value) url.searchParams.set('command', ui.initialCommand.value);
  if (ui.encoding.value !== 'utf-8') url.searchParams.set('encoding', ui.encoding.value);
  const includesPassword = authMethod() === 'password' && ui.password.value !== '';
  if (includesPassword) url.searchParams.set('password', encodePasswordForURL(ui.password.value));
  void navigator.clipboard.writeText(url.toString()).then(
    () => toast(includesPassword
      ? bilingual('连接链接已复制（含 Base64 密码，粘贴即自动连接，请谨慎分享）。', 'Connection link copied (Base64 password included; pasting auto-connects — share carefully).')
      : bilingual('连接链接已复制（不含凭据）。', 'Connection link copied (credentials excluded).')),
    () => toast(bilingual('无法访问剪贴板。', 'Could not access the clipboard.'), 'error'),
  );
}

function setPortValue(value: string | number, source: string): void {
  if (String(value).trim() === '') {
    ui.port.value = '22';
    return;
  }
  const port = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(bilingual(`${source}中的端口无效`, `Invalid port in ${source}`));
  }
  ui.port.value = String(port);
}

function applyURLParameters(): boolean {
  const query = new URLSearchParams(location.search);
  const fragment = new URLSearchParams(location.hash.replace(/^#/, ''));
  const value = (key: string): string | null => query.get(key) ?? fragment.get(key);
  const host = value('hostname') ?? value('host');
  if (host) ui.host.value = host;
  const port = value('port');
  if (port !== null) {
    try {
      setPortValue(port, bilingual('连接链接', 'connection link'));
    } catch (error) {
      showFormError(error instanceof Error ? error.message : String(error));
      return false;
    }
  }
  if (value('username')) ui.username.value = value('username')!;
  if (value('command')) ui.initialCommand.value = value('command')!;
  if (value('term')) ui.termType.value = value('term')!;
  if (value('encoding')) ui.encoding.value = value('encoding')!;
  if (value('fingerprint')) ui.fingerprint.value = value('fingerprint')!;
  if (value('title')) document.title = value('title')!;

  const legacyPassword = value('password');
  if (legacyPassword) {
    try {
      const bytes = Uint8Array.from(atob(legacyPassword), (character) => character.charCodeAt(0));
      ui.password.value = new TextDecoder().decode(bytes);
      toast(bilingual('已从链接载入密码，使用后请从浏览器历史记录中删除该链接。', 'Password loaded from the link. Remove the link from browser history after use.'), 'error');
    } catch {
      toast(bilingual('密码 URL 参数不是有效的 Base64。', 'The password URL parameter is not valid Base64.'), 'error');
    }
  }
  return Boolean(host && (value('autoconnect') === '1' || legacyPassword));
}

function applyWSSHOptions(options: WSSHOptions): void {
  historyPasswordLoadGeneration++;
  historyPasswordLoading = false;
  clearCredentials();
  ui.host.value = options.host ?? options.hostname ?? ui.host.value;
  setPortValue(options.port ?? 22, 'wssh.connect()');
  ui.username.value = options.username?.trim() || 'root';
  if (options.password !== undefined) {
    setAuthMethod('password');
    ui.password.value = options.password;
    passwordDirty = true;
  }
  const key = options.privateKey ?? options.privatekey;
  if (key !== undefined) {
    setAuthMethod('publickey');
    ui.privateKey.value = key;
  }
  if (options.command !== undefined) ui.initialCommand.value = options.command;
  if (options.term !== undefined) ui.termType.value = options.term;
  if (options.encoding !== undefined) ui.encoding.value = options.encoding;
  if (options.fingerprint !== undefined) ui.fingerprint.value = options.fingerprint;
}

function initializeCompatibilityAPI(): void {
  const compatibilityConnect = async (
    optionsOrHost: WSSHOptions | string = {},
    port?: string | number,
    username?: string,
    password?: string,
    privateKey?: string,
  ): Promise<void> => {
    if (connectionState === 'connecting' || connectionState === 'connected' || connectionState === 'disconnecting') {
      throw new Error(bilingual('已有活动的 SSH 连接', 'An SSH connection is already active'));
    }
    const options: WSSHOptions = typeof optionsOrHost === 'string'
      ? { host: optionsOrHost, port, username, password, privateKey }
      : optionsOrHost;
    applyWSSHOptions(options);
    await connect();
  };
  window.wssh = {
    connect: compatibilityConnect as WSSHCompatibilityAPI['connect'],
    send: sendTerminalData,
    resize: () => fitTerminal(true),
    set_encoding: (encoding: string) => {
      ui.encoding.value = encoding;
      decoder = createDecoder(encoding);
    },
    reset_encoding: () => {
      ui.encoding.value = 'utf-8';
      decoder = new TextDecoder('utf-8');
    },
    disconnect,
  };
}

for (const radio of ui.form.querySelectorAll<HTMLInputElement>('input[name="authMethod"]')) {
  radio.addEventListener('change', () => {
    cancelHistoryPasswordLoad();
    setAuthMethod(authMethod());
  });
}
ui.form.addEventListener('submit', (formEvent) => {
  formEvent.preventDefault();
  if (connectionState === 'connecting' || connectionState === 'connected') {
    disconnect(connectionState === 'connecting'
      ? bilingual('连接已取消', 'Connection cancelled')
      : bilingual('已由用户断开连接', 'Disconnected by user'));
  } else if (connectionState !== 'disconnecting') {
    void connect();
  }
});
ui.shareLink.addEventListener('click', copySafeLink);
ui.password.addEventListener('input', () => {
  cancelHistoryPasswordLoad();
  passwordDirty = true;
});
for (const field of [ui.host, ui.port, ui.username]) {
  field.addEventListener('input', cancelHistoryPasswordLoad);
}
ui.revealPassword.addEventListener('click', () => {
  const reveal = ui.password.type === 'password';
  ui.password.type = reveal ? 'text' : 'password';
  updateRevealPasswordButton();
});
ui.keyFile.addEventListener('change', async () => {
  const readGeneration = ++keyFileReadGeneration;
  const file = ui.keyFile.files?.[0];
  if (!file) {
    clearPrivateKeyFields();
    return;
  }
  ui.keyFileName.textContent = file.name;
  if (file.size > MAX_KEY_BYTES) {
    showFormError(bilingual('所选私钥大于 64 KiB。', 'The selected private key is larger than 64 KiB.'));
    clearPrivateKeyFields();
    return;
  }
  try {
    const privateKey = await file.text();
    if (readGeneration !== keyFileReadGeneration || ui.keyFile.files?.[0] !== file) return;
    ui.privateKey.value = privateKey;
  } catch {
    if (readGeneration !== keyFileReadGeneration) return;
    clearPrivateKeyFields();
    showFormError(bilingual('无法读取所选私钥。', 'The selected private key could not be read.'));
  }
});
ui.profileList.addEventListener('click', (clickEvent) => {
  const target = clickEvent.target as HTMLElement;
  const deleteButton = target.closest<HTMLElement>('[data-delete-profile]');
  if (deleteButton?.dataset.deleteProfile) {
    clickEvent.preventDefault();
    clickEvent.stopPropagation();
    const id = deleteButton.dataset.deleteProfile;
    const target = profiles.find((profile) => profile.id === id);
    if (target && pendingHistory?.target === passwordContext(target)) pendingHistory = null;
    void deleteProfile(id);
    return;
  }
  const card = target.closest<HTMLElement>('[data-profile-id]');
  const profile = profiles.find((item) => item.id === card?.dataset.profileId);
  if (profile) void applyProfile(profile);
});
ui.panelToggle.addEventListener('click', () => {
  const opening = !panelOpen;
  setPanelOpen(opening);
  if (opening) requestAnimationFrame(() => {
    if (connectionState === 'connecting' || connectionState === 'connected' || connectionState === 'disconnecting') ui.connect.focus();
    else ui.host.focus();
  });
});
ui.panelScrim.addEventListener('click', () => {
  setPanelOpen(false);
  ui.panelToggle.focus();
});
ui.emptyConnect.addEventListener('click', () => {
  setPanelOpen(true);
  requestAnimationFrame(() => ui.host.focus());
});
ui.clearTerminal.addEventListener('click', () => terminal.clear());
ui.fullscreenTerminal.addEventListener('click', async () => {
  if (document.fullscreenElement === ui.terminalCard) await document.exitFullscreen();
  else await ui.terminalCard.requestFullscreen();
});
document.addEventListener('fullscreenchange', () => fitTerminal(true));
ui.fileManagerTab.addEventListener('click', () => toggleWorkspaceTab('files'));
ui.processManagerTab.addEventListener('click', () => toggleWorkspaceTab('processes'));
ui.eventToggle.addEventListener('click', () => toggleWorkspaceTab('log'));
ui.fileManagerTab.addEventListener('keydown', handleWorkspaceTabKey);
ui.processManagerTab.addEventListener('keydown', handleWorkspaceTabKey);
ui.eventToggle.addEventListener('keydown', handleWorkspaceTabKey);
ui.languageToggle.addEventListener('click', () => {
  applyLanguage(currentLanguage === 'zh-CN' ? 'en' : 'zh-CN', true);
  renderProfiles();
  setState(connectionState);
  setPanelOpen(panelOpen);
  if (connectionState === 'idle' && !currentTargetLabel) ui.sessionTitle.textContent = bilingual('无活动会话', 'No active session');
});
ui.themeToggle.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem(THEME_STORAGE_KEY, next); } catch { /* Theme still applies for this page. */ }
});
ui.hostKeyDialog.addEventListener('cancel', (cancelEvent) => {
  cancelEvent.preventDefault();
  ui.hostKeyDialog.close('reject');
});
ui.hostKeyDialog.addEventListener('close', () => {
  sendHostKeyDecision(ui.hostKeyDialog.returnValue === 'accept');
});
// Bind the network interface selector once. Options are rebuilt by
// syncNetworkSelectOptions() only when the interface list changes, so the
// element keeps focus while the user interacts with it.
ui.resourceNetworkSelect.addEventListener('change', () => {
  const next = ui.resourceNetworkSelect.value;
  if (!next || next === netSelectedIface) return;
  netSelectedIface = next;
  resetNetworkBaseline();
  updateNetworkIfaceLabel();
});
terminal.onData(sendTerminalData);
new ResizeObserver(() => fitTerminal(true)).observe(ui.terminalStage);
window.addEventListener('beforeunload', () => {
  fileManager.reset();
  fileTree?.setReady(false);
  fileTree?.destroy();
  processManager.reset();
  resetNetworkMetric();
  socket?.close(1000, 'Page closed');
});

// ── Mobile shortcut key toolbar ────────────────────────────────────────────

/** Mapping from descriptive key names to raw terminal escape sequences. */
const MOBILE_KEY_SEQUENCES: Readonly<Record<string, string>> = Object.freeze({
  'ctrl-c': '\x03',
  'ctrl-d': '\x04',
  'esc':     '\x1b',
  'tab':     '\x09',
  'enter':   '\r',
  'up':      '\x1b[A',
  'down':    '\x1b[B',
  'left':    '\x1b[D',
  'right':   '\x1b[C',
  'ctrl-z':  '\x1a',
  'ctrl-l':  '\x0c',
  'ctrl-r':  '\x12',
  'ctrl-u':  '\x15',
  'ctrl-w':  '\x17',
  'ctrl-k':  '\x0b',
  'ctrl-a':  '\x01',
  'ctrl-e':  '\x05',
  'home':    '\x1b[H',
  'end':     '\x1b[F',
  'pgup':    '\x1b[5~',
  'pgdn':    '\x1b[6~',
  'delete':  '\x1b[3~',
});

let mobileToolbarReady = false;

function updateMobileToolbarVisibility(): void {
  const toolbar = document.getElementById('mobile-toolbar');
  if (!toolbar) return;
  // Show toolbar only on touch devices within mobile viewport width.
  // Aligned with the CSS media query (pointer: coarse) and (max-width: 768px).
  const isTouchDevice = window.matchMedia('(pointer: coarse) and (max-width: 768px)').matches;
  const shouldShow = isTouchDevice && connectionState === 'connected';
  toolbar.hidden = !shouldShow;
  const panel = document.getElementById('mobile-toolbar-panel');
  const toggle = document.getElementById('mobile-toolbar-toggle');
  if (!shouldShow) {
    if (panel) panel.hidden = true;
    if (toggle) {
      toggle.setAttribute('aria-expanded', 'false');
      toggle.setAttribute('aria-label', bilingual('打开快捷键工具栏', 'Open shortcut toolbar'));
      toggle.title = bilingual('快捷键', 'Shortcuts');
    }
  } else if (toggle && panel) {
    // Sync toggle state with current panel visibility
    // (essential after applyLanguage() rewrites aria-label/title from data-i18n-*)
    const isExpanded = !panel.hidden;
    toggle.setAttribute('aria-expanded', String(isExpanded));
    toggle.setAttribute('aria-label', isExpanded
      ? bilingual('关闭快捷键工具栏', 'Close shortcut toolbar')
      : bilingual('打开快捷键工具栏', 'Open shortcut toolbar'));
    toggle.title = isExpanded
      ? bilingual('关闭快捷键工具栏', 'Close shortcut toolbar')
      : bilingual('快捷键', 'Shortcuts');
  }
}

function initMobileToolbar(): void {
  if (mobileToolbarReady) return;
  mobileToolbarReady = true;

  const toggle = document.getElementById('mobile-toolbar-toggle');
  const panel = document.getElementById('mobile-toolbar-panel');
  if (!toggle || !panel) return;

  // Toggle expand / collapse
  toggle.addEventListener('click', (clickEvent: Event) => {
    clickEvent.stopPropagation();
    const wasHidden = panel.hidden;
    panel.hidden = !wasHidden;
    toggle.setAttribute('aria-expanded', String(wasHidden));
    toggle.setAttribute('aria-label', wasHidden
      ? bilingual('关闭快捷键工具栏', 'Close shortcut toolbar')
      : bilingual('打开快捷键工具栏', 'Open shortcut toolbar'));
    toggle.title = wasHidden
      ? bilingual('关闭快捷键工具栏', 'Close shortcut toolbar')
      : bilingual('快捷键', 'Shortcuts');
  });

  // Close panel when tapping outside
  document.addEventListener('click', (clickEvent: MouseEvent) => {
    const toolbar = document.getElementById('mobile-toolbar');
    if (!toolbar || toolbar.hidden) return;
    if (panel.hidden) return;
    const target = clickEvent.target as HTMLElement;
    if (!toolbar.contains(target)) {
      panel.hidden = true;
      toggle.setAttribute('aria-expanded', 'false');
      toggle.setAttribute('aria-label', bilingual('打开快捷键工具栏', 'Open shortcut toolbar'));
      toggle.title = bilingual('快捷键', 'Shortcuts');
    }
  });

  // Delegate button clicks — send the escape sequence to the terminal
  panel.addEventListener('click', (clickEvent: Event) => {
    const btn = (clickEvent.target as HTMLElement).closest<HTMLElement>('.mobile-key-btn');
    if (!btn) return;
    const key = btn.getAttribute('data-key');
    if (!key) return;
    const seq = MOBILE_KEY_SEQUENCES[key];
    if (seq !== undefined && window.wssh) {
      window.wssh.send(seq);
    }
    // Keep the panel open after sending a key so the user can tap
    // multiple shortcuts without re-expanding every time.
  });

  // Initial state
  updateMobileToolbarVisibility();
}

document.addEventListener('keydown', (keyEvent) => {
  if (keyEvent.key === 'Escape' && panelOpen && !ui.hostKeyDialog.open) {
    setPanelOpen(false);
    ui.panelToggle.focus();
  }
});

let storedTheme: string | null = null;
try { storedTheme = localStorage.getItem(THEME_STORAGE_KEY); } catch { /* Storage can be disabled. */ }
if (storedTheme === 'light' || storedTheme === 'dark') document.documentElement.dataset.theme = storedTheme;
async function initialize(): Promise<void> {
  profiles = await loadProfiles();
  applyLanguage(currentLanguage);
  element<HTMLElement>('app').hidden = false;
  renderProfiles();
  setPanelOpen(panelOpen);
  setAuthMethod('password');
  setState('idle');
  setWorkspaceTab(null);
  ui.sessionTitle.textContent = bilingual('无活动会话', 'No active session');
  ui.sessionSubtitle.textContent = bilingual('选择目标并连接', 'Choose a target and connect');
  ui.eventMessage.textContent = bilingual('Worker 运行时待命', 'Worker runtime standing by');
  initializeCompatibilityAPI();
  initMobileToolbar();
  const shouldAutoConnect = applyURLParameters();
  requestAnimationFrame(() => {
    fitTerminal(false);
    if (shouldAutoConnect) void connect();
  });
}

void initialize().catch(() => {
  // History initialization must never make the connection UI unavailable.
  profiles = loadCurrentProfiles();
  applyLanguage(currentLanguage);
  element<HTMLElement>('app').hidden = false;
  renderProfiles();
  setPanelOpen(panelOpen);
  setAuthMethod('password');
  setState('idle');
  setWorkspaceTab(null);
  initializeCompatibilityAPI();
  initMobileToolbar();
});
