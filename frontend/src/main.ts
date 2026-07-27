import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import './style.css';

type AuthMethod = 'password' | 'publickey';
type ConnectionState = 'idle' | 'connecting' | 'connected' | 'error';
type Language = 'zh-CN' | 'en';
type Translation = readonly [zh: string, en: string];

interface LocalizedMessage {
  zh: string;
  en: string;
}

interface SavedProfile {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authMethod: AuthMethod;
  passwordBase64?: string;
  initialCommand: string;
  termType: string;
  encoding: string;
  fingerprint: string;
  updatedAt: number;
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
  keyType?: string;
  trusted?: boolean;
  latency?: number;
  colo?: string;
  ts?: number;
  algorithms?: Record<string, string>;
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

const PROFILE_STORAGE_KEY = 'workers-webssh.profiles.v1';
const HOST_KEY_STORAGE_KEY = 'workers-webssh.hostkeys.v1';
const THEME_STORAGE_KEY = 'workers-webssh.theme';
const LANGUAGE_STORAGE_KEY = 'workers-webssh.language';
const MAX_PROFILES = 30;
const MAX_KEY_BYTES = 65_536;
const MAX_PASSWORD_BASE64_LENGTH = 16_384;
const PING_INTERVAL_MS = 25_000;

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
  'Invalid access token': '访问令牌无效',
  'Gateway access is not configured': '网关访问尚未配置',
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
  newProfile: element<HTMLButtonElement>('new-profile'),
  profileList: element<HTMLElement>('profile-list'),
  profileCount: element<HTMLElement>('profile-count'),
  form: element<HTMLFormElement>('connection-form'),
  profileId: element<HTMLInputElement>('profile-id'),
  profileName: element<HTMLInputElement>('profile-name'),
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
  accessToken: element<HTMLInputElement>('access-token'),
  formError: element<HTMLElement>('form-error'),
  connect: element<HTMLButtonElement>('connect-button'),
  saveProfile: element<HTMLButtonElement>('save-profile'),
  shareLink: element<HTMLButtonElement>('share-link'),
  globalStatus: element<HTMLElement>('global-status'),
  globalStatusLabel: element<HTMLElement>('global-status-label'),
  languageToggle: element<HTMLButtonElement>('language-toggle'),
  themeToggle: element<HTMLButtonElement>('theme-toggle'),
  sessionTitle: element<HTMLElement>('session-title'),
  sessionSubtitle: element<HTMLElement>('session-subtitle'),
  liveOrb: element<HTMLElement>('live-orb'),
  metricEdge: element<HTMLElement>('metric-edge'),
  metricRtt: element<HTMLElement>('metric-rtt'),
  metricUptime: element<HTMLElement>('metric-uptime'),
  metricHostKey: element<HTMLElement>('metric-host-key'),
  terminalCard: element<HTMLElement>('terminal-card'),
  terminalStage: element<HTMLElement>('terminal-stage'),
  terminalElement: element<HTMLElement>('terminal'),
  terminalEmpty: element<HTMLElement>('terminal-empty'),
  terminalLabel: element<HTMLElement>('terminal-label'),
  emptyConnect: element<HTMLButtonElement>('empty-connect'),
  clearTerminal: element<HTMLButtonElement>('clear-terminal'),
  fullscreenTerminal: element<HTMLButtonElement>('fullscreen-terminal'),
  disconnect: element<HTMLButtonElement>('disconnect-button'),
  eventMessage: element<HTMLElement>('event-message'),
  eventToggle: element<HTMLButtonElement>('event-toggle'),
  eventLog: element<HTMLElement>('event-log'),
  toastRegion: element<HTMLElement>('toast-region'),
  hostKeyDialog: element<HTMLDialogElement>('host-key-dialog'),
  hostKeyTarget: element<HTMLElement>('host-key-target'),
  hostKeyType: element<HTMLElement>('host-key-type'),
  hostKeyFingerprint: element<HTMLElement>('host-key-fingerprint'),
  rememberHostKey: element<HTMLInputElement>('remember-host-key'),
  rejectHostKey: element<HTMLButtonElement>('reject-host-key'),
  acceptHostKey: element<HTMLButtonElement>('accept-host-key'),
};

function updateRevealPasswordButton(): void {
  const revealed = ui.password.type === 'text';
  ui.revealPassword.textContent = revealed ? bilingual('隐藏', 'Hide') : bilingual('显示', 'Show');
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

  if (persist) {
    try { localStorage.setItem(LANGUAGE_STORAGE_KEY, language); } catch { /* Language still applies for this page. */ }
  }
}

let profiles = loadProfiles();
let hostKeys = loadHostKeys();
let socket: WebSocket | null = null;
let connectionState: ConnectionState = 'idle';
let sessionStartedAt = 0;
let uptimeTimer: number | null = null;
let pingTimer: number | null = null;
let lastPingAt = 0;
let pendingHostKey: { fingerprint: string; keyType: string } | null = null;
let currentTargetKey = '';
let currentInitialCommand = '';
let initialCommandSent = false;
let decoder = new TextDecoder('utf-8');
let resizeFrame = 0;
let awaitingHostKeyDecision = false;
let connectGeneration = 0;
let authorizationAbort: AbortController | null = null;
let currentExpectedFingerprint = '';
let currentSessionSubtitle: LocalizedMessage = { zh: '选择目标并连接', en: 'Choose a target and connect' };
let currentEventMessage: LocalizedMessage = { zh: 'Worker 运行时待命', en: 'Worker runtime standing by' };
let currentFormError: LocalizedMessage | null = null;
let passwordDirty = false;

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

function isSavedProfile(value: unknown): value is SavedProfile {
  if (!value || typeof value !== 'object') return false;
  const item = value as Partial<SavedProfile>;
  return (
    typeof item.id === 'string' &&
    typeof item.name === 'string' &&
    item.name.length >= 1 && item.name.length <= 253 &&
    typeof item.host === 'string' &&
    item.host.length >= 1 && item.host.length <= 253 && !/[\s/?#]/.test(item.host) &&
    typeof item.port === 'number' &&
    Number.isInteger(item.port) &&
    item.port >= 1 &&
    item.port <= 65_535 &&
    typeof item.username === 'string' &&
    item.username.length >= 1 && item.username.length <= 128 && !/[\r\n\0]/.test(item.username) &&
    (item.authMethod === 'password' || item.authMethod === 'publickey') &&
    (item.passwordBase64 === undefined || (
      typeof item.passwordBase64 === 'string' &&
      item.passwordBase64.length <= MAX_PASSWORD_BASE64_LENGTH &&
      /^[A-Za-z0-9+/]*={0,2}$/.test(item.passwordBase64)
    )) &&
    typeof item.initialCommand === 'string' &&
    item.initialCommand.length <= 4096 &&
    typeof item.termType === 'string' &&
    /^[A-Za-z0-9._+-]{1,64}$/.test(item.termType) &&
    typeof item.encoding === 'string' &&
    ['utf-8', 'gb18030', 'big5'].includes(item.encoding) &&
    typeof item.fingerprint === 'string' &&
    (item.fingerprint === '' || /^SHA256:[A-Za-z0-9+/]{43}$/.test(item.fingerprint)) &&
    typeof item.updatedAt === 'number'
  );
}

function sanitizeSavedProfile(value: unknown): SavedProfile | null {
  if (!isSavedProfile(value)) return null;
  const profile: SavedProfile = {
    id: value.id,
    name: value.name,
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
  if (value.authMethod === 'password' && value.passwordBase64) profile.passwordBase64 = value.passwordBase64;
  if (profile.passwordBase64) {
    try {
      const decoded = decodePassword(profile.passwordBase64);
      if (decoded.length > 4096 || encodePassword(decoded) !== profile.passwordBase64) delete profile.passwordBase64;
    } catch {
      delete profile.passwordBase64;
    }
  }
  return profile;
}

function loadProfiles(): SavedProfile[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(PROFILE_STORAGE_KEY) ?? '[]');
    return Array.isArray(parsed)
      ? parsed.map(sanitizeSavedProfile).filter((profile): profile is SavedProfile => profile !== null).slice(0, MAX_PROFILES)
      : [];
  } catch {
    return [];
  }
}

function loadHostKeys(): Record<string, string> {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(HOST_KEY_STORAGE_KEY) ?? '{}');
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return Object.fromEntries(
      Object.entries(parsed).filter(([key, value]) => key.length <= 512 && typeof value === 'string' && /^SHA256:[A-Za-z0-9+/]{43}$/.test(value)),
    );
  } catch {
    return {};
  }
}

function persistProfiles(): boolean {
  try {
    localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify(profiles.slice(0, MAX_PROFILES)));
    return true;
  } catch {
    toast(bilingual('此浏览器无法保存连接配置。', 'Profiles could not be saved in this browser.'), 'error');
    return false;
  }
}

function persistHostKeys(): void {
  try { localStorage.setItem(HOST_KEY_STORAGE_KEY, JSON.stringify(hostKeys)); }
  catch { toast(bilingual('此浏览器无法保存主机指纹。', 'Host fingerprints could not be saved in this browser.'), 'error'); }
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

function resetPasswordField(): void {
  ui.password.value = '';
  ui.password.type = 'password';
  passwordDirty = false;
  updateRevealPasswordButton();
}

function clearPrivateKeyFields(): void {
  ui.privateKey.value = '';
  ui.keyFile.value = '';
  ui.keyFileName.textContent = bilingual('未选择文件', 'No file selected');
}

function clearCredentials(): void {
  resetPasswordField();
  clearPrivateKeyFields();
  ui.accessToken.value = '';
}

function encodePassword(password: string): string {
  const bytes = new TextEncoder().encode(password);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodePassword(encoded: string): string {
  const binary = atob(encoded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

function normalizeHost(host: string): string {
  const trimmed = host.trim();
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) return trimmed.slice(1, -1);
  return trimmed;
}

function targetKey(host = normalizeHost(ui.host.value), port = Number(ui.port.value), username = ui.username.value.trim()): string {
  return `${username}@${host.toLowerCase()}:${port}`;
}

function applyFormDefaults(): void {
  if (!ui.username.value.trim()) ui.username.value = 'root';
  if (!ui.port.value.trim() && !ui.port.validity.badInput) ui.port.value = '22';
}

function readProfileFromForm(): SavedProfile {
  applyFormDefaults();
  if (ui.password.value.length > 4096) throw new Error(bilingual('密码不能超过 4096 个字符。', 'Password cannot exceed 4096 characters.'));
  const host = normalizeHost(ui.host.value);
  const port = Number(ui.port.value);
  const username = ui.username.value.trim();
  const profile: SavedProfile = {
    id: ui.profileId.value || crypto.randomUUID(),
    name: ui.profileName.value.trim() || host,
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
  if (profile.authMethod === 'password' && ui.password.value) {
    profile.passwordBase64 = encodePassword(ui.password.value);
  } else if (profile.authMethod === 'password' && ui.profileId.value && !passwordDirty) {
    profile.passwordBase64 = profiles.find((item) => item.id === ui.profileId.value)?.passwordBase64;
  }
  return profile;
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
  if (fingerprint && !/^SHA256:[A-Za-z0-9+/]{43}$/.test(fingerprint)) return bilingual('主机指纹必须使用 SHA256:base64 格式。', 'Host fingerprint must use the SHA256:base64 format.');
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

function applyProfile(profile: SavedProfile): void {
  clearCredentials();
  ui.profileId.value = profile.id;
  ui.profileName.value = profile.name;
  ui.host.value = profile.host;
  ui.port.value = String(profile.port);
  ui.username.value = profile.username;
  ui.initialCommand.value = profile.initialCommand;
  ui.termType.value = profile.termType;
  ui.encoding.value = profile.encoding;
  ui.fingerprint.value = profile.fingerprint || hostKeys[targetKey(profile.host, profile.port, profile.username)] || '';
  setAuthMethod(profile.authMethod);
  if (profile.authMethod === 'password' && profile.passwordBase64) {
    try {
      ui.password.value = decodePassword(profile.passwordBase64);
    } catch {
      toast(bilingual('已保存的密码无法解码，请重新输入并保存。', 'The saved password could not be decoded. Enter and save it again.'), 'error');
    }
  }
  passwordDirty = false;
  renderProfiles();
}

function clearForm(): void {
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
  renderProfiles();
  ui.profileName.focus();
}

function saveCurrentProfile(): void {
  const error = validateProfileFields();
  if (error) {
    showFormError(error);
    return;
  }
  let profile: SavedProfile;
  try {
    profile = readProfileFromForm();
  } catch (profileError) {
    showFormError(profileError instanceof Error ? profileError.message : String(profileError));
    return;
  }
  if (!ui.profileName.value.trim()) ui.profileName.value = profile.name;
  const index = profiles.findIndex((item) => item.id === profile.id);
  if (index >= 0) profiles[index] = profile;
  else profiles.unshift(profile);
  profiles = profiles.sort((a, b) => b.updatedAt - a.updatedAt).slice(0, MAX_PROFILES);
  ui.profileId.value = profile.id;
  if (!persistProfiles()) return;
  passwordDirty = false;
  renderProfiles();
  toast(profile.passwordBase64
    ? bilingual('连接配置和 Base64 编码的密码已保存在此浏览器。', 'Connection profile and Base64-encoded password saved in this browser.')
    : bilingual('连接配置已保存。', 'Connection profile saved.'));
}

function deleteProfile(id: string): void {
  profiles = profiles.filter((profile) => profile.id !== id);
  persistProfiles();
  if (ui.profileId.value === id) clearForm();
  else renderProfiles();
}

function renderProfiles(): void {
  ui.profileList.replaceChildren();
  ui.profileCount.textContent = String(profiles.length);
  if (profiles.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'empty-list';
    empty.textContent = bilingual('暂无已保存目标', 'No saved targets yet.');
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
    avatar.textContent = profile.name.slice(0, 2).toUpperCase();
    const copy = document.createElement('span');
    copy.className = 'profile-copy';
    const title = document.createElement('strong');
    title.textContent = profile.name;
    const target = document.createElement('span');
    target.textContent = `${profile.username}@${profile.host}:${profile.port}`;
    copy.append(title, target);
    main.append(avatar, copy);

    const remove = document.createElement('button');
    remove.className = 'profile-delete';
    remove.type = 'button';
    remove.dataset.deleteProfile = profile.id;
    remove.setAttribute('aria-label', bilingual(`删除 ${profile.name}`, `Delete ${profile.name}`));
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

function setState(state: ConnectionState, label?: string): void {
  connectionState = state;
  ui.globalStatus.dataset.state = state;
  ui.globalStatusLabel.textContent = label ?? ({
    idle: bilingual('离线', 'Offline'),
    connecting: bilingual('连接中', 'Connecting'),
    connected: bilingual('在线', 'Online'),
    error: bilingual('错误', 'Error'),
  } satisfies Record<ConnectionState, string>)[state];
  ui.liveOrb.className = `live-orb ${state}`;
  ui.connect.disabled = state === 'connecting' || state === 'connected';
  ui.connect.querySelector('span:last-child')!.textContent = state === 'connecting'
    ? bilingual('连接中...', 'Connecting...')
    : state === 'connected' ? bilingual('已连接', 'Connected') : bilingual('连接', 'Connect');
  ui.disconnect.disabled = state !== 'connecting' && state !== 'connected';
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
      // The terminal can be temporarily dimensionless during a mobile drawer transition.
    }
  });
}

function openPanel(open: boolean): void {
  const mobile = window.matchMedia('(max-width: 760px)').matches;
  const visible = mobile && open;
  ui.panel.classList.toggle('open', visible);
  ui.panel.inert = mobile && !visible;
  ui.panel.setAttribute('aria-hidden', String(mobile && !visible));
  ui.panelToggle.setAttribute('aria-expanded', String(visible));
  ui.panelToggle.setAttribute('aria-label', visible
    ? bilingual('关闭连接面板', 'Close connection panel')
    : bilingual('打开连接面板', 'Open connection panel'));
  ui.panelScrim.hidden = !visible;
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
    lastPingAt = performance.now();
    socket.send(JSON.stringify({ type: 'ping', ts: Date.now() }));
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
  setState('connected');
  startTimers();
  currentSessionSubtitle = messageTranslation(message);
  ui.sessionSubtitle.textContent = message;
  event(message, 'ready');
  if (currentInitialCommand && !initialCommandSent) {
    initialCommandSent = true;
    window.setTimeout(() => sendTerminalData(`${currentInitialCommand}\r`), 120);
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
    hostKeys[currentTargetKey] = hostKey.fingerprint;
    persistHostKeys();
    if (targetKey() === currentTargetKey) ui.fingerprint.value = hostKey.fingerprint;
  }
  event(accept
    ? bilingual('主机密钥已接受，可以继续认证。', 'Host key accepted; authentication may continue.')
    : bilingual('主机密钥已拒绝。', 'Host key rejected.'), 'host-key', !accept);
}

function clearHostKeyPrompt(): void {
  awaitingHostKeyDecision = false;
  pendingHostKey = null;
  if (ui.hostKeyDialog.open) ui.hostKeyDialog.close('reject');
  ui.hostKeyDialog.returnValue = '';
}

function handleServerMessage(message: ServerMessage): void {
  const type = message.type ?? 'status';
  if (type === 'pong') {
    if (lastPingAt > 0) ui.metricRtt.textContent = `${Math.max(1, Math.round(performance.now() - lastPingAt))} ms`;
    return;
  }
  if (type === 'rtt') {
    if (typeof message.latency === 'number') ui.metricRtt.textContent = `${Math.round(message.latency)} ms`;
    if (message.colo) ui.metricEdge.textContent = message.colo;
    return;
  }
  if (type === 'host_key') {
    const fingerprint = message.fingerprint ?? '';
    const keyType = message.keyType ?? '';
    if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(fingerprint) || !/^[A-Za-z0-9@._+-]{1,128}$/.test(keyType)) {
      event(bilingual('收到无效的主机密钥消息。', 'Received an invalid host key message.'), 'protocol', true);
      socket?.close(1002, 'Invalid host key message');
      return;
    }
    pendingHostKey = { fingerprint, keyType };
    ui.metricHostKey.textContent = keyType.replace('ssh-', '').replace('ecdsa-sha2-', '');
    ui.metricHostKey.title = fingerprint;
    const expected = currentExpectedFingerprint;
    if (expected && expected !== fingerprint) {
      event(bilingual('主机密钥不匹配，连接已拒绝。', 'Host key mismatch; connection rejected.'), 'host-key', true);
      socket?.close(1008, 'Host key mismatch');
      return;
    }
    if (message.trusted || expected) {
      event(bilingual('已固定的主机密钥匹配。', 'Pinned host key matched.'), 'host-key');
      return;
    }
    awaitingHostKeyDecision = true;
    ui.hostKeyTarget.textContent = ui.sessionTitle.textContent ?? currentTargetKey;
    ui.hostKeyType.textContent = keyType;
    ui.hostKeyFingerprint.textContent = fingerprint;
    ui.rememberHostKey.checked = true;
    event(bilingual(`认证已暂停，请确认首次见到的主机密钥 ${fingerprint}`, `Authentication paused for first-seen host key ${fingerprint}`), 'host-key');
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
    clearHostKeyPrompt();
    event(text, message.event ?? 'error', true);
    showFormError(text);
    toast(text, 'error');
    setState('error');
    if (socket?.readyState === WebSocket.OPEN) socket.close(1011, 'SSH session failed');
    return;
  }
  if (type === 'debug') {
    event(bilingualServerMessage(message.message, message.event, 'Debug event'), 'debug');
    return;
  }
  if (type === 'status') {
    const text = bilingualServerMessage(message.message, message.event, 'SSH handshake in progress');
    event(text, message.event ?? 'status');
    currentSessionSubtitle = messageTranslation(text);
    ui.sessionSubtitle.textContent = text;
    if (message.event === 'shell_ready' || message.event === 'ready') markReady(text);
  }
}

async function handleSocketData(data: string | ArrayBuffer | Blob): Promise<void> {
  if (typeof data === 'string') {
    try {
      handleServerMessage(JSON.parse(data) as ServerMessage);
    } catch {
      event(bilingual('已忽略无效的控制帧。', 'Ignored an invalid control frame.'), 'protocol', true);
    }
    return;
  }
  const bytes = data instanceof Blob ? new Uint8Array(await data.arrayBuffer()) : new Uint8Array(data);
  if (decoder.encoding === 'utf-8') terminal.write(bytes);
  else terminal.write(decoder.decode(bytes, { stream: true }));
}

function sendTerminalData(data: string): void {
  if (socket?.readyState !== WebSocket.OPEN || connectionState !== 'connected' || !data) return;
  socket.send(JSON.stringify({ type: 'input', data }));
}

async function issueTicket(accessToken: string, signal: AbortSignal): Promise<{ ticket: string; sessionId: string }> {
  const response = await fetch('/api/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ accessToken }),
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

async function connect(): Promise<void> {
  if (connectionState === 'connecting' || connectionState === 'connected') return;
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
  authorizationAbort?.abort();
  authorizationAbort = abortController;
  setState('connecting');
  ui.terminalEmpty.hidden = true;
  terminal.clear();
  fitTerminal(false);

  const host = normalizeHost(ui.host.value);
  const port = Number(ui.port.value);
  const username = ui.username.value.trim();
  currentTargetKey = targetKey(host, port, username);
  const pinnedKey = ui.fingerprint.value.trim() || hostKeys[currentTargetKey] || '';
  currentExpectedFingerprint = pinnedKey;
  if (pinnedKey) ui.fingerprint.value = pinnedKey;
  currentInitialCommand = ui.initialCommand.value;
  initialCommandSent = false;
  pendingHostKey = null;
  awaitingHostKeyDecision = false;
  decoder = createDecoder(ui.encoding.value);
  ui.sessionTitle.textContent = `${username}@${host}:${port}`;
  currentSessionSubtitle = localized('正在授权 Worker 会话...', 'Authorizing Worker session...');
  ui.sessionSubtitle.textContent = localize(currentSessionSubtitle);
  ui.metricEdge.textContent = '--';
  ui.metricRtt.textContent = '--';
  ui.metricHostKey.textContent = '--';
  ui.terminalLabel.textContent = `${bilingual('终端', 'terminal')} · ${username}@${host}`;
  event(bilingual(`正在连接 ${username}@${host}:${port}`, `Starting ${username}@${host}:${port}`), 'connect');

  try {
    const accessToken = ui.accessToken.value;
    const password = ui.password.value;
    const privateKey = ui.privateKey.value.trim();
    const method = authMethod();
    const term = ui.termType.value;
    const ticketRequest = issueTicket(accessToken, abortController.signal);
    clearCredentials();
    const { ticket, sessionId } = await ticketRequest;
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
      currentSessionSubtitle = localized('正在打开 TCP 连接...', 'Opening TCP connection...');
      ui.sessionSubtitle.textContent = localize(currentSessionSubtitle);
      event(bilingual('WebSocket 已建立，正在打开 SSH 传输。', 'WebSocket established; opening SSH transport.'), 'transport');
    }, { once: true });
    activeSocket.addEventListener('message', (socketEvent) => {
      if (socket === activeSocket) void handleSocketData(socketEvent.data as string | ArrayBuffer | Blob);
    });
    activeSocket.addEventListener('error', () => {
      if (socket !== activeSocket) return;
      clearHostKeyPrompt();
      event(bilingual('WebSocket 传输错误。', 'WebSocket transport error.'), 'transport', true);
      setState('error');
    });
    activeSocket.addEventListener('close', (closeEvent) => {
      if (socket !== activeSocket) return;
      socket = null;
      currentExpectedFingerprint = '';
      stopTimers();
      clearHostKeyPrompt();
      const wasActive = connectionState === 'connected';
      const reason = closeEvent.reason
        ? bilingualServerMessage(closeEvent.reason)
        : closeEvent.code === 1000
          ? bilingual('会话已关闭。', 'Session closed.')
          : bilingual(`会话已关闭（${closeEvent.code}）。`, `Session closed (${closeEvent.code}).`);
      event(reason, 'disconnect', closeEvent.code !== 1000 && closeEvent.code !== 1005);
      currentSessionSubtitle = messageTranslation(reason);
      ui.sessionSubtitle.textContent = reason;
      setState(closeEvent.code === 1000 || closeEvent.code === 1005 ? 'idle' : 'error');
      ui.disconnect.disabled = true;
      if (wasActive) toast(reason, closeEvent.code === 1000 || closeEvent.code === 1005 ? 'info' : 'error');
    });
  } catch (error) {
    if (authorizationAbort === abortController) authorizationAbort = null;
    if (generation !== connectGeneration) return;
    clearCredentials();
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
  connectGeneration++;
  authorizationAbort?.abort();
  authorizationAbort = null;
  const activeSocket = socket;
  socket = null;
  stopTimers();
  clearHostKeyPrompt();
  currentExpectedFingerprint = '';
  if (activeSocket && activeSocket.readyState < WebSocket.CLOSING) activeSocket.close(1000, 'Disconnected by user');
  currentSessionSubtitle = messageTranslation(reason);
  ui.sessionSubtitle.textContent = reason;
  event(reason, 'disconnect');
  setState('idle');
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
  void navigator.clipboard.writeText(url.toString()).then(
    () => toast(bilingual('安全连接链接已复制（不含凭据）。', 'Safe connection link copied (credentials excluded).')),
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
      toast(bilingual('已载入旧版密码 URL，使用后请从浏览器历史记录中删除。', 'A legacy password URL was loaded. Remove it from browser history after use.'), 'error');
    } catch {
      toast(bilingual('密码 URL 参数不是有效的 Base64。', 'The password URL parameter is not valid Base64.'), 'error');
    }
  }
  return Boolean(host && (value('autoconnect') === '1' || legacyPassword));
}

function applyWSSHOptions(options: WSSHOptions): void {
  clearCredentials();
  ui.host.value = options.host ?? options.hostname ?? ui.host.value;
  setPortValue(options.port ?? 22, 'wssh.connect()');
  ui.username.value = options.username?.trim() || 'root';
  if (options.password !== undefined) {
    setAuthMethod('password');
    ui.password.value = options.password;
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
    if (connectionState === 'connecting' || connectionState === 'connected') {
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
  radio.addEventListener('change', () => setAuthMethod(authMethod()));
}
ui.form.addEventListener('submit', (formEvent) => {
  formEvent.preventDefault();
  void connect();
});
ui.newProfile.addEventListener('click', clearForm);
ui.saveProfile.addEventListener('click', saveCurrentProfile);
ui.shareLink.addEventListener('click', copySafeLink);
ui.password.addEventListener('input', () => { passwordDirty = true; });
ui.revealPassword.addEventListener('click', () => {
  const reveal = ui.password.type === 'password';
  ui.password.type = reveal ? 'text' : 'password';
  updateRevealPasswordButton();
});
ui.keyFile.addEventListener('change', async () => {
  const file = ui.keyFile.files?.[0];
  if (!file) return;
  ui.keyFileName.textContent = file.name;
  if (file.size > MAX_KEY_BYTES) {
    showFormError(bilingual('所选私钥大于 64 KiB。', 'The selected private key is larger than 64 KiB.'));
    clearPrivateKeyFields();
    return;
  }
  try {
    ui.privateKey.value = await file.text();
  } catch {
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
    deleteProfile(deleteButton.dataset.deleteProfile);
    return;
  }
  const card = target.closest<HTMLElement>('[data-profile-id]');
  const profile = profiles.find((item) => item.id === card?.dataset.profileId);
  if (profile) applyProfile(profile);
});
ui.panelToggle.addEventListener('click', () => {
  const opening = !ui.panel.classList.contains('open');
  openPanel(opening);
  if (opening) requestAnimationFrame(() => ui.host.focus());
});
ui.panelScrim.addEventListener('click', () => {
  openPanel(false);
  ui.panelToggle.focus();
});
ui.emptyConnect.addEventListener('click', () => {
  if (window.matchMedia('(max-width: 760px)').matches) openPanel(true);
  ui.host.focus();
});
ui.disconnect.addEventListener('click', () => disconnect());
ui.clearTerminal.addEventListener('click', () => terminal.clear());
ui.fullscreenTerminal.addEventListener('click', async () => {
  if (document.fullscreenElement === ui.terminalCard) await document.exitFullscreen();
  else await ui.terminalCard.requestFullscreen();
});
document.addEventListener('fullscreenchange', () => fitTerminal(true));
ui.eventToggle.addEventListener('click', () => {
  ui.eventLog.hidden = !ui.eventLog.hidden;
  ui.eventToggle.setAttribute('aria-expanded', String(!ui.eventLog.hidden));
  fitTerminal(true);
});
  ui.languageToggle.addEventListener('click', () => {
  applyLanguage(currentLanguage === 'zh-CN' ? 'en' : 'zh-CN', true);
  renderProfiles();
  setState(connectionState);
  openPanel(ui.panel.classList.contains('open'));
  if (connectionState === 'idle') ui.sessionTitle.textContent = bilingual('无活动会话', 'No active session');
  ui.terminalLabel.textContent = connectionState === 'idle'
    ? bilingual('终端 · 等待', 'terminal · waiting')
    : `${bilingual('终端', 'terminal')} · ${ui.username.value.trim()}@${normalizeHost(ui.host.value)}`;
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
terminal.onData(sendTerminalData);
new ResizeObserver(() => fitTerminal(true)).observe(ui.terminalStage);
window.addEventListener('beforeunload', () => socket?.close(1000, 'Page closed'));
document.addEventListener('keydown', (keyEvent) => {
  if (keyEvent.key === 'Escape' && ui.panel.classList.contains('open') && !ui.hostKeyDialog.open) {
    openPanel(false);
    ui.panelToggle.focus();
  }
});
window.matchMedia('(max-width: 760px)').addEventListener('change', () => openPanel(false));

let storedTheme: string | null = null;
try { storedTheme = localStorage.getItem(THEME_STORAGE_KEY); } catch { /* Storage can be disabled. */ }
if (storedTheme === 'light' || storedTheme === 'dark') document.documentElement.dataset.theme = storedTheme;
applyLanguage(currentLanguage);
element<HTMLElement>('app').hidden = false;
renderProfiles();
openPanel(false);
setAuthMethod('password');
setState('idle');
ui.sessionTitle.textContent = bilingual('无活动会话', 'No active session');
ui.sessionSubtitle.textContent = bilingual('选择目标并连接', 'Choose a target and connect');
ui.terminalLabel.textContent = bilingual('终端 · 等待', 'terminal · waiting');
ui.eventMessage.textContent = bilingual('Worker 运行时待命', 'Worker runtime standing by');
initializeCompatibilityAPI();
const shouldAutoConnect = applyURLParameters();
requestAnimationFrame(() => {
  fitTerminal(false);
  if (shouldAutoConnect) void connect();
});
