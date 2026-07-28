export interface SSHPacket {
  length: number;
  paddingLength: number;
  payload: Uint8Array;
  mac?: Uint8Array;
}

export interface KEXInitMessage {
  kexAlgorithms: string[];
  hostKeyAlgorithms: string[];
  encryptionC2S: string[];
  encryptionS2C: string[];
  macC2S: string[];
  macS2C: string[];
  compressionC2S: string[];
  compressionS2C: string[];
  firstKexPacketFollows: boolean;
}

export interface SessionKeys {
  ivClientToServer: Uint8Array;
  ivServerToClient: Uint8Array;
  encKeyClientToServer: Uint8Array;
  encKeyServerToClient: Uint8Array;
  integrityKeyC2S: Uint8Array;
  integrityKeyS2C: Uint8Array;
  sessionID: Uint8Array;
}

export interface SSHConnectionConfig {
  type: 'connect';
  host: string;
  port: number;
  username: string;
  authMethod: 'password' | 'publickey';
  password?: string;
  privateKey?: string;
  cols: number;
  rows: number;
  term: string;
  expectedFingerprint?: string;
}

export interface TerminalSize {
  cols: number;
  rows: number;
}

export interface Env {
  SSH_SESSIONS: DurableObjectNamespace;
  ASSETS?: Fetcher;
  CONNECT_TIMEOUT_MS?: string;
}

export const SSH_MSG_DISCONNECT = 1;
export const SSH_MSG_IGNORE = 2;
export const SSH_MSG_UNIMPLEMENTED = 3;
export const SSH_MSG_DEBUG = 4;
export const SSH_MSG_SERVICE_REQUEST = 5;
export const SSH_MSG_SERVICE_ACCEPT = 6;
export const SSH_MSG_EXT_INFO = 7;
export const SSH_MSG_KEXINIT = 20;
export const SSH_MSG_NEWKEYS = 21;
export const SSH_MSG_KEX_ECDH_INIT = 30;
export const SSH_MSG_KEX_ECDH_REPLY = 31;
export const SSH_MSG_USERAUTH_REQUEST = 50;
export const SSH_MSG_USERAUTH_FAILURE = 51;
export const SSH_MSG_USERAUTH_SUCCESS = 52;
export const SSH_MSG_USERAUTH_INFO_REQUEST = 60;
export const SSH_MSG_GLOBAL_REQUEST = 80;
export const SSH_MSG_REQUEST_SUCCESS = 81;
export const SSH_MSG_REQUEST_FAILURE = 82;
export const SSH_MSG_CHANNEL_OPEN = 90;
export const SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
export const SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
export const SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
export const SSH_MSG_CHANNEL_DATA = 94;
export const SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
export const SSH_MSG_CHANNEL_EOF = 96;
export const SSH_MSG_CHANNEL_CLOSE = 97;
export const SSH_MSG_CHANNEL_REQUEST = 98;
export const SSH_MSG_CHANNEL_SUCCESS = 99;
export const SSH_MSG_CHANNEL_FAILURE = 100;

const HOST_RE = /^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)*[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

export function normalizeTerminalSize(cols: unknown, rows: unknown): TerminalSize | null {
  if (typeof cols !== 'number' || typeof rows !== 'number' || !Number.isFinite(cols) || !Number.isFinite(rows)) {
    return null;
  }
  const size = { cols: Math.floor(cols), rows: Math.floor(rows) };
  return size.cols >= 10 && size.cols <= 1000 && size.rows >= 5 && size.rows <= 1000 ? size : null;
}

function isValidHost(host: string): boolean {
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  if (bare.includes(':')) {
    try {
      return new URL(`http://[${bare}]`).hostname.length > 2;
    } catch {
      return false;
    }
  }
  if (/^[\d.]+$/.test(bare)) {
    if (!IPV4_RE.test(bare)) return false;
    return bare.split('.').every((part) => Number(part) <= 255 && (part === '0' || !part.startsWith('0')));
  }
  return HOST_RE.test(bare);
}

export function parseConnectMessage(value: unknown): SSHConnectionConfig {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid connect message');
  const raw = value as Record<string, unknown>;
  if (raw.type !== 'connect') throw new Error('The first message must be type "connect"');
  if (typeof raw.host !== 'string' || !isValidHost(raw.host.trim())) throw new Error('Invalid SSH host');
  if (typeof raw.port !== 'number' || !Number.isInteger(raw.port) || raw.port < 1 || raw.port > 65535) throw new Error('Invalid SSH port');
  if (typeof raw.username !== 'string' || raw.username.length < 1 || raw.username.length > 128 || /[\0\r\n]/.test(raw.username)) throw new Error('Invalid SSH username');
  if (raw.authMethod !== 'password' && raw.authMethod !== 'publickey') throw new Error('Invalid authentication method');
  const allowedFields = new Set(['type', 'host', 'port', 'username', 'authMethod', 'password', 'privateKey', 'cols', 'rows', 'term', 'expectedFingerprint']);
  if (Object.keys(raw).some((field) => !allowedFields.has(field))) throw new Error('Unsupported connection field');
  const size = normalizeTerminalSize(raw.cols ?? 120, raw.rows ?? 40);
  if (!size) throw new Error('Invalid terminal size');

  const password = typeof raw.password === 'string' ? raw.password : undefined;
  const privateKey = typeof raw.privateKey === 'string' ? raw.privateKey : undefined;
  if (raw.authMethod === 'password' && (password === undefined || password.length > 4096 || privateKey !== undefined)) throw new Error('Password is required and must be the only credential');
  if (raw.authMethod === 'publickey' && (!privateKey || privateKey.length > 128 * 1024 || !privateKey.includes('BEGIN OPENSSH PRIVATE KEY') || password !== undefined)) throw new Error('An unencrypted OpenSSH private key is required and must be the only credential');
  if (raw.expectedFingerprint !== undefined && (typeof raw.expectedFingerprint !== 'string' || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(raw.expectedFingerprint))) throw new Error('Invalid host key fingerprint');
  const term = typeof raw.term === 'string' && /^[A-Za-z0-9._+-]{1,64}$/.test(raw.term) ? raw.term : 'xterm-256color';

  return {
    type: 'connect', host: raw.host.trim().replace(/^\[|\]$/g, ''), port: raw.port,
    username: raw.username, authMethod: raw.authMethod, password, privateKey,
    cols: size.cols, rows: size.rows, term, expectedFingerprint: raw.expectedFingerprint as string | undefined,
  };
}
