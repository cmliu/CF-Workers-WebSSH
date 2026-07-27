export interface EncryptedPassword {
  v: 1;
  iv: string;
  ciphertext: string;
}

export interface DecryptedPassword {
  ok: boolean;
  password: string;
}

const IV_BYTES = 12;
const TAG_BYTES = 16;
const MAX_PASSWORD_CHARS = 4096;
const MAX_PASSWORD_BYTES = 16_384;
const MAX_CONTEXT_CHARS = 512;
const AAD_PREFIX = 'workers-webssh/history-password/v1\0';

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase64Url(value: string, maxBytes: number): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length > Math.ceil(maxBytes * 4 / 3)) return null;
  try {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
    const binary = atob(padded);
    if (binary.length > maxBytes) return null;
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return encodeBase64Url(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
}

function additionalData(context: string): Uint8Array<ArrayBuffer> {
  if (!context || context.length > MAX_CONTEXT_CHARS) throw new Error('Invalid password encryption context');
  return new TextEncoder().encode(`${AAD_PREFIX}${context}`);
}

export function isEncryptedPassword(value: unknown): value is EncryptedPassword {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const envelope = value as Partial<EncryptedPassword>;
  if (Object.keys(value).some((field) => !['v', 'iv', 'ciphertext'].includes(field))) return false;
  if (envelope.v !== 1 || typeof envelope.iv !== 'string' || typeof envelope.ciphertext !== 'string') return false;
  const iv = decodeBase64Url(envelope.iv, IV_BYTES);
  const ciphertext = decodeBase64Url(envelope.ciphertext, MAX_PASSWORD_BYTES + TAG_BYTES);
  return iv?.length === IV_BYTES && ciphertext !== null && ciphertext.length >= TAG_BYTES;
}

export async function encryptPassword(password: string, key: CryptoKey, context: string): Promise<EncryptedPassword> {
  if (password.length > MAX_PASSWORD_CHARS) throw new Error('Password is too long');
  const plaintext = new TextEncoder().encode(password);
  if (plaintext.length > MAX_PASSWORD_BYTES) throw new Error('Password is too large');
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({
    name: 'AES-GCM',
    iv,
    additionalData: additionalData(context),
    tagLength: TAG_BYTES * 8,
  }, key, plaintext));
  return { v: 1, iv: encodeBase64Url(iv), ciphertext: encodeBase64Url(ciphertext) };
}

export async function decryptPasswordResult(envelope: unknown, key: CryptoKey, context: string): Promise<DecryptedPassword> {
  if (!isEncryptedPassword(envelope)) return { ok: false, password: '' };
  try {
    const iv = decodeBase64Url(envelope.iv, IV_BYTES);
    const ciphertext = decodeBase64Url(envelope.ciphertext, MAX_PASSWORD_BYTES + TAG_BYTES);
    if (!iv || !ciphertext) return { ok: false, password: '' };
    const plaintext = new Uint8Array(await crypto.subtle.decrypt({
      name: 'AES-GCM',
      iv,
      additionalData: additionalData(context),
      tagLength: TAG_BYTES * 8,
    }, key, ciphertext));
    if (plaintext.length > MAX_PASSWORD_BYTES) return { ok: false, password: '' };
    const password = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    return password.length <= MAX_PASSWORD_CHARS
      ? { ok: true, password }
      : { ok: false, password: '' };
  } catch {
    return { ok: false, password: '' };
  }
}

export async function decryptPassword(envelope: unknown, key: CryptoKey, context: string): Promise<string> {
  return (await decryptPasswordResult(envelope, key, context)).password;
}
