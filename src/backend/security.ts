const encoder = new TextEncoder();
const decoder = new TextDecoder();
const TICKET_TTL_MS = 60_000;

interface TicketPayload {
  exp: number;
  nonce: string;
  ip: string;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('Invalid Base64URL value');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  if (toBase64Url(Uint8Array.from(binary, (char) => char.charCodeAt(0))) !== value) throw new Error('Non-canonical Base64URL value');
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export async function createTicket(secret: Uint8Array, ip: string): Promise<{ ticket: string; expiresAt: number }> {
  const expiresAt = Date.now() + TICKET_TTL_MS;
  const payload: TicketPayload = { exp: expiresAt, nonce: crypto.randomUUID(), ip };
  const encodedPayload = toBase64Url(encoder.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey('raw', new Uint8Array(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(encodedPayload)));
  return { ticket: `${encodedPayload}.${toBase64Url(signature)}`, expiresAt };
}

export async function verifyTicket(secret: Uint8Array, ticket: string, ip: string): Promise<boolean> {
  const parts = ticket.split('.');
  if (parts.length !== 2 || parts[0].length > 1024 || parts[1].length > 128) return false;
  try {
    const key = await crypto.subtle.importKey('raw', new Uint8Array(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify('HMAC', key, new Uint8Array(fromBase64Url(parts[1])), encoder.encode(parts[0]));
    if (!valid) return false;
    const payload = JSON.parse(decoder.decode(fromBase64Url(parts[0]))) as Partial<TicketPayload>;
    return typeof payload.exp === 'number' && Number.isFinite(payload.exp)
      && payload.exp >= Date.now() && payload.exp <= Date.now() + TICKET_TTL_MS + 5000
      && payload.ip === ip && typeof payload.nonce === 'string'
      && /^[0-9a-f-]{36}$/i.test(payload.nonce);
  } catch {
    return false;
  }
}

export function isSameOrigin(request: Request): boolean {
  const origin = request.headers.get('Origin');
  return origin !== null && origin === new URL(request.url).origin;
}

function isIPv4(host: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)
    && host.split('.').every((part) => Number(part) <= 255 && (part === '0' || !part.startsWith('0')));
}

function normalizeIPv6(host: string): string {
  try {
    return new URL(`http://[${host}]`).hostname.replace(/^\[|\]$/g, '').toLowerCase();
  } catch {
    return host.toLowerCase();
  }
}

export function isPrivateAddress(host: string): boolean {
  const value = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (value === 'localhost' || value.endsWith('.localhost') || value === '0.0.0.0'
    || value === 'metadata.google.internal' || value.endsWith('.internal')) return true;
  if (isIPv4(value)) {
    const [a, b, c] = value.split('.').map(Number);
    return a === 0 || a === 10 || a === 127
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 0 && c === 0)
      || (a === 192 && b === 0 && c === 2)
      || (a === 192 && b === 88 && c === 99)
      || (a === 192 && b === 168)
      || (a === 198 && (b === 18 || b === 19))
      || (a === 198 && b === 51 && c === 100)
      || (a === 203 && b === 0 && c === 113)
      || a >= 224;
  }
  if (!value.includes(':')) return false;
  const ipv6 = normalizeIPv6(value);
  if (ipv6 === '::' || ipv6 === '::1'
    || /^f[cd]/.test(ipv6)
    || /^fe[89ab]/.test(ipv6)
    || ipv6.startsWith('2001:db8:')
    || ipv6.startsWith('ff')) return true;
  if (ipv6.startsWith('::ffff:')) {
    const mapped = ipv6.slice('::ffff:'.length);
    if (isIPv4(mapped)) return isPrivateAddress(mapped);
    const halves = mapped.split(':');
    if (halves.length === 2 && halves.every((part) => /^[0-9a-f]{1,4}$/.test(part))) {
      const numeric = (Number.parseInt(halves[0], 16) * 0x10000 + Number.parseInt(halves[1], 16)) >>> 0;
      return isPrivateAddress(`${numeric >>> 24}.${numeric >>> 16 & 0xff}.${numeric >>> 8 & 0xff}.${numeric & 0xff}`);
    }
    return true;
  }
  return false;
}

interface DnsAnswer { type: number; data: string }

export async function resolvePublicAddresses(host: string): Promise<string[]> {
  if (host.includes(':') || isIPv4(host)) return [host];
  const endpoint = 'https://cloudflare-dns.com/dns-query';
  const headers = { Accept: 'application/dns-json' };
  const responses = await Promise.all(['A', 'AAAA'].map((type) => fetch(`${endpoint}?name=${encodeURIComponent(host)}&type=${type}`, {
    headers,
    redirect: 'manual',
    signal: AbortSignal.timeout(5000),
  })));
  const addresses: string[] = [];
  for (const response of responses) {
    if (!response.ok) throw new Error('Unable to verify the target DNS records');
    const responseUrl = new URL(response.url);
    if (responseUrl.origin !== 'https://cloudflare-dns.com'
      || !responseUrl.pathname.startsWith('/dns-query')
      || !response.headers.get('Content-Type')?.toLowerCase().startsWith('application/dns-json')) {
      throw new Error('Unexpected DNS resolver response');
    }
    const result = await response.json<{ Status: number; Answer?: DnsAnswer[] }>();
    if (result.Status !== 0 && result.Status !== 3) throw new Error('Unable to verify the target DNS records');
    if ((result.Answer?.length ?? 0) > 64) throw new Error('Target DNS response has too many records');
    for (const answer of result.Answer ?? []) {
      if (answer.type === 1 && isIPv4(answer.data)) addresses.push(answer.data);
      if (answer.type === 28 && answer.data.includes(':')) {
        const normalized = normalizeIPv6(answer.data);
        if (!normalized.includes('%') && normalized.includes(':')) addresses.push(normalized);
      }
    }
  }
  return addresses;
}

export async function assertPublicTarget(host: string): Promise<string[]> {
  if (isPrivateAddress(host)) throw new Error('Private and reserved SSH targets are disabled');
  const addresses = await resolvePublicAddresses(host);
  if (addresses.length === 0) throw new Error('SSH target did not resolve to an address');
  for (const address of addresses) if (isPrivateAddress(address)) throw new Error('Target DNS resolves to a private or reserved address');
  const unique = [...new Set(addresses.map((address) => address.toLowerCase()))];
  if (unique.length > 16) throw new Error('SSH target resolves to too many addresses');
  return unique;
}
