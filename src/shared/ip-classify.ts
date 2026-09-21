// Shared literal-IP classification — the SINGLE SOURCE OF TRUTH used by both
// the Worker (`src/backend/geo-service.ts`) and the browser
// (`frontend/src/network-manager.ts`).
//
// Why this lives in one place: after the geolocation lookup moved to a
// browser-direct provider call, the decision "may this address leave the
// machine for a third-party provider?" is now made in the FRONTEND. If the
// client-side classifier were even slightly weaker than the server-side one, a
// private/reserved literal it failed to recognise would leak to the provider
// over the network before the Worker fallback ever ran. Keeping a single
// implementation makes that class of drift impossible.
//
// Fail-closed by construction: only a syntactically valid IPv4/IPv6 literal can
// ever classify as `public`. Anything unparseable or unrecognised is reported
// as `invalid` (never `public`), so it can never trigger a request on either
// path.
//
// Alternate and expanded IPv6 spellings are folded through WHATWG URL
// normalization before the range checks run, so `0:0:0:0:0:0:0:1`,
// `::ffff:a00:1` and `[::ffff:a00:1]` are all recognised as private.
//
// Every IPv4-embedded IPv6 form is decoded back to its trailing 32 bits and
// classified as IPv4, so a private address cannot hide inside one of them:
//   ::ffff:0:0/96    IPv4-mapped (RFC 4291)
//   ::/96            IPv4-compatible (deprecated, RFC 4291)
//   64:ff9b::/96     NAT64 well-known prefix (RFC 6052)
//   64:ff9b:1::/96   NAT64 local-use prefix (RFC 8215)
// A NAT64/compatible address that embeds a PUBLIC IPv4 (e.g. 64:ff9b::8.8.8.8)
// is deliberately kept `public` — it denotes a routable destination, not the
// user's private space.

/** Classification of a literal IP address. */
export type IpKind = 'invalid' | 'private' | 'public';

/** Maximum accepted literal length; longer inputs are treated as invalid. */
const MAX_IP_LENGTH = 64;

function isIPv4(value: string): boolean {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (!match) return false;
  for (let index = 1; index <= 4; index++) {
    const part = match[index]!;
    if (part.length > 1 && part.startsWith('0')) return false;
    if (Number(part) > 255) return false;
  }
  return true;
}

/**
 * Normalizes an IPv6 literal to the bracketed form WHATWG's URL parser returns,
 * or null when it is not a valid IPv6 literal. A single surrounding pair of
 * brackets is tolerated (the collector may hand us `[::1]`-style hosts) so the
 * result is the same whether or not the caller kept the brackets.
 */
function normalizeIPv6(value: string): string | null {
  const stripped = value.replace(/^\[|\]$/g, '');
  if (!stripped.includes(':')) return null;
  try {
    const hostname = new URL(`http://[${stripped}]:0/`).hostname;
    return hostname.startsWith('[') ? hostname : null;
  } catch {
    return null;
  }
}

function isPrivateIPv4(value: string): boolean {
  const octets = value.split('.').map((part) => Number(part));
  const [a, b, c] = octets as [number, number, number, number];
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 169 && b === 254) return true; // link-local
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  // Only the two IETF special-use /24s (192.0.0.0/24 and 192.0.2.0/24) are
  // reserved; the rest of 192.0.0.0/16 (e.g. 192.0.10.1) is ordinary space.
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true; // multicast + reserved
  return false;
}

/**
 * Expands a normalized IPv6 literal (lowercased, brackets already stripped,
 * possibly `::`-compressed, all-hex groups) into its eight 16-bit groups.
 * Returns null when the literal is not well-formed.
 */
function expandIPv6(value: string): number[] | null {
  if (!value.includes(':')) return null;
  if ((value.match(/::/g) ?? []).length > 1) return null;
  const hasCompression = value.includes('::');
  const [headText, tailText] = hasCompression ? value.split('::') : [value, ''];
  const parseGroups = (text: string): number[] | null => {
    if (text === '') return [];
    const groups: number[] = [];
    for (const part of text.split(':')) {
      if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
      groups.push(Number.parseInt(part, 16));
    }
    return groups;
  };
  const head = parseGroups(headText ?? '');
  const tail = hasCompression ? parseGroups(tailText ?? '') : [];
  if (head === null || tail === null) return null;
  if (!hasCompression) return head.length === 8 ? head : null;
  // A compressed literal must leave room for at least one elided group.
  if (head.length + tail.length >= 8) return null;
  const zeros = new Array(8 - head.length - tail.length).fill(0);
  return [...head, ...zeros, ...tail];
}

// 96-bit prefixes whose trailing 32 bits carry an embedded IPv4 address.
const EMBEDDED_IPV4_PREFIXES: ReadonlyArray<ReadonlyArray<number>> = [
  [0, 0, 0, 0, 0, 0xffff], // ::ffff:0:0/96 IPv4-mapped
  [0, 0, 0, 0, 0, 0], //      ::/96         IPv4-compatible (deprecated)
  [0x0064, 0xff9b, 0, 0, 0, 0], // 64:ff9b::/96     NAT64 well-known
  [0x0064, 0xff9b, 0x0001, 0, 0, 0], // 64:ff9b:1::/96 NAT64 local-use
];

/**
 * Returns the dotted IPv4 address embedded in `groups` when its first 96 bits
 * match one of {@link EMBEDDED_IPV4_PREFIXES}, else null. Because the groups
 * always number eight, a matched prefix always yields exactly 32 trailing bits
 * — there is no "partial" remainder to mishandle.
 */
function embeddedIPv4FromGroups(groups: ReadonlyArray<number>): string | null {
  const matches = EMBEDDED_IPV4_PREFIXES.some((prefix) =>
    prefix.every((part, index) => groups[index] === part),
  );
  if (!matches) return null;
  const high = groups[6]!;
  const low = groups[7]!;
  return `${(high >> 8) & 0xff}.${high & 0xff}.${(low >> 8) & 0xff}.${low & 0xff}`;
}

function isPrivateIPv6(bracketed: string): boolean {
  const ip = bracketed.replace(/^\[|\]$/g, '').toLowerCase();
  // Preserve the explicit loopback / unspecified verdicts.
  if (ip === '::1' || ip === '::') return true;
  // IPv4-embedded IPv6 in dotted form (defensive: classifyIp normalizes first).
  const dotted = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(ip);
  if (dotted && isIPv4(dotted[1]!)) return isPrivateIPv4(dotted[1]!);
  // Decode any IPv4-embedded form (mapped / compatible / NAT64) and judge the
  // recovered IPv4. `classifyIp` only reaches here with a WHATWG-normalized
  // literal, so expansion cannot fail — fail closed if it somehow does.
  const groups = expandIPv6(ip);
  if (groups === null) return true;
  const embedded = embeddedIPv4FromGroups(groups);
  if (embedded !== null) return isPrivateIPv4(embedded);
  if (/^fe[89ab]/.test(ip)) return true; // fe80::/10 link-local
  if (/^f[cd]/.test(ip)) return true; // fc00::/7 unique-local
  if (/^ff/.test(ip)) return true; // ff00::/8 multicast
  return false;
}

/** Classifies a literal IP as invalid, private/reserved, or public. */
export function classifyIp(value: string): IpKind {
  const ip = typeof value === 'string' ? value.trim() : '';
  if (ip === '' || ip.length > MAX_IP_LENGTH) return 'invalid';
  if (isIPv4(ip)) return isPrivateIPv4(ip) ? 'private' : 'public';
  const v6 = normalizeIPv6(ip);
  if (v6) return isPrivateIPv6(v6) ? 'private' : 'public';
  return 'invalid';
}
