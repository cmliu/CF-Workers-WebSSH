// Parser for the network-monitor snapshot stream produced by
// `NETWORK_MONITOR_COMMAND` in src/backend/session.ts.
//
// A tick is a sequence of marker-delimited, tab-separated sections:
//
//   __CF_WEBSSH_NETWORK_AGGREGATE__\n
//   PID\tNAME\tUSER\tLISTEN_IP\tLISTEN_PORT\tREMOTE_IP_COUNT\tCONNECTION_COUNT\tBYTES_SENT\tBYTES_RECV\n
//   <pid>\t<name>\t<user>\t<lip>\t<lport>\t<nip>\t<nconn>\t<sent>\t<recv>\n
//   __CF_WEBSSH_NETWORK_CONNECTIONS__\n
//   PID\tPROTO\tLOCAL_ADDR\tLOCAL_PORT\tREMOTE_ADDR\tREMOTE_PORT\tSTATE\tBYTES_SENT\tBYTES_RECV\n
//   <connection rows, may be empty>
//   __CF_WEBSSH_NETWORK_BYTES__\t<txTotal>\t<rxTotal>\n
//   __CF_WEBSSH_NETWORK_ERROR__\t<human readable reason>\n   (only on failure)
//
// The aggregate and connection rows keep the wire shape verbatim (snake_case
// keys) so the parser and the shell agree on every column name. Only the
// Linux + `ss` collection path is implemented; other platforms are expected to
// surface a `__CF_WEBSSH_NETWORK_ERROR__` line instead.

/** Marks the per-PID aggregate section of a tick. */
export const NETWORK_AGGREGATE_MARKER = '__CF_WEBSSH_NETWORK_AGGREGATE__';
/** Marks the per-connection detail section of a tick. */
export const NETWORK_CONNECTIONS_MARKER = '__CF_WEBSSH_NETWORK_CONNECTIONS__';
/** Marks the NIC-level cumulative byte totals (tx/rx) of a tick. */
export const NETWORK_BYTES_MARKER = '__CF_WEBSSH_NETWORK_BYTES__';
/** Marks a human-readable error line; emitted at most once per monitor lifetime. */
export const NETWORK_ERROR_MARKER = '__CF_WEBSSH_NETWORK_ERROR__';

/**
 * Prefix shared by every section marker. A block body ends when the next
 * section begins, so scanning for this prefix delimits the current section
 * without knowing which marker comes next.
 */
const ANY_MARKER_PREFIX = '__CF_WEBSSH_NETWORK_';

/** Collection platform reported by the shell (`uname -s`). P0 only ships Linux. */
export type NetworkPlatform = 'linux' | 'darwin' | 'freebsd' | 'other';

/**
 * One row of the per-PID aggregate table. Byte totals are cumulative over the
 * lifetime of the process's sockets (they can drop when a socket closes) and
 * are only available when the collector can read `tcp_info` (i.e. as root).
 */
export interface NetworkAggregateRow {
  pid: number;
  name: string;
  user: string;
  listen_ip: string;
  /** Listening transport (`tcp` / `udp` / `tcp/udp`); empty when unknown. */
  proto: string;
  listen_port: number;
  remote_ip_count: number;
  connection_count: number;
  bytes_sent: number;
  bytes_recv: number;
}

/** One connection detail row. P0 forwards the block even when it is empty. */
export interface NetworkConnectionRow {
  pid: number;
  proto: string;
  local_addr: string;
  local_port: number;
  remote_addr: string;
  remote_port: number;
  state: string;
  bytes_sent: number;
  bytes_recv: number;
}

/** NIC-level cumulative counters (all non-virtual interfaces summed). */
export interface NetworkBytesTotals {
  txBytes: number;
  rxBytes: number;
}

/** A full, decoded tick. */
export interface NetworkSnapshot {
  timestamp: number;
  host: NetworkPlatform;
  aggregate: NetworkAggregateRow[];
  connections: NetworkConnectionRow[];
  bytesTotals: NetworkBytesTotals | null;
  errorMessage: string | null;
}

/** Thrown when a tick cannot be decoded (missing marker / header / bad PID). */
export class NetworkParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NetworkParseError';
  }
}

function toPlatform(value: string): NetworkPlatform {
  return value === 'linux' || value === 'darwin' || value === 'freebsd' ? value : 'other';
}

/** Parses a base-10 non-negative integer, rejecting floats, signs and overflow. */
function parseNonNegativeInteger(value: string | undefined): number | null {
  if (value === undefined || !/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

/** True for a line that begins a new section (`__CF_WEBSSH_NETWORK_*`). */
function isSectionMarker(line: string): boolean {
  return line.startsWith(ANY_MARKER_PREFIX);
}

/**
 * Returns the text between `marker` and the next section marker (exclusive).
 * Returns null when `marker` is absent. The returned slice always begins with
 * the newline that terminates the marker line.
 */
function sectionBody(raw: string, marker: string): string | null {
  const start = raw.indexOf(marker);
  if (start < 0) return null;
  const afterStart = start + marker.length;
  const end = raw.indexOf(ANY_MARKER_PREFIX, afterStart);
  return end < 0 ? raw.slice(afterStart) : raw.slice(afterStart, end);
}

/**
 * Decodes the aggregate block into per-PID rows sorted by ascending PID.
 *
 * @throws {NetworkParseError} when the aggregate marker or the column header
 *   is missing, or when a row carries a PID that is not a positive integer.
 */
export function parseAggregateBlock(raw: string, _platform: string = 'linux'): NetworkAggregateRow[] {
  const body = sectionBody(raw, NETWORK_AGGREGATE_MARKER);
  if (body === null) {
    throw new NetworkParseError(`Network payload is missing the ${NETWORK_AGGREGATE_MARKER} marker`);
  }
  const rows: NetworkAggregateRow[] = [];
  let headerSeen = false;
  for (const rawLine of body.split('\n')) {
    const line = rawLine.replace(/\r$/, '');
    if (line === '') continue;
    if (isSectionMarker(line)) break;
    const fields = line.split('\t');
    if (!headerSeen) {
      if (fields[0] !== 'PID') {
        throw new NetworkParseError('Network aggregate block is missing its header row');
      }
      headerSeen = true;
      continue;
    }
    if (fields.length < 10) {
      throw new NetworkParseError('Network aggregate row is malformed');
    }
    const pid = parseNonNegativeInteger(fields[0]);
    if (pid === null || pid === 0) {
      throw new NetworkParseError(`Invalid PID in the network aggregate block: ${fields[0]}`);
    }
    rows.push({
      pid,
      name: fields[1] ?? '',
      user: fields[2] ?? '',
      listen_ip: fields[3] ?? '',
      proto: fields[4] ?? '',
      listen_port: parseNonNegativeInteger(fields[5]) ?? 0,
      remote_ip_count: parseNonNegativeInteger(fields[6]) ?? 0,
      connection_count: parseNonNegativeInteger(fields[7]) ?? 0,
      bytes_sent: parseNonNegativeInteger(fields[8]) ?? 0,
      bytes_recv: parseNonNegativeInteger(fields[9]) ?? 0,
    });
  }
  if (!headerSeen) {
    throw new NetworkParseError('Network aggregate block is missing its header row');
  }
  rows.sort((left, right) => left.pid - right.pid);
  return rows;
}

/**
 * Decodes the connection detail block. An absent marker or an empty body both
 * yield an empty list (the shell always prints the marker and header, but P0
 * never populates the rows).
 *
 * @throws {NetworkParseError} when the header row is present but not the
 *   expected `PID` header.
 */
export function parseConnectionsBlock(raw: string, _platform: string = 'linux'): NetworkConnectionRow[] {
  const body = sectionBody(raw, NETWORK_CONNECTIONS_MARKER);
  if (body === null) return [];
  const rows: NetworkConnectionRow[] = [];
  let headerSeen = false;
  for (const rawLine of body.split('\n')) {
    const line = rawLine.replace(/\r$/, '');
    if (line === '') continue;
    if (isSectionMarker(line)) break;
    const fields = line.split('\t');
    if (!headerSeen) {
      if (fields[0] !== 'PID') {
        throw new NetworkParseError('Network connection block is missing its header row');
      }
      headerSeen = true;
      continue;
    }
    if (fields.length < 9) continue;
    const pid = parseNonNegativeInteger(fields[0]);
    if (pid === null || pid === 0) continue;
    rows.push({
      pid,
      proto: fields[1] ?? '',
      local_addr: fields[2] ?? '',
      local_port: parseNonNegativeInteger(fields[3]) ?? 0,
      remote_addr: fields[4] ?? '',
      remote_port: parseNonNegativeInteger(fields[5]) ?? 0,
      state: fields[6] ?? '',
      bytes_sent: parseNonNegativeInteger(fields[7]) ?? 0,
      bytes_recv: parseNonNegativeInteger(fields[8]) ?? 0,
    });
  }
  return rows;
}

/** Extracts `__CF_WEBSSH_NETWORK_BYTES__\t<tx>\t<rx>`; null when absent/invalid. */
function parseBytesTotals(raw: string): NetworkBytesTotals | null {
  const match = raw.match(/__CF_WEBSSH_NETWORK_BYTES__\t(\d+)\t(\d+)/);
  if (!match) return null;
  const txBytes = parseNonNegativeInteger(match[1]);
  const rxBytes = parseNonNegativeInteger(match[2]);
  if (txBytes === null || rxBytes === null) return null;
  return { txBytes, rxBytes };
}

/** Extracts the human-readable reason that follows the error marker. */
function parseErrorMessage(raw: string): string | null {
  const index = raw.indexOf(NETWORK_ERROR_MARKER);
  if (index < 0) return null;
  const rest = raw.slice(index + NETWORK_ERROR_MARKER.length);
  const line = rest.split('\n', 1)[0] ?? '';
  const message = line.replace(/^\t/, '').trim();
  return message || null;
}

/**
 * Decodes a complete tick into a {@link NetworkSnapshot}.
 *
 * @throws {NetworkParseError} propagated from {@link parseAggregateBlock} when
 *   the tick cannot be decoded at all.
 */
export function parseNetworkSnapshot(raw: string, timestamp: number, platform: string = 'linux'): NetworkSnapshot {
  return {
    timestamp,
    host: toPlatform(platform),
    aggregate: parseAggregateBlock(raw, platform),
    connections: parseConnectionsBlock(raw, platform),
    bytesTotals: parseBytesTotals(raw),
    errorMessage: parseErrorMessage(raw),
  };
}
