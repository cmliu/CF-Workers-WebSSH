export interface ProcessMetrics {
  cpuPercent: number | null;
  loadAverage: [number, number, number] | null;
  memory: ResourceUsage | null;
  swap: ResourceUsage | null;
  network: NetworkSample[] | null;
}

export interface ResourceUsage {
  usedBytes: number;
  totalBytes: number;
  percent: number;
}

// Network interface samples from a single top-monitor tick. The server emits
// one row per non-virtual interface (cumulative rx/tx byte counters, capped at
// MAX_NETWORK_INTERFACES rows); the frontend differentiates successive samples
// of the selected interface with a local clock to compute the upload /
// download rate.
export interface NetworkSample {
  iface: string;
  rxBytes: number;
  txBytes: number;
}

export interface ProcessEntry {
  pid: number;
  user: string;
  memoryBytes: number | null;
  memoryPercent: number | null;
  cpuPercent: number | null;
  state: string;
  time: string;
  command: string;
}

export interface ProcessSnapshot {
  metrics: ProcessMetrics;
  processes: ProcessEntry[];
  timestamp: number;
}

const ANSI_ESCAPE_RE = /\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))/g;
const MAX_PROCESSES = 512;
// Upper bound on the number of network interface rows the shell may emit per
// tick (and the frontend guard accepts). Mirrors the shell's own 32-line cap
// so a hostile or misbehaving host cannot flood the snapshot with rows.
const MAX_NETWORK_INTERFACES = 32;
// Matches the network section the shell command emits after a single
// `__CF_WEBSSH_NETWORK__` marker per tick. The marker mirrors the top-snapshot
// marker (octal escapes for `_`) so the same framing primitives apply.
const PROCESS_NETWORK_MARKER = '__CF_WEBSSH_NETWORK__';

// Matches a single numeric token that may use ',' or '.' as decimal separator.
const NUMBER_TOKEN_RE = /\d+(?:[.,]\d+)?/;

function finiteNumber(value: string | undefined | null): number | null {
  if (!value) return null;
  const parsed = Number(value.replace(',', '.').replace(/%$/, ''));
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

// Parses "10,23" / "10.23" / "10" -> number. Returns null on invalid input.
function parseDecimal(token: string | undefined | null): number | null {
  if (!token) return null;
  if (!NUMBER_TOKEN_RE.test(token)) return null;
  // Ensure the whole token is a number (e.g. reject "10abc").
  if (!/^\d+(?:[.,]\d+)?$/.test(token)) return null;
  return Number(token.replace(',', '.'));
}

function clampPercent(value: number): number {
  return Math.min(100, Math.max(0, value));
}

function parseLoad(lines: string[]): [number, number, number] | null {
  for (const line of lines) {
    // Linux: "load average: 10.23, 11.92, 12.63"
    // FreeBSD: "load averages: 10,23, 11,92, 12,63"
    const prefix = line.match(/load averages?\s*:\s*(.+)/i);
    if (!prefix) continue;
    const tokens = prefix[1].match(/\d+(?:[.,]\d+)?/g);
    if (!tokens || tokens.length < 3) continue;
    const values = tokens.slice(0, 3).map(parseDecimal);
    if (values.every((value): value is number => value !== null)) return values as [number, number, number];
  }
  return null;
}

function parseCPU(lines: string[]): number | null {
  for (const line of lines) {
    // Linux: "%Cpu(s): 13.1 us, 0.7 sy, 6.4 ni, 79.6 id, ..."
    // FreeBSD: "CPU: 13,1% user, 0,7% nice, 6,4% system, 0,1% interrupt, 79,6% idle"
    // macOS: "CPU usage: 13% user, 6% sys, 79% idle"
    if (!/(?:^|\s)(?:%?Cpu\(s\)|CPU(?:\s+usage)?|%CPU)\s*:/i.test(line)) continue;
    const idle = line.match(/([\d.,]+)\s*%?\s*(?:id|idle)\b/i);
    const idlePercent = parseDecimal(idle?.[1]);
    if (idlePercent !== null) return clampPercent(100 - idlePercent);
    // Fallback: sum user + sys (macOS sometimes omits idle).
    const user = line.match(/([\d.,]+)\s*%?\s*(?:us(?:er)?|user)\b/i);
    const sys = line.match(/([\d.,]+)\s*%?\s*(?:sy(?:s|stem)?|system)\b/i);
    const userVal = parseDecimal(user?.[1]);
    const sysVal = parseDecimal(sys?.[1]);
    if (userVal !== null && sysVal !== null) return clampPercent(userVal + sysVal);
  }
  return null;
}

function unitMultiplier(label: string | undefined): number {
  const unit = label?.toLowerCase() ?? '';
  if (unit.startsWith('t')) return 1024 ** 4;
  if (unit.startsWith('g')) return 1024 ** 3;
  if (unit.startsWith('m')) return 1024 ** 2;
  if (unit.startsWith('k')) return 1024;
  return 1;
}

// Parses "24G" / "3196K" / "5120M" / "10" -> bytes. Suffix is a single letter (k/m/g/t).
function parseSizeToken(token: string): number | null {
  const match = token.match(/^([\d.,]+)\s*([kmgtpe]?)$/i);
  if (!match) return null;
  const value = parseDecimal(match[1]);
  if (value === null) return null;
  const suffix = match[2].toLowerCase();
  const power = suffix ? 'kmgtpe'.indexOf(suffix) + 1 : 0;
  return Math.round(value * (1024 ** power));
}

function parseUsage(lines: string[], kind: 'Mem' | 'Swap'): ResourceUsage | null {
  for (const line of lines) {
    // macOS PhysMem (only valid for Mem).
    if (kind === 'Mem' && /^\s*PhysMem\s*:/i.test(line)) {
      const result = parseMacOSPhysMem(line);
      if (result) return result;
      continue;
    }
    if (!new RegExp(`(?:^|\\s)(?:KiB|MiB|GiB)?\\s*${kind}\\s*:`, 'i').test(line)) continue;

    // Try the explicit total/used/free labelled form first (Linux + FreeBSD Swap).
    const labelled = parseLabelledUsage(line);
    if (labelled) return labelled;

    // Then the FreeBSD category form: "Mem: 24G Active, 22G Inact, 18G Laundry, 51G Wired, 10G Free".
    if (kind === 'Mem') {
      const categorised = parseFreeBSDMemUsage(line);
      if (categorised) return categorised;
    }
  }
  return null;
}

// Handles "X total, Y used, Z free" style lines (Linux, FreeBSD Swap).
function parseLabelledUsage(line: string): ResourceUsage | null {
  const unit = line.match(/(?:^|\s)(KiB|MiB|GiB)\s*(?:Mem|Swap)\s*:/i)?.[1];
  const defaultMultiplier = unit ? unitMultiplier(unit) : 1;

  const amount = (label: string): number | null => {
    const match = line.match(new RegExp(`([\\d.,]+)\\s*([kmgtpe]i?b?|[kmgtpe]?)\\s+${label}\\b`, 'i'));
    if (!match) return null;
    const value = parseDecimal(match[1]);
    if (value === null) return null;
    const suffix = match[2];
    const mult = suffix ? unitMultiplier(suffix) : defaultMultiplier;
    return value * mult;
  };

  const total = amount('total');
  const used = amount('used');
  const free = amount('free');
  const resolvedTotal = total ?? (used !== null && free !== null ? used + free : null);
  if (resolvedTotal === null || used === null || resolvedTotal < 0) return null;
  const totalBytes = Math.round(resolvedTotal);
  const usedBytes = Math.min(totalBytes, Math.round(used));
  return {
    usedBytes,
    totalBytes,
    percent: totalBytes > 0 ? clampPercent((usedBytes / totalBytes) * 100) : 0,
  };
}

// Handles FreeBSD Mem: "24G Active, 22G Inact, 18G Laundry, 51G Wired, 10G Free".
// total = sum of all listed categories; used = total - free.
function parseFreeBSDMemUsage(line: string): ResourceUsage | null {
  const memLabels = new Set(['active', 'inact', 'laundry', 'wired', 'buf', 'cache', 'free', 'laund']);
  // Match "<number><optional unit> <Label>" pairs (e.g. "24G Active", "10G Free"). Case-insensitive so uppercase
  // unit letters (G/M/K) match the [kmgtpe] class.
  const tokenRegex = /([\d.,]+)\s*([kmgtpe]?)\s+([A-Za-z][\w-]*)/gi;
  const entries: { size: number; label: string }[] = [];
  let match: RegExpExecArray | null;
  while ((match = tokenRegex.exec(line)) !== null) {
    const size = parseSizeToken(match[1] + (match[2] || ''));
    if (size === null) continue;
    const label = match[3].toLowerCase();
    if (!memLabels.has(label)) continue;
    entries.push({ size, label });
  }
  if (entries.length === 0) return null;

  const freeEntry = entries.find((e) => e.label === 'free');
  const totalBytes = Math.round(entries.reduce((sum, e) => sum + e.size, 0));
  if (totalBytes <= 0) return null;
  const usedBytes = Math.max(0, totalBytes - (freeEntry?.size ?? 0));
  return {
    usedBytes,
    totalBytes,
    percent: clampPercent((usedBytes / totalBytes) * 100),
  };
}

// macOS: "PhysMem: 100G used (24G wired), 10G unused." or "PhysMem: 110G used, 10G unused."
function parseMacOSPhysMem(line: string): ResourceUsage | null {
  const usedMatch = line.match(/([\d.,]+)\s*([kmgtpe]?)\s*used/i);
  const unusedMatch = line.match(/([\d.,]+)\s*([kmgtpe]?)\s*(?:unused|free)/i);
  if (!usedMatch) return null;
  const used = parseSizeToken(usedMatch[1] + (usedMatch[2] || ''));
  if (used === null) return null;
  let total: number;
  if (unusedMatch) {
    const unused = parseSizeToken(unusedMatch[1] + (unusedMatch[2] || ''));
    total = used + (unused ?? 0);
  } else {
    total = used;
  }
  return {
    usedBytes: used,
    totalBytes: total,
    percent: total > 0 ? clampPercent((used / total) * 100) : 0,
  };
}

function headerIndex(headers: string[], ...names: string[]): number {
  const upperNames = names.map((n) => n.toUpperCase());
  return headers.findIndex((header) => upperNames.includes(header.toUpperCase()));
}

function parseMemoryValue(value: string | undefined): number | null {
  if (!value || !/^[\d.]+[kmgtpe]?b?$/i.test(value)) return null;
  const match = value.match(/^([\d.]+)([kmgtpe]?)/i);
  const amount = finiteNumber(match?.[1]);
  if (amount === null) return null;
  const suffix = match?.[2].toLowerCase() ?? '';
  const power = suffix ? 'kmgtpe'.indexOf(suffix) + 1 : 1;
  return Math.round(amount * (1024 ** power));
}

// Parses a non-negative integer expressed in base 10. Returns null for empty
// strings, negative numbers, floats, hex/octal literals, or anything that does
// not fit in a safe integer.
function parseNonNegativeInteger(value: string | undefined | null): number | null {
  if (!value) return null;
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

// Extracts the network interface samples from the network section, which
// starts at the `__CF_WEBSSH_NETWORK__` marker and runs to the end of the
// snapshot (or to a second marker if one exists). The payload is whitespace-
// separated (tabs inserted by `printf` on Linux, OFS in awk on macOS), so any
// run of whitespace is a valid separator. Every non-empty line is parsed in
// order; malformed rows are skipped without aborting the section, and the
// result is capped at MAX_NETWORK_INTERFACES. Returns [] when the marker is
// missing, the section is empty, or every row is malformed — the caller maps
// an empty list to null so the "no sample" semantics stay unchanged.
export function parseNetwork(raw: string): NetworkSample[] {
  const cleaned = raw.replace(ANSI_ESCAPE_RE, '').replace(/\r/g, '');
  const start = cleaned.indexOf(PROCESS_NETWORK_MARKER);
  if (start < 0) return [];
  const afterStart = start + PROCESS_NETWORK_MARKER.length;
  const end = cleaned.indexOf(PROCESS_NETWORK_MARKER, afterStart);
  const section = (end < 0 ? cleaned.slice(afterStart) : cleaned.slice(afterStart, end)).trim();
  if (!section) return [];
  const samples: NetworkSample[] = [];
  for (const line of section.split('\n')) {
    const entry = line.trim();
    if (!entry) continue;
    const parts = entry.split(/\s+/);
    if (parts.length < 3) continue;
    const iface = parts[0];
    if (!iface) continue;
    const rxBytes = parseNonNegativeInteger(parts[1]);
    const txBytes = parseNonNegativeInteger(parts[2]);
    if (rxBytes === null || txBytes === null) continue;
    samples.push({ iface, rxBytes, txBytes });
    if (samples.length >= MAX_NETWORK_INTERFACES) break;
  }
  return samples;
}

function parseProcesses(lines: string[]): ProcessEntry[] {
  // Header line starts with PID. Both Linux ("%CPU") and FreeBSD ("WCPU") headers match this.
  const headerLineIndex = lines.findIndex((line) => /^\s*PID\s+/i.test(line));
  if (headerLineIndex < 0) return [];
  const headers = lines[headerLineIndex].trim().split(/\s+/);
  const pidIndex = headerIndex(headers, 'PID');
  const userIndex = headerIndex(headers, 'USER', 'USERNAME');
  // Linux: %CPU, macOS: %CPU, FreeBSD: WCPU
  const cpuIndex = headerIndex(headers, '%CPU', 'CPU%', 'WCPU');
  const residentMemoryIndex = headerIndex(headers, 'RES', 'RSS');
  const memoryIndex = residentMemoryIndex >= 0 ? residentMemoryIndex : headerIndex(headers, 'VSZ', 'VIRT', 'SIZE');
  const memoryPercentIndex = headerIndex(headers, '%MEM', 'MEM%', '%VSZ');
  const stateIndex = headerIndex(headers, 'S', 'STAT', 'STATE');
  const timeIndex = headerIndex(headers, 'TIME+', 'TIME');
  const commandIndex = headerIndex(headers, 'COMMAND', 'CMD', 'COMMAND+');
  if (pidIndex < 0 || commandIndex < 0) return [];

  // Determine the last column index we care about (excluding COMMAND itself). When COMMAND is the
  // final column (Linux/FreeBSD), the rest of the line is the full command line. When COMMAND is
  // in the middle (macOS: "PID COMMAND %CPU TIME"), only the single token is the command name.
  const knownIndices = [pidIndex, userIndex, memoryIndex, memoryPercentIndex, cpuIndex, stateIndex, timeIndex]
    .filter((i) => i >= 0);
  const maxKnownIndex = knownIndices.length > 0 ? Math.max(...knownIndices) : -1;
  const commandIsLast = commandIndex > maxKnownIndex;

  const processes: ProcessEntry[] = [];
  for (const line of lines.slice(headerLineIndex + 1)) {
    if (!line.trim()) continue;
    const fields = line.trim().split(/\s+/);
    const pid = Number(fields[pidIndex]);
    if (!Number.isSafeInteger(pid) || pid <= 0 || fields.length <= commandIndex) continue;
    processes.push({
      pid,
      user: userIndex >= 0 ? fields[userIndex] ?? '' : '',
      memoryBytes: memoryIndex >= 0 ? parseMemoryValue(fields[memoryIndex]) : null,
      memoryPercent: memoryPercentIndex >= 0 ? finiteNumber(fields[memoryPercentIndex]) : null,
      cpuPercent: cpuIndex >= 0 ? finiteNumber(fields[cpuIndex]) : null,
      state: stateIndex >= 0 ? fields[stateIndex] ?? '' : '',
      time: timeIndex >= 0 ? fields[timeIndex] ?? '' : '',
      command: commandIsLast ? fields.slice(commandIndex).join(' ') : (fields[commandIndex] ?? ''),
    });
    if (processes.length >= MAX_PROCESSES) break;
  }
  return processes;
}

export function parseTopSnapshot(raw: string, timestamp = Date.now()): ProcessSnapshot | null {
  const cleaned = raw.replace(ANSI_ESCAPE_RE, '').replace(/\r/g, '');
  const lines = cleaned.split('\n');
  const processes = parseProcesses(lines);
  // An empty network section is indistinguishable from a missing one: map it to
  // null so the "no sample" semantics (frontend keeps the block, snapshot-empty
  // detection) stay unchanged for the single-tick case.
  const parsedNetwork = parseNetwork(cleaned);
  const metrics: ProcessMetrics = {
    cpuPercent: parseCPU(lines),
    loadAverage: parseLoad(lines),
    memory: parseUsage(lines, 'Mem'),
    swap: parseUsage(lines, 'Swap'),
    network: parsedNetwork.length > 0 ? parsedNetwork : null,
  };
  if (processes.length === 0 && metrics.cpuPercent === null && metrics.loadAverage === null && metrics.memory === null && metrics.swap === null && metrics.network === null) return null;
  return { metrics, processes, timestamp };
}
