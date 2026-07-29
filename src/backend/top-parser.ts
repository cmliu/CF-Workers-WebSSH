export interface ProcessMetrics {
  cpuPercent: number | null;
  loadAverage: [number, number, number] | null;
  memory: ResourceUsage | null;
  swap: ResourceUsage | null;
}

export interface ResourceUsage {
  usedBytes: number;
  totalBytes: number;
  percent: number;
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

function finiteNumber(value: string | undefined): number | null {
  if (!value) return null;
  const parsed = Number(value.replace(',', '.').replace(/%$/, ''));
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

function clampPercent(value: number): number {
  return Math.min(100, Math.max(0, value));
}

function parseLoad(lines: string[]): [number, number, number] | null {
  for (const line of lines) {
    const match = line.match(/load average:\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/i);
    if (!match) continue;
    const values = match.slice(1, 4).map((value) => finiteNumber(value));
    if (values.every((value): value is number => value !== null)) return values as [number, number, number];
  }
  return null;
}

function parseCPU(lines: string[]): number | null {
  for (const line of lines) {
    if (!/(?:^|\s)(?:%?Cpu\(s\)|CPU):/i.test(line)) continue;
    const idle = line.match(/([\d.]+)\s*%?\s*(?:id|idle)\b/i);
    const idlePercent = finiteNumber(idle?.[1]);
    if (idlePercent !== null) return clampPercent(100 - idlePercent);
  }
  return null;
}

function unitMultiplier(label: string | undefined): number {
  const unit = label?.toLowerCase() ?? '';
  if (unit.startsWith('g')) return 1024 ** 3;
  if (unit.startsWith('m')) return 1024 ** 2;
  if (unit.startsWith('k')) return 1024;
  return 1;
}

function parseUsage(lines: string[], kind: 'Mem' | 'Swap'): ResourceUsage | null {
  for (const line of lines) {
    if (!new RegExp(`(?:^|\\s)(?:KiB|MiB|GiB)?\\s*${kind}\\s*:`, 'i').test(line)) continue;
    const unit = line.match(/(?:^|\s)(KiB|MiB|GiB)\s*(?:Mem|Swap)\s*:/i)?.[1];
    const multiplier = unitMultiplier(unit ?? 'KiB');
    const amount = (label: 'total' | 'used' | 'free'): number | null => {
      const match = line.match(new RegExp(`([\\d.]+)\\s*([kmgt]?)\\s+${label}\\b`, 'i'));
      const value = finiteNumber(match?.[1]);
      return value === null ? null : value * (match?.[2] ? unitMultiplier(match[2]) : multiplier);
    };
    const total = amount('total');
    const used = amount('used');
    const free = amount('free');
    const resolvedTotal = total ?? (used !== null && free !== null ? used + free : null);
    if (resolvedTotal === null || used === null || resolvedTotal < 0) continue;
    const totalBytes = Math.round(resolvedTotal);
    const usedBytes = Math.min(totalBytes, Math.round(used));
    return {
      usedBytes,
      totalBytes,
      percent: totalBytes > 0 ? clampPercent((usedBytes / totalBytes) * 100) : 0,
    };
  }
  return null;
}

function headerIndex(headers: string[], ...names: string[]): number {
  return headers.findIndex((header) => names.includes(header.toUpperCase()));
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

function parseProcesses(lines: string[]): ProcessEntry[] {
  const headerLineIndex = lines.findIndex((line) => /^\s*PID\s+/i.test(line) && /(?:^|\s)%?CPU(?:\s|$)/i.test(line));
  if (headerLineIndex < 0) return [];
  const headers = lines[headerLineIndex].trim().split(/\s+/);
  const pidIndex = headerIndex(headers, 'PID');
  const userIndex = headerIndex(headers, 'USER', 'USERNAME');
  const cpuIndex = headerIndex(headers, '%CPU', 'CPU%');
  const residentMemoryIndex = headerIndex(headers, 'RES', 'RSS');
  const memoryIndex = residentMemoryIndex >= 0 ? residentMemoryIndex : headerIndex(headers, 'VSZ', 'VIRT');
  const memoryPercentIndex = headerIndex(headers, '%MEM', 'MEM%', '%VSZ');
  const stateIndex = headerIndex(headers, 'S', 'STAT', 'STATE');
  const timeIndex = headerIndex(headers, 'TIME+', 'TIME');
  const commandIndex = headerIndex(headers, 'COMMAND', 'CMD', 'COMMAND+');
  if (pidIndex < 0 || commandIndex < 0) return [];

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
      command: fields.slice(commandIndex).join(' '),
    });
    if (processes.length >= MAX_PROCESSES) break;
  }
  return processes;
}

export function parseTopSnapshot(raw: string, timestamp = Date.now()): ProcessSnapshot | null {
  const lines = raw.replace(ANSI_ESCAPE_RE, '').replace(/\r/g, '').split('\n');
  const processes = parseProcesses(lines);
  const metrics: ProcessMetrics = {
    cpuPercent: parseCPU(lines),
    loadAverage: parseLoad(lines),
    memory: parseUsage(lines, 'Mem'),
    swap: parseUsage(lines, 'Swap'),
  };
  if (processes.length === 0 && Object.values(metrics).every((value) => value === null)) return null;
  return { metrics, processes, timestamp };
}
