export type HistoryAuthMethod = 'password' | 'publickey';

export interface HistoryEntry {
  id: string;
  host: string;
  port: number;
  username: string;
  authMethod: HistoryAuthMethod;
  passwordBase64?: string;
  initialCommand: string;
  termType: string;
  encoding: string;
  fingerprint: string;
  updatedAt: number;
}

export function historyKey(host: string, port: number, username: string): string {
  return `${username}@${host.toLowerCase()}:${port}`;
}

export function historyLabel(host: string, port: number, username: string): string {
  const displayHost = host.includes(':') ? `[${host}]` : host;
  return `${username}@${displayHost}:${port}`;
}

export function normalizeHistory(entries: HistoryEntry[]): HistoryEntry[] {
  const unique = new Map<string, HistoryEntry>();
  for (const entry of [...entries].sort((left, right) => right.updatedAt - left.updatedAt)) {
    const key = historyKey(entry.host, entry.port, entry.username);
    if (!unique.has(key)) unique.set(key, entry);
  }
  return [...unique.values()];
}

export function upsertHistory(entries: HistoryEntry[], entry: HistoryEntry): HistoryEntry[] {
  const key = historyKey(entry.host, entry.port, entry.username);
  return [entry, ...entries.filter((item) => historyKey(item.host, item.port, item.username) !== key)];
}
