import type { EncryptedPassword } from './password-crypto';

export type HistoryAuthMethod = 'password' | 'publickey';

export interface HistoryEntry {
  id: string;
  host: string;
  port: number;
  username: string;
  authMethod: HistoryAuthMethod;
  passwordEncrypted?: EncryptedPassword;
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

export function normalizeHistory<T extends HistoryEntry>(entries: T[]): T[] {
  const unique = new Map<string, T>();
  for (const entry of [...entries].sort((left, right) => right.updatedAt - left.updatedAt)) {
    const key = historyKey(entry.host, entry.port, entry.username);
    if (!unique.has(key)) unique.set(key, entry);
  }
  return [...unique.values()];
}

export function upsertHistory<T extends HistoryEntry>(entries: T[], entry: T): T[] {
  const key = historyKey(entry.host, entry.port, entry.username);
  return [entry, ...entries.filter((item) => historyKey(item.host, item.port, item.username) !== key)];
}

export function upsertHistoryIfNewer<T extends HistoryEntry>(entries: T[], entry: T, now = Date.now()): { entries: T[]; applied: boolean } {
  const key = historyKey(entry.host, entry.port, entry.username);
  const existing = entries.find((item) => historyKey(item.host, item.port, item.username) === key);
  // Future timestamps can result from clock changes or edited browser storage;
  // they must not permanently block a newly completed connection.
  if (existing && existing.updatedAt >= entry.updatedAt && existing.updatedAt <= now) {
    return { entries: normalizeHistory(entries), applied: false };
  }
  return { entries: normalizeHistory(upsertHistory(entries, entry)), applied: true };
}
