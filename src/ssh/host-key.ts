export type HostKeyTrust = 'trusted' | 'first-seen' | 'changed';

export function classifyHostKey(
  expectedFingerprint: string | undefined,
  fingerprint: string,
): HostKeyTrust {
  if (!expectedFingerprint) return 'first-seen';
  return expectedFingerprint === fingerprint ? 'trusted' : 'changed';
}

