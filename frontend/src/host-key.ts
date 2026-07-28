export const SSH_FINGERPRINT_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;

export type HostKeyTrust = 'first-seen' | 'changed';

export interface HostKeyPrompt {
  fingerprint: string;
  keyType: string;
  expectedFingerprint: string;
  trust: HostKeyTrust;
}

export function classifyHostKey(
  expectedFingerprint: string,
  fingerprint: string,
): 'matched' | HostKeyTrust {
  if (!expectedFingerprint) return 'first-seen';
  return expectedFingerprint === fingerprint ? 'matched' : 'changed';
}

