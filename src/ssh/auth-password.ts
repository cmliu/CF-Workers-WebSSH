const SSH_MSG_USERAUTH_REQUEST = 50;
const SSH_MSG_USERAUTH_INFO_RESPONSE = 61;
const MAX_KEYBOARD_INTERACTIVE_PROMPTS = 16;

export interface KeyboardInteractivePrompt {
  text: string;
  echo: boolean;
}

export interface KeyboardInteractiveChallenge {
  name: string;
  instruction: string;
  language: string;
  prompts: KeyboardInteractivePrompt[];
}

export interface PasswordPromptIdentity {
  username: string;
  host: string;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(arrays.reduce((total, value) => total + value.length, 0));
  let offset = 0;
  for (const value of arrays) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

function encodeString(value: string): Uint8Array {
  const data = new TextEncoder().encode(value);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, data.length, false);
  return concat(length, data);
}

function readUint32(data: Uint8Array, offset: number): number {
  if (offset + 4 > data.length) throw new Error('Malformed SSH keyboard-interactive challenge');
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(offset, false);
}

function readString(data: Uint8Array, offset: number): { value: string; next: number } {
  const length = readUint32(data, offset);
  const start = offset + 4;
  if (length > data.length - start) throw new Error('Malformed SSH keyboard-interactive challenge');
  try {
    return {
      value: new TextDecoder('utf-8', { fatal: true }).decode(data.subarray(start, start + length)),
      next: start + length,
    };
  } catch {
    throw new Error('Malformed SSH keyboard-interactive text');
  }
}

export function buildPasswordAuthRequest(username: string, password: string): Uint8Array {
  return concat(
    new Uint8Array([SSH_MSG_USERAUTH_REQUEST]),
    encodeString(username),
    encodeString('ssh-connection'),
    encodeString('password'),
    new Uint8Array([0x00]),
    encodeString(password),
  );
}

export function buildKeyboardInteractiveAuthRequest(username: string): Uint8Array {
  return concat(
    new Uint8Array([SSH_MSG_USERAUTH_REQUEST]),
    encodeString(username),
    encodeString('ssh-connection'),
    encodeString('keyboard-interactive'),
    encodeString(''),
    encodeString(''),
  );
}

export function parseKeyboardInteractiveChallenge(payload: Uint8Array): KeyboardInteractiveChallenge {
  if (payload[0] !== 60) throw new Error('Malformed SSH keyboard-interactive message type');
  let offset = 1;
  const name = readString(payload, offset); offset = name.next;
  const instruction = readString(payload, offset); offset = instruction.next;
  const language = readString(payload, offset); offset = language.next;
  const promptCount = readUint32(payload, offset); offset += 4;
  if (promptCount > MAX_KEYBOARD_INTERACTIVE_PROMPTS) {
    throw new Error('SSH keyboard-interactive challenge has too many prompts');
  }
  const prompts: KeyboardInteractivePrompt[] = [];
  for (let index = 0; index < promptCount; index++) {
    const prompt = readString(payload, offset); offset = prompt.next;
    if (prompt.value.length === 0 || offset >= payload.length || payload[offset] > 1) {
      throw new Error('Malformed SSH keyboard-interactive prompt');
    }
    prompts.push({ text: prompt.value, echo: payload[offset] === 1 });
    offset++;
  }
  if (offset !== payload.length) throw new Error('Malformed SSH keyboard-interactive trailing data');
  return { name: name.value, instruction: instruction.value, language: language.value, prompts };
}

export function passwordResponsesForChallenge(
  challenge: KeyboardInteractiveChallenge,
  password: string,
  identity: PasswordPromptIdentity,
): string[] {
  if (challenge.prompts.length === 0) return [];
  if (challenge.prompts.length === 1 && isSupportedPasswordPrompt(challenge, identity)) {
    return [password];
  }
  throw new Error(`SSH keyboard-interactive challenge is not a supported password prompt (${challenge.prompts.length} prompts)`);
}

export function buildKeyboardInteractiveResponse(responses: string[]): Uint8Array {
  const count = new Uint8Array(4);
  new DataView(count.buffer).setUint32(0, responses.length, false);
  return concat(
    new Uint8Array([SSH_MSG_USERAUTH_INFO_RESPONSE]),
    count,
    ...responses.map(encodeString),
  );
}

export function isSupportedPasswordPrompt(
  challenge: KeyboardInteractiveChallenge,
  identity: PasswordPromptIdentity,
): boolean {
  if (challenge.prompts.length !== 1 || challenge.prompts[0].echo) return false;
  // Automatic credential reuse is deliberately limited to an unambiguous,
  // context-free password request for this exact SSH target.
  if (challenge.name.trim() || challenge.instruction.trim()) return false;
  const prompt = challenge.prompts[0].text;
  if (/[\u0000-\u001f\u007f-\u009f]/u.test(prompt)) return false;
  const normalized = prompt.trim();
  if (/^(?:password|密码|口令)\s*[:：]$/iu.test(normalized)) return true;
  const match = /^password for (.+)@(.+):$/iu.exec(normalized);
  return match !== null && match[1] === identity.username && match[2].toLowerCase() === identity.host.toLowerCase();
}
