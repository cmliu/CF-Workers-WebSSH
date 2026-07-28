const SSH_MSG_USERAUTH_REQUEST = 50;
const SSH_MSG_USERAUTH_INFO_RESPONSE = 61;

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

export function buildKeyboardInteractiveResponse(password: string, promptCount: number): Uint8Array {
  if (promptCount !== 1) throw new Error('SSH keyboard-interactive authentication requires exactly one prompt');
  return concat(
    new Uint8Array([SSH_MSG_USERAUTH_INFO_RESPONSE]),
    new Uint8Array([0, 0, 0, 1]),
    encodeString(password),
  );
}

export function isSupportedPasswordPrompt(prompt: string, echo: boolean): boolean {
  return !echo && /(?:password|passphrase|密码|口令)/i.test(prompt);
}
