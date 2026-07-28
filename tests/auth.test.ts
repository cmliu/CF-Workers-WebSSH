import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildKeyboardInteractiveAuthRequest,
  buildKeyboardInteractiveResponse,
  isSupportedPasswordPrompt,
  parseKeyboardInteractiveChallenge,
  passwordResponsesForChallenge,
} from '../src/ssh/auth-password.ts';

const IDENTITY = { username: 'alice', host: 'example.com' };

interface ChallengeFields {
  name?: string;
  instruction?: string;
  language?: string;
}

function encodeString(value: string): Uint8Array {
  const bytes = new TextEncoder().encode(value);
  const result = new Uint8Array(4 + bytes.length);
  new DataView(result.buffer).setUint32(0, bytes.length, false);
  result.set(bytes, 4);
  return result;
}

function challenge(prompts: Array<{ text: string; echo: boolean }>, fields: ChallengeFields = {}): Uint8Array {
  const count = new Uint8Array(4);
  new DataView(count.buffer).setUint32(0, prompts.length, false);
  const parts = [
    new Uint8Array([60]),
    encodeString(fields.name ?? ''),
    encodeString(fields.instruction ?? ''),
    encodeString(fields.language ?? ''),
    count,
    ...prompts.flatMap((prompt) => [encodeString(prompt.text), new Uint8Array([prompt.echo ? 1 : 0])]),
  ];
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}

function readString(data: Uint8Array, offset: number): { value: string; next: number } {
  const length = readUint32(data, offset);
  const start = offset + 4;
  return { value: new TextDecoder().decode(data.subarray(start, start + length)), next: start + length };
}

function readUint32(data: Uint8Array, offset: number): number {
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(offset, false);
}

test('builds an RFC 4256 keyboard-interactive request without the password', () => {
  const request = buildKeyboardInteractiveAuthRequest('coss');
  assert.equal(request[0], 50);
  let field = readString(request, 1);
  assert.equal(field.value, 'coss');
  field = readString(request, field.next);
  assert.equal(field.value, 'ssh-connection');
  field = readString(request, field.next);
  assert.equal(field.value, 'keyboard-interactive');
  field = readString(request, field.next);
  assert.equal(field.value, '');
  field = readString(request, field.next);
  assert.equal(field.value, '');
  assert.equal(field.next, request.length);
  assert.equal(new TextDecoder().decode(request).includes('secret'), false);
});

test('answers a password prompt', () => {
  const parsed = parseKeyboardInteractiveChallenge(challenge([{
    text: 'Password for alice@example.com:',
    echo: false,
  }]));
  const response = buildKeyboardInteractiveResponse(passwordResponsesForChallenge(parsed, 'test-secret', IDENTITY));
  assert.equal(response[0], 61);
  assert.equal(readUint32(response, 1), 1);
  const answer = readString(response, 5);
  assert.equal(answer.value, 'test-secret');
  assert.equal(answer.next, response.length);
});

test('acknowledges zero-prompt keyboard-interactive notices', () => {
  const parsed = parseKeyboardInteractiveChallenge(challenge([], { instruction: 'Authentication successful' }));
  assert.deepEqual(parsed.prompts, []);
  const response = buildKeyboardInteractiveResponse(passwordResponsesForChallenge(parsed, 'test-secret', IDENTITY));
  assert.equal(response[0], 61);
  assert.equal(readUint32(response, 1), 0);
  assert.equal(response.length, 5);
});

test('rejects multiple or non-password prompts', () => {
  const multiple = parseKeyboardInteractiveChallenge(challenge([
    { text: 'Password:', echo: false },
    { text: 'Verification code:', echo: false },
  ]));
  assert.throws(() => passwordResponsesForChallenge(multiple, 'test-secret', IDENTITY), /2 prompts/);
  const otp = parseKeyboardInteractiveChallenge(challenge([{ text: 'Verification code:', echo: false }]));
  assert.throws(() => passwordResponsesForChallenge(otp, 'test-secret', IDENTITY), /not a supported password prompt/);
});

test('only auto-answers hidden password prompts', () => {
  const supported = (text: string, echo = false, fields: ChallengeFields = {}) => isSupportedPasswordPrompt(
    parseKeyboardInteractiveChallenge(challenge([{ text, echo }], fields)),
    IDENTITY,
  );
  assert.equal(supported('Password:'), true);
  assert.equal(supported('密码：'), true);
  assert.equal(supported('Password for alice@example.com:'), true);
  assert.equal(supported('password for alice@EXAMPLE.COM:'), true);
  assert.equal(supported('Password for mallory@example.com:'), false);
  assert.equal(supported('Password:', true), false);
  assert.equal(supported('Verification code:'), false);
  assert.equal(supported('Do not enter your password; enter OTP:'), false);
  assert.equal(supported('Enter new password:'), false);
  assert.equal(supported('Password + verification code:'), false);
  assert.equal(supported('Passphrase for key:'), false);
  assert.equal(supported('Password:', false, { instruction: 'Enter your one-time code' }), false);
  assert.equal(supported('Password:', false, { name: 'Second factor' }), false);
});

test('strictly validates keyboard-interactive challenge framing', () => {
  assert.throws(() => parseKeyboardInteractiveChallenge(challenge([{ text: '', echo: false }])), /Malformed/);

  const badBoolean = challenge([{ text: 'Password:', echo: false }]);
  badBoolean[badBoolean.length - 1] = 2;
  assert.throws(() => parseKeyboardInteractiveChallenge(badBoolean), /Malformed/);

  const invalidUtf8 = challenge([], { name: 'x' });
  invalidUtf8[5] = 0xff;
  assert.throws(() => parseKeyboardInteractiveChallenge(invalidUtf8), /text/);

  const valid = challenge([{ text: 'Password:', echo: false }]);
  const trailing = new Uint8Array(valid.length + 1);
  trailing.set(valid);
  assert.throws(() => parseKeyboardInteractiveChallenge(trailing), /trailing data/);
  assert.throws(() => parseKeyboardInteractiveChallenge(valid.subarray(0, valid.length - 1)), /Malformed/);

  const tooMany = Array.from({ length: 17 }, () => ({ text: 'Password:', echo: false }));
  assert.throws(() => parseKeyboardInteractiveChallenge(challenge(tooMany)), /too many prompts/);
});
