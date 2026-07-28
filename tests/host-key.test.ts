import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyHostKey as classifyBrowserHostKey,
  SSH_FINGERPRINT_RE,
} from '../frontend/src/host-key.ts';
import { classifyHostKey as classifyWorkerHostKey } from '../src/ssh/host-key.ts';

const OLD = 'SHA256:McWyGS5cvgt9EvFLQxxLOTPDqAY1MmKx3iAhgXUpEiY';
const CURRENT = 'SHA256:xs49vJHNJGmereADhVfIZMt1xdeY04wYkj5FpDpLR9c';

test('validates OpenSSH SHA-256 fingerprints', () => {
  assert.equal(SSH_FINGERPRINT_RE.test(OLD), true);
  assert.equal(SSH_FINGERPRINT_RE.test(CURRENT), true);
  assert.equal(SSH_FINGERPRINT_RE.test(`${CURRENT}=`), false);
  assert.equal(SSH_FINGERPRINT_RE.test('SHA256:not-a-fingerprint'), false);
});

test('browser prompts only for first-seen or changed host keys', () => {
  assert.equal(classifyBrowserHostKey('', CURRENT), 'first-seen');
  assert.equal(classifyBrowserHostKey(CURRENT, CURRENT), 'matched');
  assert.equal(classifyBrowserHostKey(OLD, CURRENT), 'changed');
});

test('worker never treats a changed host key as already trusted', () => {
  assert.equal(classifyWorkerHostKey(undefined, CURRENT), 'first-seen');
  assert.equal(classifyWorkerHostKey(CURRENT, CURRENT), 'trusted');
  assert.equal(classifyWorkerHostKey(OLD, CURRENT), 'changed');
});

