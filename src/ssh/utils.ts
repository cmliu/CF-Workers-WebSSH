const textEncoder = new TextEncoder();

/** Workers WebCrypto currently types BufferSource as ArrayBuffer-backed only. */
export function toBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

export function concat(...arrays: Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const arr of arrays) {
    totalLength += arr.length;
  }

  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

export function readUint32(data: Uint8Array, offset: number): number {
  return (
    (data[offset] << 24) |
    (data[offset + 1] << 16) |
    (data[offset + 2] << 8) |
    data[offset + 3]
  ) >>> 0;
}

export function writeUint32(data: Uint8Array, offset: number, value: number): void {
  data[offset] = (value >>> 24) & 0xff;
  data[offset + 1] = (value >>> 16) & 0xff;
  data[offset + 2] = (value >>> 8) & 0xff;
  data[offset + 3] = value & 0xff;
}

export function encodeUint32(value: number): Uint8Array {
  const buf = new Uint8Array(4);
  writeUint32(buf, 0, value);
  return buf;
}

export function encodeString(input: string | Uint8Array): Uint8Array {
  const encoded = typeof input === 'string'
    ? textEncoder.encode(input)
    : input;
  const result = new Uint8Array(4 + encoded.length);
  writeUint32(result, 0, encoded.length);
  result.set(encoded, 4);
  return result;
}

export function toSSHMPInt(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }
  const significant = bytes.subarray(start);
  const needsLeadingZero = significant.length > 0 && (significant[0] & 0x80) !== 0;
  const valueOffset = needsLeadingZero ? 5 : 4;
  const result = new Uint8Array(valueOffset + significant.length);

  writeUint32(result, 0, significant.length + (needsLeadingZero ? 1 : 0));
  result.set(significant, valueOffset);

  return result;
}

/** RFC 8731 interprets the X25519 byte string as a network-order integer. */
export function x25519SecretToSSHMPInt(bytes: Uint8Array): Uint8Array {
  if (bytes.length !== 32) throw new Error(`X25519 shared secret must be 32 bytes, got ${bytes.length}`);
  return toSSHMPInt(bytes);
}
