import {
  SFTP_ATTR_FLAGS,
  SFTP_PACKET_TYPES,
  SFTP_STATUS,
  SFTP_VERSION,
  type SFTPAttrs,
  type SFTPAttrsInput,
  type SFTPClientOptions,
  type SFTPDirEntry,
  type SFTPExtendedAttribute,
  type SFTPHandle,
  type SFTPOpenFlags,
  type SFTPSize,
  type SFTPUint64Input,
  type SFTPVersionInfo,
} from './sftp-types.ts';

export * from './sftp-types.ts';

const UINT32_MAX = 0xffffffff;
const UINT64_MAX = (1n << 64n) - 1n;
const DEFAULT_MAX_PACKET_LENGTH = 4 * 1024 * 1024;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_NAME_ENTRIES = 16_384;
const DEFAULT_MAX_EXTENDED_ATTRIBUTES = 1_024;
const DEFAULT_MAX_VERSION_EXTENSIONS = 256;
const KNOWN_ATTR_FLAGS = (
  SFTP_ATTR_FLAGS.SIZE |
  SFTP_ATTR_FLAGS.UID_GID |
  SFTP_ATTR_FLAGS.PERMISSIONS |
  SFTP_ATTR_FLAGS.ACCESS_MODIFY_TIME |
  SFTP_ATTR_FLAGS.EXTENDED
) >>> 0;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export class SFTPProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SFTPProtocolError';
  }
}

export class SFTPStatusError extends Error {
  readonly code: number;
  readonly requestId: number;
  readonly description: string;
  readonly language: string;

  constructor(code: number, requestId: number, description: string, language: string) {
    super(`SFTP request ${requestId} failed with status ${code}${description ? `: ${description}` : ''}`);
    this.name = 'SFTPStatusError';
    this.code = code;
    this.requestId = requestId;
    this.description = description;
    this.language = language;
  }
}

export class SFTPTimeoutError extends Error {
  readonly requestId: number;

  constructor(requestId: number) {
    super(`SFTP request ${requestId} timed out`);
    this.name = 'SFTPTimeoutError';
    this.requestId = requestId;
  }
}

class Reader {
  private offset = 0;
  private readonly data: Uint8Array;

  constructor(data: Uint8Array) {
    this.data = data;
  }

  get remaining(): number {
    return this.data.length - this.offset;
  }

  readByte(label: string): number {
    this.require(1, label);
    return this.data[this.offset++];
  }

  readUint32(label: string): number {
    this.require(4, label);
    const value = new DataView(this.data.buffer, this.data.byteOffset + this.offset, 4).getUint32(0, false);
    this.offset += 4;
    return value;
  }

  readUint64(label: string): bigint {
    const high = this.readUint32(label);
    const low = this.readUint32(label);
    return (BigInt(high) << 32n) | BigInt(low);
  }

  readBytes(length: number, label: string): Uint8Array {
    this.require(length, label);
    const value = this.data.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  readStringBytes(label: string): Uint8Array {
    return this.readBytes(this.readUint32(`${label} length`), label);
  }

  readText(label: string): string {
    const bytes = this.readStringBytes(label);
    try {
      return decoder.decode(bytes);
    } catch {
      throw new SFTPProtocolError(`Malformed SFTP ${label}: invalid UTF-8`);
    }
  }

  assertEnd(label = 'packet'): void {
    if (this.remaining !== 0) {
      throw new SFTPProtocolError(`Malformed SFTP ${label}: ${this.remaining} trailing byte(s)`);
    }
  }

  private require(length: number, label: string): void {
    if (!Number.isSafeInteger(length) || length < 0 || length > this.remaining) {
      throw new SFTPProtocolError(`Malformed SFTP packet: truncated or invalid ${label}`);
    }
  }
}

interface PendingRequest<T> {
  readonly id: number;
  readonly timer: ReturnType<typeof setTimeout>;
  readonly parse: (type: number, reader: Reader) => T;
  readonly resolve: (value: T | PromiseLike<T>) => void;
  readonly reject: (reason: unknown) => void;
}

type SendData = (packet: Uint8Array) => void | Promise<void>;
type ClientState = 'new' | 'initializing' | 'ready' | 'disposed';

function uint32(value: number, label: string): number {
  if (!Number.isInteger(value) || value < 0 || value > UINT32_MAX) {
    throw new RangeError(`${label} must be an unsigned 32-bit integer`);
  }
  return value;
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new RangeError(`${label} must be a positive integer`);
  return value;
}

function toUint64(value: SFTPUint64Input, label: string): bigint {
  let result: bigint;
  if (typeof value === 'bigint') {
    result = value;
  } else if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new RangeError(`${label} number must be a safe integer`);
    result = BigInt(value);
  } else {
    if (!/^[0-9]+$/.test(value)) throw new RangeError(`${label} must be an unsigned decimal integer`);
    result = BigInt(value);
  }
  if (result < 0n || result > UINT64_MAX) throw new RangeError(`${label} must fit in an unsigned 64-bit integer`);
  return result;
}

function displayUint64(value: bigint): SFTPSize {
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString(10);
}

function encodeUint32(value: number, label: string): Uint8Array {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, uint32(value, label), false);
  return result;
}

function encodeUint64(value: SFTPUint64Input, label: string): Uint8Array {
  const integer = toUint64(value, label);
  const result = new Uint8Array(8);
  const view = new DataView(result.buffer);
  view.setUint32(0, Number(integer >> 32n), false);
  view.setUint32(4, Number(integer & 0xffffffffn), false);
  return result;
}

function encodeString(value: string | Uint8Array, label: string): Uint8Array {
  const bytes = typeof value === 'string' ? encoder.encode(value) : value;
  if (bytes.length > UINT32_MAX) throw new RangeError(`${label} is too long`);
  const result = new Uint8Array(4 + bytes.length);
  new DataView(result.buffer).setUint32(0, bytes.length, false);
  result.set(bytes, 4);
  return result;
}

function join(parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) {
    length += part.length;
    if (!Number.isSafeInteger(length)) throw new RangeError('SFTP packet is too large');
  }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function encodeAttrs(attrs: SFTPAttrsInput | undefined, maxExtended: number): Uint8Array {
  if (!attrs) return encodeUint32(0, 'attribute flags');
  let flags = 0;
  const values: Uint8Array[] = [];

  if (attrs.size !== undefined) {
    flags |= SFTP_ATTR_FLAGS.SIZE;
    values.push(encodeUint64(attrs.size, 'file size'));
  }
  if ((attrs.uid === undefined) !== (attrs.gid === undefined)) {
    throw new TypeError('SFTP attributes must provide uid and gid together');
  }
  if (attrs.uid !== undefined && attrs.gid !== undefined) {
    flags |= SFTP_ATTR_FLAGS.UID_GID;
    values.push(encodeUint32(attrs.uid, 'uid'), encodeUint32(attrs.gid, 'gid'));
  }
  if (attrs.permissions !== undefined) {
    flags |= SFTP_ATTR_FLAGS.PERMISSIONS;
    values.push(encodeUint32(attrs.permissions, 'permissions'));
  }
  if ((attrs.atime === undefined) !== (attrs.mtime === undefined)) {
    throw new TypeError('SFTP attributes must provide atime and mtime together');
  }
  if (attrs.atime !== undefined && attrs.mtime !== undefined) {
    flags |= SFTP_ATTR_FLAGS.ACCESS_MODIFY_TIME;
    values.push(encodeUint32(attrs.atime, 'access time'), encodeUint32(attrs.mtime, 'modification time'));
  }
  if (attrs.extended !== undefined) {
    if (attrs.extended.length > maxExtended) throw new RangeError('Too many SFTP extended attributes');
    flags = (flags | SFTP_ATTR_FLAGS.EXTENDED) >>> 0;
    values.push(encodeUint32(attrs.extended.length, 'extended attribute count'));
    for (const extension of attrs.extended) {
      values.push(encodeString(extension.type, 'extended attribute type'));
      values.push(encodeString(extension.data, 'extended attribute data'));
    }
  }
  return join([encodeUint32(flags >>> 0, 'attribute flags'), ...values]);
}

function parseAttrs(reader: Reader, maxExtended: number): SFTPAttrs {
  const flags = reader.readUint32('attribute flags');
  if ((flags & ~KNOWN_ATTR_FLAGS) !== 0) {
    throw new SFTPProtocolError(`Malformed SFTP attributes: unsupported flags 0x${flags.toString(16)}`);
  }

  let size: SFTPSize | undefined;
  let uid: number | undefined;
  let gid: number | undefined;
  let permissions: number | undefined;
  let atime: number | undefined;
  let mtime: number | undefined;
  let extended: SFTPExtendedAttribute[] | undefined;

  if (flags & SFTP_ATTR_FLAGS.SIZE) size = displayUint64(reader.readUint64('file size'));
  if (flags & SFTP_ATTR_FLAGS.UID_GID) {
    uid = reader.readUint32('uid');
    gid = reader.readUint32('gid');
  }
  if (flags & SFTP_ATTR_FLAGS.PERMISSIONS) permissions = reader.readUint32('permissions');
  if (flags & SFTP_ATTR_FLAGS.ACCESS_MODIFY_TIME) {
    atime = reader.readUint32('access time');
    mtime = reader.readUint32('modification time');
  }
  if (flags & SFTP_ATTR_FLAGS.EXTENDED) {
    const count = reader.readUint32('extended attribute count');
    if (count > maxExtended || count > Math.floor(reader.remaining / 8)) {
      throw new SFTPProtocolError('Malformed SFTP attributes: invalid extended attribute count');
    }
    extended = [];
    for (let index = 0; index < count; index++) {
      extended.push({
        type: reader.readText('extended attribute type'),
        data: reader.readStringBytes('extended attribute data').slice(),
      });
    }
  }
  return { flags, size, uid, gid, permissions, atime, mtime, extended };
}

function parseStatus(reader: Reader, requestId: number): { code: number; description: string; language: string } {
  const code = reader.readUint32('status code');
  const description = reader.readText('status description');
  const language = reader.readText('status language');
  reader.assertEnd('STATUS packet');
  return { code, description, language };
}

export class SFTPClient {
  private readonly sendData: SendData;
  private readonly maxPacketLength: number;
  private readonly maxBufferedBytes: number;
  private readonly maxNameEntries: number;
  private readonly maxExtendedAttributes: number;
  private readonly maxVersionExtensions: number;
  private readonly requestTimeoutMs: number;
  private readonly pending = new Map<number, PendingRequest<unknown>>();
  private state: ClientState = 'new';
  private nextRequestId: number;
  private header = new Uint8Array(4);
  private headerLength = 0;
  private packetBuffer: Uint8Array | null = null;
  private packetOffset = 0;
  private initializationPromise: Promise<SFTPVersionInfo> | null = null;
  private initializationResolve: ((info: SFTPVersionInfo) => void) | null = null;
  private initializationReject: ((reason: unknown) => void) | null = null;
  private initializationTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(sendData: SendData, options: SFTPClientOptions = {}) {
    this.sendData = sendData;
    this.maxPacketLength = positiveInteger(options.maxPacketLength ?? DEFAULT_MAX_PACKET_LENGTH, 'maxPacketLength');
    this.maxBufferedBytes = positiveInteger(
      options.maxBufferedBytes ?? this.maxPacketLength + 4,
      'maxBufferedBytes',
    );
    if (this.maxBufferedBytes < 5) throw new RangeError('maxBufferedBytes must hold an SFTP frame');
    this.maxNameEntries = positiveInteger(options.maxNameEntries ?? DEFAULT_MAX_NAME_ENTRIES, 'maxNameEntries');
    this.maxExtendedAttributes = positiveInteger(
      options.maxExtendedAttributes ?? DEFAULT_MAX_EXTENDED_ATTRIBUTES,
      'maxExtendedAttributes',
    );
    this.maxVersionExtensions = positiveInteger(
      options.maxVersionExtensions ?? DEFAULT_MAX_VERSION_EXTENSIONS,
      'maxVersionExtensions',
    );
    this.requestTimeoutMs = positiveInteger(
      options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
      'requestTimeoutMs',
    );
    this.nextRequestId = uint32(options.initialRequestId ?? 1, 'initialRequestId');
    if (this.nextRequestId === 0) throw new RangeError('initialRequestId must not be zero');
  }

  initialize(): Promise<SFTPVersionInfo> {
    if (this.state === 'disposed') throw new Error('SFTP client is disposed');
    if (this.initializationPromise) return this.initializationPromise;
    this.assertState('new');
    this.state = 'initializing';
    this.initializationPromise = new Promise<SFTPVersionInfo>((resolve, reject) => {
      this.initializationResolve = resolve;
      this.initializationReject = reject;
      this.initializationTimer = setTimeout(() => {
        const error = new SFTPTimeoutError(0);
        this.failInitialization(error);
        this.dispose(error);
      }, this.requestTimeoutMs);
    });

    try {
      const sent = this.sendFramed(join([
        new Uint8Array([SFTP_PACKET_TYPES.INIT]),
        encodeUint32(SFTP_VERSION, 'SFTP version'),
      ]));
      if (sent) sent.catch((error: unknown) => {
        if (this.state === 'initializing') {
          this.failInitialization(error);
          this.dispose(error instanceof Error ? error : new Error(String(error)));
        }
      });
    } catch (error) {
      this.failInitialization(error);
      this.dispose(error instanceof Error ? error : new Error(String(error)));
    }
    return this.initializationPromise;
  }

  feed(chunk: Uint8Array): void {
    if (this.state === 'disposed') throw new Error('SFTP client is disposed');
    if (!(chunk instanceof Uint8Array)) throw new TypeError('SFTP data must be a Uint8Array');

    try {
      let offset = 0;
      while (offset < chunk.length) {
        if (this.packetBuffer) {
          const count = Math.min(this.packetBuffer.length - this.packetOffset, chunk.length - offset);
          this.packetBuffer.set(chunk.subarray(offset, offset + count), this.packetOffset);
          this.packetOffset += count;
          offset += count;
          if (this.packetOffset === this.packetBuffer.length) {
            const packet = this.packetBuffer;
            this.packetBuffer = null;
            this.packetOffset = 0;
            this.dispatch(packet);
          }
          continue;
        }

        if (this.headerLength === 0 && chunk.length - offset >= 4) {
          const length = new DataView(chunk.buffer, chunk.byteOffset + offset, 4).getUint32(0, false);
          this.validatePacketLength(length);
          offset += 4;
          if (chunk.length - offset >= length) {
            this.dispatch(chunk.subarray(offset, offset + length));
            offset += length;
          } else {
            this.packetBuffer = new Uint8Array(length);
            this.packetOffset = chunk.length - offset;
            this.packetBuffer.set(chunk.subarray(offset), 0);
            offset = chunk.length;
          }
          continue;
        }

        const headerBytes = Math.min(4 - this.headerLength, chunk.length - offset);
        this.header.set(chunk.subarray(offset, offset + headerBytes), this.headerLength);
        this.headerLength += headerBytes;
        offset += headerBytes;
        if (this.headerLength === 4) {
          const length = new DataView(this.header.buffer).getUint32(0, false);
          this.headerLength = 0;
          this.validatePacketLength(length);
          this.packetBuffer = new Uint8Array(length);
          this.packetOffset = 0;
        }
      }
    } catch (error) {
      const protocolError = error instanceof Error ? error : new SFTPProtocolError(String(error));
      this.dispose(protocolError);
      throw protocolError;
    }
  }

  dispose(reason: Error = new Error('SFTP client was disposed')): void {
    if (this.state === 'disposed') return;
    this.state = 'disposed';
    this.headerLength = 0;
    this.packetBuffer = null;
    this.packetOffset = 0;
    this.failInitialization(reason);
    for (const request of this.pending.values()) {
      clearTimeout(request.timer);
      request.reject(reason);
    }
    this.pending.clear();
  }

  realpath(path: string): Promise<string> {
    return this.request(SFTP_PACKET_TYPES.REALPATH, [encodeString(path, 'path')], (type, reader, id) => {
      this.throwStatusOrUnexpected(type, reader, id, SFTP_PACKET_TYPES.NAME);
      const entries = this.parseName(reader);
      if (entries.length !== 1) throw new SFTPProtocolError('Malformed SFTP REALPATH response: expected one name');
      return entries[0].filename;
    });
  }

  openDir(path: string): Promise<SFTPHandle> {
    return this.request(SFTP_PACKET_TYPES.OPENDIR, [encodeString(path, 'path')], (type, reader, id) => {
      this.throwStatusOrUnexpected(type, reader, id, SFTP_PACKET_TYPES.HANDLE);
      const handle = reader.readStringBytes('handle');
      if (handle.length === 0) throw new SFTPProtocolError('Malformed SFTP HANDLE response: empty handle');
      return handle.slice();
    });
  }

  readDir(handle: SFTPHandle): Promise<SFTPDirEntry[] | null> {
    return this.request(SFTP_PACKET_TYPES.READDIR, [encodeString(handle, 'handle')], (type, reader, id) => {
      if (type === SFTP_PACKET_TYPES.STATUS) return this.parseEofStatus(reader, id);
      if (type !== SFTP_PACKET_TYPES.NAME) this.unexpected(type, SFTP_PACKET_TYPES.NAME);
      return this.parseName(reader);
    });
  }

  closeHandle(handle: SFTPHandle): Promise<void> {
    return this.statusRequest(SFTP_PACKET_TYPES.CLOSE, [encodeString(handle, 'handle')]);
  }

  stat(path: string): Promise<SFTPAttrs> {
    return this.request(SFTP_PACKET_TYPES.STAT, [encodeString(path, 'path')], (type, reader, id) => {
      this.throwStatusOrUnexpected(type, reader, id, SFTP_PACKET_TYPES.ATTRS);
      return parseAttrs(reader, this.maxExtendedAttributes);
    });
  }

  openFile(path: string, flags: SFTPOpenFlags, attrs?: SFTPAttrsInput): Promise<SFTPHandle> {
    return this.request(SFTP_PACKET_TYPES.OPEN, [
      encodeString(path, 'path'),
      encodeUint32(flags, 'open flags'),
      encodeAttrs(attrs, this.maxExtendedAttributes),
    ], (type, reader, id) => {
      this.throwStatusOrUnexpected(type, reader, id, SFTP_PACKET_TYPES.HANDLE);
      const handle = reader.readStringBytes('handle');
      if (handle.length === 0) throw new SFTPProtocolError('Malformed SFTP HANDLE response: empty handle');
      return handle.slice();
    });
  }

  readFile(handle: SFTPHandle, offset: SFTPUint64Input, length: number): Promise<Uint8Array | null> {
    return this.request(SFTP_PACKET_TYPES.READ, [
      encodeString(handle, 'handle'),
      encodeUint64(offset, 'file offset'),
      encodeUint32(length, 'read length'),
    ], (type, reader, id) => {
      if (type === SFTP_PACKET_TYPES.STATUS) return this.parseEofStatus(reader, id);
      if (type !== SFTP_PACKET_TYPES.DATA) this.unexpected(type, SFTP_PACKET_TYPES.DATA);
      const data = reader.readStringBytes('file data');
      if (data.length > length) throw new SFTPProtocolError('Malformed SFTP DATA response: exceeds requested length');
      return data.slice();
    });
  }

  writeFile(handle: SFTPHandle, offset: SFTPUint64Input, data: Uint8Array): Promise<void> {
    return this.statusRequest(SFTP_PACKET_TYPES.WRITE, [
      encodeString(handle, 'handle'),
      encodeUint64(offset, 'file offset'),
      encodeString(data, 'file data'),
    ]);
  }

  removeFile(path: string): Promise<void> {
    return this.statusRequest(SFTP_PACKET_TYPES.REMOVE, [encodeString(path, 'path')]);
  }

  mkdir(path: string, attrs?: SFTPAttrsInput): Promise<void> {
    return this.statusRequest(SFTP_PACKET_TYPES.MKDIR, [
      encodeString(path, 'path'),
      encodeAttrs(attrs, this.maxExtendedAttributes),
    ]);
  }

  rmdir(path: string): Promise<void> {
    return this.statusRequest(SFTP_PACKET_TYPES.RMDIR, [encodeString(path, 'path')]);
  }

  rename(oldPath: string, newPath: string): Promise<void> {
    return this.statusRequest(SFTP_PACKET_TYPES.RENAME, [
      encodeString(oldPath, 'old path'),
      encodeString(newPath, 'new path'),
    ]);
  }

  private request<T>(
    type: number,
    fields: readonly Uint8Array[],
    parse: (type: number, reader: Reader, requestId: number) => T,
  ): Promise<T> {
    this.assertState('ready');
    const id = this.allocateRequestId();
    const body = join([new Uint8Array([type]), encodeUint32(id, 'request ID'), ...fields]);

    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new SFTPTimeoutError(id));
      }, this.requestTimeoutMs);
      const pending: PendingRequest<T> = { id, timer, parse: (responseType, reader) => parse(responseType, reader, id), resolve, reject };
      this.pending.set(id, pending as PendingRequest<unknown>);
      try {
        const sent = this.sendFramed(body);
        if (sent) sent.catch((error: unknown) => this.failPending(id, error));
      } catch (error) {
        this.failPending(id, error);
      }
    });
  }

  private statusRequest(type: number, fields: readonly Uint8Array[]): Promise<void> {
    return this.request(type, fields, (responseType, reader, id) => {
      if (responseType !== SFTP_PACKET_TYPES.STATUS) this.unexpected(responseType, SFTP_PACKET_TYPES.STATUS);
      const status = parseStatus(reader, id);
      if (status.code !== SFTP_STATUS.OK) {
        throw new SFTPStatusError(status.code, id, status.description, status.language);
      }
    });
  }

  private dispatch(packet: Uint8Array): void {
    const reader = new Reader(packet);
    const type = reader.readByte('packet type');
    if (type === SFTP_PACKET_TYPES.VERSION) {
      this.handleVersion(reader);
      return;
    }
    if (this.state !== 'ready') throw new SFTPProtocolError('Received an SFTP response before version negotiation');
    const id = reader.readUint32('request ID');
    if (id === 0) throw new SFTPProtocolError('Received an SFTP response with request ID zero');
    const request = this.pending.get(id);
    if (!request) throw new SFTPProtocolError(`Received an SFTP response with unknown request ID ${id}`);
    this.pending.delete(id);
    clearTimeout(request.timer);

    try {
      const value = request.parse(type, reader);
      reader.assertEnd();
      request.resolve(value);
    } catch (error) {
      request.reject(error);
      if (!(error instanceof SFTPStatusError)) throw error;
    }
  }

  private handleVersion(reader: Reader): void {
    if (this.state !== 'initializing') throw new SFTPProtocolError('Unexpected or duplicate SFTP VERSION packet');
    const version = reader.readUint32('server version');
    if (version !== SFTP_VERSION) throw new SFTPProtocolError(`Unsupported SFTP server version ${version}`);
    const extensions = new Map<string, string>();
    let count = 0;
    while (reader.remaining > 0) {
      if (++count > this.maxVersionExtensions || reader.remaining < 8) {
        throw new SFTPProtocolError('Malformed SFTP VERSION extensions');
      }
      const name = reader.readText('extension name');
      const data = reader.readText('extension data');
      if (extensions.has(name)) throw new SFTPProtocolError(`Duplicate SFTP extension ${name}`);
      extensions.set(name, data);
    }
    reader.assertEnd('VERSION packet');
    this.state = 'ready';
    if (this.initializationTimer) clearTimeout(this.initializationTimer);
    this.initializationTimer = null;
    const resolve = this.initializationResolve;
    this.initializationResolve = null;
    this.initializationReject = null;
    resolve?.({ version, extensions });
  }

  private parseName(reader: Reader): SFTPDirEntry[] {
    const count = reader.readUint32('name count');
    if (count > this.maxNameEntries || count > Math.floor(reader.remaining / 12)) {
      throw new SFTPProtocolError('Malformed SFTP NAME response: invalid name count');
    }
    const result: SFTPDirEntry[] = [];
    for (let index = 0; index < count; index++) {
      result.push({
        filename: reader.readText('filename'),
        longname: reader.readText('long filename'),
        attrs: parseAttrs(reader, this.maxExtendedAttributes),
      });
    }
    return result;
  }

  private parseEofStatus(reader: Reader, id: number): null {
    const status = parseStatus(reader, id);
    if (status.code === SFTP_STATUS.EOF) return null;
    throw new SFTPStatusError(status.code, id, status.description, status.language);
  }

  private throwStatusOrUnexpected(type: number, reader: Reader, id: number, expected: number): void {
    if (type === expected) return;
    if (type !== SFTP_PACKET_TYPES.STATUS) this.unexpected(type, expected);
    const status = parseStatus(reader, id);
    throw new SFTPStatusError(status.code, id, status.description, status.language);
  }

  private unexpected(actual: number, expected: number): never {
    throw new SFTPProtocolError(`Unexpected SFTP response type ${actual}; expected ${expected}`);
  }

  private sendFramed(body: Uint8Array): Promise<void> | null {
    if (body.length === 0 || body.length > this.maxPacketLength || body.length > UINT32_MAX) {
      throw new RangeError(`SFTP packet length ${body.length} exceeds the configured limit`);
    }
    const frame = new Uint8Array(4 + body.length);
    new DataView(frame.buffer).setUint32(0, body.length, false);
    frame.set(body, 4);
    const result = this.sendData(frame);
    return result && typeof (result as Promise<void>).then === 'function' ? Promise.resolve(result) : null;
  }

  private validatePacketLength(length: number): void {
    const bufferedPacketLimit = this.maxBufferedBytes - 4;
    if (length < 1 || length > this.maxPacketLength || length > bufferedPacketLimit) {
      throw new SFTPProtocolError(`Invalid or oversized SFTP packet length ${length}`);
    }
  }

  private allocateRequestId(): number {
    let candidate = this.nextRequestId;
    for (let attempts = 0; attempts <= this.pending.size; attempts++) {
      if (candidate !== 0 && !this.pending.has(candidate)) {
        this.nextRequestId = (candidate + 1) >>> 0;
        if (this.nextRequestId === 0) this.nextRequestId = 1;
        return candidate;
      }
      candidate = (candidate + 1) >>> 0;
      if (candidate === 0) candidate = 1;
    }
    throw new Error('No SFTP request IDs are available');
  }

  private failPending(id: number, reason: unknown): void {
    const request = this.pending.get(id);
    if (!request) return;
    this.pending.delete(id);
    clearTimeout(request.timer);
    request.reject(reason);
  }

  private failInitialization(reason: unknown): void {
    if (this.initializationTimer) clearTimeout(this.initializationTimer);
    this.initializationTimer = null;
    const reject = this.initializationReject;
    this.initializationResolve = null;
    this.initializationReject = null;
    reject?.(reason);
  }

  private assertState(required: ClientState): void {
    if (this.state !== required) {
      throw new Error(this.state === 'disposed' ? 'SFTP client is disposed' : `SFTP client is not ${required}`);
    }
  }
}
