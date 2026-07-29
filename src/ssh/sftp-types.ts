/** SFTP protocol version implemented by this client. */
export const SFTP_VERSION = 3;

export const SFTP_PACKET_TYPES = {
  INIT: 1,
  VERSION: 2,
  OPEN: 3,
  CLOSE: 4,
  READ: 5,
  WRITE: 6,
  LSTAT: 7,
  FSTAT: 8,
  SETSTAT: 9,
  FSETSTAT: 10,
  OPENDIR: 11,
  READDIR: 12,
  REMOVE: 13,
  MKDIR: 14,
  RMDIR: 15,
  REALPATH: 16,
  STAT: 17,
  RENAME: 18,
  READLINK: 19,
  SYMLINK: 20,
  STATUS: 101,
  HANDLE: 102,
  DATA: 103,
  NAME: 104,
  ATTRS: 105,
  EXTENDED: 200,
  EXTENDED_REPLY: 201,
} as const;

export const SFTP_STATUS = {
  OK: 0,
  EOF: 1,
  NO_SUCH_FILE: 2,
  PERMISSION_DENIED: 3,
  FAILURE: 4,
  BAD_MESSAGE: 5,
  NO_CONNECTION: 6,
  CONNECTION_LOST: 7,
  OP_UNSUPPORTED: 8,
} as const;

export const SFTP_OPEN_FLAGS = {
  READ: 0x00000001,
  WRITE: 0x00000002,
  APPEND: 0x00000004,
  CREATE: 0x00000008,
  TRUNCATE: 0x00000010,
  EXCLUSIVE: 0x00000020,
} as const;

export const SFTP_ATTR_FLAGS = {
  SIZE: 0x00000001,
  UID_GID: 0x00000002,
  PERMISSIONS: 0x00000004,
  ACCESS_MODIFY_TIME: 0x00000008,
  EXTENDED: 0x80000000,
} as const;

// Protocol-style aliases make the constants easy to compare with the v3 draft.
export const SSH_FXF_READ = SFTP_OPEN_FLAGS.READ;
export const SSH_FXF_WRITE = SFTP_OPEN_FLAGS.WRITE;
export const SSH_FXF_APPEND = SFTP_OPEN_FLAGS.APPEND;
export const SSH_FXF_CREAT = SFTP_OPEN_FLAGS.CREATE;
export const SSH_FXF_TRUNC = SFTP_OPEN_FLAGS.TRUNCATE;
export const SSH_FXF_EXCL = SFTP_OPEN_FLAGS.EXCLUSIVE;
export const SSH_FILEXFER_ATTR_SIZE = SFTP_ATTR_FLAGS.SIZE;
export const SSH_FILEXFER_ATTR_UIDGID = SFTP_ATTR_FLAGS.UID_GID;
export const SSH_FILEXFER_ATTR_PERMISSIONS = SFTP_ATTR_FLAGS.PERMISSIONS;
export const SSH_FILEXFER_ATTR_ACMODTIME = SFTP_ATTR_FLAGS.ACCESS_MODIFY_TIME;
export const SSH_FILEXFER_ATTR_EXTENDED = SFTP_ATTR_FLAGS.EXTENDED;

export type SFTPOpenFlags = number;
export type SFTPHandle = Uint8Array;
export type SFTPUint64Input = number | bigint | string;
export type SFTPSize = number | string;

export interface SFTPExtendedAttribute {
  readonly type: string;
  readonly data: Uint8Array;
}

export interface SFTPExtendedAttributeInput {
  readonly type: string;
  readonly data: string | Uint8Array;
}

export interface SFTPAttrs {
  readonly flags: number;
  readonly size?: SFTPSize;
  readonly uid?: number;
  readonly gid?: number;
  readonly permissions?: number;
  readonly atime?: number;
  readonly mtime?: number;
  readonly extended?: readonly SFTPExtendedAttribute[];
}

export interface SFTPAttrsInput {
  readonly size?: SFTPUint64Input;
  readonly uid?: number;
  readonly gid?: number;
  readonly permissions?: number;
  readonly atime?: number;
  readonly mtime?: number;
  readonly extended?: readonly SFTPExtendedAttributeInput[];
}

export interface SFTPDirEntry {
  readonly filename: string;
  readonly longname: string;
  readonly attrs: SFTPAttrs;
}

export interface SFTPVersionInfo {
  readonly version: number;
  readonly extensions: ReadonlyMap<string, string>;
}

export interface SFTPClientOptions {
  /** Maximum packet length, excluding the four-byte packet length field. */
  readonly maxPacketLength?: number;
  /** Maximum memory reserved for a partially received framed packet. */
  readonly maxBufferedBytes?: number;
  readonly maxNameEntries?: number;
  readonly maxExtendedAttributes?: number;
  readonly maxVersionExtensions?: number;
  readonly requestTimeoutMs?: number;
  /** Primarily useful for deterministic request-ID rollover tests. */
  readonly initialRequestId?: number;
}

export type SFTPFileKind =
  | 'file'
  | 'directory'
  | 'symlink'
  | 'socket'
  | 'block-device'
  | 'character-device'
  | 'fifo'
  | 'unknown';

const MODE_TYPE_MASK = 0o170000;

export function getSFTPFileKind(value: SFTPAttrs | number | undefined): SFTPFileKind {
  const permissions = typeof value === 'number' ? value : value?.permissions;
  if (permissions === undefined) return 'unknown';

  switch (permissions & MODE_TYPE_MASK) {
    case 0o100000: return 'file';
    case 0o040000: return 'directory';
    case 0o120000: return 'symlink';
    case 0o140000: return 'socket';
    case 0o060000: return 'block-device';
    case 0o020000: return 'character-device';
    case 0o010000: return 'fifo';
    default: return 'unknown';
  }
}

export function formatSFTPPermissions(value: SFTPAttrs | number | undefined): string {
  const permissions = typeof value === 'number' ? value : value?.permissions;
  if (permissions === undefined) return '??????????';

  const prefix: Record<SFTPFileKind, string> = {
    file: '-',
    directory: 'd',
    symlink: 'l',
    socket: 's',
    'block-device': 'b',
    'character-device': 'c',
    fifo: 'p',
    unknown: '?',
  };
  const bits = [
    permissions & 0o400 ? 'r' : '-',
    permissions & 0o200 ? 'w' : '-',
    permissions & 0o100 ? 'x' : '-',
    permissions & 0o040 ? 'r' : '-',
    permissions & 0o020 ? 'w' : '-',
    permissions & 0o010 ? 'x' : '-',
    permissions & 0o004 ? 'r' : '-',
    permissions & 0o002 ? 'w' : '-',
    permissions & 0o001 ? 'x' : '-',
  ];

  if (permissions & 0o4000) bits[2] = permissions & 0o100 ? 's' : 'S';
  if (permissions & 0o2000) bits[5] = permissions & 0o010 ? 's' : 'S';
  if (permissions & 0o1000) bits[8] = permissions & 0o001 ? 't' : 'T';
  return prefix[getSFTPFileKind(permissions)] + bits.join('');
}

export const getFileKind = getSFTPFileKind;
export const formatPermissions = formatSFTPPermissions;
