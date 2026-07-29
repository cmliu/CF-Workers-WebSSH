import { SSHChannel, type ChannelDataChunk } from '../ssh/channel';
import {
  SFTPClient,
  SFTPStatusError,
  SFTP_OPEN_FLAGS,
  getSFTPFileKind,
  formatSFTPPermissions,
  type SFTPAttrs,
  type SFTPDirEntry,
} from '../ssh/sftp';

const MAX_PATH_BYTES = 4096;
const MAX_DIRECTORY_ENTRIES = 2000;
const MAX_DIRECTORY_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_FILENAME_BYTES = 1024;
const MAX_FILE_SIZE = 64 * 1024 * 1024;
const TRANSFER_CHUNK_SIZE = 64 * 1024;

type SendChannelData = (channel: SSHChannel, chunk: ChannelDataChunk) => Promise<void>;
type SendJSON = (message: unknown) => void;
type SendBinary = (data: Uint8Array) => void;

interface UploadState {
  requestId: string;
  destinationPath: string;
  uploadPath: string;
  size: number;
  received: number;
  handle: Uint8Array;
  handleClosed: boolean;
  temporary: boolean;
}

interface DownloadState {
  requestId: string;
  cancelled: boolean;
}

export class SFTPHandler {
  private readonly channel: SSHChannel;
  private readonly client: SFTPClient;
  private readonly sendChannelData: SendChannelData;
  private readonly sendJSON: SendJSON;
  private readonly sendBinary: SendBinary;
  private readonly sendQueue: Array<{ data: Uint8Array; offset: number }> = [];
  private flushing = false;
  private ready = false;
  private disposed = false;
  private activeDownload: DownloadState | null = null;
  private upload: UploadState | null = null;

  constructor(channel: SSHChannel, sendChannelData: SendChannelData, sendJSON: SendJSON, sendBinary: SendBinary) {
    this.channel = channel;
    this.sendChannelData = sendChannelData;
    this.sendJSON = sendJSON;
    this.sendBinary = sendBinary;
    this.client = new SFTPClient((data: Uint8Array) => this.enqueue(data));
  }

  isReady(): boolean {
    return this.ready;
  }

  async initialize(): Promise<boolean> {
    try {
      const versionInfo = await this.client.initialize();
      const version = versionInfo.version;
      if (version !== 3) throw new Error(`Unsupported SFTP version ${version}`);
      this.ready = true;
      let cwd = '.';
      try { cwd = await this.client.realpath('.'); } catch { /* Listing will surface any path error. */ }
      this.sendJSON({ type: 'sftp_ready', version, cwd });
      return true;
    } catch (error) {
      this.reportError('init', error);
      return false;
    }
  }

  announceReady(): void {
    if (this.ready) this.sendJSON({ type: 'sftp_ready', version: 3 });
  }

  feed(data: Uint8Array): void {
    this.client.feed(data);
  }

  onWindowAdjust(): void {
    void this.flush();
  }

  onClosed(message = 'SFTP channel closed'): void {
    this.ready = false;
    this.sendJSON({ type: 'sftp_closed', message });
    this.dispose();
  }

  async list(requestId: string, path: string): Promise<void> {
    try {
      this.assertReady();
      this.validatePath(path);
      const resolvedPath = await this.client.realpath(path || '.');
      const handle = await this.client.openDir(resolvedPath);
      const entries: Record<string, unknown>[] = [];
      let responseBytes = 0;
      let isTruncated = false;
      try {
        while (entries.length < MAX_DIRECTORY_ENTRIES) {
          const batch = await this.client.readDir(handle);
          if (batch === null || batch.length === 0) break;
          for (const entry of batch) {
            if (entry.filename === '.' || entry.filename === '..') continue;
            if (entries.length === MAX_DIRECTORY_ENTRIES) { isTruncated = true; break; }
            const filenameBytes = new TextEncoder().encode(entry.filename).length;
            if (filenameBytes < 1 || filenameBytes > MAX_FILENAME_BYTES || entry.filename.includes('\0')) {
              throw new Error('SFTP server returned an invalid filename');
            }
            const formatted = this.formatEntry(entry);
            const estimatedBytes = filenameBytes + String(formatted.owner ?? '').length + String(formatted.group ?? '').length + 256;
            if (responseBytes + estimatedBytes > MAX_DIRECTORY_RESPONSE_BYTES) { isTruncated = true; break; }
            responseBytes += estimatedBytes;
            entries.push(formatted);
          }
          if (isTruncated) break;
        }
        if (entries.length === MAX_DIRECTORY_ENTRIES) isTruncated = true;
      } finally {
        await this.client.closeHandle(handle).catch(() => undefined);
      }
      this.sendJSON({
        type: 'sftp_list_result', requestId, path: resolvedPath, isTruncated,
        entries,
      });
    } catch (error) {
      this.reportError('list', error, requestId);
    }
  }

  async download(requestId: string, path: string): Promise<void> {
    let handle: Uint8Array | null = null;
    const download: DownloadState = { requestId, cancelled: false };
    try {
      this.assertReady();
      this.validatePath(path);
      if (this.activeDownload) throw new Error('Another download is already in progress');
      this.activeDownload = download;
      const attrs = await this.client.stat(path);
      this.assertDownloadActive(download);
      const size = this.safeSize(attrs);
      if (size !== null && size > MAX_FILE_SIZE) throw new Error('File exceeds the 64 MiB transfer limit');
      handle = await this.client.openFile(path, SFTP_OPEN_FLAGS.READ);
      this.assertDownloadActive(download);
      const filename = path.split('/').filter(Boolean).pop() || 'download';
      this.sendJSON(size === null
        ? { type: 'sftp_download_start', requestId, filename }
        : { type: 'sftp_download_start', requestId, filename, size });
      let offset = 0;
      while (size === null || offset < size) {
        this.assertDownloadActive(download);
        const length = size === null ? TRANSFER_CHUNK_SIZE : Math.min(TRANSFER_CHUNK_SIZE, size - offset);
        if (length === 0) break;
        const chunk = await this.client.readFile(handle, offset, length);
        this.assertDownloadActive(download);
        if (chunk === null || chunk.length === 0) break;
        if (offset + chunk.length > MAX_FILE_SIZE) throw new Error('File exceeds the 64 MiB transfer limit');
        this.sendBinary(chunk);
        offset += chunk.length;
        this.sendJSON(size === null
          ? { type: 'sftp_download_progress', requestId, loaded: offset }
          : { type: 'sftp_download_progress', requestId, loaded: offset, total: size });
      }
      this.assertDownloadActive(download);
      this.sendJSON({ type: 'sftp_download_done', requestId, filename, size: offset });
    } catch (error) {
      if (download.cancelled) this.sendJSON({ type: 'sftp_download_cancelled', requestId });
      else this.reportError('download', error, requestId);
    } finally {
      if (handle) await this.client.closeHandle(handle).catch(() => undefined);
      if (this.activeDownload === download) this.activeDownload = null;
    }
  }

  cancelDownload(requestId: string): void {
    if (this.activeDownload?.requestId === requestId) this.activeDownload.cancelled = true;
  }

  async startUpload(requestId: string, path: string, size: number, overwrite: boolean): Promise<void> {
    try {
      this.assertReady();
      this.validatePath(path);
      if (this.upload) throw new Error('Another upload is already in progress');
      if (!Number.isSafeInteger(size) || size < 0 || size > MAX_FILE_SIZE) throw new Error('Invalid upload size or file exceeds the 64 MiB transfer limit');
      const uploadPath = overwrite ? this.temporaryUploadPath(path) : path;
      const handle = await this.client.openFile(
        uploadPath,
        SFTP_OPEN_FLAGS.WRITE | SFTP_OPEN_FLAGS.CREATE | SFTP_OPEN_FLAGS.TRUNCATE | SFTP_OPEN_FLAGS.EXCLUSIVE,
      );
      this.upload = {
        requestId,
        destinationPath: path,
        uploadPath,
        size,
        received: 0,
        handle,
        handleClosed: false,
        temporary: overwrite,
      };
      this.sendJSON({ type: 'sftp_upload_ready', requestId, path, size });
    } catch (error) {
      this.reportError('upload', error, requestId);
    }
  }

  async uploadChunk(data: Uint8Array): Promise<void> {
    const upload = this.upload;
    if (!upload) throw new Error('No upload is in progress');
    if (data.length === 0 || data.length > TRANSFER_CHUNK_SIZE || upload.received + data.length > upload.size) {
      const requestId = upload.requestId;
      await this.abortUpload(upload, true);
      this.reportError('upload', new Error('Invalid upload chunk'), requestId);
      return;
    }
    try {
      await this.client.writeFile(upload.handle, upload.received, data);
      upload.received += data.length;
      this.sendJSON({ type: 'sftp_upload_progress', requestId: upload.requestId, loaded: upload.received, total: upload.size });
    } catch (error) {
      const requestId = upload.requestId;
      await this.abortUpload(upload, true);
      this.reportError('upload', error, requestId);
    }
  }

  async finishUpload(requestId: string): Promise<void> {
    const upload = this.upload;
    try {
      if (!upload || upload.requestId !== requestId) throw new Error('No matching upload is in progress');
      if (upload.received !== upload.size) throw new Error('Upload ended before the declared size was received');
      await this.client.closeHandle(upload.handle);
      upload.handleClosed = true;
      if (upload.temporary) await this.client.rename(upload.uploadPath, upload.destinationPath);
      this.upload = null;
      this.sendJSON({ type: 'sftp_upload_complete', requestId, path: upload.destinationPath, size: upload.received });
    } catch (error) {
      if (upload) await this.abortUpload(upload, true);
      this.reportError('upload', error, requestId);
    }
  }

  async cancelUpload(requestId: string): Promise<void> {
    const upload = this.upload;
    if (!upload || upload.requestId !== requestId) return;
    await this.abortUpload(upload, true);
    this.sendJSON({ type: 'sftp_upload_cancelled', requestId });
  }

  async remove(requestId: string, path: string, directory: boolean): Promise<void> {
    const operation = directory ? 'rmdir' : 'delete';
    try {
      this.assertReady();
      this.validatePath(path);
      if (directory) await this.client.rmdir(path);
      else await this.client.removeFile(path);
      this.sendJSON({ type: `sftp_${operation}_result`, requestId, path, success: true });
    } catch (error) {
      this.reportError(operation, error, requestId);
    }
  }

  async mkdir(requestId: string, path: string): Promise<void> {
    try {
      this.assertReady();
      this.validatePath(path);
      await this.client.mkdir(path, { permissions: 0o755 });
      this.sendJSON({ type: 'sftp_mkdir_result', requestId, path, success: true });
    } catch (error) {
      this.reportError('mkdir', error, requestId);
    }
  }

  async rename(requestId: string, oldPath: string, newPath: string): Promise<void> {
    try {
      this.assertReady();
      this.validatePath(oldPath);
      this.validatePath(newPath);
      await this.client.rename(oldPath, newPath);
      this.sendJSON({ type: 'sftp_rename_result', requestId, oldPath, newPath, success: true });
    } catch (error) {
      this.reportError('rename', error, requestId);
    }
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.ready = false;
    this.sendQueue.length = 0;
    this.client.dispose();
  }

  private enqueue(data: Uint8Array): void {
    if (this.disposed) return;
    this.sendQueue.push({ data, offset: 0 });
    void this.flush();
  }

  private async flush(): Promise<void> {
    if (this.flushing || this.disposed) return;
    this.flushing = true;
    try {
      while (this.sendQueue.length > 0 && !this.disposed) {
        const current = this.sendQueue[0];
        const chunk = this.channel.takeChannelDataChunk(current.data, current.offset);
        if (!chunk) return;
        await this.sendChannelData(this.channel, chunk);
        current.offset += chunk.bytesConsumed;
        if (current.offset === current.data.length) this.sendQueue.shift();
      }
    } catch (error) {
      this.reportError('protocol', error);
    } finally {
      this.flushing = false;
    }
  }

  private async abortUpload(upload: UploadState, removePartial: boolean): Promise<void> {
    if (this.upload === upload) this.upload = null;
    if (!upload.handleClosed) {
      await this.client.closeHandle(upload.handle).catch(() => undefined);
      upload.handleClosed = true;
    }
    if (removePartial) await this.client.removeFile(upload.uploadPath).catch(() => undefined);
  }

  private assertReady(): void {
    if (!this.ready || this.disposed) throw new Error('SFTP is not ready');
  }

  private validatePath(path: string): void {
    const length = new TextEncoder().encode(path).length;
    if (length < 1 || length > MAX_PATH_BYTES || path.includes('\0')) throw new Error('Invalid remote path');
  }

  private safeSize(attrs: SFTPAttrs): number | null {
    if (attrs.size === undefined) return null;
    if (typeof attrs.size === 'string') throw new Error('File is too large for this client');
    const size = attrs.size;
    if (!Number.isSafeInteger(size) || size < 0) throw new Error('Invalid remote file size');
    return size;
  }

  private assertDownloadActive(download: DownloadState): void {
    if (this.activeDownload !== download || download.cancelled) throw new Error('Download cancelled');
  }

  private temporaryUploadPath(path: string): string {
    const separator = path.lastIndexOf('/');
    const parent = separator >= 0 ? path.slice(0, separator + 1) : '';
    const suffix = crypto.randomUUID().replaceAll('-', '');
    const temporary = `${parent}.cf-webssh-upload-${suffix}`;
    this.validatePath(temporary);
    return temporary;
  }

  private formatEntry(entry: SFTPDirEntry): Record<string, unknown> {
    const attrs = entry.attrs;
    const kind = getSFTPFileKind(attrs);
    const type = kind === 'directory' || kind === 'symlink' ? kind : kind === 'file' ? 'file' : 'other';
    const identity = this.parseLongnameIdentity(entry.longname);
    return {
      name: entry.filename,
      type,
      size: attrs.size ?? 0,
      mtime: attrs.mtime ?? 0,
      permissions: formatSFTPPermissions(attrs),
      permissionsRaw: attrs.permissions ?? 0,
      uid: attrs.uid,
      gid: attrs.gid,
      owner: identity.owner,
      group: identity.group,
    };
  }

  private parseLongnameIdentity(longname: string): { owner?: string; group?: string } {
    if (longname.length > 4096) return {};
    const fields = longname.trim().split(/\s+/);
    if (fields.length < 4 || !/^[bcdlps-][rwxStTs-]{9}[+@.]?$/.test(fields[0])) return {};
    return { owner: fields[2], group: fields[3] };
  }

  private reportError(operation: string, error: unknown, requestId?: string): void {
    const message = error instanceof Error ? error.message : String(error);
    const code = error instanceof SFTPStatusError ? error.code : undefined;
    this.sendJSON({ type: 'sftp_error', requestId, operation, code, message });
  }
}
