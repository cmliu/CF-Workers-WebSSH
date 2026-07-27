// RFC 4253 exchange hashes use this exact line without its CRLF terminator.
export const SSH_VERSION = 'SSH-2.0-CFWorkersWebSSH_1.0';

export function isSSH2Identification(value: string): boolean {
  return value.startsWith('SSH-2.0-') || value.startsWith('SSH-1.99-');
}

export class SSHTransport {
  private remoteVersion: string = '';
  private readonly localVersion: string = SSH_VERSION;

  setRemoteVersion(version: string): void {
    this.remoteVersion = version;
  }

  getRemoteVersion(): string {
    return this.remoteVersion;
  }

  getLocalVersion(): string {
    return this.localVersion;
  }

  getLocalIdentification(): Uint8Array {
    return new TextEncoder().encode(`${this.localVersion}\r\n`);
  }
}
