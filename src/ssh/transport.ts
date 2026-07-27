// RFC 4253 exchange hashes use this exact line without its CRLF terminator.
export const SSH_VERSION = 'SSH-2.0-CFWorkersWebSSH_1.0';

export function isSSH2Identification(value: string): boolean {
  return value.startsWith('SSH-2.0-') || value.startsWith('SSH-1.99-');
}

export class SSHTransport {
  private remoteVersion: string = '';
  private readonly localVersion: string = SSH_VERSION;
  private versionBuffer: string = '';

  handleVersionExchange(data: string): boolean {
    this.versionBuffer += data;

    const lines = this.versionBuffer.split('\r\n');
    for (const line of lines) {
      if (line.startsWith('SSH-')) {
        this.remoteVersion = line;
        return true;
      }
    }

    return false;
  }

  sendVersion(socket: { write: (data: Uint8Array) => void }): void {
    const encoder = new TextEncoder();
    socket.write(encoder.encode(SSH_VERSION + '\r\n'));
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
