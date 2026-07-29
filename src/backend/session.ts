import {
  SSH_MSG_CHANNEL_CLOSE,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_EOF,
  SSH_MSG_CHANNEL_EXTENDED_DATA,
  SSH_MSG_CHANNEL_FAILURE,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
  SSH_MSG_CHANNEL_OPEN_FAILURE,
  SSH_MSG_CHANNEL_SUCCESS,
  SSH_MSG_CHANNEL_WINDOW_ADJUST,
  SSH_MSG_DEBUG,
  SSH_MSG_DISCONNECT,
  SSH_MSG_EXT_INFO,
  SSH_MSG_GLOBAL_REQUEST,
  SSH_MSG_IGNORE,
  SSH_MSG_KEXINIT,
  SSH_MSG_KEX_ECDH_REPLY,
  SSH_MSG_NEWKEYS,
  SSH_MSG_REQUEST_FAILURE,
  SSH_MSG_REQUEST_SUCCESS,
  SSH_MSG_SERVICE_ACCEPT,
  SSH_MSG_SERVICE_REQUEST,
  SSH_MSG_UNIMPLEMENTED,
  SSH_MSG_USERAUTH_FAILURE,
  SSH_MSG_USERAUTH_INFO_REQUEST,
  SSH_MSG_USERAUTH_SUCCESS,
  type SSHConnectionConfig,
  type SSHPacket,
  type SessionKeys,
} from '../types';
import { isSSH2Identification, SSHTransport } from '../ssh/transport';
import { SSHPacketBuilder, SSHPacketParser, nextSequenceNumber } from '../ssh/packet';
import { KEXInitBuilder, filterExtInfo, negotiate, parseKEXInit, parseServerSigAlgs } from '../ssh/kex';
import {
  KEX_ALGORITHM_ECDH_NISTP256,
  getCipherSpec,
  getMacSpec,
  isCurve25519KEXAlgorithm,
} from '../ssh/algorithms';
import { ECDHKeyExchange } from '../ssh/kex-ecdh';
import { Curve25519KeyExchange, type Curve25519KeyPair } from '../ssh/kex-curve25519';
import { KeyDerivation } from '../ssh/keys';
import { SSHAESCTRCipher, SSHAESGCMCipher, SSHHMAC } from '../ssh/crypto';
import { SSHAuth } from '../ssh/auth';
import { SSHChannel, type ChannelDataChunk } from '../ssh/channel';
import { SFTPHandler } from './sftp-handler';
import { classifyHostKey } from '../ssh/host-key';
import { encodeString, readUint32, toBufferSource } from '../ssh/utils';
import { parseTopSnapshot } from './top-parser';
import { retainTrailingMarkerPrefix } from './process-framing';

type Cipher = SSHAESGCMCipher | SSHAESCTRCipher;
type Phase = 'version' | 'kex' | 'host-confirm' | 'auth' | 'pty' | 'shell' | 'ready' | 'closed';
interface PendingSFTPChannelOpen {
  readonly channelID: number;
  readonly channel: SSHChannel;
  timeout: ReturnType<typeof setTimeout> | null;
  cancelled: boolean;
}
interface PendingProcessChannelOpen {
  readonly channelID: number;
  readonly channel: SSHChannel;
  timeout: ReturnType<typeof setTimeout> | null;
  cancelled: boolean;
}
const LOCAL_WINDOW_THRESHOLD = 512 * 1024;
const MAX_VERSION_BYTES = 8192;
const MAX_QUEUED_INPUT = 1024 * 1024;
const MAX_QUEUED_SFTP_UPLOAD = 1024 * 1024;
const SFTP_CHANNEL_OPEN_TIMEOUT_MS = 15_000;
const PROCESS_CHANNEL_OPEN_TIMEOUT_MS = 15_000;
const PROCESS_MAX_BUFFER_BYTES = 2 * 1024 * 1024;
const PROCESS_SNAPSHOT_MARKER = '__CF_WEBSSH_TOP_SNAPSHOT__';
// Octal escapes keep the delimiter itself out of the command line shown by top.
// `top` flags differ across platforms: Linux procps uses `-n 1` (1 iteration) + `-c` (full command line),
// but on FreeBSD `-n 1` means "show 1 process" and `-w` is unsupported — so the previous
// Linux-only fallback chain silently truncated FreeBSD output to a single process row.
// `-c` is required on Linux/macOS because their top defaults to showing just the program name;
// FreeBSD top shows the full command line by default. `-w` is omitted on Linux because procps-ng
// batch mode defaults to unlimited width (capping it at 512 would truncate long java/node args).
// Dispatch on `uname -s` so each platform gets the correct flags:
//   Linux:    top -b -c -n 1            (batch, full command line, 1 iteration)
//   FreeBSD:  top -b -a -d 1            (batch, all processes, 1 iteration)
//   macOS:    top -l 1 -c -n 0 -s 0     (1 log sample, full command line, all processes, no delay)
const PROCESS_MONITOR_COMMAND = "LC_ALL=C LANG=C sh -c 'os=$(uname -s 2>/dev/null || echo Linux); case \"$os\" in FreeBSD) T=\"top -b -a -d 1\";; Darwin) T=\"top -l 1 -c -n 0 -s 0\";; *) T=\"top -b -c -n 1\";; esac; while :; do printf \"\\137\\137CF_WEBSSH_TOP_SNAPSHOT\\137\\137\\n\"; $T 2>/dev/null || exit 127; sleep 2; done'";
const KEEPALIVE_NAME = new TextEncoder().encode('keepalive@openssh.com');

export class SSHSession {
  private readonly encoder = new TextEncoder();
  private readonly decoder = new TextDecoder();
  private readonly transport = new SSHTransport();
  private readonly parser = new SSHPacketParser();
  private readonly shellChannel = new SSHChannel();
  private readonly channels = new Map<number, SSHChannel>([[0, this.shellChannel]]);
  private readonly config: SSHConnectionConfig;
  private readonly ws: WebSocket;
  private readonly socket: Socket;
  private phase: Phase = 'version';
  private versionBuffer = new Uint8Array();
  private writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private sendSequence = 0;
  private sendChain: Promise<void> = Promise.resolve();
  private localKex: Uint8Array | null = null;
  private remoteKex: Uint8Array | null = null;
  private kexName: string | null = null;
  private hostKeyAlgorithm: string | null = null;
  private ecdhPair: CryptoKeyPair | null = null;
  private curvePair: Curve25519KeyPair | null = null;
  private clientPublic: Uint8Array | null = null;
  private sessionId: Uint8Array | null = null;
  private keys: SessionKeys | null = null;
  private cipherC2S = 'aes128-gcm@openssh.com';
  private cipherS2C = 'aes128-gcm@openssh.com';
  private macC2S = 'none';
  private macS2C = 'none';
  private encryptor: Cipher | null = null;
  private decryptor: Cipher | null = null;
  private signer: SSHHMAC | null = null;
  private verifier: SSHHMAC | null = null;
  private serverSigAlgs: string[] = [];
  private authRequestSent = false;
  private passwordAuthMethod: 'password' | 'keyboard-interactive' = 'password';
  private keyboardInteractiveRounds = 0;
  private keyboardInteractivePasswordSent = false;
  private pendingChannelRequest: 'pty' | 'shell' | null = null;
  private nextChannelID = 1;
  private sftpChannel: SSHChannel | null = null;
  private sftpHandler: SFTPHandler | null = null;
  private sftpWebSocket: WebSocket | null = null;
  private sftpAttachUrl = '';
  private sftpTaskChain: Promise<void> = Promise.resolve();
  private sftpQueuedUploadBytes = 0;
  private pendingSFTPChannelOpen: PendingSFTPChannelOpen | null = null;
  private processChannel: SSHChannel | null = null;
  private processWebSocket: WebSocket | null = null;
  private processAttachUrl = '';
  private processBuffer = '';
  private processDecoder = new TextDecoder();
  private pendingProcessChannelOpen: PendingProcessChannelOpen | null = null;
  private ignoreNextKexPacket = false;
  private inputQueue: Uint8Array[] = [];
  private queueHeadOffset = 0;
  private queuedBytes = 0;
  private flushingInput = false;
  private keepaliveTimer: ReturnType<typeof setInterval> | null = null;
  private keepalivePending = 0;
  private shellTimer: ReturnType<typeof setTimeout> | null = null;
  private readTask: Promise<void> | null = null;
  private pendingHostConfirmation: { fingerprint: string; resolve: (accepted: boolean) => void } | null = null;

  constructor(ws: WebSocket, socket: Socket, config: SSHConnectionConfig) {
    this.ws = ws;
    this.socket = socket;
    this.config = config;
  }

  async start(): Promise<void> {
    this.status('version_exchange', 'Exchanging SSH protocol versions');
    await this.write(this.transport.getLocalIdentification());
    this.readTask = this.readLoop();
  }

  async handleClientMessage(message: string | ArrayBuffer): Promise<void> {
    if (this.phase === 'closed') return;
    if (message instanceof ArrayBuffer) {
      if (message.byteLength > 64 * 1024) throw new Error('Binary terminal input exceeds 64 KiB');
      this.queueInput(new Uint8Array(message));
      return;
    }

    let frame: unknown;
    try { frame = JSON.parse(message); } catch { throw new Error('Invalid WebSocket control JSON'); }
    if (!frame || typeof frame !== 'object' || Array.isArray(frame)) throw new Error('Invalid WebSocket control message');
    const value = frame as Record<string, unknown>;
    if (value.type === 'host_key_decision') {
      const pending = this.pendingHostConfirmation;
      if (!pending || typeof value.accept !== 'boolean' || value.fingerprint !== pending.fingerprint) throw new Error('Invalid host key decision');
      this.pendingHostConfirmation = null;
      pending.resolve(value.accept);
      return;
    }
    if (value.type === 'ping') {
      this.sendJson({ type: 'pong' });
      return;
    }
    const resize = value.type === 'resize'
      ? [value.cols, value.rows]
      : Array.isArray(value.resize) ? value.resize : null;
    if (resize) {
      await this.resize(resize[0], resize[1]);
      return;
    }
    if (value.type === 'input' || (value.type === undefined && typeof value.data === 'string')) {
      if (typeof value.data !== 'string' || value.data.length > 256 * 1024) throw new Error('Invalid terminal input');
      this.queueInput(this.encoder.encode(value.data));
      return;
    }
    throw new Error('Unsupported WebSocket message');
  }

  close(normal = false): void {
    if (this.phase === 'closed') return;
    this.phase = 'closed';
    if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
    if (this.shellTimer) clearTimeout(this.shellTimer);
    this.keepaliveTimer = null;
    this.shellTimer = null;
    this.inputQueue = [];
    this.queuedBytes = 0;
    this.sftpHandler?.dispose();
    this.sftpHandler = null;
    this.sftpChannel = null;
    this.clearPendingSFTPChannelOpen();
    this.clearPendingProcessChannelOpen();
    this.processChannel = null;
    this.processBuffer = '';
    this.channels.clear();
    try { this.sftpWebSocket?.close(normal ? 1000 : 1011, normal ? 'SSH session closed' : 'SSH session failed'); } catch { /* already closed */ }
    this.sftpWebSocket = null;
    try { this.processWebSocket?.close(normal ? 1000 : 1011, normal ? 'SSH session closed' : 'SSH session failed'); } catch { /* already closed */ }
    this.processWebSocket = null;
    this.pendingHostConfirmation?.resolve(false);
    this.pendingHostConfirmation = null;
    this.config.password = undefined;
    this.config.privateKey = undefined;
    try { this.writer?.releaseLock(); } catch { /* already released */ }
    this.writer = null;
    try { this.socket.close(); } catch { /* already closed */ }
    try { this.ws.close(normal ? 1000 : 1011, normal ? 'Session closed' : 'SSH session failed'); } catch { /* already closed */ }
  }

  private async readLoop(): Promise<void> {
    const reader = this.socket.readable.getReader();
    try {
      while (this.phase !== 'closed') {
        const { value, done } = await reader.read();
        if (done) {
          this.status('remote_closed', 'The SSH server closed the connection');
          this.close(true);
          return;
        }
        if (value.length > 0) await this.consume(value);
      }
    } catch (error) {
      this.fail(error, 'read_error');
    } finally {
      try { reader.releaseLock(); } catch { /* ignored */ }
    }
  }

  private async consume(data: Uint8Array): Promise<void> {
    if (this.phase === 'version') {
      const merged = new Uint8Array(this.versionBuffer.length + data.length);
      merged.set(this.versionBuffer);
      merged.set(data, this.versionBuffer.length);
      if (merged.length > MAX_VERSION_BYTES) throw new Error('SSH identification banner is too large');
      this.versionBuffer = merged;
      let start = 0;
      while (true) {
        const newline = this.versionBuffer.indexOf(0x0a, start);
        if (newline < 0) return;
        const bytes = this.versionBuffer.subarray(start, newline + 1);
        start = newline + 1;
        const line = this.decoder.decode(bytes).replace(/\r?\n$/, '');
        if (!line.startsWith('SSH-')) continue;
        if (!isSSH2Identification(line)) throw new Error('The server does not support SSH 2.0');
        this.transport.setRemoteVersion(line);
        const remaining = this.versionBuffer.subarray(start);
        this.versionBuffer = new Uint8Array();
        this.phase = 'kex';
        this.status('version_ready', 'Version exchange complete; negotiating keys');
        await this.startKex();
        if (remaining.length > 0) {
          this.parser.feed(remaining);
          await this.processPackets();
        }
        return;
      }
    }
    this.parser.feed(data);
    await this.processPackets();
  }

  private async startKex(): Promise<void> {
    this.localKex = KEXInitBuilder.build();
    await this.sendPlain(this.localKex);
  }

  private async processPackets(): Promise<void> {
    while (this.phase !== 'closed') {
      // NEWKEYS may enable inbound encryption while this same TCP chunk still
      // contains encrypted packets, so recompute framing on every iteration.
      const spec = this.decryptor ? getCipherSpec(this.cipherS2C) : null;
      const macLength = this.decryptor && !spec?.aead ? getMacSpec(this.macS2C).length : 0;
      const packet = await this.parser.nextPacket(
        spec?.blockSize ?? 8,
        this.decryptor ? (data, sequence, aad, commit) => this.decryptor!.decrypt(data, sequence, aad, commit) : (data) => data,
        Boolean(spec?.aead),
        macLength,
        this.verifier ? (data, mac, sequence) => this.verifier!.verify(data, sequence, mac) : undefined,
      );
      if (!packet) return;
      await this.handlePacket(packet);
    }
  }

  private async handlePacket(packet: SSHPacket): Promise<void> {
    const type = packet.payload[0];
    if (type === SSH_MSG_DISCONNECT) {
      this.validateDisconnect(packet.payload);
      this.status('remote_closed', 'The SSH server closed the connection');
      this.close(true);
      return;
    }
    if (type === SSH_MSG_IGNORE) {
      const data = this.readBytes(packet.payload, 1);
      if (data.next !== packet.payload.length) throw new Error('Malformed SSH ignore message');
      return;
    }
    if (type === SSH_MSG_DEBUG) {
      this.validateDebug(packet.payload);
      return;
    }
    if (type === SSH_MSG_UNIMPLEMENTED) {
      if (packet.payload.length !== 5) throw new Error('Malformed SSH unimplemented message');
      return;
    }
    if (type === SSH_MSG_GLOBAL_REQUEST) {
      await this.handleGlobalRequest(packet.payload);
      return;
    }
    if (type === SSH_MSG_REQUEST_SUCCESS || type === SSH_MSG_REQUEST_FAILURE) {
      this.keepalivePending = 0;
      return;
    }
    if (type === SSH_MSG_KEXINIT && this.phase !== 'kex' && this.phase !== 'host-confirm') throw new Error('Server-initiated SSH rekey is not supported');
    if (this.phase === 'kex' || this.phase === 'host-confirm') await this.handleKex(type, packet.payload);
    else if (this.phase === 'auth') await this.handleAuth(type, packet.payload);
    else if (this.phase === 'pty' || this.phase === 'shell' || this.phase === 'ready') await this.handleChannel(type, packet.payload);
  }

  private async handleKex(type: number, payload: Uint8Array): Promise<void> {
    if (this.ignoreNextKexPacket) {
      this.ignoreNextKexPacket = false;
      return;
    }
    if (type === SSH_MSG_KEXINIT) {
      if (this.encryptor) throw new Error('SSH rekey is not supported by this terminal session');
      this.remoteKex = payload;
      const client = parseKEXInit(this.localKex!);
      const server = parseKEXInit(payload);
      this.kexName = negotiate(filterExtInfo(client.kexAlgorithms), filterExtInfo(server.kexAlgorithms), 'key exchange algorithm');
      this.hostKeyAlgorithm = negotiate(client.hostKeyAlgorithms, server.hostKeyAlgorithms, 'host key algorithm');
      this.ignoreNextKexPacket = server.firstKexPacketFollows
        && (filterExtInfo(server.kexAlgorithms)[0] !== this.kexName || server.hostKeyAlgorithms[0] !== this.hostKeyAlgorithm);
      this.cipherC2S = negotiate(client.encryptionC2S, server.encryptionC2S, 'client cipher');
      this.cipherS2C = negotiate(client.encryptionS2C, server.encryptionS2C, 'server cipher');
      // RFC 4253 negotiates MAC lists even when the chosen AEAD cipher does
      // not use the result on the wire.
      const negotiatedMacC2S = negotiate(client.macC2S, server.macC2S, 'client MAC');
      const negotiatedMacS2C = negotiate(client.macS2C, server.macS2C, 'server MAC');
      this.macC2S = getCipherSpec(this.cipherC2S).aead ? 'none' : negotiatedMacC2S;
      this.macS2C = getCipherSpec(this.cipherS2C).aead ? 'none' : negotiatedMacS2C;
      if (negotiate(client.compressionC2S, server.compressionC2S, 'client compression') !== 'none'
        || negotiate(client.compressionS2C, server.compressionS2C, 'server compression') !== 'none') {
        throw new Error('SSH compression is not supported');
      }
      await this.sendEcdhInit();
      return;
    }
    if (type === SSH_MSG_KEX_ECDH_REPLY) {
      await this.handleEcdhReply(payload);
      return;
    }
    if (type === SSH_MSG_NEWKEYS) {
      if (!this.keys || !this.encryptor) throw new Error('Received NEWKEYS before completing key exchange');
      // The server's new keys apply only to subsequent inbound packets.
      await this.enableInboundEncryption();
      this.phase = 'auth';
      this.status('authenticating', 'Encrypted transport established; authenticating');
      await this.sendEncrypted(new Uint8Array([SSH_MSG_SERVICE_REQUEST, ...encodeString('ssh-userauth')]));
    }
  }

  private async sendEcdhInit(): Promise<void> {
    if (this.kexName && isCurve25519KEXAlgorithm(this.kexName)) {
      this.curvePair = await Curve25519KeyExchange.generateKeyPair();
      this.clientPublic = await Curve25519KeyExchange.exportRawPublicKey(this.curvePair);
      await this.sendPlain(Curve25519KeyExchange.buildInit(this.clientPublic));
      return;
    }
    if (this.kexName === KEX_ALGORITHM_ECDH_NISTP256) {
      this.ecdhPair = await ECDHKeyExchange.generateKeyPair();
      this.clientPublic = await ECDHKeyExchange.exportRawPublicKey(this.ecdhPair);
      await this.sendPlain(ECDHKeyExchange.buildInit(this.clientPublic));
      return;
    }
    throw new Error(`Unsupported key exchange algorithm: ${this.kexName ?? 'none'}`);
  }

  private async handleEcdhReply(payload: Uint8Array): Promise<void> {
    if (!this.kexName || !this.clientPublic || !this.localKex || !this.remoteKex) throw new Error('Unexpected key exchange reply');
    const { hostKey, serverRawPublicKey, signature } = ECDHKeyExchange.parseReply(payload);
    let sharedSecret: Uint8Array;
    let hash: Uint8Array;
    if (isCurve25519KEXAlgorithm(this.kexName)) {
      if (!this.curvePair) throw new Error('Missing Curve25519 key');
      sharedSecret = await Curve25519KeyExchange.computeSharedSecret(this.curvePair.privateKey, serverRawPublicKey);
      hash = await Curve25519KeyExchange.computeExchangeHash(this.transport.getLocalVersion(), this.transport.getRemoteVersion(), this.localKex, this.remoteKex, hostKey, this.clientPublic, serverRawPublicKey, sharedSecret);
    } else {
      if (!this.ecdhPair) throw new Error('Missing ECDH key');
      sharedSecret = await ECDHKeyExchange.computeSharedSecret(this.ecdhPair.privateKey, serverRawPublicKey);
      hash = await ECDHKeyExchange.computeExchangeHash(this.transport.getLocalVersion(), this.transport.getRemoteVersion(), this.localKex, this.remoteKex, hostKey, this.clientPublic, serverRawPublicKey, sharedSecret);
    }
    const keyTypeLength = readUint32(hostKey, 0);
    if (keyTypeLength > 128 || keyTypeLength + 4 > hostKey.length) throw new Error('Malformed SSH host key');
    const keyType = this.decoder.decode(hostKey.subarray(4, 4 + keyTypeLength));
    if (!this.isHostKeyAlgorithmCompatible(this.hostKeyAlgorithm, keyType)) throw new Error(`Server used ${keyType}, but negotiated ${this.hostKeyAlgorithm ?? 'no host key algorithm'}`);
    const fingerprint = `SHA256:${this.base64(new Uint8Array(await crypto.subtle.digest('SHA-256', toBufferSource(hostKey))))}`;
    if (!await this.verifyHostSignature(hostKey, signature, hash)) throw new Error('SSH host key signature verification failed');
    const trust = classifyHostKey(this.config.expectedFingerprint, fingerprint);
    if (trust === 'trusted') {
      this.sendJson({ type: 'host_key', fingerprint, keyType, trusted: true });
    } else if (!await this.confirmHostKey(fingerprint, keyType, trust === 'changed' ? this.config.expectedFingerprint : undefined)) {
      throw new Error('Host key was not accepted');
    }
    this.status('host_key_verified', `Host key verified (${keyType})`);

    this.sessionId ??= hash;
    const c2s = getCipherSpec(this.cipherC2S);
    const s2c = getCipherSpec(this.cipherS2C);
    this.keys = await KeyDerivation.deriveKeys(
      sharedSecret,
      hash,
      this.sessionId,
      c2s.ivLength,
      s2c.ivLength,
      getMacSpec(this.macC2S).keyLength,
      getMacSpec(this.macS2C).keyLength,
      c2s.keyLength,
      s2c.keyLength,
    );
    // Each direction switches independently at its NEWKEYS boundary. Sending
    // ours now also works with servers that wait before sending their NEWKEYS.
    await this.sendPlain(new Uint8Array([SSH_MSG_NEWKEYS]));
    await this.enableOutboundEncryption();
  }

  private async confirmHostKey(fingerprint: string, keyType: string, expectedFingerprint?: string): Promise<boolean> {
    this.phase = 'host-confirm';
    this.status('host_key_confirmation', 'Confirm this host key before credentials are sent');
    return new Promise<boolean>((resolve) => {
      let settled = false;
      const finish = (accepted: boolean): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        if (this.pendingHostConfirmation?.fingerprint === fingerprint) this.pendingHostConfirmation = null;
        if (accepted && this.phase !== 'closed') this.phase = 'kex';
        resolve(accepted);
      };
      const timeout = setTimeout(() => finish(false), 30_000);
      this.pendingHostConfirmation = { fingerprint, resolve: finish };
      // Register the decision handler before notifying the browser.
      this.sendJson({ type: 'host_key', fingerprint, keyType, trusted: false, expectedFingerprint });
    });
  }

  private async verifyHostSignature(hostKey: Uint8Array, signature: Uint8Array, hash: Uint8Array): Promise<boolean> {
    let offset = 0;
    const keyType = this.readString(hostKey, offset); offset = keyType.next;
    let sigOffset = 0;
    const signatureType = this.readString(signature, sigOffset); sigOffset = signatureType.next;
    const signatureField = this.readBytes(signature, sigOffset);
    if (signatureField.next !== signature.length) throw new Error('Malformed SSH host signature');
    const rawSignature = signatureField.value;
    if (keyType.value === 'ssh-ed25519') {
      if (this.hostKeyAlgorithm !== 'ssh-ed25519' || signatureType.value !== 'ssh-ed25519') throw new Error('Ed25519 host key or signature does not match the negotiated algorithm');
      const keyField = this.readBytes(hostKey, offset);
      if (keyField.next !== hostKey.length || keyField.value.length !== 32 || rawSignature.length !== 64) throw new Error('Malformed Ed25519 host key or signature');
      const rawKey = keyField.value;
      const key = await crypto.subtle.importKey('raw', toBufferSource(rawKey), { name: 'Ed25519' }, false, ['verify']);
      return crypto.subtle.verify('Ed25519', key, toBufferSource(rawSignature), toBufferSource(hash));
    }
    if (keyType.value.startsWith('ecdsa-sha2-nistp')) {
      if (this.hostKeyAlgorithm !== keyType.value || signatureType.value !== keyType.value) throw new Error('ECDSA host key or signature does not match the negotiated algorithm');
      const curveName = this.readString(hostKey, offset); offset = curveName.next;
      const keyField = this.readBytes(hostKey, offset);
      if (keyField.next !== hostKey.length) throw new Error('Malformed ECDSA host key');
      const rawKey = keyField.value;
      const curve = keyType.value.endsWith('256') ? 'P-256' : keyType.value.endsWith('384') ? 'P-384' : 'P-521';
      if (curveName.value !== keyType.value.replace('ecdsa-sha2-', '')) throw new Error('ECDSA curve name does not match the host key type');
      const digest = curve === 'P-256' ? 'SHA-256' : curve === 'P-384' ? 'SHA-384' : 'SHA-512';
      const coordinateBytes = curve === 'P-256' ? 32 : curve === 'P-384' ? 48 : 66;
      const key = await crypto.subtle.importKey('raw', toBufferSource(rawKey), { name: 'ECDSA', namedCurve: curve }, false, ['verify']);
      return crypto.subtle.verify({ name: 'ECDSA', hash: digest }, key, toBufferSource(this.sshEcdsaToRaw(rawSignature, coordinateBytes)), toBufferSource(hash));
    }
    if (keyType.value === 'ssh-rsa') {
      if (signatureType.value !== 'rsa-sha2-256' && signatureType.value !== 'rsa-sha2-512') throw new Error(`Unsupported RSA host signature type: ${signatureType.value}`);
      if (signatureType.value !== this.hostKeyAlgorithm) throw new Error(`RSA signature ${signatureType.value} does not match negotiated ${this.hostKeyAlgorithm}`);
      const exponent = this.readBytes(hostKey, offset); offset = exponent.next;
      const modulusField = this.readBytes(hostKey, offset);
      if (modulusField.next !== hostKey.length || exponent.value.length === 0 || modulusField.value.length === 0) throw new Error('Malformed RSA host key');
      const modulus = modulusField.value;
      const digest = signatureType.value === 'rsa-sha2-512' ? 'SHA-512' : 'SHA-256';
      const key = await crypto.subtle.importKey('jwk', { kty: 'RSA', e: this.base64UrlUnsigned(exponent.value), n: this.base64UrlUnsigned(modulus), ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: digest }, false, ['verify']);
      return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, toBufferSource(rawSignature), toBufferSource(hash));
    }
    throw new Error(`Unsupported host key type: ${keyType.value}`);
  }

  private async enableOutboundEncryption(): Promise<void> {
    if (!this.keys) throw new Error('Session keys are not available');
    const c2s = getCipherSpec(this.cipherC2S);
    this.encryptor = c2s.mode === 'gcm'
      ? new SSHAESGCMCipher(this.keys.encKeyClientToServer.subarray(0, c2s.keyLength), this.keys.ivClientToServer)
      : new SSHAESCTRCipher(this.keys.encKeyClientToServer.subarray(0, c2s.keyLength), this.keys.ivClientToServer);
    await this.encryptor.init();
    if (!c2s.aead) { this.signer = new SSHHMAC(this.macC2S, this.keys.integrityKeyC2S); await this.signer.init(); }
  }

  private async enableInboundEncryption(): Promise<void> {
    if (!this.keys) throw new Error('Session keys are not available');
    const s2c = getCipherSpec(this.cipherS2C);
    this.decryptor = s2c.mode === 'gcm'
      ? new SSHAESGCMCipher(this.keys.encKeyServerToClient.subarray(0, s2c.keyLength), this.keys.ivServerToClient)
      : new SSHAESCTRCipher(this.keys.encKeyServerToClient.subarray(0, s2c.keyLength), this.keys.ivServerToClient);
    await this.decryptor.init();
    if (!s2c.aead) { this.verifier = new SSHHMAC(this.macS2C, this.keys.integrityKeyS2C); await this.verifier.init(); }
  }

  private async handleAuth(type: number, payload: Uint8Array): Promise<void> {
    if (type === SSH_MSG_EXT_INFO) {
      if (this.authRequestSent) throw new Error('Unexpected SSH extension information after authentication started');
      this.serverSigAlgs = parseServerSigAlgs(payload);
      return;
    }
    if (type === SSH_MSG_SERVICE_ACCEPT) {
      const service = this.readString(payload, 1);
      if (service.next !== payload.length || service.value !== 'ssh-userauth') throw new Error('Invalid SSH user authentication service acceptance');
      if (this.authRequestSent) throw new Error('Duplicate SSH user authentication service acceptance');
      const request = this.config.authMethod === 'publickey'
        ? await SSHAuth.buildPublicKeyAuthRequest(this.config.username, this.config.privateKey!, this.sessionId!, this.serverSigAlgs)
        : SSHAuth.buildPasswordAuthRequest(this.config.username, this.config.password!);
      this.authRequestSent = true;
      if (this.config.authMethod === 'publickey') this.config.privateKey = undefined;
      await this.sendEncrypted(request);
      return;
    }
    if (type === SSH_MSG_USERAUTH_INFO_REQUEST) {
      if (this.config.authMethod !== 'password' || this.passwordAuthMethod !== 'keyboard-interactive' || !this.authRequestSent) {
        throw new Error('Unexpected SSH keyboard-interactive challenge');
      }
      this.keyboardInteractiveRounds++;
      if (this.keyboardInteractiveRounds > 16) throw new Error('Too many SSH keyboard-interactive challenge rounds');
      const challenge = SSHAuth.parseKeyboardInteractiveChallenge(payload);
      let responses: string[];
      if (challenge.prompts.length === 0) {
        responses = [];
      } else {
        if (this.keyboardInteractivePasswordSent || this.config.password === undefined) {
          throw new Error('SSH keyboard-interactive requested credentials more than once');
        }
        responses = SSHAuth.passwordResponsesForChallenge(challenge, this.config.password, {
          username: this.config.username,
          host: this.config.host,
        });
      }
      const response = SSHAuth.buildKeyboardInteractiveResponse(responses);
      if (responses.length > 0) {
        this.keyboardInteractivePasswordSent = true;
        this.config.password = undefined;
      }
      await this.sendEncrypted(response);
      return;
    }
    if (type === SSH_MSG_USERAUTH_SUCCESS) {
      if (payload.length !== 1) throw new Error('Malformed SSH authentication success');
      if (!this.authRequestSent) throw new Error('SSH authentication completed before credentials were sent');
      this.config.password = undefined;
      this.config.privateKey = undefined;
      this.status('auth_success', 'SSH authentication succeeded; opening terminal');
      this.phase = 'pty';
      this.startKeepalive();
      await this.sendEncrypted(this.shellChannel.buildOpenSession(0));
      return;
    }
    if (type === SSH_MSG_USERAUTH_FAILURE) {
      if (!this.authRequestSent) throw new Error('SSH authentication failed before credentials were sent');
      const methods = this.validateAuthFailure(payload);
      if (this.config.authMethod === 'password'
        && this.passwordAuthMethod === 'password'
        && this.config.password !== undefined
        && methods.includes('keyboard-interactive')) {
        this.passwordAuthMethod = 'keyboard-interactive';
        await this.sendEncrypted(SSHAuth.buildKeyboardInteractiveAuthRequest(this.config.username));
        return;
      }
      this.config.password = undefined;
      throw new Error('SSH authentication failed');
    }
  }

  private async handleChannel(type: number, payload: Uint8Array): Promise<void> {
    if (payload.length < 5) throw new Error('Malformed SSH channel message');
    const channelID = readUint32(payload, 1);
    const channel = this.channels.get(channelID);
    if (!channel) throw new Error('SSH channel message has an unknown recipient');
    const isShell = channel === this.shellChannel;
    if (type === SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
      channel.handleOpenConfirmation(payload);
      if (isShell) {
        if (this.phase !== 'pty') throw new Error('Unexpected shell channel open confirmation');
        this.pendingChannelRequest = 'pty';
        await this.sendEncrypted(channel.buildPTYRequest(this.config.cols, this.config.rows, this.config.term));
      } else if (channel === this.sftpChannel && this.sftpHandler && !this.pendingSFTPChannelOpen?.cancelled) {
        try {
          await this.sendEncrypted(channel.buildSubsystemRequest('sftp'));
        } catch (error) {
          this.clearPendingSFTPChannelOpen(channel);
          this.sftpHandler.dispose();
          this.sftpHandler = null;
          this.sftpChannel = null;
          await this.sendSFTPChannelClose(channel);
          throw error;
        }
      } else if (channel === this.processChannel && this.processWebSocket && !this.pendingProcessChannelOpen?.cancelled) {
        try {
          await this.sendEncrypted(channel.buildExecRequest(PROCESS_MONITOR_COMMAND));
        } catch (error) {
          this.clearPendingProcessChannelOpen(channel);
          this.processChannel = null;
          await this.sendAuxiliaryChannelClose(channel);
          throw error;
        }
      } else {
        // An attachment WebSocket may close while its channel is opening.
        this.clearPendingSFTPChannelOpen(channel);
        this.clearPendingProcessChannelOpen(channel);
        await this.sendAuxiliaryChannelClose(channel);
      }
      return;
    }
    if (type === SSH_MSG_CHANNEL_OPEN_FAILURE) {
      channel.handleOpenFailure(payload);
      this.clearPendingSFTPChannelOpen(channel);
      this.clearPendingProcessChannelOpen(channel);
      this.channels.delete(channelID);
      if (isShell) throw new Error('SSH server rejected the session channel');
      if (channel === this.sftpChannel) {
        this.sftpHandler?.dispose();
        this.sftpHandler = null;
        this.sftpChannel = null;
        this.sendSFTPError('init', 'SSH server rejected the SFTP channel');
      } else if (channel === this.processChannel) {
        this.processChannel = null;
        this.sendProcessError('SSH server rejected the process-monitor channel');
      }
      return;
    }
    if (type === SSH_MSG_CHANNEL_SUCCESS || type === SSH_MSG_CHANNEL_FAILURE) {
      channel.handleRequestResult(payload);
      this.clearPendingSFTPChannelOpen(channel);
      if (isShell) {
        const pending = this.pendingChannelRequest;
        if (!pending || pending !== this.phase) throw new Error('Unexpected SSH channel request result');
        this.pendingChannelRequest = null;
        if (type === SSH_MSG_CHANNEL_FAILURE) throw new Error(`SSH server rejected the ${pending === 'pty' ? 'PTY' : 'shell'} request`);
        if (pending === 'pty') {
          this.phase = 'shell';
          this.pendingChannelRequest = 'shell';
          await this.sendEncrypted(channel.buildShellRequest());
          this.shellTimer = setTimeout(() => this.markReady(), 3000);
        } else this.markReady();
      } else if (channel === this.sftpChannel && type === SSH_MSG_CHANNEL_SUCCESS) {
        const handler = this.sftpHandler;
        if (handler) {
          void handler.initialize().then((ready) => {
            if (!ready && this.sftpHandler === handler) void this.closeSFTPChannel();
          });
        }
      } else if (channel === this.sftpChannel) {
        this.sftpHandler?.dispose();
        this.sftpHandler = null;
        this.sftpChannel = null;
        this.sendSFTPError('init', 'SSH server rejected the SFTP subsystem');
        await this.sendSFTPChannelClose(channel);
      } else if (channel === this.processChannel) {
        this.clearPendingProcessChannelOpen(channel);
        if (type === SSH_MSG_CHANNEL_FAILURE) {
          this.processChannel = null;
          this.sendProcessError('SSH server rejected the top command');
          await this.sendAuxiliaryChannelClose(channel);
        } else {
          this.sendProcessJson({ type: 'process_ready' });
        }
      }
      return;
    }
    if (type === SSH_MSG_CHANNEL_DATA) {
      const output = channel.handleChannelData(payload);
      if (isShell) {
        if (this.phase === 'shell') this.markReady();
        this.ws.send(output);
      } else if (channel === this.sftpChannel && this.sftpHandler) {
        try {
          this.sftpHandler.feed(output);
        } catch (error) {
          this.sendSFTPError('protocol', error instanceof Error ? error.message : String(error));
          await this.closeSFTPChannel();
        }
      } else if (channel === this.processChannel) {
        this.consumeProcessOutput(output);
      }
      await this.adjustLocalWindow(channel);
      return;
    }
    if (type === SSH_MSG_CHANNEL_EXTENDED_DATA) {
      const output = channel.handleExtendedData(payload);
      if (isShell) {
        if (this.phase === 'shell') this.markReady();
        this.ws.send(output);
      } else if (channel === this.sftpChannel) {
        this.sendSFTPError('protocol', new TextDecoder().decode(output) || 'SFTP channel reported an error');
      } else if (channel === this.processChannel) {
        const message = new TextDecoder().decode(output).trim();
        if (message) this.sendProcessError(message.slice(0, 512));
      }
      await this.adjustLocalWindow(channel);
      return;
    }
    if (type === SSH_MSG_CHANNEL_WINDOW_ADJUST) {
      channel.handleWindowAdjust(payload);
      if (isShell) void this.flushInput();
      else if (channel === this.sftpChannel) this.sftpHandler?.onWindowAdjust();
      return;
    }
    if (type === SSH_MSG_CHANNEL_EOF) {
      channel.handleEof(payload);
      if (isShell) this.status('remote_eof', 'SSH server finished sending output');
      else if (channel === this.sftpChannel) this.sftpHandler?.onClosed();
      else if (channel === this.processChannel) this.flushProcessBuffer();
      return;
    }
    if (type === SSH_MSG_CHANNEL_CLOSE) {
      channel.handleClose(payload);
      if (!channel.hasSentClose()) await this.sendEncrypted(channel.buildClose());
      if (isShell) {
        this.status('session_ended', 'SSH session ended');
        this.close(true);
      } else {
        this.clearPendingSFTPChannelOpen(channel);
        this.channels.delete(channelID);
        if (channel === this.sftpChannel) {
          this.sftpHandler?.onClosed();
          this.sftpHandler = null;
          this.sftpChannel = null;
        } else if (channel === this.processChannel) {
          this.clearPendingProcessChannelOpen(channel);
          this.flushProcessBuffer();
          this.processChannel = null;
          this.sendProcessError('The process monitor stopped');
        }
      }
      return;
    }
  }

  private markReady(): void {
    if (this.phase === 'ready' || this.phase === 'closed') return;
    if (this.shellTimer) clearTimeout(this.shellTimer);
    this.shellTimer = null;
    this.pendingChannelRequest = null;
    this.phase = 'ready';
    this.sendJson({
      type: 'ready',
      negotiated: { kex: this.kexName, cipherC2S: this.cipherC2S, cipherS2C: this.cipherS2C, macC2S: this.macC2S, macS2C: this.macS2C },
    });
    this.status('shell_ready', 'Shell is ready');
    if (this.sftpAttachUrl) this.sendJson({ type: 'sftp_attach', url: this.sftpAttachUrl });
    if (this.processAttachUrl) this.sendJson({ type: 'process_attach', url: this.processAttachUrl });
    void this.flushInput();
  }

  setSFTPAttachUrl(url: string): void {
    if (!/^\/api\/sftp\?/.test(url)) throw new Error('Invalid SFTP attach URL');
    this.sftpAttachUrl = url;
  }

  setProcessAttachUrl(url: string): void {
    if (!/^\/api\/processes\?/.test(url)) throw new Error('Invalid process attach URL');
    this.processAttachUrl = url;
  }

  attachProcessWebSocket(ws: WebSocket): void {
    if (this.phase === 'closed' || this.processWebSocket) {
      try { ws.close(1008, 'Process monitor is unavailable'); } catch { /* already closed */ }
      return;
    }
    this.processWebSocket = ws;
  }

  detachProcessWebSocket(ws: WebSocket): void {
    if (this.processWebSocket !== ws) return;
    this.processWebSocket = null;
    void this.closeProcessChannel();
  }

  async handleProcessClientMessage(message: string | ArrayBuffer): Promise<void> {
    if (this.phase === 'closed' || !this.processWebSocket) return;
    if (message instanceof ArrayBuffer || message.length > 4096) throw new Error('Invalid process-monitor message');
    let decoded: unknown;
    try { decoded = JSON.parse(message); } catch { throw new Error('Invalid process-monitor JSON'); }
    if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) throw new Error('Invalid process-monitor message');
    const value = decoded as Record<string, unknown>;
    if (value.type === 'ping') { this.sendProcessJson({ type: 'pong' }); return; }
    if (value.type === 'process_start') { await this.openProcessChannel(); return; }
    if (value.type === 'process_stop') { await this.closeProcessChannel(); return; }
    throw new Error('Unsupported process-monitor message');
  }

  private async openProcessChannel(): Promise<void> {
    if (!this.processWebSocket) throw new Error('Process-monitor WebSocket is not attached');
    if (this.phase !== 'ready') throw new Error('SSH connection is not ready');
    if (this.pendingProcessChannelOpen?.cancelled) throw new Error('The previous process channel is still closing');
    if (this.processChannel) {
      this.sendProcessJson({ type: 'process_ready' });
      return;
    }
    const channelID = this.nextChannelID++;
    const channel = new SSHChannel();
    const pending: PendingProcessChannelOpen = { channelID, channel, timeout: null, cancelled: false };
    this.channels.set(channelID, channel);
    this.processChannel = channel;
    this.processBuffer = '';
    this.processDecoder = new TextDecoder();
    this.pendingProcessChannelOpen = pending;
    try {
      await this.sendEncrypted(channel.buildOpenSession(channelID));
      if (this.pendingProcessChannelOpen === pending) {
        pending.timeout = setTimeout(() => this.expirePendingProcessChannelOpen(pending), PROCESS_CHANNEL_OPEN_TIMEOUT_MS);
      }
    } catch (error) {
      this.clearPendingProcessChannelOpen(channel);
      this.channels.delete(channelID);
      this.processChannel = null;
      throw error;
    }
  }

  private async closeProcessChannel(): Promise<void> {
    const channel = this.processChannel;
    const pending = this.pendingProcessChannelOpen;
    if (pending?.channel === channel) pending.cancelled = true;
    this.processChannel = null;
    this.processBuffer = '';
    if (!channel?.isOpen()) return;
    await this.sendAuxiliaryChannelClose(channel);
  }

  private consumeProcessOutput(data: Uint8Array): void {
    this.processBuffer += this.processDecoder.decode(data, { stream: true });
    if (this.processBuffer.length > PROCESS_MAX_BUFFER_BYTES) {
      const marker = this.processBuffer.lastIndexOf(PROCESS_SNAPSHOT_MARKER);
      this.processBuffer = marker >= 0
        ? this.processBuffer.slice(marker)
        : retainTrailingMarkerPrefix(this.processBuffer, PROCESS_SNAPSHOT_MARKER);
      this.sendProcessError('Process snapshot exceeded the buffer limit');
      return;
    }
    while (true) {
      const first = this.processBuffer.indexOf(PROCESS_SNAPSHOT_MARKER);
      if (first < 0) {
        this.processBuffer = retainTrailingMarkerPrefix(this.processBuffer, PROCESS_SNAPSHOT_MARKER);
        return;
      }
      if (first > 0) this.processBuffer = this.processBuffer.slice(first);
      const next = this.processBuffer.indexOf(PROCESS_SNAPSHOT_MARKER, PROCESS_SNAPSHOT_MARKER.length);
      if (next < 0) return;
      this.emitProcessSnapshot(this.processBuffer.slice(PROCESS_SNAPSHOT_MARKER.length, next));
      this.processBuffer = this.processBuffer.slice(next);
    }
  }

  private flushProcessBuffer(): void {
    this.processBuffer += this.processDecoder.decode();
    const marker = this.processBuffer.lastIndexOf(PROCESS_SNAPSHOT_MARKER);
    if (marker >= 0) this.emitProcessSnapshot(this.processBuffer.slice(marker + PROCESS_SNAPSHOT_MARKER.length));
    this.processBuffer = '';
    this.processDecoder = new TextDecoder();
  }

  private emitProcessSnapshot(raw: string): void {
    const snapshot = parseTopSnapshot(raw);
    if (snapshot) this.sendProcessJson({ type: 'process_snapshot', ...snapshot });
  }

  private expirePendingProcessChannelOpen(expected: PendingProcessChannelOpen): void {
    if (this.pendingProcessChannelOpen !== expected) return;
    this.pendingProcessChannelOpen = null;
    expected.timeout = null;
    expected.cancelled = true;
    if (this.processChannel === expected.channel) this.processChannel = null;
    this.sendProcessError('Timed out opening the process-monitor channel');
    if (expected.channel.isOpen()) void this.sendAuxiliaryChannelClose(expected.channel);
    try { this.processWebSocket?.close(1011, 'Process channel setup timed out'); } catch { /* already closed */ }
  }

  private clearPendingProcessChannelOpen(channel?: SSHChannel): void {
    const pending = this.pendingProcessChannelOpen;
    if (!pending || (channel && pending.channel !== channel)) return;
    if (pending.timeout) clearTimeout(pending.timeout);
    pending.timeout = null;
    this.pendingProcessChannelOpen = null;
  }

  private sendProcessJson(value: unknown): void {
    if (this.processWebSocket?.readyState === WebSocket.OPEN) this.processWebSocket.send(JSON.stringify(value));
  }

  private sendProcessError(message: string): void {
    this.sendProcessJson({ type: 'process_error', message });
  }

  attachSFTPWebSocket(ws: WebSocket): void {
    if (this.phase === 'closed' || this.sftpWebSocket) {
      try { ws.close(1008, 'SFTP connection is unavailable'); } catch { /* already closed */ }
      return;
    }
    this.sftpWebSocket = ws;
  }

  detachSFTPWebSocket(ws: WebSocket): void {
    if (this.sftpWebSocket !== ws) return;
    this.sftpWebSocket = null;
    void this.closeSFTPChannel();
  }

  async handleSFTPClientMessage(message: string | ArrayBuffer): Promise<void> {
    if (this.phase === 'closed' || !this.sftpWebSocket) return;
    if (message instanceof ArrayBuffer) {
      if (message.byteLength === 0 || message.byteLength > 64 * 1024) {
        this.sendSFTPError('upload', 'Invalid upload chunk');
        return;
      }
      if (this.sftpQueuedUploadBytes + message.byteLength > MAX_QUEUED_SFTP_UPLOAD) {
        this.sendSFTPError('upload', 'Upload queue limit exceeded');
        return;
      }
      const chunk = new Uint8Array(message);
      this.sftpQueuedUploadBytes += chunk.byteLength;
      await this.queueSFTPTask('upload', undefined, async () => {
        try {
          if (!this.sftpHandler) throw new Error('SFTP is not initialized');
          await this.sftpHandler.uploadChunk(chunk);
        } finally {
          this.sftpQueuedUploadBytes = Math.max(0, this.sftpQueuedUploadBytes - chunk.byteLength);
        }
      });
      return;
    }
    if (message.length > 16 * 1024) {
      this.sendSFTPError('protocol', 'SFTP control message is too large');
      return;
    }
    let value: Record<string, unknown>;
    try {
      const parsed = JSON.parse(message) as unknown;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
      value = parsed as Record<string, unknown>;
    } catch {
      this.sendSFTPError('protocol', 'Invalid SFTP control message');
      return;
    }
    if (value.type === 'ping') { this.sendSFTPJson({ type: 'pong' }); return; }
    if (value.type === 'sftp_download_cancel') {
      try {
        const requestId = this.requestId(value.requestId);
        if (!this.sftpHandler) throw new Error('SFTP is not initialized');
        this.sftpHandler.cancelDownload(requestId);
      } catch (error) {
        this.sendSFTPError('download', error instanceof Error ? error.message : String(error));
      }
      return;
    }
    const operation = typeof value.type === 'string' ? value.type.replace(/^sftp_/, '') : 'protocol';
    await this.queueSFTPTask(operation, this.requestId(value.requestId, false), () => this.handleSFTPControl(value));
  }

  private async handleSFTPControl(value: Record<string, unknown>): Promise<void> {
    const type = typeof value.type === 'string' ? value.type : '';
    if (type === 'sftp_close') { await this.closeSFTPChannel(); return; }
    if (this.phase !== 'ready') throw new Error('SSH connection is not ready');
    if (type === 'sftp_init') {
      await this.openSFTPChannel();
      return;
    }
    if (!this.sftpHandler) throw new Error('SFTP is not initialized');
    const requestId = this.requestId(value.requestId);
    if (type === 'sftp_list') return this.sftpHandler.list(requestId, this.path(value.path));
    if (type === 'sftp_download') return this.sftpHandler.download(requestId, this.path(value.path));
    if (type === 'sftp_upload_start') {
      if (typeof value.size !== 'number') throw new Error('Invalid upload size');
      if (typeof value.overwrite !== 'boolean') throw new Error('Invalid upload overwrite option');
      return this.sftpHandler.startUpload(requestId, this.path(value.path), value.size, value.overwrite);
    }
    if (type === 'sftp_upload_end') return this.sftpHandler.finishUpload(requestId);
    if (type === 'sftp_upload_cancel') return this.sftpHandler.cancelUpload(requestId);
    if (type === 'sftp_delete') return this.sftpHandler.remove(requestId, this.path(value.path), false);
    if (type === 'sftp_rmdir') return this.sftpHandler.remove(requestId, this.path(value.path), true);
    if (type === 'sftp_mkdir') return this.sftpHandler.mkdir(requestId, this.path(value.path));
    if (type === 'sftp_rename') return this.sftpHandler.rename(requestId, this.path(value.oldPath), this.path(value.newPath));
    throw new Error('Unsupported SFTP control message');
  }

  private async openSFTPChannel(): Promise<void> {
    if (!this.sftpWebSocket) throw new Error('SFTP WebSocket is not attached');
    if (this.pendingSFTPChannelOpen?.cancelled) throw new Error('The previous SFTP channel is still closing');
    if (this.sftpHandler) {
      if (this.sftpHandler.isReady()) this.sftpHandler.announceReady();
      else this.sendSFTPError('init', 'SFTP initialization is already in progress');
      return;
    }
    const channelID = this.nextChannelID++;
    const channel = new SSHChannel();
    this.channels.set(channelID, channel);
    this.sftpChannel = channel;
    this.sftpHandler = new SFTPHandler(
      channel,
      (target, chunk) => this.sendChannelData(target, chunk),
      (message) => this.sendSFTPJson(message),
      (data) => this.sendSFTPBinary(data),
    );
    const pending: PendingSFTPChannelOpen = {
      channelID,
      channel,
      cancelled: false,
      timeout: null,
    };
    this.pendingSFTPChannelOpen = pending;
    try {
      await this.sendEncrypted(channel.buildOpenSession(channelID));
      if (this.pendingSFTPChannelOpen === pending) {
        pending.timeout = setTimeout(() => this.expirePendingSFTPChannelOpen(pending), SFTP_CHANNEL_OPEN_TIMEOUT_MS);
      }
    } catch (error) {
      this.clearPendingSFTPChannelOpen(channel);
      this.channels.delete(channelID);
      this.sftpHandler.dispose();
      this.sftpHandler = null;
      this.sftpChannel = null;
      throw error;
    }
  }

  private async closeSFTPChannel(): Promise<void> {
    const handler = this.sftpHandler;
    if (!handler) return;
    const channel = this.sftpChannel;
    const pending = this.pendingSFTPChannelOpen;
    if (pending?.channel === channel) pending.cancelled = true;
    this.sftpHandler = null;
    this.sftpChannel = null;
    handler.dispose();
    if (!channel) return;
    if (!channel.isOpen()) return;
    await this.sendSFTPChannelClose(channel);
  }

  private async queueSFTPTask(operation: string, requestId: string | undefined, task: () => Promise<void>): Promise<void> {
    const run = this.sftpTaskChain.then(task);
    const handled = run.catch((error) => {
      this.sendSFTPError(operation, error instanceof Error ? error.message : String(error), requestId);
    });
    this.sftpTaskChain = handled;
    await handled;
  }

  private expirePendingSFTPChannelOpen(expected: PendingSFTPChannelOpen): void {
    if (this.pendingSFTPChannelOpen !== expected) return;
    this.pendingSFTPChannelOpen = null;
    expected.timeout = null;
    expected.cancelled = true;
    if (this.sftpChannel === expected.channel) {
      this.sftpHandler?.dispose();
      this.sftpHandler = null;
      this.sftpChannel = null;
    }
    this.sendSFTPError('init', 'Timed out opening the SFTP channel');
    if (expected.channel.isOpen()) void this.sendSFTPChannelClose(expected.channel);
    try { this.sftpWebSocket?.close(1011, 'SFTP channel setup timed out'); } catch { /* already closed */ }
  }

  private async sendSFTPChannelClose(channel: SSHChannel): Promise<void> {
    await this.sendAuxiliaryChannelClose(channel);
  }

  private async sendAuxiliaryChannelClose(channel: SSHChannel): Promise<void> {
    if (!channel.isOpen() || channel.hasSentClose()) return;
    try {
      await this.sendEncrypted(channel.buildEof());
      await this.sendEncrypted(channel.buildClose());
    } catch { /* The SSH session may already be closing. */ }
  }

  private clearPendingSFTPChannelOpen(channel?: SSHChannel): void {
    const pending = this.pendingSFTPChannelOpen;
    if (!pending || (channel && pending.channel !== channel)) return;
    if (pending.timeout) clearTimeout(pending.timeout);
    pending.timeout = null;
    this.pendingSFTPChannelOpen = null;
  }

  private requestId(value: unknown): string;
  private requestId(value: unknown, required: true): string;
  private requestId(value: unknown, required: false): string | undefined;
  private requestId(value: unknown, required = true): string | undefined {
    if (typeof value === 'string' && /^[A-Za-z0-9._:-]{1,64}$/.test(value)) return value;
    if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return String(value);
    if (!required) return undefined;
    throw new Error('Invalid SFTP request identifier');
  }

  private path(value: unknown): string {
    if (typeof value !== 'string') throw new Error('Invalid remote path');
    return value;
  }

  private sendSFTPJson(value: unknown): void {
    if (this.sftpWebSocket?.readyState === WebSocket.OPEN) this.sftpWebSocket.send(JSON.stringify(value));
  }

  private sendSFTPBinary(data: Uint8Array): void {
    if (this.sftpWebSocket?.readyState === WebSocket.OPEN) this.sftpWebSocket.send(data);
  }

  private sendSFTPError(operation: string, message: string, requestId?: string): void {
    this.sendSFTPJson({ type: 'sftp_error', operation, message, requestId });
  }

  private queueInput(data: Uint8Array): void {
    if (data.length === 0) return;
    if (this.phase !== 'ready') throw new Error('Terminal is not ready');
    if (this.queuedBytes + data.length > MAX_QUEUED_INPUT) throw new Error('Terminal input queue limit exceeded');
    this.inputQueue.push(data);
    this.queuedBytes += data.length;
    void this.flushInput();
  }

  private async flushInput(): Promise<void> {
    if (this.flushingInput || this.phase !== 'ready') return;
    this.flushingInput = true;
    try {
      while (this.inputQueue.length > 0 && this.phase === 'ready') {
        const first = this.inputQueue[0];
        const chunk = this.shellChannel.takeChannelDataChunk(first, this.queueHeadOffset);
        if (!chunk) return;
        await this.sendChannelData(this.shellChannel, chunk);
        this.queueHeadOffset += chunk.bytesConsumed;
        this.queuedBytes -= chunk.bytesConsumed;
        if (this.queueHeadOffset === first.length) {
          this.inputQueue.shift();
          this.queueHeadOffset = 0;
        }
      }
    } finally {
      this.flushingInput = false;
    }
  }

  private async resize(cols: unknown, rows: unknown): Promise<void> {
    if (typeof cols !== 'number' || typeof rows !== 'number' || !Number.isInteger(cols) || !Number.isInteger(rows) || cols < 10 || cols > 1000 || rows < 5 || rows > 1000) throw new Error('Invalid terminal size');
    if (this.phase === 'ready') await this.sendEncrypted(this.shellChannel.buildWindowChange(cols, rows));
  }

  private async adjustLocalWindow(channel: SSHChannel): Promise<void> {
    const amount = channel.takeLocalWindowAdjustment(LOCAL_WINDOW_THRESHOLD);
    if (amount !== null) await this.sendEncrypted(channel.buildWindowAdjust(amount));
  }

  private async handleGlobalRequest(payload: Uint8Array): Promise<void> {
    if (payload.length < 6) throw new Error('Malformed global request');
    const nameLength = readUint32(payload, 1);
    if (5 + nameLength >= payload.length) throw new Error('Malformed global request');
    try { new TextDecoder('utf-8', { fatal: true }).decode(payload.subarray(5, 5 + nameLength)); }
    catch { throw new Error('Malformed global request name'); }
    if (payload[5 + nameLength] > 1) throw new Error('Malformed global request reply flag');
    const wantsReply = payload[5 + nameLength] === 1;
    if (wantsReply && this.encryptor) await this.sendEncrypted(new Uint8Array([SSH_MSG_REQUEST_FAILURE]));
  }

  private startKeepalive(): void {
    this.keepaliveTimer = setInterval(() => {
      if (this.phase === 'closed') return;
      if (this.keepalivePending >= 3) {
        this.fail(new Error('SSH keepalive timed out'), 'keepalive_timeout');
        return;
      }
      this.keepalivePending++;
      const payload = new Uint8Array(1 + 4 + KEEPALIVE_NAME.length + 1);
      payload[0] = SSH_MSG_GLOBAL_REQUEST;
      new DataView(payload.buffer).setUint32(1, KEEPALIVE_NAME.length, false);
      payload.set(KEEPALIVE_NAME, 5);
      payload[payload.length - 1] = 1;
      void this.sendEncrypted(payload).catch((error) => this.fail(error, 'keepalive_failed'));
    }, 25_000);
  }

  private async sendPlain(payload: Uint8Array): Promise<void> {
    await this.serialSend(async () => {
      const packet = await SSHPacketBuilder.build(payload, 8, null, this.sendSequence);
      this.sendSequence = nextSequenceNumber(this.sendSequence);
      await this.write(packet);
    });
  }

  private async sendEncrypted(payload: Uint8Array): Promise<void> {
    await this.serialSend(async () => {
      if (!this.encryptor) throw new Error('SSH encryption is not initialized');
      const spec = getCipherSpec(this.cipherC2S);
      const packet = await SSHPacketBuilder.build(payload, spec.blockSize, (data, sequence, aad) => this.encryptor!.encrypt(data, sequence, aad), this.sendSequence, spec.aead, this.signer ? (data, sequence) => this.signer!.sign(data, sequence) : undefined);
      this.sendSequence = nextSequenceNumber(this.sendSequence);
      await this.write(packet);
    });
  }

  private async sendChannelData(channel: SSHChannel, chunk: ChannelDataChunk): Promise<void> {
    await this.serialSend(async () => {
      if (!this.encryptor) throw new Error('SSH encryption is not initialized');
      const spec = getCipherSpec(this.cipherC2S);
      const packet = await SSHPacketBuilder.buildWithPayloadWriter(chunk.payloadLength, (target, offset) => channel.writeChannelDataPayload(target, offset, chunk.source, chunk.sourceOffset, chunk.bytesConsumed), spec.blockSize, (data, sequence, aad) => this.encryptor!.encrypt(data, sequence, aad), this.sendSequence, spec.aead, this.signer ? (data, sequence) => this.signer!.sign(data, sequence) : undefined);
      this.sendSequence = nextSequenceNumber(this.sendSequence);
      await this.write(packet);
    });
  }

  private async serialSend(operation: () => Promise<void>): Promise<void> {
    const next = this.sendChain.then(operation);
    this.sendChain = next.catch(() => undefined);
    await next;
  }

  private async write(data: Uint8Array): Promise<void> {
    const writer = this.writer ?? this.socket.writable.getWriter();
    this.writer = writer;
    await writer.write(data);
  }

  private readBytes(bytes: Uint8Array, offset: number): { value: Uint8Array; next: number } {
    if (offset + 4 > bytes.length) throw new Error('Malformed SSH key data');
    const length = readUint32(bytes, offset);
    if (length > bytes.length - offset - 4) throw new Error('Malformed SSH key data');
    return { value: bytes.subarray(offset + 4, offset + 4 + length), next: offset + 4 + length };
  }

  private readString(bytes: Uint8Array, offset: number): { value: string; next: number } {
    const field = this.readBytes(bytes, offset);
    try {
      return { value: new TextDecoder('utf-8', { fatal: true }).decode(field.value), next: field.next };
    } catch {
      throw new Error('Malformed SSH text field');
    }
  }

  private sshEcdsaToRaw(signature: Uint8Array, coordinateBytes: number): Uint8Array {
    const rField = this.readBytes(signature, 0);
    const sField = this.readBytes(signature, rField.next);
    if (sField.next !== signature.length) throw new Error('Malformed ECDSA signature trailing data');
    const trim = (value: Uint8Array): Uint8Array => {
      if (value.length === 0 || (value[0] & 0x80) !== 0) throw new Error('ECDSA signature integers must be positive');
      if (value.length > 1 && value[0] === 0 && (value[1] & 0x80) === 0) throw new Error('ECDSA signature integer is not minimally encoded');
      const normalized = value.length > 1 && value[0] === 0 ? value.subarray(1) : value;
      if (normalized.every((byte) => byte === 0)) throw new Error('ECDSA signature integers must be non-zero');
      return normalized;
    };
    const r = trim(rField.value); const s = trim(sField.value);
    if (r.length > coordinateBytes || s.length > coordinateBytes) throw new Error('Invalid ECDSA signature');
    const result = new Uint8Array(coordinateBytes * 2);
    result.set(r, coordinateBytes - r.length);
    result.set(s, coordinateBytes * 2 - s.length);
    return result;
  }

  private base64(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/=+$/, '');
  }

  private base64UrlUnsigned(bytes: Uint8Array): string {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    return this.base64(bytes.subarray(start)).replace(/\+/g, '-').replace(/\//g, '_');
  }

  private validateDisconnect(payload: Uint8Array): void {
    if (payload.length < 13) throw new Error('Malformed SSH disconnect message');
    let offset = 5;
    offset = this.readBytes(payload, offset).next;
    offset = this.readBytes(payload, offset).next;
    if (offset !== payload.length) throw new Error('Malformed SSH disconnect message');
  }

  private validateDebug(payload: Uint8Array): void {
    if (payload.length < 10 || payload[1] > 1) throw new Error('Malformed SSH debug message');
    let offset = 2;
    offset = this.readBytes(payload, offset).next;
    offset = this.readBytes(payload, offset).next;
    if (offset !== payload.length) throw new Error('Malformed SSH debug message');
  }

  private validateAuthFailure(payload: Uint8Array): string[] {
    if (payload.length < 6) throw new Error('Malformed SSH authentication failure');
    const methodsLength = readUint32(payload, 1);
    if (methodsLength > payload.length - 6 || methodsLength + 6 !== payload.length) {
      throw new Error('Malformed SSH authentication failure');
    }
    const partialSuccess = payload[payload.length - 1];
    if (partialSuccess > 1) throw new Error('Malformed SSH authentication partial-success flag');
    if (partialSuccess === 1) throw new Error('Multi-factor SSH authentication is not supported');
    let methods: string;
    try { methods = new TextDecoder('utf-8', { fatal: true }).decode(payload.subarray(5, 5 + methodsLength)); }
    catch { throw new Error('Malformed SSH authentication methods'); }
    if (methods && methods.split(',').some((method) => method.length === 0 || !/^[A-Za-z0-9@._+-]+$/.test(method))) {
      throw new Error('Malformed SSH authentication methods');
    }
    return methods ? methods.split(',') : [];
  }

  private isHostKeyAlgorithmCompatible(negotiated: string | null, keyType: string): boolean {
    if (!negotiated) return false;
    if (negotiated === keyType) return true;
    return keyType === 'ssh-rsa' && (negotiated === 'rsa-sha2-256' || negotiated === 'rsa-sha2-512');
  }

  private status(event: string, message: string): void { this.sendJson({ type: 'status', event, message }); }
  private sendJson(value: unknown): void { if (this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(value)); }
  private fail(error: unknown, event: string): void {
    const message = error instanceof Error ? error.message : String(error);
    this.sendJson({ type: 'error', event, message });
    this.close();
  }
}
