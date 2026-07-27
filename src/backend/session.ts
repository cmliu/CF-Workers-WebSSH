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
import { encodeString, readUint32, toBufferSource } from '../ssh/utils';

type Cipher = SSHAESGCMCipher | SSHAESCTRCipher;
type Phase = 'version' | 'kex' | 'host-confirm' | 'auth' | 'pty' | 'shell' | 'ready' | 'closed';
const LOCAL_WINDOW_THRESHOLD = 512 * 1024;
const MAX_VERSION_BYTES = 8192;
const MAX_QUEUED_INPUT = 1024 * 1024;
const KEEPALIVE_NAME = new TextEncoder().encode('keepalive@openssh.com');

export class SSHSession {
  private readonly encoder = new TextEncoder();
  private readonly decoder = new TextDecoder();
  private readonly transport = new SSHTransport();
  private readonly parser = new SSHPacketParser();
  private readonly channel = new SSHChannel();
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
  private pendingChannelRequest: 'pty' | 'shell' | null = null;
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
    this.pendingHostConfirmation?.resolve(false);
    this.pendingHostConfirmation = null;
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
    if (this.config.expectedFingerprint && this.config.expectedFingerprint !== fingerprint) throw new Error(`Host key mismatch: expected ${this.config.expectedFingerprint}, received ${fingerprint}`);
    if (!await this.verifyHostSignature(hostKey, signature, hash)) throw new Error('SSH host key signature verification failed');
    if (this.config.expectedFingerprint) {
      this.sendJson({ type: 'host_key', fingerprint, keyType, trusted: true });
    } else if (!await this.confirmHostKey(fingerprint, keyType)) {
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

  private async confirmHostKey(fingerprint: string, keyType: string): Promise<boolean> {
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
      this.sendJson({ type: 'host_key', fingerprint, keyType, trusted: false });
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
      this.config.password = undefined;
      this.config.privateKey = undefined;
      await this.sendEncrypted(request);
      return;
    }
    if (type === SSH_MSG_USERAUTH_SUCCESS) {
      if (payload.length !== 1) throw new Error('Malformed SSH authentication success');
      if (!this.authRequestSent) throw new Error('SSH authentication completed before credentials were sent');
      this.status('auth_success', 'SSH authentication succeeded; opening terminal');
      this.phase = 'pty';
      this.startKeepalive();
      await this.sendEncrypted(this.channel.buildOpenSession(0));
      return;
    }
    if (type === SSH_MSG_USERAUTH_FAILURE) {
      if (!this.authRequestSent) throw new Error('SSH authentication failed before credentials were sent');
      this.validateAuthFailure(payload);
      throw new Error('SSH authentication failed');
    }
  }

  private async handleChannel(type: number, payload: Uint8Array): Promise<void> {
    if (type === SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
      if (this.phase !== 'pty') throw new Error('Unexpected channel open confirmation');
      this.channel.handleOpenConfirmation(payload);
      this.pendingChannelRequest = 'pty';
      await this.sendEncrypted(this.channel.buildPTYRequest(this.config.cols, this.config.rows, this.config.term));
      return;
    }
    if (type === SSH_MSG_CHANNEL_OPEN_FAILURE) {
      this.channel.handleOpenFailure(payload);
      throw new Error('SSH server rejected the session channel');
    }
    if (type === SSH_MSG_CHANNEL_SUCCESS || type === SSH_MSG_CHANNEL_FAILURE) {
      this.channel.handleRequestResult(payload);
      const pending = this.pendingChannelRequest;
      if (!pending || pending !== this.phase) throw new Error('Unexpected SSH channel request result');
      this.pendingChannelRequest = null;
      if (type === SSH_MSG_CHANNEL_FAILURE) throw new Error(`SSH server rejected the ${pending === 'pty' ? 'PTY' : 'shell'} request`);
      if (pending === 'pty') {
        this.phase = 'shell';
        this.pendingChannelRequest = 'shell';
        await this.sendEncrypted(this.channel.buildShellRequest());
        this.shellTimer = setTimeout(() => this.markReady(), 3000);
      } else this.markReady();
      return;
    }
    if (type === SSH_MSG_CHANNEL_DATA) {
      if (this.phase === 'shell') this.markReady();
      const output = this.channel.handleChannelData(payload);
      this.ws.send(output);
      await this.adjustLocalWindow();
      return;
    }
    if (type === SSH_MSG_CHANNEL_EXTENDED_DATA) {
      if (this.phase === 'shell') this.markReady();
      const output = this.channel.handleExtendedData(payload);
      this.ws.send(output);
      await this.adjustLocalWindow();
      return;
    }
    if (type === SSH_MSG_CHANNEL_WINDOW_ADJUST) {
      this.channel.handleWindowAdjust(payload);
      void this.flushInput();
      return;
    }
    if (type === SSH_MSG_CHANNEL_EOF) {
      this.channel.handleEof(payload);
      this.status('remote_eof', 'SSH server finished sending output');
      return;
    }
    if (type === SSH_MSG_CHANNEL_CLOSE) {
      this.channel.handleClose(payload);
      if (!this.channel.hasSentClose()) await this.sendEncrypted(this.channel.buildClose());
      this.status('session_ended', 'SSH session ended');
      this.close(true);
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
    void this.flushInput();
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
        const chunk = this.channel.takeChannelDataChunk(first, this.queueHeadOffset);
        if (!chunk) return;
        await this.sendChannelData(chunk);
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
    if (this.phase === 'ready') await this.sendEncrypted(this.channel.buildWindowChange(cols, rows));
  }

  private async adjustLocalWindow(): Promise<void> {
    const amount = this.channel.takeLocalWindowAdjustment(LOCAL_WINDOW_THRESHOLD);
    if (amount !== null) await this.sendEncrypted(this.channel.buildWindowAdjust(amount));
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

  private async sendChannelData(chunk: ChannelDataChunk): Promise<void> {
    await this.serialSend(async () => {
      if (!this.encryptor) throw new Error('SSH encryption is not initialized');
      const spec = getCipherSpec(this.cipherC2S);
      const packet = await SSHPacketBuilder.buildWithPayloadWriter(chunk.payloadLength, (target, offset) => this.channel.writeChannelDataPayload(target, offset, chunk.source, chunk.sourceOffset, chunk.bytesConsumed), spec.blockSize, (data, sequence, aad) => this.encryptor!.encrypt(data, sequence, aad), this.sendSequence, spec.aead, this.signer ? (data, sequence) => this.signer!.sign(data, sequence) : undefined);
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
    return { value: this.decoder.decode(field.value), next: field.next };
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

  private validateAuthFailure(payload: Uint8Array): void {
    if (payload.length < 6) throw new Error('Malformed SSH authentication failure');
    const methodsLength = readUint32(payload, 1);
    if (methodsLength > payload.length - 6 || methodsLength + 6 !== payload.length) {
      throw new Error('Malformed SSH authentication failure');
    }
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
