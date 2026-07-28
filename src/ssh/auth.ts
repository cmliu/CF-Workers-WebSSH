import { SSH_MSG_USERAUTH_REQUEST } from '../types';
import { encodeString, concat, readUint32, toBufferSource } from './utils';
import {
  buildKeyboardInteractiveAuthRequest,
  buildKeyboardInteractiveResponse,
  buildPasswordAuthRequest,
  isSupportedPasswordPrompt,
  parseKeyboardInteractiveChallenge,
  passwordResponsesForChallenge,
  type KeyboardInteractiveChallenge,
  type PasswordPromptIdentity,
} from './auth-password';

// SSH key type constants
const SSH_ED25519 = 'ssh-ed25519';
const SSH_RSA = 'ssh-rsa';
const ECDSA_SHA2_NISTP256 = 'ecdsa-sha2-nistp256';
const ECDSA_SHA2_NISTP384 = 'ecdsa-sha2-nistp384';
const ECDSA_SHA2_NISTP521 = 'ecdsa-sha2-nistp521';

// Web Crypto algorithm names
const ED25519_ALGO = 'Ed25519';
const RSA_ALGO = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
const ECDSA_P256_ALGO = { name: 'ECDSA', namedCurve: 'P-256' };
const ECDSA_P384_ALGO = { name: 'ECDSA', namedCurve: 'P-384' };
const ECDSA_P521_ALGO = { name: 'ECDSA', namedCurve: 'P-521' };

interface ParsedKey {
  signingKey: CryptoKey;
  rsaPkcs8?: Uint8Array;
  publicKeyBlob: Uint8Array;
  keyType: string;
}

export class SSHAuth {
  static buildPasswordAuthRequest(
    username: string,
    password: string
  ): Uint8Array {
    return buildPasswordAuthRequest(username, password);
  }

  static buildKeyboardInteractiveAuthRequest(username: string): Uint8Array {
    return buildKeyboardInteractiveAuthRequest(username);
  }

  static parseKeyboardInteractiveChallenge(payload: Uint8Array): KeyboardInteractiveChallenge {
    return parseKeyboardInteractiveChallenge(payload);
  }

  static passwordResponsesForChallenge(
    challenge: KeyboardInteractiveChallenge,
    password: string,
    identity: PasswordPromptIdentity,
  ): string[] {
    return passwordResponsesForChallenge(challenge, password, identity);
  }

  static buildKeyboardInteractiveResponse(responses: string[]): Uint8Array {
    return buildKeyboardInteractiveResponse(responses);
  }

  static isSupportedPasswordPrompt(challenge: KeyboardInteractiveChallenge, identity: PasswordPromptIdentity): boolean {
    return isSupportedPasswordPrompt(challenge, identity);
  }

  /** Build a signed public-key authentication request (RFC 4252 section 7). */
  static async buildPublicKeyAuthRequest(
    username: string,
    privateKeyPEM: string,
    sessionID: Uint8Array,
    serverSigAlgs?: string[],
  ): Promise<Uint8Array> {
    const { signingKey, publicKeyBlob, keyType, rsaPkcs8 } = await this.parsePrivateKey(privateKeyPEM);

    let requestAlgo = keyType;
    let signatureAlgo = keyType;

    if (keyType === SSH_RSA) {
      const chosen = this.selectRsaSigAlgorithm(serverSigAlgs);
      requestAlgo = chosen;
      signatureAlgo = chosen;
    }

    // Build the request body (without signature first)
    const requestBody = concat(
      new Uint8Array([SSH_MSG_USERAUTH_REQUEST]),
      encodeString(username),
      encodeString('ssh-connection'),
      encodeString('publickey'),
      new Uint8Array([0x01]), // TRUE = has signature
      encodeString(requestAlgo),
      encodeString(publicKeyBlob),
    );

    // Data to sign: session_id_string || request_body
    const dataToSign = concat(encodeString(sessionID), requestBody);

    // Sign based on key type
    let rawSignature: Uint8Array;
    let signatureBlob: Uint8Array;

    if (keyType === SSH_ED25519) {
      rawSignature = new Uint8Array(await crypto.subtle.sign(ED25519_ALGO, signingKey, toBufferSource(dataToSign)));
      signatureBlob = concat(
        encodeString(SSH_ED25519),
        encodeString(rawSignature),
      );
    } else if (keyType === SSH_RSA) {
      const hash = signatureAlgo === 'rsa-sha2-512' ? 'SHA-512' : 'SHA-256';
      let sigKey = signingKey;
      if (hash !== 'SHA-256' && rsaPkcs8) {
        sigKey = await crypto.subtle.importKey(
          'pkcs8', toBufferSource(rsaPkcs8),
          { name: 'RSASSA-PKCS1-v1_5', hash },
          false, ['sign'],
        );
      }
      rawSignature = new Uint8Array(
        await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5', hash }, sigKey, toBufferSource(dataToSign))
      );
      signatureBlob = concat(
        encodeString(signatureAlgo),
        encodeString(rawSignature),
      );
    } else if (keyType.startsWith('ecdsa-sha2-')) {
      const hash = this.ecdsaHashForCurve(keyType);
      const sigBytes = new Uint8Array(await crypto.subtle.sign(
        { name: 'ECDSA', hash },
        signingKey,
        toBufferSource(dataToSign)
      ));
      const sshSignature = this.ecdsaWebCryptoToSSH(sigBytes, this.ecdsaCoordBytes(keyType));
      signatureBlob = concat(
        encodeString(keyType),
        encodeString(sshSignature),
      );
    } else {
      throw new Error(`Unsupported key type: ${keyType}`);
    }

    // Full auth packet: requestBody || string signature_blob
    return concat(requestBody, encodeString(signatureBlob));
  }
  private static selectRsaSigAlgorithm(
    serverSigAlgs: string[] | undefined,
  ): string {
    const localOrder = ['rsa-sha2-512', 'rsa-sha2-256'];

    if (!serverSigAlgs || serverSigAlgs.length === 0) {
      return 'rsa-sha2-256';
    }

    const serverSet = new Set(serverSigAlgs);
    for (const algo of localOrder) {
      if (serverSet.has(algo)) return algo;
    }
    throw new Error(
      `no_supported_rsa_signature_algorithm: server=[${serverSigAlgs.join(',')}] local=[${localOrder.join(',')}]`
    );
  }
  private static ecdsaHashForCurve(keyType: string): 'SHA-256' | 'SHA-384' | 'SHA-512' {
    switch (keyType) {
      case ECDSA_SHA2_NISTP256: return 'SHA-256';
      case ECDSA_SHA2_NISTP384: return 'SHA-384';
      case ECDSA_SHA2_NISTP521: return 'SHA-512';
    }
    throw new Error(`unsupported ECDSA key type: ${keyType}`);
  }
  private static ecdsaCoordBytes(keyType: string): number {
    switch (keyType) {
      case ECDSA_SHA2_NISTP256: return 32;
      case ECDSA_SHA2_NISTP384: return 48;
      case ECDSA_SHA2_NISTP521: return 66;
    }
    throw new Error(`unsupported ECDSA key type: ${keyType}`);
  }
  private static ecdsaWebCryptoToSSH(sigBytes: Uint8Array, coordBytes: number): Uint8Array {
    if (sigBytes.length < 2) throw new Error('ECDSA signature is too short');

    // Workers Web Crypto returns IEEE-P1363 r || s. Check its exact size
    // before considering DER because a valid r can itself start with 0x30.
    if (sigBytes.length === coordBytes * 2) {
      const r = sigBytes.subarray(0, coordBytes);
      const s = sigBytes.subarray(coordBytes);
      return concat(this.sshMPInt(r), this.sshMPInt(s));
    }
    if (sigBytes[0] === 0x30) return this.convertECDSADERToSSH(sigBytes);
    throw new Error(`Invalid ECDSA signature length: expected ${coordBytes * 2}; received ${sigBytes.length}`);
  }

  /**
   * Parse an OpenSSH private key and detect its type.
   */
  private static async parsePrivateKey(pem: string): Promise<ParsedKey> {
    const match = /^-----BEGIN OPENSSH PRIVATE KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END OPENSSH PRIVATE KEY-----$/.exec(pem.trim());
    if (!match) throw new Error('Unsupported private key format; only OpenSSH keys are accepted');
    const b64 = match[1].replace(/\r?\n/g, '');
    if (b64.length === 0 || b64.length % 4 !== 0) throw new Error('Malformed OpenSSH private key Base64 data');
    let raw: Uint8Array;
    try {
      const binary = atob(b64);
      raw = Uint8Array.from(binary, c => c.charCodeAt(0));
      const canonical = btoa(binary);
      if (canonical !== b64) throw new Error('non-canonical Base64');
    } catch {
      throw new Error('Malformed OpenSSH private key Base64 data');
    }

    // Parse OpenSSH format: "openssh-key-v1\0" magic
    const magic = 'openssh-key-v1\0';
    const magicBytes = new TextEncoder().encode(magic);
    if (raw.length < magicBytes.length) {
      throw new Error('Private key data is too short');
    }
    for (let i = 0; i < magicBytes.length; i++) {
      if (raw[i] !== magicBytes[i]) {
        throw new Error('Unsupported private key format; only OpenSSH keys are accepted');
      }
    }
    let offset = magicBytes.length;

    // ciphername
    if (offset + 4 > raw.length) throw new Error('Malformed private key cipher length');
    const cipherLen = readUint32(raw, offset); offset += 4;
    if (offset + cipherLen > raw.length) throw new Error('Malformed private key cipher field');
    const cipher = this.decodeText(raw.slice(offset, offset + cipherLen), 'private key cipher'); offset += cipherLen;
    if (cipher !== 'none') throw new Error('Encrypted private keys are not supported; remove the passphrase with ssh-keygen -p');

    // kdfname
    if (offset + 4 > raw.length) throw new Error('Malformed private key KDF length');
    const kdfLen = readUint32(raw, offset); offset += 4;
    if (offset + kdfLen > raw.length) throw new Error('Malformed private key KDF field');
    const kdf = this.decodeText(raw.slice(offset, offset + kdfLen), 'private key KDF');
    offset += kdfLen;
    if (kdf !== 'none') {
      throw new Error('Malformed unencrypted private key: KDF must be none');
    }

    // kdfoptions
    if (offset + 4 > raw.length) throw new Error('Malformed private key KDF options length');
    const kdfOptLen = readUint32(raw, offset); offset += 4;
    if (offset + kdfOptLen > raw.length) throw new Error('Malformed private key KDF options');
    if (kdfOptLen !== 0) {
      throw new Error('Malformed unencrypted private key: KDF options must be empty');
    }
    offset += kdfOptLen;

    // number of keys
    if (offset + 4 > raw.length) throw new Error('Malformed private key count');
    const numKeys = readUint32(raw, offset); offset += 4;
    if (numKeys !== 1) throw new Error('Only single-key files are supported');

    // public key section
    if (offset + 4 > raw.length) throw new Error('Malformed public key section length');
    const pubSecLen = readUint32(raw, offset); offset += 4;
    if (offset + pubSecLen > raw.length) throw new Error('Malformed public key section');
    const publicKeyBlob = raw.slice(offset, offset + pubSecLen);
    offset += pubSecLen;

    // private key section
    if (offset + 4 > raw.length) throw new Error('Malformed private key section length');
    const privSecLen = readUint32(raw, offset); offset += 4;
    if (offset + privSecLen > raw.length) throw new Error('Malformed private key section');
    const privSection = raw.slice(offset, offset + privSecLen);
    offset += privSecLen;
    if (offset !== raw.length) throw new Error('Trailing data after private key section');

    // Parse private section: checkint1, checkint2, keytype, ...
    let po = 0;
    if (privSection.length < 8) throw new Error('Malformed private key check integers');
    const checkint1 = readUint32(privSection, po); po += 4;
    const checkint2 = readUint32(privSection, po); po += 4;
    if (checkint1 !== checkint2) {
      throw new Error('Private key check integers do not match');
    }

    // key type
    if (po + 4 > privSection.length) throw new Error('Malformed private key type length');
    const ktLen = readUint32(privSection, po); po += 4;
    if (po + ktLen > privSection.length) throw new Error('Malformed private key type');
    const keyType = this.decodeText(privSection.slice(po, po + ktLen), 'private key type'); po += ktLen;

    // Parse based on key type
    if (keyType === SSH_ED25519) {
      return this.parseEd25519Key(privSection, po, publicKeyBlob);
    } else if (keyType === SSH_RSA) {
      return this.parseRSAKey(privSection, po, publicKeyBlob);
    } else if (keyType.startsWith('ecdsa-sha2-')) {
      return this.parseECDSAKey(privSection, po, keyType, publicKeyBlob);
    } else {
      throw new Error(`Unsupported key type: ${keyType}`);
    }
  }

  /**
   * Parse Ed25519 private key from OpenSSH format.
   */
  private static async parseEd25519Key(
    privSection: Uint8Array,
    offset: number,
    outerPublicKeyBlob: Uint8Array,
  ): Promise<ParsedKey> {
    let po = offset;

    // public key (32 bytes)
    if (po + 4 > privSection.length) throw new Error('Malformed public key length');
    const pubKeyLen = readUint32(privSection, po); po += 4;
    if (po + pubKeyLen > privSection.length) throw new Error('Malformed public key');
    const pubKeyRaw = privSection.slice(po, po + pubKeyLen); po += pubKeyLen;
    if (pubKeyRaw.length !== 32) throw new Error('Malformed Ed25519 public key length');

    // private key (64 bytes = 32 bytes seed + 32 bytes pubkey)
    if (po + 4 > privSection.length) throw new Error('Malformed private key length');
    const privKeyLen = readUint32(privSection, po); po += 4;
    if (po + privKeyLen > privSection.length) throw new Error('Malformed private key');
    const privKeyRaw = privSection.slice(po, po + privKeyLen); po += privKeyLen;
    if (privKeyRaw.length !== 64) throw new Error('Malformed Ed25519 private key length');
    if (!this.bytesEqual(pubKeyRaw, privKeyRaw.subarray(32))) {
      throw new Error('Ed25519 private key public suffix does not match its public key');
    }

    this.validateEd25519PublicBlob(outerPublicKeyBlob, pubKeyRaw);
    this.validatePrivateSectionTail(privSection, po);

    const seed = privKeyRaw.slice(0, 32);

    const pkcs8 = this.buildEd25519PKCS8(seed);
    const signingKey = await crypto.subtle.importKey(
      'pkcs8', toBufferSource(pkcs8), { name: ED25519_ALGO }, false, ['sign']
    );
    const probe = new Uint8Array([0x43, 0x46, 0x57, 0x53]);
    const probeSignature = await crypto.subtle.sign(ED25519_ALGO, signingKey, toBufferSource(probe));
    const publicKey = await crypto.subtle.importKey('raw', toBufferSource(pubKeyRaw), { name: ED25519_ALGO }, false, ['verify']);
    if (!await crypto.subtle.verify(ED25519_ALGO, publicKey, probeSignature, toBufferSource(probe))) {
      throw new Error('Ed25519 private seed does not match its public key');
    }

    return { signingKey, publicKeyBlob: outerPublicKeyBlob, keyType: SSH_ED25519 };
  }

  /**
   * Parse RSA private key from OpenSSH format.
   */
  private static async parseRSAKey(
    privSection: Uint8Array,
    offset: number,
    outerPublicKeyBlob: Uint8Array,
  ): Promise<ParsedKey> {
    let po = offset;

    const readMPINT = (name: string): Uint8Array => {
      const field = this.readPositiveMPInt(privSection, po, `RSA ${name}`);
      po = field.offset;
      return field.value;
    };

    const n = readMPINT('modulus');
    const e = readMPINT('public exponent');
    const d = readMPINT('private exponent');
    const iqmp = readMPINT('coefficient');
    const p = readMPINT('prime p');
    const q = readMPINT('prime q');

    this.validateRSAPublicBlob(outerPublicKeyBlob, e, n);
    this.validateRSAComponents(n, e, d, iqmp, p, q);
    this.validatePrivateSectionTail(privSection, po);

    const pkcs8 = this.buildRSAPKCS8(n, e, d, p, q, iqmp);

    const signingKey = await crypto.subtle.importKey(
      'pkcs8', toBufferSource(pkcs8), RSA_ALGO, false, ['sign']
    );

    return { signingKey, rsaPkcs8: pkcs8, publicKeyBlob: outerPublicKeyBlob, keyType: SSH_RSA };
  }

  /**
   * Parse ECDSA private key from OpenSSH format.
   */
  private static async parseECDSAKey(
    privSection: Uint8Array,
    offset: number,
    keyType: string,
    outerPublicKeyBlob: Uint8Array,
  ): Promise<ParsedKey> {
    let po = offset;

    let namedCurve: string;
    let algo: EcKeyImportParams;

    if (keyType === ECDSA_SHA2_NISTP256) {
      namedCurve = 'P-256';
      algo = ECDSA_P256_ALGO;
    } else if (keyType === ECDSA_SHA2_NISTP384) {
      namedCurve = 'P-384';
      algo = ECDSA_P384_ALGO;
    } else if (keyType === ECDSA_SHA2_NISTP521) {
      namedCurve = 'P-521';
      algo = ECDSA_P521_ALGO;
    } else {
      throw new Error(`Unsupported ECDSA curve: ${keyType}`);
    }

    // curve name
    if (po + 4 > privSection.length) throw new Error('Malformed private key curve length');
    const curveLen = readUint32(privSection, po); po += 4;
    if (po + curveLen > privSection.length) throw new Error('Malformed private key curve');
    const curve = this.decodeText(privSection.slice(po, po + curveLen), 'private key curve'); po += curveLen;

    const expectedCurve = namedCurve.replace('P-', 'nistp');
    if (curve !== expectedCurve) {
      throw new Error(`Curve mismatch: expected ${expectedCurve}; received ${curve}`);
    }

    // public key
    if (po + 4 > privSection.length) throw new Error('Malformed public key length');
    const pubKeyLen = readUint32(privSection, po); po += 4;
    if (po + pubKeyLen > privSection.length) throw new Error('Malformed public key');
    const pubKeyRaw = privSection.slice(po, po + pubKeyLen); po += pubKeyLen;

    // private key
    if (po + 4 > privSection.length) throw new Error('Malformed private key length');
    const scalar = this.readPositiveMPInt(privSection, po, 'ECDSA private scalar');
    po = scalar.offset;

    const coordBytes = this.ecdsaCoordBytes(keyType);
    if (scalar.value.length > coordBytes) throw new Error('Malformed ECDSA private scalar length');
    const privKeyRaw = new Uint8Array(coordBytes);
    privKeyRaw.set(scalar.value, coordBytes - scalar.value.length);

    if (pubKeyRaw.length !== 1 + (coordBytes * 2) || pubKeyRaw[0] !== 0x04) {
      throw new Error('Malformed ECDSA public key point');
    }
    this.validateECDSAPublicBlob(outerPublicKeyBlob, keyType, curve, pubKeyRaw);
    this.validatePrivateSectionTail(privSection, po);

    const pkcs8 = this.buildECDSAPKCS8(namedCurve, privKeyRaw);

    const signingKey = await crypto.subtle.importKey(
      'pkcs8', toBufferSource(pkcs8), algo, false, ['sign']
    );
    const publicKey = await crypto.subtle.importKey('raw', toBufferSource(pubKeyRaw), algo, false, ['verify']);
    const probe = new Uint8Array([0x43, 0x46, 0x57, 0x53]);
    const probeSignature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: this.ecdsaHashForCurve(keyType) },
      signingKey,
      toBufferSource(probe),
    );
    if (!await crypto.subtle.verify(
      { name: 'ECDSA', hash: this.ecdsaHashForCurve(keyType) },
      publicKey,
      probeSignature,
      toBufferSource(probe),
    )) throw new Error('ECDSA private scalar does not match its public key');

    return { signingKey, publicKeyBlob: outerPublicKeyBlob, keyType };
  }

  private static validateEd25519PublicBlob(blob: Uint8Array, publicKey: Uint8Array): void {
    let offset = 0;
    const type = this.readSSHString(blob, offset, 'Ed25519 public key type'); offset = type.offset;
    const key = this.readSSHString(blob, offset, 'Ed25519 public key'); offset = key.offset;
    if (this.decodeText(type.value, 'Ed25519 public key type') !== SSH_ED25519) {
      throw new Error('Ed25519 outer public key type does not match private key');
    }
    if (offset !== blob.length) throw new Error('Trailing data in Ed25519 public key blob');
    if (key.value.length !== 32 || !this.bytesEqual(key.value, publicKey)) {
      throw new Error('Ed25519 outer public key does not match private key');
    }
  }

  private static validateRSAPublicBlob(blob: Uint8Array, exponent: Uint8Array, modulus: Uint8Array): void {
    let offset = 0;
    const type = this.readSSHString(blob, offset, 'RSA public key type'); offset = type.offset;
    if (this.decodeText(type.value, 'RSA public key type') !== SSH_RSA) {
      throw new Error('RSA outer public key type does not match private key');
    }
    const outerExponent = this.readPositiveMPInt(blob, offset, 'RSA outer public exponent');
    offset = outerExponent.offset;
    const outerModulus = this.readPositiveMPInt(blob, offset, 'RSA outer modulus');
    offset = outerModulus.offset;
    if (offset !== blob.length) throw new Error('Trailing data in RSA public key blob');
    if (!this.bytesEqual(outerExponent.value, exponent) || !this.bytesEqual(outerModulus.value, modulus)) {
      throw new Error('RSA outer public key does not match private key');
    }
  }

  private static validateECDSAPublicBlob(
    blob: Uint8Array,
    keyType: string,
    curve: string,
    publicKey: Uint8Array,
  ): void {
    let offset = 0;
    const outerType = this.readSSHString(blob, offset, 'ECDSA public key type'); offset = outerType.offset;
    const outerCurve = this.readSSHString(blob, offset, 'ECDSA public key curve'); offset = outerCurve.offset;
    const outerKey = this.readSSHString(blob, offset, 'ECDSA public key point'); offset = outerKey.offset;
    if (offset !== blob.length) throw new Error('Trailing data in ECDSA public key blob');
    if (this.decodeText(outerType.value, 'ECDSA public key type') !== keyType
      || this.decodeText(outerCurve.value, 'ECDSA public key curve') !== curve
      || !this.bytesEqual(outerKey.value, publicKey)) {
      throw new Error('ECDSA outer public key does not match private key');
    }
  }

  private static validatePrivateSectionTail(section: Uint8Array, offset: number): void {
    const comment = this.readSSHString(section, offset, 'private key comment');
    const paddingLength = section.length - comment.offset;
    if (section.length % 8 !== 0 || paddingLength > 7) {
      throw new Error('Malformed OpenSSH private key padding');
    }
    for (let i = 0; i < paddingLength; i++) {
      if (section[comment.offset + i] !== i + 1) {
        throw new Error('Malformed OpenSSH private key padding');
      }
    }
  }

  private static readSSHString(
    data: Uint8Array,
    offset: number,
    label: string,
  ): { value: Uint8Array; offset: number } {
    if (offset + 4 > data.length) throw new Error(`Malformed ${label} length`);
    const length = readUint32(data, offset);
    offset += 4;
    if (offset + length > data.length) throw new Error(`Malformed ${label} data`);
    return { value: data.slice(offset, offset + length), offset: offset + length };
  }

  private static readPositiveMPInt(
    data: Uint8Array,
    offset: number,
    label: string,
  ): { value: Uint8Array; offset: number } {
    const field = this.readSSHString(data, offset, label);
    const value = field.value;
    if (value.length === 0 || (value[0] & 0x80) !== 0) {
      throw new Error(`Malformed ${label}: expected a positive MPINT`);
    }
    if (value[0] === 0) {
      if (value.length === 1 || (value[1] & 0x80) === 0) {
        throw new Error(`Malformed ${label}: non-canonical MPINT`);
      }
      return { value: value.slice(1), offset: field.offset };
    }
    return field;
  }

  private static decodeText(data: Uint8Array, label: string): string {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(data);
    } catch {
      throw new Error(`Malformed ${label}: invalid UTF-8`);
    }
  }

  private static bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let difference = 0;
    for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
    return difference === 0;
  }

  private static validateRSAComponents(
    n: Uint8Array,
    e: Uint8Array,
    d: Uint8Array,
    iqmp: Uint8Array,
    p: Uint8Array,
    q: Uint8Array,
  ): void {
    const toBigInt = (bytes: Uint8Array): bigint => {
      let value = 0n;
      for (const byte of bytes) value = (value << 8n) | BigInt(byte);
      return value;
    };
    const modulus = toBigInt(n);
    const exponent = toBigInt(e);
    const privateExponent = toBigInt(d);
    const primeP = toBigInt(p);
    const primeQ = toBigInt(q);
    const coefficient = toBigInt(iqmp);
    if (primeP <= 2n || primeQ <= 2n || modulus !== primeP * primeQ) throw new Error('RSA private factors do not match the modulus');
    if (exponent < 3n || (exponent & 1n) === 0n || privateExponent < 1n) throw new Error('Malformed RSA exponents');
    if ((coefficient * primeQ) % primeP !== 1n) throw new Error('RSA CRT coefficient does not match the private factors');
    const pMinus1 = primeP - 1n;
    const qMinus1 = primeQ - 1n;
    if ((privateExponent * exponent) % pMinus1 !== 1n || (privateExponent * exponent) % qMinus1 !== 1n) {
      throw new Error('RSA private exponent does not match the public exponent');
    }
  }

  /**
   * Build PKCS#8 DER format for Ed25519 seed.
   */
  private static buildEd25519PKCS8(seed: Uint8Array): Uint8Array {
    const oid = new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x70]);
    const seedOctet = new Uint8Array([0x04, seed.length, ...seed]);
    const innerOctet = new Uint8Array([0x04, seedOctet.length, ...seedOctet]);
    const algoSeq = new Uint8Array([0x30, oid.length, ...oid]);
    const version = new Uint8Array([0x02, 0x01, 0x00]);
    const totalLen = version.length + algoSeq.length + innerOctet.length;
    return new Uint8Array([0x30, totalLen, ...version, ...algoSeq, ...innerOctet]);
  }

  /**
   * Build PKCS#8 DER format for RSA private key.
   */
  private static buildRSAPKCS8(
    n: Uint8Array, e: Uint8Array, d: Uint8Array,
    p: Uint8Array, q: Uint8Array, iqmp: Uint8Array
  ): Uint8Array {
    const pkcs1 = this.buildRSAPKCS1(n, e, d, p, q, iqmp);

    const rsaOid = new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
    const nullParam = new Uint8Array([0x05, 0x00]);
    const algoSeq = this.buildDERSequence(concat(rsaOid, nullParam));

    const version = new Uint8Array([0x02, 0x01, 0x00]);
    const privKeyOctet = this.buildDEROctetString(pkcs1);

    return this.buildDERSequence(concat(version, algoSeq, privKeyOctet));
  }

  /**
   * Build PKCS#1 RSAPrivateKey DER format.
   */
  private static buildRSAPKCS1(
    n: Uint8Array, e: Uint8Array, d: Uint8Array,
    p: Uint8Array, q: Uint8Array, iqmp: Uint8Array
  ): Uint8Array {
    const version = this.buildDERInteger(new Uint8Array([0]));
    const modulus = this.buildDERInteger(n);
    const publicExp = this.buildDERInteger(e);
    const privateExp = this.buildDERInteger(d);
    const prime1 = this.buildDERInteger(p);
    const prime2 = this.buildDERInteger(q);

    const pMinus1 = this.bigIntSubtract(p, new Uint8Array([1]));
    const qMinus1 = this.bigIntSubtract(q, new Uint8Array([1]));
    const exponent1 = this.buildDERInteger(this.bigIntMod(d, pMinus1));
    const exponent2 = this.buildDERInteger(this.bigIntMod(d, qMinus1));
    const coefficient = this.buildDERInteger(iqmp);

    return this.buildDERSequence(
      concat(version, modulus, publicExp, privateExp, prime1, prime2, exponent1, exponent2, coefficient)
    );
  }

  /**
   * Build PKCS#8 DER format for ECDSA private key.
   */
  private static buildECDSAPKCS8(namedCurve: string, privateKey: Uint8Array): Uint8Array {
    let curveOid: Uint8Array;
    if (namedCurve === 'P-256') {
      curveOid = new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
    } else if (namedCurve === 'P-384') {
      curveOid = new Uint8Array([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]);
    } else if (namedCurve === 'P-521') {
      curveOid = new Uint8Array([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]);
    } else {
      throw new Error(`Unsupported curve: ${namedCurve}`);
    }

    const ecVersion = this.buildDERInteger(new Uint8Array([1]));
    const ecPrivKeyOctet = this.buildDEROctetString(privateKey);
    const parameters = new Uint8Array([0xa0, curveOid.length, ...curveOid]);
    const ecPrivateKey = this.buildDERSequence(concat(ecVersion, ecPrivKeyOctet, parameters));

    const ecOid = new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
    const algoSeq = this.buildDERSequence(concat(ecOid, curveOid));

    const pkcs8Version = this.buildDERInteger(new Uint8Array([0]));
    const privateKeyOctet = this.buildDEROctetString(ecPrivateKey);

    return this.buildDERSequence(concat(pkcs8Version, algoSeq, privateKeyOctet));
  }

  /**
   * Build DER INTEGER.
   */
  private static buildDERInteger(value: Uint8Array): Uint8Array {
    let data = value;
    if (data.length > 0 && (data[0] & 0x80) !== 0) {
      data = concat(new Uint8Array([0]), data);
    }
    while (data.length > 1 && data[0] === 0 && data[1] === 0) {
      data = data.slice(1);
    }

    return concat(
      new Uint8Array([0x02]),
      this.encodeDERLength(data.length),
      data
    );
  }

  /**
   * Build DER OCTET STRING.
   */
  private static buildDEROctetString(data: Uint8Array): Uint8Array {
    return concat(
      new Uint8Array([0x04]),
      this.encodeDERLength(data.length),
      data
    );
  }

  /**
   * Build DER SEQUENCE.
   */
  private static buildDERSequence(data: Uint8Array): Uint8Array {
    return concat(
      new Uint8Array([0x30]),
      this.encodeDERLength(data.length),
      data
    );
  }

  /**
   * Encode DER length.
   */
  private static encodeDERLength(length: number): Uint8Array {
    if (length < 0x80) {
      return new Uint8Array([length]);
    } else if (length < 0x100) {
      return new Uint8Array([0x81, length]);
    } else if (length < 0x10000) {
      return new Uint8Array([0x82, (length >> 8) & 0xff, length & 0xff]);
    } else {
      throw new Error('DER length is out of range');
    }
  }

  /**
   * Convert ECDSA DER signature to SSH format (r || s).
   */
  private static convertECDSADERToSSH(derSignature: Uint8Array): Uint8Array {
    let offset = 0;

    if (derSignature.length < 8 || derSignature[offset] !== 0x30) throw new Error('Invalid DER signature');
    offset++;

    const sequence = this.readDERLength(derSignature, offset);
    offset = sequence.offset;
    if (sequence.length !== derSignature.length - offset) throw new Error('Invalid DER signature length');

    if (derSignature[offset] !== 0x02) throw new Error('Invalid DER signature');
    offset++;

    const rLength = this.readDERLength(derSignature, offset);
    offset = rLength.offset;
    if (rLength.length === 0 || rLength.length > derSignature.length - offset) throw new Error('Invalid DER signature integer');
    const r = derSignature.slice(offset, offset + rLength.length);
    offset += rLength.length;

    if (derSignature[offset] !== 0x02) throw new Error('Invalid DER signature');
    offset++;

    const sLength = this.readDERLength(derSignature, offset);
    offset = sLength.offset;
    if (sLength.length === 0 || sLength.length !== derSignature.length - offset) throw new Error('Invalid DER signature integer');
    const s = derSignature.slice(offset, offset + sLength.length);

    for (const integer of [r, s]) {
      if ((integer[0] & 0x80) !== 0 || (integer.length > 1 && integer[0] === 0 && (integer[1] & 0x80) === 0)) {
        throw new Error('Invalid DER signature integer encoding');
      }
    }

    return concat(this.sshMPInt(r), this.sshMPInt(s));
  }

  private static readDERLength(data: Uint8Array, offset: number): { length: number; offset: number } {
    if (offset >= data.length) throw new Error('Invalid DER length');
    const first = data[offset++];
    if (first < 0x80) return { length: first, offset };
    const bytes = first & 0x7f;
    if (bytes === 0 || bytes > 4 || offset + bytes > data.length || data[offset] === 0) throw new Error('Invalid DER length');
    let length = 0;
    for (let index = 0; index < bytes; index++) length = (length * 256) + data[offset + index];
    if (length < 0x80 || !Number.isSafeInteger(length)) throw new Error('Invalid DER length');
    return { length, offset: offset + bytes };
  }

  /**
   * Encode MPINT in SSH format.
   */
  private static sshMPInt(value: Uint8Array): Uint8Array {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) {
      start++;
    }
    const significant = value.subarray(start);

    const needsLeadingZero = significant.length > 0 && (significant[0] & 0x80) !== 0;
    const data = needsLeadingZero
      ? concat(new Uint8Array([0]), significant)
      : significant;

    return encodeString(data);
  }

  /**
   * Subtract two big integers (big-endian).
   */
  private static bigIntSubtract(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(a.length);
    let borrow = 0;

    for (let i = a.length - 1; i >= 0; i--) {
      const aByte = a[i];
      const bByte = i >= a.length - b.length ? b[b.length - (a.length - i)] : 0;

      let diff = aByte - bByte - borrow;
      if (diff < 0) {
        diff += 256;
        borrow = 1;
      } else {
        borrow = 0;
      }
      result[i] = diff;
    }

    let start = 0;
    while (start < result.length - 1 && result[start] === 0) {
      start++;
    }
    return result.slice(start);
  }

  /**
   * Calculate a mod m for big integers.
   */
  private static bigIntMod(a: Uint8Array, m: Uint8Array): Uint8Array {
    const toBigInt = (bytes: Uint8Array): bigint => {
      let n = 0n;
      for (const b of bytes) n = (n << 8n) | BigInt(b);
      return n;
    };
    const r = toBigInt(a) % toBigInt(m);
    const hex = r.toString(16).padStart(2, '0');
    const padded = hex.length % 2 ? '0' + hex : hex;
    const out = new Uint8Array(padded.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
    return out;
  }

}
