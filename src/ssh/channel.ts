import {
  SSH_MSG_CHANNEL_OPEN,
  SSH_MSG_CHANNEL_WINDOW_ADJUST,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_REQUEST,
  SSH_MSG_CHANNEL_EOF,
  SSH_MSG_CHANNEL_CLOSE,
} from '../types';
import { encodeString, readUint32, writeUint32 } from './utils';

const SESSION_FIELD = encodeString('session');
const PTY_REQ_FIELD = encodeString('pty-req');
const SHELL_FIELD = encodeString('shell');
const SUBSYSTEM_FIELD = encodeString('subsystem');
const EXEC_FIELD = encodeString('exec');
const WINDOW_CHANGE_FIELD = encodeString('window-change');
const EMPTY_TERMINAL_MODES_FIELD = encodeString(new Uint8Array([0]));
const UINT32_MAX = 0xffffffff;
const DEFAULT_WINDOW_SIZE = 2 * 1024 * 1024;
const DEFAULT_MAX_PACKET_SIZE = 32 * 1024;

export interface ChannelDataChunk {
  source: Uint8Array;
  sourceOffset: number;
  bytesConsumed: number;
  payloadLength: number;
}

function writeBytes(target: Uint8Array, offset: number, source: Uint8Array): number {
  target.set(source, offset);
  return offset + source.length;
}

export class SSHChannel {
  private localChannelID: number = 0;
  private remoteChannelID: number = 0;
  private localWindowSize: number = DEFAULT_WINDOW_SIZE;
  private remoteWindowSize: number = 0;
  private remoteMaxPacketSize: number = DEFAULT_MAX_PACKET_SIZE;
  private consumedSinceWindowAdjust: number = 0;
  private eofSent: boolean = false;
  private eofReceived: boolean = false;
  private closeSent: boolean = false;
  private closeReceived: boolean = false;
  private openConfirmed: boolean = false;

  getLocalChannelID(): number {
    return this.localChannelID;
  }

  getRemoteChannelID(): number {
    return this.remoteChannelID;
  }

  isClosed(): boolean {
    return this.closeSent && this.closeReceived;
  }

  hasSentClose(): boolean {
    return this.closeSent;
  }

  buildOpenSession(channelID: number = 0): Uint8Array {
    this.localChannelID = channelID;

    const payload = new Uint8Array(1 + SESSION_FIELD.length + 12);
    let offset = 0;
    payload[offset++] = SSH_MSG_CHANNEL_OPEN;
    offset = writeBytes(payload, offset, SESSION_FIELD);
    writeUint32(payload, offset, this.localChannelID);
    offset += 4;
    writeUint32(payload, offset, DEFAULT_WINDOW_SIZE);
    offset += 4;
    writeUint32(payload, offset, DEFAULT_MAX_PACKET_SIZE);
    return payload;
  }

  handleOpenConfirmation(payload: Uint8Array): void {
    if (payload.length !== 17) throw new Error('Malformed channel open confirmation');
    if (readUint32(payload, 1) !== this.localChannelID) throw new Error('Channel confirmation has an unexpected recipient');
    if (this.openConfirmed) throw new Error('Duplicate channel open confirmation');
    let offset = 1;
    offset += 4;
    this.remoteChannelID = readUint32(payload, offset);
    offset += 4;
    this.remoteWindowSize = readUint32(payload, offset);
    offset += 4;
    const serverMaxPacket = readUint32(payload, offset);
    if (serverMaxPacket === 0) throw new Error('Channel maximum packet size must be positive');
    this.remoteMaxPacketSize = serverMaxPacket;
    this.openConfirmed = true;
  }

  handleOpenFailure(payload: Uint8Array): void {
    if (payload.length < 17 || readUint32(payload, 1) !== this.localChannelID) {
      throw new Error('Malformed channel open failure');
    }
    let offset = 9;
    for (let index = 0; index < 2; index++) {
      if (offset + 4 > payload.length) throw new Error('Malformed channel open failure');
      const length = readUint32(payload, offset);
      offset += 4;
      if (length > payload.length - offset) throw new Error('Malformed channel open failure');
      offset += length;
    }
    if (offset !== payload.length) throw new Error('Malformed channel open failure');
  }

  buildPTYRequest(cols: number, rows: number, terminal = 'xterm-256color'): Uint8Array {
    const terminalField = encodeString(terminal);
    const payload = new Uint8Array(
      1 + 4 + PTY_REQ_FIELD.length + 1 + terminalField.length + 16 + EMPTY_TERMINAL_MODES_FIELD.length
    );
    let offset = 0;
    payload[offset++] = SSH_MSG_CHANNEL_REQUEST;
    writeUint32(payload, offset, this.remoteChannelID);
    offset += 4;
    offset = writeBytes(payload, offset, PTY_REQ_FIELD);
    payload[offset++] = 0x01;
    offset = writeBytes(payload, offset, terminalField);
    writeUint32(payload, offset, cols);
    offset += 4;
    writeUint32(payload, offset, rows);
    offset += 4;
    writeUint32(payload, offset, 0);
    offset += 4;
    writeUint32(payload, offset, 0);
    offset += 4;
    writeBytes(payload, offset, EMPTY_TERMINAL_MODES_FIELD);
    return payload;
  }

  buildShellRequest(): Uint8Array {
    const payload = new Uint8Array(1 + 4 + SHELL_FIELD.length + 1);
    let offset = 0;
    payload[offset++] = SSH_MSG_CHANNEL_REQUEST;
    writeUint32(payload, offset, this.remoteChannelID);
    offset += 4;
    offset = writeBytes(payload, offset, SHELL_FIELD);
    payload[offset] = 0x01;
    return payload;
  }

  buildSubsystemRequest(subsystem: string): Uint8Array {
    const name = encodeString(subsystem);
    const payload = new Uint8Array(1 + 4 + SUBSYSTEM_FIELD.length + 1 + name.length);
    let offset = 0;
    payload[offset++] = SSH_MSG_CHANNEL_REQUEST;
    writeUint32(payload, offset, this.remoteChannelID);
    offset += 4;
    offset = writeBytes(payload, offset, SUBSYSTEM_FIELD);
    payload[offset++] = 0x01; // want_reply = true
    writeBytes(payload, offset, name);
    return payload;
  }

  buildExecRequest(command: string): Uint8Array {
    const cmdBytes = encodeString(command);
    const payload = new Uint8Array(1 + 4 + EXEC_FIELD.length + 1 + cmdBytes.length);
    let offset = 0;
    payload[offset++] = SSH_MSG_CHANNEL_REQUEST;
    writeUint32(payload, offset, this.remoteChannelID);
    offset += 4;
    offset = writeBytes(payload, offset, EXEC_FIELD);
    payload[offset++] = 0x01; // want_reply = true
    writeBytes(payload, offset, cmdBytes);
    return payload;
  }

  buildEof(): Uint8Array {
    if (this.eofSent || this.closeSent) throw new Error('Channel EOF was already sent');
    this.eofSent = true;
    const payload = new Uint8Array(5);
    payload[0] = SSH_MSG_CHANNEL_EOF;
    writeUint32(payload, 1, this.remoteChannelID);
    return payload;
  }

  buildClose(): Uint8Array {
    if (this.closeSent) throw new Error('Channel close was already sent');
    this.closeSent = true;
    const payload = new Uint8Array(5);
    payload[0] = SSH_MSG_CHANNEL_CLOSE;
    writeUint32(payload, 1, this.remoteChannelID);
    return payload;
  }

  takeChannelDataChunk(data: Uint8Array, offset: number = 0): ChannelDataChunk | null {
    const bytesAvailable = data.length - offset;
    if (bytesAvailable <= 0) {
      return null;
    }

    const bytesToSend = Math.min(bytesAvailable, this.remoteMaxPacketSize, this.remoteWindowSize);
    if (bytesToSend <= 0) {
      return null;
    }

    this.remoteWindowSize -= bytesToSend;
    return {
      source: data,
      sourceOffset: offset,
      bytesConsumed: bytesToSend,
      payloadLength: 9 + bytesToSend,
    };
  }

  writeChannelDataPayload(
    target: Uint8Array,
    offset: number,
    source: Uint8Array,
    sourceOffset: number,
    sourceLength: number
  ): void {
    target[offset] = SSH_MSG_CHANNEL_DATA;
    writeUint32(target, offset + 1, this.remoteChannelID);
    writeUint32(target, offset + 5, sourceLength);
    target.set(source.subarray(sourceOffset, sourceOffset + sourceLength), offset + 9);
  }

  handleWindowAdjust(payload: Uint8Array): number {
    if (payload.length !== 9) throw new Error('Malformed channel window adjustment');
    const recipientChannelID = readUint32(payload, 1);
    if (recipientChannelID !== this.localChannelID) {
      throw new Error('Channel window adjustment has an unexpected recipient');
    }

    const bytesToAdd = readUint32(payload, 5);
    if (bytesToAdd === 0 || bytesToAdd > UINT32_MAX - this.remoteWindowSize) {
      throw new Error('Invalid channel window adjustment');
    }
    this.remoteWindowSize += bytesToAdd;
    return bytesToAdd;
  }

  handleChannelData(payload: Uint8Array): Uint8Array {
    if (payload.length < 9) throw new Error('Malformed channel data');
    let offset = 1;
    const recipientChannelID = readUint32(payload, offset);
    if (recipientChannelID !== this.localChannelID) throw new Error('Channel data has an unexpected recipient');
    offset += 4;
    const dataLen = readUint32(payload, offset);
    offset += 4;
    if (dataLen !== payload.length - offset) throw new Error('Malformed channel data');
    this.consumeLocalWindow(dataLen);
    return payload.subarray(offset, offset + dataLen);
  }

  handleExtendedData(payload: Uint8Array): Uint8Array {
    if (payload.length < 13) throw new Error('Malformed extended channel data');
    if (readUint32(payload, 1) !== this.localChannelID) throw new Error('Extended channel data has an unexpected recipient');
    const dataLen = readUint32(payload, 9);
    if (dataLen !== payload.length - 13) throw new Error('Malformed extended channel data');
    this.consumeLocalWindow(dataLen);
    return payload.subarray(13);
  }

  handleRequestResult(payload: Uint8Array): void {
    this.validateRecipientOnlyMessage(payload, 'channel request result');
  }

  handleEof(payload: Uint8Array): void {
    this.validateRecipientOnlyMessage(payload, 'channel EOF');
    if (this.eofReceived) throw new Error('Duplicate channel EOF');
    this.eofReceived = true;
  }

  handleClose(payload: Uint8Array): void {
    this.validateRecipientOnlyMessage(payload, 'channel close');
    if (this.closeReceived) throw new Error('Duplicate channel close');
    this.closeReceived = true;
  }

  buildWindowChange(cols: number, rows: number): Uint8Array {
    const payload = new Uint8Array(1 + 4 + WINDOW_CHANGE_FIELD.length + 1 + 16);
    let offset = 0;
    payload[offset++] = SSH_MSG_CHANNEL_REQUEST;
    writeUint32(payload, offset, this.remoteChannelID);
    offset += 4;
    offset = writeBytes(payload, offset, WINDOW_CHANGE_FIELD);
    payload[offset++] = 0x00;
    writeUint32(payload, offset, cols);
    offset += 4;
    writeUint32(payload, offset, rows);
    offset += 4;
    writeUint32(payload, offset, 0);
    offset += 4;
    writeUint32(payload, offset, 0);
    return payload;
  }

  buildWindowAdjust(bytesToAdd: number): Uint8Array {
    const payload = new Uint8Array(9);
    payload[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
    writeUint32(payload, 1, this.remoteChannelID);
    writeUint32(payload, 5, bytesToAdd);
    return payload;
  }

  takeLocalWindowAdjustment(threshold: number): number | null {
    if (!Number.isInteger(threshold) || threshold < 1) throw new Error('Invalid local channel window threshold');
    if (this.consumedSinceWindowAdjust < threshold) {
      return null;
    }
    const amount = this.consumedSinceWindowAdjust;
    this.consumedSinceWindowAdjust = 0;
    this.localWindowSize += amount;
    return amount;
  }

  private consumeLocalWindow(bytes: number): void {
    // CHANNEL_EOF ends the sender's ordinary data stream. Some servers still
    // send request metadata before CLOSE, but additional channel data is invalid.
    if (this.eofReceived || this.closeReceived) throw new Error('Channel data received after EOF or close');
    if (bytes > DEFAULT_MAX_PACKET_SIZE) throw new Error('Channel data exceeds the advertised maximum packet size');
    if (bytes > this.localWindowSize) throw new Error('Channel data exceeds the local receive window');
    this.localWindowSize -= bytes;
    this.consumedSinceWindowAdjust += bytes;
  }

  private validateRecipientOnlyMessage(payload: Uint8Array, label: string): void {
    if (payload.length !== 5) throw new Error(`Malformed ${label}`);
    if (readUint32(payload, 1) !== this.localChannelID) throw new Error(`${label} has an unexpected recipient`);
  }
}
