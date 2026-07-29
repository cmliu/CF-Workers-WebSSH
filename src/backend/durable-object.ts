import { connect } from 'cloudflare:sockets';
import { parseConnectMessage, type Env } from '../types';
import { assertPublicTarget, toSocketHostname } from './security';
import { createTicket, verifyTicket } from './security';
import { SSHSession } from './session';

interface MainAttachment { role: 'main'; phase: 'waiting' | 'connecting' | 'connected' }
interface SFTPAttachment { role: 'sftp'; phase: 'connected' }
type Attachment = MainAttachment | SFTPAttachment;
interface StoredTicket { secret: number[]; expiresAt: number; ip: string }
interface PendingConnection {
  cancelled: boolean;
  socket?: Socket;
  closedSockets: WeakSet<Socket>;
}
interface SFTPAttachToken {
  mainWebSocket: WebSocket;
  attachUrl: string;
  expiresAt: number;
  timeout: ReturnType<typeof setTimeout>;
  session?: SSHSession;
}
const TICKET_STORAGE_KEY = 'session-ticket';
const SFTP_ATTACH_TOKEN_TTL_MS = 10 * 60 * 1000;
const SFTP_ATTACH_TOKEN_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class SSHSessionDO implements DurableObject {
  private readonly state: DurableObjectState;
  private readonly env: Env;
  private readonly sessions = new Map<WebSocket, SSHSession>();
  private readonly pendingConnections = new Map<WebSocket, PendingConnection>();
  private readonly deadlines = new Map<WebSocket, ReturnType<typeof setTimeout>>();
  private readonly sftpAttachTokens = new Map<string, SFTPAttachToken>();
  private readonly sftpTokenByMainWebSocket = new Map<WebSocket, string>();
  private readonly sftpSessions = new Map<WebSocket, SSHSession>();
  private readonly sftpOwners = new Map<WebSocket, WebSocket>();
  private readonly sftpWebSocketsByMain = new Map<WebSocket, Set<WebSocket>>();

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    for (const ws of state.getWebSockets()) {
      const attachment = ws.deserializeAttachment() as Attachment | null;
      if (attachment?.role === 'sftp') {
        try { ws.close(1012, 'Worker session restarted; reconnect required'); } catch { /* already closed */ }
      } else if (attachment?.phase === 'connected') {
        try { ws.close(1012, 'Worker session restarted; reconnect required'); } catch { /* already closed */ }
      } else {
        try { ws.close(1008, 'Session state expired'); } catch { /* already closed */ }
      }
    }
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/ticket' && request.method === 'POST') {
      const ip = request.headers.get('x-client-ip') ?? 'unknown';
      if (!/^[0-9a-f:.]{2,64}$|^local$|^unknown$/i.test(ip)) return Response.json({ error: 'Invalid client address' }, { status: 400 });
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const created = await createTicket(secret, ip);
      const stored = await this.state.storage.transaction(async (tx) => {
        if (await tx.get(TICKET_STORAGE_KEY)) return false;
        await tx.put(TICKET_STORAGE_KEY, { secret: Array.from(secret), expiresAt: created.expiresAt, ip } satisfies StoredTicket);
        await tx.setAlarm(created.expiresAt);
        return true;
      });
      secret.fill(0);
      return stored ? Response.json(created) : Response.json({ error: 'Ticket already created' }, { status: 409 });
    }
    if (url.pathname === '/sftp') return this.attachSFTP(request);
    if (url.pathname !== '/connect') return Response.json({ error: 'Not found' }, { status: 404 });
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return Response.json({ error: 'WebSocket upgrade required' }, { status: 426 });
    const sftpAttachToken = request.headers.get('x-sftp-attach-token');
    const sftpAttachUrl = request.headers.get('x-sftp-attach-url');
    if (!sftpAttachToken || !SFTP_ATTACH_TOKEN_PATTERN.test(sftpAttachToken)
      || !sftpAttachUrl || !this.isValidSFTPAttachUrl(sftpAttachUrl, sftpAttachToken)) {
      return Response.json({ error: 'Invalid SFTP attachment authorization' }, { status: 400 });
    }
    const ticket = request.headers.get('x-session-ticket');
    const ip = request.headers.get('x-client-ip') ?? 'unknown';
    if (!ticket || !await this.consumeTicket(ticket, ip)) {
      return Response.json({ error: 'Invalid session ticket' }, { status: 401 });
    }
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.state.acceptWebSocket(server);
    server.serializeAttachment({ role: 'main', phase: 'waiting' } satisfies MainAttachment);
    this.registerSFTPAttachToken(sftpAttachToken, sftpAttachUrl, server);
    const deadline = setTimeout(() => this.reject(server, 'Connect message timeout'), 10_000);
    this.deadlines.set(server, deadline);
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const sftpSession = this.sftpSessions.get(ws);
    if (sftpSession || this.isSFTPWebSocket(ws)) {
      try {
        if (!sftpSession || ws.readyState !== WebSocket.OPEN) {
          this.cleanupSFTPWebSocket(ws);
          if (ws.readyState === WebSocket.OPEN) ws.close(1008, 'SFTP session is unavailable');
          return;
        }
        await sftpSession.handleSFTPClientMessage(message);
      } catch {
        this.cleanupSFTPWebSocket(ws);
        try { ws.close(1011, 'SFTP request failed'); } catch { /* already closed */ }
      }
      return;
    }
    try {
      if (ws.readyState !== WebSocket.OPEN) {
        this.cleanup(ws);
        return;
      }
      const session = this.sessions.get(ws);
      if (session) {
        await session.handleClientMessage(message);
        return;
      }
      if (this.pendingConnections.has(ws)) throw new Error('An SSH connection is already being initialized');
      if (typeof message !== 'string' || message.length > 160 * 1024) throw new Error('The first WebSocket message must be a connect JSON object');
      let decoded: unknown;
      try { decoded = JSON.parse(message); } catch { throw new Error('Invalid connect JSON'); }
      const config = parseConnectMessage(decoded);
      const pending: PendingConnection = { cancelled: false, closedSockets: new WeakSet() };
      this.pendingConnections.set(ws, pending);
      ws.serializeAttachment({ role: 'main', phase: 'connecting' } satisfies MainAttachment);
      this.clearDeadline(ws);
      if (config.port === 25) throw new Error('Cloudflare Workers cannot connect to outbound TCP port 25');
      const verifiedAddresses = await assertPublicTarget(config.host);
      this.assertConnectionActive(ws, pending);
      ws.send(JSON.stringify({ type: 'status', event: 'tcp_connecting', message: `Connecting to ${config.host}:${config.port}` }));

      // Connect to the exact address that passed SSRF validation. Keeping the
      // original hostname only for host-key pinning prevents DNS rebinding.
      const socket = await this.openVerifiedAddress(verifiedAddresses, config.port, pending);
      this.assertConnectionActive(ws, pending, socket);

      const ssh = new SSHSession(ws, socket, config);
      const token = this.sftpTokenByMainWebSocket.get(ws);
      const sftpAttach = token ? this.sftpAttachTokens.get(token) : undefined;
      if (sftpAttach) {
        sftpAttach.session = ssh;
        ssh.setSFTPAttachUrl(sftpAttach.attachUrl);
      }
      this.sessions.set(ws, ssh);
      this.pendingConnections.delete(ws);
      pending.socket = undefined;
      ws.serializeAttachment({ role: 'main', phase: 'connected' } satisfies MainAttachment);
      await ssh.start();
    } catch (error) {
      this.reject(ws, error instanceof Error ? error.message : String(error));
    }
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    if (this.isSFTPWebSocket(ws)) this.cleanupSFTPWebSocket(ws);
    else this.cleanup(ws);
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    if (this.isSFTPWebSocket(ws)) this.cleanupSFTPWebSocket(ws);
    else this.cleanup(ws);
  }

  async alarm(): Promise<void> {
    await this.state.storage.delete(TICKET_STORAGE_KEY);
  }

  private connectTimeout(): number {
    const configured = Number(this.env.CONNECT_TIMEOUT_MS ?? 10_000);
    return Number.isFinite(configured) ? Math.min(30_000, Math.max(2_000, Math.floor(configured))) : 10_000;
  }

  private async consumeTicket(ticket: string, ip: string): Promise<boolean> {
    return this.state.storage.transaction(async (tx) => {
      const stored = await tx.get<StoredTicket>(TICKET_STORAGE_KEY);
      if (!stored) return false;
      // A presented ticket is one-shot even when malformed, which closes the
      // replay race without retaining authorization material after an attempt.
      await tx.delete(TICKET_STORAGE_KEY);
      await tx.deleteAlarm();
      // 不校验 stored.ip !== ip：反代/CDN（如腾讯云 EdgeOne）多节点回源会让
      // CF-Connecting-IP 在签发与使用两次请求间不一致，导致 ticket 误判失效
      // （概率性 "WebSocket 传输错误"）。详见 verifyTicket 注释。stored.ip 保留用于审计。
      if (stored.expiresAt < Date.now() || stored.secret.length !== 32) return false;
      const secret = new Uint8Array(stored.secret);
      try {
        return await verifyTicket(secret, ticket, ip);
      } finally {
        secret.fill(0);
      }
    });
  }

  private attachSFTP(request: Request): Response {
    if (request.method !== 'GET') return Response.json({ error: 'Method not allowed' }, { status: 405 });
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return Response.json({ error: 'WebSocket upgrade required' }, { status: 426 });
    }
    const token = request.headers.get('x-sftp-attach-token');
    if (!token || !SFTP_ATTACH_TOKEN_PATTERN.test(token)) {
      return Response.json({ error: 'Invalid SFTP attachment token' }, { status: 401 });
    }
    const attach = this.sftpAttachTokens.get(token);
    if (!attach || attach.expiresAt < Date.now() || attach.mainWebSocket.readyState !== WebSocket.OPEN) {
      if (attach) this.deleteSFTPAttachToken(token, attach);
      return Response.json({ error: 'Invalid or expired SFTP attachment token' }, { status: 401 });
    }
    if (!attach.session) return Response.json({ error: 'SSH session is still initializing' }, { status: 409 });

    // Consume before exposing the client endpoint so concurrent replays cannot
    // attach a second file-management channel to the same SSH session.
    this.deleteSFTPAttachToken(token, attach);
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.state.acceptWebSocket(server);
    server.serializeAttachment({ role: 'sftp', phase: 'connected' } satisfies SFTPAttachment);
    this.sftpSessions.set(server, attach.session);
    this.sftpOwners.set(server, attach.mainWebSocket);
    const sockets = this.sftpWebSocketsByMain.get(attach.mainWebSocket) ?? new Set<WebSocket>();
    sockets.add(server);
    this.sftpWebSocketsByMain.set(attach.mainWebSocket, sockets);
    try {
      attach.session.attachSFTPWebSocket(server);
    } catch (error) {
      this.cleanupSFTPWebSocket(server);
      try { server.close(1011, 'Unable to attach SFTP channel'); } catch { /* already closed */ }
      console.error('Unable to attach SFTP WebSocket', error instanceof Error ? error.message : String(error));
      return Response.json({ error: 'Unable to attach SFTP channel' }, { status: 500 });
    }
    return new Response(null, { status: 101, webSocket: client });
  }

  private registerSFTPAttachToken(token: string, attachUrl: string, mainWebSocket: WebSocket): void {
    const expiresAt = Date.now() + SFTP_ATTACH_TOKEN_TTL_MS;
    const attach: SFTPAttachToken = {
      mainWebSocket,
      attachUrl,
      expiresAt,
      timeout: setTimeout(() => this.deleteSFTPAttachToken(token, attach), SFTP_ATTACH_TOKEN_TTL_MS),
    };
    this.sftpAttachTokens.set(token, attach);
    this.sftpTokenByMainWebSocket.set(mainWebSocket, token);
  }

  private deleteSFTPAttachToken(token: string, expected?: SFTPAttachToken): void {
    const attach = this.sftpAttachTokens.get(token);
    if (!attach || (expected && attach !== expected)) return;
    clearTimeout(attach.timeout);
    this.sftpAttachTokens.delete(token);
    if (this.sftpTokenByMainWebSocket.get(attach.mainWebSocket) === token) {
      this.sftpTokenByMainWebSocket.delete(attach.mainWebSocket);
    }
  }

  private isValidSFTPAttachUrl(value: string, token: string): boolean {
    if (value.length > 2048) return false;
    try {
      const url = new URL(value, 'https://session.invalid');
      return value.startsWith('/api/sftp?')
        && url.origin === 'https://session.invalid'
        && url.pathname === '/api/sftp'
        && !url.hash
        && url.searchParams.get('token') === token
        && url.searchParams.get('session') === this.state.id.toString();
    } catch {
      return false;
    }
  }

  private async openVerifiedAddress(addresses: string[], port: number, pending: PendingConnection): Promise<Socket> {
    let lastError: unknown = new Error('No verified target address is available');
    for (const address of addresses) {
      if (pending.cancelled) throw new Error('SSH connection attempt was cancelled');
      const socket = connect({ hostname: toSocketHostname(address), port }, { secureTransport: 'off', allowHalfOpen: false });
      pending.socket = socket;
      let timeoutId: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          socket.opened,
          new Promise<never>((_, reject) => { timeoutId = setTimeout(() => reject(new Error('TCP connection timed out')), this.connectTimeout()); }),
        ]);
        if (pending.cancelled) throw new Error('SSH connection attempt was cancelled');
        return socket;
      } catch (error) {
        lastError = error;
        this.closePendingSocket(pending, socket);
        if (pending.cancelled) throw error;
      } finally {
        if (timeoutId) clearTimeout(timeoutId);
      }
    }
    throw lastError;
  }

  private reject(ws: WebSocket, message: string): void {
    try { ws.send(JSON.stringify({ type: 'error', event: 'connection_failed', message })); } catch { /* already closed */ }
    this.cleanup(ws);
    try { ws.close(1011, 'SSH connection failed'); } catch { /* already closed */ }
  }

  private clearDeadline(ws: WebSocket): void {
    const deadline = this.deadlines.get(ws);
    if (deadline) clearTimeout(deadline);
    this.deadlines.delete(ws);
  }

  private cleanup(ws: WebSocket): void {
    this.clearDeadline(ws);
    const token = this.sftpTokenByMainWebSocket.get(ws);
    if (token) this.deleteSFTPAttachToken(token);
    const sftpWebSockets = this.sftpWebSocketsByMain.get(ws);
    if (sftpWebSockets) {
      for (const sftpWebSocket of [...sftpWebSockets]) {
        this.cleanupSFTPWebSocket(sftpWebSocket);
        try { sftpWebSocket.close(1000, 'SSH session closed'); } catch { /* already closed */ }
      }
      this.sftpWebSocketsByMain.delete(ws);
    }
    const pending = this.pendingConnections.get(ws);
    if (pending) {
      pending.cancelled = true;
      this.closePendingSocket(pending);
      this.pendingConnections.delete(ws);
    }
    this.sessions.get(ws)?.close(true);
    this.sessions.delete(ws);
  }

  private cleanupSFTPWebSocket(ws: WebSocket): void {
    const session = this.sftpSessions.get(ws);
    if (!session) return;
    this.sftpSessions.delete(ws);
    try { session.detachSFTPWebSocket(ws); } catch { /* session is already closed */ }
    const mainWebSocket = this.sftpOwners.get(ws);
    this.sftpOwners.delete(ws);
    if (!mainWebSocket) return;
    const sockets = this.sftpWebSocketsByMain.get(mainWebSocket);
    sockets?.delete(ws);
    if (sockets?.size === 0) this.sftpWebSocketsByMain.delete(mainWebSocket);
  }

  private isSFTPWebSocket(ws: WebSocket): boolean {
    if (this.sftpSessions.has(ws)) return true;
    const attachment = ws.deserializeAttachment() as Attachment | null;
    return attachment?.role === 'sftp';
  }

  private assertConnectionActive(ws: WebSocket, pending: PendingConnection, socket?: Socket): void {
    if (!pending.cancelled && this.pendingConnections.get(ws) === pending && ws.readyState === WebSocket.OPEN) return;
    if (socket) this.closePendingSocket(pending, socket);
    throw new Error('SSH connection attempt was cancelled');
  }

  private closePendingSocket(pending: PendingConnection, socket = pending.socket): void {
    if (!socket || pending.closedSockets.has(socket)) return;
    pending.closedSockets.add(socket);
    if (pending.socket === socket) pending.socket = undefined;
    try { void socket.close().catch(() => undefined); } catch { /* already closed */ }
  }
}
