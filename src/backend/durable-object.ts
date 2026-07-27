import { connect } from 'cloudflare:sockets';
import { parseConnectMessage, type Env } from '../types';
import { assertPublicTarget } from './security';
import { createTicket, verifyTicket } from './security';
import { SSHSession } from './session';

interface Attachment { phase: 'waiting' | 'connecting' | 'connected' }
interface StoredTicket { secret: number[]; expiresAt: number; ip: string }
interface PendingConnection {
  cancelled: boolean;
  socket?: Socket;
  closedSockets: WeakSet<Socket>;
}
const TICKET_STORAGE_KEY = 'session-ticket';

export class SSHSessionDO implements DurableObject {
  private readonly state: DurableObjectState;
  private readonly env: Env;
  private readonly sessions = new Map<WebSocket, SSHSession>();
  private readonly pendingConnections = new Map<WebSocket, PendingConnection>();
  private readonly deadlines = new Map<WebSocket, ReturnType<typeof setTimeout>>();

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    for (const ws of state.getWebSockets()) {
      const attachment = ws.deserializeAttachment() as Attachment | null;
      if (attachment?.phase === 'connected') {
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
    if (url.pathname !== '/connect') return Response.json({ error: 'Not found' }, { status: 404 });
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return Response.json({ error: 'WebSocket upgrade required' }, { status: 426 });
    const ticket = request.headers.get('x-session-ticket');
    const ip = request.headers.get('x-client-ip') ?? 'unknown';
    if (!ticket || !await this.consumeTicket(ticket, ip)) {
      return Response.json({ error: 'Invalid session ticket' }, { status: 401 });
    }
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.state.acceptWebSocket(server);
    server.serializeAttachment({ phase: 'waiting' } satisfies Attachment);
    const deadline = setTimeout(() => this.reject(server, 'Connect message timeout'), 10_000);
    this.deadlines.set(server, deadline);
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
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
      ws.serializeAttachment({ phase: 'connecting' } satisfies Attachment);
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
      this.sessions.set(ws, ssh);
      this.pendingConnections.delete(ws);
      pending.socket = undefined;
      ws.serializeAttachment({ phase: 'connected' } satisfies Attachment);
      await ssh.start();
    } catch (error) {
      this.reject(ws, error instanceof Error ? error.message : String(error));
    }
  }

  async webSocketClose(ws: WebSocket): Promise<void> { this.cleanup(ws); }
  async webSocketError(ws: WebSocket): Promise<void> { this.cleanup(ws); }

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
      if (stored.ip !== ip || stored.expiresAt < Date.now() || stored.secret.length !== 32) return false;
      const secret = new Uint8Array(stored.secret);
      try {
        return await verifyTicket(secret, ticket, ip);
      } finally {
        secret.fill(0);
      }
    });
  }

  private async openVerifiedAddress(addresses: string[], port: number, pending: PendingConnection): Promise<Socket> {
    let lastError: unknown = new Error('No verified target address is available');
    for (const hostname of addresses) {
      if (pending.cancelled) throw new Error('SSH connection attempt was cancelled');
      const socket = connect({ hostname, port }, { secureTransport: 'off', allowHalfOpen: false });
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
    const pending = this.pendingConnections.get(ws);
    if (pending) {
      pending.cancelled = true;
      this.closePendingSocket(pending);
      this.pendingConnections.delete(ws);
    }
    this.sessions.get(ws)?.close(true);
    this.sessions.delete(ws);
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
