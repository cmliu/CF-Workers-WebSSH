import type { Env } from './types';
import { SSHSessionDO } from './backend/durable-object';
import { constantTimeEqual, isSameOrigin } from './backend/security';
import { httpsRedirect, isProductionHttp, jsonError, secureResponse } from './http-security';

export { SSHSessionDO };

function clientAddress(request: Request): string {
  const value = request.headers.get('CF-Connecting-IP') ?? 'local';
  return /^[0-9A-Fa-f:.]{2,64}$/.test(value) ? value.toLowerCase() : 'unknown';
}

async function sessionTicket(request: Request, env: Env): Promise<Response> {
  if (!isSameOrigin(request)) return jsonError('Invalid request origin', 403);
  if (!request.headers.get('Content-Type')?.toLowerCase().startsWith('application/json')) return jsonError('Expected application/json', 415);
  const contentLength = Number(request.headers.get('Content-Length') ?? 0);
  if (!Number.isFinite(contentLength) || contentLength < 0 || contentLength > 8192) return jsonError('Request body is too large', 413);
  let body: unknown;
  try {
    const text = await request.text();
    if (new TextEncoder().encode(text).length > 8192) return jsonError('Request body is too large', 413);
    body = JSON.parse(text);
  } catch { return jsonError('Invalid JSON body', 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return jsonError('Invalid JSON body', 400);
  const fields = Object.keys(body as Record<string, unknown>);
  if (fields.some((field) => field !== 'accessToken')) return jsonError('Unsupported request field', 400);
  if (!env.ACCESS_TOKEN && env.ALLOW_ANONYMOUS !== 'true') {
    return jsonError('Gateway access is not configured', 503);
  }
  const supplied = (body as Record<string, unknown>).accessToken;
  if (typeof supplied === 'string' && supplied.length > 4096) return jsonError('Access token is too large', 413);
  if (env.ACCESS_TOKEN && (typeof supplied !== 'string' || !constantTimeEqual(supplied, env.ACCESS_TOKEN))) return jsonError('Invalid access token', 401);
  const id = env.SSH_SESSIONS.newUniqueId();
  const stub = env.SSH_SESSIONS.get(id);
  const response = await stub.fetch(new Request('https://session.internal/ticket', {
    method: 'POST',
    headers: { 'x-client-ip': clientAddress(request) },
  }));
  if (!response.ok) return jsonError('Unable to create a session ticket', 503);
  const ticket = await response.json<{ ticket: string; expiresAt: number }>();
  return secureResponse(Response.json({ ...ticket, sessionId: id.toString() }, { headers: { 'Cache-Control': 'no-store' } }));
}

async function sshUpgrade(request: Request, env: Env): Promise<Response> {
  if (!isSameOrigin(request)) return jsonError('Invalid WebSocket origin', 403);
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return jsonError('WebSocket upgrade required', 426);
  const url = new URL(request.url);
  const ticket = url.searchParams.get('ticket');
  const sessionId = url.searchParams.get('session');
  if (!ticket || !sessionId) return jsonError('Missing session ticket', 401);
  let id: DurableObjectId;
  try { id = env.SSH_SESSIONS.idFromString(sessionId); } catch { return jsonError('Invalid session identifier', 401); }
  const headers = new Headers(request.headers);
  headers.delete('Cookie');
  headers.delete('Authorization');
  headers.set('x-session-ticket', ticket);
  headers.set('x-client-ip', clientAddress(request));
  const response = await env.SSH_SESSIONS.get(id).fetch(new Request('https://session.internal/connect', { headers }));
  if (response.status === 401) return jsonError('Invalid, expired, or already used session ticket', 401);
  return response;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (isProductionHttp(request)) {
        if (url.pathname.startsWith('/api/')) return jsonError('HTTPS is required', 403);
        if (request.method === 'GET' || request.method === 'HEAD') return httpsRedirect(request);
        return jsonError('HTTPS is required', 403);
      }
      if (url.pathname === '/api/health' && request.method === 'GET') {
        return secureResponse(Response.json({ status: 'ok', runtime: 'cloudflare-workers', ssh: true }, { headers: { 'Cache-Control': 'no-store' } }));
      }
      if (url.pathname === '/api/session') {
        if (request.method !== 'POST') return jsonError('Method not allowed', 405);
        return sessionTicket(request, env);
      }
      if (url.pathname === '/api/ssh') {
        if (request.method !== 'GET') return jsonError('Method not allowed', 405);
        return sshUpgrade(request, env);
      }
      if (url.pathname.startsWith('/api/')) return jsonError('Not found', 404);
      if (!env.ASSETS) return jsonError('Static assets binding is not configured', 503);
      return secureResponse(await env.ASSETS.fetch(request));
    } catch (error) {
      console.error('Worker request failed', error instanceof Error ? error.message : String(error));
      return jsonError('Internal server error', 500);
    }
  },
};
