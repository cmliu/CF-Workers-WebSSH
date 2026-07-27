export function secureResponse(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set('Strict-Transport-Security', 'max-age=31536000');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Referrer-Policy', 'same-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (response.headers.get('Content-Type')?.includes('text/html')) {
    headers.set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export function corsResponse(response: Response): Response {
  // WebSocket 升级响应（101）必须原样返回，不能用 new Response 重新包装：
  // 复制 Sec-WebSocket-* / Upgrade / Connection 等握手头并重建 Response 会
  // 破坏 Cloudflare 运行时与浏览器之间的升级握手，导致前端概率性出现
  // "WebSocket 传输错误"（de005b5 引入的回归）。WebSocket 协议本身不受
  // 同源/CORS 约束，101 响应无需附加 CORS 头。
  if (response.webSocket) return response;
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export function corsPreflightResponse(): Response {
  return secureResponse(new Response(null, {
    status: 204,
    headers: { 'Access-Control-Max-Age': '86400' },
  }));
}

export function jsonError(error: string, status: number): Response {
  return secureResponse(Response.json({ error }, { status, headers: { 'Cache-Control': 'no-store' } }));
}

export function isProductionHttp(request: Request): boolean {
  return new URL(request.url).protocol === 'http:' && request.headers.has('CF-Connecting-IP');
}

export function httpsRedirect(request: Request): Response {
  const url = new URL(request.url);
  url.protocol = 'https:';
  return secureResponse(new Response(null, {
    status: 308,
    headers: { Location: url.toString(), 'Cache-Control': 'no-store' },
  }));
}
