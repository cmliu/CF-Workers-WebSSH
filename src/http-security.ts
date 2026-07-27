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
