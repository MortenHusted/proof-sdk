import { createHash, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import express from 'express';

// Trust identity headers only behind Tailscale Serve with a loopback-only backend.
const users = new Set((process.env.PROOF_TAILSCALE_USERS || '').split(',').map(value => value.trim()).filter(Boolean));
const token = process.env.PROOF_INSTANCE_TOKEN || '';
function equal(a: string, b: string): boolean {
  return timingSafeEqual(createHash('sha256').update(a).digest(), createHash('sha256').update(b).digest());
}
export function instanceAuthorized(req: IncomingMessage): boolean {
  if (!token && users.size === 0) return true;
  const user = req.headers['tailscale-user-login'];
  if (typeof user === 'string' && users.has(user)) return true;
  return instanceAgentAuthorized(req);
}
export function instanceAgentAuthorized(req: IncomingMessage): boolean {
  const header = req.headers['x-proof-instance-token'];
  return Boolean(token && typeof header === 'string' && equal(header, token));
}
function originAllowed(req: IncomingMessage): boolean {
  return !req.headers.origin || (process.env.PROOF_CORS_ALLOW_ORIGINS || '').split(',')
    .map(value => value.trim()).includes(req.headers.origin);
}
export function instanceWebSocketAuthorized(req: IncomingMessage): boolean {
  return instanceAuthorized(req) && originAllowed(req);
}
export const instanceAuth = express.Router();
instanceAuth.use((req, res, next) => {
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && !originAllowed(req)) {
    res.status(403).json({ error: 'Origin not allowed' });
    return;
  }
  if (instanceAuthorized(req)) { next(); return; }
  res.status(401).json({ error: 'An allowed Tailscale user or agent credential is required' });
});
