import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import express from 'express';

// Deployment boundary, separate from Proof's document capability tokens.
// All holders are trusted instance members; actor labels remain self-asserted.
const token = process.env.PROOF_INSTANCE_TOKEN || '';
const cookieName = 'proof_instance_session';
const session = token ? createHmac('sha256', token).update('proof-instance-session-v1').digest('hex') : '';
function equal(a: string, b: string): boolean {
  return timingSafeEqual(createHash('sha256').update(a).digest(), createHash('sha256').update(b).digest());
}
export function instanceAuthorized(req: IncomingMessage): boolean {
  if (!token) return true;
  const header = req.headers['x-proof-instance-token'];
  if (typeof header === 'string' && equal(header, token)) return true;
  const cookies = (req.headers.cookie || '').split(';').map(value => value.trim());
  const value = cookies.find(value => value.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
  return Boolean(value && equal(value, session));
}
export function instanceWebSocketAuthorized(req: IncomingMessage): boolean {
  if (!instanceAuthorized(req)) return false;
  if (!token || !req.headers.origin) return true;
  const allowed = (process.env.PROOF_CORS_ALLOW_ORIGINS || '').split(',').map(value => value.trim());
  return allowed.includes(req.headers.origin);
}
export const instanceAuth = express.Router();
instanceAuth.use((_req, res, next) => {
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  next();
});
instanceAuth.post('/_instance/login', express.urlencoded({ extended: false, limit: '2kb' }), (req, res) => {
  if (!token || typeof req.body?.password !== 'string' || !equal(req.body.password, token)) {
    res.status(401).send('Invalid instance password');
    return;
  }
  // Forwarded protocol is accepted only because this deployment binds loopback.
  const secure = req.secure || req.header('x-forwarded-proto')?.split(',')[0].trim() === 'https';
  res.cookie(cookieName, session, { httpOnly: true, secure, sameSite: 'strict', path: '/', maxAge: 7 * 24 * 60 * 60 * 1000 });
  res.redirect(303, '/');
});
instanceAuth.use((req, res, next) => {
  if (instanceAuthorized(req)) { next(); return; }
  if (req.method === 'GET' && req.accepts(['html', 'json']) === 'html') {
    res.status(401).type('html').send('<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>Private Proof instance</title></head><body><h1>Private Proof instance</h1><p>Enter the instance password, then open your document link.</p><form method="post" action="/_instance/login"><label>Password <input type="password" name="password" autocomplete="current-password" required></label><button>Sign in</button></form></body></html>');
    return;
  }
  res.status(401).json({ error: 'Instance authentication required', header: 'X-Proof-Instance-Token' });
});
