import type { RequestHandler } from 'express';
import { createHmac } from 'node:crypto';
import { getCookie, shareTokenCookieName } from './cookies.js';
import { createDocumentAccessToken, getDocumentBySlug, resolveDocumentAccessRole } from './db.js';
import { instanceAgentAuthorized } from './instance-auth.js';

/** Private deployments require a capability even on the SDK's public share routes. */
export const requireDocumentAccess: RequestHandler = (req, res, next) => {
  if (process.env.PROOF_REQUIRE_DOCUMENT_TOKEN !== 'true') return next();
  const slug = String(req.params.slug ?? '');
  if (instanceAgentAuthorized(req)) {
    const document = getDocumentBySlug(slug);
    if (document?.share_state === 'ACTIVE') {
      const secret = createHmac('sha256', process.env.PROOF_INSTANCE_TOKEN!)
        .update(JSON.stringify(['workspace-editor', slug, document.access_epoch])).digest('hex');
      if (!resolveDocumentAccessRole(slug, secret)) createDocumentAccessToken(slug, 'editor', secret);
      req.headers['x-share-token'] = secret;
      req.headers['x-bridge-token'] = secret;
      req.headers.authorization = `Bearer ${secret}`;
      req.headers.cookie = `${shareTokenCookieName(slug)}=${secret}; ${req.headers.cookie || ''}`;
    }
  }
  const header = req.header('x-share-token') || req.header('x-bridge-token')
    || req.header('authorization')?.match(/^Bearer\s+(.+)$/i)?.[1];
  const query = typeof req.query.token === 'string' ? req.query.token : '';
  const cookie = getCookie(req, shareTokenCookieName(slug));
  const candidates = header ? [header] : [query, cookie];
  const role = candidates.map(value => value ? resolveDocumentAccessRole(slug, value) : null).find(Boolean);
  const doc = role ? getDocumentBySlug(slug) : null;
  if (!role || !doc || doc.share_state === 'DELETED'
    || (doc.share_state !== 'ACTIVE' && role !== 'owner_bot')) {
    res.status(401).json({ error: 'Missing or invalid document token' });
    return;
  }
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.path.startsWith('/bridge/')) {
    const mayReview = role === 'commenter' || role === 'editor' || role === 'owner_bot';
    const mayEdit = role === 'editor' || role === 'owner_bot';
    if (!mayReview || (req.path === '/bridge/rewrite' && !mayEdit)) {
      res.status(403).json({ error: 'Document role does not permit this operation' });
      return;
    }
  }
  next();
};
