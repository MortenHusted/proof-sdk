import express from 'express';
import { createDocumentAccessToken, getDocumentBySlug, listActiveDocuments, resolveDocumentAccessRole } from './db.js';
import { getCookie, shareTokenCookieName } from './cookies.js';

// This is a single owner's library, not a multi-user document permission model.
const owner = process.env.PROOF_LIBRARY_USER || '';
const allowedUsers = (process.env.PROOF_TAILSCALE_USERS || '').split(',').map(value => value.trim());
function isOwner(req: express.Request): boolean {
  return Boolean(owner && allowedUsers.includes(owner) && req.header('tailscale-user-login') === owner);
}
function escape(value: string): string {
  return value.replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!);
}

export const privateLibrary = express.Router();
privateLibrary.get('/', (req, res, next) => {
  if (!owner) return next();
  if (!isOwner(req)) { res.status(403).send('This document library is private.'); return; }
  const documents = listActiveDocuments().sort((a, b) => b.updated_at.localeCompare(a.updated_at) || a.slug.localeCompare(b.slug));
  res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Your documents · Proof</title><style>
body{font:17px/1.6 system-ui,sans-serif;background:#f7faf5;color:#17261d;margin:0;padding:48px 24px}
main{max-width:760px;margin:auto}h1{margin-bottom:8px}a{color:#266854}ul{list-style:none;padding:0}
li{padding:18px 0;border-bottom:1px solid #dce5dc}time{display:block;font-size:14px;color:#536457}
form{display:flex;gap:12px;margin:28px 0}input{flex:1;min-width:0}input,button{font:inherit;padding:10px 14px;border:1px solid #a9b8aa;border-radius:6px}
button{background:#266854;color:white;cursor:pointer}#error{color:#9b2828}
</style></head><body><main><h1>Your documents</h1><p>A private space to write together.</p>
<form id="create"><input name="title" aria-label="Document title" placeholder="Untitled document" maxlength="200"><button>New document</button></form>
<p id="error" role="alert"></p>
<ul>${documents.map(doc => `<li><a href="/library/open/${encodeURIComponent(doc.slug)}">${escape(doc.title || 'Untitled document')}</a><time>${escape(doc.updated_at.slice(0, 10))}</time></li>`).join('')}</ul>
${documents.length ? '' : '<p>No documents yet. Start your first draft above.</p>'}
</main><script>
document.querySelector('#create').addEventListener('submit',async event=>{
 event.preventDefault();const form=event.currentTarget;const button=form.querySelector('button');button.disabled=true;
 try{const title=form.elements.title.value.trim()||'Untitled document';
 const response=await fetch('/documents',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title,markdown:'# '+title+'\\n\\n'})});
 if(!response.ok)throw new Error('Could not create the document. Please try again.');
 const doc=await response.json();location.assign('/library/open/'+encodeURIComponent(doc.slug));
 }catch(error){document.querySelector('#error').textContent=error.message;button.disabled=false;}
});
</script></body></html>`);
});

privateLibrary.get('/library/open/:slug', (req, res) => {
  if (!isOwner(req)) { res.status(403).send('This document library is private.'); return; }
  const slug = String(req.params.slug);
  const doc = getDocumentBySlug(slug);
  if (!doc || doc.share_state !== 'ACTIVE') { res.status(404).send('Document unavailable.'); return; }
  const cookie = getCookie(req, shareTokenCookieName(slug));
  const role = cookie ? resolveDocumentAccessRole(slug, cookie) : null;
  if (role !== 'editor' && role !== 'owner_bot') {
    const access = createDocumentAccessToken(slug, 'editor');
    res.cookie(shareTokenCookieName(slug), access.secret, {
      httpOnly: true, sameSite: 'lax', path: '/',
      secure: (process.env.PROOF_PUBLIC_BASE_URL || '').startsWith('https://'),
    });
  }
  res.redirect(303, `/d/${encodeURIComponent(slug)}`);
});
