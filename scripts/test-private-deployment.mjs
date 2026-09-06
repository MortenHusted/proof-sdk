import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:net';
import WebSocket from 'ws';

const temp = mkdtempSync(join(tmpdir(), 'proof-private-test-'));
const reservation = createServer();
await new Promise(resolve => reservation.listen(0, '127.0.0.1', resolve));
const port = reservation.address().port;
await new Promise(resolve => reservation.close(resolve));
const base = `http://127.0.0.1:${port}`;
const instance = randomUUID();
const child = spawn(process.execPath, ['--import', 'tsx', 'server/index.ts'], {
  env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', DATABASE_PATH: join(temp, 'proof.sqlite'),
    PROOF_INSTANCE_TOKEN: instance, PROOF_TAILSCALE_USERS: 'MortenHusted@github,2biias@github', PROOF_LIBRARY_USER: 'MortenHusted@github', PROOF_REQUIRE_DOCUMENT_TOKEN: process.env.PROOF_REQUIRE_DOCUMENT_TOKEN ?? 'true',
    PROOF_PUBLIC_BASE_URL: base, COLLAB_PUBLIC_BASE_URL: `ws://127.0.0.1:${port}/ws`,
    PROOF_CORS_ALLOW_ORIGINS: base, PROOF_COLLAB_SIGNING_SECRET: randomUUID() },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let diagnostic = '';
child.stdout.on('data', data => { diagnostic += data; });
child.stderr.on('data', data => { diagnostic += data; });
const instanceHeaders = { 'X-Proof-Instance-Token': instance, 'Content-Type': 'application/json' };
async function request(path, token, options = {}) {
  return fetch(base + path, { ...options, headers: { ...instanceHeaders,
    ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers } });
}
try {
  let ready = false;
  for (let attempt = 0; attempt < 120; attempt++) {
    if (child.exitCode !== null) throw new Error('Test server exited during startup');
    try { ready = (await request('/health')).ok; } catch {}
    if (ready) break;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  assert.ok(ready, 'server must start');
  assert.equal((await fetch(base + '/health', { headers: { Accept: 'application/json' } })).status, 401);
  const create = async title => {
    const response = await request('/documents', null, { method: 'POST', body: JSON.stringify({ title, markdown: '# Private fixture\n\nShared paragraph.' }) });
    assert.equal(response.status, 200);
    return response.json();
  };
  const doc = await create('Private access fixture');
  const other = await create('Other capability fixture');
  assert.ok(doc.tokenUrl.startsWith(base + '/d/'));
  const paths = [`/d/${doc.slug}`, `/api/documents/${doc.slug}`, `/documents/${doc.slug}`,
    `/documents/${doc.slug}/state`, `/documents/${doc.slug}/snapshot`,
    `/documents/${doc.slug}/bridge/state`, `/og/share/${doc.slug}.png`];
  for (const path of paths) {
    for (const token of [null, 'invalid', other.accessToken]) {
      const response = await request(path, token, { headers: { 'X-Proof-Instance-Token': '', 'Tailscale-User-Login': 'MortenHusted@github' } });
      assert.equal(response.status, 401, `${path} must reject absent/invalid/cross-document capability`);
      assert.ok(!(await response.text()).includes('Shared paragraph'));
    }
  }
  assert.equal((await request(`/documents/${doc.slug}`, doc.accessToken)).status, 200);
  const editor = await request(`/d/${doc.slug}?token=${encodeURIComponent(doc.accessToken)}`, null, { headers: { Accept: 'text/html', 'User-Agent': 'Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36' } });
  assert.equal(editor.status, 200);
  assert.ok(/assets\/editor\.js/.test(await editor.text()), 'browser receives built editor');
  assert.equal((await request('/assets/editor.js')).status, 200);
  const agentIndex = await request('/', null, { headers: { Accept: 'application/json' } });
  assert.equal(agentIndex.status, 200);
  assert.deepEqual(new Set((await agentIndex.json()).documents.map(d => d.slug)), new Set([doc.slug, other.slug]));
  for (const fixture of [doc, other]) {
    assert.equal((await request(`/documents/${fixture.slug}`)).status, 200, 'agent reads every document without a document token');
    assert.equal((await request(`/documents/${fixture.slug}/state`)).status, 200);
  }
  const ownerHeaders = { 'Tailscale-User-Login': 'MortenHusted@github' };
  const library = await fetch(base + '/', { headers: ownerHeaders });
  assert.equal(library.status, 200);
  const html = await library.text();
  assert.ok(html.includes('Private access fixture') && html.includes('Other capability fixture'));
  assert.ok(html.includes('New document'));
  assert.ok(!html.includes(doc.accessToken), 'library does not embed capabilities');
  for (const headers of [{ 'Tailscale-User-Login': '2biias@github' }]) {
    assert.equal((await fetch(base + '/', { headers })).status, 403);
    assert.equal((await fetch(base + `/library/open/${doc.slug}`, { headers, redirect: 'manual' })).status, 403);
  }
  const opened = await fetch(base + `/library/open/${doc.slug}`, { headers: ownerHeaders, redirect: 'manual' });
  assert.equal(opened.status, 303);
  assert.equal(opened.headers.get('location'), `/d/${doc.slug}`);
  const setCookie = opened.headers.get('set-cookie');
  assert.ok(setCookie?.includes('HttpOnly') && setCookie.includes('SameSite=Lax'));
  const cookieHeaders = { ...ownerHeaders, Cookie: setCookie.split(';')[0] };
  const cleanEditor = await fetch(base + `/d/${doc.slug}`, { headers: { ...cookieHeaders, Accept: 'text/html', 'User-Agent': 'Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36' } });
  assert.equal(cleanEditor.status, 200);
  assert.ok((await cleanEditor.text()).includes('assets/editor.js'));
  const reopened = await fetch(base + `/library/open/${doc.slug}`, { headers: cookieHeaders, redirect: 'manual' });
  assert.equal(reopened.headers.get('set-cookie'), null, 'reuse existing document access');
  assert.equal((await fetch(base + '/library/open/missing-document', { headers: ownerHeaders })).status, 404);
  for (const user of ['MortenHusted@github', '2biias@github']) {
    assert.equal((await fetch(base + '/health', { headers: { 'Tailscale-User-Login': user } })).status, 200);
  }
  assert.equal((await fetch(base + '/health', { headers: { 'Tailscale-User-Login': 'other@github' } })).status, 401);
  const crossOrigin = await fetch(base + '/documents', { method: 'POST', headers: {
    'Tailscale-User-Login': 'MortenHusted@github', Origin: 'https://untrusted.example', 'Content-Type': 'application/json',
  }, body: JSON.stringify({ markdown: 'must not be created' }) });
  assert.equal(crossOrigin.status, 403, 'browser writes must reject foreign origins');
  const refused = await new Promise(resolve => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws?slug=${doc.slug}&token=${doc.accessToken}`);
    ws.on('unexpected-response', (_request, response) => { response.resume(); resolve(response.statusCode); });
    ws.on('error', () => {});
    ws.on('open', () => { ws.close(); resolve(101); });
  });
  assert.equal(refused, 401, 'WebSocket must enforce instance authentication');
  console.log('Private deployment: owner library and clean editor links, HTTP capabilities, cross-document denial, built editor/assets, Tailscale users, foreign-origin denial, and WebSocket admission passed.');
} finally {
  child.kill('SIGTERM');
  await new Promise(resolve => { if (child.exitCode !== null) resolve(); else child.once('exit', resolve); });
  rmSync(temp, { recursive: true, force: true });
}
