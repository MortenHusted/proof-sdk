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
    PROOF_INSTANCE_TOKEN: instance, PROOF_REQUIRE_DOCUMENT_TOKEN: process.env.PROOF_REQUIRE_DOCUMENT_TOKEN ?? 'true',
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
      const response = await request(path, token);
      assert.equal(response.status, 401, `${path} must reject absent/invalid/cross-document capability`);
      assert.ok(!(await response.text()).includes('Shared paragraph'));
    }
  }
  assert.equal((await request(`/documents/${doc.slug}`, doc.accessToken)).status, 200);
  const editor = await request(`/d/${doc.slug}?token=${encodeURIComponent(doc.accessToken)}`, null, { headers: { Accept: 'text/html', 'User-Agent': 'Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36' } });
  assert.equal(editor.status, 200);
  assert.ok(/assets\/editor\.js/.test(await editor.text()), 'browser receives built editor');
  assert.equal((await request('/assets/editor.js')).status, 200);
  const login = await fetch(base + '/_instance/login', { method: 'POST', redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ password: instance }) });
  assert.equal(login.status, 303);
  const cookie = login.headers.get('set-cookie');
  assert.match(cookie, /HttpOnly/i);
  assert.match(cookie, /SameSite=Strict/i);
  const refused = await new Promise(resolve => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws?slug=${doc.slug}&token=${doc.accessToken}`);
    ws.on('unexpected-response', (_request, response) => { response.resume(); resolve(response.statusCode); });
    ws.on('error', () => {});
    ws.on('open', () => { ws.close(); resolve(101); });
  });
  assert.equal(refused, 401, 'WebSocket must enforce instance authentication');
  console.log('Private deployment: HTTP capabilities, cross-document denial, built editor/assets, login cookie, and WebSocket admission passed.');
} finally {
  child.kill('SIGTERM');
  await new Promise(resolve => { if (child.exitCode !== null) resolve(); else child.once('exit', resolve); });
  rmSync(temp, { recursive: true, force: true });
}
