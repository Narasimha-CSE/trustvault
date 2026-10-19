'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadConfig } = require('../src/config');
const { createApp } = require('../src/app');
const { seedDemo, DEMO_PASSWORDS } = require('../src/bootstrap');
const samples = require('../scripts/samples');

/** Starts a real server on an ephemeral port with a throw-away data dir and a controllable clock. */
async function startTestApp(overrides = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-test-'));
  const clock = { t: Date.now() };
  const cfg = loadConfig({
    dataDir, port: 0, secret: 'test-secret-test-secret-test-secret-123', scryptCost: 1024,
    now: () => clock.t, maintenanceIntervalMs: 0, ...overrides,
  });
  const app = createApp(cfg);
  if (overrides.seed !== false) await seedDemo(app);
  const port = await app.start();
  const base = `http://127.0.0.1:${port}`;
  return { app, cfg, base, clock, dataDir, close: () => app.close().then(() => fs.rmSync(dataDir, { recursive: true, force: true })) };
}

/** A tiny HTTP client that behaves like a browser: keeps the session cookie and sends the CSRF header. */
class Client {
  constructor(base) { this.base = base; this.cookie = null; this.csrf = null; this.user = null; }

  async raw(method, url, { json, body, headers = {}, csrf = true } = {}) {
    const h = { ...headers };
    if (this.cookie) h.cookie = this.cookie;
    if (csrf && this.csrf && method !== 'GET') h['x-csrf-token'] = this.csrf;
    let payload = body;
    if (json !== undefined) { payload = JSON.stringify(json); h['content-type'] = 'application/json'; }
    const res = await fetch(this.base + url, { method, headers: h, body: payload, redirect: 'manual' });
    const buf = Buffer.from(await res.arrayBuffer());
    let parsed = null;
    if ((res.headers.get('content-type') || '').includes('application/json')) { try { parsed = JSON.parse(buf.toString('utf8')); } catch { /* ignore */ } }
    return { status: res.status, json: parsed, headers: res.headers, buffer: buf };
  }

  async login(email, password) {
    const r = await this.raw('POST', '/api/auth/login', { json: { email, password }, csrf: false });
    if (r.status === 200) {
      const sc = r.headers.get('set-cookie');
      this.cookie = sc.split(';')[0];
      this.csrf = r.json.csrfToken;
      this.user = r.json.user;
    }
    return r;
  }

  get(url) { return this.raw('GET', url); }
  post(url, json) { return this.raw('POST', url, { json: json ?? {} }); }
  patch(url, json) { return this.raw('PATCH', url, { json }); }
  del(url) { return this.raw('DELETE', url); }
  upload(url, buffer, { csrf = true, type = 'application/octet-stream' } = {}) {
    return this.raw('POST', url, { body: buffer, headers: { 'content-type': type }, csrf });
  }
}

async function loginAs(base, who) {
  const map = {
    admin: ['admin@trustvault.demo', DEMO_PASSWORDS.admin],
    alice: ['alice@trustvault.demo', DEMO_PASSWORDS.owner],
    bob: ['bob@trustvault.demo', DEMO_PASSWORDS.owner],
    carol: ['carol@trustvault.demo', DEMO_PASSWORDS.viewer],
    dave: ['dave@trustvault.demo', DEMO_PASSWORDS.viewer],
    partner: ['partner@external.demo', DEMO_PASSWORDS.external],
  };
  const c = new Client(base);
  const r = await c.login(...map[who]);
  if (r.status !== 200) throw new Error(`login failed for ${who}: ${r.status} ${JSON.stringify(r.json)}`);
  return c;
}

const uploadUrl = (name, extra = '') => `/api/documents?name=${encodeURIComponent(name)}${extra}`;

module.exports = { startTestApp, Client, loginAs, samples, uploadUrl, DEMO_PASSWORDS };
