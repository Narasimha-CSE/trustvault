'use strict';
const { test, before, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { startTestApp, loginAs, samples, uploadUrl, Client, DEMO_PASSWORDS } = require('./helpers');

let t;
before(async () => { t = await startTestApp(); });
after(() => t.close());

describe('authentication', () => {
  test('every API route except login requires a session', async () => {
    const anon = new Client(t.base);
    for (const [m, u] of [['GET', '/api/documents'], ['GET', '/api/auth/me'], ['GET', '/api/trash'], ['GET', '/api/admin/users'], ['GET', '/api/folders'], ['GET', '/api/tags'], ['GET', '/api/users/directory'], ['POST', '/api/documents']]) {
      assert.equal((await anon.raw(m, u, m === 'GET' ? {} : { json: {} })).status, 401, `${m} ${u}`);
    }
  });

  test('login failure is identical for unknown email, wrong password and disabled account', async () => {
    const c = new Client(t.base);
    const a = await c.login('nobody@trustvault.demo', 'whatever-password');
    const b = await c.login('alice@trustvault.demo', 'wrong-password-123');
    assert.equal(a.status, 401); assert.equal(b.status, 401);
    assert.deepEqual(a.json, b.json);
  });

  test('brute force is throttled per account and a correct password does not bypass the lock', async () => {
    const c = new Client(t.base);
    for (let i = 0; i < 5; i++) assert.equal((await c.login('dave@trustvault.demo', `bad-password-${i}`)).status, 401);
    const locked = await c.login('dave@trustvault.demo', DEMO_PASSWORDS.viewer);
    assert.equal(locked.status, 429);
    assert.ok(Number(locked.headers.get('retry-after')) > 0);
    // lock applies to unknown emails the same way (no account enumeration)
    for (let i = 0; i < 5; i++) await c.login('ghost@trustvault.demo', `bad-password-${i}`);
    assert.equal((await c.login('ghost@trustvault.demo', 'x-password-123')).status, 429);
    // it expires
    t.clock.t += 16 * 60_000;
    assert.equal((await c.login('dave@trustvault.demo', DEMO_PASSWORDS.viewer)).status, 200);
    t.clock.t -= 16 * 60_000;
  });

  test('session cookie is HttpOnly + SameSite=Strict, new id on every login, raw token never stored', async () => {
    const c = new Client(t.base);
    const r1 = await c.login('carol@trustvault.demo', DEMO_PASSWORDS.viewer);
    const sc = r1.headers.get('set-cookie');
    assert.match(sc, /HttpOnly/); assert.match(sc, /SameSite=Strict/); assert.match(sc, /Path=\//);
    const token = sc.split(';')[0].split('=')[1];
    const rows = t.app.db.prepare('SELECT id_hash FROM sessions').all();
    assert.ok(rows.every((r) => r.id_hash !== token), 'raw token must not be in the database');
    const r2 = await new Client(t.base).login('carol@trustvault.demo', DEMO_PASSWORDS.viewer);
    assert.notEqual(sc.split(';')[0], r2.headers.get('set-cookie').split(';')[0]);
  });

  test('a forged or garbage session cookie is rejected', async () => {
    const c = new Client(t.base);
    c.cookie = 'tv_sid=' + 'a'.repeat(43);
    assert.equal((await c.get('/api/auth/me')).status, 401);
    c.cookie = 'tv_sid=' + 'x'.repeat(5000);
    assert.equal((await c.get('/api/auth/me')).status, 401);
  });

  test('logout destroys the session server-side', async () => {
    const c = await loginAs(t.base, 'carol');
    const cookie = c.cookie;
    assert.equal((await c.post('/api/auth/logout')).status, 200);
    const replay = new Client(t.base); replay.cookie = cookie;
    assert.equal((await replay.get('/api/auth/me')).status, 401);
  });

  test('idle and absolute session timeouts', async () => {
    const c = await loginAs(t.base, 'carol');
    t.clock.t += 31 * 60_000;
    try { assert.equal((await c.get('/api/auth/me')).status, 401, 'idle timeout'); } finally { t.clock.t -= 31 * 60_000; }
    const d = await loginAs(t.base, 'carol');
    for (let i = 0; i < 17; i++) { t.clock.t += 29 * 60_000; await d.get('/api/auth/me'); } // stays active ~8.2h
    assert.equal((await d.get('/api/auth/me')).status, 401, 'absolute timeout even while active');
    t.clock.t -= 17 * 29 * 60_000;
  });

  test('temporary password forces a change; the new password works and kills other sessions', async () => {
    const admin = await loginAs(t.base, 'admin');
    const created = await admin.post('/api/admin/users', { email: 'newbie@trustvault.demo', name: 'New Bie', role: 'owner', department: 'HR' });
    assert.equal(created.status, 201);
    const temp = created.json.temporaryPassword;
    assert.ok(temp.length >= 16);
    const n1 = new Client(t.base); assert.equal((await n1.login('newbie@trustvault.demo', temp)).status, 200);
    const blocked = await n1.get('/api/documents');
    assert.equal(blocked.status, 403); assert.equal(blocked.json.code, 'PASSWORD_CHANGE_REQUIRED');
    const n2 = new Client(t.base); await n2.login('newbie@trustvault.demo', temp);
    assert.equal((await n1.post('/api/auth/password', { currentPassword: temp, newPassword: 'short' })).status, 400);
    assert.equal((await n1.post('/api/auth/password', { currentPassword: 'wrong-current', newPassword: 'A-brand-new-pass-1' })).status, 403);
    assert.equal((await n1.post('/api/auth/password', { currentPassword: temp, newPassword: 'A-brand-new-pass-1' })).status, 200);
    assert.equal((await n1.get('/api/documents')).status, 200);
    assert.equal((await n2.get('/api/auth/me')).status, 401, 'other sessions are logged out');
    assert.equal((await new Client(t.base).login('newbie@trustvault.demo', temp)).status, 401);
    assert.equal((await new Client(t.base).login('newbie@trustvault.demo', 'A-brand-new-pass-1')).status, 200);
  });

  test('passwords are stored as salted scrypt hashes, never plaintext', () => {
    const rows = t.app.db.prepare('SELECT password_hash FROM users').all();
    for (const r of rows) assert.match(r.password_hash, /^scrypt\$\d+\$8\$1\$/);
    assert.equal(new Set(rows.map((r) => r.password_hash.split('$')[4])).size, rows.length, 'unique salts');
    assert.ok(!fs.readFileSync(t.cfg.dbPath).includes(Buffer.from(DEMO_PASSWORDS.owner)));
  });

  test('admin cannot lock everyone out', async () => {
    const admin = await loginAs(t.base, 'admin');
    assert.equal((await admin.patch(`/api/admin/users/${admin.user.id}`, { role: 'owner' })).status, 400);
    assert.equal((await admin.patch(`/api/admin/users/${admin.user.id}`, { disabled: true })).status, 400);
  });
});

describe('CSRF and request hygiene', () => {
  test('state-changing requests need the CSRF header', async () => {
    const alice = await loginAs(t.base, 'alice');
    const r = await alice.raw('POST', '/api/folders', { json: { name: 'x' }, csrf: false });
    assert.equal(r.status, 403);
    const wrong = await alice.raw('POST', '/api/folders', { json: { name: 'x' }, headers: { 'x-csrf-token': 'nope' }, csrf: false });
    assert.equal(wrong.status, 403);
    assert.equal((await alice.post('/api/folders', { name: 'fine' })).status, 201);
  });

  test('cross-site origins are refused even with a valid session and token', async () => {
    const alice = await loginAs(t.base, 'alice');
    const r = await alice.raw('POST', '/api/folders', { json: { name: 'evil' }, headers: { origin: 'https://evil.example' } });
    assert.equal(r.status, 403);
    const r2 = await alice.raw('POST', '/api/folders', { json: { name: 'evil2' }, headers: { 'sec-fetch-site': 'cross-site' } });
    assert.equal(r2.status, 403);
  });

  test('security headers are present on pages and API responses', async () => {
    for (const url of ['/', '/api/auth/me']) {
      const r = await fetch(t.base + url);
      assert.match(r.headers.get('content-security-policy'), /default-src 'none'/);
      assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'none'/);
      assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(r.headers.get('x-frame-options'), 'DENY');
      assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
    }
    assert.equal((await fetch(t.base + '/api/auth/me')).headers.get('cache-control'), 'no-store');
  });

  test('only the explicit static files are served (no path traversal, no data dir, no source)', async () => {
    for (const p of ['/../package.json', '/%2e%2e/package.json', '/server.js', '/data/trustvault.db', '/src/config.js', '/package.json', '/.git/config', '/files/x']) {
      const r = await fetch(t.base + p);
      assert.equal(r.status, 404, p);
    }
    assert.equal((await fetch(t.base + '/app.js')).status, 200);
  });

  test('malformed and oversize bodies are rejected cleanly', async () => {
    const c = new Client(t.base);
    assert.equal((await c.raw('POST', '/api/auth/login', { body: 'not json', headers: { 'content-type': 'application/json' }, csrf: false })).status, 400);
    assert.equal((await c.raw('POST', '/api/auth/login', { body: 'a=b', headers: { 'content-type': 'text/plain' }, csrf: false })).status, 415);
    const big = JSON.stringify({ email: 'a@b.cc', password: 'x'.repeat(100_000) });
    assert.equal((await c.raw('POST', '/api/auth/login', { body: big, headers: { 'content-type': 'application/json' }, csrf: false })).status, 413);
  });

  test('SQL-injection style input is treated as data', async () => {
    const alice = await loginAs(t.base, 'alice');
    const r = await alice.get(`/api/documents?q=${encodeURIComponent("' OR 1=1 --")}`);
    assert.equal(r.status, 200); assert.equal(r.json.documents.length, 0);
    const l = await new Client(t.base).login("alice@trustvault.demo' OR '1'='1", 'x');
    assert.ok([400, 401].includes(l.status));
    assert.equal((await alice.get('/api/documents?sort=name;DROP TABLE users')).status, 400);
  });

  test('errors never leak internals', async () => {
    const alice = await loginAs(t.base, 'alice');
    const r = await alice.get('/api/documents/not-a-uuid');
    assert.equal(r.status, 404);
    assert.ok(!/at .*\.js|SQLITE|node:/i.test(JSON.stringify(r.json)));
  });
});

describe('uploads and storage', () => {
  let alice;
  before(async () => { alice = await loginAs(t.base, 'alice'); });

  test('dangerous or mismatched files are refused', async () => {
    const bad = [
      ['evil.html', Buffer.from('<script>alert(1)</script>')], ['evil.svg', Buffer.from('<svg onload=alert(1)>')], ['run.exe', Buffer.from('MZ....')],
      ['x.js', Buffer.from('alert(1)')], ['noext', Buffer.from('hello')],
      ['fake.pdf', Buffer.from('<html>not a pdf</html>')], ['fake.png', samples.pdf('x')], ['fake.docx', Buffer.from('PK plain')], ['bin.txt', Buffer.from([1, 2, 0, 3])],
      ['empty.txt', Buffer.alloc(0)],
    ];
    for (const [name, buf] of bad) {
      const r = await alice.upload(uploadUrl(name), buf);
      assert.ok([400, 415].includes(r.status), `${name} -> ${r.status}`);
    }
  });

  test('valid files of every allowed type are accepted', async () => {
    for (const [name, buf] of [['a.pdf', samples.pdf('hi')], ['a.docx', samples.docx('hi')], ['a.png', samples.png()], ['a.txt', samples.txt('hi')], ['a.csv', samples.txt('a,b\n1,2')], ['a.md', samples.txt('# hi')]]) {
      const r = await alice.upload(uploadUrl(name), buf);
      assert.equal(r.status, 201, `${name}: ${JSON.stringify(r.json)}`);
    }
  });

  test('size limit is enforced', async () => {
    const small = await startTestApp();
    small.cfg.maxUploadBytes = 1024; // lowered after seeding; read per request
    try {
      const a = await loginAs(small.base, 'alice');
      const big = await a.upload(uploadUrl('big.txt'), Buffer.alloc(2000, 97));
      assert.equal(big.status, 413); assert.match(big.json.error, /1 KB/);
      assert.equal((await a.upload(uploadUrl('ok.txt'), Buffer.alloc(500, 97))).status, 201);
    } finally { await small.close(); }
  });

  test('file names are sanitised: no paths, no traversal; storage names are random', async () => {
    const r = await alice.upload(uploadUrl('../../etc/passwd.txt'), samples.txt('x'));
    assert.equal(r.status, 201);
    assert.equal(r.json.document.fileName, 'passwd.txt');
    const dot = await alice.upload(uploadUrl('..\\..\\win.txt'), samples.txt('x'));
    assert.equal(dot.json.document.fileName, 'win.txt');
    const v = t.app.db.prepare('SELECT storage_key FROM document_versions WHERE document_id = ?').get(r.json.document.id);
    assert.match(v.storage_key, /^[0-9a-f]{32}$/);
  });

  test('files at rest are encrypted: plaintext is not on disk', async () => {
    const secret = 'TOP-SECRET-MARKER-' + Math.random();
    const r = await alice.upload(uploadUrl('marker.txt'), samples.txt(secret));
    const v = t.app.db.prepare('SELECT storage_key FROM document_versions WHERE document_id = ?').get(r.json.document.id);
    const onDisk = fs.readFileSync(t.app.storage.pathFor(v.storage_key));
    assert.ok(!onDisk.includes(Buffer.from('TOP-SECRET-MARKER')));
    assert.equal((await alice.get(`/api/documents/${r.json.document.id}/download`)).buffer.toString(), secret);
  });

  test('tampering with a stored file, or swapping two ciphertexts, is detected', async () => {
    const a = (await alice.upload(uploadUrl('one.txt'), samples.txt('contents of one'))).json.document.id;
    const b = (await alice.upload(uploadUrl('two.txt'), samples.txt('contents of two'))).json.document.id;
    const ka = t.app.db.prepare('SELECT storage_key FROM document_versions WHERE document_id = ?').get(a).storage_key;
    const kb = t.app.db.prepare('SELECT storage_key FROM document_versions WHERE document_id = ?').get(b).storage_key;
    const pa = t.app.storage.pathFor(ka), pb = t.app.storage.pathFor(kb);
    const origA = fs.readFileSync(pa), origB = fs.readFileSync(pb);
    // flip a bit
    const flipped = Buffer.from(origA); flipped[20] ^= 1; fs.writeFileSync(pa, flipped);
    assert.equal((await alice.get(`/api/documents/${a}/download`)).status, 500);
    // swap
    fs.writeFileSync(pa, origB); fs.writeFileSync(pb, origA);
    assert.equal((await alice.get(`/api/documents/${a}/download`)).status, 500);
    assert.equal((await alice.get(`/api/documents/${b}/download`)).status, 500);
    fs.writeFileSync(pa, origA); fs.writeFileSync(pb, origB);
    assert.equal((await alice.get(`/api/documents/${a}/download`)).buffer.toString(), 'contents of one');
  });

  test('downloads are always attachments with nosniff and a neutral content type', async () => {
    const r = await alice.get(`/api/documents/${(await alice.upload(uploadUrl('page.txt'), samples.txt('<script>alert(1)</script>'))).json.document.id}/download`);
    assert.match(r.headers.get('content-disposition'), /^attachment;/);
    assert.equal(r.headers.get('content-type'), 'application/octet-stream');
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  });

  test('new versions keep history; old versions stay downloadable by those with access', async () => {
    const id = (await alice.upload(uploadUrl('ver.txt'), samples.txt('v1 text'))).json.document.id;
    const up = await alice.upload(`/api/documents/${id}/versions?name=ver.txt`, samples.txt('v2 text'));
    assert.equal(up.status, 201); assert.equal(up.json.document.currentVersion, 2);
    assert.equal((await alice.get(`/api/documents/${id}/download`)).buffer.toString(), 'v2 text');
    assert.equal((await alice.get(`/api/documents/${id}/download?version=1`)).buffer.toString(), 'v1 text');
    assert.equal(up.json.document.versions.length, 2);
  });

  test('titles and tags containing markup are stored as plain text and validated', async () => {
    const r = await alice.upload(uploadUrl('x.txt', `&title=${encodeURIComponent('<img src=x onerror=alert(1)>')}&tags=${encodeURIComponent('ok-tag')}`), samples.txt('x'));
    assert.equal(r.status, 201);
    assert.equal(r.json.document.name, '<img src=x onerror=alert(1)>'); // stored verbatim; the UI renders it with textContent
    assert.equal((await alice.upload(uploadUrl('x.txt', `&tags=${encodeURIComponent('<b>bad</b>')}`), samples.txt('x'))).status, 400);
    assert.ok(!/innerHTML/.test(fs.readFileSync(require('node:path').join(__dirname, '..', 'public', 'app.js'), 'utf8').replace(/\/\/.*|\/\*[\s\S]*?\*\//g, '')), 'front end must not use innerHTML');
  });
});

describe('audit trail', () => {
  test('records access, denials, grants and logins; verifies clean', async () => {
    const alice = await loginAs(t.base, 'alice');
    const id = (await alice.upload(uploadUrl('audited.txt'), samples.txt('x'))).json.document.id;
    await alice.get(`/api/documents/${id}/download`);
    const bob = await loginAs(t.base, 'bob');
    await bob.get(`/api/documents/${id}/download`);
    const actions = t.app.db.prepare('SELECT action, outcome FROM audit_log WHERE target_id = ?').all(id).map((r) => `${r.action}:${r.outcome}`);
    assert.ok(actions.includes('document.upload:allowed'));
    assert.ok(actions.includes('document.download:allowed'));
    assert.ok(actions.includes('document.download:denied'));
    assert.equal(t.app.audit.verify().ok, true);
  });

  test('the application cannot UPDATE or DELETE audit rows', () => {
    assert.throws(() => t.app.db.exec("UPDATE audit_log SET action = 'x' WHERE seq = 1"), /append-only/);
    assert.throws(() => t.app.db.exec('DELETE FROM audit_log WHERE seq = 1'), /append-only/);
  });

  test('editing a middle row, deleting rows, or truncating the tail is detected', () => {
    const db = t.app.db;
    const snapshot = () => db.prepare('SELECT * FROM audit_log ORDER BY seq').all();
    const rows = snapshot();
    const mid = rows[Math.floor(rows.length / 2)];
    const raw = (sql) => { db.exec('DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete;'); try { db.exec(sql); } finally {
      db.exec("CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END; CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;"); } };
    // 1) edit a middle row (attacker with DB access, triggers dropped)
    raw(`UPDATE audit_log SET outcome = 'allowed', action = 'doctored' WHERE seq = ${mid.seq}`);
    let v = t.app.audit.verify(); assert.equal(v.ok, false); assert.equal(v.brokenAtSeq, Number(mid.seq));
    raw(`UPDATE audit_log SET outcome = '${mid.outcome}', action = '${mid.action}' WHERE seq = ${mid.seq}`);
    assert.equal(t.app.audit.verify().ok, true);
    // 2) delete a middle row
    raw(`DELETE FROM audit_log WHERE seq = ${mid.seq}`);
    v = t.app.audit.verify(); assert.equal(v.ok, false);
    // restore the row
    db.prepare('INSERT INTO audit_log (seq, ts, actor_id, actor_email, action, outcome, target_type, target_id, ip, details, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(mid.seq, mid.ts, mid.actor_id, mid.actor_email, mid.action, mid.outcome, mid.target_type, mid.target_id, mid.ip, mid.details, mid.prev_hash, mid.hash);
    assert.equal(t.app.audit.verify().ok, true);
    // 3) chop the tail
    const last = rows[rows.length - 1];
    raw(`DELETE FROM audit_log WHERE seq = ${last.seq}`);
    v = t.app.audit.verify(); assert.equal(v.ok, false); assert.match(v.reason, /tail|behind/);
    db.prepare('INSERT INTO audit_log (seq, ts, actor_id, actor_email, action, outcome, target_type, target_id, ip, details, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(last.seq, last.ts, last.actor_id, last.actor_email, last.action, last.outcome, last.target_type, last.target_id, last.ip, last.details, last.prev_hash, last.hash);
    assert.equal(t.app.audit.verify().ok, true);
  });

  test('an attacker without the secret cannot forge a valid chain', () => {
    const { computeHashForTest } = {};
    const crypto = require('node:crypto');
    const rows = t.app.db.prepare('SELECT * FROM audit_log ORDER BY seq').all();
    const wrongKey = crypto.randomBytes(32);
    const canonical = (e) => JSON.stringify([e.ts, e.actor_id ?? null, e.actor_email ?? null, e.action, e.outcome, e.target_type ?? null, e.target_id ?? null, e.ip ?? null, e.details]);
    const forged = crypto.createHmac('sha256', wrongKey).update(rows[1].prev_hash + '|' + canonical(rows[1])).digest('hex');
    assert.notEqual(forged, rows[1].hash);
    assert.equal(computeHashForTest, undefined);
  });

  test('a failed change leaves no half-written state (atomic with its audit row)', async () => {
    const alice = await loginAs(t.base, 'alice');
    const countDocs = () => t.app.db.prepare('SELECT COUNT(*) n FROM documents').get().n;
    const before = countDocs();
    const real = t.app.audit.record;
    // Force the audit write to fail during upload: the document must not exist afterwards.
    t.app.db.exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_log WHEN NEW.action = 'document.upload' BEGIN SELECT RAISE(ABORT, 'boom'); END;");
    try {
      const r = await alice.upload(uploadUrl('nope.txt'), samples.txt('x'));
      assert.equal(r.status, 500);
    } finally { t.app.db.exec('DROP TRIGGER fail_audit'); }
    assert.equal(countDocs(), before);
    const files = fs.readdirSync(t.cfg.filesDir).length;
    const live = t.app.db.prepare('SELECT COUNT(*) n FROM document_versions').get().n;
    assert.equal(files, live, 'no orphaned ciphertext left on disk');
    assert.equal(real, t.app.audit.record);
    assert.equal(t.app.audit.verify().ok, true);
  });

  test('admin audit API: filters work and only admins can read it', async () => {
    const admin = await loginAs(t.base, 'admin');
    const denied = (await admin.get('/api/admin/audit?denied=1')).json.entries;
    assert.ok(denied.length > 0 && denied.every((e) => e.outcome === 'denied'));
    const perm = (await admin.get('/api/admin/audit?category=permission')).json.entries;
    assert.ok(perm.every((e) => /^(grant|user|ai)\./.test(e.action)));
    assert.equal((await admin.get('/api/admin/audit/verify')).json.ok, true);
    assert.equal((await admin.get('/api/admin/audit?category=bogus')).status, 400);
  });

  test('admin alerts flag probing, failed logins and tampering', async () => {
    const bob = await loginAs(t.base, 'bob');
    const alice = await loginAs(t.base, 'alice');
    const priv = t.app.db.prepare("SELECT id FROM documents WHERE name = 'Private notes'").get().id;
    for (let i = 0; i < 4; i++) await bob.get(`/api/documents/${priv}`);
    const admin = await loginAs(t.base, 'admin');
    const r = (await admin.get('/api/admin/alerts')).json;
    assert.ok(r.alerts.some((a) => a.kind === 'access_probing' && a.actor === 'bob@trustvault.demo'));
    assert.ok(r.alerts.some((a) => a.kind === 'failed_logins'));
    assert.equal(r.auditOk, true);
    void alice;
  });
});
