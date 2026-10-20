'use strict';
const { test, before, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const { startTestApp, loginAs, samples, uploadUrl, Client } = require('./helpers');
const { effectivePermission, readableWhere } = require('../src/authz');

let t, alice, bob, carol, dave, partner, admin;
const find = (c, q) => c.get(`/api/documents?q=${encodeURIComponent(q)}`).then((r) => r.json.documents[0]);
const idOf = (name) => t.app.db.prepare('SELECT id FROM documents WHERE name = ?').get(name).id;

before(async () => {
  // Long sessions here: these tests move the clock by weeks to prove expiry. Session expiry has its own test (security.test.js).
  t = await startTestApp({ sessionIdleMs: 3650 * 86400_000, sessionAbsoluteMs: 3650 * 86400_000 });
  [alice, bob, carol, dave, partner, admin] = await Promise.all(['alice', 'bob', 'carol', 'dave', 'partner', 'admin'].map((w) => loginAs(t.base, w)));
});
after(() => t.close());

describe('one user cannot reach another user\'s documents', () => {
  test('a user with no grant gets 404 on view, download, versions, edit, share, delete (same as a missing id)', async () => {
    const priv = idOf('Private notes'); // alice only
    const missing = '00000000-0000-4000-8000-000000000000';
    const probes = [
      ['GET', `/api/documents/${priv}`], ['GET', `/api/documents/${priv}/download`], ['GET', `/api/documents/${priv}/grants`],
      ['GET', `/api/documents/${priv}/activity`],
    ];
    for (const who of [bob, carol, dave, partner]) {
      for (const [m, u] of probes) {
        const real = await who.raw(m, u);
        const fake = await who.raw(m, u.replace(priv, missing));
        assert.equal(real.status, fake.status, `${m} ${u} should look identical to a missing document`);
        assert.ok([403, 404].includes(real.status));
      }
    }
    for (const who of [bob]) {
      assert.equal((await who.patch(`/api/documents/${priv}`, { name: 'pwned' })).status, 404);
      assert.equal((await who.del(`/api/documents/${priv}`)).status, 404);
      assert.equal((await who.post(`/api/documents/${priv}/grants`, { userId: bob.user.id, permission: 'read' })).status, 404);
      assert.equal((await who.upload(`/api/documents/${priv}/versions?name=x.txt`, samples.txt('x'))).status, 404);
      assert.equal((await who.post(`/api/documents/${priv}/ai/suggest`)).status, 404);
    }
    // and nothing changed
    assert.equal(t.app.db.prepare('SELECT name FROM documents WHERE id = ?').get(priv).name, 'Private notes');
  });

  test('guessing document ids via list/search/tags never reveals other people\'s documents', async () => {
    const mine = (await bob.get('/api/documents')).json.documents.map((d) => d.name);
    assert.ok(!mine.includes('Private notes'));
    assert.equal((await bob.get('/api/documents?q=Private')).json.documents.length, 0);
    assert.equal((await bob.get('/api/documents?tag=private')).json.documents.length, 0);
    const tags = (await bob.get('/api/tags')).json.tags.map((x) => x.tag);
    assert.ok(!tags.includes('private'), 'tag cloud must not leak tags of unreachable documents');
  });

  test('a version number can never reach another document\'s file', async () => {
    const priv = idOf('Private notes');
    // bob owns "Q3 audit workpapers" - using it with version params must still only serve its own files
    const q3 = idOf('Q3 audit workpapers');
    const ok = await bob.get(`/api/documents/${q3}/download?version=1`);
    assert.equal(ok.status, 200);
    assert.ok(ok.buffer.toString().includes('account,amount'));
    assert.equal((await bob.get(`/api/documents/${q3}/download?version=2`)).status, 404);
    assert.equal((await bob.get(`/api/documents/${priv}/download?version=1`)).status, 404);
  });

  test('every refused attempt is written to the audit trail', async () => {
    const priv = idOf('Private notes');
    const before = t.app.db.prepare("SELECT COUNT(*) n FROM audit_log WHERE outcome='denied' AND target_id=?").get(priv).n;
    await bob.get(`/api/documents/${priv}/download`);
    const after = t.app.db.prepare("SELECT COUNT(*) n FROM audit_log WHERE outcome='denied' AND target_id=?").get(priv).n;
    assert.equal(after, before + 1);
  });
});

describe('roles', () => {
  test('admins have NO content access, even to documents that exist', async () => {
    const priv = idOf('Private notes');
    for (const u of [`/api/documents/${priv}`, `/api/documents/${priv}/download`]) assert.equal((await admin.get(u)).status, 404);
    assert.equal((await admin.get('/api/documents')).json.documents.length, 0);
    // but can see metadata through the admin console
    const meta = await admin.get('/api/admin/documents');
    assert.equal(meta.status, 200);
    assert.ok(meta.json.documents.some((d) => d.name === 'Private notes'));
    assert.ok(!JSON.stringify(meta.json).includes('storage_key'));
  });

  test('admins cannot be granted documents', async () => {
    const r = await alice.post(`/api/documents/${idOf('Private notes')}/grants`, { userId: admin.user.id, permission: 'read' });
    assert.equal(r.status, 400);
  });

  test('viewers are read-only: cannot upload, edit, version, share or delete, even their own grants', async () => {
    assert.equal((await carol.upload(uploadUrl('x.txt'), samples.txt('x'))).status, 403);
    const salary = idOf('Salary letter - A. Example'); // carol has READ
    assert.equal((await carol.get(`/api/documents/${salary}/download`)).status, 200);
    assert.equal((await carol.patch(`/api/documents/${salary}`, { name: 'x' })).status, 403);
    assert.equal((await carol.del(`/api/documents/${salary}`)).status, 403);
    assert.equal((await carol.post(`/api/documents/${salary}/grants`, { userId: dave.user.id, permission: 'read' })).status, 403);
    assert.equal((await carol.get('/api/folders')).status, 403);
  });

  test('a viewer with a forged "edit" grant row is still capped at read', async () => {
    const doc = idOf('Employee handbook 2026');
    t.app.db.prepare("UPDATE grants SET permission='edit' WHERE document_id=? AND grantee_id=?").run(doc, dave.user.id);
    try {
      assert.equal((await dave.get(`/api/documents/${doc}`)).json.document.myPermission, 'read');
      assert.equal((await dave.patch(`/api/documents/${doc}`, { name: 'x' })).status, 403);
    } finally {
      t.app.db.prepare("UPDATE grants SET permission='read' WHERE document_id=? AND grantee_id=?").run(doc, dave.user.id);
    }
  });

  test('an owner with only a READ grant cannot edit; with EDIT can edit but not share or delete', async () => {
    const salary = idOf('Salary letter - A. Example'); // bob has read
    assert.equal((await bob.patch(`/api/documents/${salary}`, { name: 'x' })).status, 403);
    const q3 = idOf('Q3 audit workpapers'); // alice has edit
    assert.equal((await alice.patch(`/api/documents/${q3}`, { description: 'edited by alice' })).status, 200);
    assert.equal((await alice.get(`/api/documents/${q3}/grants`)).status, 403, 'editors cannot see or manage sharing');
    assert.equal((await alice.del(`/api/documents/${q3}`)).status, 403);
    assert.equal((await alice.post(`/api/documents/${q3}/grants`, { userId: dave.user.id, permission: 'read' })).status, 403);
    assert.equal((await alice.patch(`/api/documents/${q3}`, { folderId: null })).status, 403, 'only the owner moves a document');
  });

  test('role gates are enforced server-side on admin routes', async () => {
    for (const who of [alice, carol, partner]) {
      assert.equal((await who.get('/api/admin/users')).status, 403);
      assert.equal((await who.get('/api/admin/audit')).status, 403);
      assert.equal((await who.post('/api/admin/users', { email: 'x@y.zz', name: 'x', role: 'admin' })).status, 403);
    }
    assert.equal((await admin.get('/api/users/directory')).status, 200);
    assert.equal((await carol.get('/api/users/directory')).status, 403);
  });
});

describe('revocation, expiry, trash', () => {
  test('revoking takes effect on the very next request', async () => {
    const doc = idOf('Employee handbook 2026');
    assert.equal((await dave.get(`/api/documents/${doc}/download`)).status, 200);
    const g = (await alice.get(`/api/documents/${doc}/grants`)).json.grants.find((x) => x.status === 'active');
    assert.equal((await alice.del(`/api/documents/${doc}/grants/${g.id}`)).status, 200);
    assert.equal((await dave.get(`/api/documents/${doc}/download`)).status, 404);
    assert.equal((await dave.get(`/api/documents/${doc}`)).status, 404);
    assert.ok(!(await dave.get('/api/documents')).json.documents.some((d) => d.id === doc));
    // restore for later tests
    await alice.post(`/api/documents/${doc}/grants`, { userId: dave.user.id, permission: 'read' });
  });

  test('access ends automatically at the expiry time', async () => {
    const doc = idOf('Salary letter - A. Example'); // bob has a 30-day grant
    assert.equal((await bob.get(`/api/documents/${doc}`)).status, 200);
    t.clock.t += 31 * 86400_000;
    try {
      assert.equal((await bob.get(`/api/documents/${doc}`)).status, 404);
      assert.ok(!(await bob.get('/api/documents')).json.documents.some((d) => d.id === doc));
      const row = (await alice.get(`/api/documents/${doc}/grants`)).json.grants.find((g) => g.grantee.id === bob.user.id);
      assert.equal(row.status, 'expired');
    } finally { t.clock.t -= 31 * 86400_000; }
  });

  test('trashing a document cuts off everyone, removes grants, and restore does not re-expose it', async () => {
    const up = await alice.upload(uploadUrl('trash-me.txt'), samples.txt('secret'));
    const id = up.json.document.id;
    await alice.post(`/api/documents/${id}/grants`, { userId: carol.user.id, permission: 'read' });
    assert.equal((await carol.get(`/api/documents/${id}/download`)).status, 200);
    assert.equal((await alice.del(`/api/documents/${id}`)).status, 200);
    assert.equal((await carol.get(`/api/documents/${id}/download`)).status, 404);
    assert.ok((await alice.get('/api/trash')).json.documents.some((d) => d.id === id));
    assert.equal((await alice.post(`/api/documents/${id}/restore`)).status, 200);
    assert.equal((await carol.get(`/api/documents/${id}/download`)).status, 404, 'restored documents are private again');
    // purge
    await alice.del(`/api/documents/${id}`);
    assert.equal((await alice.del(`/api/documents/${id}/purge`)).status, 200);
    assert.equal(t.app.db.prepare('SELECT COUNT(*) n FROM document_versions WHERE document_id=?').get(id).n, 0);
  });

  test('trash retention purges old documents and their encrypted files', async () => {
    const up = await alice.upload(uploadUrl('old.txt'), samples.txt('old'));
    const id = up.json.document.id;
    const key = t.app.db.prepare('SELECT storage_key FROM document_versions WHERE document_id=?').get(id).storage_key;
    const fs = require('node:fs');
    assert.ok(fs.existsSync(t.app.storage.pathFor(key)));
    await alice.del(`/api/documents/${id}`);
    t.clock.t += 31 * 86400_000;
    try { assert.equal(t.app.runMaintenance().purged >= 1, true); } finally { t.clock.t -= 31 * 86400_000; }
    assert.ok(!fs.existsSync(t.app.storage.pathFor(key)));
  });

  test('a disabled user is locked out immediately, including existing sessions', async () => {
    const c = await loginAs(t.base, 'dave');
    assert.equal((await c.get('/api/documents')).status, 200);
    assert.equal((await admin.patch(`/api/admin/users/${c.user.id}`, { disabled: true })).status, 200);
    assert.equal((await c.get('/api/documents')).status, 401);
    assert.equal((await new Client(t.base).login('dave@trustvault.demo', 'Viewer#Demo2026')).status, 401);
    await admin.patch(`/api/admin/users/${c.user.id}`, { disabled: false });
  });

  test('an admin can force-revoke any grant', async () => {
    const doc = idOf('Customer contract - Acme');
    assert.equal((await partner.get(`/api/documents/${doc}`)).status, 200);
    const g = (await admin.get('/api/admin/grants')).json.grants.find((x) => x.documentId === doc && x.grantee.id === partner.user.id);
    assert.equal((await admin.post(`/api/admin/grants/${g.id}/revoke`)).status, 200);
    assert.equal((await partner.get(`/api/documents/${doc}`)).status, 404);
  });
});

describe('sharing rules', () => {
  test('external people need an expiry of at most 30 days; viewers cannot get edit', async () => {
    const doc = idOf('Private notes');
    assert.equal((await alice.post(`/api/documents/${doc}/grants`, { userId: partner.user.id, permission: 'read' })).status, 400);
    assert.equal((await alice.post(`/api/documents/${doc}/grants`, { userId: partner.user.id, permission: 'read', expiresAt: Date.now() + 90 * 86400_000 })).status, 400);
    assert.equal((await alice.post(`/api/documents/${doc}/grants`, { userId: carol.user.id, permission: 'edit' })).status, 400);
    assert.equal((await alice.post(`/api/documents/${doc}/grants`, { userId: partner.user.id, permission: 'read', expiresAt: Date.now() - 1000 })).status, 400);
    const ok = await alice.post(`/api/documents/${doc}/grants`, { userId: partner.user.id, permission: 'read', expiresAt: Date.now() + 5 * 86400_000 });
    assert.equal(ok.status, 201);
    assert.equal((await partner.get(`/api/documents/${doc}/download`)).status, 200);
    await alice.del(`/api/documents/${doc}/grants/${ok.json.grant.id}`);
  });

  test('folders carry no permissions: documents in a shared-looking folder stay private', async () => {
    const f = (await alice.post('/api/folders', { name: 'Everyone' })).json.folder;
    const up = await alice.upload(uploadUrl('in-folder.txt', `&folderId=${f.id}`), samples.txt('x'));
    assert.equal((await bob.get(`/api/documents/${up.json.document.id}`)).status, 404);
    assert.equal((await bob.get(`/api/documents?folder=${f.id}`)).json.documents.length, 0);
    // someone else's folder id is rejected as if it did not exist
    assert.equal((await bob.upload(uploadUrl('x.txt', `&folderId=${f.id}`), samples.txt('x'))).status, 404);
  });

  test('the owner can see who accessed their document, including refused attempts', async () => {
    const doc = idOf('Private notes');
    await bob.get(`/api/documents/${doc}/download`);
    const act = (await alice.get(`/api/documents/${doc}/activity`)).json.activity;
    assert.ok(act.some((a) => a.outcome === 'denied' && a.actor === 'bob@trustvault.demo'));
  });
});

describe('list/search SQL agrees with the single authorisation function (every user x every document)', () => {
  test('exhaustive agreement', () => {
    const users = t.app.db.prepare('SELECT * FROM users').all();
    const docs = t.app.db.prepare('SELECT * FROM documents').all();
    for (const u of users) {
      const w = readableWhere(t.cfg, u);
      const sqlSet = new Set(t.app.db.prepare(`SELECT d.id FROM documents d WHERE ${w.sql}`).all(w.params).map((r) => r.id));
      for (const d of docs) {
        const viaFn = !!effectivePermission(t.app.db, t.cfg, u, d);
        assert.equal(sqlSet.has(d.id), viaFn, `${u.email} / ${d.name}`);
      }
    }
  });
});
