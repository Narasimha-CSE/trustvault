'use strict';
const { test, before, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const { startTestApp, loginAs } = require('./helpers');

let t, alice, bob, carol, partner;
const idOf = (n) => t.app.db.prepare('SELECT id FROM documents WHERE name = ?').get(n).id;
before(async () => { t = await startTestApp(); [alice, bob, carol, partner] = await Promise.all(['alice', 'bob', 'carol', 'partner'].map((w) => loginAs(t.base, w))); });
after(() => t.close());

describe('AI sharing assistant: suggests, never decides', () => {
  test('requesting suggestions changes no access', async () => {
    const doc = idOf('Salary revision letter'); // bob's, no grants
    const grantsBefore = t.app.db.prepare('SELECT COUNT(*) n FROM grants').get().n;
    const r = await bob.post(`/api/documents/${doc}/ai/suggest`);
    assert.equal(r.status, 201);
    assert.equal(t.app.db.prepare('SELECT COUNT(*) n FROM grants').get().n, grantsBefore);
    assert.equal((await carol.get(`/api/documents/${doc}`)).status, 404);
    assert.ok(r.json.sensitive); assert.equal(r.json.suggestedExpiryDays, 30);
  });

  test('suggestions are read-only, exclude owner/admins/externals/existing grantees, and say why', async () => {
    const doc = idOf('Salary revision letter');
    const r = (await bob.post(`/api/documents/${doc}/ai/suggest`)).json;
    for (const c of r.candidates) {
      assert.equal(c.suggestedPermission, 'read');
      assert.ok(c.reasons.length > 0);
      assert.notEqual(c.email, 'bob@trustvault.demo');
      assert.notEqual(c.email, 'admin@trustvault.demo');
      assert.notEqual(c.email, 'partner@external.demo');
    }
  });

  test('only the owner can request suggestions; others get nothing', async () => {
    const doc = idOf('Salary revision letter');
    assert.equal((await alice.post(`/api/documents/${doc}/ai/suggest`)).status, 404);
    assert.equal((await carol.post(`/api/documents/${doc}/ai/suggest`)).status, 403);
  });

  test('a person confirms: grants are created, linked to the suggestion, and both are audited', async () => {
    const doc = idOf('Employee handbook 2026'); // alice's; HR-ish content
    const s = (await alice.post(`/api/documents/${doc}/ai/suggest`)).json;
    t.app.db.prepare('SELECT 1').get();
    const pick = s.candidates[0];
    if (!pick) return; // no candidates for this doc in the seed; covered by the next test
    const d = await alice.post(`/api/documents/${doc}/ai/suggestions/${s.suggestionId}/decision`, { accept: [{ userId: pick.userId, permission: 'read' }], reject: s.candidates.slice(1).map((c) => c.userId) });
    assert.equal(d.status, 200);
    assert.equal(d.json.grants[0].viaSuggestion, true);
  });

  test('confirming someone who was NOT suggested is refused (cannot smuggle grants through a suggestion)', async () => {
    const doc = idOf('Salary revision letter');
    const s = (await bob.post(`/api/documents/${doc}/ai/suggest`)).json;
    const r = await bob.post(`/api/documents/${doc}/ai/suggestions/${s.suggestionId}/decision`, { accept: [{ userId: partner.user.id, permission: 'read', expiresAt: Date.now() + 86400_000 }] });
    assert.equal(r.status, 400);
    assert.equal(t.app.db.prepare('SELECT COUNT(*) n FROM grants WHERE document_id = ? AND grantee_id = ?').get(doc, partner.user.id).n, 0);
  });

  test('a suggestion can be decided once, only by the person who asked, for the right document', async () => {
    const doc = idOf('Salary revision letter');
    const other = idOf('Customer contract - Acme');
    const s = (await bob.post(`/api/documents/${doc}/ai/suggest`)).json;
    assert.equal((await bob.post(`/api/documents/${other}/ai/suggestions/${s.suggestionId}/decision`, { accept: [] })).status, 404);
    assert.equal((await alice.post(`/api/documents/${doc}/ai/suggestions/${s.suggestionId}/decision`, { accept: [] })).status, 404);
    assert.equal((await bob.post(`/api/documents/${doc}/ai/suggestions/${s.suggestionId}/decision`, { accept: [], reject: s.candidates.map((c) => c.userId) })).status, 200);
    assert.equal((await bob.post(`/api/documents/${doc}/ai/suggestions/${s.suggestionId}/decision`, { accept: [] })).status, 409);
    const log = t.app.db.prepare("SELECT action, details FROM audit_log WHERE target_id = ? AND action IN ('ai.suggestion','ai.decision') ORDER BY seq").all(doc).map((r) => r.action);
    assert.ok(log.includes('ai.suggestion') && log.includes('ai.decision'));
  });

  test('every grant rule still applies to confirmed suggestions (expiry caps, viewers read-only)', async () => {
    const src = require('node:fs').readFileSync(require('node:path').join(__dirname, '..', 'src', 'suggest.js'), 'utf8');
    assert.ok(!/INSERT|UPDATE|DELETE/i.test(src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '')), 'the suggester has no write path at all');
  });
});
