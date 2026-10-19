'use strict';
/** First-run setup: create the first administrator, or load clearly-labelled demo data. */
const crypto = require('node:crypto');
const { hashPassword } = require('./crypto');
const { validateUpload } = require('./validate');
const { sha256Hex } = require('./crypto');

const DAY = 86400_000;

async function createUser(app, { email, name, role, department = null, isExternal = false, password, mustChange = true, by = null }) {
  const id = crypto.randomUUID();
  const hash = await hashPassword(password, app.cfg.scryptCost);
  app.db.prepare('INSERT INTO users (id, email, name, role, department, is_external, password_hash, must_change_password, created_at, created_by) VALUES (?,?,?,?,?,?,?,?,?,?)')
    .run(id, email.toLowerCase(), name, role, department, isExternal ? 1 : 0, hash, mustChange ? 1 : 0, app.cfg.now(), by);
  return app.db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function userCount(app) {
  return app.db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
}

async function createAdmin(app, email, password) {
  if (userCount(app) > 0) return null;
  const u = await createUser(app, { email, name: 'Administrator', role: 'admin', department: 'IT', password, mustChange: true });
  app.audit.record({ action: 'user.create', outcome: 'allowed', targetType: 'user', targetId: u.id, details: { email: u.email, role: 'admin', via: 'bootstrap' } });
  return u;
}

function addDocument(app, owner, { title, fileName, buffer, description = '', tags = [], ageDays = 0 }) {
  const { cfg, db, storage, audit } = app;
  const file = validateUpload(fileName, buffer, cfg.maxUploadBytes);
  const docId = crypto.randomUUID();
  const versionId = crypto.randomUUID();
  const stored = storage.put(versionId, buffer);
  const now = cfg.now() - ageDays * DAY;
  db.tx(() => {
    db.prepare('INSERT INTO documents (id, owner_id, name, description, current_version, created_at, updated_at) VALUES (?,?,?,?,?,?,?)').run(docId, owner.id, title, description, 1, now, now);
    db.prepare('INSERT INTO document_versions (id, document_id, version, storage_key, original_name, mime, size, sha256, wrapped_key, uploaded_by, uploaded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .run(versionId, docId, 1, stored.storageKey, file.name, file.mime, buffer.length, sha256Hex(buffer), stored.wrappedKey, owner.id, now);
    for (const t of tags) db.prepare('INSERT INTO document_tags (document_id, tag) VALUES (?,?)').run(docId, t);
    audit.record({ actor: owner, action: 'document.upload', outcome: 'allowed', targetType: 'document', targetId: docId, details: { name: title, file: file.name, size: buffer.length, seeded: true } });
  });
  return docId;
}

function addGrant(app, owner, docId, grantee, permission, expiresInDays = null) {
  const { cfg, db, audit } = app;
  const id = crypto.randomUUID();
  const now = cfg.now();
  db.tx(() => {
    db.prepare('INSERT INTO grants (id, document_id, grantee_id, permission, granted_by, granted_at, expires_at) VALUES (?,?,?,?,?,?,?)')
      .run(id, docId, grantee.id, permission, owner.id, now, expiresInDays ? now + expiresInDays * DAY : null);
    audit.record({ actor: owner, action: 'grant.create', outcome: 'allowed', targetType: 'document', targetId: docId, details: { grantId: id, grantee: grantee.id, granteeEmail: grantee.email, permission, expiresAt: expiresInDays ? now + expiresInDays * DAY : null, external: !!grantee.is_external, seeded: true } });
  });
  return id;
}

const DEMO_PASSWORDS = {
  admin: 'Admin#Demo2026', owner: 'Owner#Demo2026', viewer: 'Viewer#Demo2026', external: 'Partner#Demo2026',
};

/** DEMO DATA ONLY. Passwords here are public (they are in the README). Never enable on a real deployment. */
async function seedDemo(app) {
  if (userCount(app) > 0) return false;
  const samples = require('../scripts/samples');
  const mk = (email, name, role, department, password, isExternal = false) => createUser(app, { email, name, role, department, password, isExternal, mustChange: false });
  const admin = await mk('admin@trustvault.demo', 'Ada Admin', 'admin', 'IT', DEMO_PASSWORDS.admin);
  const alice = await mk('alice@trustvault.demo', 'Alice Owner', 'owner', 'HR', DEMO_PASSWORDS.owner);
  const bob = await mk('bob@trustvault.demo', 'Bob Owner', 'owner', 'Finance', DEMO_PASSWORDS.owner);
  const carol = await mk('carol@trustvault.demo', 'Carol Viewer', 'viewer', 'Legal', DEMO_PASSWORDS.viewer);
  const dave = await mk('dave@trustvault.demo', 'Dave Viewer', 'viewer', 'Engineering', DEMO_PASSWORDS.viewer);
  const partner = await mk('partner@external.demo', 'Pat Partner (external)', 'viewer', null, DEMO_PASSWORDS.external, true);
  app.audit.record({ actor: admin, action: 'seed.demo', outcome: 'info', details: { users: 6, note: 'demo data loaded' } });

  const offer = addDocument(app, alice, { title: 'Salary letter - A. Example', fileName: 'salary-letter-a-example.docx', buffer: samples.docx('Salary letter for A. Example. CONFIDENTIAL demo document.'), description: 'Annual salary letter (demo data)', tags: ['hr', 'salary', 'confidential'], ageDays: 12 });
  addGrant(app, alice, offer, carol, 'read');
  addGrant(app, alice, offer, bob, 'read', 30);
  addDocument(app, alice, { title: 'Employee handbook 2026', fileName: 'employee-handbook-2026.pdf', buffer: samples.pdf('Employee handbook 2026 (demo)'), description: 'Company-wide handbook (demo data)', tags: ['hr', 'policy'], ageDays: 20 });
  const handbook = app.db.prepare("SELECT id FROM documents WHERE name = 'Employee handbook 2026'").get().id;
  addGrant(app, alice, handbook, dave, 'read');
  addDocument(app, alice, { title: 'Private notes', fileName: 'private-notes.txt', buffer: samples.txt('Only Alice can see this. Try opening it as anyone else.\n'), description: 'Private - shared with nobody', tags: ['private'], ageDays: 3 });

  const audit1 = addDocument(app, bob, { title: 'Q3 audit workpapers', fileName: 'q3-audit-workpapers.csv', buffer: samples.txt('account,amount\nrevenue,100\ncosts,60\n'), description: 'Audit working papers (demo data)', tags: ['finance', 'audit'], ageDays: 8 });
  addGrant(app, bob, audit1, alice, 'edit', 30);
  const contract = addDocument(app, bob, { title: 'Customer contract - Acme', fileName: 'customer-contract-acme.pdf', buffer: samples.pdf('Customer contract - Acme (demo)'), description: 'Signed customer contract (demo data)', tags: ['contract', 'customer'], ageDays: 5 });
  addGrant(app, bob, contract, partner, 'read', 14);
  addGrant(app, bob, contract, carol, 'read');
  addDocument(app, bob, { title: 'Salary revision letter', fileName: 'salary-revision-letter.docx', buffer: samples.docx('Salary revision letter (demo). Try "Suggest who should see this".'), description: 'Draft - nobody has access yet', tags: ['salary'], ageDays: 1 });
  return true;
}

module.exports = { createUser, createAdmin, seedDemo, userCount, DEMO_PASSWORDS };
