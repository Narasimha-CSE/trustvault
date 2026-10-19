'use strict';
/**
 * Administration. What an admin CAN do: manage accounts, see document METADATA, see every active grant,
 * force-revoke access, read the audit trail and verify its integrity.
 * What an admin CANNOT do: read, download or edit document contents (see authz.js).
 */
const crypto = require('node:crypto');
const { HttpError, readJson, str, email, uuid, oneOf } = require('../http');
const { hashPassword, generateTempPassword } = require('../crypto');
const { publicUser } = require('./auth');

module.exports = function register(app) {
  const { db, cfg, audit } = app;
  const A = { roles: ['admin'] };

  const userRow = (u) => ({ ...publicUser(u), disabled: !!u.disabled, createdAt: u.created_at });

  // ---------- users ----------
  app.route('GET', '/api/admin/users', A, async (ctx) => {
    const rows = db.prepare('SELECT * FROM users ORDER BY name COLLATE NOCASE').all();
    audit.record({ actor: ctx.user, action: 'admin.view_users', outcome: 'info', ip: ctx.ip });
    return { body: { users: rows.map(userRow) } };
  });

  app.route('POST', '/api/admin/users', A, async (ctx) => {
    const b = await readJson(ctx.req);
    const addr = email(b.email);
    const name = str(b.name, { min: 1, max: 100, field: 'name' });
    const role = oneOf(b.role, ['admin', 'owner', 'viewer'], 'role');
    const department = b.department ? str(b.department, { max: 40, field: 'department' }) : null;
    const isExternal = b.isExternal === true;
    if (isExternal && role !== 'viewer') throw new HttpError(400, 'External people can only be viewers');
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(addr)) throw new HttpError(409, 'An account with that email already exists');
    const temp = generateTempPassword();
    const hash = await hashPassword(temp, cfg.scryptCost);
    const id = crypto.randomUUID();
    db.tx(() => {
      db.prepare('INSERT INTO users (id, email, name, role, department, is_external, password_hash, must_change_password, created_at, created_by) VALUES (?,?,?,?,?,?,?,?,?,?)')
        .run(id, addr, name, role, department, isExternal ? 1 : 0, hash, 1, cfg.now(), ctx.user.id);
      audit.record({ actor: ctx.user, action: 'user.create', outcome: 'allowed', targetType: 'user', targetId: id, ip: ctx.ip, details: { email: addr, role, external: isExternal } });
    });
    // The temporary password is shown ONCE and the user must change it at first login.
    return { status: 201, body: { user: userRow(db.prepare('SELECT * FROM users WHERE id = ?').get(id)), temporaryPassword: temp } };
  });

  function adminCount() {
    return db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0").get().n;
  }

  app.route('PATCH', '/api/admin/users/:id', A, async (ctx) => {
    const b = await readJson(ctx.req);
    const target = db.prepare('SELECT * FROM users WHERE id = ?').get(uuid(ctx.params.id, 'user id'));
    if (!target) throw new HttpError(404, 'User not found');
    const next = {
      name: b.name !== undefined ? str(b.name, { min: 1, max: 100, field: 'name' }) : target.name,
      role: b.role !== undefined ? oneOf(b.role, ['admin', 'owner', 'viewer'], 'role') : target.role,
      department: b.department !== undefined ? (b.department ? str(b.department, { max: 40, field: 'department' }) : null) : target.department,
      disabled: b.disabled !== undefined ? (b.disabled === true ? 1 : 0) : target.disabled,
    };
    if (target.is_external && next.role !== 'viewer') throw new HttpError(400, 'External people can only be viewers');
    const losesAdmin = target.role === 'admin' && !target.disabled && (next.role !== 'admin' || next.disabled);
    if (losesAdmin && (target.id === ctx.user.id || adminCount() <= 1)) {
      throw new HttpError(400, target.id === ctx.user.id ? 'You cannot remove your own admin access or disable yourself' : 'At least one active administrator must remain');
    }
    db.tx(() => {
      db.prepare('UPDATE users SET name = ?, role = ?, department = ?, disabled = ? WHERE id = ?').run(next.name, next.role, next.department, next.disabled, target.id);
      const details = {};
      if (next.role !== target.role) details.role = { from: target.role, to: next.role };
      if (next.disabled !== target.disabled) details.disabled = !!next.disabled;
      if (next.department !== target.department) details.department = { from: target.department, to: next.department };
      if (next.name !== target.name) details.name = true;
      if (next.disabled) ctx.destroySessionsFor(target.id); // disabling logs the person out on the spot
      const action = details.role ? 'user.role_change' : details.disabled !== undefined ? (next.disabled ? 'user.disable' : 'user.enable') : 'user.update';
      audit.record({ actor: ctx.user, action, outcome: 'allowed', targetType: 'user', targetId: target.id, ip: ctx.ip, details });
    });
    return { body: { user: userRow(db.prepare('SELECT * FROM users WHERE id = ?').get(target.id)) } };
  });

  app.route('POST', '/api/admin/users/:id/reset-password', A, async (ctx) => {
    const target = db.prepare('SELECT * FROM users WHERE id = ?').get(uuid(ctx.params.id, 'user id'));
    if (!target) throw new HttpError(404, 'User not found');
    const temp = generateTempPassword();
    const hash = await hashPassword(temp, cfg.scryptCost);
    db.tx(() => {
      db.prepare('UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?').run(hash, target.id);
      ctx.destroySessionsFor(target.id);
      audit.record({ actor: ctx.user, action: 'user.password_reset', outcome: 'allowed', targetType: 'user', targetId: target.id, ip: ctx.ip });
    });
    return { body: { temporaryPassword: temp } };
  });

  // ---------- documents (METADATA ONLY) and grants ----------
  app.route('GET', '/api/admin/documents', A, async (ctx) => {
    const now = cfg.now();
    const rows = db.prepare(
      `SELECT d.id, d.name, d.created_at, d.updated_at, d.deleted_at, d.current_version, u.name AS owner_name, u.email AS owner_email,
              (SELECT size FROM document_versions v WHERE v.document_id = d.id AND v.version = d.current_version) AS size,
              (SELECT COUNT(*) FROM grants g WHERE g.document_id = d.id AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > ?)) AS active_grants,
              (SELECT COUNT(*) FROM grants g JOIN users x ON x.id = g.grantee_id WHERE g.document_id = d.id AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > ?) AND x.is_external = 1) AS external_grants
       FROM documents d JOIN users u ON u.id = d.owner_id ORDER BY d.updated_at DESC LIMIT 500`
    ).all(now, now);
    audit.record({ actor: ctx.user, action: 'admin.view_documents', outcome: 'info', ip: ctx.ip, details: { count: rows.length } });
    return { body: { documents: rows.map((r) => ({ id: r.id, name: r.name, owner: { name: r.owner_name, email: r.owner_email }, size: r.size, version: r.current_version, createdAt: r.created_at, updatedAt: r.updated_at, inTrash: !!r.deleted_at, activeGrants: r.active_grants, externalGrants: r.external_grants })) } };
  });

  app.route('GET', '/api/admin/grants', A, async (ctx) => {
    const now = cfg.now();
    const rows = db.prepare(
      `SELECT g.*, d.name AS doc_name, o.name AS owner_name FROM grants g
       JOIN documents d ON d.id = g.document_id JOIN users o ON o.id = d.owner_id
       WHERE g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > ?) ORDER BY g.granted_at DESC LIMIT 500`
    ).all(now);
    audit.record({ actor: ctx.user, action: 'admin.view_grants', outcome: 'info', ip: ctx.ip, details: { count: rows.length } });
    return { body: { grants: rows.map((g) => ({ ...app.grantView(g), documentId: g.document_id, documentName: g.doc_name, owner: g.owner_name })) } };
  });

  app.route('POST', '/api/admin/grants/:id/revoke', A, async (ctx) => {
    const g = db.prepare('SELECT * FROM grants WHERE id = ?').get(uuid(ctx.params.id, 'grant id'));
    if (!g) throw new HttpError(404, 'Grant not found');
    app.revokeGrantAsAdmin(ctx, g.document_id, g.id);
    return { body: { ok: true } };
  });

  // ---------- audit trail ----------
  const CATEGORY = {
    access: ['document.download', 'document.view', 'document.upload', 'document.edit', 'document.new_version'],
    permission: ['grant.create', 'grant.change', 'grant.revoke', 'user.role_change', 'user.disable', 'user.enable', 'user.create', 'ai.suggestion', 'ai.decision'],
    auth: ['auth.login', 'auth.login_failed', 'auth.login_blocked', 'auth.logout', 'auth.password_change', 'user.password_reset'],
  };

  app.route('GET', '/api/admin/audit', A, async (ctx) => {
    const q = ctx.query;
    const where = [];
    const params = {};
    if (q.category) {
      const list = CATEGORY[q.category];
      if (!list) throw new HttpError(400, 'category must be access, permission or auth');
      where.push(`action IN (${list.map((_, i) => `:c${i}`).join(',')})`);
      list.forEach((a, i) => { params[`c${i}`] = a; });
    }
    if (q.denied === '1') where.push("outcome = 'denied'");
    if (q.action) { params.action = String(q.action).slice(0, 60); where.push('action = :action'); }
    if (q.actor) { params.actor = `%${String(q.actor).replace(/[\\%_]/g, '\\$&').slice(0, 80)}%`; where.push("actor_email LIKE :actor ESCAPE '\\'"); }
    if (q.target) { params.target = String(q.target).slice(0, 64); where.push('target_id = :target'); }
    if (q.from) { const t = Date.parse(q.from); if (!Number.isFinite(t)) throw new HttpError(400, 'from is not a date'); params.from = t; where.push('ts >= :from'); }
    if (q.to) { const t = Date.parse(q.to); if (!Number.isFinite(t)) throw new HttpError(400, 'to is not a date'); params.to = t; where.push('ts <= :to'); }
    if (q.before) { params.before = parseInt(q.before, 10) || 0; where.push('seq < :before'); }
    const limit = Math.min(Math.max(parseInt(q.limit || '100', 10) || 100, 1), 500);
    const sql = `SELECT seq, ts, actor_id, actor_email, action, outcome, target_type, target_id, ip, details FROM audit_log ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY seq DESC LIMIT ${limit}`;
    const rows = db.prepare(sql).all(params);
    return { body: { entries: rows.map((r) => ({ ...r, seq: Number(r.seq), details: JSON.parse(r.details) })) } };
  });

  app.route('GET', '/api/admin/audit/verify', A, async (ctx) => {
    const result = audit.verify();
    audit.record({ actor: ctx.user, action: 'admin.verify_audit', outcome: 'info', ip: ctx.ip, details: { ok: result.ok, checked: result.checked } });
    return { body: result };
  });

  // ---------- things worth noticing ----------
  app.route('GET', '/api/admin/alerts', A, async (ctx) => {
    const now = cfg.now();
    const hour = now - 3600_000;
    const alerts = [];

    // 1) someone probing documents they were not granted (possible ID guessing / snooping)
    const probes = db.prepare(
      `SELECT actor_email, COUNT(*) AS n, COUNT(DISTINCT target_id) AS docs FROM audit_log
       WHERE outcome = 'denied' AND target_type = 'document' AND actor_id IS NOT NULL AND ts > ? GROUP BY actor_id HAVING n >= 3`
    ).all(hour);
    for (const p of probes) alerts.push({ severity: 'high', kind: 'access_probing', message: `${p.actor_email} was refused ${p.n} times on ${p.docs} document(s) in the last hour`, actor: p.actor_email });

    // 2) locked-out / repeated failed logins
    const fails = db.prepare(`SELECT target_id AS email, COUNT(*) AS n FROM audit_log WHERE action IN ('auth.login_failed','auth.login_blocked') AND ts > ? GROUP BY target_id HAVING n >= 3`).all(hour);
    for (const f of fails) alerts.push({ severity: f.n >= 5 ? 'high' : 'medium', kind: 'failed_logins', message: `${f.n} failed or blocked sign-ins for ${f.email} in the last hour`, actor: f.email });

    // 3) bulk downloads
    const bulk = db.prepare(`SELECT actor_email, COUNT(*) AS n FROM audit_log WHERE action = 'document.download' AND outcome = 'allowed' AND ts > ? GROUP BY actor_id HAVING n >= 10`).all(now - 600_000);
    for (const b of bulk) alerts.push({ severity: 'high', kind: 'bulk_download', message: `${b.actor_email} downloaded ${b.n} files in 10 minutes`, actor: b.actor_email });

    // 4) external people who have actually downloaded something recently
    const ext = db.prepare(
      `SELECT a.actor_email, COUNT(*) AS n FROM audit_log a JOIN users u ON u.id = a.actor_id
       WHERE a.action = 'document.download' AND a.outcome = 'allowed' AND u.is_external = 1 AND a.ts > ? GROUP BY a.actor_id`
    ).all(now - 86400_000);
    for (const e of ext) alerts.push({ severity: 'info', kind: 'external_download', message: `External user ${e.actor_email} downloaded ${e.n} file(s) in the last 24 hours`, actor: e.actor_email });

    // 5) active external grants and grants about to expire
    const extGrants = db.prepare(
      `SELECT COUNT(*) AS n FROM grants g JOIN users u ON u.id = g.grantee_id
       WHERE g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > ?) AND u.is_external = 1`
    ).get(now).n;
    if (extGrants) alerts.push({ severity: 'info', kind: 'external_grants', message: `${extGrants} active grant(s) to external people` });

    // 6) integrity of the trail itself
    const v = audit.verify();
    if (!v.ok) alerts.unshift({ severity: 'critical', kind: 'audit_tamper', message: `AUDIT TRAIL FAILED VERIFICATION at entry ${v.brokenAtSeq}: ${v.reason}` });

    // 7) a user changed to a more powerful role
    const roleUps = db.prepare(`SELECT details, target_id, ts FROM audit_log WHERE action = 'user.role_change' AND ts > ?`).all(now - 86400_000);
    for (const r of roleUps) { const d = JSON.parse(r.details); if (d.role && d.role.to === 'admin') alerts.push({ severity: 'high', kind: 'admin_granted', message: `A user was promoted to administrator in the last 24 hours (user ${r.target_id.slice(0, 8)})` }); }

    const order = { critical: 0, high: 1, medium: 2, info: 3 };
    alerts.sort((a, b) => order[a.severity] - order[b.severity]);
    const stats = {
      users: db.prepare('SELECT COUNT(*) AS n FROM users WHERE disabled = 0').get().n,
      documents: db.prepare('SELECT COUNT(*) AS n FROM documents WHERE deleted_at IS NULL').get().n,
      activeGrants: db.prepare('SELECT COUNT(*) AS n FROM grants WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)').get(now).n,
      deniedLastDay: db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE outcome = 'denied' AND ts > ?").get(now - 86400_000).n,
    };
    return { body: { alerts, stats, auditOk: v.ok } };
  });
};
