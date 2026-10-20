'use strict';
const crypto = require('node:crypto');
const { HttpError, readJson, uuid, oneOf } = require('../http');
const { requireDocument } = require('../authz');
const { suggest } = require('../suggest');

module.exports = function register(app) {
  const { db, cfg, audit } = app;

  function grantView(g) {
    const u = db.prepare('SELECT id, name, email, role, is_external FROM users WHERE id = ?').get(g.grantee_id);
    const by = db.prepare('SELECT name FROM users WHERE id = ?').get(g.granted_by);
    const now = cfg.now();
    return {
      id: g.id,
      grantee: u ? { id: u.id, name: u.name, email: u.email, role: u.role, isExternal: !!u.is_external } : null,
      permission: g.permission,
      grantedBy: by ? by.name : null,
      grantedAt: g.granted_at,
      expiresAt: g.expires_at,
      revokedAt: g.revoked_at,
      status: g.revoked_at ? 'revoked' : g.expires_at && g.expires_at <= now ? 'expired' : 'active',
      viaSuggestion: !!g.via_suggestion,
    };
  }

  /**
   * The ONLY function that creates a grant. Both the manual path and the confirm-an-AI-suggestion path
   * call it, so every rule below applies to both. Must be called inside a transaction.
   */
  function createGrant(ctx, doc, { userId, permission, expiresAt, suggestionId = null }) {
    const grantee = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!grantee || grantee.disabled) throw new HttpError(404, 'User not found');
    if (grantee.id === doc.owner_id) throw new HttpError(400, 'The owner already has full access');
    if (grantee.role === 'admin') throw new HttpError(400, 'Administrators have no content access by design and cannot be granted documents');
    if (permission === 'edit' && grantee.role === 'viewer') throw new HttpError(400, 'Viewer accounts are read-only; they cannot receive edit access');
    const now = cfg.now();
    let exp = null;
    if (expiresAt !== undefined && expiresAt !== null && expiresAt !== '') {
      exp = typeof expiresAt === 'number' ? expiresAt : Date.parse(expiresAt);
      if (!Number.isFinite(exp)) throw new HttpError(400, 'expiresAt is not a valid date');
      if (exp <= now) throw new HttpError(400, 'expiresAt must be in the future');
      if (exp > now + cfg.maxGrantDays * 86400_000) throw new HttpError(400, `Access cannot be granted for more than ${cfg.maxGrantDays} days at a time`);
    }
    if (grantee.is_external) {
      // Sharing outside the company is a deliberate, time-boxed act, never open-ended.
      if (exp === null) throw new HttpError(400, `External people need an expiry date (at most ${cfg.externalMaxGrantDays} days)`);
      if (exp > now + cfg.externalMaxGrantDays * 86400_000) throw new HttpError(400, `Access for external people is limited to ${cfg.externalMaxGrantDays} days`);
    }
    const existing = db.prepare('SELECT * FROM grants WHERE document_id = ? AND grantee_id = ? AND revoked_at IS NULL').get(doc.id, grantee.id);
    if (existing) {
      // A change is a revoke + a new grant, so history shows both.
      db.prepare('UPDATE grants SET revoked_at = ?, revoked_by = ? WHERE id = ?').run(now, ctx.user.id, existing.id);
    }
    const id = crypto.randomUUID();
    db.prepare('INSERT INTO grants (id, document_id, grantee_id, permission, granted_by, granted_at, expires_at, via_suggestion) VALUES (?,?,?,?,?,?,?,?)')
      .run(id, doc.id, grantee.id, permission, ctx.user.id, now, exp, suggestionId);
    audit.record({
      actor: ctx.user, action: existing ? 'grant.change' : 'grant.create', outcome: 'allowed', targetType: 'document', targetId: doc.id, ip: ctx.ip,
      details: { grantId: id, grantee: grantee.id, granteeEmail: grantee.email, permission, expiresAt: exp, external: !!grantee.is_external, previous: existing ? { permission: existing.permission, expiresAt: existing.expires_at } : null, viaSuggestion: suggestionId },
    });
    return db.prepare('SELECT * FROM grants WHERE id = ?').get(id);
  }

  app.route('GET', '/api/documents/:id/grants', { roles: ['owner'] }, async (ctx) => {
    const { doc } = requireDocument(ctx, ctx.params.id, 'share', 'grant.list');
    const rows = db.prepare('SELECT * FROM grants WHERE document_id = ? ORDER BY granted_at DESC').all(doc.id);
    return { body: { grants: rows.map(grantView) } };
  });

  app.route('POST', '/api/documents/:id/grants', { roles: ['owner'] }, async (ctx) => {
    const body = await readJson(ctx.req);
    const { doc } = requireDocument(ctx, ctx.params.id, 'share', 'grant.create');
    const userId = uuid(body.userId, 'userId');
    const permission = oneOf(body.permission, ['read', 'edit'], 'permission');
    const g = db.tx(() => createGrant(ctx, doc, { userId, permission, expiresAt: body.expiresAt }));
    return { status: 201, body: { grant: grantView(g) } };
  });

  /** Taking access away: effective on the very next request, because authorisation reads this row every time. */
  function revoke(ctx, docId, grantId, actorIsAdmin) {
    const g = db.prepare('SELECT * FROM grants WHERE id = ? AND document_id = ?').get(grantId, docId);
    if (!g || g.revoked_at) throw new HttpError(404, 'Grant not found');
    db.tx(() => {
      db.prepare('UPDATE grants SET revoked_at = ?, revoked_by = ? WHERE id = ?').run(cfg.now(), ctx.user.id, g.id);
      audit.record({ actor: ctx.user, action: 'grant.revoke', outcome: 'allowed', targetType: 'document', targetId: docId, ip: ctx.ip, details: { grantId: g.id, grantee: g.grantee_id, permission: g.permission, byAdmin: actorIsAdmin } });
    });
  }

  app.route('DELETE', '/api/documents/:id/grants/:grantId', { roles: ['owner'] }, async (ctx) => {
    const { doc } = requireDocument(ctx, ctx.params.id, 'share', 'grant.revoke');
    revoke(ctx, doc.id, uuid(ctx.params.grantId, 'grantId'), false);
    return { body: { ok: true } };
  });

  // "Who opened this, and when?" - the owner can see the trail for their own document, including refused attempts.
  app.route('GET', '/api/documents/:id/activity', { roles: ['owner'] }, async (ctx) => {
    const { doc } = requireDocument(ctx, ctx.params.id, 'share', 'document.activity');
    const rows = db.prepare(
      `SELECT ts, actor_email, action, outcome, ip, details FROM audit_log
       WHERE target_type = 'document' AND target_id = ? AND action NOT IN ('document.activity','grant.list','ai.suggest')
       ORDER BY seq DESC LIMIT 100`
    ).all(doc.id);
    return { body: { activity: rows.map((r) => ({ ts: r.ts, actor: r.actor_email, action: r.action, outcome: r.outcome, ip: r.ip, details: JSON.parse(r.details) })) } };
  });

  // ---------- AI assist: suggestions never grant anything ----------
  app.route('POST', '/api/documents/:id/ai/suggest', { roles: ['owner'] }, async (ctx) => {
    const { doc } = requireDocument(ctx, ctx.params.id, 'share', 'ai.suggest');
    const result = suggest(db, cfg, ctx.user, doc);
    const id = crypto.randomUUID();
    db.tx(() => {
      db.prepare('INSERT INTO ai_suggestions (id, document_id, requested_by, created_at, suggestions) VALUES (?,?,?,?,?)')
        .run(id, doc.id, ctx.user.id, cfg.now(), JSON.stringify(result));
      audit.record({
        actor: ctx.user, action: 'ai.suggestion', outcome: 'info', targetType: 'document', targetId: doc.id, ip: ctx.ip,
        details: { suggestionId: id, engine: 'rule-based', sensitive: result.sensitive, candidates: result.candidates.map((c) => ({ userId: c.userId, permission: c.suggestedPermission, score: c.score, reasons: c.reasons })) },
      });
    });
    return { status: 201, body: { suggestionId: id, note: 'Suggestions only. Nothing is shared until you confirm.', ...result } };
  });

  app.route('POST', '/api/documents/:id/ai/suggestions/:sid/decision', { roles: ['owner'] }, async (ctx) => {
    const body = await readJson(ctx.req);
    const { doc } = requireDocument(ctx, ctx.params.id, 'share', 'ai.decision');
    const sid = uuid(ctx.params.sid, 'suggestion id');
    const sug = db.prepare('SELECT * FROM ai_suggestions WHERE id = ? AND document_id = ? AND requested_by = ?').get(sid, doc.id, ctx.user.id);
    if (!sug) throw new HttpError(404, 'Suggestion not found');
    if (sug.decided_at) throw new HttpError(409, 'This suggestion has already been decided');
    const offered = JSON.parse(sug.suggestions).candidates;
    const accept = Array.isArray(body.accept) ? body.accept : [];
    const reject = Array.isArray(body.reject) ? body.reject.map((x) => uuid(x, 'reject id')) : [];
    if (accept.length > 10) throw new HttpError(400, 'Too many entries');

    const created = db.tx(() => {
      const made = [];
      for (const a of accept) {
        const userId = uuid(a && a.userId, 'userId');
        const offer = offered.find((c) => c.userId === userId);
        if (!offer) throw new HttpError(400, 'You can only confirm people that were actually suggested');
        // The owner chooses the permission (never wider than the suggestion's "read" unless THEY pick edit, which is their decision, audited).
        const permission = oneOf(a.permission || offer.suggestedPermission, ['read', 'edit'], 'permission');
        made.push(createGrant(ctx, doc, { userId, permission, expiresAt: a.expiresAt, suggestionId: sid }));
      }
      db.prepare('UPDATE ai_suggestions SET decided_at = ?, decision = ? WHERE id = ?').run(cfg.now(), JSON.stringify({ accepted: made.map((g) => g.grantee_id), rejected: reject }), sid);
      audit.record({
        actor: ctx.user, action: 'ai.decision', outcome: 'allowed', targetType: 'document', targetId: doc.id, ip: ctx.ip,
        details: { suggestionId: sid, accepted: made.map((g) => ({ userId: g.grantee_id, permission: g.permission, expiresAt: g.expires_at })), rejected: reject, offered: offered.map((c) => c.userId) },
      });
      return made;
    });
    return { body: { grants: created.map(grantView) } };
  });

  app.revokeGrantAsAdmin = (ctx, docId, grantId) => revoke(ctx, docId, grantId, true);
  app.grantView = grantView;
};
