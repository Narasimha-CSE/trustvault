'use strict';
/**
 * THE authorisation decision point. Every route that touches a document calls
 * requireDocument() below; nothing else decides who may do what.
 *
 * Rules (DESIGN.md has the reasoning):
 *   - A document is reachable only by its OWNER or by someone holding an ACTIVE per-document grant.
 *   - ADMINS have NO implicit access to content. They manage accounts, see metadata and the audit trail,
 *     and can force-revoke grants. They cannot read, download or edit file contents.
 *   - The VIEWER role is capped at read, even if an edit grant somehow exists.
 *   - Trashed documents are reachable by their owner only (so deletion cuts everyone else off at once).
 *   - A disabled user is never authorised for anything.
 *   - Denials are returned to the client as 404 (indistinguishable from "does not exist"), but the real
 *     reason is written to the audit trail.
 */
const { HttpError } = require('./http');

// action -> minimum permission needed
const ACTIONS = {
  read: ['read', 'edit', 'owner'],        // metadata, versions, download
  edit: ['edit', 'owner'],                // rename/describe/tag, upload new version
  share: ['owner'],                       // see grants, grant, revoke, AI suggestions
  delete: ['owner'],                      // move to trash, restore, purge
};

function activeGrantSql(alias = 'g') {
  return `${alias}.revoked_at IS NULL AND (${alias}.expires_at IS NULL OR ${alias}.expires_at > :now)`;
}

/** Returns 'owner' | 'edit' | 'read' | null for this user on this document row. */
function effectivePermission(db, cfg, user, doc) {
  if (!user || user.disabled) return null;
  if (!doc) return null;
  if (doc.owner_id === user.id && user.role !== 'viewer') return 'owner';
  if (doc.deleted_at) return null; // trashed: owner only
  const g = db.prepare(
    `SELECT permission FROM grants g WHERE g.document_id = :doc AND g.grantee_id = :uid AND ${activeGrantSql()}`
  ).get({ doc: doc.id, uid: user.id, now: cfg.now() });
  if (!g) return null;
  if (user.role === 'viewer') return 'read'; // role cap
  return g.permission;
}

function decide(db, cfg, user, docId, action) {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(String(docId));
  if (!doc) return { ok: false, doc: null, perm: null, reason: 'no such document' };
  const perm = effectivePermission(db, cfg, user, doc);
  if (!perm) return { ok: false, doc, perm: null, reason: doc.deleted_at && doc.owner_id !== user.id ? 'document is in trash' : 'no grant' };
  if (!ACTIONS[action].includes(perm)) return { ok: false, doc, perm, reason: `permission "${perm}" is not enough for "${action}"` };
  return { ok: true, doc, perm, reason: null };
}

/**
 * Load a document for a user and an action, or throw 404.
 * Always audits denials. Caller passes ctx = { db, cfg, audit, user, ip }.
 */
function requireDocument(ctx, docId, action, auditAction) {
  const r = decide(ctx.db, ctx.cfg, ctx.user, docId, action);
  if (!r.ok) {
    ctx.audit.record({
      actor: ctx.user, action: auditAction || `document.${action}`, outcome: 'denied',
      targetType: 'document', targetId: String(docId).slice(0, 64), ip: ctx.ip,
      details: { reason: r.reason, existed: !!r.doc },
    });
    // No access at all -> 404 (indistinguishable from a missing document).
    // Can already see it but not do THIS -> 403 (they know it exists, so nothing is leaked).
    if (r.perm) throw new HttpError(403, 'You do not have permission to do that on this document');
    throw new HttpError(404, 'Document not found');
  }
  return r;
}

/**
 * SQL fragment that restricts a query on documents (alias d) to rows the user may READ.
 * Used by list/search so a hit can never reveal a document the user cannot open.
 * A test asserts this agrees with effectivePermission() for every (user, document) pair.
 */
function readableWhere(cfg, user) {
  const params = { uid: user.id, now: cfg.now() };
  // Both named parameters are always referenced so callers can pass this object unchanged.
  if (user.disabled) return { sql: '(0 AND :uid IS NOT NULL AND :now IS NOT NULL)', params };
  const ownerClause = user.role !== 'viewer' ? 'd.owner_id = :uid' : '0';
  return {
    sql: `((${ownerClause}) OR (d.deleted_at IS NULL AND EXISTS (
            SELECT 1 FROM grants g WHERE g.document_id = d.id AND g.grantee_id = :uid AND ${activeGrantSql()})))`,
    params,
  };
}

module.exports = { ACTIONS, effectivePermission, decide, requireDocument, readableWhere };
