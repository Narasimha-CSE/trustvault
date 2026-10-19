'use strict';
/**
 * Tamper-evident audit trail.
 *
 *  - Every row stores hash = HMAC-SHA256(auditKey, prev_hash | canonical(row)).
 *    Editing, reordering or deleting a middle row breaks every later hash.
 *  - The HMAC key is NOT in the database, so someone with only the DB file cannot recompute a valid chain.
 *  - SQLite triggers reject UPDATE/DELETE from the application.
 *  - The head (seq + hash) is also written to a separate file so deleting the TAIL rows is detected.
 *
 * Honest limit: someone holding BOTH the secret and write access to the DB and head file can rewrite history.
 * Ship the head hash off-box regularly (the admin "verify" screen shows it) to close that gap.
 */
const fs = require('node:fs');
const crypto = require('node:crypto');

const GENESIS = '0'.repeat(64);

function canonical(entry) {
  return JSON.stringify([
    entry.ts, entry.actor_id ?? null, entry.actor_email ?? null, entry.action, entry.outcome,
    entry.target_type ?? null, entry.target_id ?? null, entry.ip ?? null, entry.details,
  ]);
}

function computeHash(auditKey, prevHash, entry) {
  return crypto.createHmac('sha256', auditKey).update(prevHash + '|' + canonical(entry)).digest('hex');
}

function createAudit(db, cfg) {
  const lastStmt = db.prepare('SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1');
  const insertStmt = db.prepare(
    `INSERT INTO audit_log (ts, actor_id, actor_email, action, outcome, target_type, target_id, ip, details, prev_hash, hash)
     VALUES (?,?,?,?,?,?,?,?,?,?,?)`
  );

  /**
   * record() joins the caller's transaction when there is one (so a change and its audit row are atomic).
   * If this throws, the surrounding change rolls back: nothing happens without being recorded.
   */
  function record({ actor = null, action, outcome = 'info', targetType = null, targetId = null, ip = null, details = {} }) {
    return db.tx(() => {
      const last = lastStmt.get();
      const prev = last ? last.hash : GENESIS;
      const entry = {
        ts: cfg.now(),
        actor_id: actor ? actor.id : null,
        actor_email: actor ? actor.email : null,
        action, outcome,
        target_type: targetType, target_id: targetId, ip,
        details: JSON.stringify(details),
      };
      const hash = computeHash(cfg.auditKey, prev, entry);
      const res = insertStmt.run(entry.ts, entry.actor_id, entry.actor_email, action, outcome, targetType, targetId, ip, entry.details, prev, hash);
      return Number(res.lastInsertRowid);
    });
  }

  // The head pointer file is written only AFTER the outermost transaction commits (db.onCommit),
  // so it can never be ahead of the database because of a rolled-back change.
  function writeHead() {
    const row = lastStmt.get();
    if (row) fs.writeFileSync(cfg.auditHeadFile, JSON.stringify({ seq: Number(row.seq), hash: row.hash }), { mode: 0o600 });
  }
  db.onCommit = writeHead;

  function verify() {
    const rows = db.prepare('SELECT * FROM audit_log ORDER BY seq ASC').all();
    let prev = GENESIS;
    let expectedSeq = null;
    for (const row of rows) {
      if (expectedSeq !== null && Number(row.seq) !== expectedSeq) {
        return { ok: false, checked: rows.length, brokenAtSeq: Number(row.seq), reason: 'sequence gap (rows removed)' };
      }
      expectedSeq = Number(row.seq) + 1;
      if (row.prev_hash !== prev) return { ok: false, checked: rows.length, brokenAtSeq: Number(row.seq), reason: 'prev_hash does not match previous row' };
      const h = computeHash(cfg.auditKey, prev, row);
      if (h !== row.hash) return { ok: false, checked: rows.length, brokenAtSeq: Number(row.seq), reason: 'row content does not match its hash' };
      prev = row.hash;
    }
    const head = rows.length ? { seq: Number(rows[rows.length - 1].seq), hash: rows[rows.length - 1].hash } : null;
    let headFile = null;
    try { headFile = JSON.parse(fs.readFileSync(cfg.auditHeadFile, 'utf8')); } catch { /* none yet */ }
    if (headFile && (!head || headFile.seq > head.seq || (headFile.seq === head.seq && headFile.hash !== head.hash))) {
      return { ok: false, checked: rows.length, brokenAtSeq: head ? head.seq : 0, reason: 'database head is behind or different from the recorded head (tail rows removed or replaced)' };
    }
    return { ok: true, checked: rows.length, head };
  }

  return { record, verify, writeHead };
}

module.exports = { createAudit, GENESIS };
