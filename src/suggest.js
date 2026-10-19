'use strict';
/**
 * "Who should see this?" assistant.
 *
 * This is a deterministic, rule-based suggester. It is deliberately NOT a language model call:
 *   - it uses METADATA only (file name, description, tags, the owner's own sharing history, departments);
 *     document contents never leave the server and are never read by this code;
 *   - it can only RETURN candidates. It has no database write path and no access to the grant function.
 *     A grant happens only when the owner explicitly confirms (routes/sharing.js), and both the
 *     suggestion and the decision are written to the audit trail.
 *
 * Safety biases (so it errs toward narrower access):
 *   - never suggests people who already have access, the owner, disabled accounts, or EXTERNAL users;
 *   - never suggests "edit" - only "read";
 *   - sensitive-looking documents get a default expiry suggestion and a warning.
 * A model-backed suggester could replace suggest() behind the same return shape without touching the
 * authorisation path - that separation is the point.
 */

const SENSITIVE = /(salary|payroll|compensation|offer|bonus|contract|nda|agreement|audit|tax|invoice|confidential|medical|termination|disciplinary)/i;

const DEPARTMENT_HINTS = [
  { re: /(salary|payroll|compensation|offer|bonus|termination|disciplinary|leave|hiring)/i, departments: ['HR', 'Finance'], label: 'people/pay topic' },
  { re: /(contract|nda|agreement|terms|legal|compliance)/i, departments: ['Legal', 'Sales'], label: 'legal topic' },
  { re: /(audit|tax|invoice|budget|forecast|ledger|expense)/i, departments: ['Finance', 'Legal'], label: 'finance topic' },
  { re: /(drawing|spec|design|architecture|blueprint|schematic|release)/i, departments: ['Engineering'], label: 'engineering topic' },
];

function tokens(text) {
  return String(text).toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length > 2);
}

function suggest(db, cfg, owner, doc) {
  const now = cfg.now();
  const docTags = db.prepare('SELECT tag FROM document_tags WHERE document_id = ?').all(doc.id).map((r) => r.tag);
  const docWords = new Set([...tokens(doc.name), ...tokens(doc.description), ...docTags]);

  const candidates = db.prepare(
    `SELECT id, name, email, department, role, is_external FROM users
     WHERE disabled = 0 AND is_external = 0 AND id != ? AND id NOT IN (
       SELECT grantee_id FROM grants WHERE document_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
     )`
  ).all(owner.id, doc.id, now);

  // The owner's own history: who they granted on other documents, and what those documents looked like.
  const history = db.prepare(
    `SELECT g.grantee_id, d.id AS doc_id, d.name, d.description
     FROM grants g JOIN documents d ON d.id = g.document_id
     WHERE d.owner_id = ? AND d.id != ?`
  ).all(owner.id, doc.id);
  const histTags = new Map();
  for (const t of db.prepare(`SELECT dt.document_id, dt.tag FROM document_tags dt JOIN documents d ON d.id = dt.document_id WHERE d.owner_id = ?`).all(owner.id)) {
    if (!histTags.has(t.document_id)) histTags.set(t.document_id, []);
    histTags.get(t.document_id).push(t.tag);
  }

  const hint = DEPARTMENT_HINTS.find((h) => h.re.test(`${doc.name} ${doc.description} ${docTags.join(' ')}`));
  const sensitive = SENSITIVE.test(`${doc.name} ${doc.description} ${docTags.join(' ')}`);

  const scored = [];
  for (const u of candidates) {
    if (u.role === 'admin') continue; // admins have no content access by design; do not suggest it
    let score = 0;
    const reasons = [];

    // 1) similar documents the owner already shared with this person
    let similar = 0;
    for (const h of history.filter((x) => x.grantee_id === u.id)) {
      const hw = new Set([...tokens(h.name), ...tokens(h.description), ...(histTags.get(h.doc_id) || [])]);
      const overlap = [...hw].filter((w) => docWords.has(w)).length;
      if (overlap > 0) similar++;
    }
    if (similar) { score += Math.min(60, similar * 30); reasons.push(`you shared ${similar} similar document${similar > 1 ? 's' : ''} with them before`); }

    // 2) department fit for the kind of document
    if (hint && u.department && hint.departments.includes(u.department)) {
      score += 35; reasons.push(`${u.department} team - ${hint.label}`);
    }

    // 3) frequent collaborator (weak signal)
    const freq = history.filter((x) => x.grantee_id === u.id).length;
    if (freq >= 3) { score += 10; reasons.push('frequent collaborator'); }

    if (score > 0) scored.push({ userId: u.id, name: u.name, email: u.email, department: u.department, suggestedPermission: 'read', score, reasons });
  }
  scored.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

  return {
    sensitive,
    suggestedExpiryDays: sensitive ? 30 : null,
    warning: sensitive ? 'This looks sensitive. Consider a short expiry and double-check each person.' : null,
    candidates: scored.slice(0, 5),
  };
}

module.exports = { suggest };
