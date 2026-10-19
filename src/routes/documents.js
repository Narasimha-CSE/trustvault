'use strict';
const crypto = require('node:crypto');
const { HttpError, readBody, readJson, str, uuid, tags: parseTags } = require('../http');
const { requireDocument, effectivePermission, readableWhere } = require('../authz');
const { validateUpload } = require('../validate');
const { sha256Hex } = require('../crypto');

const like = (s) => `%${String(s).replace(/[\\%_]/g, '\\$&')}%`;

module.exports = function register(app) {
  const { db, cfg, audit, storage } = app;

  // ---------- views ----------
  function loadTags(docId) {
    return db.prepare('SELECT tag FROM document_tags WHERE document_id = ? ORDER BY tag').all(docId).map((r) => r.tag);
  }

  function currentVersion(doc) {
    return db.prepare('SELECT * FROM document_versions WHERE document_id = ? AND version = ?').get(doc.id, doc.current_version);
  }

  function docView(doc, perm, user, { detail = false } = {}) {
    const v = currentVersion(doc);
    const owner = db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(doc.owner_id);
    const out = {
      id: doc.id,
      name: doc.name,
      description: doc.description,
      tags: loadTags(doc.id),
      owner: owner ? { id: owner.id, name: owner.name, email: owner.email } : null,
      myPermission: perm,
      // Folders belong to the owner's own organisation; nobody else learns about them.
      folderId: perm === 'owner' ? doc.folder_id : null,
      currentVersion: doc.current_version,
      fileName: v ? v.original_name : null,
      mime: v ? v.mime : null,
      size: v ? v.size : null,
      createdAt: doc.created_at,
      updatedAt: doc.updated_at,
      deletedAt: doc.deleted_at,
    };
    if (detail) {
      out.versions = db.prepare(
        `SELECT v.version, v.original_name, v.mime, v.size, v.sha256, v.uploaded_at, u.name AS uploaded_by
         FROM document_versions v JOIN users u ON u.id = v.uploaded_by WHERE v.document_id = ? ORDER BY v.version DESC`
      ).all(doc.id).map((x) => ({ version: x.version, fileName: x.original_name, mime: x.mime, size: x.size, sha256: x.sha256, uploadedAt: x.uploaded_at, uploadedBy: x.uploaded_by }));
    }
    return out;
  }

  function ownedFolderOrThrow(user, folderId) {
    if (folderId === null || folderId === undefined || folderId === '') return null;
    const id = uuid(folderId, 'folderId');
    const f = db.prepare('SELECT id FROM folders WHERE id = ? AND owner_id = ?').get(id, user.id);
    if (!f) throw new HttpError(404, 'Folder not found'); // someone else's folder looks identical to a missing one
    return f.id;
  }

  // ---------- list / search (the SQL is restricted to documents the caller may read) ----------
  app.route('GET', '/api/documents', {}, async (ctx) => {
    const w = readableWhere(cfg, ctx.user);
    const where = [w.sql, 'd.deleted_at IS NULL'];
    const params = { ...w.params };
    const q = ctx.query;
    const scope = q.scope || 'all';
    if (scope === 'mine') where.push('d.owner_id = :uid');
    else if (scope === 'shared') where.push('d.owner_id != :uid');
    else if (scope !== 'all') throw new HttpError(400, 'scope must be mine, shared or all');
    if (q.q) {
      params.q = like(String(q.q).slice(0, 100));
      where.push(`(d.name LIKE :q ESCAPE '\\' OR d.description LIKE :q ESCAPE '\\' OR EXISTS (SELECT 1 FROM document_tags t WHERE t.document_id = d.id AND t.tag LIKE :q ESCAPE '\\'))`);
    }
    if (q.tag) { params.tag = String(q.tag).toLowerCase().slice(0, 30); where.push('EXISTS (SELECT 1 FROM document_tags t WHERE t.document_id = d.id AND t.tag = :tag)'); }
    if (q.folder === 'none') where.push('d.folder_id IS NULL AND d.owner_id = :uid');
    else if (q.folder) { params.folder = uuid(q.folder, 'folder'); where.push('d.folder_id = :folder AND d.owner_id = :uid'); }
    const sortCol = { name: 'd.name COLLATE NOCASE', updated: 'd.updated_at', created: 'd.created_at' }[q.sort || 'updated'];
    if (!sortCol) throw new HttpError(400, 'sort must be name, updated or created');
    const dir = q.dir === 'asc' ? 'ASC' : 'DESC';
    const limit = Math.min(Math.max(parseInt(q.limit || '50', 10) || 50, 1), 100);
    const offset = Math.max(parseInt(q.offset || '0', 10) || 0, 0);

    const rows = db.prepare(`SELECT d.* FROM documents d WHERE ${where.join(' AND ')} ORDER BY ${sortCol} ${dir} LIMIT ${limit} OFFSET ${offset}`).all(params);
    const total = db.prepare(`SELECT COUNT(*) AS n FROM documents d WHERE ${where.join(' AND ')}`).get(params).n;
    // Permission is recomputed through the one decision function, not copied from the SQL.
    const documents = rows.map((d) => ({ d, perm: effectivePermission(db, cfg, ctx.user, d) })).filter((x) => x.perm).map((x) => docView(x.d, x.perm, ctx.user));
    return { body: { documents, total, limit, offset } };
  });

  app.route('GET', '/api/tags', {}, async (ctx) => {
    const w = readableWhere(cfg, ctx.user);
    const rows = db.prepare(
      `SELECT t.tag, COUNT(*) AS n FROM document_tags t JOIN documents d ON d.id = t.document_id
       WHERE ${w.sql} AND d.deleted_at IS NULL GROUP BY t.tag ORDER BY n DESC, t.tag LIMIT 50`
    ).all(w.params);
    return { body: { tags: rows.map((r) => ({ tag: r.tag, count: r.n })) } };
  });

  // ---------- upload (raw body; metadata in the query string) ----------
  function readUpload(ctx) {
    const type = String(ctx.req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (type !== 'application/octet-stream') throw new HttpError(415, 'Content-Type must be application/octet-stream');
    return readBody(ctx.req, cfg.maxUploadBytes);
  }

  app.route('POST', '/api/documents', { roles: ['owner'] }, async (ctx) => {
    const buf = await readUpload(ctx);
    const file = validateUpload(ctx.query.name, buf, cfg.maxUploadBytes);
    const title = ctx.query.title ? str(ctx.query.title, { min: 1, max: 150, field: 'title' }) : file.name;
    const description = ctx.query.description ? str(ctx.query.description, { max: 1000, field: 'description' }) : '';
    const tagList = parseTags(ctx.query.tags);
    const folderId = ownedFolderOrThrow(ctx.user, ctx.query.folderId);

    const docId = crypto.randomUUID();
    const versionId = crypto.randomUUID();
    const sha = sha256Hex(buf);
    const stored = storage.put(versionId, buf);
    try {
      db.tx(() => {
        const now = cfg.now();
        db.prepare('INSERT INTO documents (id, owner_id, folder_id, name, description, current_version, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)')
          .run(docId, ctx.user.id, folderId, title, description, 1, now, now);
        db.prepare('INSERT INTO document_versions (id, document_id, version, storage_key, original_name, mime, size, sha256, wrapped_key, uploaded_by, uploaded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
          .run(versionId, docId, 1, stored.storageKey, file.name, file.mime, buf.length, sha, stored.wrappedKey, ctx.user.id, now);
        for (const t of tagList) db.prepare('INSERT INTO document_tags (document_id, tag) VALUES (?,?)').run(docId, t);
        audit.record({ actor: ctx.user, action: 'document.upload', outcome: 'allowed', targetType: 'document', targetId: docId, ip: ctx.ip, details: { name: title, file: file.name, size: buf.length, sha256: sha } });
      });
    } catch (e) {
      storage.remove(stored.storageKey); // no orphaned ciphertext if the database write failed
      throw e;
    }
    const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(docId);
    return { status: 201, body: { document: docView(doc, 'owner', ctx.user, { detail: true }) } };
  });

  // ---------- read ----------
  app.route('GET', '/api/documents/:id', {}, async (ctx) => {
    const { doc, perm } = requireDocument(ctx, ctx.params.id, 'read', 'document.view');
    audit.record({ actor: ctx.user, action: 'document.view', outcome: 'allowed', targetType: 'document', targetId: doc.id, ip: ctx.ip, details: { permission: perm } });
    return { body: { document: docView(doc, perm, ctx.user, { detail: true }) } };
  });

  const asciiName = (n) => n.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_');

  app.route('GET', '/api/documents/:id/download', {}, async (ctx) => {
    const { doc, perm } = requireDocument(ctx, ctx.params.id, 'read', 'document.download');
    const versionNo = ctx.query.version ? parseInt(ctx.query.version, 10) : doc.current_version;
    if (!Number.isInteger(versionNo) || versionNo < 1) throw new HttpError(400, 'version must be a positive integer');
    // The version is looked up WITHIN this document, so a version number can never reach another document's file.
    const v = db.prepare('SELECT * FROM document_versions WHERE document_id = ? AND version = ?').get(doc.id, versionNo);
    if (!v) {
      audit.record({ actor: ctx.user, action: 'document.download', outcome: 'denied', targetType: 'document', targetId: doc.id, ip: ctx.ip, details: { reason: 'no such version', version: versionNo } });
      throw new HttpError(404, 'Version not found');
    }
    let plain;
    try {
      plain = storage.get(v.id, v.storage_key, v.wrapped_key);
    } catch (e) {
      audit.record({ actor: ctx.user, action: 'document.download', outcome: 'denied', targetType: 'document', targetId: doc.id, ip: ctx.ip, details: { reason: 'stored file failed integrity check', version: versionNo } });
      console.error('integrity failure for version', v.id, e.message);
      throw new HttpError(500, 'The stored file failed its integrity check');
    }
    // Audit BEFORE any byte leaves. If the audit write fails the download fails: no unrecorded reads.
    audit.record({ actor: ctx.user, action: 'document.download', outcome: 'allowed', targetType: 'document', targetId: doc.id, ip: ctx.ip, details: { permission: perm, version: versionNo, file: v.original_name, size: v.size } });
    ctx.res.writeHead(200, {
      'Content-Type': 'application/octet-stream', // never the stored type: nothing is rendered in our origin
      'Content-Length': plain.length,
      'Content-Disposition': `attachment; filename="${asciiName(v.original_name)}"; filename*=UTF-8''${encodeURIComponent(v.original_name)}`,
      'Cache-Control': 'no-store',
      'X-Content-SHA256': v.sha256,
    });
    ctx.res.end(plain);
    return app.RAW;
  });

  // ---------- edit ----------
  app.route('PATCH', '/api/documents/:id', { roles: ['owner'] }, async (ctx) => {
    const body = await readJson(ctx.req);
    const { doc, perm } = requireDocument(ctx, ctx.params.id, 'edit', 'document.edit');
    const changes = {};
    if (body.name !== undefined) changes.name = str(body.name, { min: 1, max: 150, field: 'name' });
    if (body.description !== undefined) changes.description = str(body.description, { max: 1000, field: 'description' });
    if (body.tags !== undefined) changes.tags = parseTags(body.tags);
    if (body.folderId !== undefined) {
      if (perm !== 'owner') throw new HttpError(403, 'Only the owner can move a document');
      changes.folderId = ownedFolderOrThrow(ctx.user, body.folderId);
    }
    if (!Object.keys(changes).length) throw new HttpError(400, 'Nothing to change');
    db.tx(() => {
      db.prepare('UPDATE documents SET name = ?, description = ?, folder_id = ?, updated_at = ? WHERE id = ?').run(
        changes.name ?? doc.name, changes.description ?? doc.description,
        changes.folderId !== undefined ? changes.folderId : doc.folder_id, cfg.now(), doc.id
      );
      if (changes.tags) {
        db.prepare('DELETE FROM document_tags WHERE document_id = ?').run(doc.id);
        for (const t of changes.tags) db.prepare('INSERT INTO document_tags (document_id, tag) VALUES (?,?)').run(doc.id, t);
      }
      audit.record({ actor: ctx.user, action: 'document.edit', outcome: 'allowed', targetType: 'document', targetId: doc.id, ip: ctx.ip, details: { fields: Object.keys(changes), permission: perm } });
    });
    const fresh = db.prepare('SELECT * FROM documents WHERE id = ?').get(doc.id);
    return { body: { document: docView(fresh, perm, ctx.user, { detail: true }) } };
  });

  app.route('POST', '/api/documents/:id/versions', { roles: ['owner'] }, async (ctx) => {
    // Authorise BEFORE reading the (up to 10 MB) body.
    const { doc, perm } = requireDocument(ctx, ctx.params.id, 'edit', 'document.new_version');
    const buf = await readUpload(ctx);
    const file = validateUpload(ctx.query.name, buf, cfg.maxUploadBytes);
    const versionId = crypto.randomUUID();
    const sha = sha256Hex(buf);
    const stored = storage.put(versionId, buf);
    try {
      db.tx(() => {
        // Re-check inside the transaction: access may have been revoked while the body was uploading.
        const again = db.prepare('SELECT * FROM documents WHERE id = ?').get(doc.id);
        const p = effectivePermission(db, cfg, ctx.user, again);
        if (!p || !['edit', 'owner'].includes(p)) throw new HttpError(404, 'Document not found');
        const next = again.current_version + 1;
        const now = cfg.now();
        db.prepare('INSERT INTO document_versions (id, document_id, version, storage_key, original_name, mime, size, sha256, wrapped_key, uploaded_by, uploaded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
          .run(versionId, doc.id, next, stored.storageKey, file.name, file.mime, buf.length, sha, stored.wrappedKey, ctx.user.id, now);
        db.prepare('UPDATE documents SET current_version = ?, updated_at = ? WHERE id = ?').run(next, now, doc.id);
        audit.record({ actor: ctx.user, action: 'document.new_version', outcome: 'allowed', targetType: 'document', targetId: doc.id, ip: ctx.ip, details: { version: next, file: file.name, size: buf.length, sha256: sha, permission: perm } });
      });
    } catch (e) {
      storage.remove(stored.storageKey);
      throw e;
    }
    const fresh = db.prepare('SELECT * FROM documents WHERE id = ?').get(doc.id);
    return { status: 201, body: { document: docView(fresh, perm, ctx.user, { detail: true }) } };
  });

  // ---------- delete / trash / restore / purge ----------
  app.route('DELETE', '/api/documents/:id', { roles: ['owner'] }, async (ctx) => {
    const { doc } = requireDocument(ctx, ctx.params.id, 'delete', 'document.trash');
    if (doc.deleted_at) throw new HttpError(409, 'Already in trash');
    db.tx(() => {
      const now = cfg.now();
      db.prepare('UPDATE documents SET deleted_at = ?, deleted_by = ?, updated_at = ? WHERE id = ?').run(now, ctx.user.id, now, doc.id);
      // Trashing also revokes every grant, so restoring never silently re-exposes the file.
      const active = db.prepare('SELECT id, grantee_id FROM grants WHERE document_id = ? AND revoked_at IS NULL').all(doc.id);
      for (const g of active) {
        db.prepare('UPDATE grants SET revoked_at = ?, revoked_by = ? WHERE id = ?').run(now, ctx.user.id, g.id);
        audit.record({ actor: ctx.user, action: 'grant.revoke', outcome: 'allowed', targetType: 'document', targetId: doc.id, ip: ctx.ip, details: { grantId: g.id, grantee: g.grantee_id, reason: 'document trashed' } });
      }
      audit.record({ actor: ctx.user, action: 'document.trash', outcome: 'allowed', targetType: 'document', targetId: doc.id, ip: ctx.ip, details: { name: doc.name, grantsRevoked: active.length } });
    });
    return { body: { ok: true, purgeAfterDays: cfg.trashRetentionDays } };
  });

  app.route('GET', '/api/trash', { roles: ['owner'] }, async (ctx) => {
    const rows = db.prepare('SELECT * FROM documents WHERE owner_id = ? AND deleted_at IS NOT NULL ORDER BY deleted_at DESC').all(ctx.user.id);
    return {
      body: {
        documents: rows.map((d) => ({
          ...docView(d, 'owner', ctx.user),
          purgeAt: d.deleted_at + cfg.trashRetentionDays * 86400_000,
        })),
      },
    };
  });

  app.route('POST', '/api/documents/:id/restore', { roles: ['owner'] }, async (ctx) => {
    const { doc } = requireDocument(ctx, ctx.params.id, 'delete', 'document.restore');
    if (!doc.deleted_at) throw new HttpError(409, 'Document is not in trash');
    db.tx(() => {
      db.prepare('UPDATE documents SET deleted_at = NULL, deleted_by = NULL, updated_at = ? WHERE id = ?').run(cfg.now(), doc.id);
      audit.record({ actor: ctx.user, action: 'document.restore', outcome: 'allowed', targetType: 'document', targetId: doc.id, ip: ctx.ip, details: { name: doc.name } });
    });
    return { body: { ok: true, note: 'Restored as private. Share it again if needed.' } };
  });

  app.route('DELETE', '/api/documents/:id/purge', { roles: ['owner'] }, async (ctx) => {
    const { doc } = requireDocument(ctx, ctx.params.id, 'delete', 'document.purge');
    if (!doc.deleted_at) throw new HttpError(409, 'Move the document to trash first');
    app.purgeDocument(doc.id, ctx.user, 'owner purge');
    return { body: { ok: true } };
  });

  // ---------- folders (organisation only; they grant nothing) ----------
  app.route('GET', '/api/folders', { roles: ['owner'] }, async (ctx) => {
    const rows = db.prepare(
      `SELECT f.id, f.name, (SELECT COUNT(*) FROM documents d WHERE d.folder_id = f.id AND d.deleted_at IS NULL) AS count
       FROM folders f WHERE f.owner_id = ? ORDER BY f.name COLLATE NOCASE`
    ).all(ctx.user.id);
    return { body: { folders: rows } };
  });

  app.route('POST', '/api/folders', { roles: ['owner'] }, async (ctx) => {
    const body = await readJson(ctx.req);
    const name = str(body.name, { min: 1, max: 60, field: 'name' });
    const id = crypto.randomUUID();
    try {
      db.tx(() => {
        db.prepare('INSERT INTO folders (id, owner_id, name, created_at) VALUES (?,?,?,?)').run(id, ctx.user.id, name, cfg.now());
        audit.record({ actor: ctx.user, action: 'folder.create', outcome: 'allowed', targetType: 'folder', targetId: id, ip: ctx.ip, details: { name } });
      });
    } catch (e) {
      if (/UNIQUE/.test(e.message)) throw new HttpError(409, 'You already have a folder with that name');
      throw e;
    }
    return { status: 201, body: { folder: { id, name, count: 0 } } };
  });

  function ownFolder(ctx) {
    const f = db.prepare('SELECT * FROM folders WHERE id = ? AND owner_id = ?').get(uuid(ctx.params.id, 'folder id'), ctx.user.id);
    if (!f) throw new HttpError(404, 'Folder not found');
    return f;
  }

  app.route('PATCH', '/api/folders/:id', { roles: ['owner'] }, async (ctx) => {
    const f = ownFolder(ctx);
    const name = str((await readJson(ctx.req)).name, { min: 1, max: 60, field: 'name' });
    try {
      db.tx(() => {
        db.prepare('UPDATE folders SET name = ? WHERE id = ?').run(name, f.id);
        audit.record({ actor: ctx.user, action: 'folder.rename', outcome: 'allowed', targetType: 'folder', targetId: f.id, ip: ctx.ip, details: { from: f.name, to: name } });
      });
    } catch (e) {
      if (/UNIQUE/.test(e.message)) throw new HttpError(409, 'You already have a folder with that name');
      throw e;
    }
    return { body: { folder: { id: f.id, name } } };
  });

  app.route('DELETE', '/api/folders/:id', { roles: ['owner'] }, async (ctx) => {
    const f = ownFolder(ctx);
    db.tx(() => {
      db.prepare('UPDATE documents SET folder_id = NULL WHERE folder_id = ?').run(f.id); // documents move to the top level
      db.prepare('DELETE FROM folders WHERE id = ?').run(f.id);
      audit.record({ actor: ctx.user, action: 'folder.delete', outcome: 'allowed', targetType: 'folder', targetId: f.id, ip: ctx.ip, details: { name: f.name } });
    });
    return { body: { ok: true } };
  });
};
