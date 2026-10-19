'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','owner','viewer')),
  department TEXT,
  is_external INTEGER NOT NULL DEFAULT 0,
  password_hash TEXT NOT NULL,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  created_by TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY,          -- sha256 of the cookie token; the raw token is never stored
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip TEXT,
  user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email_lc TEXT NOT NULL,
  ip TEXT NOT NULL,
  ts INTEGER NOT NULL,
  success INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_email ON login_attempts(email_lc, ts);
CREATE INDEX IF NOT EXISTS idx_attempts_ip ON login_attempts(ip, ts);

-- Folders are ORGANISATION ONLY. They carry no permissions and grant nothing (see DESIGN.md).
CREATE TABLE IF NOT EXISTS folders (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (owner_id, name)
);

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id),
  folder_id TEXT REFERENCES folders(id),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  current_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER,
  deleted_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);

CREATE TABLE IF NOT EXISTS document_tags (
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  tag TEXT NOT NULL,
  PRIMARY KEY (document_id, tag)
);

CREATE TABLE IF NOT EXISTS document_versions (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  storage_key TEXT NOT NULL,         -- random name on disk; derived from nothing the user controls
  original_name TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,              -- of the plaintext, for integrity display
  wrapped_key BLOB NOT NULL,
  uploaded_by TEXT NOT NULL REFERENCES users(id),
  uploaded_at INTEGER NOT NULL,
  UNIQUE (document_id, version)
);

-- A grant is a row. Revoking sets revoked_at; history is kept for the audit view.
-- Authorisation reads this table on EVERY request, so revocation is immediate.
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  grantee_id TEXT NOT NULL REFERENCES users(id),
  permission TEXT NOT NULL CHECK (permission IN ('read','edit')),
  granted_by TEXT NOT NULL REFERENCES users(id),
  granted_at INTEGER NOT NULL,
  expires_at INTEGER,
  revoked_at INTEGER,
  revoked_by TEXT,
  via_suggestion TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_grant ON grants(document_id, grantee_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_grants_grantee ON grants(grantee_id);

CREATE TABLE IF NOT EXISTS ai_suggestions (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  requested_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  suggestions TEXT NOT NULL,         -- JSON
  decided_at INTEGER,
  decision TEXT                      -- JSON
);

-- Append-only, hash-chained (HMAC) audit trail. Triggers below make UPDATE/DELETE fail.
CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  actor_id TEXT,
  actor_email TEXT,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('allowed','denied','info')),
  target_type TEXT,
  target_id TEXT,
  ip TEXT,
  details TEXT NOT NULL DEFAULT '{}',
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
`;

/**
 * Opens the database and adds a small transaction helper.
 * tx() nests via SAVEPOINT, and everything is synchronous (no awaits inside a
 * transaction), so a state change and its audit row commit or roll back together.
 */
function openDb(dbPath) {
  if (dbPath !== ':memory:') fs.mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  db.exec(SCHEMA);
  let depth = 0;
  db.tx = (fn) => {
    const name = `sp_${depth}`;
    db.exec(depth === 0 ? 'BEGIN IMMEDIATE' : `SAVEPOINT ${name}`);
    depth++;
    try {
      const result = fn();
      depth--;
      db.exec(depth === 0 ? 'COMMIT' : `RELEASE ${name}`);
      if (depth === 0 && db.onCommit) db.onCommit();
      return result;
    } catch (err) {
      depth--;
      db.exec(depth === 0 ? 'ROLLBACK' : `ROLLBACK TO ${name}; RELEASE ${name}`);
      throw err;
    }
  };
  return db;
}

module.exports = { openDb };
