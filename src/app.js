'use strict';
/**
 * Application core: HTTP server, router, session + CSRF + role gates, security headers,
 * static files (explicit allow-list), error handling and background maintenance.
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { openDb } = require('./db');
const { createAudit } = require('./audit');
const { createStorage } = require('./storage');
const { HttpError, sendJson, parseCookies } = require('./http');
const { randomToken, sha256Hex, safeEqual } = require('./crypto');

const RAW = Symbol('raw'); // handler already wrote the response

const PUBLIC_DIR = path.resolve(__dirname, '..', 'public');
const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
  '/favicon.svg': ['favicon.svg', 'image/svg+xml'],
};

function createApp(cfg) {
  const db = openDb(cfg.dbPath);
  const audit = createAudit(db, cfg);
  const storage = createStorage(cfg);
  const cookieName = cfg.secureCookies ? '__Host-tv_sid' : 'tv_sid';
  const routes = [];

  function route(method, pattern, opts, handler) {
    const keys = [];
    const re = new RegExp('^' + pattern.replace(/:([a-zA-Z]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
    routes.push({ method, re, keys, opts: { auth: true, roles: null, allowWhileMustChange: false, ...opts }, handler });
  }

  // ---------- client ip ----------
  function clientIp(req) {
    if (cfg.trustProxy) {
      const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
      if (xff.length) return xff[xff.length - 1]; // last hop = the one our own proxy appended
    }
    return req.socket.remoteAddress || 'unknown';
  }

  // ---------- sessions ----------
  function createSession(user, ip, ua) {
    const token = randomToken(32);
    const csrf = randomToken(24);
    const now = cfg.now();
    db.prepare('INSERT INTO sessions (id_hash, user_id, csrf_token, created_at, last_seen, expires_at, ip, user_agent) VALUES (?,?,?,?,?,?,?,?)')
      .run(sha256Hex(token), user.id, csrf, now, now, now + cfg.sessionAbsoluteMs, ip, String(ua || '').slice(0, 200));
    return { token, csrf };
  }

  function sessionCookie(token, maxAgeSec) {
    return `${cookieName}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${cfg.secureCookies ? '; Secure' : ''}`;
  }

  function loadSession(req) {
    const token = parseCookies(req.headers.cookie)[cookieName];
    if (!token || token.length > 200) return null;
    const idHash = sha256Hex(token);
    const row = db.prepare(
      `SELECT s.*, u.id AS uid FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?`
    ).get(idHash);
    if (!row) return null;
    const now = cfg.now();
    if (now > row.expires_at || now - row.last_seen > cfg.sessionIdleMs) {
      db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(idHash);
      return null;
    }
    // Re-read the user from the database on EVERY request: role changes and disabling take effect immediately.
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(row.user_id);
    if (!user || user.disabled) {
      db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(idHash);
      return null;
    }
    db.prepare('UPDATE sessions SET last_seen = ? WHERE id_hash = ?').run(now, idHash);
    return { idHash, csrf: row.csrf_token, user };
  }

  const destroySessionsFor = (userId, exceptIdHash = null) =>
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND id_hash IS NOT ?').run(userId, exceptIdHash);

  // ---------- login throttling (keyed on the email STRING, so unknown accounts behave identically) ----------
  function throttleStatus(emailLc, ip) {
    const since = cfg.now() - cfg.loginWindowMs;
    const byEmail = db.prepare(
      `SELECT COUNT(*) AS n, MIN(ts) AS first FROM login_attempts
       WHERE email_lc = ? AND success = 0 AND ts > ?
         AND ts > COALESCE((SELECT MAX(ts) FROM login_attempts WHERE email_lc = ? AND success = 1), 0)`
    ).get(emailLc, since, emailLc);
    const byIp = db.prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND success = 0 AND ts > ?').get(ip, since);
    const locked = byEmail.n >= cfg.loginMaxFailures || byIp.n >= cfg.loginIpMaxFailures;
    const retryAfterSec = locked && byEmail.first ? Math.max(1, Math.ceil((byEmail.first + cfg.loginWindowMs - cfg.now()) / 1000)) : Math.ceil(cfg.loginWindowMs / 1000);
    return { locked, retryAfterSec, failures: byEmail.n };
  }
  const recordAttempt = (emailLc, ip, success) =>
    db.prepare('INSERT INTO login_attempts (email_lc, ip, ts, success) VALUES (?,?,?,?)').run(emailLc, ip, cfg.now(), success ? 1 : 0);

  // ---------- headers ----------
  function securityHeaders(res) {
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    if (cfg.secureCookies) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  function originOk(req) {
    const origin = req.headers.origin;
    if (origin) {
      if (origin === 'null') return false;
      try { if (new URL(origin).host !== req.headers.host) return false; } catch { return false; }
    }
    if (req.headers['sec-fetch-site'] === 'cross-site') return false;
    return true;
  }

  // ---------- dispatch ----------
  async function handle(req, res) {
    securityHeaders(res);
    const url = new URL(req.url, 'http://localhost');
    const method = req.method;

    if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url);

    res.setHeader('Cache-Control', 'no-store');
    const match = routes.find((r) => r.method === method && r.re.test(url.pathname));
    if (!match) {
      if (routes.some((r) => r.re.test(url.pathname))) throw new HttpError(405, 'Method not allowed');
      throw new HttpError(404, 'Not found');
    }
    const m = url.pathname.match(match.re);
    const params = {};
    match.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]); });

    const ip = clientIp(req);
    const unsafe = !['GET', 'HEAD', 'OPTIONS'].includes(method);
    if (unsafe && !originOk(req)) throw new HttpError(403, 'Cross-site request refused');

    let session = null;
    if (match.opts.auth) {
      session = loadSession(req);
      if (!session) throw new HttpError(401, 'Authentication required');
      if (unsafe) {
        const sent = req.headers['x-csrf-token'];
        if (!sent || !safeEqual(sent, session.csrf)) throw new HttpError(403, 'Missing or invalid CSRF token');
      }
      if (session.user.must_change_password && !match.opts.allowWhileMustChange) {
        throw new HttpError(403, 'You must change your password first', { code: 'PASSWORD_CHANGE_REQUIRED' });
      }
      if (match.opts.roles && !match.opts.roles.includes(session.user.role)) {
        audit.record({ actor: session.user, action: 'access.role_denied', outcome: 'denied', targetType: 'route', targetId: `${method} ${url.pathname}`.slice(0, 120), ip, details: { role: session.user.role, needed: match.opts.roles } });
        throw new HttpError(403, 'Your role does not allow this');
      }
    }

    const ctx = {
      db, cfg, audit, storage, req, res, url, params, ip,
      query: Object.fromEntries(url.searchParams),
      user: session ? session.user : null,
      session,
      createSession, sessionCookie, destroySessionsFor, throttleStatus, recordAttempt, cookieName,
    };
    const out = await match.handler(ctx);
    if (out === RAW) return;
    if (out === undefined) { res.writeHead(204); return res.end(); }
    sendJson(res, out.status || 200, out.body, out.headers || {});
  }

  function serveStatic(req, res, url) {
    if (!['GET', 'HEAD'].includes(req.method)) throw new HttpError(405, 'Method not allowed');
    const entry = STATIC[url.pathname]; // exact-match allow-list: no filesystem path is ever built from the URL
    if (!entry) throw new HttpError(404, 'Not found');
    const body = fs.readFileSync(path.join(PUBLIC_DIR, entry[0]));
    res.writeHead(200, { 'Content-Type': entry[1], 'Content-Length': body.length, 'Cache-Control': 'no-cache' });
    res.end(req.method === 'HEAD' ? undefined : body);
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      if (res.headersSent) { res.destroy(); return; }
      if (err instanceof HttpError) {
        const headers = err.extra && err.extra.retryAfter ? { 'Retry-After': String(err.extra.retryAfter) } : {};
        return sendJson(res, err.status, { error: err.message, ...(err.extra && err.extra.code ? { code: err.extra.code } : {}) }, headers);
      }
      const id = crypto.randomBytes(4).toString('hex');
      console.error(`[error ${id}]`, err); // details stay in the server log, never in the response
      sendJson(res, 500, { error: 'Internal error', id });
    });
  });
  server.requestTimeout = 60_000;
  server.headersTimeout = 15_000;

  // ---------- maintenance: trash retention, expired sessions, old login attempts ----------
  function runMaintenance() {
    const now = cfg.now();
    const cutoff = now - cfg.trashRetentionDays * 86400_000;
    const stale = db.prepare('SELECT id, name, owner_id FROM documents WHERE deleted_at IS NOT NULL AND deleted_at < ?').all(cutoff);
    for (const d of stale) purgeDocument(d.id, null, 'retention period elapsed');
    db.prepare('DELETE FROM sessions WHERE expires_at < ? OR last_seen < ?').run(now, now - cfg.sessionIdleMs);
    db.prepare('DELETE FROM login_attempts WHERE ts < ?').run(now - 7 * 86400_000);
    return { purged: stale.length };
  }

  /** Permanently removes a document, its versions and its encrypted files. Audited. */
  function purgeDocument(docId, actor, reason) {
    const keys = db.tx(() => {
      const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(docId);
      if (!doc) return [];
      const versions = db.prepare('SELECT storage_key FROM document_versions WHERE document_id = ?').all(docId);
      audit.record({ actor, action: 'document.purge', outcome: 'allowed', targetType: 'document', targetId: docId, details: { name: doc.name, owner: doc.owner_id, reason, versions: versions.length } });
      db.prepare('DELETE FROM documents WHERE id = ?').run(docId); // cascades versions, tags, grants, suggestions
      return versions.map((v) => v.storage_key);
    });
    for (const k of keys) storage.remove(k); // files removed only after the rows are gone
    return keys.length;
  }

  let timer = null;
  function start() {
    return new Promise((resolve) => {
      server.listen(cfg.port, cfg.host, () => {
        runMaintenance();
        if (cfg.maintenanceIntervalMs) {
          timer = setInterval(() => { try { runMaintenance(); } catch (e) { console.error('maintenance failed', e); } }, cfg.maintenanceIntervalMs);
          timer.unref();
        }
        resolve(server.address().port);
      });
    });
  }
  function close() {
    if (timer) clearInterval(timer);
    return new Promise((resolve) => { server.close(() => { db.close(); resolve(); }); server.closeAllConnections?.(); });
  }

  const app = { cfg, db, audit, storage, server, route, start, close, runMaintenance, purgeDocument, RAW };
  // Route modules register themselves here.
  require('./routes/auth')(app);
  require('./routes/documents')(app);
  require('./routes/sharing')(app);
  require('./routes/admin')(app);
  return app;
}

module.exports = { createApp, RAW };
