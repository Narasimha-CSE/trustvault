'use strict';
const { HttpError, readJson, str, email } = require('../http');
const { hashPassword, verifyPassword, dummyVerify } = require('../crypto');

function publicUser(u) {
  return { id: u.id, email: u.email, name: u.name, role: u.role, department: u.department, isExternal: !!u.is_external, mustChangePassword: !!u.must_change_password };
}

function checkNewPassword(cfg, pw, userEmail) {
  if (typeof pw !== 'string') throw new HttpError(400, 'newPassword must be a string');
  if (pw.length < cfg.passwordMinLength) throw new HttpError(400, `Password must be at least ${cfg.passwordMinLength} characters`);
  if (pw.length > 200) throw new HttpError(400, 'Password is too long');
  if (userEmail && pw.toLowerCase().includes(userEmail.split('@')[0].toLowerCase()) && userEmail.split('@')[0].length > 3) {
    throw new HttpError(400, 'Password must not contain your email name');
  }
  if (/^(.)\1+$/.test(pw) || ['password123', '1234567890', 'qwertyuiop'].includes(pw.toLowerCase())) throw new HttpError(400, 'Password is too easy to guess');
}

module.exports = function register(app) {
  const { cfg } = app;

  app.route('POST', '/api/auth/login', { auth: false }, async (ctx) => {
    const body = await readJson(ctx.req);
    const emailLc = email(body.email);
    const password = str(body.password, { min: 1, max: 200, field: 'password' });

    const t = ctx.throttleStatus(emailLc, ctx.ip);
    if (t.locked) {
      ctx.audit.record({ action: 'auth.login_blocked', outcome: 'denied', targetType: 'user', targetId: emailLc, ip: ctx.ip, details: { reason: 'too many failed attempts' } });
      throw new HttpError(429, 'Too many failed attempts. Try again later.', { retryAfter: t.retryAfterSec });
    }

    const user = ctx.db.prepare('SELECT * FROM users WHERE email = ?').get(emailLc);
    const valid = user ? await verifyPassword(password, user.password_hash) : await dummyVerify(password, cfg.scryptCost);
    if (!user || !valid || user.disabled) {
      ctx.recordAttempt(emailLc, ctx.ip, false);
      ctx.audit.record({
        actor: user && !user.disabled ? user : null, action: 'auth.login_failed', outcome: 'denied', targetType: 'user', targetId: emailLc, ip: ctx.ip,
        details: { reason: !user ? 'unknown account' : user.disabled ? 'account disabled' : 'bad password' },
      });
      throw new HttpError(401, 'Invalid email or password'); // identical for every failure cause
    }

    ctx.recordAttempt(emailLc, ctx.ip, true);
    // New session id on every login (prevents session fixation); old sessions stay valid on other devices.
    const { token, csrf } = ctx.createSession(user, ctx.ip, ctx.req.headers['user-agent']);
    ctx.audit.record({ actor: user, action: 'auth.login', outcome: 'allowed', targetType: 'user', targetId: user.id, ip: ctx.ip });
    return {
      body: { user: publicUser(user), csrfToken: csrf },
      headers: { 'Set-Cookie': ctx.sessionCookie(token, Math.floor(cfg.sessionAbsoluteMs / 1000)) },
    };
  });

  app.route('POST', '/api/auth/logout', { allowWhileMustChange: true }, async (ctx) => {
    ctx.db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(ctx.session.idHash);
    ctx.audit.record({ actor: ctx.user, action: 'auth.logout', outcome: 'allowed', targetType: 'user', targetId: ctx.user.id, ip: ctx.ip });
    return { status: 200, body: { ok: true }, headers: { 'Set-Cookie': ctx.sessionCookie('', 0) } };
  });

  app.route('GET', '/api/auth/me', { allowWhileMustChange: true }, async (ctx) => ({
    body: { user: publicUser(ctx.user), csrfToken: ctx.session.csrf },
  }));

  app.route('POST', '/api/auth/password', { allowWhileMustChange: true }, async (ctx) => {
    const body = await readJson(ctx.req);
    const current = str(body.currentPassword, { min: 1, max: 200, field: 'currentPassword' });
    checkNewPassword(cfg, body.newPassword, ctx.user.email);
    if (!(await verifyPassword(current, ctx.user.password_hash))) {
      ctx.audit.record({ actor: ctx.user, action: 'auth.password_change', outcome: 'denied', targetType: 'user', targetId: ctx.user.id, ip: ctx.ip, details: { reason: 'wrong current password' } });
      throw new HttpError(403, 'Current password is incorrect');
    }
    if (body.newPassword === current) throw new HttpError(400, 'New password must be different');
    const hash = await hashPassword(body.newPassword, cfg.scryptCost);
    ctx.db.tx(() => {
      ctx.db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?').run(hash, ctx.user.id);
      ctx.destroySessionsFor(ctx.user.id, ctx.session.idHash); // every OTHER session is logged out
      ctx.audit.record({ actor: ctx.user, action: 'auth.password_change', outcome: 'allowed', targetType: 'user', targetId: ctx.user.id, ip: ctx.ip });
    });
    return { body: { ok: true } };
  });

  // Directory used to pick named people when sharing. Owners/admins only; active accounts only.
  app.route('GET', '/api/users/directory', { roles: ['owner', 'admin'] }, async (ctx) => {
    const q = `%${String(ctx.query.q || '').replace(/[\\%_]/g, '\\$&').slice(0, 60)}%`;
    const rows = ctx.db.prepare(
      `SELECT id, name, email, role, department, is_external FROM users
       WHERE disabled = 0 AND id != ? AND (name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\') ORDER BY name LIMIT 25`
    ).all(ctx.user.id, q, q);
    return { body: { users: rows.map((r) => ({ id: r.id, name: r.name, email: r.email, role: r.role, department: r.department, isExternal: !!r.is_external })) } };
  });
};

module.exports.publicUser = publicUser;
module.exports.checkNewPassword = checkNewPassword;
