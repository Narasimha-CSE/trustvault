'use strict';
/** Small HTTP primitives shared by the router and the routes. */

class HttpError extends Error {
  constructor(status, message, extra) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

function sendJson(res, status, body, headers = {}) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    ...headers,
  });
  res.end(data);
}

/** Reads a body into a Buffer, refusing as soon as it exceeds `limit` bytes. */
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > limit) {
      req.resume();
      return reject(new HttpError(413, `Body too large (limit ${limit} bytes)`));
    }
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        req.destroy();
        reject(new HttpError(413, `Body too large (limit ${limit} bytes)`));
      } else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', () => reject(new HttpError(400, 'Could not read request body')));
  });
}

async function readJson(req, limit = 64 * 1024) {
  const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (type !== 'application/json') throw new HttpError(415, 'Content-Type must be application/json');
  const buf = await readBody(req, limit);
  if (!buf.length) return {};
  try {
    const v = JSON.parse(buf.toString('utf8'));
    if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error('not an object');
    return v;
  } catch {
    throw new HttpError(400, 'Invalid JSON body');
  }
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

// ---- tiny input validators (all inputs are validated, never trusted) ----

const str = (v, { min = 0, max = 255, field = 'value' } = {}) => {
  if (typeof v !== 'string') throw new HttpError(400, `${field} must be a string`);
  const s = v.trim();
  if (s.length < min || s.length > max) throw new HttpError(400, `${field} must be ${min}-${max} characters`);
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(s)) throw new HttpError(400, `${field} contains control characters`);
  return s;
};

const email = (v) => {
  const s = str(v, { min: 3, max: 254, field: 'email' }).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) throw new HttpError(400, 'email is not valid');
  return s;
};

const uuid = (v, field = 'id') => {
  if (typeof v !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) throw new HttpError(400, `${field} is not valid`);
  return v.toLowerCase();
};

const oneOf = (v, list, field = 'value') => {
  if (!list.includes(v)) throw new HttpError(400, `${field} must be one of: ${list.join(', ')}`);
  return v;
};

function tags(v) {
  if (v === undefined || v === null || v === '') return [];
  const arr = Array.isArray(v) ? v : String(v).split(',');
  const out = [...new Set(arr.map((t) => String(t).trim().toLowerCase()).filter(Boolean))];
  if (out.length > 10) throw new HttpError(400, 'At most 10 tags');
  for (const t of out) if (!/^[a-z0-9][a-z0-9 _-]{0,29}$/.test(t)) throw new HttpError(400, `Invalid tag "${t.slice(0, 30)}" (letters, digits, space, - and _; max 30)`);
  return out;
}

module.exports = { HttpError, sendJson, readBody, readJson, parseCookies, str, email, uuid, oneOf, tags };
