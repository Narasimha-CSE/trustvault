'use strict';
/**
 * Upload validation. We never trust the filename, the extension, or the client-declared type.
 * The extension must be on an allow-list AND the bytes must actually look like that type.
 * Anything else (html, svg, js, exe, ...) is refused. Files are only ever served back as
 * attachments with nosniff, so even an allowed type cannot execute in our origin.
 */
const { HttpError } = require('./http');

const TYPES = {
  pdf:  { mime: 'application/pdf', check: (b) => startsWith(b, '%PDF-') },
  png:  { mime: 'image/png', check: (b) => b.length > 8 && b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) },
  jpg:  { mime: 'image/jpeg', check: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  jpeg: { mime: 'image/jpeg', check: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  docx: { mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', check: (b) => ooxml(b, 'word/') },
  xlsx: { mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', check: (b) => ooxml(b, 'xl/') },
  pptx: { mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', check: (b) => ooxml(b, 'ppt/') },
  txt:  { mime: 'text/plain', check: isText },
  csv:  { mime: 'text/csv', check: isText },
  md:   { mime: 'text/markdown', check: isText },
};

function startsWith(buf, s) {
  return buf.length >= s.length && buf.subarray(0, s.length).toString('latin1') === s;
}

function ooxml(buf, dir) {
  // A zip whose directory contains [Content_Types].xml and the expected part folder.
  if (!(buf.length > 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04)) return false;
  const latin = buf.toString('latin1');
  return latin.includes('[Content_Types].xml') && latin.includes(dir);
}

function isText(buf) {
  if (buf.includes(0)) return false;
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(buf);
    return true;
  } catch {
    return false;
  }
}

/** Reduce an uploaded name to a safe display filename (no paths, no control chars). */
function sanitiseFilename(raw) {
  let name = String(raw ?? '');
  try { name = decodeURIComponent(name); } catch { /* keep as is */ }
  name = name.replace(/\\/g, '/').split('/').pop();                 // strip any directory part
  // eslint-disable-next-line no-control-regex
  name = name.replace(/[\u0000-\u001F\u007F"<>|:*?]/g, '').replace(/^\.+/, '').trim(); // no leading dots / odd chars
  if (name.length > 150) {
    const dot = name.lastIndexOf('.');
    const ext = dot > 0 ? name.slice(dot) : '';
    name = name.slice(0, 150 - ext.length) + ext;
  }
  if (!name) throw new HttpError(400, 'A file name is required');
  return name;
}

function validateUpload(rawName, buffer, maxBytes) {
  const name = sanitiseFilename(rawName);
  if (!buffer || buffer.length === 0) throw new HttpError(400, 'The file is empty');
  if (buffer.length > maxBytes) throw new HttpError(413, `File exceeds the ${Math.round(maxBytes / 1024 / 1024)} MB limit`);
  const dot = name.lastIndexOf('.');
  const ext = dot > 0 ? name.slice(dot + 1).toLowerCase() : '';
  const type = TYPES[ext];
  if (!type) throw new HttpError(415, `File type ".${ext || '?'}" is not allowed. Allowed: ${Object.keys(TYPES).join(', ')}`);
  if (!type.check(buffer)) throw new HttpError(415, `The file contents do not match a valid .${ext} file`);
  return { name, ext, mime: type.mime };
}

module.exports = { validateUpload, sanitiseFilename, ALLOWED_EXTENSIONS: Object.keys(TYPES) };
