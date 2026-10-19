'use strict';
// Generates a strong TV_SECRET and prints the commands to run. Writes nothing secret to the repo.
const crypto = require('node:crypto');
const secret = crypto.randomBytes(48).toString('base64url');
console.log('# Copy these into your host\'s environment settings (never commit them):\n');
console.log(`TV_SECRET=${secret}`);
console.log('NODE_ENV=production');
console.log('TV_TRUST_PROXY=1            # only when behind a TLS-terminating proxy (Render, Fly, nginx...)');
console.log('TV_ADMIN_EMAIL=you@example.com');
console.log('TV_ADMIN_PASSWORD=<a long temporary password; you must change it at first sign-in>');
console.log('\n# For a judged demo with sample data instead of a real admin:  TV_SEED_DEMO=1');
console.log('# Keep TV_SECRET safe: losing it makes every stored file permanently unreadable.');
