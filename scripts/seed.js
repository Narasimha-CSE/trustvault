'use strict';
// Loads demo users and documents into an EMPTY database. Usage: node scripts/seed.js
const { loadConfig } = require('../src/config');
const { createApp } = require('../src/app');
const { seedDemo, DEMO_PASSWORDS } = require('../src/bootstrap');

(async () => {
  const app = createApp(loadConfig());
  const did = await seedDemo(app);
  console.log(did ? 'Demo data loaded.' : 'Database already has users; nothing changed.');
  if (did) {
    console.log('\nDemo accounts (public demo credentials):');
    console.log(`  admin    admin@trustvault.demo     ${DEMO_PASSWORDS.admin}`);
    console.log(`  owner    alice@trustvault.demo     ${DEMO_PASSWORDS.owner}`);
    console.log(`  owner    bob@trustvault.demo       ${DEMO_PASSWORDS.owner}`);
    console.log(`  viewer   carol@trustvault.demo     ${DEMO_PASSWORDS.viewer}`);
    console.log(`  viewer   dave@trustvault.demo      ${DEMO_PASSWORDS.viewer}`);
    console.log(`  external partner@external.demo     ${DEMO_PASSWORDS.external}`);
  }
  await app.close();
})().catch((e) => { console.error(e); process.exit(1); });
