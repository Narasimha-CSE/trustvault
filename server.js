'use strict';
const { loadConfig } = require('./src/config');
const { createApp } = require('./src/app');
const { createAdmin, seedDemo, userCount } = require('./src/bootstrap');

(async () => {
  const cfg = loadConfig();
  const app = createApp(cfg);

  if (userCount(app) === 0) {
    if (process.env.TV_SEED_DEMO === '1') {
      await seedDemo(app);
      console.log('Demo data loaded (TV_SEED_DEMO=1). Demo passwords are public - do not use this on a real deployment.');
    } else if (process.env.TV_ADMIN_EMAIL && process.env.TV_ADMIN_PASSWORD) {
      await createAdmin(app, process.env.TV_ADMIN_EMAIL, process.env.TV_ADMIN_PASSWORD);
      console.log(`First administrator created: ${process.env.TV_ADMIN_EMAIL} (must change password at first sign-in).`);
    } else {
      console.warn('No users exist. Set TV_ADMIN_EMAIL + TV_ADMIN_PASSWORD, or TV_SEED_DEMO=1, or run: npm run seed');
    }
  }

  const port = await app.start();
  console.log(`TrustVault listening on http://${cfg.host}:${port}  (production=${cfg.production}, secureCookies=${cfg.secureCookies})`);
  const stop = () => app.close().then(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
})().catch((e) => { console.error(e.message); process.exit(1); });
