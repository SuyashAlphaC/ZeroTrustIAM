'use strict';

// CLI: apply PostgreSQL migrations, roll back by id, or print applied vs pending.
require('dotenv').config();
const db = require('../database');

(async () => {
  try {
    const [, , cmd, arg] = process.argv;

    if (cmd === 'up') {
      await db.init();
      // eslint-disable-next-line no-console
      console.log('OK: migrations');
      process.exit(0);
    }

    if (cmd === 'down') {
      if (!arg) {
        // eslint-disable-next-line no-console
        console.error('Usage: node scripts/migrate.js down <targetId|0>');
        process.exit(1);
      }
      await db.init();
      await db.rollbackMigrationsTo(arg);
      // eslint-disable-next-line no-console
      console.log(`OK: rolled back to "${arg}"`);
      process.exit(0);
    }

    if (cmd === 'status') {
      await db.init();
      const st = await db.getMigrationStatus();
      // eslint-disable-next-line no-console
      console.log('Applied:', st.applied.map((r) => r.name).join(', ') || '(none)');
      // eslint-disable-next-line no-console
      console.log('Pending:', st.pending.join(', ') || '(none)');
      process.exit(0);
    }

    // eslint-disable-next-line no-console
    console.error('Usage: node scripts/migrate.js up | down <targetId> | status');
    process.exit(1);
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error(e);
    process.exit(1);
  } finally {
    await db.close();
  }
})();
