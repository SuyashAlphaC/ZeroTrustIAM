'use strict';

/**
 * Validates forward migrations, rollback to empty app schema, and re-apply.
 */

process.env.NODE_ENV = 'test';
process.env.TEST_DATABASE_URL = process.env.TEST_DATABASE_URL
  || 'postgresql://ztiam:testpassword@127.0.0.1:5432/ztiam_test';

const db = require('../../database');

async function listTables() {
  const p = db.getDb();
  const { rows } = await p.query(
    `SELECT table_name FROM information_schema.tables
     WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name`
  );
  return rows.map((r) => r.table_name);
}

beforeAll(async () => {
  await db.init();
});

describe('database migrations', () => {
  it('creates tables on init and clears them on rollback to 0, then reapplies idempotently', async () => {
    await db.init();
    const withSchema = await listTables();
    expect(withSchema).toContain('users');
    expect(withSchema).toContain('schema_migrations');

    await db.rollbackMigrationsTo('0');
    const afterDown = await listTables();
    expect(afterDown).not.toContain('users');

    const { rows: migCount } = await db.getDb().query('SELECT COUNT(*)::int AS c FROM schema_migrations');
    expect(migCount[0].c).toBe(0);

    // Re-apply migrations against the live pool (init() short-circuits if pool already exists).
    const p = db.getDb();
    const client = await p.connect();
    try {
      await client.query('BEGIN');
      for (const m of db.MIGRATIONS) {
        await m.up(client);
        await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [m.id]);
      }
      await client.query('COMMIT');
    } finally {
      client.release();
    }
    const rep = await listTables();
    expect(rep).toContain('users');
    expect(rep).toContain('refresh_tokens');

    const { rows: mig2 } = await db.getDb().query('SELECT name FROM schema_migrations');
    expect(mig2.some((r) => r.name === '001_initial')).toBe(true);
  });
});
