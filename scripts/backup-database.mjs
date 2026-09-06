import Database from 'better-sqlite3';

const destination = process.argv[2];
if (!process.env.DATABASE_PATH || !destination || process.argv.length !== 3) {
  console.error('Usage: DATABASE_PATH=/data/proof.sqlite node scripts/backup-database.mjs /backups/proof.sqlite');
  process.exit(1);
}
const database = new Database(process.env.DATABASE_PATH, { readonly: true });
try {
  await database.backup(destination);
  const backup = new Database(destination, { readonly: true });
  try {
    if (backup.pragma('integrity_check', { simple: true }) !== 'ok') throw new Error('Backup integrity check failed');
  } finally { backup.close(); }
  console.log('SQLite online backup completed and integrity checked.');
} finally { database.close(); }
