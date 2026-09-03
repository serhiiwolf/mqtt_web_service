const path = require('path');
if (Number(process.versions.node.split('.')[0]) < 22) {
  throw new Error('Node.js 22.5 or newer is required because the project uses the built-in node:sqlite module.');
}
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');

const [username, password] = process.argv.slice(2);
if (!username || !password || password.length < 6) {
  console.error('Usage: npm run create-admin -- <username> <password>');
  process.exit(1);
}

const db = new DatabaseSync(path.join(__dirname, '..', 'mqtt-web-service.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    permissions TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);
if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) {
  console.error('User already exists.');
  process.exit(1);
}
db.prepare(`
  INSERT INTO users (username, password_hash, permissions, created_at)
  VALUES (?, ?, ?, ?)
`).run(username, bcrypt.hashSync(password, 10), JSON.stringify([
  'view:dashboard', 'view:nodes_ui', 'view:admin', 'view:mqtt_logs',
  'manage:users', 'grant:permissions', 'manage:devices', 'access:editor'
]), new Date().toISOString());
console.log(`Admin ${username} created.`);
