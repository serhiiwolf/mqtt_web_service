const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function loadEnvFile() {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!match || process.env[match[1]] !== undefined) continue;
    process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2');
  }
}

loadEnvFile();

if (Number(process.versions.node.split('.')[0]) < 22) {
  throw new Error('Node.js 22.5 or newer is required because the project uses the built-in node:sqlite module.');
}
const { DatabaseSync } = require('node:sqlite');
const RED = require('node-red');
const http = require('http');
const Aedes = require('aedes');
const net = require('net');
const ws = require('ws');
const websocketStream = require('websocket-stream');

const app = express();
// Довіряємо одному proxy (cloudflared або Apache).
// Це дозволяє читати X-Forwarded-Proto: https від Cloudflare
// і правильно визначати реальний IP клієнта.
app.set('trust proxy', 1);
const server = http.createServer(app);

// ── SQLite storage ─────────────────────────────────────────────────────────────
const db = new DatabaseSync(path.join(__dirname, 'mqtt-web-service.db'));
db.exec('PRAGMA journal_mode = WAL;');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    permissions TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS mqtt_devices (
    username TEXT PRIMARY KEY,
    password_encrypted TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS mqtt_event_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    type TEXT NOT NULL,
    client_id TEXT,
    topic TEXT,
    payload TEXT,
    qos INTEGER
  );
`);
const mqttLogColumns = db.prepare('PRAGMA table_info(mqtt_event_logs)').all().map(column => column.name);
if (!mqttLogColumns.includes('username')) {
  db.exec('ALTER TABLE mqtt_event_logs ADD COLUMN username TEXT');
}

const ALL_PERMISSIONS = [
  'view:dashboard', 'view:nodes_ui', 'view:admin', 'view:mqtt_logs',
  'manage:users', 'grant:permissions', 'manage:devices', 'access:editor'
];
const ROLE_PERMISSIONS = {
  user: ['view:dashboard'],
  viewer: ['view:nodes_ui'],
  admin: ALL_PERMISSIONS
};

function permissionsForLegacyRole(role) {
  return ROLE_PERMISSIONS[role] || ROLE_PERMISSIONS.user;
}

function parsePermissions(value) {
  try {
    const permissions = JSON.parse(value || '[]');
    return Array.isArray(permissions) ? permissions.filter(p => typeof p === 'string') : [];
  } catch (error) {
    console.warn('[AUTH] Invalid permissions in database:', error.message);
    return [];
  }
}

function userFromRow(row) {
  if (!row) return null;
  const permissions = parsePermissions(row.permissions);
  const role = permissions.includes('access:editor') ? 'admin' :
    permissions.includes('view:nodes_ui') ? 'viewer' : 'user';
  return { username: row.username, permissions, role, createdAt: row.created_at };
}

function getUser(username) {
  return userFromRow(db.prepare('SELECT username, permissions, created_at FROM users WHERE username = ?').get(username));
}

function getUserWithPassword(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function encryptDevicePassword(password) {
  const keyValue = process.env.MQTT_ENCRYPTION_KEY;
  if (!keyValue) throw new Error('MQTT_ENCRYPTION_KEY is required');
  const key = Buffer.from(keyValue, /^[0-9a-f]{64}$/i.test(keyValue) ? 'hex' : 'base64');
  if (key.length !== 32) throw new Error('MQTT_ENCRYPTION_KEY must be a 32-byte hex or base64 key');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(password, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map(part => part.toString('base64')).join('.');
}

function decryptDevicePassword(value) {
  const keyValue = process.env.MQTT_ENCRYPTION_KEY;
  if (!keyValue) throw new Error('MQTT_ENCRYPTION_KEY is required');
  const key = Buffer.from(keyValue, /^[0-9a-f]{64}$/i.test(keyValue) ? 'hex' : 'base64');
  if (key.length !== 32) throw new Error('MQTT_ENCRYPTION_KEY must be a 32-byte hex or base64 key');
  const [iv, authTag, encrypted] = value.split('.').map(part => Buffer.from(part, 'base64'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

function migrateUsers() {
  const count = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
  const legacyFile = path.join(__dirname, 'users.json');
  if (count !== 0 || !fs.existsSync(legacyFile)) return;
  const legacyUsers = JSON.parse(fs.readFileSync(legacyFile, 'utf8'));
  const insert = db.prepare(`
    INSERT INTO users (username, password_hash, permissions, created_at)
    VALUES (?, ?, ?, ?)
  `);
  db.exec('BEGIN');
  try {
    for (const [username, user] of Object.entries(legacyUsers)) {
      insert.run(username, user.password, JSON.stringify(permissionsForLegacyRole(user.role)), user.createdAt || new Date().toISOString());
    }
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
  fs.renameSync(legacyFile, `${legacyFile}.migrated`);
  console.log('[AUTH] Migrated users.json to SQLite.');
}

migrateUsers();

// ── MQTT Broker ────────────────────────────────────────────────────────────────
const aedes = Aedes();
const MQTT_EVENT_LOG_RETENTION_MS = 3 * 24 * 60 * 60 * 1000;

aedes.authenticate = (client, username, password, callback) => {
  try {
    if (!username || password == null) return callback(new Error('MQTT authentication required'), false);
    const device = db.prepare('SELECT password_encrypted FROM mqtt_devices WHERE username = ?').get(String(username));
    if (!device || decryptDevicePassword(device.password_encrypted) !== Buffer.from(password).toString('utf8')) {
      return callback(new Error('Invalid MQTT credentials'), false);
    }
    client.username = String(username);
    pushMqttEvent({ type: 'connect', clientId: client.id || 'unknown', username: client.username });
    callback(null, true);
  } catch (error) {
    callback(error, false);
  }
};

function pushMqttEvent(event) {
  const loggedEvent = {
    ts: new Date().toISOString(),
    ...event
  };
  db.prepare(`
    INSERT INTO mqtt_event_logs (ts, type, client_id, username, topic, payload, qos)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    loggedEvent.ts,
    loggedEvent.type || 'unknown',
    loggedEvent.clientId || null,
    loggedEvent.username || null,
    loggedEvent.topic || null,
    loggedEvent.payload || null,
    loggedEvent.qos ?? null
  );
  pruneMqttEventLogs();
}

function pruneMqttEventLogs() {
  const cutoff = new Date(Date.now() - MQTT_EVENT_LOG_RETENTION_MS).toISOString();
  db.prepare('DELETE FROM mqtt_event_logs WHERE ts < ?').run(cutoff);
}

function readMqttEventLogs() {
  pruneMqttEventLogs();
  return db.prepare(`
    SELECT ts, type, client_id AS clientId, username, topic, payload, qos
    FROM mqtt_event_logs
    ORDER BY ts DESC, id DESC
  `).all();
}

function readMqttDeviceStatuses() {
  pruneMqttEventLogs();
  return db.prepare(`
    SELECT d.username, d.created_at AS createdAt,
      (
        SELECT e.ts FROM mqtt_event_logs e
        WHERE e.username = d.username AND e.type = 'connect'
        ORDER BY e.ts DESC, e.id DESC LIMIT 1
      ) AS connectedAt,
      (
        SELECT e.ts FROM mqtt_event_logs e
        WHERE e.username = d.username AND e.type = 'disconnect'
        ORDER BY e.ts DESC, e.id DESC LIMIT 1
      ) AS disconnectedAt
    FROM mqtt_devices d
    ORDER BY d.username
  `).all().map((device) => ({
    ...device,
    connected: Boolean(device.connectedAt) &&
      (!device.disconnectedAt || device.connectedAt > device.disconnectedAt)
  }));
}

function clipPayload(payload, maxLen = 200) {
  if (payload == null) return '';
  const asString = String(payload);
  return asString.length > maxLen ? `${asString.slice(0, maxLen)}…` : asString;
}

// TCP MQTT  (mqtt://localhost:1883)
const mqttServer = net.createServer(aedes.handle);
mqttServer.listen(1883, () => {
  console.log('MQTT broker: mqtt://localhost:1883');
});

// WebSocket MQTT  (ws://localhost:3000/mqtt) — for browser clients
const wssServer = new ws.Server({ noServer: true });
server.on('upgrade', (request, socket, head) => {
  const pathname = new URL(request.url, 'http://localhost').pathname;
  if (pathname !== '/mqtt') return;
  wssServer.handleUpgrade(request, socket, head, (clientSocket) => {
    wssServer.emit('connection', clientSocket, request);
  });
});
wssServer.on('connection', (socket) => {
  // MQTT over WebSocket must stay in binary mode.
  // objectMode may corrupt MQTT frames and cause disconnects after publish.
  const stream = websocketStream(socket, { binary: true });
  socket.on('error', (err) => {
    console.warn('[MQTT][WS] socket error:', err.message);
  });
  aedes.handle(stream);
});

aedes.on('client', (client) => {
  console.log(`[MQTT] client connected: ${client.id}`);
});
aedes.on('clientDisconnect', (client) => {
  pushMqttEvent({ type: 'disconnect', clientId: client.id || 'unknown', username: client.username || null });
  console.log(`[MQTT] client disconnected: ${client.id}`);
});
aedes.on('publish', (packet, client) => {
  if (client) {
    pushMqttEvent({
      type: 'publish',
      clientId: client.id || 'unknown',
      username: client.username || null,
      topic: packet.topic,
      payload: clipPayload(packet.payload && packet.payload.toString())
    });
    console.log(`[MQTT] ${packet.topic}: ${packet.payload.toString()}`);
  }
});

aedes.on('subscribe', (subscriptions, client) => {
  if (!client || !Array.isArray(subscriptions)) return;
  subscriptions.forEach((sub) => {
    pushMqttEvent({
      type: 'subscribe',
      clientId: client.id || 'unknown',
      username: client.username || null,
      topic: sub.topic,
      qos: sub.qos
    });
  });
});

aedes.on('unsubscribe', (subscriptions, client) => {
  if (!client || !Array.isArray(subscriptions)) return;
  subscriptions.forEach((topic) => {
    pushMqttEvent({
      type: 'unsubscribe',
      clientId: client.id || 'unknown',
      username: client.username || null,
      topic
    });
  });
});

// ── Session & body parsing ─────────────────────────────────────────────────────
// NODE_ENV=production встановлюється в systemd service на сервері.
// Це вмикає secure cookie — обов'язково при роботі через Cloudflare HTTPS.
const isProd = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET || 'dev-change-me-session-secret';
const nodeRedCredentialSecret = process.env.NODERED_CREDENTIAL_SECRET || 'dev-change-me-nodered-credential-secret';

if (isProd && (!process.env.SESSION_SECRET || !process.env.NODERED_CREDENTIAL_SECRET || !process.env.MQTT_ENCRYPTION_KEY)) {
  throw new Error('[SECURITY] SESSION_SECRET, NODERED_CREDENTIAL_SECRET and MQTT_ENCRYPTION_KEY are required in production.');
}

app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    secure: isProd ? 'auto' : false, // HTTPS за проксі, HTTP для локальної розробки
    sameSite: 'lax'
  }
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use((req, res, next) => {
  if (req.method === 'GET' && req.path.toLowerCase().endsWith('.html')) {
    return res.status(404).end();
  }
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

function getLandingPathForUser(user) {
  if (user && user.permissions.includes('access:editor')) return '/editor';
  if (user && user.permissions.includes('view:nodes_ui')) return '/nodes/ui';
  return '/dashboard';
}

function isBrowserLikeRequest(req) {
  return req.xhr || (req.headers.accept && req.headers.accept.includes('application/json'));
}

function isAjaxLikeRequest(req) {
  return isBrowserLikeRequest(req) || req.path.startsWith('/comms') || req.path.startsWith('/auth') || req.path.match(/\.(js|css|png|ico|json|map)$/);
}

function redirectToLanding(req, res) {
  if (req.session && req.session.user) {
    return res.redirect(getLandingPathForUser(getUser(req.session.user.username)));
  }
  return res.redirect('/dashboard');
}

// ── Auth routes ────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/dashboard');
  res.redirect(getLandingPathForUser(getUser(req.session.user.username)));
});

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect(getLandingPathForUser(getUser(req.session.user.username)));
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect(getLandingPathForUser(getUser(req.session.user.username)));
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', (req, res) => {
  const user = req.session.user && getUser(req.session.user.username);
  if (user && !user.permissions.includes('view:dashboard')) {
    return res.redirect(getLandingPathForUser(user));
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.json({ error: 'Заповніть всі поля' });
  if (password.length < 6)
    return res.json({ error: 'Пароль — мінімум 6 символів' });

  if (getUser(username))
    return res.json({ error: 'Користувач із таким іменем вже існує' });

  const hash = await bcrypt.hash(password, 10);
  db.prepare(`
    INSERT INTO users (username, password_hash, permissions, created_at)
    VALUES (?, ?, ?, ?)
  `).run(username, hash, JSON.stringify(ROLE_PERMISSIONS.user), new Date().toISOString());

  req.session.user = { username };
  res.json({ success: true, redirectTo: '/dashboard' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.json({ error: 'Заповніть всі поля' });

  const user = getUserWithPassword(username);
  if (!user)
    return res.json({ error: 'Невірний логін або пароль' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid)
    return res.json({ error: 'Невірний логін або пароль' });

  const profile = userFromRow(user);
  req.session.user = { username };
  res.json({ success: true, role: profile.role, permissions: profile.permissions, redirectTo: getLandingPathForUser(profile) });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/dashboard'));
});

// ── Session info endpoint (used by dashboard) ──────────────────────────────────
app.get('/api/me', (req, res) => {
  if (req.session.user) {
    const user = getUser(req.session.user.username);
    if (user) return res.json(user);
  }
  res.status(401).json({ error: 'not authenticated' });
});

app.get('/api/mqtt/logs', requirePermission('view:mqtt_logs'), (req, res) => {
  res.json({ items: readMqttEventLogs(), retentionDays: 3 });
});

app.get('/api/mqtt/devices/status', requirePermission('view:dashboard'), (req, res) => {
  res.json(readMqttDeviceStatuses());
});

app.post('/api/mqtt/publish', requirePermission('view:dashboard'), (req, res) => {
  const topic = typeof req.body.topic === 'string' ? req.body.topic.trim() : '';
  const payload = typeof req.body.payload === 'string' ? req.body.payload : '';
  if (!topic || topic.includes('#') || topic.includes('+') || topic.length > 65535) {
    return res.status(400).json({ error: 'Вкажіть коректний MQTT topic без wildcard-символів' });
  }
  if (Buffer.byteLength(payload, 'utf8') > 1024 * 1024) {
    return res.status(400).json({ error: 'Payload не може перевищувати 1 MiB' });
  }

  const clientId = `dashboard:${req.currentUser.username}`;
  const packet = { topic, payload: Buffer.from(payload, 'utf8'), qos: 0, retain: false };
  try {
    aedes.publish(packet, (error) => {
      if (error) return res.status(502).json({ error: 'Не вдалося опублікувати MQTT повідомлення' });
      pushMqttEvent({ type: 'publish', clientId, topic, payload: clipPayload(payload) });
      res.json({ success: true, topic, payload });
    });
  } catch (error) {
    console.error('[MQTT] dashboard publish failed:', error);
    res.status(502).json({ error: 'Не вдалося опублікувати MQTT повідомлення' });
  }
});

// ── Permission middleware ──────────────────────────────────────────────────────
function requirePermission(permission) {
  return (req, res, next) => {
    const user = req.session && req.session.user && getUser(req.session.user.username);
    if (user && user.permissions.includes(permission)) {
      req.currentUser = user;
      return next();
    }
    res.status(403).json({ error: 'Доступ заборонено' });
  };
}

function requireDashboardViewerOrAdmin(req, res, next) {
  const user = req.session && req.session.user && getUser(req.session.user.username);
  if (!user) {
    if (isAjaxLikeRequest(req)) return res.status(401).json({ error: 'Unauthorized' });
    return res.redirect('/dashboard');
  }

  if (user.permissions.includes('view:nodes_ui')) return next();

  if (isBrowserLikeRequest(req)) {
    return res.status(403).json({ error: 'Доступ заборонено' });
  }
  return res.redirect('/dashboard');
}

function requireAdminPage(req, res, next) {
  const user = req.session && req.session.user && getUser(req.session.user.username);
  if (!user) return res.redirect('/dashboard');
  if (!user.permissions.includes('view:admin')) return res.redirect(getLandingPathForUser(user));
  req.currentUser = user;
  next();
}

// ── Admin API ──────────────────────────────────────────────────────────────────
app.get('/admin', (req, res) => {
  const user = req.session.user && getUser(req.session.user.username);
  if (!user) return res.redirect('/dashboard');
  if (!user.permissions.includes('view:admin')) return res.redirect(getLandingPathForUser(user));
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin/mqtt-logs', (req, res) => {
  const user = req.session.user && getUser(req.session.user.username);
  if (!user) return res.redirect('/dashboard');
  if (!user.permissions.includes('view:mqtt_logs')) return res.redirect(getLandingPathForUser(user));
  res.sendFile(path.join(__dirname, 'public', 'mqtt-logs.html'));
});

app.get('/admin/mqtt-devices', (req, res) => {
  const user = req.session.user && getUser(req.session.user.username);
  if (!user) return res.redirect('/dashboard');
  if (!user.permissions.includes('manage:devices')) return res.redirect(getLandingPathForUser(user));
  res.sendFile(path.join(__dirname, 'public', 'mqtt-devices.html'));
});

app.get('/api/users', requirePermission('view:admin'), (req, res) => {
  const list = db.prepare('SELECT username, permissions, created_at FROM users ORDER BY username').all()
    .map(userFromRow);
  res.json(list);
});

app.patch('/api/users/:username/permissions', requirePermission('grant:permissions'), (req, res) => {
  const { username } = req.params;
  const permissions = Array.isArray(req.body.permissions) ? [...new Set(req.body.permissions)] : null;
  if (!permissions || permissions.some(permission => !ALL_PERMISSIONS.includes(permission))) {
    return res.status(400).json({ error: 'Невалідні права' });
  }
  const user = getUser(username);
  if (!user)
    return res.status(404).json({ error: 'Користувача не знайдено' });
  if (username === req.session.user.username && !permissions.includes('grant:permissions')) {
    return res.status(400).json({ error: 'Не можна забрати власні права керування' });
  }
  db.prepare('UPDATE users SET permissions = ? WHERE username = ?').run(JSON.stringify(permissions), username);
  res.json({ success: true });
});

app.patch('/api/users/:username/role', requirePermission('grant:permissions'), (req, res) => {
  const role = req.body.role;
  if (!Object.prototype.hasOwnProperty.call(ROLE_PERMISSIONS, role)) {
    return res.status(400).json({ error: 'Невалідна роль' });
  }
  const user = getUser(req.params.username);
  if (!user) return res.status(404).json({ error: 'Користувача не знайдено' });
  if (req.params.username === req.session.user.username && role !== 'admin') {
    return res.status(400).json({ error: 'Не можна забрати власні права керування' });
  }
  db.prepare('UPDATE users SET permissions = ? WHERE username = ?')
    .run(JSON.stringify(permissionsForLegacyRole(role)), req.params.username);
  res.json({ success: true });
});

app.delete('/api/users/:username', requirePermission('manage:users'), (req, res) => {
  const { username } = req.params;
  if (username === req.session.user.username)
    return res.status(400).json({ error: 'Не можна видалити себе' });
  if (!getUser(username))
    return res.status(404).json({ error: 'Користувача не знайдено' });
  db.prepare('DELETE FROM users WHERE username = ?').run(username);
  res.json({ success: true });
});

app.post('/api/mqtt/devices', requirePermission('manage:devices'), (req, res) => {
  const { username } = req.body;
  if (!username || !/^[A-Za-z0-9._-]{3,64}$/.test(username)) {
    return res.status(400).json({ error: 'Username пристрою має містити 3–64 дозволених символи' });
  }
  if (db.prepare('SELECT 1 FROM mqtt_devices WHERE username = ?').get(username)) {
    return res.status(409).json({ error: 'Такий MQTT-пристрій вже існує' });
  }
  const password = crypto.randomBytes(24).toString('base64url').slice(0, 16);
  db.prepare('INSERT INTO mqtt_devices (username, password_encrypted, created_at) VALUES (?, ?, ?)')
    .run(username, encryptDevicePassword(password), new Date().toISOString());
  res.status(201).json({ username, password });
});

app.get('/api/mqtt/devices', requirePermission('manage:devices'), (req, res) => {
  res.json(db.prepare('SELECT username, created_at AS createdAt FROM mqtt_devices ORDER BY username').all());
});

app.get('/api/mqtt/devices/:username/password', requirePermission('manage:devices'), (req, res) => {
  const device = db.prepare('SELECT password_encrypted FROM mqtt_devices WHERE username = ?').get(req.params.username);
  if (!device) return res.status(404).json({ error: 'Пристрій не знайдено' });
  res.json({ username: req.params.username, password: decryptDevicePassword(device.password_encrypted) });
});

app.delete('/api/mqtt/devices/:username', requirePermission('manage:devices'), (req, res) => {
  const result = db.prepare('DELETE FROM mqtt_devices WHERE username = ?').run(req.params.username);
  if (!result.changes) return res.status(404).json({ error: 'Пристрій не знайдено' });
  res.json({ success: true });
});
// ── Node-RED auth middleware ───────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.user && getUser(req.session.user.username)) return next();
  const isAjax =
    req.xhr ||
    (req.headers.accept && req.headers.accept.includes('application/json')) ||
    req.path.startsWith('/comms') ||
    req.path.startsWith('/auth') ||
    req.path.match(/\.(js|css|png|ico|json|map)$/);
  if (isAjax) return res.status(401).json({ error: 'Unauthorized' });
  res.redirect('/login');
}

function requireAdminForEditor(req, res, next) {
  const user = req.session && req.session.user && getUser(req.session.user.username);
  if (!user) {
    if (isAjaxLikeRequest(req)) return res.status(401).json({ error: 'Unauthorized' });
    return res.redirect('/dashboard');
  }

  if (user.permissions.includes('access:editor')) return next();

  if (isBrowserLikeRequest(req)) {
    return res.status(403).json({ error: 'Доступ заборонено' });
  }
  return res.redirect(getLandingPathForUser(user));
}

function requireNodeHttpAccess(req, res, next) {
  if (req.path.startsWith('/ui')) {
    return requireDashboardViewerOrAdmin(req, res, next);
  }
  return requirePermission('access:editor')(req, res, next);
}

// ── Node-RED ───────────────────────────────────────────────────────────────────
const noderedUserDir = path.join(__dirname, '.node-red');
if (!fs.existsSync(noderedUserDir)) fs.mkdirSync(noderedUserDir, { recursive: true });

const settings = {
  httpAdminRoot: '/editor',
  httpNodeRoot: '/nodes',
  userDir: noderedUserDir,
  flowFile: 'flows.json',
  credentialSecret: nodeRedCredentialSecret,
  httpAdminMiddleware: requireAdminForEditor,
  disableEditor: false,
  functionGlobalContext: {},
  ui: {
    path: 'ui',
    middleware: requireDashboardViewerOrAdmin
  },
  logging: {
    console: { level: 'warn', metrics: false, audit: false }
  },
  editorTheme: {
    page: {
      title: 'Node-RED — MQTT',
      scripts: [path.join(__dirname, 'public', 'editor-nav.js')]
    }
  }
};

RED.init(server, settings);
app.use(settings.httpAdminRoot, requireAdminPage, RED.httpAdmin);
app.use(settings.httpNodeRoot, requireNodeHttpAccess, RED.httpNode);

// ── Start ──────────────────────────────────────────────────────────────────────
server.listen(3000, '127.0.0.1', () => {
  console.log('');
  console.log('  App:          http://localhost:3000');
  console.log('  Dashboard:    http://localhost:3000/dashboard');
  console.log('  Node-RED UI:  http://localhost:3000/nodes/ui');
  console.log('  Node-RED:     http://localhost:3000/editor');
  console.log('  MQTT:         mqtt://localhost:1883');
  console.log('  MQTT (WS):    ws://localhost:3000/mqtt');
  console.log('');
});

RED.start();
