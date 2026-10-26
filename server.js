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

const isProd = process.env.NODE_ENV === 'production';
if (isProd && (!process.env.SESSION_SECRET || !process.env.NODERED_CREDENTIAL_SECRET || !process.env.MQTT_ENCRYPTION_KEY || !process.env.JWT_SECRET)) {
  throw new Error('[SECURITY] SESSION_SECRET, NODERED_CREDENTIAL_SECRET, MQTT_ENCRYPTION_KEY and JWT_SECRET are required in production.');
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

// CORS для мобільного застосунку (SWOLF Auth Android) та зовнішніх клієнтів
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-API-Key');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

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
  CREATE TABLE IF NOT EXISTS nav_pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    permission_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sensor_telemetry (
    device_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    value TEXT NOT NULL,
    unit TEXT,
    raw_payload TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (device_id, metric)
  );
`);
const mqttLogColumns = db.prepare('PRAGMA table_info(mqtt_event_logs)').all().map(column => column.name);
if (!mqttLogColumns.includes('username')) {
  db.exec('ALTER TABLE mqtt_event_logs ADD COLUMN username TEXT');
}
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_mqtt_event_logs_ts ON mqtt_event_logs (ts);
  CREATE INDEX IF NOT EXISTS idx_mqtt_event_logs_username_type ON mqtt_event_logs (username, type);
`);

const userColumns = db.prepare('PRAGMA table_info(users)').all().map(column => column.name);
if (!userColumns.includes('email')) {
  db.exec('ALTER TABLE users ADD COLUMN email TEXT');
  console.log('[AUTH] Added email column to users table.');
}

const deviceColumns = db.prepare('PRAGMA table_info(mqtt_devices)').all().map(column => column.name);
if (!deviceColumns.includes('owner_email')) {
  db.exec('ALTER TABLE mqtt_devices ADD COLUMN owner_email TEXT');
  console.log('[AUTH] Added owner_email column to mqtt_devices table.');
}

const navPageColumns = db.prepare('PRAGMA table_info(nav_pages)').all().map(column => column.name);
if (!navPageColumns.includes('created_by')) {
  db.exec('ALTER TABLE nav_pages ADD COLUMN created_by TEXT');
  db.exec("UPDATE nav_pages SET created_by = 'admin' WHERE created_by IS NULL");
  console.log('[AUTH] Added created_by column to nav_pages table.');
}

const ALL_PERMISSIONS = [
  'view:dashboard', 'view:nodes_ui', 'view:admin', 'view:mqtt_logs',
  'manage:users', 'grant:permissions', 'manage:devices', 'manage:navigation', 'access:editor'
];

try {
  const usersWithAdmin = db.prepare('SELECT username, permissions FROM users').all();
  usersWithAdmin.forEach(u => {
    const perms = parsePermissions(u.permissions);
    if (perms.includes('grant:permissions') || perms.includes('view:admin') || perms.includes('access:editor')) {
      if (!perms.includes('manage:navigation')) {
        perms.push('manage:navigation');
        db.prepare('UPDATE users SET permissions = ? WHERE username = ?').run(JSON.stringify(perms), u.username);
      }
    }
  });
} catch (e) {}

function getAllNavPages() {
  return db.prepare('SELECT id, title, path, permission_key, created_by AS createdBy, created_at AS createdAt FROM nav_pages ORDER BY id ASC').all();
}

function getAllDevicePermissions() {
  const devices = db.prepare('SELECT username FROM mqtt_devices').all();
  let telemetryDevs = [];
  try {
    telemetryDevs = db.prepare('SELECT DISTINCT device_id FROM sensor_telemetry').all().map(r => ({ username: r.device_id }));
  } catch (e) {}
  const allNames = new Set([...devices.map(d => d.username), ...telemetryDevs.map(d => d.username)]);
  return Array.from(allNames).map(name => `device:${name}`);
}

function getAllValidPermissions() {
  const dynamic = getAllNavPages().map(page => page.permission_key);
  const devicePerms = getAllDevicePermissions();
  return [...new Set([...ALL_PERMISSIONS, ...dynamic, ...devicePerms])];
}
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
  return { username: row.username, email: row.email || null, permissions, role, createdAt: row.created_at };
}

function getUser(username) {
  if (!username) return null;
  return userFromRow(db.prepare('SELECT username, email, permissions, created_at FROM users WHERE LOWER(username) = LOWER(?)').get(String(username).trim()));
}

function getUserByEmail(email) {
  if (!email) return null;
  return userFromRow(db.prepare('SELECT username, email, permissions, created_at FROM users WHERE LOWER(email) = LOWER(?) ORDER BY rowid DESC').get(String(email).trim()));
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
}

function pruneMqttEventLogs() {
  try {
    const cutoff = new Date(Date.now() - MQTT_EVENT_LOG_RETENTION_MS).toISOString();
    const result = db.prepare('DELETE FROM mqtt_event_logs WHERE ts < ?').run(cutoff);
    if (result && result.changes > 0) {
      console.log(`[MQTT] Pruned ${result.changes} event logs older than 3 days.`);
    }
  } catch (err) {
    console.error('[MQTT] Prune event logs error:', err.message);
  }
}

const MQTT_EVENT_LOG_PRUNE_INTERVAL_MS = 60 * 60 * 1000; // 1 hour
// Initial prune on startup
pruneMqttEventLogs();
// Background timer for periodic log pruning
const mqttPruneTimer = setInterval(pruneMqttEventLogs, MQTT_EVENT_LOG_PRUNE_INTERVAL_MS);
if (mqttPruneTimer.unref) mqttPruneTimer.unref();

function readMqttEventLogs() {
  const cutoff = new Date(Date.now() - MQTT_EVENT_LOG_RETENTION_MS).toISOString();
  return db.prepare(`
    SELECT ts, type, client_id AS clientId, username, topic, payload, qos
    FROM mqtt_event_logs
    WHERE ts >= ?
    ORDER BY ts DESC, id DESC
  `).all(cutoff);
}

function readMqttDeviceStatuses() {
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

// ── JWT verification & signing helpers (HS256 via process.env.JWT_SECRET) ─────
function signJwtToken(payload) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET is not configured in environment');
  const headerB64 = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signatureB64 = crypto.createHmac('sha256', secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64url');
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

function verifyJwtToken(token) {
  if (!token || typeof token !== 'string') return null;
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    console.warn('[AUTH] JWT_SECRET is not set in environment.');
    return null;
  }

  try {
    const parts = token.trim().split('.');
    if (parts.length !== 3) {
      console.warn('[AUTH] JWT format invalid: expected 3 parts, got', parts.length);
      return null;
    }
    const [headerB64, payloadB64, signatureB64] = parts;
    const cleanSig = signatureB64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    const expectedSignature = crypto.createHmac('sha256', secret)
      .update(`${headerB64}.${payloadB64}`)
      .digest('base64url');

    const sigBuf = Buffer.from(cleanSig);
    const expBuf = Buffer.from(expectedSignature);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      console.warn('[AUTH] JWT signature mismatch.');
      return null;
    }

    const verifiedPayload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    if (verifiedPayload.exp && Date.now() >= verifiedPayload.exp * 1000) {
      console.warn('[AUTH] JWT expired at', new Date(verifiedPayload.exp * 1000).toISOString());
      return null;
    }
    return verifiedPayload;
  } catch (err) {
    console.warn('[AUTH] JWT verification error:', err.message);
    return null;
  }
}

function extractTokenFromRequest(req) {
  if (!req || !req.headers) return null;

  // 1. Direct Authorization / HTTP_AUTHORIZATION headers (Apache / reverse-proxy safe)
  const authHeader = req.headers.authorization ||
                     req.headers.Authorization ||
                     req.headers.http_authorization ||
                     req.headers.HTTP_AUTHORIZATION ||
                     req.headers['x-http-authorization'];
  if (authHeader && typeof authHeader === 'string') {
    const trimmed = authHeader.trim();
    if (trimmed && trimmed !== '(null)' && trimmed !== 'null' && trimmed !== 'undefined') {
      if (/^bearer\s+/i.test(trimmed)) {
        const candidate = trimmed.replace(/^bearer\s+/i, '').trim();
        if (candidate && candidate !== 'null' && candidate !== 'undefined') return candidate;
      }
      // Raw JWT format (3 base64url parts separated by dots)
      if (trimmed.split('.').length === 3) {
        return trimmed;
      }
    }
  }

  // 2. Scan all incoming headers for any Bearer or raw JWT token (e.g. x-api-key, auth-token, etc.)
  for (const [key, value] of Object.entries(req.headers)) {
    if (typeof value !== 'string') continue;
    const trimmed = value.trim();
    if (/^bearer\s+ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i.test(trimmed)) {
      return trimmed.replace(/^bearer\s+/i, '').trim();
    }
    if (/^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(trimmed)) {
      return trimmed;
    }
  }

  // 3. Query string parameters (?token= or ?apiKey=)
  if (req.query) {
    for (const val of Object.values(req.query)) {
      if (typeof val === 'string' && /^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(val.trim())) {
        return val.trim();
      }
    }
  }

  // 4. Cookies (e.g. token=ey... or jwt=ey...)
  if (req.headers && req.headers.cookie) {
    const cookies = req.headers.cookie.split(';');
    for (const c of cookies) {
      const parts = c.trim().split('=');
      if (parts.length >= 2) {
        const val = parts.slice(1).join('=').trim();
        if (/^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(val)) {
          return val;
        }
      }
    }
  }

  return null;
}

function getAuthUser(req) {
  const token = extractTokenFromRequest(req);
  if (token) {
    const tokenUser = authenticateUserFromToken(token);
    if (tokenUser) return tokenUser;
    console.warn('[AUTH] Token found in request headers, but failed verification.');
  }

  // Check web session
  if (req.session && req.session.user) {
    const sessionUser = getUser(req.session.user.username);
    if (sessionUser) return sessionUser;
  }

  return null;
}

function authenticateUserFromToken(token) {
  const verified = verifyJwtToken(token);
  if (!verified) return null;

  let user = null;
  // 1. Try matching by username / sub / name
  if (verified.username) user = getUser(verified.username);
  if (!user && verified.name) user = getUser(verified.name);
  if (!user && verified.sub) user = getUser(verified.sub);
  // 2. Fall back to email
  if (!user && verified.email) user = getUserByEmail(verified.email);

  // If user profile is linked by email/username in SQLite:
  if (user) {
    const tokenDevs = Array.isArray(verified.devices)
      ? verified.devices.map(d => (String(d).startsWith('device:') ? String(d) : `device:${d}`))
      : (typeof verified.deviceId === 'string' && verified.deviceId ? [`device:${verified.deviceId}`] : []);
    const mergedPerms = tokenDevs.length > 0
      ? Array.from(new Set([...user.permissions, ...tokenDevs]))
      : user.permissions;
    return { ...user, permissions: mergedPerms, isJwt: true, tokenData: verified };
  }

  // If valid token issued by SWOLF Auth with Admin role:
  const isSwolfAdmin = Boolean(verified.role && /admin/i.test(verified.role));
  let fallbackPerms = isSwolfAdmin ? ALL_PERMISSIONS : ROLE_PERMISSIONS.user;
  if (Array.isArray(verified.permissions)) {
    fallbackPerms = verified.permissions;
  }
  if (Array.isArray(verified.devices)) {
    const devPerms = verified.devices.map(d => (String(d).startsWith('device:') ? String(d) : `device:${d}`));
    fallbackPerms = [...fallbackPerms, ...devPerms];
  } else if (typeof verified.deviceId === 'string' && verified.deviceId) {
    fallbackPerms = [...fallbackPerms, `device:${verified.deviceId}`];
  }

  return {
    username: verified.email || verified.name || verified.sub || 'swolf_auth_user',
    email: verified.email || null,
    permissions: fallbackPerms,
    role: isSwolfAdmin ? 'admin' : 'user',
    isJwt: true,
    tokenData: verified
  };
}

// ── Sensor telemetry handlers ──────────────────────────────────────────────────
const METRIC_UNITS = {
  Temp: '°C',
  HUMIDITY: '%',
  PRESSURE: 'hPa',
  ALTITUDE: 'm'
};
const KNOWN_METRIC_KEYS = new Set(['temp', 'humidity', 'pressure', 'altitude', 'status']);

function handleSensorTelemetry(topic, payloadStr, timestamp = new Date().toISOString()) {
  if (!topic || !payloadStr) return;
  const match = topic.match(/^Metrics\/([^/]+)\/([^/]+)$/i);
  if (!match) return;

  const topicPart1 = match[1];
  const topicPart2 = match[2];

  if (payloadStr.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(payloadStr);

      let payloadDevId = null;
      if (parsed.device_id) payloadDevId = String(parsed.device_id);
      else if (parsed.data && parsed.data.device_id) payloadDevId = String(parsed.data.device_id);

      let rawMetric = topicPart1;
      let deviceId = payloadDevId || topicPart2;

      // Handle both Metrics/<deviceId>/<metric> and Metrics/<metric>/<deviceId>
      if (KNOWN_METRIC_KEYS.has(topicPart2.toLowerCase()) && !KNOWN_METRIC_KEYS.has(topicPart1.toLowerCase())) {
        rawMetric = topicPart2;
        deviceId = payloadDevId || topicPart1;
      } else if (KNOWN_METRIC_KEYS.has(topicPart1.toLowerCase())) {
        rawMetric = topicPart1;
        deviceId = payloadDevId || topicPart2;
      }

      const metricType = parsed.type || rawMetric;

      if (metricType.toLowerCase() === 'status') {
        const state = (parsed.data && parsed.data.state) ? parsed.data.state : (parsed.state || 'online');
        db.prepare(`
          INSERT INTO sensor_telemetry (device_id, metric, value, unit, raw_payload, updated_at)
          VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(device_id, metric) DO UPDATE SET
            value = excluded.value,
            unit = excluded.unit,
            raw_payload = excluded.raw_payload,
            updated_at = excluded.updated_at
        `).run(deviceId, 'status', state, '', payloadStr, timestamp);
        return;
      }

      const dataVal = parsed.data !== undefined ? String(parsed.data) : (parsed.value !== undefined ? String(parsed.value) : '');
      const unit = METRIC_UNITS[rawMetric] || METRIC_UNITS[metricType] || '';

      db.prepare(`
        INSERT INTO sensor_telemetry (device_id, metric, value, unit, raw_payload, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id, metric) DO UPDATE SET
          value = excluded.value,
          unit = excluded.unit,
          raw_payload = excluded.raw_payload,
          updated_at = excluded.updated_at
      `).run(deviceId, rawMetric, dataVal, unit, payloadStr, timestamp);

      console.log(`[TELEMETRY] ${deviceId} -> ${rawMetric}: ${dataVal} ${unit}`);
    } catch (e) {
      // payload not JSON
    }
  }
}

function requestSensorRefresh(deviceId, callback) {
  const metricsToQuery = ['Temp', 'HUMIDITY', 'PRESSURE', 'ALTITUDE'];
  let count = 0;
  for (const m of metricsToQuery) {
    const topic = `Metrics/${m}/${deviceId}`;
    const packet = {
      topic,
      payload: Buffer.from('get', 'utf8'),
      qos: 1,
      retain: false
    };
    aedes.publish(packet, (err) => {
      if (err) console.error(`[MQTT] Publish refresh to ${topic} error:`, err);
      count++;
      if (count === metricsToQuery.length && callback) {
        callback();
      }
    });
  }
}

function getSensorTelemetry(targetDeviceId = null, user = null) {
  let query = 'SELECT device_id, metric, value, unit, raw_payload, updated_at FROM sensor_telemetry';
  const params = [];
  if (targetDeviceId) {
    query += ' WHERE device_id = ?';
    params.push(targetDeviceId);
  }
  query += ' ORDER BY device_id, metric';
  const rows = db.prepare(query).all(...params);

  const devicesMap = {};
  for (const row of rows) {
    if (!devicesMap[row.device_id]) {
      devicesMap[row.device_id] = {
        deviceId: row.device_id,
        status: 'unknown',
        lastSeen: row.updated_at,
        metrics: {}
      };
    }
    const dev = devicesMap[row.device_id];
    if (row.updated_at > dev.lastSeen) {
      dev.lastSeen = row.updated_at;
    }
    if (row.metric.toLowerCase() === 'status') {
      dev.status = row.value;
    } else {
      dev.metrics[row.metric] = {
        value: isNaN(Number(row.value)) ? row.value : Number(row.value),
        unit: row.unit,
        updatedAt: row.updated_at
      };
    }
  }

  // Cross-check with registered MQTT devices & online statuses
  const statuses = readMqttDeviceStatuses();
  for (const st of statuses) {
    if (devicesMap[st.username]) {
      devicesMap[st.username].status = st.connected ? 'online' : (devicesMap[st.username].status || 'offline');
      if (st.connectedAt && (!devicesMap[st.username].lastSeen || st.connectedAt > devicesMap[st.username].lastSeen)) {
        devicesMap[st.username].lastSeen = st.connectedAt;
      }
    } else if (!targetDeviceId) {
      devicesMap[st.username] = {
        deviceId: st.username,
        status: st.connected ? 'online' : 'offline',
        lastSeen: st.connectedAt || st.createdAt,
        metrics: {}
      };
    }
  }

  let resultList = Object.values(devicesMap);

  // Filter by user permissions
  const explicitDevicePerms = (user && Array.isArray(user.permissions))
    ? user.permissions.filter(p => typeof p === 'string' && p.startsWith('device:'))
    : [];

  const isSuperAdmin = Boolean(user && (
    user.role === 'admin' ||
    (Array.isArray(user.permissions) && (user.permissions.includes('view:admin') || user.permissions.includes('access:editor')))
  ));

  // If user has explicitly assigned device permissions (even if admin), strictly respect them!
  if (explicitDevicePerms.length > 0) {
    const allowedDeviceIds = new Set(explicitDevicePerms.map(p => p.slice(7)));
    resultList = resultList.filter(dev => allowedDeviceIds.has(dev.deviceId));
  } else if (!isSuperAdmin) {
    // Non-admin without any explicit device permissions gets no devices
    resultList = [];
  }

  if (targetDeviceId) {
    const single = devicesMap[targetDeviceId] || null;
    if (!single) return null;
    if (explicitDevicePerms.length > 0) {
      const allowedDeviceIds = new Set(explicitDevicePerms.map(p => p.slice(7)));
      if (!allowedDeviceIds.has(targetDeviceId)) return null;
    } else if (!isSuperAdmin) {
      return null;
    }
    return single;
  }

  return resultList;
}

function backfillSensorTelemetryFromLogs() {
  try {
    const logs = db.prepare(`
      SELECT topic, payload, ts FROM mqtt_event_logs
      WHERE topic LIKE 'Metrics/%'
      ORDER BY id ASC
    `).all();
    for (const log of logs) {
      handleSensorTelemetry(log.topic, log.payload, log.ts);
    }
    if (logs.length > 0) {
      console.log(`[TELEMETRY] Backfilled telemetry from ${logs.length} previous logs.`);
    }
  } catch (err) {
    console.warn('[TELEMETRY] Backfill notice:', err.message);
  }
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
  const payloadStr = packet.payload ? packet.payload.toString() : '';
  if (client) {
    pushMqttEvent({
      type: 'publish',
      clientId: client.id || 'unknown',
      username: client.username || null,
      topic: packet.topic,
      payload: clipPayload(payloadStr)
    });
    console.log(`[MQTT] ${packet.topic}: ${payloadStr}`);
  }
  handleSensorTelemetry(packet.topic, payloadStr);
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
const sessionSecret = process.env.SESSION_SECRET || 'dev-change-me-session-secret';
const nodeRedCredentialSecret = process.env.NODERED_CREDENTIAL_SECRET || 'dev-change-me-nodered-credential-secret';

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
  const { username, password, email } = req.body;
  if (!username || !password)
    return res.json({ error: 'All fields are required' });
  if (password.length < 6)
    return res.json({ error: 'Password must be at least 6 characters' });

  if (getUser(username))
    return res.json({ error: 'User already exists' });

  const cleanEmail = (email && typeof email === 'string' && email.includes('@')) ? email.trim().toLowerCase() : null;
  if (cleanEmail && getUserByEmail(cleanEmail)) {
    return res.json({ error: 'Email is already linked to another user' });
  }

  const hash = await bcrypt.hash(password, 10);
  db.prepare(`
    INSERT INTO users (username, email, password_hash, permissions, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(username, cleanEmail, hash, JSON.stringify(ROLE_PERMISSIONS.user), new Date().toISOString());

  req.session.user = { username };
  res.json({ success: true, redirectTo: '/dashboard' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.json({ error: 'All fields are required' });

  const user = getUserWithPassword(username);
  if (!user)
    return res.json({ error: 'Invalid username or password' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid)
    return res.json({ error: 'Invalid username or password' });

  const profile = userFromRow(user);
  req.session.user = { username };
  res.json({ success: true, role: profile.role, permissions: profile.permissions, redirectTo: getLandingPathForUser(profile) });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/dashboard'));
});

// ── Session info endpoint (used by dashboard) ──────────────────────────────────
app.get('/api/me', (req, res) => {
  const user = getAuthUser(req);
  if (user) {
    const allNavPages = getAllNavPages();
    const userNavPages = allNavPages.filter(p => user.permissions.includes(p.permission_key));
    return res.json({
      ...user,
      navPages: userNavPages,
      allNavPages: user.permissions.includes('view:admin') ? allNavPages : undefined
    });
  }
  res.status(401).json({ error: 'not authenticated' });
});

// Update own email
app.patch('/api/me/email', (req, res) => {
  let currentUsername = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const u = authenticateUserFromToken(authHeader.slice(7).trim());
    if (u) currentUsername = u.username;
  } else if (req.session && req.session.user) {
    currentUsername = req.session.user.username;
  }

  if (!currentUsername) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const email = (req.body.email || '').trim().toLowerCase();
  if (email && (!email.includes('@') || email.length > 255)) {
    return res.status(400).json({ error: 'Valid email address required' });
  }

  if (email) {
    const existing = getUserByEmail(email);
    if (existing && existing.username !== currentUsername) {
      return res.status(400).json({ error: 'Email already linked to another account' });
    }
  }

  db.prepare('UPDATE users SET email = ? WHERE username = ?').run(email || null, currentUsername);
  res.json({ success: true, username: currentUsername, email: email || null });
});

// ── Permissions Catalog API (Categorized RBAC for Admin Matrix) ──────────────
app.get('/api/permissions/catalog', (req, res) => {
  const navPages = getAllNavPages();
  const devices = db.prepare('SELECT username, created_at, owner_email FROM mqtt_devices ORDER BY username').all();
  let telemetryDevs = [];
  try {
    telemetryDevs = db.prepare('SELECT DISTINCT device_id FROM sensor_telemetry').all();
  } catch (e) {}

  const knownDevices = new Set(devices.map(d => d.username));
  for (const t of telemetryDevs) {
    if (!knownDevices.has(t.device_id)) {
      devices.push({ username: t.device_id, created_at: null, owner_email: null });
      knownDevices.add(t.device_id);
    }
  }

  const systemPages = [
    { key: 'view:dashboard', label: 'Dashboard', desc: 'Основний SCADA-дашборд' },
    { key: 'view:nodes_ui', label: 'Node-RED UI', desc: 'SCADA панель керування' },
    { key: 'view:mqtt_logs', label: 'MQTT Logs', desc: 'Журнал подій брокера' },
    { key: 'view:admin', label: 'Users & Access', desc: 'Матриця прав користувачів' },
    { key: 'access:editor', label: 'Node-RED Editor', desc: 'Редактор логіки flows' }
  ];

  const rolePerms = [
    { key: 'grant:permissions', label: 'Grant Permissions', desc: 'Зміна прав доступу' },
    { key: 'manage:users', label: 'Manage Users', desc: 'Видалення акаунтів' },
    { key: 'manage:devices', label: 'Manage Devices', desc: 'Керування пристроями та ключами' },
    { key: 'manage:navigation', label: 'Manage Navigation', desc: 'Створення та налаштування кастомної навігації' }
  ];

  const catalog = {
    systemPages,
    roles: rolePerms,
    system: [...systemPages, ...rolePerms],
    navPages: navPages.map(p => ({
      key: p.permission_key,
      title: p.title,
      path: p.path
    })),
    devices: devices.map(d => ({
      key: `device:${d.username}`,
      deviceId: d.username,
      label: d.username === 's3_sensor_01' ? 'ESP32-S3 (AHT20/BMP280)' : d.username,
      ownerEmail: d.owner_email || null
    }))
  };

  res.json(catalog);
});

// ── Sensors / Telemetry API (Mobile App & SCADA) ──────────────────────────────
app.post('/api/auth/mobile-token', (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  if (!email || !email.includes('@')) {
    return res.status(400).json({ success: false, error: 'Valid email is required' });
  }
  const user = getUserByEmail(email);
  if (!user) {
    return res.status(403).json({ success: false, error: 'User with this email is not registered' });
  }
  try {
    const nowSec = Math.floor(Date.now() / 1000);
    const token = signJwtToken({
      sub: user.username,
      username: user.username,
      name: name || user.username,
      email: user.email,
      role: user.role,
      iat: nowSec,
      exp: nowSec + 7 * 24 * 60 * 60
    });
    res.json({
      success: true,
      token,
      user: {
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    console.error('[AUTH] Failed to sign mobile token:', err.message);
    res.status(500).json({ success: false, error: 'Server JWT configuration error' });
  }
});

app.get('/api/sensors', (req, res) => {
  const user = getAuthUser(req);
  if (!user) {
    const rawAuth = req.headers.authorization || req.headers.Authorization || '(none)';
    const headerKeys = Object.keys(req.headers || {}).join(', ');
    console.warn(`[AUTH] /api/sensors: 401 Unauthorized. rawAuth = [${rawAuth}], headersReceived = [${headerKeys}]`);
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  res.json({
    success: true,
    devices: getSensorTelemetry(null, user)
  });
});

app.get('/api/sensors/:deviceId', (req, res) => {
  const user = getAuthUser(req);
  if (!user) {
    console.warn(`[AUTH] /api/sensors/${req.params.deviceId}: 401 Unauthorized`);
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  const dev = getSensorTelemetry(req.params.deviceId, user);
  if (!dev) {
    return res.status(404).json({ success: false, error: 'Device not found or access denied' });
  }
  res.json({
    success: true,
    device: dev
  });
});

app.post('/api/sensors/:deviceId/refresh', (req, res) => {
  const user = getAuthUser(req);
  if (!user) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  const deviceId = req.params.deviceId;
  const explicitDevicePerms = Array.isArray(user.permissions)
    ? user.permissions.filter(p => typeof p === 'string' && p.startsWith('device:'))
    : [];
  const isSuperAdmin = Boolean(
    user.role === 'admin' ||
    (Array.isArray(user.permissions) && (user.permissions.includes('view:admin') || user.permissions.includes('access:editor')))
  );

  if (explicitDevicePerms.length > 0) {
    if (!user.permissions.includes(`device:${deviceId}`)) {
      return res.status(403).json({ success: false, error: 'Access denied to this device' });
    }
  } else if (!isSuperAdmin) {
    return res.status(403).json({ success: false, error: 'Access denied to this device' });
  }

  requestSensorRefresh(deviceId, () => {
    setTimeout(() => {
      const dev = getSensorTelemetry(deviceId, user);
      res.json({
        success: true,
        message: `Telemetry refresh requested for ${deviceId}`,
        device: dev || { deviceId, status: 'unknown', metrics: {} }
      });
    }, 600);
  });
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
    return res.status(400).json({ error: 'Specify a valid MQTT topic without wildcard characters' });
  }
  if (Buffer.byteLength(payload, 'utf8') > 1024 * 1024) {
    return res.status(400).json({ error: 'Payload must not exceed 1 MiB' });
  }

  const clientId = `dashboard:${req.currentUser.username}`;
  const packet = { topic, payload: Buffer.from(payload, 'utf8'), qos: 0, retain: false };
  try {
    aedes.publish(packet, (error) => {
      if (error) return res.status(502).json({ error: 'Failed to publish MQTT message' });
      pushMqttEvent({ type: 'publish', clientId, topic, payload: clipPayload(payload) });
      res.json({ success: true, topic, payload });
    });
  } catch (error) {
    console.error('[MQTT] dashboard publish failed:', error);
    res.status(502).json({ error: 'Failed to publish MQTT message' });
  }
});

// ── Permission middleware ──────────────────────────────────────────────────────
function requirePermission(permission) {
  return (req, res, next) => {
    const user = getAuthUser(req);
    if (user && user.permissions && user.permissions.includes(permission)) {
      req.currentUser = user;
      return next();
    }
    res.status(403).json({ error: 'Access denied' });
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
    return res.status(403).json({ error: 'Access denied' });
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
  const list = db.prepare('SELECT username, email, permissions, created_at FROM users ORDER BY username').all()
    .map(userFromRow);
  res.json(list);
});

app.patch('/api/users/:username/email', requirePermission('grant:permissions'), (req, res) => {
  const { username } = req.params;
  const user = getUser(username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const email = (req.body.email || '').trim().toLowerCase();
  if (email && (!email.includes('@') || email.length > 255)) {
    return res.status(400).json({ error: 'Valid email address required' });
  }

  if (email) {
    const existing = getUserByEmail(email);
    if (existing && existing.username !== username) {
      return res.status(400).json({ error: 'Email already linked to another account' });
    }
  }

  db.prepare('UPDATE users SET email = ? WHERE username = ?').run(email || null, username);
  res.json({ success: true, username, email: email || null });
});

app.patch('/api/users/:username/permissions', requirePermission('grant:permissions'), (req, res) => {
  const { username } = req.params;
  const permissions = Array.isArray(req.body.permissions) ? [...new Set(req.body.permissions)] : null;
  const validPermissions = getAllValidPermissions();
  if (!permissions || permissions.some(permission => !validPermissions.includes(permission))) {
    return res.status(400).json({ error: 'Invalid permissions' });
  }
  const user = getUser(username);
  if (!user)
    return res.status(404).json({ error: 'User not found' });
  if (username === req.session.user.username && !permissions.includes('grant:permissions')) {
    return res.status(400).json({ error: 'Cannot revoke own administrative permissions' });
  }
  db.prepare('UPDATE users SET permissions = ? WHERE username = ?').run(JSON.stringify(permissions), username);
  res.json({ success: true });
});

// ── Navigation Pages API ───────────────────────────────────────────────────────
app.get('/api/nav-pages', (req, res) => {
  const user = req.session.user && getUser(req.session.user.username);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  const pages = getAllNavPages();
  if (user.permissions.includes('view:admin') || user.permissions.includes('grant:permissions') || user.permissions.includes('manage:navigation')) {
    return res.json(pages);
  }
  res.json(pages.filter(p => user.permissions.includes(p.permission_key)));
});

app.post('/api/nav-pages', requirePermission('manage:navigation'), (req, res) => {
  const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
  let pagePath = typeof req.body.path === 'string' ? req.body.path.trim() : '';
  if (!title || title.length > 64) {
    return res.status(400).json({ error: 'Page title is required (up to 64 characters)' });
  }
  if (!pagePath || pagePath.length > 255) {
    return res.status(400).json({ error: 'Valid page path or URL is required' });
  }
  if (!pagePath.startsWith('/') && !pagePath.startsWith('http://') && !pagePath.startsWith('https://')) {
    pagePath = '/' + pagePath;
  }

  const existing = db.prepare('SELECT id FROM nav_pages WHERE path = ?').get(pagePath);
  if (existing) {
    return res.status(409).json({ error: 'A navigation page with this path already exists' });
  }

  const createdBy = (req.currentUser && req.currentUser.username) || (req.session && req.session.user && req.session.user.username) || 'admin';
  const tempKey = 'view:page_' + Date.now();
  const insertResult = db.prepare(`
    INSERT INTO nav_pages (title, path, permission_key, created_by, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(title, pagePath, tempKey, createdBy, new Date().toISOString());

  const pageId = insertResult.lastInsertRowid;
  const permissionKey = `view:page_${pageId}`;
  db.prepare('UPDATE nav_pages SET permission_key = ? WHERE id = ?').run(permissionKey, pageId);

  // Automatically grant permission to users with manage:navigation, grant:permissions or view:admin
  const usersWithGrant = db.prepare('SELECT username, permissions FROM users').all();
  usersWithGrant.forEach(u => {
    const perms = parsePermissions(u.permissions);
    if (perms.includes('manage:navigation') || perms.includes('grant:permissions') || perms.includes('view:admin') || u.username === createdBy) {
      if (!perms.includes(permissionKey)) {
        perms.push(permissionKey);
        db.prepare('UPDATE users SET permissions = ? WHERE username = ?').run(JSON.stringify(perms), u.username);
      }
    }
  });

  const createdPage = db.prepare('SELECT id, title, path, permission_key, created_by AS createdBy, created_at AS createdAt FROM nav_pages WHERE id = ?').get(pageId);
  res.status(201).json(createdPage);
});

app.delete('/api/nav-pages/:id', requirePermission('manage:navigation'), (req, res) => {
  const pageId = Number(req.params.id);
  const page = db.prepare('SELECT id, permission_key FROM nav_pages WHERE id = ?').get(pageId);
  if (!page) {
    return res.status(404).json({ error: 'Page not found' });
  }

  db.prepare('DELETE FROM nav_pages WHERE id = ?').run(pageId);

  const allUsers = db.prepare('SELECT username, permissions FROM users').all();
  allUsers.forEach(u => {
    const perms = parsePermissions(u.permissions);
    if (perms.includes(page.permission_key)) {
      const filtered = perms.filter(p => p !== page.permission_key);
      db.prepare('UPDATE users SET permissions = ? WHERE username = ?').run(JSON.stringify(filtered), u.username);
    }
  });

  res.json({ success: true });
});

app.patch('/api/users/:username/role', requirePermission('grant:permissions'), (req, res) => {
  const role = req.body.role;
  if (!Object.prototype.hasOwnProperty.call(ROLE_PERMISSIONS, role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  const user = getUser(req.params.username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (req.params.username === req.session.user.username && role !== 'admin') {
    return res.status(400).json({ error: 'Cannot revoke own administrative permissions' });
  }
  db.prepare('UPDATE users SET permissions = ? WHERE username = ?')
    .run(JSON.stringify(permissionsForLegacyRole(role)), req.params.username);
  res.json({ success: true });
});

app.delete('/api/users/:username', requirePermission('manage:users'), (req, res) => {
  const { username } = req.params;
  if (username === req.session.user.username)
    return res.status(400).json({ error: 'Cannot delete your own account' });
  if (!getUser(username))
    return res.status(404).json({ error: 'User not found' });
  db.prepare('DELETE FROM users WHERE username = ?').run(username);
  res.json({ success: true });
});

app.post('/api/mqtt/devices', requirePermission('manage:devices'), (req, res) => {
  const { username } = req.body;
  if (!username || !/^[A-Za-z0-9._-]{3,64}$/.test(username)) {
    return res.status(400).json({ error: 'Device username must be 3–64 allowed characters' });
  }
  if (db.prepare('SELECT 1 FROM mqtt_devices WHERE username = ?').get(username)) {
    return res.status(409).json({ error: 'MQTT device already exists' });
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
  if (!device) return res.status(404).json({ error: 'Device not found' });
  res.json({ username: req.params.username, password: decryptDevicePassword(device.password_encrypted) });
});

app.delete('/api/mqtt/devices/:username', requirePermission('manage:devices'), (req, res) => {
  const result = db.prepare('DELETE FROM mqtt_devices WHERE username = ?').run(req.params.username);
  if (!result.changes) return res.status(404).json({ error: 'Device not found' });
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
    return res.status(403).json({ error: 'Access denied' });
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
backfillSensorTelemetryFromLogs();

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
