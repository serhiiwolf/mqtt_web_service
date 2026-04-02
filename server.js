const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
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

// ── MQTT Broker ────────────────────────────────────────────────────────────────
const aedes = Aedes();
const mqttEventLog = [];
const MQTT_EVENT_LOG_LIMIT = 50;

function pushMqttEvent(event) {
  mqttEventLog.push({
    ts: new Date().toISOString(),
    ...event
  });
  while (mqttEventLog.length > MQTT_EVENT_LOG_LIMIT) mqttEventLog.shift();
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
const wssServer = new ws.Server({ server, path: '/mqtt' });
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
  pushMqttEvent({ type: 'connect', clientId: client.id || 'unknown' });
  console.log(`[MQTT] client connected: ${client.id}`);
});
aedes.on('clientDisconnect', (client) => {
  pushMqttEvent({ type: 'disconnect', clientId: client.id || 'unknown' });
  console.log(`[MQTT] client disconnected: ${client.id}`);
});
aedes.on('publish', (packet, client) => {
  if (client) {
    pushMqttEvent({
      type: 'publish',
      clientId: client.id || 'unknown',
      topic: packet.topic,
      payload: clipPayload(packet.payload && packet.payload.toString())
    });
    console.log(`[MQTT] ${packet.topic}: ${packet.payload.toString()}`);
  }
});

// ── Session & body parsing ─────────────────────────────────────────────────────
// NODE_ENV=production встановлюється в systemd service на сервері.
// Це вмикає secure cookie — обов'язково при роботі через Cloudflare HTTPS.
const isProd = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET || 'dev-change-me-session-secret';
const nodeRedCredentialSecret = process.env.NODERED_CREDENTIAL_SECRET || 'dev-change-me-nodered-credential-secret';

if (isProd && (!process.env.SESSION_SECRET || !process.env.NODERED_CREDENTIAL_SECRET)) {
  console.warn('[SECURITY] SESSION_SECRET and NODERED_CREDENTIAL_SECRET must be set in production.');
}

app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    secure: isProd,   // true за Cloudflare (HTTPS); false при локальній розробці
    sameSite: 'lax'
  }
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Users store (JSON file) ────────────────────────────────────────────────────
const USERS_FILE = path.join(__dirname, 'users.json');

function getLandingPathForRole(role) {
  return role === 'admin' ? '/editor' : '/dashboard';
}

function getUsers() {
  if (!fs.existsSync(USERS_FILE)) return {};
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// ── Auth routes ────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.redirect(getLandingPathForRole(req.session.user.role));
});

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect(getLandingPathForRole(req.session.user.role));
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect(getLandingPathForRole(req.session.user.role));
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/mqtt-dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'mqtt-dashboard.html'));
});

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.json({ error: 'Заповніть всі поля' });
  if (password.length < 6)
    return res.json({ error: 'Пароль — мінімум 6 символів' });

  const users = getUsers();
  if (users[username])
    return res.json({ error: 'Користувач із таким іменем вже існує' });

  const hash = await bcrypt.hash(password, 10);
  users[username] = { password: hash, role: 'user', createdAt: new Date().toISOString() };
  saveUsers(users);

  req.session.user = { username, role: 'user' };
  res.json({ success: true, redirectTo: '/dashboard' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.json({ error: 'Заповніть всі поля' });

  const users = getUsers();
  if (!users[username])
    return res.json({ error: 'Невірний логін або пароль' });

  const valid = await bcrypt.compare(password, users[username].password);
  if (!valid)
    return res.json({ error: 'Невірний логін або пароль' });

  const role = users[username].role;
  req.session.user = { username, role };
  res.json({ success: true, role, redirectTo: getLandingPathForRole(role) });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ── Session info endpoint (used by dashboard) ──────────────────────────────────
app.get('/api/me', (req, res) => {
  if (req.session.user) return res.json(req.session.user);
  res.status(401).json({ error: 'not authenticated' });
});

app.get('/api/mqtt/logs', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: 'not authenticated' });
  }
  res.json({ items: mqttEventLog.slice(-MQTT_EVENT_LOG_LIMIT).reverse() });
});

// ── Admin middleware ──────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === 'admin') return next();
  res.status(403).json({ error: 'Доступ заборонено' });
}

function requireAdminPage(req, res, next) {
  if (!req.session || !req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.redirect('/dashboard');
  next();
}

// ── Admin API ──────────────────────────────────────────────────────────────────
app.get('/admin', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/api/users', requireAdmin, (req, res) => {
  const users = getUsers();
  const list = Object.entries(users).map(([username, data]) => ({
    username,
    role: data.role,
    createdAt: data.createdAt
  }));
  res.json(list);
});

app.patch('/api/users/:username/role', requireAdmin, (req, res) => {
  const { username } = req.params;
  const { role } = req.body;
  if (!['admin', 'user'].includes(role))
    return res.status(400).json({ error: 'Невалідна роль' });
  const users = getUsers();
  if (!users[username])
    return res.status(404).json({ error: 'Користувача не знайдено' });
  // Prevent the last admin from losing admin rights
  if (role === 'user' && users[username].role === 'admin') {
    const adminCount = Object.values(users).filter(u => u.role === 'admin').length;
    if (adminCount <= 1)
      return res.status(400).json({ error: 'Неможливо прибрати права останнього адміна' });
  }
  users[username].role = role;
  saveUsers(users);
  res.json({ success: true });
});

app.delete('/api/users/:username', requireAdmin, (req, res) => {
  const { username } = req.params;
  if (username === req.session.user.username)
    return res.status(400).json({ error: 'Не можна видалити себе' });
  const users = getUsers();
  if (!users[username])
    return res.status(404).json({ error: 'Користувача не знайдено' });
  delete users[username];
  saveUsers(users);
  res.json({ success: true });
});
// ── Node-RED auth middleware ───────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
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
  if (!req.session || !req.session.user) {
    const isAjax =
      req.xhr ||
      (req.headers.accept && req.headers.accept.includes('application/json')) ||
      req.path.startsWith('/comms') ||
      req.path.startsWith('/auth') ||
      req.path.match(/\.(js|css|png|ico|json|map)$/);
    if (isAjax) return res.status(401).json({ error: 'Unauthorized' });
    return res.redirect('/login');
  }

  if (req.session.user.role === 'admin') return next();

  if (req.xhr || (req.headers.accept && req.headers.accept.includes('application/json'))) {
    return res.status(403).json({ error: 'Доступ заборонено' });
  }
  return res.redirect('/dashboard');
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
app.use(settings.httpNodeRoot, requireAdmin, RED.httpNode);

// ── Start ──────────────────────────────────────────────────────────────────────
server.listen(3000, '127.0.0.1', () => {
  console.log('');
  console.log('  App:          http://localhost:3000');
  console.log('  Node-RED:     http://localhost:3000/editor');
  console.log('  MQTT:         mqtt://localhost:1883');
  console.log('  MQTT (WS):    ws://localhost:3000/mqtt');
  console.log('');
});

RED.start();
