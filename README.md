# MQTT Web Service

Веб-сервіс для керування MQTT, Node-RED, користувачами та пристроями в одному
SCADA/IIoT control plane. Сервер працює на Node.js 22.5+ і використовує
вбудований `node:sqlite`.

## Можливості

- SCADA dashboard `/dashboard` з broker/runtime метриками, live topics,
  подіями та статусом кожного зареєстрованого MQTT-пристрою.
- Quick Publisher на dashboard: публікація topic/payload через авторизований API.
- MQTT broker:
  - TCP `mqtt://localhost:1883`;
  - WebSocket `ws://localhost:3000/mqtt`;
  - username/password authentication для пристроїв.
- Журнал connect, disconnect, publish, subscribe та unsubscribe у SQLite.
  Зберігаються події за останні 3 дні.
- Сторінка `/admin/mqtt-logs` з пошуком, фільтрами, метриками та автооновленням.
- Керування MQTT-пристроями на `/admin/mqtt-devices`: створення, видалення,
  перегляд і повторне приховування паролів, online/offline статуси на dashboard.
- Керування користувачами та granular permissions на `/admin`.
- Node-RED dashboard `/nodes/ui` та Node-RED editor `/editor`.
- Спільна SCADA-навігація на веб-сторінках і в Node-RED editor.

## Доступ і permissions

Доступ визначається безпосередньо набором permissions, які адміністратор
вмикає або вимикає для кожного користувача в permission matrix на `/admin`.
Доступні права:

- `view:dashboard` — основний dashboard і Quick Publisher;
- `view:nodes_ui` — Node-RED dashboard;
- `view:admin` — Users & Access;
- `view:mqtt_logs` — MQTT Logs;
- `manage:users` — видалення користувачів;
- `grant:permissions` — зміна permissions;
- `manage:devices` — MQTT Devices і credentials;
- `access:editor` — Node-RED editor.

Новий користувач отримує тільки `view:dashboard`. API та захищені сторінки
перевіряють сесію і permissions server-side. Старий endpoint призначення
`role` збережений лише для сумісності з попередніми даними; актуальний UI
працює виключно через granular permissions.

## Запуск

Потрібен Node.js 22.5+ (Node.js 22 LTS рекомендовано).

```bash
copy .env.example .env
# встановіть у .env унікальні SESSION_SECRET,
# NODERED_CREDENTIAL_SECRET, 32-byte MQTT_ENCRYPTION_KEY та JWT_SECRET
npm install
npm start
```

Для першого адміністратора:

```bash
npm run create-admin -- <username> <password>
```

Адреси після запуску:

- `http://localhost:3000/dashboard`
- `http://localhost:3000/login`
- `http://localhost:3000/register`
- `http://localhost:3000/admin`
- `http://localhost:3000/admin/mqtt-logs`
- `http://localhost:3000/admin/mqtt-devices`
- `http://localhost:3000/nodes/ui`
- `http://localhost:3000/editor`

## API

### Сесія

- `POST /api/register`
- `POST /api/login`
- `POST /logout`
- `GET /api/me`

### MQTT

- `GET /api/mqtt/logs` — події за останні 3 дні (`view:mqtt_logs`);
- `POST /api/mqtt/publish` — Quick Publisher (`view:dashboard`);
- `GET /api/mqtt/devices/status` — online/offline статуси (`view:dashboard`);
- `GET /api/mqtt/devices` — список пристроїв (`manage:devices`);
- `POST /api/mqtt/devices` — створення credentials;
- `GET /api/mqtt/devices/:username/password` — отримання пароля за permission;
- `DELETE /api/mqtt/devices/:username` — видалення пристрою.

### Користувачі

- `GET /api/users`;
- `PATCH /api/users/:username/permissions`;
- `DELETE /api/users/:username`.

Усі перелічені API, крім login/register/me, вимагають відповідного permission.

## Node-RED та деплой

Конфігурація в `server.js`: `httpAdminRoot=/editor`, `httpNodeRoot=/nodes`,
dashboard path `/nodes/ui`. Основний flow зберігається у
`.node-red/flows.json`. `flows_cred.json` навмисно не додається до Git, бо
містить credentials; його треба створити або налаштувати локально на сервері.

Для reverse proxy/deployment є приклади:

- `apache.conf` — Apache з HTTP та WebSocket proxy;
- `cloudflared.yml` — Cloudflare Tunnel;
- `mqtttest.service` — systemd unit.

## Зберігання і безпека

- користувачі, MQTT devices і MQTT event logs зберігаються в
  `mqtt-web-service.db`;
- passwords пристроїв шифруються AES-256-GCM;
- секрети з `.env`, database, Node-RED credentials, TLS keys і runtime backup
  файли не повинні потрапляти до Git;
- прямий доступ до `public/*.html` закритий, сторінки віддаються через route
  handlers;
- у production обов'язково задайте всі чотири secret variables (включно з JWT_SECRET) і використовуйте
  HTTPS/reverse proxy.

## Структура

- `server.js` — Express, SQLite, auth, MQTT broker, WebSocket і Node-RED;
- `public/` — dashboard, auth, admin, MQTT logs/devices та UI theme;
- `.node-red/flows.json` — версійований Node-RED flow;
- `scripts/create-admin.js` — створення адміністратора;
- `.env.example` — шаблон змінних середовища.
