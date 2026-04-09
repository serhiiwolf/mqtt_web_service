# MQTT Web Service

Веб-сервіс з MQTT broker, Node-RED та рольовим доступом до веб-інтерфейсів.

## Що є в проєкті

- Публічна сторінка сервісу на `/dashboard`
- Node-RED dashboard для ролі `viewer` на `/nodes/ui`
- Node-RED editor на `/editor` тільки для `admin`
- Адмін-панель на `/admin` тільки для `admin`
- MQTT broker всередині застосунку:
  - TCP: `mqtt://localhost:1883`
  - WebSocket: `ws://localhost:3000/mqtt`

## Ролі

- `user` - бачить тільки публічну сторінку сервісу
- `viewer` - бачить тільки Node-RED dashboards
- `admin` - має доступ до всього

## Як це працює

- Незалоговані користувачі потрапляють на публічну сторінку `/dashboard`
- Звичайний користувач після входу теж залишається лише на `/dashboard`
- Роль `viewer` після входу переходить на `/nodes/ui`
- Роль `admin` після входу переходить на `/editor`
- Прямий доступ до HTML-файлів з `public/` закритий, доступ йде тільки через маршрути сервера

## Структура

- `server.js` - сервер, авторизація, ролі, MQTT, Node-RED
- `users.json` - сховище користувачів
- `public/dashboard.html` - публічна сторінка сервісу
- `public/login.html` - сторінка входу
- `public/register.html` - сторінка реєстрації
- `public/admin.html` - адмін-панель
- `public/editor-nav.js` - додаткова навігація в Node-RED editor
- `apache.conf` - приклад reverse proxy конфігурації Apache
- `cloudflared.yml` - приклад конфігу Cloudflare Tunnel
- `mqtttest.service` - приклад systemd unit

## Локальний запуск

1. Встановити залежності:

```bash
npm install
```

2. Запустити застосунок:

```bash
npm start
```

3. Відкрити у браузері:

- `http://localhost:3000/dashboard`
- `http://localhost:3000/login`
- `http://localhost:3000/register`
- `http://localhost:3000/admin`
- `http://localhost:3000/editor`
- `http://localhost:3000/nodes/ui`

## Маршрути

### Публічні

- `GET /` - редірект на `/dashboard` або landing за роллю
- `GET /dashboard` - публічна сторінка сервісу
- `GET /login`
- `GET /register`

### Авторизовані

- `GET /nodes/ui` - Node-RED dashboards для ролі `viewer` та `admin`
- `GET /admin` - тільки `admin`
- `GET /editor` - тільки `admin`

### API

- `POST /api/register` - створює користувача з роллю `user`
- `POST /api/login`
- `POST /logout`
- `GET /api/me`
- `GET /api/mqtt/logs` - тільки `admin`
- `GET /api/users` - тільки `admin`
- `PATCH /api/users/:username/role` - тільки `admin`
- `DELETE /api/users/:username` - тільки `admin`

## Node-RED

Налаштування в `server.js`:

- `httpAdminRoot: /editor`
- `httpNodeRoot: /nodes`
- `ui.path: ui`
- dashboard доступний як `/nodes/ui`

## Безпека

- `SESSION_SECRET` і `NODERED_CREDENTIAL_SECRET` треба задати через environment variables
- У production не використовувати fallback-значення з коду
- HTTP доступ до `public/*.html` напряму закритий, використовуються тільки route handlers

## Перевірка

1. Відкрити `/dashboard` без входу
2. Залогінитися як `user` і переконатися, що доступний тільки `/dashboard`
3. Залогінитися як `viewer` і перевірити доступ до `/nodes/ui`
4. Залогінитися як `admin` і перевірити `/admin` та `/editor`
