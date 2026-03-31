# MQTT Web Service (Node-RED + MQTT + Role-based Web UI)

Веб-сервіс для роботи з MQTT, вбудованим брокером та Node-RED редактором з авторизацією і ролями користувачів.

## Що вміє проєкт

- Реєстрація та вхід користувачів
- Сесійна авторизація (cookie-based)
- Ролі: user та admin
- MQTT брокер всередині застосунку (Aedes):
  - TCP: mqtt://localhost:1883
  - WebSocket: ws://localhost:3000/mqtt
- MQTT Dashboard у браузері:
  - publish/subscribe
  - live лог повідомлень
  - quick publish кнопки
- Node-RED редактор на /editor (доступ лише для admin)
- Адмін-панель на /admin:
  - перегляд користувачів
  - зміна ролі
  - видалення користувачів

## Технології

- Node.js
- Express
- express-session
- bcryptjs
- Node-RED
- Aedes (MQTT broker)
- ws + websocket-stream
- Прості HTML/CSS/JS сторінки у public

## Структура проєкту

- server.js — головний сервер, auth, ролі, API, MQTT, Node-RED
- users.json — сховище користувачів
- public/login.html — сторінка входу
- public/register.html — сторінка реєстрації
- public/dashboard.html — MQTT dashboard
- public/admin.html — адмін-панель
- public/editor-nav.js — додаткова навігація всередині Node-RED
- apache.conf — приклад reverse proxy конфігурації Apache
- cloudflared.yml — приклад конфігу Cloudflare Tunnel
- mqtttest.service — приклад systemd unit

## Архітектура

```text
Browser (HTTPS)
  -> Cloudflare Edge
    -> cloudflared tunnel
      -> Apache (:80)
        -> Node.js app (:3000)
          ->
             - Web UI (/login, /register, /dashboard, /admin)
             - Node-RED (/editor, /nodes)
             - MQTT WS (/mqtt)
             - MQTT TCP broker (:1883)
```

## Вимоги

- Node.js 18+
- npm

## Змінні оточення

Створіть файл `.env` на базі `.env.example`:

```bash
copy .env.example .env
```

Обов'язково задайте:

- SESSION_SECRET
- NODERED_CREDENTIAL_SECRET

У production не використовуйте fallback-значення з коду.

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

- App: http://localhost:3000
- Login: http://localhost:3000/login
- Register: http://localhost:3000/register
- Dashboard: http://localhost:3000/dashboard
- Admin: http://localhost:3000/admin
- Node-RED Editor: http://localhost:3000/editor
- MQTT TCP: mqtt://localhost:1883
- MQTT WS: ws://localhost:3000/mqtt

## Ролі та доступ

### user

- Доступ: /dashboard
- Немає доступу: /admin, /editor

### admin

- Доступ: /dashboard, /admin, /editor
- Може:
  - міняти ролі користувачів
  - видаляти користувачів

## Маршрути та API

### Сторінки

- GET / — редірект на /login або landing за роллю
- GET /login
- GET /register
- GET /dashboard — тільки для авторизованих
- GET /admin — тільки для admin
- GET /editor — Node-RED editor, тільки для admin

### Auth API

- POST /api/register
  - body: { username, password }
  - створює користувача з роллю user
- POST /api/login
  - body: { username, password }
- POST /logout

### Session API

- GET /api/me
  - повертає поточного користувача або 401

### Admin API (тільки admin)

- GET /api/users
- PATCH /api/users/:username/role
  - body: { role: "admin" | "user" }
- DELETE /api/users/:username

## Зберігання користувачів

Користувачі зберігаються у файлі users.json у форматі:

```json
{
  "username": {
    "password": "bcrypt-hash",
    "role": "user|admin",
    "createdAt": "ISO-date"
  }
}
```

Важливо:

- Реєстрація створює лише роль user
- Останнього admin не можна понизити до user
- Адмін не може видалити сам себе

## MQTT Dashboard

Dashboard на /dashboard дозволяє:

- Публікувати повідомлення у topic
- Підписуватись на topic або wildcard (наприклад test/# або #)
- Дивитись live-лог вхідних повідомлень
- Автоматично перепідключатися до MQTT по WS

## Node-RED інтеграція

Налаштування у server.js:

- httpAdminRoot: /editor
- httpNodeRoot: /nodes
- userDir: .node-red
- flowFile: flows.json
- editorTheme scripts: public/editor-nav.js

Доступ до /nodes обмежено middleware для admin.

## Продакшн/деплой

У репозиторії є шаблони:

- Apache reverse proxy: apache.conf
- Cloudflare Tunnel: cloudflared.yml
- systemd service: mqtttest.service

Типовий сценарій:

1. Запустити Node.js застосунок локально на 127.0.0.1:3000
2. Apache проксуює HTTP і WebSocket (включно з /editor/comms та /mqtt)
3. cloudflared віддає зовнішній HTTPS домен

Для продакшну важливо:

- Встановити NODE_ENV=production (для secure cookie)
- Тримати секрети поза кодом (env vars)
- Закрити зовнішній доступ до внутрішніх портів 3000 і 1883 через firewall

## Безпека та рекомендації

Поточна реалізація робоча, але для продакшну бажано:

- Винести session secret та credentialSecret в змінні оточення
- Додати rate limit для /api/login та /api/register
- Додати CSRF захист для state-changing запитів
- Додати валідацію username (дозволені символи, довжина)
- Додати резервне копіювання users.json і .node-red/flows.json
- Додати TLS для MQTT TCP (або лишити TCP лише локально)

## Підготовка до public GitHub

Перед зміною visibility на public перевірте:

1. У репозиторії немає реальних `.env`, cloudflared credentials, ключів (`.pem`, `.key`).
2. `users.json` не відстежується git і не міститься в історії комітів.
3. У `server.js` немає хардкод-секретів (використовуються env).
4. `node_modules` не відстежується git.

Швидкі команди перевірки:

```bash
git ls-files | Select-String -Pattern '(^users\.json$|^\.env|^node_modules/|\.pem$|\.key$|^\.cloudflared/)'
```

Якщо щось зайве вже в індексі, прибрати з відстеження:

```bash
git rm -r --cached node_modules users.json .env .cloudflared
git commit -m "chore: remove sensitive/local files from tracking"
```

## Нотатки

- Сервер слухає 127.0.0.1:3000, тобто доступний локально або через reverse proxy.
- MQTT TCP брокер слухає 1883 (без TLS).
- UI локалізований українською.

## Швидка перевірка після запуску

1. Відкрити /register і створити користувача
2. Увійти на /login
3. На /dashboard:
   - підписатися на test/#
   - відправити повідомлення у test/hello
   - перевірити, що воно з'явилось у логах
4. Перевірити доступ до /admin та /editor відповідно до ролі
