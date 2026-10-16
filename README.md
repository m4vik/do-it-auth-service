# Auth Service

REST-сервис аутентификации: C# / ASP.NET Core, PostgreSQL, Redis, Docker Compose.

Реализованы регистрация по email или телефону и паролю, подтверждение контакта,
JWT Access + Refresh, включение и выключение 2FA через одноразовые коды,
ротация refresh и выход с отзывом токенов сессии.

Аккаунт сразу активен. Признак подтверждения контакта хранится отдельно:
неподтверждённый контакт не блокирует вход. Отправка email/SMS реализована заглушкой — код выводится в лог.

## Запуск

Нужны Git и запущенный Docker Desktop с Linux containers.

```powershell
git clone https://github.com/m4vik/do-it-auth-service.git
cd do-it-auth-service
docker compose up --build
```

API и тестовый интерфейс: **http://localhost:8080/**.
База, ключи и таблицы создаются автоматически. Завершение `init` и `migrate` с кодом `0` — ожидаемое состояние.

Коды подтверждения видны в окне запуска Docker или через:

```powershell
docker compose logs -f api
```

Остановка: `Ctrl+C` или `docker compose stop`. Повторный запуск: `docker compose up --build`.

## Проверка через интерфейс

1. Открой http://localhost:8080/, выбери email или телефон и введи пароль.
2. Нажми **Зарегистрироваться**, **Войти**, затем **Профиль**. Ожидается активный аккаунт с `isContactVerified=false`.
3. Запроси код подтверждения контакта. Найди в логах `purpose=contact`, введи код и подтверди. Ожидается `isContactVerified=true`.
4. Выбери **Включить 2FA**, получи код `purpose=enable` и подтверди изменение. Потребуется войти заново.
5. Нажми **Войти**. Вместо токенов появится второй шаг: введи код `purpose=login` и подтверди вход. В профиле ожидается `twoFactorEnabled=true`.
6. Нажми **Обновить токены**, затем **Профиль**. Оба запроса должны завершиться с ответом `200`.
7. Выбери **Выключить 2FA**, получи код `purpose=disable` и подтверди. Повторный вход проходит без второго кода.
8. Нажми **Выйти**. Ожидается `204`; токены текущей сессии больше не принимаются.

Токены подставляются интерфейсом автоматически. Справа отображаются статус и JSON ответа.
После обновления страницы нужно войти снова. Для повторной регистрации используй новый контакт.

## Эндпоинты

Запросы и ответы — JSON. Защищённые маршруты требуют заголовок
`Authorization: Bearer <accessToken>`.

| Метод и путь | Тело запроса | Результат | Авторизация |
|---|---|---|---|
| POST `/auth/register` | `identifierType`, `identifier`, `password` | 201, профиль | Нет |
| POST `/auth/login` | `identifierType`, `identifier`, `password` | 200, пара токенов либо challenge второго фактора | Нет |
| POST `/auth/2fa/verify` | `challengeId`, `code` | 200, пара токенов | Нет |
| POST `/auth/refresh` | `refreshToken` | 200, новая пара; предыдущий refresh недействителен | Refresh в теле |
| POST `/auth/logout` | Нет | 204, токены текущей сессии отозваны | Access |
| GET `/users/me` | Нет | 200, профиль | Access |
| POST `/users/me/contact-verification/request` | Нет | 202, challenge; код в логах | Access |
| POST `/users/me/contact-verification/confirm` | `challengeId`, `code` | 200, подтверждённый профиль | Access |
| POST `/users/me/2fa/request` | `action`: `enable` или `disable`, `password` | 202, challenge; код в логах | Access |
| POST `/users/me/2fa/enable` | `challengeId`, `code` | 204, 2FA включена | Access |
| POST `/users/me/2fa/disable` | `challengeId`, `code` | 204, 2FA выключена | Access |

- `identifierType`: `email` или `phone`. Телефон — с кодом страны, например `+12025550123`.
- Пароль: 8–128 символов. Код: строка из шести цифр, включая ведущие нули.
- Профиль: `id`, `identifierType`, `identifier`, `isActive`, `isContactVerified`, `twoFactorEnabled`.
- Пара токенов: `accessToken`, `refreshToken`, `expiresIn` в секундах, `tokenType`.
- Challenge: `challengeId`, `expiresIn`, `twoFactorRequired`. При включённой 2FA login не выдаёт токены до проверки кода.
- Код привязан к пользователю и назначению. В логах выбирай строку с `challenge`, совпадающим с полученным `challengeId`.
- После включения или выключения 2FA существующие сессии отзываются; требуется новый вход.
- Повторная отправка кода доступна через 60 секунд.
- Ошибки: `400` — формат или код, `401` — авторизация, `409` — занятый контакт/конфликт состояния, `429` — лимит попыток, `503` — недоступное хранилище.

## Проверка вручную (PowerShell)

Открой второй терминал. Регистрация, вход и профиль:

```powershell
$base = 'http://localhost:8080'
$credentials = @{ identifierType='email'; identifier="test-$([guid]::NewGuid().ToString('N'))@example.com"; password='Test-password-123!' }
$body = $credentials | ConvertTo-Json
Invoke-RestMethod "$base/auth/register" -Method Post -ContentType 'application/json' -Body $body
$tokens = Invoke-RestMethod "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
$headers = @{ Authorization="Bearer $($tokens.accessToken)" }
Invoke-RestMethod "$base/users/me" -Headers $headers
```

Подтверждение контакта:

```powershell
$challenge = Invoke-RestMethod "$base/users/me/contact-verification/request" -Method Post -Headers $headers
$code = Read-Host 'Код contact из логов Docker'
$confirmation = @{ challengeId=$challenge.challengeId; code=$code } | ConvertTo-Json
Invoke-RestMethod "$base/users/me/contact-verification/confirm" -Method Post -Headers $headers -ContentType 'application/json' -Body $confirmation
```

Включение 2FA и вход с кодом:

```powershell
$setup = @{ action='enable'; password=$credentials.password } | ConvertTo-Json
$challenge = Invoke-RestMethod "$base/users/me/2fa/request" -Method Post -Headers $headers -ContentType 'application/json' -Body $setup
$code = Read-Host 'Код enable из логов Docker'
$confirmation = @{ challengeId=$challenge.challengeId; code=$code } | ConvertTo-Json
Invoke-RestMethod "$base/users/me/2fa/enable" -Method Post -Headers $headers -ContentType 'application/json' -Body $confirmation
$challenge = Invoke-RestMethod "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
$code = Read-Host 'Код login из логов Docker'
$confirmation = @{ challengeId=$challenge.challengeId; code=$code } | ConvertTo-Json
$tokens = Invoke-RestMethod "$base/auth/2fa/verify" -Method Post -ContentType 'application/json' -Body $confirmation
$headers = @{ Authorization="Bearer $($tokens.accessToken)" }
Invoke-RestMethod "$base/users/me" -Headers $headers
```

Для выключения 2FA запроси код через `/users/me/2fa/request` с `action='disable'` и паролем,
затем отправь `challengeId` и код `purpose=disable` в `/users/me/2fa/disable`.
После этого снова выполни login: он выдаст пару токенов без второго шага. Обнови `$headers`.

Обновление токенов и выход:

```powershell
$refreshBody = @{ refreshToken=$tokens.refreshToken } | ConvertTo-Json
$tokens = Invoke-RestMethod "$base/auth/refresh" -Method Post -ContentType 'application/json' -Body $refreshBody
$headers = @{ Authorization="Bearer $($tokens.accessToken)" }
Invoke-RestMethod "$base/users/me" -Headers $headers
Invoke-RestMethod "$base/auth/logout" -Method Post -Headers $headers
```

После выхода запрос профиля с тем же access и обновление с тем же refresh должны вернуть `401`.
Для телефона повтори сценарий с `identifierType='phone'` и новым номером: коды появятся как `DEMO SMS`.
