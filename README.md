# Auth Service

REST-сервис аутентификации на C# / ASP.NET Core (.NET 10), PostgreSQL и Redis.
Регистрация по email **или** телефону, подтверждение контакта, JWT Access + Refresh,
2FA через одноразовые email/SMS-коды, ротация refresh и отзыв сессий.
Доставка кодов — **заглушка в логах**, как предусмотрено заданием.

## Быстрый запуск

Нужны Git и запущенный Docker Desktop с Linux containers. .NET на компьютере для этого способа не требуется.

```powershell
git clone https://github.com/m4vik/do-it-auth-service.git
cd do-it-auth-service
docker compose up --build
```

API: `http://localhost:8080`. Интерфейса сайта нет. `GET /` возвращает 404;
проверить доступность можно через `GET /users/me` — без токена ожидается 401.
Первая сборка скачивает образы и NuGet-пакеты и требует интернета.

Compose последовательно подготавливает PostgreSQL, генерирует локальные секреты,
выполняет миграции, дожидается Redis и запускает API. `init` и `migrate` завершаются
с кодом 0 — это ожидаемое состояние, не падение сервиса.

```powershell
docker compose ps -a
docker compose logs -f api
docker compose stop
docker compose start
```

Запуск в фоне: `docker compose up --build -d`. Остановка с удалением контейнеров,
но сохранением данных: `docker compose down`. **`docker compose down -v` удаляет
данные и ключи этого проекта**; использовать только для намеренного сброса демо.

## Архитектура и чтение кода

```text
HTTP → controllers / DTO → application services → PostgreSQL
                                  ├────────────→ Redis
                                  └────────────→ email/SMS log stub
```

- `src/AuthService/Features/Auth`: регистрация, пароль, JWT-сессии, refresh, logout.
- `src/AuthService/Features/Verification`: одноразовые коды, подтверждение контакта, 2FA.
- `src/AuthService/Features/UsersController.cs`: профиль и защищённые операции.
- `src/AuthService/Security`: нормализация контакта и криптографические операции с JWT.
- `src/AuthService/Infrastructure`: EF Core, сущности и миграции.
- `src/AuthService/Configuration`: настройки сроков и ограничений.
- `tests/AuthService.Tests`: unit- и интеграционные тесты.

Контроллеры работают с HTTP, сервисы определяют правила и транзакции.
EF Core отвечает за запросы и отслеживание изменений. Дополнительного универсального
CRUD-слоя нет. Пароли хешируются стандартным PasswordHasher (PBKDF2, соль,
версионируемый формат). Проверка выполняется готовой библиотекой.

### Хранение

| Данные | Хранилище |
|---|---|
| Пользователь, нормализованный контакт, хеш пароля, активность, подтверждение, состояние/версия 2FA | PostgreSQL, `users` |
| Сессия, SHA-256 digest случайного подписанного refresh, срок и отзыв | PostgreSQL, `sessions` |
| HMAC кодов, назначение, попытки, время жизни, cooldown и rate-limit | Redis |
| Ключ подписи JWT и отдельный ключ HMAC | Закрытый Docker volume `secrets` |

Тип контакта и его значение уникальны в БД. Email обрезается по краям и приводится
к нижнему регистру, без специальных правил Gmail. Телефон должен включать `+` и код
страны; библиотека libphonenumber приводит его к E.164. Пароль: 8–128 символов.
Один аккаунт имеет один регистрационный контакт; привязка дополнительного контакта
не входит в задание. Новый аккаунт активен, но контакт ещё не подтверждён.

## REST API

Все тела запросов и ответов — JSON, поля camelCase. Для защищённых маршрутов:
`Authorization: Bearer <accessToken>`. Значения `identifierType`: `email`, `phone`.

| Метод / путь | Тело | Успешный ответ | Авторизация |
|---|---|---|---|
| POST `/auth/register` | `identifierType`, `identifier`, `password` | 201, профиль | Нет |
| POST `/auth/login` | те же поля | 200, токены или challenge | Нет |
| POST `/auth/2fa/verify` | `challengeId`, `code` | 200, токены | Нет |
| POST `/auth/refresh` | `refreshToken` | 200, новая пара | Refresh в теле |
| POST `/auth/logout` | нет | 204 | Access |
| GET `/users/me` | нет | 200, профиль | Access |
| POST `/users/me/contact-verification/request` | нет | 202, challenge | Access |
| POST `/users/me/contact-verification/confirm` | `challengeId`, `code` | 200, профиль | Access |
| POST `/users/me/2fa/request` | `action`: `enable`/`disable`, `password` | 202, challenge | Access |
| POST `/users/me/2fa/enable` | `challengeId`, `code` | 204 | Access |
| POST `/users/me/2fa/disable` | `challengeId`, `code` | 204 | Access |

Профиль: `id`, `identifierType`, `identifier`, `isActive`, `isContactVerified`, `twoFactorEnabled`.
Токены: `accessToken`, `refreshToken`, `expiresIn` (секунды), `tokenType` (`Bearer`).
Challenge: `challengeId`, `expiresIn`, `twoFactorRequired` (true только для второго шага входа).
Код — строка из 6 цифр, включая возможные ведущие нули.

```json
{"error":{"code":"invalid_code","message":"Invalid, expired or already used code."}}
```

Ошибки: 400 — формат/код; 401 — неверная авторизация; 409 — занятый контакт или
уже установленное состояние; 429 — лимит; 503 — недоступное хранилище;
500 — непредвиденная ошибка без внутренних деталей. Для неизвестного аккаунта
и неверного пароля возвращается одинаковое сообщение.

## Проверка вручную (PowerShell)

В отдельном терминале оставь `docker compose logs -f api`: сообщения `DEMO EMAIL`
или `DEMO SMS` содержат назначение, `challenge` и `code`. Код должен относиться
к тому `challengeId`, который вернул твой запрос. Настоящие письма и SMS не уходят.

### 1. Регистрация, вход и профиль

```powershell
$base = 'http://localhost:8080'
$credentials = @{ identifierType='email'; identifier='demo@example.com'; password='Demo-password-123!' }
$body = $credentials | ConvertTo-Json
Invoke-RestMethod "$base/auth/register" -Method Post -ContentType 'application/json' -Body $body
$tokens = Invoke-RestMethod "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
$headers = @{ Authorization="Bearer $($tokens.accessToken)" }
Invoke-RestMethod "$base/users/me" -Headers $headers
```

Ожидается `isActive=true`, `isContactVerified=false`: вход доступен без подтверждения.
Для телефонного сценария используй `identifierType='phone'`, `identifier='+12025550123'`.
Повторная регистрация того же контакта вернёт 409 — для повторного прогона выбери новый.

### 2. Подтверждение контакта

```powershell
$challenge = Invoke-RestMethod "$base/users/me/contact-verification/request" -Method Post -Headers $headers
$code = Read-Host 'Код contact из логов'
$confirmation = @{ challengeId=$challenge.challengeId; code=$code } | ConvertTo-Json
Invoke-RestMethod "$base/users/me/contact-verification/confirm" -Method Post -Headers $headers -ContentType 'application/json' -Body $confirmation
```

Ожидается `isContactVerified=true`. Повторное применение кода вернёт 400.

### 3. Включение 2FA и вход со вторым фактором

```powershell
$setup = @{ action='enable'; password=$credentials.password } | ConvertTo-Json
$challenge = Invoke-RestMethod "$base/users/me/2fa/request" -Method Post -Headers $headers -ContentType 'application/json' -Body $setup
$code = Read-Host 'Код enable из логов'
$confirmation = @{ challengeId=$challenge.challengeId; code=$code } | ConvertTo-Json
Invoke-RestMethod "$base/users/me/2fa/enable" -Method Post -Headers $headers -ContentType 'application/json' -Body $confirmation
$challenge = Invoke-RestMethod "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
$code = Read-Host 'Код login из логов'
$confirmation = @{ challengeId=$challenge.challengeId; code=$code } | ConvertTo-Json
$tokens = Invoke-RestMethod "$base/auth/2fa/verify" -Method Post -ContentType 'application/json' -Body $confirmation
$headers = @{ Authorization="Bearer $($tokens.accessToken)" }
Invoke-RestMethod "$base/users/me" -Headers $headers
```

После включения 2FA прежние сессии отозваны. Login возвращает только challenge,
основных токенов до проверки второго фактора нет. Включение 2FA подтверждает контакт,
если он ещё не был подтверждён, поскольку пользователь ввёл доставленный код.

### 4. Ротация и logout

```powershell
$refreshBody = @{ refreshToken=$tokens.refreshToken } | ConvertTo-Json
$tokens = Invoke-RestMethod "$base/auth/refresh" -Method Post -ContentType 'application/json' -Body $refreshBody
$headers = @{ Authorization="Bearer $($tokens.accessToken)" }
Invoke-RestMethod "$base/users/me" -Headers $headers
Invoke-RestMethod "$base/auth/logout" -Method Post -Headers $headers
```

После выхода профиль и refresh этой сессии вернут 401. Другие сессии пользователя
не затрагиваются. Повторное применение старого refresh также отзывает его сессию:
для обычного клиента refresh нужно вызывать последовательно, без параллельных повторов.

### 5. Выключение 2FA

Снова войди через пароль и код. С действующим access выполни `/users/me/2fa/request`
с `action='disable'` и текущим паролем. Введи полученный код в `/users/me/2fa/disable`
(тело `challengeId`, `code`). Ответ 204, сессии отозваны; новый login выдаёт токены
после пароля. Нельзя использовать для этого код `contact` или `login`.

## Тесты

Без установленного .NET:

```powershell
docker compose --profile test run --build --rm tests
```

Тесты создают отдельную случайно названную БД и удаляют её по завершении.
Демонстрационные пользователи API не меняются. В тестах доставка кодов перехватывается
через ICodeSender, но операции Redis и PostgreSQL настоящие.

С установленным .NET 10 SDK:

```powershell
dotnet restore
dotnet test --filter 'Category!=Integration'
docker compose -f docker-compose.test.yml up -d --wait
$env:TEST_POSTGRES='Host=localhost;Port=55432;Database=auth;Username=auth;Password=local-demo-password'
$env:TEST_REDIS='localhost:56379'
dotnet test
docker compose -f docker-compose.test.yml down
```

Проверяем оба полных сценария, нормализацию, уникальность при гонке, хеширование,
разделение access/refresh, срок сессии, попытки/TTL/замену кодов, чужие коды,
повторное потребление, конкурентные refresh и 2FA, refresh против logout.

## Настройки и безопасность

Настройки ASP.NET Core передаются через переменные окружения (`__` означает вложенность).

| Настройка | Значение по умолчанию |
|---|---|
| `Auth__AccessMinutes` | 15 |
| `Auth__SessionDays` | 7, абсолютный срок сессии |
| `Auth__ContactCodeMinutes` | 10 |
| `Auth__FactorCodeMinutes` | 5 |
| `Auth__CodeAttempts` | 5 |
| `Auth__SendCooldownSeconds` | 60, на пользователя и назначение |
| `Auth__Issuer` / `Auth__Audience` | auth-service / auth-service-client |
| `Auth__SigningKey` / `Auth__CodeKey` | Из volume, если не переданы явно; разные, минимум 64 символа |
| `ConnectionStrings__Postgres` / `ConnectionStrings__Redis` | В Compose |

Login ограничен 10 попытками за 5 минут на контакт и 100 на IP; проверка второго фактора
— 100 на IP за 5 минут. Проверка пароля при смене 2FA — 10 на пользователя за 5 минут.
Завершение кода в Redis атомарно. Транзакции PostgreSQL блокируют сначала пользователя,
потом сессию; это предотвращает противоречия при конкурентных изменениях.

PostgreSQL — источник истины об отзыве. Все защищённые запросы проверяют сессию,
поэтому logout действует сразу, даже если JWT ещё не истёк. Сбой Redis не возвращает
жизнь отозванному токену. Если код уже потреблён, а БД не завершила операцию,
нужно повторить запрос кода/вход: токены в этом случае не выдаются.

Демонстрационный пароль PostgreSQL указан в Compose специально для запуска одной
командой; БД и Redis не публикуют порты на хост. API привязан к localhost. Приложение
работает не от root; только одноразовый init настраивает права volume.
Для внешнего сервера нужны собственные секреты, HTTPS и настоящая доставка кодов.
Данное задание не выдаётся за готовую публичную production-инсталляцию.

## Git и работа в Visual Studio

Открой `AuthService.slnx` в Visual Studio с поддержкой .NET 10. Терминал открывается
через **Вид → Терминал**. Версии кода сохранены отдельными коммитами.

```powershell
git status
git log --oneline --decorate
git pull --ff-only
```

Для своей правки создай ветку, измени код, выполни тесты и проверь diff:

```powershell
git switch -c feature/my-change
git diff
git add src tests README.md
git diff --cached
git commit -m "fix: describe the change"
git push -u origin feature/my-change
```

Для следующих push той же ветки достаточно `git push`. Чтобы посмотреть прошлую
версию без изменения main, сначала сохрани текущие правки, затем:

```powershell
git switch -c inspect-old-version COMMIT_HASH
```

Вернуться: `git switch main`. Чтобы отменить уже опубликованный коммит с сохранением
истории, используй `git revert COMMIT_HASH`, затем `git push`. Не используй force push
или `reset --hard` для обычного отката. Смена версии кода не откатывает автоматически
схему и данные БД; изменения схемы оформляются отдельными миграциями.

## Локальная отладка и изменение схемы

Для отладки в Visual Studio запусти отдельные хранилища:
`docker compose -f docker-compose.test.yml up -d --wait`. Затем в PowerShell
подготовь конфигурацию только для текущего терминала:

```powershell
$env:ConnectionStrings__Postgres='Host=localhost;Port=55432;Database=auth;Username=auth;Password=local-demo-password'
$env:ConnectionStrings__Redis='localhost:56379'
$env:SecretsDirectory=Join-Path $PWD 'secrets'
dotnet run --project src/AuthService -- --init-secrets
dotnet run --project src/AuthService -- --migrate
dotnet run --project src/AuthService
```

Локальный профиль запуска использует `http://localhost:5280`. Для F5 в Visual Studio
те же переменные задаются в локальной конфигурации отладки; папка `secrets` исключена
из Git. Секреты не нужно вставлять в `appsettings.json` или коммиты.

При изменении сущностей:

```powershell
dotnet tool restore
dotnet ef migrations add MeaningfulChange --project src/AuthService --output-dir Infrastructure/Migrations
dotnet ef migrations has-pending-model-changes --project src/AuthService
```

Проверь сгенерированную миграцию перед применением. Для приложения её выполнит
`migrate` при следующем `docker compose up --build`. Не редактируй уже применённую
миграцию ради нового изменения; создай следующую и проверь её на тестовой БД.
