# Cyber Backup Open API — методы подключения и доступные функции

Источник: `https://docs.cyberprotect.ru/ru-RU/CyberBackup/api/index.html` и связанные OpenAPI-спеки.

## 1) Как подключаться к API

### Базовые URL

- Для получения токена: `https://{host}:{port}`
- Для остальных сервисов API: `https://{host}:{port}/api/{version}`

### Точка выдачи токенов

- `POST /idp/token`

### Поддерживаемые методы OAuth2 (grant types)

1. `password`
2. `authorization_code`
3. `refresh_token`
4. `client_credentials`
5. `urn:ietf:params:oauth:grant-type:device_code`
6. `urn:ietf:params:oauth:grant-type:jwt-bearer`

### Ключевые поля запроса на токен

- Обязательное: `grant_type`
- Остальные поля применяются по выбранному `grant_type`: `client_id`, `client_secret`, `username`, `password`, `refresh_token`, `code`, `scope`, `assertion`, `device_code`, `totp_code`, `code_verifier`.

## 2) Какие функции доступны через API

## Tokens API

| Метод | Endpoint | Назначение |
|---|---|---|
| POST | `/idp/token` | Получение access/refresh токенов |

## Resources API

| Метод | Endpoint | Назначение | Важные параметры |
|---|---|---|---|
| GET | `/resources` | Список устройств/ресурсов | `tenant_id`, `type`, `resource_id`, `search`, `limit`, `before`, `after` |
| GET | `/resources/{resource_id}` | Информация по конкретному ресурсу | path: `resource_id`, query: `include_attributes` |

> В спецификации для `/resources` явно указан OAuth2 scope `urn:acronis.com::resource_management::read`.

## Policies API

| Метод | Endpoint | Назначение | Важные параметры |
|---|---|---|---|
| GET | `/policies` | Список планов резервного копирования | `tenant_id`, `type`, `enabled`, `policy_id`, `limit` |
| GET | `/policies/{policy_id}` | Данные конкретного плана | path: `policy_id` |
| GET | `/policy_applications` | Список применений планов | `tenant_id`, `agent_id`, `policy_id`, `status`, `limit` |
| POST | `/policy_applications:run` | Запуск применения/выполнения плана | тело запроса по схеме API |

## Tasks & Activities API

| Метод | Endpoint | Назначение | Важные параметры |
|---|---|---|---|
| GET | `/tasks` | Список задач | фильтры: `type`, `state`, `policy_id`, `resource_id`, `result_code`, `limit`, `after` |
| GET | `/tasks/{task-id}` | Детали задачи | path: `task-id` |
| GET | `/activities` | Список действий | фильтры: `type`, `state`, `policy_id`, `resource_id`, `task_id`, `limit`, `after` |
| GET | `/activities/{activity-id}` | Детали действия | path: `activity-id` |

## Credentials API

| Метод | Endpoint | Назначение | Важные параметры |
|---|---|---|---|
| POST | `/credentials` | Создать реквизиты | query: `tenant_id`, `no_session` |
| GET | `/credentials/{credentials_id}` | Получить реквизиты | path: `credentials_id`, query: `include_secret`, `tenant_id` |
| DELETE | `/credentials/{credentials_id}` | Удалить реквизиты | path: `credentials_id`, query: `tenant_id` |

> Для Credentials в OpenAPI у операций чтения/удаления указаны OAuth2 scopes семейства `credentials_store::*`.

## 3) Примеры вызовов cURL

> Ниже — шаблоны. Подставьте реальные значения `HOST`, `PORT`, `VERSION` и токен.

### 3.1 Получение токена (password grant)

```bash
curl -k -X POST "https://HOST:PORT/idp/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "username=USER" \
  --data-urlencode "password=PASS" \
  --data-urlencode "client_id=CLIENT_ID" \
  --data-urlencode "client_secret=CLIENT_SECRET" \
  --data-urlencode "scope=urn:acronis.com::resource_management::read"
```

### 3.2 Список ресурсов

```bash
curl -k "https://HOST:PORT/api/VERSION/resources?limit=50" \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

### 3.3 Детали ресурса

```bash
curl -k "https://HOST:PORT/api/VERSION/resources/RESOURCE_ID" \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

### 3.4 Список политик

```bash
curl -k "https://HOST:PORT/api/VERSION/policies?limit=50" \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

### 3.5 Запуск применения политики

```bash
curl -k -X POST "https://HOST:PORT/api/VERSION/policy_applications:run" \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"policy_id":"POLICY_ID","context_id":"RESOURCE_OR_GROUP_ID"}'
```

### 3.6 Мониторинг задач/действий

```bash
curl -k "https://HOST:PORT/api/VERSION/tasks?limit=100&state=running" \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

```bash
curl -k "https://HOST:PORT/api/VERSION/activities?limit=100" \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

### 3.7 Credentials

```bash
curl -k -X POST "https://HOST:PORT/api/VERSION/credentials?tenant_id=TENANT_ID" \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"kind":"username_password","name":"linux-root","username":"root","password":"***"}'
```

```bash
curl -k "https://HOST:PORT/api/VERSION/credentials/CREDENTIALS_ID?tenant_id=TENANT_ID" \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

```bash
curl -k -X DELETE "https://HOST:PORT/api/VERSION/credentials/CREDENTIALS_ID?tenant_id=TENANT_ID" \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

## 4) Что это дает с точки зрения автоматизации

С этим API можно автоматизировать:

- централизованную авторизацию (получение/обновление токенов),
- инвентаризацию и поиск ресурсов,
- чтение и запуск backup-политик,
- мониторинг выполнения через задачи/действия,
- управление хранилищем учетных реквизитов.
