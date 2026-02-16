# CyberBackup Monitoring Tool

Лёгкий инструмент мониторинга Cyber Backup Open API с настраиваемыми виджетами.

## Возможности

- Подключение к Cyber Backup по `POST /idp/token` (password grant).
- Виджеты по данным API:
  - количество ресурсов,
  - количество политик,
  - задачи по состояниям,
  - действия по состояниям,
  - детали конкретных credentials.
- Настройка виджетов через JSON-конфиг.
- Встроенный веб-дашборд (stdlib HTTP server), автообновление.
- Явная авторизация через UI/API и ручное получение токена.

## Запуск

1. Скопируйте пример:

```bash
cp monitoring_tool/config.example.json monitoring_tool/config.json
```

2. Заполните реальные параметры подключения и идентификаторы.

3. Запустите:

```bash
python3 monitoring_tool/cyberbackup_monitor.py --config monitoring_tool/config.json
```

4. Откройте:

- `http://localhost:8080`

## Явная авторизация и получение токена

В дашборде есть форма **«Явная авторизация и получение токена»**:

- `username`
- `password`
- `client_id`
- `client_secret`
- `scope` (опционально)

После нажатия кнопки выполняется `POST /api/auth`, сервер запрашивает токен у Cyber Backup (`POST /idp/token`) и возвращает статус.

Дополнительно доступна проверка состояния токена:

- `GET /api/auth/status`

## Формат виджета

```json
{
  "title": "Задачи по состояниям",
  "type": "tasks_by_state",
  "params": {
    "limit": 200
  }
}
```

Поддерживаемые `type`:

- `resources_count`
- `policies_count`
- `tasks_by_state`
- `activities_by_state`
- `credentials_detail` (требует `params.credentials_id`)

## Ограничения

- Инструмент использует только Python stdlib и не включает полноценную валидацию TLS-сертификатов переключателем `verify_ssl`.
- Для production рекомендуется добавить reverse proxy, auth и хранение секретов через vault.
