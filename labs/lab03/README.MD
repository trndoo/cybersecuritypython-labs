# ЛР №3 (варіант 15): Реєстр ризиків налаштування робочих станцій

Web API на FastAPI + SQLite (без ORM). Облік знахідок аудиту налаштувань
робочих станцій.

- **categories** — напрям перевірки: `updates`, `permissions`, `protection`
- **records** — знахідки: `code`, `title`, `category_id`, `value`, `status`
- `value` — навчальна оцінка ризику, **score**, `float`, 0–10 включно
- Поріг: **8.0** (інформативний, API його не застосовує)
- `status`: `new`, `in_progress`, `done`

## Встановлення (з кореня репозиторію, Python 3.10+)

```bash
pip install fastapi uvicorn pydantic ruff
pip freeze | grep -iE "^(fastapi|uvicorn|pydantic|ruff|starlette)=="   # додайте у requirements.txt
```

## Запуск

```bash
python -m labs.lab03.database      # (необов'язково) створити таблиці
python -m labs.lab03.seed          # початкові дані: 3 категорії, 8 записів
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

Swagger UI: http://127.0.0.1:8000/docs, OpenAPI: http://127.0.0.1:8000/openapi.json

## Приклади запитів

```bash
curl -i "http://127.0.0.1:8000/ping"
curl -i "http://127.0.0.1:8000/records?category_id=1&status=new&limit=5&offset=0"
curl -i -X POST "http://127.0.0.1:8000/records" -H "Content-Type: application/json" \
  -d '{"code":"V15-TEST","title":"Навчальна знахідка","category_id":1,"value":7.5,"status":"new"}'
# скасування пакета (V15-01 вже є в базі) -> 409, V15-ROLLBACK не збережено
curl -i -X POST "http://127.0.0.1:8000/records/bulk" -H "Content-Type: application/json" \
  -d '[{"code":"V15-ROLLBACK","title":"Перший елемент","category_id":1,"value":4.0,"status":"new"},{"code":"V15-01","title":"Дублікат коду","category_id":2,"value":5.0,"status":"new"}]'
```

## Перевірка стилю

```bash
ruff check labs/lab03 && ruff format --check labs/lab03
```