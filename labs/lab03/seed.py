# заповнення бази з data/seed.json.

import json
import sqlite3
from pathlib import Path
from typing import Any

from . import repository
from .database import BASE_DIR, initialize_database
from .schemas import CategoryCreate, RecordCreate

SEED_PATH = BASE_DIR / "data" / "seed.json"


def load_seed(path: Path = SEED_PATH) -> tuple[list[dict], list[dict]]:
    """Прочитати та перевірити JSON. Кидає ValueError за некоректних даних."""
    raw: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {"categories", "records"}:
        raise ValueError("JSON має містити лише ключі categories і records")

    categories: list[dict] = []
    for item in raw["categories"]:
        if not isinstance(item, dict) or set(item) != {"id", "name"}:
            raise ValueError("Категорія має містити лише id і name")
        category_id = item["id"]
        if not isinstance(category_id, int) or isinstance(category_id, bool):
            raise TypeError("id категорії має бути цілим числом")
        if category_id <= 0:
            raise ValueError("id категорії має бути додатним")
        name = CategoryCreate(name=item["name"]).name
        categories.append({"id": category_id, "name": name})

    ids = [c["id"] for c in categories]
    if len(set(ids)) != len(ids):
        raise ValueError("id категорій мають бути унікальними")

    records = [RecordCreate(**item).model_dump() for item in raw["records"]]
    for record in records:
        if record["category_id"] not in ids:
            raise ValueError(f"Невідома категорія у записі {record['code']}")
    return categories, records


def main() -> int:
    """Заповнити порожню базу; повторний запуск нічого не змінює."""
    initialize_database()
    if not repository.is_database_empty():
        print("База вже містить дані — заповнення пропущено.")
        return 0
    try:
        categories, records = load_seed()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Некоректні початкові дані: {exc}")
        return 1
    try:
        repository.insert_seed(categories, records)
    except sqlite3.Error as exc:
        print(f"Помилка запису в базу, зміни скасовано: {exc}")
        return 1
    print(f"Додано категорій: {len(categories)}, записів: {len(records)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())