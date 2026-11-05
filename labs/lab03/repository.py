"""Параметризовані SQL-запити. Модуль не залежить від FastAPI."""

import sqlite3
from contextlib import closing
from typing import Any

from .database import get_connection

Row = dict[str, Any]

RECORD_SELECT = (
    "SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name, "
    "r.value, r.status "
    "FROM records AS r JOIN categories AS c ON c.id = r.category_id"
)


class RepositoryError(Exception):
    """Базова помилка шару доступу до даних."""


class NotFoundError(RepositoryError):
    """Запис або категорія не існує."""


class ConflictError(RepositoryError):
    """Дублікат або порушення зв'язку."""


def _connect() -> sqlite3.Connection:
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    return connection


def _translate(exc: sqlite3.IntegrityError, duplicate_message: str) -> None:
    """Перетворити IntegrityError на помилку шару даних."""
    text = str(exc)
    if "UNIQUE constraint failed" in text:
        raise ConflictError(duplicate_message) from exc
    if "FOREIGN KEY constraint failed" in text:
        raise NotFoundError("Категорію не знайдено") from exc
    raise exc


def _category_exists(connection: sqlite3.Connection, category_id: int) -> bool:
    row = connection.execute(
        "SELECT 1 FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    return row is not None


def _fetch_record(connection: sqlite3.Connection, record_id: int) -> Row | None:
    row = connection.execute(RECORD_SELECT + " WHERE r.id = ?", (record_id,)).fetchone()
    return dict(row) if row else None


#  Категорії.


def create_category(name: str) -> Row:
    """Створити категорію."""
    with closing(_connect()) as connection:
        try:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO categories (name) VALUES (?)", (name,)
                )
        except sqlite3.IntegrityError as exc:
            _translate(exc, "Категорія з такою назвою вже існує")
        return {"id": cursor.lastrowid, "name": name}


def list_categories() -> list[Row]:
    """Список категорій за зростанням id."""
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію."""
    with closing(_connect()) as connection:
        try:
            with connection:
                if not _category_exists(connection, category_id):
                    raise NotFoundError("Категорію не знайдено")
                used = connection.execute(
                    "SELECT COUNT(*) FROM records WHERE category_id = ?",
                    (category_id,),
                ).fetchone()[0]
                if used:
                    raise ConflictError("Категорія містить записи")
                connection.execute(
                    "DELETE FROM categories WHERE id = ?", (category_id,)
                )
        except sqlite3.IntegrityError as exc:
            _translate(exc, "Категорія містить записи")


# Записи 


def create_record(data: Row) -> Row:
    """Додати запис і повернути його разом із category_name."""
    with closing(_connect()) as connection:
        try:
            with connection:
                if not _category_exists(connection, data["category_id"]):
                    raise NotFoundError("Категорію не знайдено")
                cursor = connection.execute(
                    "INSERT INTO records (code, title, category_id, value, status) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        data["code"],
                        data["title"],
                        data["category_id"],
                        data["value"],
                        data["status"],
                    ),
                )
                record = _fetch_record(connection, cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            _translate(exc, "Запис з таким code вже існує")
        return record


def get_record(record_id: int) -> Row:
    """Отримати запис за id."""
    with closing(_connect()) as connection:
        record = _fetch_record(connection, record_id)
    if record is None:
        raise NotFoundError("Запис не знайдено")
    return record


def list_records(
    category_id: int | None,
    status: str | None,
    min_value: float | None,
    q: str | None,
    limit: int,
    offset: int,
) -> list[Row]:
    """Список записів із фільтрами (AND) та сторінками, сортування за id."""
    clauses: list[str] = []
    params: list[Any] = []
    if category_id is not None:
        clauses.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        clauses.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        clauses.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        clauses.append("instr(r.title, ?) > 0")
        params.append(q)

    sql = RECORD_SELECT
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY r.id LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(_connect()) as connection:
        rows = connection.execute(sql, params).fetchall()
        return [dict(row) for row in rows]


def replace_record(record_id: int, data: Row) -> Row:
    """Повністю замінити змінювані поля запису; id не змінюється."""
    with closing(_connect()) as connection:
        try:
            with connection:
                if _fetch_record(connection, record_id) is None:
                    raise NotFoundError("Запис не знайдено")
                if not _category_exists(connection, data["category_id"]):
                    raise NotFoundError("Категорію не знайдено")
                connection.execute(
                    "UPDATE records SET code = ?, title = ?, category_id = ?, "
                    "value = ?, status = ? WHERE id = ?",
                    (
                        data["code"],
                        data["title"],
                        data["category_id"],
                        data["value"],
                        data["status"],
                        record_id,
                    ),
                )
                record = _fetch_record(connection, record_id)
        except sqlite3.IntegrityError as exc:
            _translate(exc, "Запис з таким code вже існує")
        return record


def delete_record(record_id: int) -> None:
    """Видалити запис."""
    with closing(_connect()) as connection, connection:
        cursor = connection.execute("DELETE FROM records WHERE id = ?", (record_id,))
        if cursor.rowcount == 0:
            raise NotFoundError("Запис не знайдено")


def create_records_bulk(items: list[Row]) -> list[Row]:
    """Атомарно додати пакет записів в одній транзакції."""
    with closing(_connect()) as connection:
        try:
            with connection:  # один commit у кінці або rollback при винятку
                for category_id in {item["category_id"] for item in items}:
                    if not _category_exists(connection, category_id):
                        raise NotFoundError("Категорію не знайдено")
                new_ids: list[int] = []
                for item in items:
                    cursor = connection.execute(
                        "INSERT INTO records "
                        "(code, title, category_id, value, status) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (
                            item["code"],
                            item["title"],
                            item["category_id"],
                            item["value"],
                            item["status"],
                        ),
                    )
                    new_ids.append(cursor.lastrowid)
                created = [_fetch_record(connection, rid) for rid in new_ids]
        except sqlite3.IntegrityError as exc:
            _translate(exc, "Один із code уже існує (у базі або в пакеті)")
        return created


#  Початкове заповнення


def is_database_empty() -> bool:
    """Чи порожні обидві таблиці."""
    with closing(_connect()) as connection:
        categories = connection.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
        records = connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    return categories == 0 and records == 0


def insert_seed(categories: list[Row], records: list[Row]) -> None:
    """Додати категорії та записи в одній транзакції."""
    with closing(_connect()) as connection, connection:
        connection.executemany(
            "INSERT INTO categories (id, name) VALUES (?, ?)",
            [(c["id"], c["name"]) for c in categories],
        )
        connection.executemany(
            "INSERT INTO records (code, title, category_id, value, status) "
            "VALUES (?, ?, ?, ?, ?)",
            [
                (r["code"], r["title"], r["category_id"], r["value"], r["status"])
                for r in records
            ],
        )