"""FastAPI-застосунок."""

import logging
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from shared import student as student_module

from . import config
from .database import initialize_database
from .repository import ConflictError, NotFoundError
from .routers import categories, records
from .schemas import StudentRead

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Створити відсутні таблиці під час запуску."""
    initialize_database()
    yield


app = FastAPI(
    title=config.DOMAIN,
    description=(
        f"{config.DOMAIN_DESCRIPTION} Одиниця вимірювання: {config.UNIT}, "
        f"діапазон {config.VALUE_MIN}–{config.VALUE_MAX}, "
        f"поріг {config.THRESHOLD}."
    ),
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(categories.router)
app.include_router(records.router)


@app.exception_handler(NotFoundError)
async def not_found_handler(_: Request, exc: NotFoundError) -> JSONResponse:
    """Не знайдено -> 404."""
    return JSONResponse(status_code=404, content={"detail": str(exc)})


@app.exception_handler(ConflictError)
async def conflict_handler(_: Request, exc: ConflictError) -> JSONResponse:
    """Конфлікт -> 409."""
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.exception_handler(sqlite3.Error)
async def sqlite_error_handler(_: Request, exc: sqlite3.Error) -> JSONResponse:
    """Технічну помилку БД логуємо, клієнту — загальне повідомлення."""
    logger.error("Помилка SQLite: %s", exc, exc_info=exc)
    return JSONResponse(
        status_code=500, content={"detail": "Внутрішня помилка сервера"}
    )


@app.get("/ping", tags=["Службові"], summary="Перевірка доступності")
def ping() -> dict[str, str]:
    """Повернути статус API."""
    return {"status": "ok"}


@app.get(
    "/student", response_model=StudentRead, tags=["Службові"], summary="Дані студента"
)
def get_student() -> StudentRead:
    """Повернути дані з shared/student.py."""
    return StudentRead(
        student_name=student_module.STUDENT_NAME,
        group_name=student_module.GROUP_NAME,
        variant_number=student_module.VARIANT_NUMBER,
    )