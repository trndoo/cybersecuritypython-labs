"""Маршрути записів."""

from typing import Annotated

from fastapi import APIRouter, Body, Path, Query, Response

from .. import repository
from ..schemas import RecordCreate, RecordRead, RecordReplace, Status

router = APIRouter(prefix="/records", tags=["Записи"])

RecordId = Annotated[int, Path(gt=0, description="Ідентифікатор запису")]
NOT_FOUND = {404: {"description": "Запис або категорію не знайдено"}}
CONFLICT = {409: {"description": "Запис з таким code вже існує"}}


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Список записів",
    operation_id="list_records",
)
def list_records(
    category_id: Annotated[
        int | None, Query(gt=0, description="Лише записи цієї категорії")
    ] = None,
    status: Annotated[Status | None, Query(description="Лише цей статус")] = None,
    min_value: Annotated[
        float | None,
        Query(ge=0, le=10, allow_inf_nan=False, description="value >= min_value"),
    ] = None,
    q: Annotated[
        str | None,
        Query(min_length=1, max_length=120, description="Підрядок у title"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100, description="Макс. кількість")] = 20,
    offset: Annotated[int, Query(ge=0, description="Скільки пропустити")] = 0,
) -> list[dict]:
    """Фільтри поєднуються через AND; сортування за id."""
    return repository.list_records(category_id, status, min_value, q, limit, offset)


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=201,
    summary="Пакетне створення записів",
    operation_id="create_records_bulk",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_records_bulk(
    items: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
) -> list[dict]:
    """Створити 1–100 записів атомарно: або всі, або жодного."""
    return repository.create_records_bulk([item.model_dump() for item in items])


@router.post(
    "",
    response_model=RecordRead,
    status_code=201,
    summary="Створити запис",
    operation_id="create_record",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_record(record: RecordCreate) -> dict:
    """Створити новий запис."""
    return repository.create_record(record.model_dump())


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати запис",
    operation_id="get_record",
    responses=NOT_FOUND,
)
def get_record(record_id: RecordId) -> dict:
    """Повернути один запис за id."""
    return repository.get_record(record_id)


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Замінити запис",
    operation_id="replace_record",
    responses={**NOT_FOUND, **CONFLICT},
)
def replace_record(record_id: RecordId, record: RecordReplace) -> dict:
    """Замінити всі змінювані поля запису."""
    return repository.replace_record(record_id, record.model_dump())


@router.delete(
    "/{record_id}",
    status_code=204,
    summary="Видалити запис",
    operation_id="delete_record",
    responses=NOT_FOUND,
)
def delete_record(record_id: RecordId) -> Response:
    """Видалити запис."""
    repository.delete_record(record_id)
    return Response(status_code=204)