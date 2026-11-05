"""Pydantic-моделі запитів і відповідей."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Status = Literal["new", "in_progress", "done"]


class CategoryCreate(BaseModel):
    """Дані для створення категорії."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(min_length=2, max_length=40, description="Назва категорії")


class CategoryRead(CategoryCreate):
    """Категорія у відповіді."""

    id: int


class RecordCreate(BaseModel):
    """Дані для створення запису (id задає база)."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    code: str = Field(min_length=3, max_length=40, description="Унікальний код")
    title: str = Field(min_length=3, max_length=120, description="Назва знахідки")
    category_id: int = Field(gt=0, description="Ідентифікатор категорії")
    value: float = Field(
        ge=0, le=10, allow_inf_nan=False, description="Оцінка ризику (score), 0–10"
    )
    status: Status = Field(description="Стан опрацювання")


class RecordReplace(RecordCreate):
    """Повна заміна змінюваних полів (усі поля обов'язкові)."""


class RecordRead(RecordCreate):
    """Запис у відповіді."""

    id: int
    category_name: str


class StudentRead(BaseModel):
    """Дані студента."""

    student_name: str
    group_name: str
    variant_number: int
