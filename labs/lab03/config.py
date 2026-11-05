"""Налаштування варіанта 15."""

VARIANT_NUMBER = 15
DOMAIN = "Реєстр ризиків налаштування робочих станцій"
DOMAIN_DESCRIPTION = (
    "Сервіс обліку знахідок аудиту налаштувань робочих станцій. "
    "Категорія (updates, permissions, protection) визначає напрям перевірки, "
    "value — навчальну оцінку ризику, status — стан опрацювання знахідки."
)
UNIT = "score"
VALUE_MIN = 0.0
VALUE_MAX = 10.0
THRESHOLD = 8.0
STATUSES = ("new", "in_progress", "done")