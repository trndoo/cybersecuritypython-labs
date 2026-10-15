"""Точка входу ЛР №2: команди `demo` (Завдання 1) та `analyze` (Завдання 2)."""

# дозволяє використовувати сучасні підказки типів (наприклад, list[str] замість List[str])
from __future__ import annotations

import argparse
import sys

# імпортуємо логіку з  попередніх файлів
from labs.lab02 import task1, task2


def _run_demo(_args: argparse.Namespace) -> int:
    """функція-обгортка для запуску першого завдання."""
    # викликаємо демонстрацію класів з task1
    task1.demo()
    # повертаємо 0, що для операційної системи означає "програма завершилася без помилок"
    return 0


def build_parser() -> argparse.ArgumentParser:
    """будує парсер аргументів командного рядка (наш cli інтерфейс)."""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab02.main",
        description="Lab 02: OOP demo and sudo log auditor (variant 15).",
    )

    # add_subparsers створює розгалуження команд. required=True означає,
    # що користувач зобов'язаний вказати або 'demo', або 'analyze'
    subparsers = parser.add_subparsers(dest="command", required=True)

    # налаштування команди demo
    demo_parser = subparsers.add_parser("demo", help="run the Task 1 OOP demo")
    # прив'язуємо функцію _run_demo до команди demo.
    # якщо користувач викличе demo, парсер запам'ятає, що треба виконати саме цю функцію
    demo_parser.set_defaults(func=_run_demo)

    # налаштування команди analyze
    analyze_parser = subparsers.add_parser(
        "analyze", help="audit a sudo log (Task 2, variant 15)"
    )
    # не пишемо всі аргументи тут, а делегуємо це файлу task2 (там є функція add_arguments),
    # щоб зберегти код чистим і модульним
    task2.add_arguments(analyze_parser)
    # так само прив'язуємо головну функцію run з task2 до команди analyze
    analyze_parser.set_defaults(func=task2.run)

    return parser


def main(argv: list[str] | None = None) -> int:
    """головна функція скрипта."""
    # розбираємо те, що користувач ввів у консолі
    args = build_parser().parse_args(argv)

    # тут відбувається: args.func містить посилання на ту функцію, яку ми
    # прив'язали через set_defaults (або _run_demo, або task2.run).
    # ми викликаємо її і передаємо їй аргументи.
    return args.func(args)


if __name__ == "__main__":
    # sys.exit бере результат нашої функції main (це буде 0 або 1)
    # і передає його системі, щоб термінал знав, чи успішно відпрацював скрипт
    sys.exit(main())
