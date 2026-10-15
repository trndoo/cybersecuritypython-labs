from __future__ import annotations

import argparse
import json
import logging
import re
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

# створюємо окремий логер для нашої утиліти
logger = logging.getLogger("sudo_audit")

# додаємо власний рівень логування (35), щоб він був помітніший за звичайний WARNING (30),
# але не зупиняв програму як ERROR (40)
ALERT_LEVEL = 35
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
DEFAULT_ALERT_COMMANDS = ("chmod 777", "nc", "nmap", "dd", "/etc/shadow")
TOP_USERS = 5
# pathlib.Path допомагає створювати шляхи, які будуть працювати
DEFAULT_DATA_DIR = Path(__file__).parent / "data" / "data_v15"
DEFAULT_SUDO_LOG = DEFAULT_DATA_DIR / "sudo.log"
DEFAULT_ALERT_FILE = DEFAULT_DATA_DIR / "alert_commands.txt"
ROOT_USER = "root"

# регулярний вираз для парсингу рядка логу.
# (?P<name>...) створює іменовані групи, щоб потім зручно діставати дані за ключем, а не за індексом
SUDO_LINE_RE = re.compile(
    r"(?P<timestamp>\S+)\s+(?P<host>\S+)\s+sudo:\s+(?P<user>\S+)\s+:\s+"
    r"TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>.+?)\s+;\s+"
    r"USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.+?)"
)


# @dataclass автоматично створює методи __init__, __repr__ та інші.
# frozen=True означає, що об'єкт не можна змінити після створення (як константу)
@dataclass(frozen=True)
class SudoEntry:
    """один розібраний запис журналу sudo."""

    timestamp: datetime
    host: str
    user: str
    tty: str
    pwd: str
    target_user: str
    command: str

    # @property дозволяє звертатися до цього методу як до звичайного атрибута (наприклад, entry.is_root)
    @property
    def is_root(self) -> bool:
        return self.target_user == ROOT_USER


@dataclass(frozen=True)
class Finding:
    """підозрілий запис + які саме шаблони загроз спрацювали."""

    entry: SudoEntry
    matched: tuple[str, ...]


@dataclass
class AuditResult:
    """підсумок аналізу журналу, де зберігається вся статистика."""

    total: int = 0
    skipped: int = 0
    root_count: int = 0
    first_time: datetime | None = None
    last_time: datetime | None = None
    # Counter з модуля collections ідеально підходить для підрахунку (хто скільки разів ввів команду)
    # field(default_factory=...) вказує, як створити порожній лічильник або список при ініціалізації
    commands_per_user: Counter[str] = field(default_factory=Counter)
    risky_per_user: Counter[str] = field(default_factory=Counter)
    findings: list[Finding] = field(default_factory=list)


# парсинг
def parse_line(line: str) -> SudoEntry | None:
    """розбирає рядок логу; повертає None, якщо формат не підтримується."""
    # fullmatch перевіряє, чи весь рядок повністю відповідає нашому регулярному виразу
    match = SUDO_LINE_RE.fullmatch(line.strip())
    if match is None:
        return None
    try:
        # конвертуємо текст дати у справжній об'єкт datetime для порівнянь
        timestamp = datetime.fromisoformat(match["timestamp"])
    except ValueError:
        return None
    if (
        timestamp.tzinfo is None
    ):  # час без пояса вважаємо UTC, щоб уникнути багів з локальним часом
        timestamp = timestamp.replace(tzinfo=UTC)

    # повертаємо заповнений датаклас
    return SudoEntry(
        timestamp=timestamp,
        host=match["host"],
        user=match["user"],
        tty=match["tty"],
        pwd=match["pwd"],
        target_user=match["target_user"],
        command=match["command"],
    )


def iter_log_lines(path: Path) -> Iterator[tuple[int, str]]:
    """генератор: читає файл порядково (без завантаження всього в пам'ять)."""
    with path.open(encoding="utf-8") as handle:
        # enumerate додає номери рядків (починаючи з 1)
        for number, raw in enumerate(handle, start=1):
            line = raw.strip()
            if line:
                # yield перетворює функцію на генератор, вона віддає по одному рядку за раз (економить оперативку)
                yield number, line


def load_alert_commands(sources: Sequence[str] | None) -> list[str]:
    """збирає шаблони: кожен елемент — шлях до файлу або сам шаблон."""
    if not sources:
        return list(DEFAULT_ALERT_COMMANDS)
    patterns: list[str] = []
    for source in sources:
        path = Path(source)
        # якщо передали шлях до файлу, читаємо з нього
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                # ігноруємо порожні рядки і коментарі (які починаються з #)
                if line and not line.startswith("#"):
                    patterns.append(line)
        # інакше вважаємо, що передали саму команду напряму
        elif source.strip():
            patterns.append(source.strip())
    # dict.fromkeys() — спосіб видалити дублікати, зберігши початковий порядок
    return list(dict.fromkeys(patterns))


def compile_alert(pattern: str) -> re.Pattern[str]:
    """шаблон -> regex зі «словесними» межами.

    це потрібно, щоб `nc` не спрацьовував випадково всередині слова `sync`,
    а `dd` не збігався зі словом `add`.
    """
    # re.escape екранує спецсимволи, щоб вони сприймалися як звичайний текст
    body = r"\s+".join(re.escape(part) for part in pattern.split())
    # (?<!...) та (?!...) — це негативні перевірки (lookbehind/lookahead), які гарантують, що з боків немає інших літер
    return re.compile(rf"(?<![\w/.-]){body}(?![\w.-])")


def normalize_command(command: str) -> str:
    """`/usr/bin/nc -l` -> `nc -l` (відрізаємо повний шлях до програми для кращого пошуку)."""
    head, _, tail = command.partition(" ")
    return f"{PurePosixPath(head).name} {tail}".strip()


def find_matches(command: str, alerts: dict[str, re.Pattern[str]]) -> tuple[str, ...]:
    """шукає, чи є в команді щось із нашого списку заборонених шаблонів."""
    # перевіряємо і оригінальну команду, і нормалізовану (без шляхів)
    variants = (command, normalize_command(command))
    return tuple(
        pattern
        for pattern, regex in alerts.items()
        if any(regex.search(text) for text in variants)
    )


# аналіз
def analyze(log_path: Path, patterns: Sequence[str]) -> AuditResult:
    """головна функція, яка проходить по логах і збирає всю статистику."""
    alerts = {pattern: compile_alert(pattern) for pattern in patterns}
    result = AuditResult()

    # проходимося по кожному рядку через наш генератор
    for number, line in iter_log_lines(log_path):
        entry = parse_line(line)
        if entry is None:
            result.skipped += 1
            logger.warning("Line %d skipped (unrecognized format)", number)
            continue

        logger.debug("Line %d parsed: %s ran %s", number, entry.user, entry.command)
        result.total += 1
        # плюсуємо лічильник команд для конкретного користувача
        result.commands_per_user[entry.user] += 1

        if entry.is_root:
            result.root_count += 1

        # шукаємо найпершу і найостаннішу подію в часі
        if result.first_time is None or entry.timestamp < result.first_time:
            result.first_time = entry.timestamp
        if result.last_time is None or entry.timestamp > result.last_time:
            result.last_time = entry.timestamp

        # перевіряємо, чи є команда підозрілою
        matched = find_matches(entry.command, alerts)
        if matched:
            result.risky_per_user[entry.user] += 1
            result.findings.append(Finding(entry, matched))
            # логуємо з нашим кастомним рівнем ALERT_LEVEL
            logger.log(
                ALERT_LEVEL,
                "User '%s' executed: 'sudo %s' as %s on TTY=%s",
                entry.user,
                entry.command,
                entry.target_user,
                entry.tty,
            )
    return result


# звіт
def _iso(value: datetime | None) -> str | None:
    """допоміжна функція для безпечної конвертації дати в текст."""
    return value.isoformat() if value else None


def build_report(
    result: AuditResult, source: Path, patterns: Sequence[str]
) -> dict[str, Any]:
    """формує великий словник (dict), який потім перетвориться на json-файл."""
    return {
        "source_file": str(source),
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "alert_patterns": list(patterns),
        "summary": {
            "total_sudo_commands": result.total,
            "root_executions": result.root_count,
            "suspicious_commands": len(result.findings),
            "skipped_lines": result.skipped,
            "first_event": _iso(result.first_time),
            "last_event": _iso(result.last_time),
        },
        # .most_common() з Counter автоматично сортує дані від найбільшого до найменшого
        "commands_per_user": dict(result.commands_per_user.most_common()),
        "suspicious_per_user": dict(result.risky_per_user.most_common()),
        "suspicious_entries": [
            {
                "timestamp": item.entry.timestamp.isoformat(),
                "user": item.entry.user,
                "tty": item.entry.tty,
                "pwd": item.entry.pwd,
                "target_user": item.entry.target_user,
                "command": item.entry.command,
                "matched_patterns": list(item.matched),
            }
            for item in result.findings
        ],
    }


def write_report(report: dict[str, Any], path: Path) -> None:
    """створює папку, якщо її немає, і записує json на диск."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        # indent=2 робить json красивим, а ensure_ascii=False зберігає кирилицю
        json.dump(report, handle, ensure_ascii=False, indent=2)


def print_summary(result: AuditResult) -> None:
    print("\n=== Privileged Execution Summary ===")
    # :> або :, додають роздільники тисяч для великих чисел
    print(f"Total Sudo Commands : {result.total:,}")
    print(f"Root Executions     : {result.root_count:,}")
    print(f"Suspicious Commands : {len(result.findings):,}")
    print("\n=== Top Sudo Users ===")
    for rank, (user, count) in enumerate(
        result.commands_per_user.most_common(TOP_USERS), start=1
    ):
        risky = result.risky_per_user.get(user, 0)
        note = f" (High risk commands: {risky})" if risky else ""
        print(f"{rank}. {user} : {count} commands{note}")


# CLI
def add_arguments(parser: argparse.ArgumentParser) -> None:
    """налаштовує аргументи командного рядка (те, що ми передаємо через консоль)."""
    parser.add_argument(
        "--sudo-log",
        type=Path,  # argparse сам перетворить рядок на об'єкт Path
        default=DEFAULT_SUDO_LOG,
        help="path to the sudo log file (default: data/data_v15/sudo.log)",
    )
    parser.add_argument(
        "--alert-commands",
        nargs="+",  # дозволяє передавати кілька файлів або команд через пробіл
        metavar="PATTERN_OR_FILE",
        help="alert patterns and/or text files with one pattern per line "
        f"(default: {', '.join(DEFAULT_ALERT_COMMANDS)})",
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        help="JSON report path (default: sudo_audit_report.json next to the log)",
    )
    parser.add_argument(
        "--log-level",
        type=str.upper,  # автоматично робить літери великими, щоб не було помилок
        choices=LOG_LEVELS,  # обмежує можливі варіанти (не можна ввести щось випадкове)
        default="INFO",
        help="logging level (default: INFO)",
    )


def configure_logging(level_name: str) -> None:
    """реєструє наш новий рівень логування ALERT і налаштовує формат виводу."""
    logging.addLevelName(ALERT_LEVEL, "ALERT")
    logging.basicConfig(
        level=getattr(logging, level_name),
        format="[%(levelname)s] %(message)s",
        force=True,  # перезаписує попередні налаштування логера, якщо вони були
    )


def run(args: argparse.Namespace) -> int:
    """головна точка входу для логіки утиліти. повертає 0 при успіху, 1 при помилці."""
    configure_logging(args.log_level)
    sources = args.alert_commands

    # якщо юзер нічого не передав, але файл з папки за замовчуванням існує — беремо його
    if sources is None and DEFAULT_ALERT_FILE.is_file():
        sources = [str(DEFAULT_ALERT_FILE)]

    # якщо не вказано шлях збереження, кладемо json у ту саму папку, де лежить лог-файл
    out_path = args.out_json or args.sudo_log.with_name("sudo_audit_report.json")

    try:
        patterns = load_alert_commands(sources)
    except (OSError, UnicodeDecodeError) as exc:
        logger.error("Cannot read alert commands: %s", exc)
        return 1

    if not patterns:
        logger.error("No alert patterns provided")
        return 1

    logger.info("Parsing sudo usage logs from %s...", args.sudo_log)
    try:
        result = analyze(args.sudo_log, patterns)
    except (OSError, UnicodeDecodeError) as exc:
        logger.error("Cannot read sudo log: %s", exc)
        return 1

    logger.info("Processed %s privileged execution entries.", f"{result.total:,}")
    if result.total == 0:
        logger.warning("No valid sudo entries found in %s", args.sudo_log)

    print_summary(result)

    try:
        write_report(build_report(result, args.sudo_log, patterns), out_path)
    except OSError as exc:
        logger.error("Cannot write report: %s", exc)
        return 1

    logger.info("Privileged command audit saved to %s", out_path)
    return 0
