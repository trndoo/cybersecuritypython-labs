# Лабораторна робота №2 — Консольні утиліти для задач кібербезпеки

**Варіант 15:** Аудитор логів використання привілейованих команд (Sudo / Privileged Access).

## Встановлення
Потрібен Python 3.11+ (використовується `datetime.UTC`).

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt  # ruff
```

## Структура
```
labs/lab02/
├── main.py      # команди demo та analyze
├── task1.py     # User, Admin, Session, AuditLog, UserAccount
├── task2.py     # аудитор sudo.log (варіант 15)
└── data/data_v15/
    ├── sudo.log             # журнал sudo (вхід)
    └── alert_commands.txt   # небезпечні команди, по одній на рядок (вхід)
```
Усі команди виконуються з кореня репозиторію.

## Завдання 1 — демонстрація ООП
```bash
python -m labs.lab02.main demo
```

## Завдання 2 — аналіз sudo.log
```bash
python -m labs.lab02.main analyze \
  --sudo-log labs/lab02/data/data_v15/sudo.log \
  --alert-commands labs/lab02/data/data_v15/alert_commands.txt \
  --out-json labs/lab02/data/data_v15/sudo_audit_report.json
```

### Параметри `analyze`
| Параметр | Опис |
|---|---|
| `--sudo-log` | **обов'язковий**, шлях до журналу sudo |
| `--alert-commands` | шаблони та/або файли з шаблонами (кілька значень через пробіл). Якщо значення — існуючий файл, шаблони читаються з нього (порожні рядки та `#` ігноруються); інакше значення вважається шаблоном. За замовчуванням: `chmod 777, nc, nmap, dd, /etc/shadow` |
| `--out-json` | шлях до JSON-звіту (за замовчуванням `sudo_audit_report.json` поруч із журналом) |
| `--log-level` | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` (за замовчуванням `INFO`) |

Приклад із шаблонами в командному рядку: `--alert-commands nc "chmod 777" /etc/shadow`.

### Формат рядка журналу
```
2026-09-27T09:20:00+03:00 host01 sudo: carol : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/chmod 777 /srv/share
```

### Поведінка при помилках
- файл журналу/шаблонів відсутній або нечитний → `[ERROR]`, код виходу `1`, без traceback;
- порожній список шаблонів → `[ERROR]`, код `1`;
- рядок невідомого формату → `[WARNING]`, рядок пропускається, лічильник `skipped_lines` у звіті;
- не вдалося записати звіт → `[ERROR]`, код `1`;
- неправильне значення `--log-level` або відсутній `--sudo-log` → помилка `argparse` (код `2`).

Підозрілі команди логуються рівнем `[ALERT]` (35, між WARNING і ERROR).

## Перевірка якості коду
```bash
ruff check .
ruff format --check .
```
