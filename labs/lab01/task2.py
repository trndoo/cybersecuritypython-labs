import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import VARIANT_NUMBER

users = {
    "admin15": {"role": "administrator", "clearance": 4, "department": "IT", "active": True},
    "analyst15": {"role": "analyst", "clearance": 2, "department": "Security", "active": True},
    "guest15": {"role": "guest", "clearance": 1, "department": "External", "active": True},
    "manager15": {"role": "manager", "clearance": 3, "department": "Operations", "active": True},
    "blocked15": {"role": "contractor", "clearance": 1, "department": "External", "active": False},
}

resources = [
    ("database_backup", 4),
    ("user_logs", 2),
    ("public_docs", 1),
    ("financial_reports", 3),
    ("system_config", 4),
    ("training_materials", 1),
    ("security_policies", 3),
    ("audit_logs", 4),
    ("employee_data", 3),
    ("temp_files", 1),
]

security_levels = ("Public", "Internal", "Confidential", "Secret")
blocked_users = {"blocked15", "temp_user", "suspended_acc"}


def check_access(username, resource):
    res_name = resource[0]
    res_level = resource[1]

    # чи існує користувач у системі
    if username not in users:
        return "DENY", "Користувача не знайдено"

    # чи заблокований користувач
    if username in blocked_users:
        return "DENY", "Користувач заблокований"

    # чи активний акаунт
    user_info = users[username]
    if user_info["active"] == False:
        return "DENY", "Акаунт неактивний"

    # чи рівень допуску користувача >= рівню ресурсу
    user_clearance = user_info["clearance"]
    if user_clearance >= res_level:
        return "ALLOW", "Доступ дозволено"
    else:
        return "DENY", "Недостатній рівень допуску"

print(" СПИСОК РЕСУРСІВ СИСТЕМИ (Варіант", VARIANT_NUMBER, ") ")
for item in resources:
    res_name = item[0]
    res_level_num = item[1]

    # перетворюємо число (1-4) на текст ("Public" - "Secret")
    # віднімаємо 1, бо індекси починаються з 0 (1-1=0 -> Public)
    level_text = security_levels[res_level_num - 1]

    print("Ресурс:", res_name, "| Рівень безпеки:", level_text)

print("\n ПЕРЕВІРКА ДОСТУПУ КОРИСТУВАЧІВ ")

# список користувачів для перевірки (неіснуючого для тесту)
test_users = ["admin15", "analyst15", "blocked15", "unknown_user"]

for username in test_users:
    print("\n Користувач:", username)
    for res in resources:
        status, reason = check_access(username, res)
        res_name = res[0]
        print("  Ресурс:", res_name, "-> Статус:", status, "(Причина:", reason + ")")