import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "password123",
    "Qwerty!2023",
    "admin_root",
    "MyP@ssw0rd2026",
    "12345678",
    "SecurePass!15",
    "test_user",
    "P@ssw0rd15_test",
    "welcome2026",
    "StrongP@ss15!",
]

criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = ["password", "123456", "admin", "test", "welcome", "qwerty"]


def check_password(password, all_passwords):
    # перевіряємо чи пароль заборонений або занадто короткий
    if password in forbidden_passwords or len(password) < criteria["min_length"]:
        return "заборонений"

    # для перевірки типів символів
    has_digit = False
    has_upper = False
    has_lower = False
    has_special = False

    # посимвольно перевірка паролю
    for char in password:
        if char.isdigit():
            has_digit = True
        elif char.isupper():
            has_upper = True
        elif char.islower():
            has_lower = True
        else:
            has_special = True

    # кількість виконаних критеріїв
    criteria_count = 0
    if has_digit:
        criteria_count += 1
    if has_upper:
        criteria_count += 1
    if has_lower:
        criteria_count += 1
    if has_special:
        criteria_count += 1

    # Чи виконано всі 4 критерії
    all_met = has_digit and has_upper and has_lower and has_special

    # оцінка надійності за вимогами
    if all_met:
        # дуже сильний: 
        if len(password) >= criteria["min_length"] + 4 and all_passwords.count(password) == 1:
            return "дуже сильний"
        else:
            return "сильний"
    elif criteria_count >= 2:
        return "середній"
    else:
        return "слабкий"

print("Студент:", STUDENT_NAME)
print("Група:", GROUP_NAME)
print("Варіант:", VARIANT_NUMBER)
print("-" * 40)

# копія списку та 3 випадкові дублікати
extended_passwords = passwords.copy()
for _ in range(3):
    random_index = random.randint(0, len(passwords) - 1)
    random_password = passwords[random_index]
    extended_passwords.append(random_password)

# результат
print("Пароль                 | Оцінка")
print("-" * 40)
for pwd in extended_passwords:
    rating = check_password(pwd, extended_passwords)
    spaces = " " * (22 - len(pwd))
    print(pwd + spaces + "| " + rating)