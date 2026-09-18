import csv
from datetime import datetime
import functools
import hashlib
import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

HASH_ALG = "sha1"
MIN_PASS_LEN = 9
SALT = "00015"

# шляхи до папки data та файлів
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_FILE = os.path.join(DATA_DIR, "users.csv")
LOG_FILE = os.path.join(DATA_DIR, "log.json")

# клас помилки для перевірки довжини пароля
class ValidationError(Exception):
    pass

# декоратор для автоматичного запису спроб входу в log.json
def log_event(func):
    @functools.wraps(func)
    def wrapper(username, password):
        result_status = "failure"
        success = False

        try:
            success = func(username, password)
            if success:
                result_status = "success"
        except Exception:
            result_status = "failure"
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            os.makedirs(DATA_DIR, exist_ok=True)

            logs = []
            if os.path.exists(LOG_FILE):
                try:
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except Exception:
                    logs = []

            logs.append(log_entry)
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)

        return success

    return wrapper

# генерація SHA1 хешу
def generate_hash(password, salt=SALT):
    if len(password) < MIN_PASS_LEN:
        raise ValidationError("Пароль закороткий! Мінімум символів: " + str(MIN_PASS_LEN))

    # додаємо сіль і обчислюємо SHA1 хеш
    data_to_hash = (password + salt).encode("utf-8")
    hasher = hashlib.sha1(data_to_hash)
    return hasher.hexdigest()

# запис користувачів у CSV
def create_users_db(users_list):
    os.makedirs(DATA_DIR, exist_ok=True)

    rows_to_save = []
    for username, password in users_list:
        try:
            pwd_hash = generate_hash(password)
            rows_to_save.append([username, pwd_hash])
        except ValidationError as e:
            print("Не вдалося створити користувача", username, ":", e)

    with open(USERS_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "password_hash"])
        writer.writerows(rows_to_save)

# читання баз користувачів з CSV
def read_users_db():
    users_db = {}
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None) 
            for row in reader:
                if row:
                    users_db[row[0]] = row[1]
    return users_db

# авторизація користувача з логуванням
@log_event
def login(username, password):
    db = read_users_db()

    if username not in db:
        return False

    try:
        input_hash = generate_hash(password)
        if input_hash == db[username]:
            return True
    except ValidationError:
        return False

    return False

def main():
    print("Студент:", STUDENT_NAME, "| Варіант:", VARIANT_NUMBER)

    users_to_register = [
        ("alice15", "SuperP@ssw0rd123"),  # довжина 16 (проходить)
        ("bob15", "SecurePass123!"),      # довжина 14 (проходить)
        ("charlie15", "Short1!"),         # довжина 7 (викличе ValidationError, бо < 9)
    ]

    print("\n1. Створення бази користувачів u CSV (алгоритм SHA1)...")
    create_users_db(users_to_register)

    print("\n2. Перевірка входу:")

    # спроба 1: правильний пароль
    res1 = login("alice15", "SuperP@ssw0rd123")
    print("Вхід alice15 (вірно):", res1)

    # спроба 2: неправильний пароль
    res2 = login("alice15", "WrongPassword123!")
    print("Вхід alice15 (невірно):", res2)


if __name__ == "__main__":
    main()