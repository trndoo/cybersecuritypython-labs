import csv
import hashlib
import json
import os
from datetime import datetime
from functools import wraps

VARIANT_NUMBER = 15
HASH_ALGORITHM = "sha1"
MIN_PASSWORD_LENGTH = 9

PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)  # "00015"

# шляхи до файлів бази даних та журналу подій.
DATA_DIR = os.path.join("labs", "lab01", "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")

users_to_register = (
    ("q_researcher", "Qu4ntumSecure!"),
    ("pq_dev01", "P0stQuantum#Dev"),
    ("net_sec_eng", "N3tworkGuard@2023"),
    ("crypto_int", "Cr9ptoIntern!ship"),
    ("sim_operator", "S1mulationRun#"),
    ("edu_admin", "EduAdmin@Portal1"),
    ("research_lead", "R3searchLead#Sec"),
    ("hybrid_dev", "Hybr1dSystem@Dev"),
    ("key_manager", "K3yManager#2023"),
    ("tutor_bot", "Tut0rBot@Secure1"),
    ("user_33", "fhkeeityyyyyYYY774!")
)


class ValidationError(Exception):
    """власний виняток: виникає, якщо пароль не відповідає вимогам довжини."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """згенерувати шістнадцятковий хеш від конкатенації пароля та солі."""

    if not password or not salt:
        raise ValueError("Password and salt must not be empty")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
        )

    # конкатенація пароля та солі, потім хешування обраним алгоритмом.
    combined = (password + salt).encode("utf-8")
    hash_object = hashlib.new(HASH_ALGORITHM, combined)
    return hash_object.hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    # створюється запис користувача. 
    # хешування виконується з персональною сіллю.

    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list: tuple) -> None:
    # хахешувати список користувачів і записати їх у CSV-файл.
    # папка data/ створюється автоматично, якщо її ще немає.
    # exist_ok=True означає: якщо папка вже є, не викидати помилку.

    os.makedirs(DATA_DIR, exist_ok=True)

    with open(USERS_CSV_PATH, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        for username, password in users_list:
            login, hash_value = create_user(username, password)
            writer.writerow([login, hash_value])

    print(f"Створено {len(users_list)} користувачів у файлі {USERS_CSV_PATH}")


def read_users_db() -> list:
    # прочитати CSV-файл користувачів у список пар.
    users_db = []
    with open(USERS_CSV_PATH, mode="r", newline="", encoding="utf-8") as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            users_db.append(row)
    return users_db


def print_users_db(users_db: list) -> None:
    # вивести базу користувачів у вигляді таблиці.
    print(f"{'Логін':<20}{'Хеш пароля':<45}")
    print("-" * 65)
    for login, hash_value in users_db:
        print(f"{login:<20}{hash_value:<45}")
    print()


def log_event(func):
    """декоратор, що логує кожен виклик функції входу у JSON-файл.
    логування винесено в окремий декоратор (а не всередину login())"""
    # для перевірки автентифікації. 

    @wraps(func)
    def wrapper(*args, **kwargs):
        # username завжди передається першим позиційним аргументом
        # у функції login(username, password).
        username = args[0] if args else kwargs.get("username", "unknown")

        try:
            result = func(*args, **kwargs)
            status = "success" if result else "failure"
        except (ValueError, ValidationError):
            # навіть якщо login() завершився винятком, все одно
            # фіксую невдалу спробу входу в журналі.
            status = "failure"
            raise
        finally:
            # формат запису журналу відповідає методичці:
            # event, user, result, timestamp, args, kwargs.
            log_entry = {
                "event": "login",
                "user": username,
                "result": status if "status" in locals() else "failure",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": [],
                "kwargs": {},
            }
            _append_log_entry(log_entry)

        return result

    return wrapper


def _append_log_entry(entry: dict) -> None:
    """додати один запис у JSON-файл журналу подій.
       файл зберігається як список записів. якщо файл ще не існує
       або пошкоджений, створюємо новий список."""
    os.makedirs(DATA_DIR, exist_ok=True)

    try:
        with open(LOG_JSON_PATH, mode="r", encoding="utf-8") as log_file:
            events = json.load(log_file)
    except (FileNotFoundError, json.JSONDecodeError):
        events = []

    events.append(entry)

    with open(LOG_JSON_PATH, mode="w", encoding="utf-8") as log_file:
        json.dump(events, log_file, ensure_ascii=False, indent=2)


@log_event
def login(username: str, password: str) -> bool:
    # перевірка автентифікації користувача за логіном і паролем.

    if not username or not password:
        raise ValueError("Username and password must not be empty")

    users_db = read_users_db()
    password_hash = generate_hash(password, PERSONAL_SALT)

    for login_name, stored_hash in users_db:
        if login_name == username and stored_hash == password_hash:
            return True

    return False


def main() -> None:
    # головна функція. 
    try:
        # 1. реєстрація користувачів та запис у CSV.
        create_users(users_to_register)

        # 2. зчитування бази даних та виведення у вигляді таблиці.
        users_db = read_users_db()
        print_users_db(users_db)

        # 3. демонстрація автентифікації: одна вдала і одна невдала спроба.
        correct_username, correct_password = users_to_register[0]
        print(f"Спроба входу '{correct_username}' з правильним паролем:")
        print(login(correct_username, correct_password))

        print(f"Спроба входу '{correct_username}' з неправильним паролем:")
        print(login(correct_username, "wrongPassword123"))

    except FileNotFoundError:
        print("Помилка: файл не знайдено.")
    except PermissionError:
        print("Помилка: недостатньо прав доступу до файлу.")
    except IOError:
        print("Помилка вводу/виводу під час роботи з файлом.")
    except ValidationError as error:
        print(f"Помилка валідації пароля: {error}")
    except ValueError as error:
        print(f"Некоректні вхідні дані: {error}")


if __name__ == "__main__":
    main()