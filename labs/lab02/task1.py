from __future__ import annotations

import hashlib  # хешування паролів
import hmac  # безпечне порівняння хешів (compare_digest)
import os  # os.urandom — криптографічно стійкі випадкові байти для солі
import re  # регулярні вирази для перевірки email
from collections.abc import Iterable  # тип "щось, по чому можна пройтись циклом"
from dataclasses import dataclass  # декоратор для простих класів-даних
from datetime import UTC, datetime, timedelta  # робота з часом
from typing import Any, ClassVar  # Any — будь-який тип; ClassVar — змінна класу

PBKDF2_HASH_NAME = "sha256"  # внутрішня хеш-функція для PBKDF2
PBKDF2_ITERATIONS = 600_000  # чим більше, тим дорожче підбір пароля
SALT_SIZE_BYTES = 16  # довжина випадкової солі (16 байт = 128 біт)
SESSION_TIMEOUT_SEC = 900  # 15 хвилин

# Назви дій для журналу аудиту (щоб не робити друкарських помилок у рядках)
ACTION_LOGIN_SUCCESS = "login_success"
ACTION_LOGIN_FAILURE = "login_failure"
ACTION_LOGOUT = "logout"

# Локальна частина: літера + ще 2-63 символи (разом 3-64), далі @ і домен
# з принаймні однією крапкою.
# Розбір шаблону:
#   [A-Za-z]               — перший символ лише літера
#   [A-Za-z0-9_]{2,63}     — далі 2-63 літери/цифри/підкреслення
#   @                      — символ собаки
#   [A-Za-z0-9-]+          — перша частина домену (напр. "example")
#   (?:\.[A-Za-z0-9-]+)+   — одна або більше частин через крапку (напр. ".com")
EMAIL_PATTERN = re.compile(
    r"[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
)


def utc_now() -> datetime:
    """Поточний час UTC з часовим поясом (aware datetime)."""
    # єдина функція отримання часу: якщо треба буде підмінити час
    # (наприклад, у тестах), змінювати треба лише тут.
    return datetime.now(UTC)


class User:
    """Користувач із безпечним зберіганням пароля (PBKDF2 + сіль)."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "user",
        active: bool = True,
    ) -> None:
        # перевіряє, що ім'я — це непорожній рядок (strip прибирає пробіли
        # по краях, тому "   " теж вважається порожнім).
        if not isinstance(username, str) or not username.strip():
            raise ValueError("username must be a non-empty string")
        self.username = username
        self.role = role
        self.active = active  # чи активний акаунт (False = заблокований)
        # подвійне підкреслення -> name mangling: _User__password_hash
        # тобто ззовні напряму user.__password_hash не прочитати.
        # спочатку ставить порожні значення, справжні задасть set_password()

        self.__password_hash = (
            b""  # створює порожнє приватне поле для хешу пароля (в байтах)
        )
        self.__password_salt = b""  # створює порожнє приватне поле для солі (в байтах)
        self._email = ""  # одинарне підкреслення = "приватне за домовленістю"
        self.email = email  # викликає setter із валідацією
        self.set_password(password)  # генерує сіль і зберігає хеш

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        # staticmethod: не потребує self, це просто допоміжна функція.
        # перетворює пароль + сіль у хеш за алгоритмом PBKDF2-HMAC.
        # той самий пароль з тією самою сіллю завжди дає той самий результат.
        return hashlib.pbkdf2_hmac(
            PBKDF2_HASH_NAME, password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )

    @property
    def email(self) -> str:
        # Getter: дозволяє писати user.email, як звичайний атрибут.
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        # Setter: викликається при user.email = "...".
        # fullmatch вимагає, щоб ВЕСЬ рядок відповідав шаблону, а не його частина.
        if not isinstance(value, str) or EMAIL_PATTERN.fullmatch(value) is None:
            raise ValueError(f"invalid email: {value!r}")
        self._email = value

    def set_password(self, password: str) -> None:
        """генерує нову сіль і зберігає лише хеш пароля."""
        if not isinstance(password, str) or not password:
            raise ValueError("password must be a non-empty string")
        # нова випадкова сіль при кожній зміні пароля: однакові паролі
        # у різних користувачів будуть різні хеші.
        salt = os.urandom(SALT_SIZE_BYTES)
        self.__password_salt = salt
        self.__password_hash = self._derive_key(password, salt)
        # сам пароль ніде не зберігається — лише сіль і хеш.

    def check_password(self, password: str) -> bool:
        """порівнює хеші у сталий час (захист від timing-атак)."""
        if not isinstance(password, str):
            return False
        # хешуємо введений пароль з тією самою сіллю, що й збережений.
        candidate = self._derive_key(password, self.__password_salt)
        # compare_digest порівнює за однаковий час незалежно від того,
        # де саме хеші розходяться — це не дає зловмиснику вгадувати
        # хеш за часом відповіді.
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        # деактивація акаунта: дані лишаються, але вхід заборонений.
        self.active = False

    def __str__(self) -> str:
        # текстове представлення для print(user). Пароль/хеш не виводиться.
        # !r додає лапки навколо рядків (repr).
        return (
            f"User(username={self.username!r}, email={self.email!r}, "
            f"role={self.role!r}, active={self.active})"
        )


class Admin(User):
    """Адміністратор: користувач + набір дозволів."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        permissions: Iterable[str] | None = None,
        active: bool = True,
    ) -> None:
        # викликає конструктор батьківсього класу User; роль завжди "admin".
        super().__init__(username, email, password, role="admin", active=active)
        # нова множина для кожного об'єкта (не змінюваний аргумент за замовчуванням)
        # set — множина: дозволи не повторюються.
        self.permissions: set[str] = set()
        # `permissions or ()` — якщо передали None, перебираємо порожній кортеж.
        # кожен дозвіл додаємо через grant_permission, щоб спрацювала перевірка.
        for permission in permissions or ():
            self.grant_permission(permission)

    def grant_permission(self, permission: str) -> None:
        # видати дозвіл (з перевіркою, що це непорожній рядок).
        if not isinstance(permission, str) or not permission.strip():
            raise ValueError("permission must be a non-empty string")
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        # забрати дозвіл. discard (на відміну від remove) не кидає помилку,
        # якщо такого дозволу не було.
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        # перевірка: чи є в адміністратора такий дозвіл.
        return permission in self.permissions

    def __str__(self) -> str:
        # беремо рядок батьківського класу й додаємо список дозволів
        # (відсортований; якщо порожній — слово "none").
        perms = ", ".join(sorted(self.permissions)) or "none"
        return f"{super().__str__()} permissions=[{perms}]"


class Session:
    """Сеанс користувача з відстеженням останньої активності."""

    def __init__(self, ip: str, login_time: datetime | None = None) -> None:
        self.ip = ip  # IP-адреса, з якої виконано вхід
        # якщо час входу не передали — беремо поточний.
        self.login_time = login_time or utc_now()
        # на початку остання активність = момент входу.
        self.last_activity = self.login_time

    def touch(self) -> None:
        # оновити час останньої активності,
        # тобто продовжити сеанс.
        self.last_activity = utc_now()

    def is_active(self, timeout_sec: int) -> bool:
        # сеанс активний, якщо з останньої активності минуло менше
        # ніж timeout_sec секунд.
        if timeout_sec <= 0:
            raise ValueError("timeout_sec must be positive")
        idle = utc_now() - self.last_activity  # скільки часу "простою"
        return idle < timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
# frozen=True робить запис незмінним: після створення поля змінити не можна
# (для журналу аудиту це важливо — історію не можна відредагувати).
class AuditRecord:
    """Один запис аудиту: час (UTC), користувач, дія. Пароль не зберігається."""

    # dataclass сам створить __init__ за цими полями.
    timestamp: datetime
    username: str
    action: str

    def __str__(self) -> str:
        # формат: "2025-01-01T12:00:00+00:00 | taras_k | login_success"
        when = self.timestamp.isoformat(timespec="seconds")
        return f"{when} | {self.username} | {self.action}"


class AuditLog:
    """Журнал аудиту у пам'яті."""

    def __init__(self) -> None:
        # внутрішній список записів (одинарне підкреслення = не чіпати ззовні).
        self._records: list[AuditRecord] = []

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        # віддає копію у вигляді кортежу (незмінного), щоб зовнішній код
        # не міг змінити внутрішній список.
        return tuple(self._records)

    def add_log(self, username: str, action: str) -> AuditRecord:
        # створює запис із поточним часом, додає в журнал і повертає його.
        record = AuditRecord(utc_now(), username, action)
        self._records.append(record)
        return record

    def show_all(self) -> None:
        # виводить усі записи; якщо їх немає — повідомлення про порожній журнал.
        if not self._records:
            print("(журнал аудиту порожній)")
        for record in self._records:
            print(record)  # використовує AuditRecord.__str__


class UserAccount:
    """Обліковий запис: об'єднує користувача, сеанс і журнал аудиту."""

    # дозволені ключі для account[...] і очікувані типи значень.
    # хеш і сіль пароля сюди навмисно не входять.
    # ClassVar — це змінна класу (спільна для всіх об'єктів), а не атрибут екземпляра.
    # для session допустимо ще й None (сеансу немає).
    _KEY_TYPES: ClassVar[dict[str, tuple[type, ...]]] = {
        "user": (User,),
        "session": (Session, type(None)),
        "audit_log": (AuditLog,),
    }

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
        timeout_sec: int = SESSION_TIMEOUT_SEC,
    ) -> None:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec must be positive")
        self.user = user
        self.session = session  # None, доки користувач не увійшов
        # якщо журнал не передали — створюємо новий (is not None, а не `or`,
        # щоб порожній, але переданий журнал не підмінявся новим).
        self.audit_log = audit_log if audit_log is not None else AuditLog()
        self.timeout_sec = timeout_sec

    def login(self, username: str, password: str, ip: str) -> bool:
        # вхід успішний лише якщо одночасно: акаунт активний,
        # ім'я збігається і пароль правильний. `and` зупиняється на першій
        # хибній умові, тож пароль не перевіряється для неактивного акаунта.
        ok = (
            self.user.active
            and username == self.user.username
            and self.user.check_password(password)
        )
        if not ok:
            # невдалу спробу теж записуємо в аудит (важливо для безпеки).
            self.audit_log.add_log(username, ACTION_LOGIN_FAILURE)
            return False
        self.session = Session(ip)  # сеанс створюється лише після успіху
        self.session.touch()  # фіксуємо час активності
        self.audit_log.add_log(username, ACTION_LOGIN_SUCCESS)
        return True

    def is_authenticated(self) -> bool:
        """Лише читає стан: touch() тут не викликається (сеанс не подовжується)."""
        # не автентифікований, якщо сеансу немає або акаунт вимкнено.
        if self.session is None or not self.user.active:
            return False
        # інакше — залежить від того, чи не вийшов таймаут бездіяльності.
        return self.session.is_active(self.timeout_sec)

    def logout(self) -> bool:
        # якщо входу не було — виходити нема з чого.
        if self.session is None:
            return False
        self.session = None
        self.audit_log.add_log(self.user.username, ACTION_LOGOUT)
        return True

    #  __getitem__/__setitem__ дають доступ у стилі словника:
    # account["user"] та account["session"] = ...
    def __getitem__(self, key: str) -> Any:
        # дозволяємо читати лише ключі зі списку (хеш пароля сюди не потрапить).
        if key not in self._KEY_TYPES:
            raise KeyError(key)
        return getattr(self, key)  # getattr бере атрибут за його назвою-рядком

    def __setitem__(self, key: str, value: Any) -> None:
        # 1) ключ має бути дозволеним; 2) значення — правильного типу.
        if key not in self._KEY_TYPES:
            raise KeyError(key)
        if not isinstance(value, self._KEY_TYPES[key]):
            # формуємо читабельний текст помилки, напр. "Session | NoneType".
            expected = " | ".join(t.__name__ for t in self._KEY_TYPES[key])
            raise TypeError(f"{key!r} expects {expected}, got {type(value).__name__}")
        setattr(self, key, value)  # встановлюємо атрибут за назвою-рядком


# демонстрація (викликається з main.py, при імпорті не запускається)
def _section(title: str) -> None:
    # допоміжна функція для красивих заголовків (у demo() зараз не використовується).
    print(f"\n=== {title} ===")


def demo() -> None:
    """Сценарій демонстрації для команди `python -m labs.lab02.main demo`."""
    # Створюємо користувача й обліковий запис навколо нього.
    user = User("taras_k", "taras_k@example.com", "Str0ng_Pass!")
    account = UserAccount(user)

    print("1. Користувач")
    print(user)
    print("Пароль у відкритому вигляді не зберігається і не виводиться.")

    print("2. Вхід: невдалий і успішний")
    # Спершу неправильний пароль -> False, у журналі login_failure.
    print("Невірний пароль ->", account.login("taras_k", "wrong", "10.0.0.5"))
    print("Автентифікований?", account.is_authenticated())  # False
    # Потім правильний -> True, створюється сеанс.
    print("Вірний пароль   ->", account.login("taras_k", "Str0ng_Pass!", "10.0.0.5"))
    print("Автентифікований?", account.is_authenticated())  # True

    print("3. Зміна email із валідацією")
    user.email = "taras_kovalenko@corp.example.org"  # коректний email — приймається
    print("Новий email:", user.email)
    # Три некоректні варіанти: надто коротка локальна частина,
    # починається з цифри, домен без крапки. Усі мають викликати ValueError.
    for bad in ("ab@example.com", "1taras@example.com", "taras@localhost"):
        try:
            user.email = bad
        except ValueError as exc:
            print(f"Відхилено: {exc}")

    print("4. Права адміністратора")
    # Створюємо адміністратора з початковим дозволом "read".
    admin = Admin("olena_admin", "olena_admin@example.com", "Adm1n_Pass!", ["read"])
    admin.grant_permission("manage_users")
    admin.grant_permission("delete_logs")
    admin.revoke_permission("delete_logs")  # одразу забираємо
    print(admin)
    print("manage_users:", admin.has_permission("manage_users"))  # True
    print("delete_logs :", admin.has_permission("delete_logs"))  # False

    print("5. Завершення сеансу за таймаутом (симуляція)")
    # assert — перевірка для себе (і для підказок типів), що сеанс існує.
    assert account.session is not None
    # забираємо час останньої активності на 901 с,
    # ніби користувач нічого не робив понад 15 хвилин.
    account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    print("Минуло понад 900 с без активності.")
    print("Автентифікований?", account.is_authenticated())  # False

    print("6. Доступ через ключі account[...]")
    print("account['user'] ->", account["user"].username)
    # перевіряємо два випадки помилок:
    #   ("password_hash", None) — спроба ЧИТАТИ заборонений ключ -> KeyError
    #   ("session", "not a session") — ЗАПИС значення неправильного типу -> TypeError
    for key, value in (("password_hash", None), ("session", "not a session")):
        try:
            if value is None:
                account[key]  # виклик __getitem__
            else:
                account[key] = value  # виклик __setitem__
        except (KeyError, TypeError) as exc:
            print(f"{type(exc).__name__}: {exc}")

    print("7. Повторний вхід і вихід")
    account.login("taras_k", "Str0ng_Pass!", "10.0.0.5")  # новий сеанс
    print("Автентифікований?", account.is_authenticated())  # True
    account.logout()
    print("Після logout:", account.is_authenticated())  # False

    print("8. Журнал аудиту")
    # показуємо всі події: невдалий вхід, вхід, повторний вхід, вихід.
    account.audit_log.show_all()


if __name__ == "__main__":
    demo()
