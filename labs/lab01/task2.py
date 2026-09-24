users = {
    "quantum_researcher": {
        "role": "quantum_security",
        "clearance": 4,
        "department": "Quantum Research",
        "active": True,
    },
    "post_quantum_dev": {
        "role": "pq_cryptographer",
        "clearance": 4,
        "department": "Post-Quantum",
        "active": True,
    },
    "network_security": {
        "role": "network_security",
        "clearance": 3,
        "department": "Network Security",
        "active": True,
    },
    "crypto_intern": {
        "role": "crypto_intern",
        "clearance": 1,
        "department": "Internship",
        "active": True,
    },
    "quantum_sim": {
        "role": "simulator",
        "clearance": 2,
        "department": "Simulation",
        "active": False,
    },
}

resources = [
    ("quantum_algorithms", 4),
    ("pq_implementations", 4),
    ("network_protocols", 3),
    ("learning_materials", 1),
    ("quantum_keys", 4),
    ("educational_content", 1),
    ("hybrid_systems", 3),
    ("quantum_computers", 4),
    ("crypto_libraries", 2),
    ("tutorials", 1),
]

security_levels = ("Educational", "Research", "Classified Research", "Quantum Secure")

blocked_users = {"quantum_sim", "quantum_attack", "algorithm_theft"}


def get_security_level_name(level: int) -> str:
    """перетворює числовий рівень допуску (1-4) у його словесну назву."""
    # рівні починаються з 1, а індексація списків/кортежів з 0, ми віднімаємо 1.
    return security_levels[level - 1]

def print_resources() -> None:
    """виводить у консоль загальний список усіх ресурсів та їхній текстовий рівень безпеки."""
    print("Список ресурсів системи")
    for resource_name, level in resources:
        level_name = get_security_level_name(level)
        print(f"{resource_name} -> рівень безпеки: {level_name}")
    print()


def check_access(username: str, resource_name: str, required_level: int) -> tuple[str, str]:
    
    # 1. Перевіряємо існування користувача в словнику users.
    #    метод .get() безпечніший за users[username], бо не викликає KeyError, якщо ключа немає — просто повертає None.
    user_data = users.get(username)
    if user_data is None:
        return "DENY", "User not found"

    # 2. Перевіряємо, чи користувач у списку заблокованих.
    if username in blocked_users:
        return "DENY", "User is blocked"

    # 3. Перевіряємо активності облікового запису.
    if not user_data["active"]:
        return "DENY", "Account inactive"

    # 4. Порівняння рівня допуску користувача з рівнем безпеки ресурсу.
    if user_data["clearance"] >= required_level:
        return "ALLOW", ""
    return "DENY", "Insufficient clearance"


def run_access_checks() -> None:
    print("Результати перевірки доступу")
    for username in users:
        for resource_name, required_level in resources:
            decision, reason = check_access(username, resource_name, required_level)
            if decision == "ALLOW":
                print(f"user={username} resource={resource_name} -> ALLOW")
            else:
                print(f"user={username} resource={resource_name} -> DENY ({reason})")


def main() -> None:
    #головна функція: запускає весь сценарій завдання
    print_resources()
    run_access_checks()


if __name__ == "__main__":
    main()