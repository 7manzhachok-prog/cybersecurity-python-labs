import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "Hello123!",
    "simple",
    "CompL3x@Pass",
    "password",
    "Str0ng#2023",
    "weak",
    "MySecur3!",
    "12345",
    "Advanced@1",
    "basic",
]
criteria = {
    "min_length": 10,
    "require_lower": True,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
forbidden_passwords = {"password", "simple", "weak", "basic", "12345", "hello"}


def analyze_password(pwd, all_passwords, crit, forbidden):
    min_len = crit["min_length"]

    if pwd.lower() in forbidden or len(pwd) < min_len:
        return "Заборонений"

    checks = {
        "require_lower": any(char.islower() for char in pwd),
        "require_upper": any(char.isupper() for char in pwd),
        "require_digits": any(char.isdigit() for char in pwd),
        "require_special": any(not char.isalnum() for char in pwd),
    }
    required_criteria = [key for key in checks if crit.get(key, False)]
    criteria_met_count = sum(checks[key] for key in required_criteria)
    required_count = len(required_criteria)
    meets_all_criteria = criteria_met_count == required_count

    if meets_all_criteria:
        is_unique = all_passwords.count(pwd) == 1
        if len(pwd) >= min_len + 4 and is_unique:
            return "Дуже сильний"
        return "Сильний"

    if required_count and criteria_met_count >= (required_count + 1) // 2:
        return "Середній"

    if criteria_met_count >= 1:
        return "Слабкий"

    return "Невизначений"


def run():
    print(f"Студент: {STUDENT_NAME} | Варіант: {VARIANT_NUMBER}\n")
    print(f"Початкова кількість паролів: {len(passwords)}")

    random_indices = [random.randint(0, len(passwords) - 1) for _ in range(3)]
    for idx in random_indices:
        passwords.append(passwords[idx])

    print(f"Кількість паролів після додавання дублікатів: {len(passwords)}\n")

    print(f"{'Пароль':<20} | {'Статус надійності'}")
    print("-" * 45)

    for pwd in passwords:
        status = analyze_password(pwd, passwords, criteria, forbidden_passwords)
        print(f"{pwd:<20} | {status}")


if __name__ == "__main__":
    run()
