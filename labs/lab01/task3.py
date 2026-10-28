import csv
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from functools import wraps

current_folder = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_folder, "../../"))
sys.path.append(project_root)

try:
    from shared.student import VARIANT_NUMBER
except ImportError:
    VARIANT_NUMBER = 2

data_folder = os.path.join(current_folder, "labs", "lab01", "data")
os.makedirs(data_folder, exist_ok=True)
csv_path = os.path.join(data_folder, "users.csv")
log_path = os.path.join(data_folder, "log.json")

users_db = []


class ValidationError(Exception):
    pass


def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль або сіль порожні!")

    if len(password) < 10:
        raise ValidationError("Пароль закороткий! Треба мінімум 10 символів.")

    text = password + salt
    return hashlib.sha3_224(text.encode("utf-8")).hexdigest()


personal_salt = str(VARIANT_NUMBER).zfill(5)


users_to_register = (
    ("admin", "SuperAdmin123"),
    ("user1", "12345"),
    ("guest", ""),
    ("student", "MySecretPass2026"),
    ("test", "testpass"),
    ("manager", "ManagerSecure99"),
    ("hacker", "HackTheBox24"),
    ("bot", "bot"),
    ("dev", "DevOps2026Lviv"),
    ("sysadmin", "RootAdminSys"),
)


def create_user(username, password):
    hash_val = generate_hash(password, personal_salt)
    return (username, hash_val)


def create_users(users_list):
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["login", "hash_password"])

        for username, password in users_list:
            try:
                user_record = create_user(username, password)
                writer.writerow([user_record[0], user_record[1]])
                print(f"Користувача '{username}' успішно зареєстровано.")
            except (ValueError, ValidationError) as e:
                print(f"Помилка реєстрації '{username}': {e}")
    print(f"\nБазу даних збережено: {csv_path}\n")


def load_users_db():
    users_db.clear()

    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)

            print(f"{'Логін':<15} | {'Хеш пароля'}")
            print("-" * 75)
            for row in reader:
                if len(row) == 2:
                    users_db.append({"username": row[0], "hash": row[1]})
                    print(f"{row[0]:<15} | {row[1]}")
    except FileNotFoundError:
        print(f"Файл бази даних не знайдено: {csv_path}")
        return
    except PermissionError as e:
        print(f"Помилка: Немає прав для доступу до файлу: {e}")
    except OSError as e:
        print(f"Помилка читання бази даних: {e}")
        return
    print("\n")


def log_event(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "unknown")
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        result_status = "failure"

        try:
            result = func(*args, **kwargs)
            if result:
                result_status = "success"
            return result
        except Exception:
            result_status = "error"
            raise
        finally:
            log_entry = {
                "event": func.__name__,
                "user": username,
                "result": result_status,
                "timestamp": timestamp,
            }

            logs = []
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    try:
                        logs = json.load(f)
                    except json.JSONDecodeError:
                        logs = []
            except FileNotFoundError:
                logs = []

            for entry in logs:
                if isinstance(entry, dict) and entry.get("event") == "login":
                    entry.pop("args", None)
                    entry.pop("kwargs", None)

            logs.append(log_entry)

            try:
                with open(log_path, "w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4, ensure_ascii=False)
            except OSError as e:
                print(f"Помилка запису логів: {e}")
            except PermissionError as e:
                print(f"Помилка: Немає прав для доступу до файлу: {e}")

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    try:
        if not username or not password:
            raise ValueError("Логін або пароль порожні!")

        stored_hash = None
        for user in users_db:
            if user["username"] == username:
                stored_hash = user["hash"]
                break

        if stored_hash is None:
            return False

        entered_hash = generate_hash(password, personal_salt)
        return entered_hash == stored_hash
    except ValidationError:
        return False


def main():
    print(f"=== Сіль для хешування: {personal_salt} ===\n")

    try:
        create_users(users_to_register)

        load_users_db()

        print("=== ТЕСТУВАННЯ АВТОРИЗАЦІЇ ===")

        test_cases = [
            ("admin", "SuperAdmin123"),
            ("admin", "WrongPassword"),
            ("student", "MySecretPass2026"),
            ("unknown", "Pass1234567"),
            ("guest", ""),
        ]

        for u, p in test_cases:
            try:
                status = login(u, p)
                print(f"Спроба входу [{u}]: {'Дозволено' if status else 'Відхилено'}")
            except ValueError as e:
                print(f"Спроба входу [{u}]: Помилка - {e}")
            except ValidationError as e:
                print(f"Спроба входу [{u}]: Помилка - {e}")

        print(f"\nПеревірте файл логів за адресою: {log_path}")

    except FileNotFoundError as e:
        print(f"Помилка: Файл або директорію не знайдено: {e}")

    except OSError as e:
        print(f"Помилка вводу/виводу при роботі з файлами: {e}")


if __name__ == "__main__":
    main()