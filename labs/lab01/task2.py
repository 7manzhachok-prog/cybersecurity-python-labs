import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

users = {
    "sysadmin02": {
        "role": "system_admin",
        "clearance": 4,
        "department": "Infrastructure",
        "active": True,
    },
    "analyst234": {
        "role": "security_analyst",
        "clearance": 3,
        "department": "SOC",
        "active": True,
    },
    "developer567": {
        "role": "developer",
        "clearance": 2,
        "department": "Development",
        "active": True,
    },
    "intern890": {"role": "intern", "clearance": 1, "department": "HR", "active": True},
    "external123": {
        "role": "external",
        "clearance": 1,
        "department": "Vendor",
        "active": False,
    },
}

resources = [
    ("prod_database", 4),
    ("dev_environment", 2),
    ("documentation", 1),
    ("source_code", 3),
    ("server_configs", 4),
    ("test_data", 2),
    ("compliance_docs", 3),
    ("system_logs", 4),
    ("project_files", 2),
    ("public_wiki", 1),
]

security_levels = ("Open", "Internal", "Restricted", "Top Secret")
blocked_users = {"external123", "old_account", "test_user"}


def check_access(username, resource_name, resource_level):
    if username not in users:
        return "DENY (User not found)"

    if username in blocked_users:
        return "DENY (User is blocked)"

    user_info = users[username]
    if not user_info["active"]:
        return "DENY (Account inactive)"

    user_clearance = user_info["clearance"]
    if user_clearance >= resource_level:
        return "ALLOW"
    else:
        return "DENY (Insufficient clearance)"


def run():
    print("список ресурсів")
    for res_name, res_level in resources:
        level_name = security_levels[res_level - 1]
        print(f"Ресурс: {res_name:<16} | Рівень безпеки: {level_name}")
    print("\n")

    print("результати перевірки доступу")

    users_to_test = list(users.keys()) + ["unknown_hacker"]

    for user in users_to_test:
        for res_name, res_level in resources:
            result = check_access(user, res_name, res_level)
            print(f"user=[{user}] resource=[{res_name}] -> {result}")
        print("-" * 50)


if __name__ == "__main__":
    run()
