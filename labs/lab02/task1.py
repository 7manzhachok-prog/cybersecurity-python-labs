"""Завдання 1: модель користувача, сеансу, аудиту та облікового запису."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
SESSION_TIMEOUT_SEC = 900

ACTION_LOGIN_SUCCESS = "login_success"
ACTION_LOGIN_FAILURE = "login_failure"
ACTION_LOGOUT = "logout"
ALLOWED_ACTIONS = frozenset({ACTION_LOGIN_SUCCESS, ACTION_LOGIN_FAILURE, ACTION_LOGOUT})

# Локальна частина: літера + ще 2..63 символи (разом 3-64), домен із крапкою.
EMAIL_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,63}@(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User:
    """Користувач із безпечним зберіганням пароля (PBKDF2-HMAC-SHA256 + сіль)."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str,
        password: str,
        active: bool = True,
    ) -> None:
        if not username:
            raise ValueError("username не може бути порожнім")
        self.username = username
        self.role = role
        self.active = active
        self._email = ""
        self.email = email  # проходить через валідацію в setter
        self.__password_hash = b""
        self.__password_salt = b""
        self.set_password(password)

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_RE.fullmatch(value):
            raise ValueError(f"Некоректний email: {value!r}")
        self._email = value

    @staticmethod
    def _derive(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )

    def set_password(self, password: str) -> None:
        if not isinstance(password, str) or not password:
            raise ValueError("Пароль має бути непорожнім рядком")
        self.__password_salt = os.urandom(SALT_SIZE)
        self.__password_hash = self._derive(password, self.__password_salt)

    def check_password(self, password: str) -> bool:
        if not isinstance(password, str):
            return False
        candidate = self._derive(password, self.__password_salt)
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        state = "active" if self.active else "inactive"
        return (
            f"User(username={self.username}, email={self.email}, "
            f"role={self.role}, {state})"
        )


class Admin(User):
    """Адміністратор: користувач (Is-A) з набором дозволів."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        permissions: Iterable[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username, email, "admin", password, active)
        self.permissions: set[str] = set(permissions or ())

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        perms = ", ".join(sorted(self.permissions)) or "none"
        return f"Admin({super().__str__()}, permissions=[{perms}])"


class Session:
    """Сеанс користувача; усі позначки часу — UTC з часовим поясом."""

    def __init__(self, ip: str) -> None:
        ipaddress.ip_address(ip)  # ValueError для некоректної адреси
        self.ip = ip
        self.login_time: datetime = _utcnow()
        self.last_activity: datetime = self.login_time

    def touch(self) -> None:
        self.last_activity = _utcnow()

    def is_active(self, timeout_sec: int, now: datetime | None = None) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути додатним")
        current = now or _utcnow()
        return current - self.last_activity <= timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
class AuditEntry:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал аудиту. Паролі в записи не потрапляють."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)

    def add_log(self, username: str, action: str) -> None:
        if action not in ALLOWED_ACTIONS:
            raise ValueError(f"Невідома дія аудиту: {action!r}")
        self._entries.append(AuditEntry(_utcnow(), username, action))

    def show_all(self) -> None:
        for entry in self._entries:
            stamp = entry.timestamp.isoformat(timespec="seconds")
            print(f"{stamp} | {entry.username:<12} | {entry.action}")


class UserAccount:
    """Композиція: обліковий запис складається з User, Session та AuditLog."""

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
    ) -> None:
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        ipaddress.ip_address(ip)  # відхиляємо некоректну IP до автентифікації
        password_ok = self.user.check_password(password)
        if not (self.user.active and username == self.user.username and password_ok):
            self.audit_log.add_log(username, ACTION_LOGIN_FAILURE)
            return False
        self.session = Session(ip)
        self.session.touch()
        self.audit_log.add_log(username, ACTION_LOGIN_SUCCESS)
        return True

    def is_authenticated(self) -> bool:
        return self.session is not None and self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> bool:
        if self.session is None:
            return False
        self.session = None
        self.audit_log.add_log(self.user.username, ACTION_LOGOUT)
        return True

    def __getitem__(self, key: str) -> Any:
        if key not in self._KEY_TYPES:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key not in self._KEY_TYPES:
            raise KeyError(key)
        if not isinstance(value, self._KEY_TYPES[key]):
            raise TypeError(f"Неправильний тип для {key!r}: {type(value).__name__}")
        setattr(self, key, value)


def run_demo() -> None:
    """Демонстраційний сценарій (викликається з main.py demo)."""
    print("=== 1. Створення облікового запису ===")
    user = User("alice", "alice_01@example.com", "user", "S3cret!pass")
    account = UserAccount(user)
    print(account["user"])

    print("\n=== 2. Невдалий і успішний вхід ===")
    print("Невірний пароль :", account.login("alice", "wrong", "192.168.1.10"))
    print("Вірний пароль   :", account.login("alice", "S3cret!pass", "192.168.1.10"))
    print("Автентифіковано :", account.is_authenticated())

    print("\n=== 3. Зміна email із валідацією ===")
    user.email = "alice_new@corp.ua"
    print("Новий email:", user.email)
    for bad in ("1abc@example.com", "ab@example.com", "alice@localhost"):
        try:
            user.email = bad
        except ValueError as exc:
            print("ValueError:", exc)

    print("\n=== 4. Права адміністратора ===")
    admin = Admin("root_admin", "root_admin@corp.ua", "Adm1n!pass")
    admin.grant_permission("read_logs")
    admin.grant_permission("manage_users")
    admin.revoke_permission("read_logs")
    print(admin)
    print("manage_users:", admin.has_permission("manage_users"))
    print("read_logs   :", admin.has_permission("read_logs"))

    print("\n=== 5. Завершення сеансу за таймаутом ===")
    account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    print("Автентифіковано після таймауту:", account.is_authenticated())

    print("\n=== 6. Вихід із системи ===")
    print("logout:", account.logout())

    print("\n=== 7. Захист ключів UserAccount ===")
    for key in ("password_hash", "session"):
        try:
            account[key] = "text"
        except (KeyError, TypeError) as exc:
            print(f"{type(exc).__name__}: {exc}")

    print("\n=== 8. Записи AuditLog ===")
    account.audit_log.show_all()


if __name__ == "__main__":
    run_demo()
