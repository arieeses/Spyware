"""认证: 密码哈希(PBKDF2)、会话、密码重置。纯标准库。"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

SESSION_DAYS = 7
RESET_MINUTES = 30
_ITER = 200_000


def _hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), _ITER).hex()


def hash_password(password: str):
    salt = secrets.token_hex(16)
    return salt, _hash(password, salt)


def verify_password(password: str, salt: str, expected: str) -> bool:
    return hmac.compare_digest(_hash(password, salt), expected)


def create_admin(store, username: str, password: str, email: str | None = None) -> None:
    salt, h = hash_password(password)
    store.create_admin(username, email, salt, h)


def authenticate(store, login: str, password: str):
    a = store.get_admin_by_name(login) or store.get_admin_by_email(login)
    if a and verify_password(password, a["salt"], a["pwd_hash"]):
        return a
    return None


def new_session(store, admin_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.utcnow() + timedelta(days=SESSION_DAYS)).isoformat()
    store.create_session(token, admin_id, expires)
    return token


def session_admin(store, token: str):
    if not token:
        return None
    s = store.get_session(token)
    if not s:
        return None
    try:
        if datetime.fromisoformat(s["expires"]) < datetime.utcnow():
            store.delete_session(token)
            return None
    except (ValueError, TypeError):
        return None
    return store.get_admin_by_id(s["admin_id"])


def new_reset(store, admin_id: int) -> str:
    token = secrets.token_urlsafe(24)
    expires = (datetime.utcnow() + timedelta(minutes=RESET_MINUTES)).isoformat()
    store.create_reset(token, admin_id, expires)
    return token


def consume_reset(store, token: str, new_password: str) -> bool:
    r = store.get_reset(token)
    if not r or r["used"]:
        return False
    try:
        if datetime.fromisoformat(r["expires"]) < datetime.utcnow():
            return False
    except (ValueError, TypeError):
        return False
    salt, h = hash_password(new_password)
    store.update_admin_password(r["admin_id"], salt, h)
    store.mark_reset_used(token)
    return True
