import hashlib
import hmac
import secrets
import time

from fastapi import HTTPException, Request


COOKIE = "safety_session"


def password_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def check_password(password: str, stored: str) -> bool:
    _, salt, expected = stored.split("$")
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000).hex()
    return hmac.compare_digest(actual, expected)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def session_user(db, token: str | None) -> dict | None:
    if not token:
        return None
    return db.one(
        "SELECT users.id, username, role FROM users JOIN sessions ON users.id=sessions.user_id "
        "WHERE token_hash=? AND expires_at>? AND users.status='active'",
        (token_hash(token), time.time()),
    )


def current_user(request: Request) -> dict:
    user = session_user(request.app.state.db, request.cookies.get(COOKIE))
    if not user:
        raise HTTPException(401, "请先登录")
    return user


def admin_user(request: Request) -> dict:
    user = current_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "需要管理员权限")
    return user
