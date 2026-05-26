"""Authentication, user management, LDAP, CSRF, and rate limiting for Scrinium.

State lives in a single SQLite database (`auth.db`) inside the config dir.
Passwords are hashed with Werkzeug's default scrypt; LDAP binds use ldap3.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import time
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Callable, Iterable, Optional

from flask import (
    abort,
    current_app,
    redirect,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    source        TEXT NOT NULL DEFAULT 'local',
    created_at    TEXT NOT NULL,
    last_login    TEXT
);
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


# ---------------------------------------------------------------------------
# database
# ---------------------------------------------------------------------------


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def _conn():
    db_path = current_app.config["AUTH_DB"]
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# user CRUD
# ---------------------------------------------------------------------------


def list_users() -> list[sqlite3.Row]:
    with _conn() as c:
        return list(c.execute("SELECT * FROM users ORDER BY username COLLATE NOCASE"))


def get_user(user_id: int) -> Optional[sqlite3.Row]:
    with _conn() as c:
        return c.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_name(username: str) -> Optional[sqlite3.Row]:
    with _conn() as c:
        return c.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
        ).fetchone()


def admin_count() -> int:
    with _conn() as c:
        return c.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0]


def has_admin() -> bool:
    return admin_count() > 0


def create_user(
    username: str,
    password: Optional[str],
    *,
    is_admin: bool = False,
    source: str = "local",
) -> int:
    pw_hash = generate_password_hash(password) if password else None
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO users (username, password_hash, is_admin, source, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (username.strip(), pw_hash, 1 if is_admin else 0, source, now),
        )
        return cur.lastrowid


def set_password(user_id: int, password: str) -> None:
    pw_hash = generate_password_hash(password)
    with _conn() as c:
        c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, user_id))


def set_admin(user_id: int, is_admin: bool) -> None:
    with _conn() as c:
        c.execute(
            "UPDATE users SET is_admin = ? WHERE id = ?",
            (1 if is_admin else 0, user_id),
        )


def delete_user(user_id: int) -> None:
    with _conn() as c:
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))


def touch_login(user_id: int) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as c:
        c.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user_id))


# ---------------------------------------------------------------------------
# config (LDAP) storage
# ---------------------------------------------------------------------------


def get_config(key: str) -> Optional[dict]:
    with _conn() as c:
        row = c.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value"]) if row else None


def set_config(key: str, value: dict) -> None:
    payload = json.dumps(value)
    with _conn() as c:
        c.execute(
            "INSERT INTO config (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, payload),
        )


# ---------------------------------------------------------------------------
# LDAP
# ---------------------------------------------------------------------------


LDAP_DEFAULTS: dict = {
    "enabled": False,
    "server_uri": "",
    "bind_dn": "",
    "bind_password": "",
    "user_base_dn": "",
    "user_filter": "(uid={username})",
    "use_starttls": False,
    "verify_cert": True,
    "auto_provision": True,
    "connect_timeout": 5,
}


_LDAP_SECRET_KEYS = {"bind_password"}


def ldap_settings(redact: bool = False) -> dict:
    saved = get_config("ldap") or {}
    settings = dict(LDAP_DEFAULTS)
    settings.update(saved)
    if redact:
        for k in _LDAP_SECRET_KEYS:
            if settings.get(k):
                settings[k] = "********"
    return settings


def save_ldap_settings(form: dict, *, keep_existing_password: bool = True) -> None:
    """Merge form-submitted LDAP settings, keeping the existing bind_password
    if the user did not enter a new one (when `keep_existing_password`)."""
    saved = get_config("ldap") or {}
    cleaned = dict(LDAP_DEFAULTS)
    cleaned.update(saved)
    for key in LDAP_DEFAULTS:
        if key in {"enabled", "use_starttls", "verify_cert", "auto_provision"}:
            cleaned[key] = bool(form.get(key))
        elif key == "connect_timeout":
            try:
                cleaned[key] = max(1, int(form.get(key) or LDAP_DEFAULTS[key]))
            except ValueError:
                cleaned[key] = LDAP_DEFAULTS[key]
        else:
            value = (form.get(key) or "").strip()
            if key == "bind_password" and not value and keep_existing_password:
                cleaned[key] = saved.get(key, "")
            else:
                cleaned[key] = value
    set_config("ldap", cleaned)


def _ldap_escape(value: str) -> str:
    """RFC 4515 escape for LDAP search filter values."""
    return (
        value.replace("\\", "\\5c")
        .replace("*", "\\2a")
        .replace("(", "\\28")
        .replace(")", "\\29")
        .replace("\x00", "\\00")
    )


class LDAPResult:
    def __init__(self, ok: bool, message: str, found: int = 0) -> None:
        self.ok = ok
        self.message = message
        self.found = found


def ldap_test(settings: dict) -> LDAPResult:
    """Bind as the service account and run a lookup against user_base_dn.
    Used by the admin panel's 'Test connection' button."""
    if not settings.get("server_uri"):
        return LDAPResult(False, "Server URI is required.")
    try:
        from ldap3 import ALL, Connection, Server, Tls  # type: ignore[import-not-found]
        from ldap3.core.exceptions import LDAPException  # type: ignore[import-not-found]
    except ImportError:
        return LDAPResult(False, "ldap3 is not installed in this build.")
    import ssl

    tls = Tls(
        validate=ssl.CERT_REQUIRED if settings.get("verify_cert", True) else ssl.CERT_NONE
    )
    server = Server(
        settings["server_uri"],
        get_info=ALL,
        tls=tls,
        connect_timeout=int(settings.get("connect_timeout") or 5),
    )
    try:
        if settings.get("bind_dn"):
            conn = Connection(
                server,
                settings["bind_dn"],
                settings.get("bind_password") or "",
                auto_bind=False,
            )
        else:
            conn = Connection(server, auto_bind=False)
        if settings.get("use_starttls"):
            if not conn.open():
                return LDAPResult(False, "Could not open LDAP connection.")
            if not conn.start_tls():
                return LDAPResult(False, f"StartTLS failed: {conn.last_error}")
        if not conn.bind():
            return LDAPResult(False, f"Bind failed: {conn.last_error or conn.result}")
        base = settings.get("user_base_dn") or ""
        if not base:
            conn.unbind()
            return LDAPResult(True, "Bound successfully (no search base configured).")
        flt = settings.get("user_filter") or "(objectClass=*)"
        flt = flt.replace("{username}", "*")
        conn.search(base, flt, attributes=["cn"])
        n = len(conn.entries)
        conn.unbind()
        return LDAPResult(True, f"Bound successfully. Search returned {n} entries.", n)
    except LDAPException as e:
        return LDAPResult(False, f"LDAP error: {e}")
    except Exception as e:  # network/SSL/etc
        return LDAPResult(False, f"Connection error: {e}")


def ldap_authenticate(username: str, password: str) -> Optional[dict]:
    """Bind as the service account, locate the user DN, then bind as the user
    to verify the password. Returns a small dict on success, else None."""
    if not password:
        return None
    settings = ldap_settings()
    if not settings.get("enabled") or not settings.get("server_uri"):
        return None
    try:
        from ldap3 import ALL, Connection, Server, Tls  # type: ignore[import-not-found]
        from ldap3.core.exceptions import LDAPException  # type: ignore[import-not-found]
    except ImportError:
        current_app.logger.error("LDAP enabled but ldap3 is not installed")
        return None
    import ssl

    tls = Tls(
        validate=ssl.CERT_REQUIRED if settings.get("verify_cert", True) else ssl.CERT_NONE
    )
    server = Server(
        settings["server_uri"],
        get_info=ALL,
        tls=tls,
        connect_timeout=int(settings.get("connect_timeout") or 5),
    )
    try:
        if settings.get("bind_dn"):
            conn = Connection(
                server,
                settings["bind_dn"],
                settings.get("bind_password") or "",
                auto_bind=False,
            )
        else:
            conn = Connection(server, auto_bind=False)
        if settings.get("use_starttls"):
            conn.open()
            if not conn.start_tls():
                return None
        if not conn.bind():
            return None
        flt = settings.get("user_filter") or "(uid={username})"
        flt = flt.replace("{username}", _ldap_escape(username))
        conn.search(settings.get("user_base_dn") or "", flt, attributes=["cn"])
        if not conn.entries:
            conn.unbind()
            return None
        user_dn = conn.entries[0].entry_dn
        conn.unbind()

        user_conn = Connection(server, user_dn, password, auto_bind=False)
        if user_conn.open() is False:
            return None
        if settings.get("use_starttls") and not user_conn.start_tls():
            return None
        bound = user_conn.bind()
        user_conn.unbind()
        if not bound:
            return None
        return {"username": username, "dn": user_dn}
    except LDAPException as e:
        current_app.logger.error("LDAP authentication error: %s", e)
        return None
    except Exception:
        current_app.logger.exception("LDAP authentication error")
        return None


# ---------------------------------------------------------------------------
# login flow
# ---------------------------------------------------------------------------


def authenticate(username: str, password: str) -> Optional[sqlite3.Row]:
    """Resolve a username to a row, verifying the password by source."""
    username = (username or "").strip()
    if not username or not password:
        return None
    user = get_user_by_name(username)
    if user is not None:
        if user["source"] == "local":
            if user["password_hash"] and check_password_hash(
                user["password_hash"], password
            ):
                return user
            return None
        if user["source"] == "ldap":
            if ldap_authenticate(username, password):
                return user
            return None
    settings = ldap_settings()
    if settings.get("enabled") and settings.get("auto_provision", True):
        if ldap_authenticate(username, password):
            uid = create_user(username, None, is_admin=False, source="ldap")
            return get_user(uid)
    return None


def current_user() -> Optional[sqlite3.Row]:
    uid = session.get("user_id")
    if not uid:
        return None
    user = get_user(uid)
    if user is None:
        session.pop("user_id", None)
    return user


def login_session(user: sqlite3.Row) -> None:
    session.clear()
    session["user_id"] = user["id"]
    session.permanent = True
    touch_login(user["id"])


def logout_session() -> None:
    session.clear()


# ---------------------------------------------------------------------------
# decorators
# ---------------------------------------------------------------------------


def login_required(view: Callable) -> Callable:
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not has_admin():
            return redirect(url_for("setup"))
        if current_user() is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view: Callable) -> Callable:
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not has_admin():
            return redirect(url_for("setup"))
        u = current_user()
        if u is None:
            return redirect(url_for("login", next=request.path))
        if not u["is_admin"]:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


# ---------------------------------------------------------------------------
# rate limiting (in-memory; resets on restart)
# ---------------------------------------------------------------------------


_failed: dict[str, list[float]] = defaultdict(list)
LOCKOUT_LIMIT = 8
LOCKOUT_WINDOW = 300  # seconds


def _prune(key: str) -> list[float]:
    cutoff = time.time() - LOCKOUT_WINDOW
    fresh = [t for t in _failed[key] if t > cutoff]
    _failed[key] = fresh
    return fresh


def lockout_remaining(key: str) -> int:
    attempts = _prune(key)
    if len(attempts) >= LOCKOUT_LIMIT:
        return int(LOCKOUT_WINDOW - (time.time() - attempts[0]))
    return 0


def record_failure(key: str) -> None:
    _prune(key)
    _failed[key].append(time.time())


def clear_failures(key: str) -> None:
    _failed.pop(key, None)


def login_rate_key(username: str) -> str:
    ip = request.remote_addr or "unknown"
    return f"{ip}|{(username or '').lower()}"


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------


CSRF_KEY = "csrf_token"


def csrf_token() -> str:
    token = session.get(CSRF_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_KEY] = token
    return token


def verify_csrf() -> None:
    token = request.form.get(CSRF_KEY) or request.headers.get("X-CSRF-Token")
    expected = session.get(CSRF_KEY)
    if not token or not expected or not secrets.compare_digest(token, expected):
        abort(400, "CSRF token missing or invalid. Please reload the page and try again.")


# ---------------------------------------------------------------------------
# misc helpers used by routes
# ---------------------------------------------------------------------------


def safe_next(target: Optional[str], fallback: str) -> str:
    """Avoid open-redirects: only allow same-origin paths starting with '/'."""
    if not target:
        return fallback
    if target.startswith("//") or "://" in target:
        return fallback
    if not target.startswith("/"):
        return fallback
    return target


def require_password(value: str, *, min_length: int = 8) -> None:
    if not value or len(value) < min_length:
        raise ValueError(f"Password must be at least {min_length} characters.")


def require_username(value: str) -> str:
    cleaned = (value or "").strip()
    if len(cleaned) < 1 or len(cleaned) > 64:
        raise ValueError("Username must be between 1 and 64 characters.")
    bad = set(' \t\r\n/\\:*?"<>|')
    if any(c in bad for c in cleaned):
        raise ValueError("Username may not contain whitespace or path separators.")
    return cleaned


__all__: Iterable[str] = (
    "init_db",
    "list_users",
    "get_user",
    "get_user_by_name",
    "create_user",
    "set_password",
    "set_admin",
    "delete_user",
    "touch_login",
    "has_admin",
    "admin_count",
    "ldap_settings",
    "save_ldap_settings",
    "ldap_test",
    "ldap_authenticate",
    "authenticate",
    "current_user",
    "login_session",
    "logout_session",
    "login_required",
    "admin_required",
    "csrf_token",
    "verify_csrf",
    "lockout_remaining",
    "record_failure",
    "clear_failures",
    "login_rate_key",
    "safe_next",
    "require_password",
    "require_username",
)
