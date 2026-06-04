"""Authentication, user management, LDAP, CSRF, and rate limiting for Scrinium.

State lives in a single SQLite database (`auth.db`) inside the config dir.
Passwords are hashed with Werkzeug's default scrypt; LDAP binds use ldap3.
"""
from __future__ import annotations

import json
import os
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
CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    actor     TEXT,
    actor_id  INTEGER,
    ip        TEXT,
    action    TEXT NOT NULL,
    target    TEXT,
    details   TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log (target);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action);
CREATE TABLE IF NOT EXISTS groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE NOT NULL COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_groups (
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id  INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_user_groups_user ON user_groups (user_id);
CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups (group_id);
CREATE TABLE IF NOT EXISTS trash (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    original_rel TEXT NOT NULL,
    kind         TEXT NOT NULL,
    trashed_path TEXT NOT NULL,
    deleted_at   TEXT NOT NULL,
    deleted_by   INTEGER,
    size_bytes   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_trash_deleted_at ON trash (deleted_at DESC);
"""


# ---------------------------------------------------------------------------
# database
# ---------------------------------------------------------------------------


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA)
        migrate_db(conn)


def migrate_db(conn: sqlite3.Connection) -> None:
    """Opportunistic schema upgrades for existing installs."""
    have = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    if "theme" not in have:
        conn.execute(
            "ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'system'"
        )
    if "sidebar_default" not in have:
        conn.execute(
            "ALTER TABLE users ADD COLUMN sidebar_default TEXT NOT NULL "
            "DEFAULT 'expanded'"
        )
    if "first_name" not in have:
        conn.execute("ALTER TABLE users ADD COLUMN first_name TEXT")
    if "last_name" not in have:
        conn.execute("ALTER TABLE users ADD COLUMN last_name TEXT")


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
    first_name: str | None = None,
    last_name: str | None = None,
) -> int:
    pw_hash = generate_password_hash(password) if password else None
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO users (username, password_hash, is_admin, source, created_at, "
            "first_name, last_name) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                username.strip(),
                pw_hash,
                1 if is_admin else 0,
                source,
                now,
                (first_name or "").strip() or None,
                (last_name or "").strip() or None,
            ),
        )
        return cur.lastrowid


def update_user_names(
    user_id: int,
    *,
    first_name: str | None = None,
    last_name: str | None = None,
) -> None:
    """Refresh LDAP given name / surname on the user row."""
    with _conn() as c:
        c.execute(
            "UPDATE users SET first_name = ?, last_name = ? WHERE id = ?",
            (
                (first_name or "").strip() or None,
                (last_name or "").strip() or None,
                user_id,
            ),
        )


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
    invalidate_user_label_cache()


def touch_login(user_id: int) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as c:
        c.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user_id))


VALID_THEMES = frozenset({"dark", "light", "system"})
VALID_SIDEBAR_DEFAULTS = frozenset({"expanded", "collapsed"})


def get_user_prefs(user_id: int) -> dict:
    user = get_user(user_id)
    if user is None:
        return {"theme": "system", "sidebar_default": "expanded"}
    theme = (user["theme"] if "theme" in user.keys() else None) or "system"
    if theme not in VALID_THEMES:
        theme = "system"
    sidebar_default = (
        user["sidebar_default"] if "sidebar_default" in user.keys() else None
    ) or "expanded"
    if sidebar_default not in VALID_SIDEBAR_DEFAULTS:
        sidebar_default = "expanded"
    return {"theme": theme, "sidebar_default": sidebar_default}


def set_user_prefs(user_id: int, **kwargs) -> None:
    updates: list[str] = []
    values: list[object] = []
    if "theme" in kwargs:
        theme = kwargs["theme"]
        if theme not in VALID_THEMES:
            raise ValueError("Invalid theme.")
        updates.append("theme = ?")
        values.append(theme)
    if "sidebar_default" in kwargs:
        sidebar_default = kwargs["sidebar_default"]
        if sidebar_default not in VALID_SIDEBAR_DEFAULTS:
            raise ValueError("Invalid sidebar default.")
        updates.append("sidebar_default = ?")
        values.append(sidebar_default)
    if not updates:
        return
    values.append(user_id)
    with _conn() as c:
        c.execute(
            f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
            tuple(values),
        )


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
    "attr_first_name": "givenName",
    "attr_last_name": "sn",
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


# ---------------------------------------------------------------------------
# site appearance & feature flags
# ---------------------------------------------------------------------------


APPEARANCE_DEFAULTS: dict = {
    "sans_font": "system",
    "mono_font": "system",
    "default_theme": "system",
    "site_name": "",
}

FEATURE_DEFAULTS: dict = {
    "code_copy": True,
    "code_linenos": False,
    "wiki_broken_warn": False,
    "compact_density": False,
    "show_tag_cloud": True,
}

ATTACHMENT_DEFAULTS: dict = {
    "enabled": True,
    "max_mb": int(os.environ.get("SCRINIUM_MAX_ATTACHMENT_MB", "50")),
    "extensions": [
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".odt",
        ".ods",
        ".odp",
        ".txt",
        ".csv",
        ".log",
        ".md",
        ".json",
        ".yaml",
        ".yml",
        ".zip",
        ".tar",
        ".gz",
        ".7z",
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
        ".gif",
        ".mp3",
        ".wav",
        ".ogg",
        ".mp4",
        ".webm",
        ".mov",
    ],
}

FONT_CHOICES_SANS: dict[str, str] = {
    "system": "System default",
    "inter": "Inter",
    "ibm-plex-sans": "IBM Plex Sans",
}

FONT_CHOICES_MONO: dict[str, str] = {
    "system": "System default",
    "jetbrains-nerd": "JetBrains Mono Nerd Font",
    "fira-nerd": "FiraCode Nerd Font",
    "ibm-plex-mono": "IBM Plex Mono",
}

FONT_CSS_STACKS: dict[str, dict[str, str]] = {
    "sans": {
        "system": 'system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
        "inter": '"Inter", system-ui, sans-serif',
        "ibm-plex-sans": '"IBM Plex Sans", system-ui, sans-serif',
    },
    "mono": {
        "system": 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
        "jetbrains-nerd": '"JetBrainsMono Nerd Font", ui-monospace, monospace',
        "fira-nerd": '"FiraCode Nerd Font", ui-monospace, monospace',
        "ibm-plex-mono": '"IBM Plex Mono", ui-monospace, monospace',
    },
}


def appearance_settings() -> dict:
    saved = get_config("appearance") or {}
    out = dict(APPEARANCE_DEFAULTS)
    out.update(saved)
    if out.get("default_theme") not in VALID_THEMES:
        out["default_theme"] = "system"
    if out.get("sans_font") not in FONT_CHOICES_SANS:
        out["sans_font"] = "system"
    if out.get("mono_font") not in FONT_CHOICES_MONO:
        out["mono_font"] = "system"
    return out


def save_appearance_settings(form: dict) -> None:
    cleaned = dict(APPEARANCE_DEFAULTS)
    cleaned["sans_font"] = (form.get("sans_font") or "system").strip()
    cleaned["mono_font"] = (form.get("mono_font") or "system").strip()
    cleaned["default_theme"] = (form.get("default_theme") or "system").strip()
    cleaned["site_name"] = (form.get("site_name") or "").strip()
    if cleaned["sans_font"] not in FONT_CHOICES_SANS:
        cleaned["sans_font"] = "system"
    if cleaned["mono_font"] not in FONT_CHOICES_MONO:
        cleaned["mono_font"] = "system"
    if cleaned["default_theme"] not in VALID_THEMES:
        cleaned["default_theme"] = "system"
    set_config("appearance", cleaned)


def feature_flags() -> dict:
    saved = get_config("features") or {}
    out = dict(FEATURE_DEFAULTS)
    out.update(saved)
    for key in FEATURE_DEFAULTS:
        out[key] = bool(out.get(key))
    return out


def save_feature_flags(form: dict) -> None:
    cleaned = {
        key: bool(form.get(key)) for key in FEATURE_DEFAULTS
    }
    set_config("features", cleaned)


def _normalize_extensions(value: object) -> list[str]:
    if isinstance(value, str):
        items = [line.strip() for line in value.replace(",", "\n").splitlines()]
    elif isinstance(value, list):
        items = [str(v).strip() for v in value]
    else:
        items = []
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if not item:
            continue
        if not item.startswith("."):
            item = "." + item
        item = item.lower()
        if len(item) < 2 or any(ch.isspace() for ch in item):
            continue
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def attachment_settings() -> dict:
    saved = get_config("attachments") or {}
    out = dict(ATTACHMENT_DEFAULTS)
    out.update(saved)
    out["enabled"] = bool(out.get("enabled"))
    try:
        out["max_mb"] = max(1, min(1024, int(out.get("max_mb") or 50)))
    except (TypeError, ValueError):
        out["max_mb"] = ATTACHMENT_DEFAULTS["max_mb"]
    exts = _normalize_extensions(out.get("extensions"))
    out["extensions"] = exts or list(ATTACHMENT_DEFAULTS["extensions"])
    return out


def save_attachment_settings(form: dict) -> None:
    enabled = bool(form.get("enabled"))
    try:
        max_mb = int(form.get("max_mb") or ATTACHMENT_DEFAULTS["max_mb"])
    except ValueError:
        max_mb = ATTACHMENT_DEFAULTS["max_mb"]
    max_mb = max(1, min(1024, max_mb))
    extensions = _normalize_extensions(form.get("extensions"))
    if not extensions:
        extensions = list(ATTACHMENT_DEFAULTS["extensions"])
    set_config(
        "attachments",
        {"enabled": enabled, "max_mb": max_mb, "extensions": extensions},
    )


def list_groups() -> list[sqlite3.Row]:
    with _conn() as c:
        return list(c.execute("SELECT * FROM groups ORDER BY name COLLATE NOCASE"))


def get_group(group_id: int) -> Optional[sqlite3.Row]:
    with _conn() as c:
        return c.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()


def create_group(name: str, description: str = "") -> int:
    cleaned = require_username(name)
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO groups (name, description, created_at) VALUES (?, ?, ?)",
            (cleaned, (description or "").strip(), now),
        )
        return cur.lastrowid


def delete_group(group_id: int) -> None:
    with _conn() as c:
        c.execute("DELETE FROM groups WHERE id = ?", (group_id,))


def group_by_name(name: str) -> Optional[sqlite3.Row]:
    with _conn() as c:
        return c.execute(
            "SELECT * FROM groups WHERE name = ? COLLATE NOCASE",
            ((name or "").strip(),),
        ).fetchone()


def add_user_to_group(user_id: int, group_id: int) -> None:
    with _conn() as c:
        c.execute(
            "INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)",
            (user_id, group_id),
        )


def remove_user_from_group(user_id: int, group_id: int) -> None:
    with _conn() as c:
        c.execute(
            "DELETE FROM user_groups WHERE user_id = ? AND group_id = ?",
            (user_id, group_id),
        )


def groups_for_user(user_id: int) -> list[sqlite3.Row]:
    with _conn() as c:
        return list(
            c.execute(
                "SELECT g.* FROM groups g "
                "JOIN user_groups ug ON ug.group_id = g.id "
                "WHERE ug.user_id = ? ORDER BY g.name COLLATE NOCASE",
                (user_id,),
            )
        )


def members_of_group(group_id: int) -> list[sqlite3.Row]:
    with _conn() as c:
        return list(
            c.execute(
                "SELECT u.* FROM users u "
                "JOIN user_groups ug ON ug.user_id = u.id "
                "WHERE ug.group_id = ? ORDER BY u.username COLLATE NOCASE",
                (group_id,),
            )
        )


def font_css_variables(appearance: Optional[dict] = None) -> str:
    """Return a :root { --sans; --mono; } block for inline injection."""
    app = appearance or appearance_settings()
    sans_key = app.get("sans_font") or "system"
    mono_key = app.get("mono_font") or "system"
    sans = FONT_CSS_STACKS["sans"].get(sans_key, FONT_CSS_STACKS["sans"]["system"])
    mono = FONT_CSS_STACKS["mono"].get(mono_key, FONT_CSS_STACKS["mono"]["system"])
    return f":root {{ --sans: {sans}; --mono: {mono}; }}"


def effective_site_name(env_default: str) -> str:
    name = (appearance_settings().get("site_name") or "").strip()
    return name or env_default


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


def display_name(user: sqlite3.Row | dict | None) -> str:
    """Human-readable label: LDAP first+last when available, else username."""
    if user is None:
        return ""
    source = user["source"] if "source" in user.keys() else user.get("source", "local")
    first = (user["first_name"] if "first_name" in user.keys() else user.get("first_name")) or ""
    last = (user["last_name"] if "last_name" in user.keys() else user.get("last_name")) or ""
    first = str(first).strip()
    last = str(last).strip()
    if source == "ldap" and (first or last):
        return f"{first} {last}".strip()
    username = user["username"] if "username" in user.keys() else user.get("username", "")
    return str(username or "")


_user_label_cache: dict[str, tuple[float, dict]] = {}
_USER_LABEL_CACHE_TTL = 30.0


def _user_label_maps() -> tuple[dict[int, str], dict[str, str]]:
    """Cached id->label and username->label maps for templates and audit resolution."""
    now = time.time()
    cached = _user_label_cache.get("maps")
    if cached and now - cached[0] < _USER_LABEL_CACHE_TTL:
        return cached[1], cached[2]
    by_id: dict[int, str] = {}
    by_username: dict[str, str] = {}
    for u in list_users():
        label = display_name(u)
        by_id[int(u["id"])] = label
        by_username[str(u["username"]).lower()] = label
    _user_label_cache["maps"] = (now, by_id, by_username)
    return by_id, by_username


def invalidate_user_label_cache() -> None:
    _user_label_cache.clear()


def label_for_id(user_id: int | None) -> str:
    if user_id is None:
        return ""
    by_id, _ = _user_label_maps()
    return by_id.get(int(user_id), f"user #{user_id}")


def label_for_username(username: str | None) -> str:
    if not username or username == "system":
        return username or ""
    _, by_username = _user_label_maps()
    return by_username.get(str(username).lower(), str(username))


def _ldap_attr_value(entry: object, attr: str) -> str:
    """Read a single string value from an ldap3 entry attribute."""
    if not attr:
        return ""
    try:
        val = entry[attr]  # type: ignore[index]
    except (KeyError, TypeError):
        return ""
    if val is None:
        return ""
    if hasattr(val, "value"):
        raw = val.value
    elif isinstance(val, (list, tuple)) and val:
        raw = val[0]
    else:
        raw = val
    return str(raw).strip() if raw is not None else ""


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
                current_app.logger.error("LDAP: service-account START_TLS failed")
                return None
        if not conn.bind():
            current_app.logger.error(
                "LDAP: service-account bind failed (result: %s)", conn.result
            )
            return None
        flt = settings.get("user_filter") or "(uid={username})"
        flt = flt.replace("{username}", _ldap_escape(username))
        attr_first = (settings.get("attr_first_name") or "givenName").strip()
        attr_last = (settings.get("attr_last_name") or "sn").strip()
        search_attrs = ["cn"]
        for a in (attr_first, attr_last):
            if a and a not in search_attrs:
                search_attrs.append(a)
        current_app.logger.debug("LDAP: searching base=%r filter=%r", settings.get("user_base_dn"), flt)
        conn.search(settings.get("user_base_dn") or "", flt, attributes=search_attrs)
        if not conn.entries:
            current_app.logger.error(
                "LDAP: user %r not found (base=%r filter=%r)",
                username, settings.get("user_base_dn"), flt,
            )
            conn.unbind()
            return None
        entry = conn.entries[0]
        user_dn = entry.entry_dn
        first_name = _ldap_attr_value(entry, attr_first)
        last_name = _ldap_attr_value(entry, attr_last)
        current_app.logger.debug("LDAP: found user DN %r, attempting user bind", user_dn)
        conn.unbind()

        user_conn = Connection(server, user_dn, password, auto_bind=False)
        if user_conn.open() is False:
            current_app.logger.error("LDAP: failed to open connection for user DN %r", user_dn)
            return None
        if settings.get("use_starttls") and not user_conn.start_tls():
            current_app.logger.error("LDAP: user START_TLS failed for DN %r", user_dn)
            return None
        bound = user_conn.bind()
        user_conn.unbind()
        if not bound:
            current_app.logger.error(
                "LDAP: user bind failed for DN %r (result: %s)", user_dn, user_conn.result
            )
            return None
        return {
            "username": username,
            "dn": user_dn,
            "first_name": first_name,
            "last_name": last_name,
        }
    except LDAPException as e:
        current_app.logger.error("LDAP authentication error: %s", e)
        return None
    except Exception:
        current_app.logger.exception("LDAP authentication error")
        return None


# ---------------------------------------------------------------------------
# login flow
# ---------------------------------------------------------------------------


def _apply_ldap_profile(user_id: int, ldap_info: dict) -> None:
    update_user_names(
        user_id,
        first_name=ldap_info.get("first_name"),
        last_name=ldap_info.get("last_name"),
    )
    invalidate_user_label_cache()


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
            ldap_info = ldap_authenticate(username, password)
            if ldap_info:
                _apply_ldap_profile(int(user["id"]), ldap_info)
                return get_user(int(user["id"]))
            return None
    settings = ldap_settings()
    if settings.get("enabled") and settings.get("auto_provision", True):
        ldap_info = ldap_authenticate(username, password)
        if ldap_info:
            uid = create_user(
                username,
                None,
                is_admin=False,
                source="ldap",
                first_name=ldap_info.get("first_name"),
                last_name=ldap_info.get("last_name"),
            )
            invalidate_user_label_cache()
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
    "migrate_db",
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
    "get_user_prefs",
    "set_user_prefs",
    "VALID_THEMES",
    "appearance_settings",
    "save_appearance_settings",
    "feature_flags",
    "save_feature_flags",
    "font_css_variables",
    "effective_site_name",
    "FONT_CHOICES_SANS",
    "FONT_CHOICES_MONO",
    "APPEARANCE_DEFAULTS",
    "FEATURE_DEFAULTS",
    "ATTACHMENT_DEFAULTS",
    "attachment_settings",
    "save_attachment_settings",
    "list_groups",
    "get_group",
    "create_group",
    "delete_group",
    "group_by_name",
    "add_user_to_group",
    "remove_user_from_group",
    "groups_for_user",
    "members_of_group",
)
