"""Shared links dashboard for Scrinium.

A wiki-style "tools and bookmarks" dashboard at /dash. Any signed-in user
can add, edit, or remove links. Each link belongs to a free-form section
heading; favicons are fetched best-effort and cached on disk under
SCRINIUM_CONFIG/favicons. When fetching fails (offline, private host,
weird redirects) we generate a deterministic letter-tile SVG fallback so
the grid always looks tidy.

Data lives in the same SQLite database as auth (`auth.db`), in the
`dashboard_links` table created by `init_db`. The module exposes a small
CRUD surface (used by routes in app.py) and stays free of Flask imports
except for the `current_app` logger so unit-testing is straightforward.
"""
from __future__ import annotations

import hashlib
import io
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urljoin, urlparse

from flask import current_app


SCHEMA = """
CREATE TABLE IF NOT EXISTS dashboard_links (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    url         TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    section     TEXT NOT NULL DEFAULT '',
    favicon     TEXT NOT NULL DEFAULT '',
    sort_order  INTEGER NOT NULL DEFAULT 0,
    created_by  INTEGER,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dashboard_links_section
    ON dashboard_links(section COLLATE NOCASE, sort_order, id);
"""


FAVICON_DIR_NAME = "favicons"
FAVICON_TIMEOUT = 4  # seconds, per request
FAVICON_MAX_BYTES = 256 * 1024


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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


_ALLOWED_SCHEMES = {"http", "https"}


def normalize_url(value: str) -> str:
    """Trim, default to https://, and reject anything that isn't a real
    http(s) URL with a host. Raises ValueError on bad input."""
    s = (value or "").strip()
    if not s:
        raise ValueError("URL is required.")
    if "://" not in s:
        s = "https://" + s
    parsed = urlparse(s)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValueError("URL must start with http:// or https://.")
    if not parsed.netloc:
        raise ValueError("URL is missing a hostname.")
    return s


def normalize_title(value: str) -> str:
    s = (value or "").strip()
    if not s:
        raise ValueError("Title is required.")
    if len(s) > 120:
        raise ValueError("Title must be 120 characters or less.")
    return s


def normalize_section(value: str) -> str:
    s = (value or "").strip()
    if len(s) > 60:
        raise ValueError("Section must be 60 characters or less.")
    return s


def normalize_description(value: str) -> str:
    s = (value or "").strip()
    if len(s) > 280:
        raise ValueError("Description must be 280 characters or less.")
    return s


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def list_links() -> list[sqlite3.Row]:
    with _conn() as c:
        return list(
            c.execute(
                "SELECT * FROM dashboard_links "
                "ORDER BY section COLLATE NOCASE, sort_order, "
                "title COLLATE NOCASE"
            )
        )


def get_link(link_id: int) -> Optional[sqlite3.Row]:
    with _conn() as c:
        return c.execute(
            "SELECT * FROM dashboard_links WHERE id = ?", (link_id,)
        ).fetchone()


def existing_sections() -> list[str]:
    with _conn() as c:
        rows = c.execute(
            "SELECT DISTINCT section FROM dashboard_links "
            "WHERE section <> '' ORDER BY section COLLATE NOCASE"
        ).fetchall()
    return [r["section"] for r in rows]


def create_link(
    *,
    title: str,
    url: str,
    description: str,
    section: str,
    favicon: str,
    created_by: Optional[int],
) -> int:
    now = _now()
    with _conn() as c:
        cur = c.execute(
            """INSERT INTO dashboard_links
               (title, url, description, section, favicon, sort_order,
                created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?,
                       COALESCE((SELECT MAX(sort_order) + 1
                                 FROM dashboard_links WHERE section = ?), 0),
                       ?, ?, ?)""",
            (title, url, description, section, favicon, section,
             created_by, now, now),
        )
        return int(cur.lastrowid)


def update_link(
    link_id: int,
    *,
    title: str,
    url: str,
    description: str,
    section: str,
    favicon: Optional[str] = None,
) -> None:
    now = _now()
    with _conn() as c:
        if favicon is None:
            c.execute(
                """UPDATE dashboard_links
                   SET title=?, url=?, description=?, section=?, updated_at=?
                   WHERE id=?""",
                (title, url, description, section, now, link_id),
            )
        else:
            c.execute(
                """UPDATE dashboard_links
                   SET title=?, url=?, description=?, section=?,
                       favicon=?, updated_at=?
                   WHERE id=?""",
                (title, url, description, section, favicon, now, link_id),
            )


def delete_link(link_id: int) -> None:
    with _conn() as c:
        c.execute("DELETE FROM dashboard_links WHERE id = ?", (link_id,))


def grouped_links() -> list[dict]:
    """Return links grouped by section, in display order. Empty section
    becomes a leading 'Pinned' group so it's visually deliberate."""
    rows = list_links()
    by_section: dict[str, list[sqlite3.Row]] = {}
    order: list[str] = []
    for r in rows:
        key = r["section"] or ""
        if key not in by_section:
            by_section[key] = []
            order.append(key)
    for r in rows:
        by_section[r["section"] or ""].append(r)
    groups: list[dict] = []
    for key in order:
        groups.append(
            {
                "section": key,
                "display_name": key if key else "Pinned",
                "links": by_section[key],
            }
        )
    return groups


# ---------------------------------------------------------------------------
# favicons
# ---------------------------------------------------------------------------


def favicon_dir() -> Path:
    base = Path(current_app.config["AUTH_DB"]).parent
    p = base / FAVICON_DIR_NAME
    p.mkdir(parents=True, exist_ok=True)
    return p


_LINK_ICON_RE = re.compile(
    r"""<link[^>]+rel\s*=\s*['"]?[^'">]*\bicon\b[^'">]*['"]?[^>]*>""",
    re.IGNORECASE,
)
_HREF_RE = re.compile(r"""href\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)


def _content_type_to_ext(ctype: str) -> str:
    ctype = (ctype or "").split(";", 1)[0].strip().lower()
    return {
        "image/png": ".png",
        "image/x-icon": ".ico",
        "image/vnd.microsoft.icon": ".ico",
        "image/svg+xml": ".svg",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "image/webp": ".webp",
    }.get(ctype, ".ico")


def _request_get(url: str, *, timeout: int = FAVICON_TIMEOUT):
    """Thin wrapper so we can swap requests for urllib without rewiring."""
    try:
        import requests
    except ImportError:
        return None, None, None
    try:
        r = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
            headers={"User-Agent": "ScriniumFaviconFetcher/1.0"},
        )
    except Exception as e:
        current_app.logger.info("favicon: GET %s failed: %s", url, e)
        return None, None, None
    if r.status_code != 200:
        current_app.logger.info(
            "favicon: GET %s -> HTTP %s", url, r.status_code
        )
        r.close()
        return None, None, None
    return r, r.headers.get("Content-Type", ""), r.headers.get(
        "Content-Length", ""
    )


def _read_capped(r) -> bytes:
    buf = io.BytesIO()
    total = 0
    for chunk in r.iter_content(8192):
        if not chunk:
            break
        total += len(chunk)
        if total > FAVICON_MAX_BYTES:
            r.close()
            return b""
        buf.write(chunk)
    r.close()
    return buf.getvalue()


def fetch_favicon(url: str) -> str:
    """Best-effort favicon fetch. On success, write the bytes under
    favicon_dir() with a content-derived filename and return the basename
    so it can be stored alongside the link row. On any failure, return ''
    (the template falls back to a generated letter tile)."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in _ALLOWED_SCHEMES or not parsed.netloc:
            return ""
        origin = f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return ""

    candidate_url: Optional[str] = None
    candidate_ext = ".ico"

    page_r, page_ct, _ = _request_get(url)
    if page_r is not None and (page_ct or "").lower().startswith("text/html"):
        body = _read_capped(page_r)
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        for tag in _LINK_ICON_RE.findall(text):
            m = _HREF_RE.search(tag)
            if m:
                href = m.group(1).strip()
                if href:
                    candidate_url = urljoin(url, href)
                    break
    elif page_r is not None:
        page_r.close()

    if candidate_url is None:
        candidate_url = urljoin(origin + "/", "favicon.ico")

    icon_r, icon_ct, _ = _request_get(candidate_url)
    if icon_r is None:
        return ""
    data = _read_capped(icon_r)
    if not data:
        return ""
    candidate_ext = _content_type_to_ext(icon_ct)

    digest = hashlib.sha1(
        f"{origin}|{candidate_url}|{len(data)}".encode("utf-8")
    ).hexdigest()[:16]
    fname = f"{digest}{candidate_ext}"
    target = favicon_dir() / fname
    try:
        target.write_bytes(data)
    except OSError as e:
        current_app.logger.warning("favicon: write %s failed: %s", target, e)
        return ""
    return fname


def favicon_path(filename: str) -> Optional[Path]:
    """Return the on-disk path for a stored favicon file, if it exists."""
    if not filename:
        return None
    # Defence in depth: refuse anything with separators.
    if "/" in filename or "\\" in filename or filename.startswith("."):
        return None
    p = favicon_dir() / filename
    if not p.is_file():
        return None
    return p


# ---------------------------------------------------------------------------
# letter-tile fallback
# ---------------------------------------------------------------------------


_TILE_COLORS = [
    "#1f6feb", "#238636", "#a371f7", "#db61a2", "#bb800a",
    "#3fb950", "#f78166", "#388bfd", "#d29922", "#8957e5",
]


def letter_tile_svg(label: str, *, size: int = 40) -> str:
    """Render a deterministic two-letter tile as inline SVG."""
    text = (label or "?").strip()
    initials = "".join(
        part[:1].upper() for part in re.split(r"\W+", text) if part
    )[:2] or "?"
    h = hashlib.sha1(text.encode("utf-8")).digest()
    bg = _TILE_COLORS[h[0] % len(_TILE_COLORS)]
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40" '
        f'width="{size}" height="{size}" aria-hidden="true">'
        f'<rect width="40" height="40" rx="8" fill="{bg}"/>'
        f'<text x="20" y="26" text-anchor="middle" font-family="system-ui,sans-serif" '
        f'font-size="18" font-weight="600" fill="#ffffff">{initials}</text>'
        f'</svg>'
    )


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------


def host_label(url: str) -> str:
    try:
        return urlparse(url).netloc or url
    except Exception:
        return url


__all__: Iterable[str] = (
    "init_db",
    "list_links",
    "get_link",
    "existing_sections",
    "create_link",
    "update_link",
    "delete_link",
    "grouped_links",
    "normalize_url",
    "normalize_title",
    "normalize_section",
    "normalize_description",
    "fetch_favicon",
    "favicon_path",
    "favicon_dir",
    "letter_tile_svg",
    "host_label",
)
