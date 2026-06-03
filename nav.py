"""Navigation: categories config, sidebar tree, breadcrumbs, dashboard data.

Categories are admin-defined groupings. Each top-level folder under DATA_DIR
whose name matches a category slug is treated as that category's content. The
folder under it (one level deeper) is an "entry" — e.g. a server, an app, a
network device. Inside an entry you can have any number of markdown documents
or further nested folders. Anything else at the top level is either a "loose"
markdown document (.md directly under DATA_DIR) or shows up under "Other".
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Iterable, Optional


MD_EXT = ".md"

# Folders that are part of Scrinium's storage layout but should never
# appear in any user-facing listing (sidebar tree, folder views, etc.).
HIDDEN_DIRS = frozenset({"_attachments"})


def is_hidden_entry(name: str) -> bool:
    """True for dotfiles and any backend-only directory name."""
    return name.startswith(".") or name in HIDDEN_DIRS

RESERVED_SLUGS = {
    "new", "edit", "delete", "admin", "static", "api", "loose", "other",
    "login", "logout", "setup", "search", "health", "dash",
    "c", "d", "e", "f", "n", "s", "a",
    "security", "itsm",
}

DEFAULT_CATEGORIES: list[dict] = [
    {
        "slug": "servers",
        "name": "Servers",
        "noun": "server",
        "icon": "server",
        "description": "Physical hosts and virtual machines.",
    },
    {
        "slug": "applications",
        "name": "Applications",
        "noun": "application",
        "icon": "box",
        "description": "Software and services running for the org.",
    },
    {
        "slug": "network",
        "name": "Network",
        "noun": "device",
        "icon": "network",
        "description": "Switches, routers, firewalls, and other gear.",
    },
]


# Inline SVG icons (Lucide-derived, MIT). Each value is the inner contents of
# <svg viewBox="0 0 24 24">. Keep the list short and curated -- this is a
# picker, not a full icon set.
ICON_LIBRARY: dict[str, str] = {
    "server": (
        '<rect x="3" y="4" width="18" height="7" rx="2"/>'
        '<rect x="3" y="13" width="18" height="7" rx="2"/>'
        '<line x1="6" y1="7.5" x2="6.01" y2="7.5"/>'
        '<line x1="6" y1="16.5" x2="6.01" y2="16.5"/>'
    ),
    "box": (
        '<path d="M21 8a2 2 0 0 0-1-1.73L13 2.27a2 2 0 0 0-2 0L4 6.27A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4.04a2 2 0 0 0 2 0l7-4.04A2 2 0 0 0 21 16Z"/>'
        '<polyline points="3.27 6.96 12 12.01 20.73 6.96"/>'
        '<line x1="12" y1="22.08" x2="12" y2="12"/>'
    ),
    "network": (
        '<rect x="2" y="2.5" width="6" height="6" rx="1"/>'
        '<rect x="16" y="2.5" width="6" height="6" rx="1"/>'
        '<rect x="9" y="15.5" width="6" height="6" rx="1"/>'
        '<path d="M5 8.5v3h14v-3M12 11.5v4"/>'
    ),
    "database": (
        '<ellipse cx="12" cy="5" rx="9" ry="3"/>'
        '<path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/>'
        '<path d="M3 12c0 1.66 4.03 3 9 3s9-1.34 9-3"/>'
    ),
    "cloud": (
        '<path d="M17.5 19a4.5 4.5 0 1 0 0-9c-.13 0-.27 0-.4.02A6 6 0 0 0 5.5 11a4 4 0 0 0 .5 8h11.5z"/>'
    ),
    "shield": (
        '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
    ),
    "lock": (
        '<rect x="3.5" y="11" width="17" height="10" rx="2"/>'
        '<path d="M7.5 11V7a4.5 4.5 0 0 1 9 0v4"/>'
    ),
    "key": (
        '<circle cx="8" cy="15" r="4"/>'
        '<path d="m21 2-9.5 9.5M16 7l3 3"/>'
    ),
    "folder": (
        '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>'
    ),
    "globe": (
        '<circle cx="12" cy="12" r="9"/>'
        '<path d="M3 12h18"/>'
        '<path d="M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>'
    ),
    "cpu": (
        '<rect x="6" y="6" width="12" height="12" rx="1"/>'
        '<rect x="9.5" y="9.5" width="5" height="5"/>'
        '<path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 5l-2 2M5 19l2-2M17 19l-2-2"/>'
    ),
    "terminal": (
        '<rect x="2" y="4" width="20" height="16" rx="2"/>'
        '<polyline points="6 9 10 12 6 15"/>'
        '<line x1="12" y1="15" x2="18" y2="15"/>'
    ),
    "monitor": (
        '<rect x="2.5" y="3.5" width="19" height="13" rx="2"/>'
        '<line x1="8" y1="21" x2="16" y2="21"/>'
        '<line x1="12" y1="16.5" x2="12" y2="21"/>'
    ),
    "wifi": (
        '<path d="M5 12.55a11 11 0 0 1 14 0"/>'
        '<path d="M2 8.82a16 16 0 0 1 20 0"/>'
        '<path d="M8.5 16.43a6 6 0 0 1 7 0"/>'
        '<line x1="12" y1="20" x2="12.01" y2="20"/>'
    ),
    "code": (
        '<polyline points="16 18 22 12 16 6"/>'
        '<polyline points="8 6 2 12 8 18"/>'
    ),
    "tag": (
        '<path d="M20.59 13.41 13 21a2 2 0 0 1-2.83 0L2 12.83V3h9.83L20.59 11.59a2 2 0 0 1 0 2.83Z"/>'
        '<line x1="7" y1="7" x2="7.01" y2="7"/>'
    ),
    "circle": (
        '<circle cx="12" cy="12" r="9"/>'
    ),
}

DEFAULT_ICON = "folder"


def icon_svg(name: str | None, *, css_class: str = "icon-svg") -> str:
    """Return inline SVG for the named icon, or a fallback."""
    inner = ICON_LIBRARY.get(name or "") or ICON_LIBRARY[DEFAULT_ICON]
    return (
        f'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" '
        f'class="{css_class}" aria-hidden="true">{inner}</svg>'
    )

OVERVIEW_CANDIDATES = ("overview.md", "_index.md", "README.md", "readme.md")


# ---------------------------------------------------------------------------
# slugs
# ---------------------------------------------------------------------------


_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{0,38}[a-z0-9])?$")


def normalize_slug(value: str) -> str:
    s = (value or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")


def is_valid_slug(slug: str) -> bool:
    if not slug or slug in RESERVED_SLUGS:
        return False
    return bool(_SLUG_RE.match(slug))


# ---------------------------------------------------------------------------
# categories config I/O
# ---------------------------------------------------------------------------


def categories_path(config_dir: Path) -> Path:
    return config_dir / "categories.json"


def load_categories(config_dir: Path) -> list[dict]:
    p = categories_path(config_dir)
    if not p.exists():
        save_categories(config_dir, DEFAULT_CATEGORIES)
        return [dict(c) for c in DEFAULT_CATEGORIES]
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, list):
        return []
    cleaned: list[dict] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        slug = entry.get("slug")
        if not slug or not is_valid_slug(slug):
            continue
        icon = entry.get("icon") or DEFAULT_ICON
        if icon not in ICON_LIBRARY:
            icon = DEFAULT_ICON
        cleaned.append(
            {
                "slug": slug,
                "name": entry.get("name") or slug.title(),
                "noun": entry.get("noun") or "entry",
                "icon": icon,
                "description": entry.get("description") or "",
                "restricted": bool(entry.get("restricted")),
                "allowed_users": _normalize_allowed_users(
                    entry.get("allowed_users")
                ),
                "allowed_groups": _normalize_allowed_groups(
                    entry.get("allowed_groups")
                ),
            }
        )
    return cleaned


def _normalize_allowed_users(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        name = str(item).strip().lower()
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _normalize_allowed_groups(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        name = str(item).strip().lower()
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def save_categories(config_dir: Path, categories: list[dict]) -> None:
    p = categories_path(config_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    serialised = []
    for c in categories:
        if not c.get("slug"):
            continue
        icon = c.get("icon") or DEFAULT_ICON
        if icon not in ICON_LIBRARY:
            icon = DEFAULT_ICON
        serialised.append(
            {
                "slug": c["slug"],
                "name": c.get("name") or c["slug"],
                "noun": c.get("noun") or "entry",
                "icon": icon,
                "description": c.get("description") or "",
                "restricted": bool(c.get("restricted")),
                "allowed_users": _normalize_allowed_users(
                    c.get("allowed_users")
                ),
                "allowed_groups": _normalize_allowed_groups(
                    c.get("allowed_groups")
                ),
            }
        )
    p.write_text(json.dumps(serialised, indent=2) + "\n", encoding="utf-8")


def find_category(categories: list[dict], slug: str) -> Optional[dict]:
    for c in categories:
        if c.get("slug") == slug:
            return c
    return None


def category_slug_for_path(rel_path: str) -> Optional[str]:
    """Return the top-level category slug for a doc/folder path, or None."""
    parts = [p for p in (rel_path or "").split("/") if p]
    return parts[0] if parts else None


def user_can_access_category(
    slug: str,
    user: Optional[dict],
    cats: list[dict],
) -> bool:
    if not slug:
        return True
    if user and user.get("is_admin"):
        return True
    cat = find_category(cats, slug)
    if cat is None or not cat.get("restricted"):
        return True
    if not user:
        return False
    allowed = {u.lower() for u in cat.get("allowed_users") or []}
    if user["username"].lower() in allowed:
        return True
    allowed_groups = {g.lower() for g in cat.get("allowed_groups") or []}
    user_groups = {g.lower() for g in user.get("groups") or []}
    return bool(allowed_groups & user_groups)


def accessible_category_slugs(
    user: Optional[dict], cats: list[dict]
) -> set[str]:
    return {
        c["slug"]
        for c in cats
        if c.get("slug") and user_can_access_category(c["slug"], user, cats)
    }


def path_is_accessible(
    rel_path: str,
    user: Optional[dict],
    cats: list[dict],
) -> bool:
    slug = category_slug_for_path(rel_path)
    if slug is None:
        return True
    cat_slugs = {c["slug"] for c in cats if c.get("slug")}
    if slug not in cat_slugs:
        return True
    return user_can_access_category(slug, user, cats)


def filter_accessible_paths(
    paths: Iterable[str],
    user: Optional[dict],
    cats: list[dict],
) -> set[str]:
    return {p for p in paths if path_is_accessible(p, user, cats)}


# ---------------------------------------------------------------------------
# tree helpers
# ---------------------------------------------------------------------------


def doc_rel(path: Path, root: Path) -> str:
    rel = path.relative_to(root)
    s = str(rel).replace("\\", "/")
    if s.endswith(MD_EXT):
        s = s[: -len(MD_EXT)]
    return s


def _list_dir(path: Path) -> list[Path]:
    try:
        return sorted(
            path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())
        )
    except OSError:
        return []


def build_tree(folder: Path, root: Path) -> dict:
    """Recursively walk a folder and return {folders, docs} with hidden
    entries skipped. `root` is DATA_DIR, used to compute display-friendly
    relative paths."""
    folders: list[dict] = []
    docs: list[dict] = []
    if not folder.exists():
        return {"folders": folders, "docs": docs}
    for entry in _list_dir(folder):
        if is_hidden_entry(entry.name):
            continue
        if entry.is_dir():
            folders.append(
                {
                    "name": entry.name,
                    "rel": doc_rel(entry, root),
                    "children": build_tree(entry, root),
                }
            )
        elif entry.is_file() and entry.suffix == MD_EXT:
            docs.append({"name": entry.stem, "rel": doc_rel(entry, root)})
    return {"folders": folders, "docs": docs}


def find_overview(folder: Path) -> Optional[Path]:
    for name in OVERVIEW_CANDIDATES:
        candidate = folder / name
        if candidate.is_file():
            return candidate
    return None


_TAG_LINE_RE = re.compile(r"^\s*tags?\s*:\s*(.+?)\s*$", re.IGNORECASE)


def parse_overview_tags(path: Optional[Path]) -> list[str]:
    """Extract tags from YAML frontmatter or legacy ``tags:`` line."""
    if not path:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []

    try:
        import frontmatter as fm_mod

        parsed, _body = fm_mod.parse(text)
        tags = parsed.get("tags")
        if isinstance(tags, list):
            out: list[str] = []
            seen: set[str] = set()
            for t in tags:
                s = str(t).strip().lstrip("#").strip()
                if s and s.lower() not in seen:
                    seen.add(s.lower())
                    out.append(s)
            if out:
                return out
    except Exception:
        pass

    try:
        with path.open(encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= 25:
                    break
                m = _TAG_LINE_RE.match(line)
                if m:
                    parts = re.split(r"[,;]", m.group(1))
                    seen: set[str] = set()
                    out: list[str] = []
                    for p in parts:
                        t = p.strip().lstrip("#").strip()
                        if t and t.lower() not in seen:
                            seen.add(t.lower())
                            out.append(t)
                    return out
    except OSError:
        return []
    return []


def resolve_wikilink(target: str, all_paths: set[str]) -> dict:
    """Resolve ``[[target]]`` against known doc paths.

    Returns a dict with ``status`` in ``resolved``, ``ambiguous``, ``broken``
    and optional ``rel`` / ``title``.
    """
    raw = (target or "").strip().strip("/")
    if not raw:
        return {"status": "broken"}

    norm = raw.replace("\\", "/").strip("/")
    lower_map = {p.lower(): p for p in all_paths}

    if norm in all_paths:
        return {"status": "resolved", "rel": norm}

    exact_ci = lower_map.get(norm.lower())
    if exact_ci:
        return {"status": "resolved", "rel": exact_ci}

    stem = norm.rsplit("/", 1)[-1].lower()
    stem_matches = sorted(
        p for p in all_paths if p.rsplit("/", 1)[-1].lower() == stem
    )
    if len(stem_matches) == 1:
        return {"status": "resolved", "rel": stem_matches[0]}
    if len(stem_matches) > 1:
        chosen = stem_matches[0]
        title = "Multiple matches: " + ", ".join(stem_matches[:5])
        if len(stem_matches) > 5:
            title += ", ..."
        return {
            "status": "ambiguous",
            "rel": chosen,
            "title": title,
            "matches": stem_matches,
        }
    return {"status": "broken"}


def count_descendant_docs(node: dict) -> int:
    n = len(node.get("docs") or [])
    for f in node.get("folders") or []:
        n += count_descendant_docs(f.get("children") or {"folders": [], "docs": []})
    return n


# ---------------------------------------------------------------------------
# sidebar navigation
# ---------------------------------------------------------------------------


def build_navigation(
    root: Path,
    categories: list[dict],
    *,
    user: Optional[dict] = None,
) -> dict:
    """Group the top of the data tree by category for the sidebar."""
    if user is not None:
        categories = [
            c
            for c in categories
            if user_can_access_category(c.get("slug") or "", user, categories)
        ]
    cat_slugs = {c["slug"] for c in categories if c.get("slug")}

    loose_docs: list[dict] = []
    other_folders: list[dict] = []

    if root.exists():
        for entry in _list_dir(root):
            if is_hidden_entry(entry.name):
                continue
            if entry.is_file() and entry.suffix == MD_EXT:
                loose_docs.append(
                    {"name": entry.stem, "rel": doc_rel(entry, root)}
                )
            elif entry.is_dir() and entry.name not in cat_slugs:
                other_folders.append(
                    {
                        "name": entry.name,
                        "rel": doc_rel(entry, root),
                        "children": build_tree(entry, root),
                    }
                )

    cats_with_data: list[dict] = []
    for cat in categories:
        slug = cat.get("slug")
        if not slug:
            continue
        cat_path = root / slug
        entries: list[dict] = []
        if cat_path.is_dir():
            for child in _list_dir(cat_path):
                if is_hidden_entry(child.name):
                    continue
                if child.is_dir():
                    sub = build_tree(child, root)
                    overview = find_overview(child)
                    entries.append(
                        {
                            "kind": "entry",
                            "name": child.name,
                            "rel": doc_rel(child, root),
                            "doc_count": count_descendant_docs(sub),
                            "children": sub,
                            "tags": parse_overview_tags(overview),
                            "overview_rel": (
                                doc_rel(overview, root) if overview else None
                            ),
                        }
                    )
                elif child.is_file() and child.suffix == MD_EXT:
                    entries.append(
                        {
                            "kind": "doc",
                            "name": child.stem,
                            "rel": doc_rel(child, root),
                        }
                    )
        cats_with_data.append(
            {
                "slug": slug,
                "name": cat.get("name") or slug.title(),
                "noun": cat.get("noun") or "entry",
                "icon": cat.get("icon") or DEFAULT_ICON,
                "description": cat.get("description") or "",
                "entries": entries,
                "entry_count": sum(1 for e in entries if e["kind"] == "entry"),
            }
        )

    return {
        "loose": loose_docs,
        "categories": cats_with_data,
        "other": other_folders,
    }


# ---------------------------------------------------------------------------
# breadcrumbs
# ---------------------------------------------------------------------------


def relative_time(ts: float, now: Optional[float] = None) -> str:
    """Render an mtime/ctime as a short, human-friendly relative string."""
    now = now if now is not None else time.time()
    diff = max(0.0, now - ts)
    if diff < 60:
        return "just now"
    if diff < 3600:
        m = int(diff // 60)
        return f"{m}m ago"
    if diff < 86400:
        h = int(diff // 3600)
        return f"{h}h ago"
    if diff < 86400 * 2:
        return "yesterday"
    if diff < 86400 * 14:
        d = int(diff // 86400)
        return f"{d}d ago"
    if diff < 86400 * 60:
        w = int(diff // (86400 * 7))
        return f"{w}w ago"
    if diff < 86400 * 365:
        mo = int(diff // (86400 * 30))
        return f"{mo}mo ago"
    y = int(diff // (86400 * 365))
    return f"{y}y ago"


def find_entries_with_tag(
    root: Path,
    categories: list[dict],
    tag: str,
    *,
    user: Optional[dict] = None,
) -> list[dict]:
    """Return entries whose overview's tags list includes the given tag
    (case-insensitive)."""
    target = tag.strip().lstrip("#").lower()
    if not target:
        return []
    matches: list[dict] = []
    for cat in categories:
        slug = cat.get("slug")
        if not slug:
            continue
        if user is not None and not user_can_access_category(slug, user, categories):
            continue
        cat_path = root / slug
        if not cat_path.is_dir():
            continue
        for child in _list_dir(cat_path):
            if not child.is_dir() or child.name.startswith("."):
                continue
            ov = find_overview(child)
            tags = parse_overview_tags(ov)
            if any(t.lower() == target for t in tags):
                try:
                    mtime = (ov or child).stat().st_mtime
                except OSError:
                    mtime = 0.0
                matches.append(
                    {
                        "name": child.name,
                        "rel": doc_rel(child, root),
                        "tags": tags,
                        "mtime": mtime,
                        "category": cat,
                    }
                )
    matches.sort(key=lambda m: m["name"].lower())
    return matches


def dashboard_data(
    root: Path,
    categories: list[dict],
    *,
    recent_doc_limit: int = 6,
    recent_entry_limit: int = 6,
    tag_limit: int = 30,
    user: Optional[dict] = None,
) -> dict:
    """Compute everything the dashboard template needs in a single pass."""
    if user is not None:
        categories = [
            c
            for c in categories
            if user_can_access_category(c.get("slug") or "", user, categories)
        ]
    cat_map = {c["slug"]: c for c in categories if c.get("slug")}
    cat_doc_counts: dict[str, int] = {s: 0 for s in cat_map}
    cat_entry_set: dict[str, set[str]] = {s: set() for s in cat_map}

    docs: list[dict] = []
    if root.exists():
        for p in root.rglob(f"*{MD_EXT}"):
            try:
                rel = p.relative_to(root)
            except ValueError:
                continue
            parts = rel.parts
            if any(is_hidden_entry(part) for part in parts):
                continue
            try:
                stat = p.stat()
            except OSError:
                continue

            location = "Loose document"
            if len(parts) >= 2 and parts[0] in cat_map:
                cat = cat_map[parts[0]]
                if user is not None and not user_can_access_category(
                    parts[0], user, categories
                ):
                    continue
                cat_doc_counts[parts[0]] += 1
                if len(parts) >= 3:
                    cat_entry_set[parts[0]].add(parts[1])
                    location = f"{cat['name']} · {parts[1]}"
                else:
                    location = cat["name"]
            elif len(parts) >= 2:
                location = "/".join(parts[:-1])

            docs.append(
                {
                    "rel": doc_rel(p, root),
                    "title": p.stem,
                    "mtime": stat.st_mtime,
                    "location": location,
                }
            )

    recent_docs = sorted(docs, key=lambda d: d["mtime"], reverse=True)[
        :recent_doc_limit
    ]

    entries: list[dict] = []
    tag_counter: dict[str, int] = {}
    for cat in categories:
        slug = cat.get("slug")
        if not slug:
            continue
        cat_path = root / slug
        if not cat_path.is_dir():
            continue
        for child in _list_dir(cat_path):
            if not child.is_dir() or child.name.startswith("."):
                continue
            try:
                ctime = child.stat().st_ctime
            except OSError:
                ctime = 0.0
            ov = find_overview(child)
            tags = parse_overview_tags(ov)
            for t in tags:
                tag_counter[t] = tag_counter.get(t, 0) + 1
            entries.append(
                {
                    "name": child.name,
                    "rel": doc_rel(child, root),
                    "ctime": ctime,
                    "tags": tags,
                    "category_name": cat.get("name") or slug,
                    "category_slug": slug,
                    "category_icon": cat.get("icon") or DEFAULT_ICON,
                }
            )

    recent_entries = sorted(entries, key=lambda e: e["ctime"], reverse=True)[
        :recent_entry_limit
    ]

    cat_stats = []
    for cat in categories:
        slug = cat.get("slug")
        if not slug:
            continue
        cat_stats.append(
            {
                **cat,
                "entry_count": len(cat_entry_set.get(slug, set())),
                "doc_count": cat_doc_counts.get(slug, 0),
            }
        )

    tag_cloud = [
        {"name": k, "count": v}
        for k, v in sorted(
            tag_counter.items(), key=lambda kv: (-kv[1], kv[0].lower())
        )
    ][:tag_limit]

    return {
        "total_docs": len(docs),
        "total_entries": len(entries),
        "total_tags": len(tag_counter),
        "categories": cat_stats,
        "recent_docs": recent_docs,
        "recent_entries": recent_entries,
        "tag_cloud": tag_cloud,
    }


def breadcrumbs(rel: str, leaf_kind: str = "doc") -> list[dict]:
    parts = [p for p in rel.split("/") if p]
    crumbs: list[dict] = []
    acc = ""
    for i, part in enumerate(parts):
        acc = f"{acc}/{part}" if acc else part
        last = i == len(parts) - 1
        crumbs.append(
            {
                "name": part,
                "rel": acc,
                "is_leaf": last,
                "is_doc_leaf": last and leaf_kind == "doc",
                "is_folder_leaf": last and leaf_kind == "folder",
            }
        )
    return crumbs


__all__: Iterable[str] = (
    "DEFAULT_CATEGORIES",
    "RESERVED_SLUGS",
    "OVERVIEW_CANDIDATES",
    "ICON_LIBRARY",
    "DEFAULT_ICON",
    "icon_svg",
    "load_categories",
    "save_categories",
    "find_category",
    "category_slug_for_path",
    "user_can_access_category",
    "accessible_category_slugs",
    "path_is_accessible",
    "filter_accessible_paths",
    "find_overview",
    "parse_overview_tags",
    "resolve_wikilink",
    "doc_rel",
    "build_tree",
    "build_navigation",
    "breadcrumbs",
    "is_valid_slug",
    "normalize_slug",
    "count_descendant_docs",
    "relative_time",
    "dashboard_data",
    "find_entries_with_tag",
    "_normalize_allowed_groups",
)
