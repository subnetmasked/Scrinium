"""YAML frontmatter parsing and serialization for Scrinium markdown docs."""
from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any, Iterable, Optional

import yaml


_FRONTMATTER_RE = re.compile(
    r"^---\r?\n(.*?)\r?\n---\r?\n?",
    re.DOTALL,
)

# Legacy alias — kept for imports; prefer INFBOX_BASE_ORDER + CATEGORY_FIELDS.
DEFAULT_KEYS = ("title", "created", "tags", "owner", "status", "reviewed")

# Display / serialization order for keys shared by every document type.
INFBOX_BASE_ORDER = (
    "title",
    "hostname",
    "created",
    "updated",
    "tags",
    "owner",
    "contact",
    "status",
    "reviewed",
)

# Optional keys seeded (empty) on new docs when no category schema matches.
GENERIC_TEMPLATE_KEYS = (
    "hostname",
    "ip",
    "url",
    "location",
    "owner",
    "contact",
    "status",
    "reviewed",
)

COMMON_TEMPLATE_KEYS = ("owner", "contact", "status", "reviewed")

# Category-specific fields a sysadmin would expect on an entry overview.
# Keys listed here are written into new entry overviews as empty placeholders
# and shown in the infobox only once filled in.
CATEGORY_FIELDS: dict[str, tuple[str, ...]] = {
    "servers": (
        "hostname",
        "ip",
        "vlan",
        "os",
        "role",
        "environment",
        "location",
        "serial",
        "vendor",
        "model",
    ),
    "applications": (
        "url",
        "version",
        "environment",
        "host",
        "port",
        "protocol",
        "vendor",
        "license_expiry",
    ),
    "network": (
        "hostname",
        "ip",
        "vlan",
        "device_type",
        "model",
        "serial",
        "firmware",
        "location",
        "site",
    ),
}

# Vault path of the doc (synthesised at render time, not stored in YAML).
SYNTHESIZED_KEYS = frozenset({"updated", "folder"})


def parse(text: str) -> tuple[dict[str, Any], str]:
    """Split leading YAML frontmatter from markdown body.

    Returns ``({}, text)`` when no valid frontmatter block is present.
    """
    if not text:
        return {}, ""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text
    raw = m.group(1)
    try:
        loaded = yaml.safe_load(raw)
    except yaml.YAMLError:
        return {}, text
    if not isinstance(loaded, dict):
        return {}, text
    body = text[m.end() :]
    return loaded, body


def infer_category(rel: str, known_slugs: Iterable[str] | None = None) -> Optional[str]:
    """Return the top-level category slug for a doc path, if recognised."""
    parts = [p for p in rel.split("/") if p]
    if not parts:
        return None
    slug = parts[0]
    known = frozenset(known_slugs or CATEGORY_FIELDS.keys())
    return slug if slug in known else None


def is_empty(value: Any) -> bool:
    """True when a frontmatter value should be hidden from the infobox."""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, dict)):
        return len(value) == 0
    return False


def _field_order(category: Optional[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    keys: list[str] = []
    for k in INFBOX_BASE_ORDER:
        keys.append(k)
        seen.add(k)
    if category and category in CATEGORY_FIELDS:
        for k in CATEGORY_FIELDS[category]:
            if k not in seen:
                keys.append(k)
                seen.add(k)
    for k in ("folder",):
        if k not in seen:
            keys.append(k)
            seen.add(k)
    return tuple(keys)


def _ordered_keys(fm: dict[str, Any], category: Optional[str] = None) -> list[str]:
    seen: set[str] = set()
    keys: list[str] = []
    for k in _field_order(category):
        if k in fm:
            keys.append(k)
            seen.add(k)
    for k in sorted(fm.keys()):
        if k not in seen:
            keys.append(k)
    return keys


def _normalize(value: Any) -> Any:
    """Convert non-YAML-friendly types to representable equivalents."""
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    return value


def _strip_yaml_markers(text: str) -> str:
    lines = [
        ln for ln in text.splitlines()
        if ln.strip() not in ("---", "...")
    ]
    return "\n".join(lines)


def serialize(fm: dict[str, Any], body: str, *, category: Optional[str] = None) -> str:
    """Rebuild a markdown file with stable frontmatter key order."""
    if not fm:
        return body
    ordered = {k: _normalize(fm[k]) for k in _ordered_keys(fm, category)}
    yaml_text = yaml.safe_dump(
        ordered,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        indent=2,
    )
    yaml_text = _strip_yaml_markers(yaml_text).strip("\n")
    body = body.lstrip("\n")
    if body:
        return f"---\n{yaml_text}\n---\n\n{body}"
    return f"---\n{yaml_text}\n---\n"


def default_frontmatter(
    title: str,
    *,
    tags: list[str] | None = None,
    category: str | None = None,
) -> dict[str, Any]:
    """Starter frontmatter for newly created documents.

    Category entry overviews get a fuller template (IP, VLAN, owner, …)
    with empty values so editors know what to fill in. Empty values are
    omitted from the infobox at render time.
    """
    fm: dict[str, Any] = {
        "title": title,
        "created": date.today().isoformat(),
        "tags": list(tags or []),
    }

    if category and category in CATEGORY_FIELDS:
        template_keys = list(COMMON_TEMPLATE_KEYS) + list(CATEGORY_FIELDS[category])
    else:
        template_keys = list(GENERIC_TEMPLATE_KEYS)

    for key in template_keys:
        if key in fm:
            continue
        fm[key] = ""

    if category in ("servers", "network"):
        fm["hostname"] = title

    return fm


def fm_rows(
    fm: dict[str, Any],
    category: Optional[str] = None,
) -> list[tuple[str, Any]]:
    """Frontmatter keys in display order for the infobox, omitting empty values."""
    return [
        (k, fm[k])
        for k in _ordered_keys(fm, category)
        if not is_empty(fm[k])
    ]


def default_frontmatter_text(
    title: str,
    *,
    category: Optional[str] = None,
    tags: list[str] | None = None,
) -> str:
    """Return the category-aware default YAML block as a string.

    Includes the leading and trailing ``---`` delimiters and a trailing
    newline, ready to be prepended to a markdown body. Empty placeholder
    values are kept so the editor sees the full template.
    """
    fm = default_frontmatter(title, tags=tags, category=category)
    block = serialize(fm, "", category=category)
    return block.rstrip("\n") + "\n"


def has_frontmatter(text: str) -> bool:
    """True iff ``text`` starts with a valid YAML frontmatter block."""
    if not text:
        return False
    fm, _ = parse(text)
    return bool(fm)


__all__ = (
    "CATEGORY_FIELDS",
    "DEFAULT_KEYS",
    "INFBOX_BASE_ORDER",
    "default_frontmatter",
    "default_frontmatter_text",
    "fm_rows",
    "has_frontmatter",
    "infer_category",
    "is_empty",
    "parse",
    "serialize",
)
