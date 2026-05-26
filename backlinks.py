"""Backlinks index for Scrinium.

Walks every markdown file in the data dir, extracts ``[[wikilinks]]`` and
resolvable markdown links, and builds a reverse map ``target_rel -> [Backlink]``
used by the ``_backlinks.html`` panel on doc and entry pages.

Results are cached in-process keyed on the max mtime of the vault, so back-to-
back requests don't re-walk the tree.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import unquote, urlparse

import frontmatter
import nav
from markdown_ext import WIKILINK_RE as _WIKILINK_RE_PATTERN


WIKILINK_RE = re.compile(_WIKILINK_RE_PATTERN)
MD_LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")

MD_EXT = ".md"

_CACHE: dict[str, Any] = {}


@dataclass(frozen=True)
class Backlink:
    source_rel: str
    snippet: str


def _max_mtime(data_dir: Path) -> float:
    latest = 0.0
    if not data_dir.exists():
        return latest
    for p in data_dir.rglob(f"*{MD_EXT}"):
        try:
            if any(part.startswith(".") for part in p.relative_to(data_dir).parts):
                continue
            latest = max(latest, p.stat().st_mtime)
        except (OSError, ValueError):
            continue
    return latest


def _iter_md_files(data_dir: Path) -> list[Path]:
    out: list[Path] = []
    if not data_dir.exists():
        return out
    for p in data_dir.rglob(f"*{MD_EXT}"):
        try:
            rel_parts = p.relative_to(data_dir).parts
        except ValueError:
            continue
        if any(part.startswith(".") for part in rel_parts):
            continue
        out.append(p)
    return out


def _normalize_link_target(raw: str, source_rel: str) -> str:
    target = (raw or "").strip()
    if not target or target.startswith("#"):
        return ""
    if "://" in target:
        parsed = urlparse(target)
        if parsed.scheme in {"http", "https"}:
            path = (parsed.path or "").lstrip("/")
            if path.endswith(MD_EXT):
                path = path[: -len(MD_EXT)]
            return path.strip("/")
        return ""
    if target.startswith("/"):
        target = target.lstrip("/")
    if target.endswith(MD_EXT):
        target = target[: -len(MD_EXT)]
    if target.startswith("./"):
        target = target[2:]
    if not target:
        return ""
    if "/" not in target and source_rel:
        parent = source_rel.rsplit("/", 1)[0] if "/" in source_rel else ""
        return f"{parent}/{target}".strip("/") if parent else target
    return target.strip("/")


def _resolve_target(target: str, all_paths: set[str]) -> Optional[str]:
    result = nav.resolve_wikilink(target, all_paths)
    if result.get("status") in {"resolved", "ambiguous"}:
        return result.get("rel")
    return None


def _snippet(text: str, needle: str, width: int = 120) -> str:
    lower = text.lower()
    i = lower.find(needle.lower())
    if i < 0:
        return text[:width].replace("\n", " ").strip()
    start = max(0, i - width // 2)
    end = min(len(text), i + len(needle) + width // 2)
    snip = text[start:end].replace("\n", " ").strip()
    if start > 0:
        snip = "... " + snip
    if end < len(text):
        snip = snip + " ..."
    return snip


def _extract_references(
    text: str, source_rel: str, all_paths: set[str]
) -> list[tuple[str, str]]:
    """Return list of (target_rel, snippet_needle) for resolved links only."""
    refs: list[tuple[str, str]] = []
    seen: set[str] = set()

    for m in WIKILINK_RE.finditer(text):
        target_raw = m.group(1).strip()
        resolved = _resolve_target(target_raw, all_paths)
        if resolved and resolved not in seen:
            seen.add(resolved)
            refs.append((resolved, target_raw))

    for m in MD_LINK_RE.finditer(text):
        raw = unquote(m.group(2).strip())
        norm = _normalize_link_target(raw, source_rel)
        if not norm:
            continue
        resolved = _resolve_target(norm, all_paths) or (
            norm if norm in all_paths else None
        )
        if resolved and resolved not in seen:
            seen.add(resolved)
            refs.append((resolved, m.group(1) or norm))

    return refs


def _scan(data_dir: Path, all_paths: set[str]) -> dict[str, list[Backlink]]:
    reverse: dict[str, list[Backlink]] = {}
    for path in _iter_md_files(data_dir):
        source_rel = nav.doc_rel(path, data_dir)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        _, body = frontmatter.parse(text)
        for target, needle in _extract_references(body, source_rel, all_paths):
            reverse.setdefault(target, []).append(
                Backlink(source_rel=source_rel, snippet=_snippet(body, needle))
            )
    for blist in reverse.values():
        blist.sort(key=lambda b: b.source_rel.lower())
    return reverse


def _ensure_scan(data_dir: Path, all_paths: set[str]) -> None:
    mtime = _max_mtime(data_dir)
    key = (str(data_dir), tuple(sorted(all_paths)))
    if _CACHE.get("key") == key and _CACHE.get("mtime") == mtime:
        return
    reverse = _scan(data_dir, all_paths)
    _CACHE.clear()
    _CACHE.update({"key": key, "mtime": mtime, "reverse": reverse})


def build_index(data_dir: Path, all_paths: set[str]) -> dict[str, list[Backlink]]:
    _ensure_scan(data_dir, all_paths)
    return _CACHE["reverse"]


def backlinks_for(data_dir: Path, all_paths: set[str], doc_rel: str) -> list[Backlink]:
    return build_index(data_dir, all_paths).get(doc_rel, [])


__all__ = (
    "Backlink",
    "backlinks_for",
    "build_index",
)
