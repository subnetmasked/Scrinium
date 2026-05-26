"""Markdown extensions: wikilinks and attachment image rewriting."""
from __future__ import annotations

from html import escape
from typing import Callable, Optional
from urllib.parse import quote

from markdown import Extension
from markdown.inlinepatterns import InlineProcessor
from markdown.treeprocessors import Treeprocessor


WIKILINK_RE = r"\[\[([^\]\|]+?)(?:\|([^\]]+))?\]\]"


class RenderContext:
    """Per-request markdown rendering context."""

    doc_rel: str = ""
    all_paths: set[str] = set()
    resolve_wikilink: Optional[Callable[[str, set[str]], dict]] = None
    attachment_url: Optional[Callable[[str, str], str]] = None


_ctx = RenderContext()


def set_render_context(
    *,
    doc_rel: str,
    all_paths: set[str],
    resolve_wikilink: Callable[[str, set[str]], dict],
    attachment_url: Callable[[str, str], str],
) -> None:
    _ctx.doc_rel = doc_rel
    _ctx.all_paths = all_paths
    _ctx.resolve_wikilink = resolve_wikilink
    _ctx.attachment_url = attachment_url


def clear_render_context() -> None:
    _ctx.doc_rel = ""
    _ctx.all_paths = set()
    _ctx.resolve_wikilink = None
    _ctx.attachment_url = None


class WikiLinkProcessor(InlineProcessor):
    def handleMatch(self, m, data):  # noqa: N802
        target = (m.group(1) or "").strip()
        alias = (m.group(2) or "").strip()
        display = escape(alias or target)
        resolver = _ctx.resolve_wikilink
        paths = _ctx.all_paths
        if not resolver:
            el = self.md.htmlStash.store(f'<span class="wiki-link">{display}</span>')
            return el, m.start(0), m.end(0)

        result = resolver(target, paths)
        status = result.get("status")
        rel = result.get("rel", "")
        folder = ""
        if _ctx.doc_rel and "/" in _ctx.doc_rel:
            folder = _ctx.doc_rel.rsplit("/", 1)[0]

        if status == "resolved" and rel:
            href = f"/d/{quote(rel, safe='/')}"
            html = f'<a class="wiki-link" href="{href}">{display}</a>'
        elif status == "ambiguous" and rel:
            href = f"/d/{quote(rel, safe='/')}"
            title = result.get("title", "Multiple matches")
            html = (
                f'<a class="wiki-link wiki-ambiguous" href="{href}" '
                f'title="{title}">{display}</a>'
            )
        else:
            params = f"name={quote(target)}"
            if folder:
                params += f"&folder={quote(folder)}"
            href = f"/n?{params}"
            html = (
                f'<a class="wiki-link wiki-broken" href="{href}">{display}</a>'
            )
        el = self.md.htmlStash.store(html)
        return el, m.start(0), m.end(0)


class AttachmentImageProcessor(Treeprocessor):
    def run(self, root):
        url_fn = _ctx.attachment_url
        doc_rel = _ctx.doc_rel
        if not url_fn or not doc_rel:
            return root
        for img in root.iter("img"):
            src = img.get("src") or ""
            if not src or src.startswith(("/", "http://", "https://", "data:")):
                continue
            img.set("src", url_fn(doc_rel, src))
            img.set("loading", "lazy")
            img.set("decoding", "async")
        return root


class ScriniumExtension(Extension):
    def extendMarkdown(self, md):  # noqa: N802
        md.inlinePatterns.register(
            WikiLinkProcessor(WIKILINK_RE, md), "wikilink", 175
        )
        md.treeprocessors.register(AttachmentImageProcessor(md), "attachments", 15)


def makeExtension(**kwargs):  # noqa: N802
    return ScriniumExtension(**kwargs)


__all__ = (
    "WIKILINK_RE",
    "clear_render_context",
    "makeExtension",
    "set_render_context",
)
