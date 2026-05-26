"""Scrinium - a small, markdown-native IT documentation app."""
from __future__ import annotations

import logging
import os
import secrets
import shutil
import sys
from datetime import timedelta
from pathlib import Path
from typing import Optional

import markdown
from flask import (
    Flask,
    Response,
    abort,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

import auth
import links
import nav


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------


DATA_DIR = Path(os.environ.get("SCRINIUM_DATA", "/data")).resolve()
CONFIG_DIR = Path(
    os.environ.get("SCRINIUM_CONFIG", str(DATA_DIR / ".scrinium"))
).resolve()
HOST = os.environ.get("SCRINIUM_HOST", "0.0.0.0")
PORT = int(os.environ.get("SCRINIUM_PORT", "8080"))
SITE_NAME = os.environ.get("SCRINIUM_SITE_NAME", "Scrinium")
HTTPS_ONLY = os.environ.get("SCRINIUM_HTTPS_ONLY", "0") == "1"
TRUST_PROXY = os.environ.get("SCRINIUM_TRUST_PROXY", "0") == "1"
APP_VERSION = "0.6.0"
PROJECT_URL = "https://github.com/subnetmasked/Scrinium"
AUTHOR_NAME = "subnetmasked"
AUTHOR_URL = "https://github.com/subnetmasked"
LICENSE_NAME = "GPL-3.0-or-later"

MD_EXT = ".md"
_BAD_PATH_CHARS = set('/\\:*?"<>|')

CONFIG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)


def _load_secret_key() -> bytes:
    env = os.environ.get("SCRINIUM_SECRET_KEY")
    if env:
        return env.encode()
    key_file = CONFIG_DIR / "secret.key"
    if key_file.exists():
        return key_file.read_bytes()
    key = secrets.token_bytes(32)
    key_file.write_bytes(key)
    try:
        key_file.chmod(0o600)
    except OSError:
        pass
    return key


logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

app = Flask(__name__)
app.config.update(
    SITE_NAME=SITE_NAME,
    SECRET_KEY=_load_secret_key(),
    AUTH_DB=str(CONFIG_DIR / "auth.db"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=HTTPS_ONLY,
    PERMANENT_SESSION_LIFETIME=timedelta(days=14),
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,
)

if TRUST_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

auth.init_db(Path(app.config["AUTH_DB"]))
links.init_db(Path(app.config["AUTH_DB"]))
nav.load_categories(CONFIG_DIR)


md_renderer = markdown.Markdown(
    extensions=[
        "fenced_code",
        "tables",
        "toc",
        "sane_lists",
        "admonition",
        "codehilite",
        "footnotes",
        "attr_list",
        "def_list",
    ],
    extension_configs={
        "codehilite": {"guess_lang": False, "css_class": "codehilite"},
        "toc": {"permalink": False},
    },
    output_format="html5",
)


# ---------------------------------------------------------------------------
# path helpers
# ---------------------------------------------------------------------------


class PathError(ValueError):
    """User-facing error for path / name validation."""


def is_valid_segment(seg: str) -> bool:
    if not seg or seg in {".", ".."}:
        return False
    if seg.startswith("."):
        return False
    if any(c in _BAD_PATH_CHARS for c in seg):
        return False
    if any(ord(c) < 32 or ord(c) == 127 for c in seg):
        return False
    return True


def parse_segments(path_input: str) -> list[str]:
    if path_input is None:
        raise PathError("Please enter a name.")
    s = path_input.replace("\\", "/").strip().strip("/")
    if not s:
        raise PathError("Please enter a name.")
    raw = [seg.strip() for seg in s.split("/")]
    if any(not seg for seg in raw):
        raise PathError("Path may not contain empty segments (e.g. // or trailing /).")
    for seg in raw:
        if not is_valid_segment(seg):
            raise PathError(f"Invalid path segment: {seg!r}")
    return raw


def safe_join(rel: str) -> Path:
    rel = (rel or "").strip().lstrip("/")
    target = (DATA_DIR / rel).resolve()
    if target != DATA_DIR and DATA_DIR not in target.parents:
        abort(400, "Invalid path")
    return target


def doc_rel(path: Path) -> str:
    return nav.doc_rel(path, DATA_DIR)


def build_tree(root: Path) -> dict:
    return nav.build_tree(root, DATA_DIR)


def breadcrumbs(rel: str, leaf_kind: str = "doc") -> list[dict]:
    return nav.breadcrumbs(rel, leaf_kind)


def categories() -> list[dict]:
    return nav.load_categories(CONFIG_DIR)


def all_doc_paths() -> list[str]:
    """Every relative path under DATA_DIR that can be linked to from a
    dashboard card: folders (categories, entries, sub-folders) and
    markdown docs (with .md stripped, matching the existing `rel` form)."""
    paths: set[str] = set()
    if not DATA_DIR.exists():
        return []
    for p in DATA_DIR.rglob("*"):
        try:
            rel_parts = p.relative_to(DATA_DIR).parts
        except ValueError:
            continue
        if any(part.startswith(".") for part in rel_parts):
            continue
        if not rel_parts:
            continue
        if p.is_dir():
            paths.add("/".join(rel_parts))
        elif p.is_file() and p.suffix == MD_EXT:
            paths.add("/".join(rel_parts)[: -len(MD_EXT)])
    return sorted(paths, key=str.lower)


# ---------------------------------------------------------------------------
# template context + auth gates
# ---------------------------------------------------------------------------


PUBLIC_ENDPOINTS = {"login", "setup", "static", "health"}
CSRF_EXEMPT_ENDPOINTS: set[str] = set()


@app.context_processor
def inject_globals():
    user = auth.current_user() if "user_id" in session else None
    return {
        "site_name": SITE_NAME,
        "app_version": APP_VERSION,
        "project_url": PROJECT_URL,
        "author_name": AUTHOR_NAME,
        "author_url": AUTHOR_URL,
        "license_name": LICENSE_NAME,
        "navigation": nav.build_navigation(DATA_DIR, categories()),
        "current_user": user,
        "csrf_token": auth.csrf_token,
        "category_icon": nav.icon_svg,
        "icon_names": list(nav.ICON_LIBRARY.keys()),
    }


@app.before_request
def gate():
    if request.endpoint in {"static", "health"}:
        return
    if request.method == "POST" and request.endpoint not in CSRF_EXEMPT_ENDPOINTS:
        auth.verify_csrf()
    if request.endpoint in PUBLIC_ENDPOINTS:
        return
    if request.endpoint is None:
        return
    if not auth.has_admin():
        return redirect(url_for("setup"))
    if auth.current_user() is None:
        return redirect(url_for("login", next=request.full_path.rstrip("?")))


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------


@app.route("/health")
def health():
    return {"ok": True, "version": APP_VERSION, "data": str(DATA_DIR)}


# ---------------------------------------------------------------------------
# auth: setup, login, logout
# ---------------------------------------------------------------------------


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if auth.has_admin():
        return redirect(url_for("login"))
    error = None
    username_value = ""
    if request.method == "POST":
        username_value = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        try:
            username = auth.require_username(username_value)
            auth.require_password(password)
            if password != confirm:
                raise ValueError("Passwords do not match.")
            uid = auth.create_user(username, password, is_admin=True)
            user = auth.get_user(uid)
            auth.login_session(user)
            return redirect(url_for("index"))
        except ValueError as e:
            error = str(e)
    return render_template("setup.html", error=error, username_value=username_value)


@app.route("/login", methods=["GET", "POST"])
def login():
    if not auth.has_admin():
        return redirect(url_for("setup"))
    error = None
    username_value = ""
    next_url = auth.safe_next(
        request.values.get("next"), fallback=url_for("index")
    )
    if request.method == "POST":
        username_value = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        rate_key = auth.login_rate_key(username_value)
        remaining = auth.lockout_remaining(rate_key)
        if remaining > 0:
            error = (
                f"Too many failed attempts. Try again in {remaining} seconds."
            )
        else:
            user = auth.authenticate(username_value, password)
            if user is None:
                auth.record_failure(rate_key)
                error = "Invalid username or password."
            else:
                auth.clear_failures(rate_key)
                auth.login_session(user)
                return redirect(next_url)
    return render_template(
        "login.html",
        error=error,
        username_value=username_value,
        next_url=next_url,
    )


@app.route("/logout", methods=["POST"])
def logout():
    auth.logout_session()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# routes (gated by before_request)
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    cats = categories()
    data = nav.dashboard_data(DATA_DIR, cats)
    welcome_html = None
    welcome = DATA_DIR / f"welcome{MD_EXT}"
    if welcome.is_file():
        try:
            md_renderer.reset()
            welcome_html = md_renderer.convert(
                welcome.read_text(encoding="utf-8")
            )
        except OSError:
            welcome_html = None
    return render_template(
        "dashboard.html",
        stats=data,
        recent_docs=data["recent_docs"],
        recent_entries=data["recent_entries"],
        tag_cloud=data["tag_cloud"],
        welcome_html=welcome_html,
    )


@app.route("/t/<path:tag>")
def tag_page(tag: str):
    cats = categories()
    matches = nav.find_entries_with_tag(DATA_DIR, cats, tag)
    return render_template(
        "tag.html",
        tag=tag,
        matches=matches,
    )


@app.template_filter("reltime")
def _jinja_reltime(value):
    try:
        return nav.relative_time(float(value))
    except (TypeError, ValueError):
        return ""


@app.template_filter("hostlabel")
def _jinja_hostlabel(value):
    return links.host_label(value or "")


@app.template_filter("docurl")
def _jinja_docurl(rel):
    """Return the right URL for a stored doc_path: /d/<rel> if it's a
    markdown file under data/, otherwise /f/<rel>. Empty input yields
    an empty string so templates can guard with `{% if ... %}`."""
    rel = (rel or "").strip().strip("/")
    if not rel:
        return ""
    try:
        target_dir = (DATA_DIR / rel).resolve()
        target_md = (DATA_DIR / (rel + MD_EXT)).resolve()
    except (OSError, ValueError):
        return ""
    if target_dir != DATA_DIR and DATA_DIR not in target_dir.parents:
        return ""
    if target_md.is_file():
        return url_for("view", path=rel)
    if target_dir.is_dir():
        return url_for("folder", path=rel)
    return ""


@app.route("/d/<path:path>")
def view(path: str):
    target = safe_join(path + MD_EXT)
    if not target.is_file():
        abort(404)
    text = target.read_text(encoding="utf-8")
    md_renderer.reset()
    html = md_renderer.convert(text)
    return render_template(
        "view.html",
        rel=path,
        html=html,
        crumbs=breadcrumbs(path),
        title=target.stem,
        related_links=links.links_for_doc_path(path),
    )


@app.route("/f/<path:path>")
def folder(path: str):
    target = safe_join(path)
    if not target.is_dir():
        abort(404)

    parts = [p for p in path.split("/") if p]
    cats = categories()
    cat_map = {c["slug"]: c for c in cats}
    category = cat_map.get(parts[0]) if parts else None
    is_category = bool(category) and len(parts) == 1
    is_entry = bool(category) and len(parts) == 2

    children = build_tree(target)

    overview_html = None
    overview_rel = None
    entry_tags: list[str] = []
    category_entries: list[dict] = []

    if is_entry:
        overview = nav.find_overview(target)
        if overview:
            md_renderer.reset()
            overview_html = md_renderer.convert(
                overview.read_text(encoding="utf-8")
            )
            overview_rel = doc_rel(overview)
            children["docs"] = [
                d for d in children["docs"] if d["rel"] != overview_rel
            ]
            entry_tags = nav.parse_overview_tags(overview)

    if is_category:
        try:
            children_iter = sorted(
                target.iterdir(), key=lambda p: p.name.lower()
            )
        except OSError:
            children_iter = []
        for child in children_iter:
            if child.name.startswith("."):
                continue
            if child.is_dir():
                sub = build_tree(child)
                ov = nav.find_overview(child)
                category_entries.append(
                    {
                        "name": child.name,
                        "rel": doc_rel(child),
                        "doc_count": nav.count_descendant_docs(sub),
                        "tags": nav.parse_overview_tags(ov),
                    }
                )

    return render_template(
        "folder.html",
        rel=path,
        children=children,
        crumbs=breadcrumbs(path, leaf_kind="folder"),
        title=target.name,
        category=category,
        is_category=is_category,
        is_entry=is_entry,
        overview_html=overview_html,
        overview_rel=overview_rel,
        entry_tags=entry_tags,
        category_entries=category_entries,
        related_links=links.links_for_doc_prefix(path),
    )


@app.route("/e/<path:path>", methods=["GET", "POST"])
def edit(path: str):
    target = safe_join(path + MD_EXT)
    if not target.is_file():
        abort(404)
    if request.method == "POST":
        body = request.form.get("body", "")
        target.write_text(body, encoding="utf-8", newline="\n")
        return redirect(url_for("view", path=path))
    return render_template(
        "edit.html",
        rel=path,
        body=target.read_text(encoding="utf-8"),
        crumbs=breadcrumbs(path),
        title=target.stem,
    )


@app.route("/n", methods=["GET", "POST"])
def new():
    error: str | None = None
    kind = request.values.get("kind", "doc")
    folder_hint = (request.values.get("folder") or "").strip().strip("/")
    path_value = (folder_hint + "/") if folder_hint and request.method == "GET" else ""

    if request.method == "POST":
        kind = request.form.get("kind", "doc")
        path_input = request.form.get("path", "")
        if not path_input:
            folder_part = (request.form.get("folder") or "").strip().strip("/")
            name_part = (request.form.get("name") or "").strip()
            path_input = f"{folder_part}/{name_part}" if folder_part else name_part
        path_value = path_input
        try:
            segments = parse_segments(path_input)
            if kind == "folder":
                target = DATA_DIR.joinpath(*segments)
                if target.exists():
                    raise PathError("A folder or file with that path already exists.")
                try:
                    target.mkdir(parents=True, exist_ok=False)
                except OSError as e:
                    raise PathError(
                        f"Could not create folder. Check permissions for {DATA_DIR}."
                    ) from e
                return redirect(url_for("folder", path="/".join(segments)))
            leaf = segments[-1]
            if leaf.endswith(MD_EXT):
                leaf = leaf[: -len(MD_EXT)]
                segments[-1] = leaf
            if not leaf:
                raise PathError("Document name cannot be empty.")
            target = DATA_DIR.joinpath(*segments[:-1], leaf + MD_EXT)
            existing_dir = DATA_DIR.joinpath(*segments)
            if target.exists():
                raise PathError("A document with that path already exists.")
            if existing_dir.is_dir():
                raise PathError("A folder with that name already exists at this path.")
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(f"# {leaf}\n\n", encoding="utf-8", newline="\n")
            except OSError as e:
                raise PathError(
                    f"Could not create document. Check permissions for {DATA_DIR}."
                ) from e
            return redirect(url_for("edit", path=doc_rel(target)))
        except PathError as e:
            error = str(e)

    return render_template(
        "new.html",
        path_value=path_value,
        kind=kind,
        error=error,
    )


@app.route("/c/<slug>/new", methods=["GET", "POST"])
def entry_new(slug: str):
    cat = nav.find_category(categories(), slug)
    if not cat:
        abort(404)
    error: str | None = None
    name_value = ""
    description_value = ""
    tags_value = ""
    if request.method == "POST":
        name_value = (request.form.get("name") or "").strip()
        description_value = (request.form.get("description") or "").strip()
        tags_value = (request.form.get("tags") or "").strip()
        try:
            if not is_valid_segment(name_value):
                raise PathError(
                    f"Invalid {cat['noun']} name. Avoid slashes and special characters."
                )
            entry_dir = DATA_DIR / slug / name_value
            if entry_dir.exists():
                raise PathError(
                    f"A {cat['noun']} called {name_value!r} already exists."
                )
            try:
                entry_dir.mkdir(parents=True, exist_ok=False)
                overview = entry_dir / "overview.md"
                body_lines: list[str] = []
                if tags_value:
                    cleaned_tags = ", ".join(
                        t.strip().lstrip("#").strip()
                        for t in tags_value.replace(";", ",").split(",")
                        if t.strip()
                    )
                    if cleaned_tags:
                        body_lines.append(f"tags: {cleaned_tags}")
                        body_lines.append("")
                body_lines.append(f"# {name_value}")
                body_lines.append("")
                if description_value:
                    body_lines.append(description_value)
                    body_lines.append("")
                overview.write_text(
                    "\n".join(body_lines), encoding="utf-8", newline="\n"
                )
            except OSError as e:
                raise PathError(
                    f"Could not create {cat['noun']}: {e}"
                ) from e
            return redirect(url_for("folder", path=f"{slug}/{name_value}"))
        except PathError as e:
            error = str(e)
    return render_template(
        "entry_new.html",
        category=cat,
        error=error,
        name_value=name_value,
        description_value=description_value,
        tags_value=tags_value,
    )


@app.route("/del/<path:path>", methods=["POST"])
def delete(path: str):
    target = safe_join(path + MD_EXT)
    if target.is_file():
        target.unlink()
        return redirect(url_for("index"))
    folder_target = safe_join(path)
    if folder_target.is_dir():
        shutil.rmtree(folder_target)
        return redirect(url_for("index"))
    abort(404)


@app.route("/s")
def search():
    q = (request.args.get("q") or "").strip()
    cats = categories()
    cat_slug = (request.args.get("category") or "").strip()
    selected_category = nav.find_category(cats, cat_slug) if cat_slug else None
    if cat_slug and not selected_category:
        cat_slug = ""

    results: list[dict] = []
    if q:
        needle = q.lower()
        if selected_category:
            search_root = DATA_DIR / selected_category["slug"]
            walker = (
                search_root.rglob(f"*{MD_EXT}") if search_root.is_dir() else []
            )
        else:
            walker = DATA_DIR.rglob(f"*{MD_EXT}")
        for path in walker:
            try:
                rel = path.relative_to(DATA_DIR)
            except ValueError:
                continue
            if any(part.startswith(".") for part in rel.parts):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            if needle in text.lower() or needle in path.stem.lower():
                results.append(
                    {
                        "rel": doc_rel(path),
                        "title": path.stem,
                        "snippet": _snippet(text, needle),
                    }
                )
        results.sort(key=lambda r: r["title"].lower())
    return render_template(
        "search.html",
        q=q,
        results=results,
        categories=cats,
        selected_category=selected_category,
        category_slug=cat_slug,
    )


def _snippet(text: str, needle: str, width: int = 140) -> str:
    lower = text.lower()
    i = lower.find(needle)
    if i < 0:
        return text[:width].strip()
    start = max(0, i - width // 2)
    end = min(len(text), i + len(needle) + width // 2)
    snip = text[start:end].replace("\n", " ").strip()
    if start > 0:
        snip = "... " + snip
    if end < len(text):
        snip = snip + " ..."
    return snip


@app.route("/api/preview", methods=["POST"])
def api_preview():
    body = request.get_data(as_text=True)
    md_renderer.reset()
    return md_renderer.convert(body)


# ---------------------------------------------------------------------------
# links dashboard (/dash)
# ---------------------------------------------------------------------------


@app.route("/dash")
@auth.login_required
def dash():
    groups = links.grouped_links()
    sections = links.existing_sections()
    doc_paths = all_doc_paths()
    edit_id_raw = request.args.get("edit", "")
    new_form = request.args.get("new") is not None
    editing = None
    if edit_id_raw.isdigit():
        editing = links.get_link(int(edit_id_raw))
    form_values = None
    form_error = session.pop("dash_form_error", None)
    if form_error:
        form_values = session.pop("dash_form_values", None)
    return render_template(
        "dash.html",
        groups=groups,
        sections=sections,
        doc_paths=doc_paths,
        editing=editing,
        new_form=new_form,
        form_error=form_error,
        form_values=form_values,
        hide_sidebar=True,
    )


def _dash_form_payload() -> dict:
    return {
        "title": request.form.get("title", ""),
        "url": request.form.get("url", ""),
        "description": request.form.get("description", ""),
        "section": request.form.get("section", ""),
        "doc_path": request.form.get("doc_path", ""),
    }


def _stash_form_error(message: str, mode: str, link_id: Optional[int] = None) -> None:
    session["dash_form_error"] = message
    session["dash_form_values"] = {
        **_dash_form_payload(),
        "mode": mode,
        "id": link_id,
    }


@app.route("/dash/new", methods=["POST"])
@auth.login_required
def dash_new():
    valid_paths = set(all_doc_paths())
    try:
        title = links.normalize_title(request.form.get("title", ""))
        url = links.normalize_url(request.form.get("url", ""))
        description = links.normalize_description(
            request.form.get("description", "")
        )
        section = links.normalize_section(request.form.get("section", ""))
        doc_path = links.normalize_doc_path(
            request.form.get("doc_path", ""), valid_paths=valid_paths
        )
    except ValueError as e:
        _stash_form_error(str(e), "new")
        return redirect(url_for("dash", new=1))
    favicon = links.fetch_favicon(url)
    me = auth.current_user()
    links.create_link(
        title=title,
        url=url,
        description=description,
        section=section,
        favicon=favicon,
        doc_path=doc_path,
        created_by=(me["id"] if me else None),
    )
    return redirect(url_for("dash"))


@app.route("/dash/<int:link_id>/edit", methods=["POST"])
@auth.login_required
def dash_edit(link_id: int):
    existing = links.get_link(link_id)
    if existing is None:
        abort(404)
    valid_paths = set(all_doc_paths())
    try:
        title = links.normalize_title(request.form.get("title", ""))
        url = links.normalize_url(request.form.get("url", ""))
        description = links.normalize_description(
            request.form.get("description", "")
        )
        section = links.normalize_section(request.form.get("section", ""))
        doc_path = links.normalize_doc_path(
            request.form.get("doc_path", ""), valid_paths=valid_paths
        )
    except ValueError as e:
        _stash_form_error(str(e), "edit", link_id)
        return redirect(url_for("dash", edit=link_id))
    new_favicon: Optional[str] = None
    if url != existing["url"]:
        fetched = links.fetch_favicon(url)
        new_favicon = fetched
    links.update_link(
        link_id,
        title=title,
        url=url,
        description=description,
        section=section,
        doc_path=doc_path,
        favicon=new_favicon,
    )
    return redirect(url_for("dash"))


@app.route("/dash/<int:link_id>/delete", methods=["POST"])
@auth.login_required
def dash_delete(link_id: int):
    if links.get_link(link_id) is None:
        abort(404)
    links.delete_link(link_id)
    return redirect(url_for("dash"))


@app.route("/dash/<int:link_id>/refresh-favicon", methods=["POST"])
@auth.login_required
def dash_refresh_favicon(link_id: int):
    existing = links.get_link(link_id)
    if existing is None:
        abort(404)
    fetched = links.fetch_favicon(existing["url"])
    links.update_link(
        link_id,
        title=existing["title"],
        url=existing["url"],
        description=existing["description"],
        section=existing["section"],
        doc_path=existing["doc_path"],
        favicon=fetched,
    )
    return redirect(url_for("dash"))


@app.route("/dash/favicon/<int:link_id>")
@auth.login_required
def dash_favicon(link_id: int):
    row = links.get_link(link_id)
    if row is None:
        abort(404)
    p = links.favicon_path(row["favicon"]) if row["favicon"] else None
    if p is not None:
        return send_file(p, max_age=86400)
    svg = links.letter_tile_svg(row["title"] or links.host_label(row["url"]))
    return Response(svg, mimetype="image/svg+xml")


# ---------------------------------------------------------------------------
# admin panel
# ---------------------------------------------------------------------------


@app.route("/admin")
@auth.admin_required
def admin_index():
    return redirect(url_for("admin_users"))


@app.route("/admin/users", methods=["GET", "POST"])
@auth.admin_required
def admin_users():
    error = None
    notice = None
    me = auth.current_user()
    if request.method == "POST":
        action = request.form.get("action") or ""
        try:
            if action == "create":
                username = auth.require_username(request.form.get("username", ""))
                password = request.form.get("password", "")
                auth.require_password(password)
                if auth.get_user_by_name(username):
                    raise ValueError("That username already exists.")
                is_admin = bool(request.form.get("is_admin"))
                auth.create_user(username, password, is_admin=is_admin)
                notice = f"User {username!r} created."
            elif action in {"set_password", "toggle_admin", "delete"}:
                target_id = int(request.form.get("user_id") or 0)
                target = auth.get_user(target_id)
                if not target:
                    raise ValueError("User not found.")
                if action == "set_password":
                    pw = request.form.get("password", "")
                    auth.require_password(pw)
                    auth.set_password(target_id, pw)
                    notice = f"Password updated for {target['username']!r}."
                elif action == "toggle_admin":
                    will_be_admin = not bool(target["is_admin"])
                    if (
                        not will_be_admin
                        and target["is_admin"]
                        and auth.admin_count() <= 1
                    ):
                        raise ValueError(
                            "Cannot remove admin from the only remaining admin."
                        )
                    auth.set_admin(target_id, will_be_admin)
                    notice = (
                        f"{target['username']!r} is now "
                        f"{'an admin' if will_be_admin else 'a regular user'}."
                    )
                elif action == "delete":
                    if me and target_id == me["id"]:
                        raise ValueError("You cannot delete your own account.")
                    if target["is_admin"] and auth.admin_count() <= 1:
                        raise ValueError("Cannot delete the only remaining admin.")
                    auth.delete_user(target_id)
                    notice = f"User {target['username']!r} deleted."
            else:
                raise ValueError("Unknown action.")
        except ValueError as e:
            error = str(e)

    return render_template(
        "admin_users.html",
        users=auth.list_users(),
        error=error,
        notice=notice,
        me=me,
    )


@app.route("/admin/categories", methods=["GET", "POST"])
@auth.admin_required
def admin_categories():
    error = None
    notice = None
    cats = categories()

    if request.method == "POST":
        action = request.form.get("action") or ""

        def _icon_or_default(value: str) -> str:
            value = (value or "").strip()
            return value if value in nav.ICON_LIBRARY else nav.DEFAULT_ICON

        try:
            if action == "create":
                name = (request.form.get("name") or "").strip()
                slug_input = (request.form.get("slug") or "").strip()
                noun = (request.form.get("noun") or "").strip() or "entry"
                description = (request.form.get("description") or "").strip()
                icon = _icon_or_default(request.form.get("icon"))
                if not name:
                    raise ValueError("Name is required.")
                slug = nav.normalize_slug(slug_input or name)
                if not nav.is_valid_slug(slug):
                    raise ValueError(
                        f"Invalid slug {slug!r}. Use lowercase letters, "
                        "digits, dashes, or underscores; reserved words are not allowed."
                    )
                if any(c.get("slug") == slug for c in cats):
                    raise ValueError(f"Slug {slug!r} already exists.")
                cats.append(
                    {
                        "slug": slug,
                        "name": name,
                        "noun": noun,
                        "icon": icon,
                        "description": description,
                    }
                )
                nav.save_categories(CONFIG_DIR, cats)
                notice = f"Category {name!r} added."
            elif action == "update":
                slug = request.form.get("slug") or ""
                name = (request.form.get("name") or "").strip()
                noun = (request.form.get("noun") or "").strip() or "entry"
                description = (request.form.get("description") or "").strip()
                icon = _icon_or_default(request.form.get("icon"))
                target = next((c for c in cats if c.get("slug") == slug), None)
                if not target:
                    raise ValueError("Category not found.")
                if not name:
                    raise ValueError("Name is required.")
                target["name"] = name
                target["noun"] = noun
                target["icon"] = icon
                target["description"] = description
                nav.save_categories(CONFIG_DIR, cats)
                notice = f"Category {name!r} updated."
            elif action == "reorder_full":
                requested = request.form.getlist("slugs[]") or request.form.getlist("slugs")
                by_slug = {c["slug"]: c for c in cats}
                seen: set[str] = set()
                new_order: list[dict] = []
                for s in requested:
                    if s in by_slug and s not in seen:
                        new_order.append(by_slug[s])
                        seen.add(s)
                for c in cats:
                    if c["slug"] not in seen:
                        new_order.append(c)
                cats = new_order
                nav.save_categories(CONFIG_DIR, cats)
                if request.headers.get("X-Requested-With") == "scrinium-fetch":
                    return ("", 204)
                notice = "Order updated."
            elif action == "move":
                slug = request.form.get("slug") or ""
                direction = request.form.get("direction") or ""
                idx = next(
                    (i for i, c in enumerate(cats) if c.get("slug") == slug),
                    -1,
                )
                if idx < 0:
                    raise ValueError("Category not found.")
                if direction == "up" and idx > 0:
                    cats[idx - 1], cats[idx] = cats[idx], cats[idx - 1]
                elif direction == "down" and idx < len(cats) - 1:
                    cats[idx + 1], cats[idx] = cats[idx], cats[idx + 1]
                nav.save_categories(CONFIG_DIR, cats)
                notice = "Order updated."
            elif action == "delete":
                slug = request.form.get("slug") or ""
                also_remove_folder = bool(request.form.get("remove_folder"))
                target = next((c for c in cats if c.get("slug") == slug), None)
                if not target:
                    raise ValueError("Category not found.")
                cats = [c for c in cats if c.get("slug") != slug]
                nav.save_categories(CONFIG_DIR, cats)
                if also_remove_folder:
                    folder_path = DATA_DIR / slug
                    if folder_path.is_dir():
                        shutil.rmtree(folder_path)
                notice = (
                    f"Category {target.get('name', slug)!r} removed."
                    + (
                        " Folder and its contents were deleted."
                        if also_remove_folder
                        else " Folder kept on disk (it now appears under Other)."
                    )
                )
            else:
                raise ValueError("Unknown action.")
        except (ValueError, OSError) as e:
            error = str(e)
        cats = categories()

    folder_status = []
    for c in cats:
        cp = DATA_DIR / c["slug"]
        folder_status.append(
            {**c, "folder_exists": cp.is_dir()}
        )

    return render_template(
        "admin_categories.html",
        categories=folder_status,
        error=error,
        notice=notice,
    )


@app.route("/admin/ldap", methods=["GET", "POST"])
@auth.admin_required
def admin_ldap():
    error = None
    notice = None
    test_result = None
    settings = auth.ldap_settings()

    if request.method == "POST":
        action = request.form.get("action", "save")
        # Build a working dict from form so changes persist across re-renders
        # whether the user clicked Save or Test.
        merged = dict(settings)
        for k in auth.LDAP_DEFAULTS:
            if k in {"enabled", "use_starttls", "verify_cert", "auto_provision"}:
                merged[k] = bool(request.form.get(k))
            elif k == "connect_timeout":
                try:
                    merged[k] = max(1, int(request.form.get(k) or settings[k]))
                except ValueError:
                    merged[k] = settings[k]
            else:
                value = (request.form.get(k) or "").strip()
                if k == "bind_password" and not value:
                    merged[k] = settings.get(k, "")
                else:
                    merged[k] = value
        if action == "test":
            test_result = auth.ldap_test(merged)
            settings = merged
        else:
            try:
                auth.save_ldap_settings(request.form, keep_existing_password=True)
                settings = auth.ldap_settings()
                notice = "LDAP settings saved."
            except Exception as e:  # pragma: no cover
                error = f"Could not save settings: {e}"
                settings = merged

    return render_template(
        "admin_ldap.html",
        s=settings,
        has_password=bool(settings.get("bind_password")),
        error=error,
        notice=notice,
        test_result=test_result,
    )


# ---------------------------------------------------------------------------
# error handlers
# ---------------------------------------------------------------------------


@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="Forbidden."), 403


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="Not found."), 404


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message=str(e.description)), 400


@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return e
    app.logger.exception("Unhandled error")
    return (
        render_template(
            "error.html", code=500, message="Something went wrong on the server."
        ),
        500,
    )


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    from waitress import serve

    print(
        f"Scrinium {APP_VERSION} serving {DATA_DIR} on http://{HOST}:{PORT}",
        flush=True,
    )
    serve(app, host=HOST, port=PORT, ident="scrinium")


if __name__ == "__main__":
    main()
