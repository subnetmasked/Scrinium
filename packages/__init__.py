"""Scrinium platform package framework."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from flask import Flask, request, url_for

import auth
import nav
from packages import authz, db, hub, registry
from packages.admin import admin_bp
from packages.builtins import register_builtin_nav_apps

logger = logging.getLogger(__name__)

_data_dir: Path | None = None


def _check_slug_collisions(data_dir: Path) -> None:
    for pkg in registry.iter_packages():
        collision = data_dir / pkg.id
        if collision.is_dir():
            logger.warning(
                "Package mount %r may shadow existing data folder: %s",
                pkg.id,
                collision,
            )


def _mount_modules(app: Flask) -> None:
    for pkg in registry.iter_packages():
        for mod in pkg.modules:
            prefix = f"/{pkg.id}/{mod.id}"
            app.register_blueprint(mod.blueprint, url_prefix=prefix)


def _entry_active(entry: dict) -> bool:
    path = request.path or ""
    ep = request.endpoint or ""
    if entry["kind"] == "package":
        return path == entry["url"] or path.startswith(entry["url"].rstrip("/") + "/")
    if entry["id"] == "dashboard":
        return bool(ep and ep.startswith("dash"))
    if entry["id"] == "documentation":
        if path.startswith("/security") or path.startswith("/dash"):
            return False
        if ep and ep.startswith("admin"):
            return False
        return True
    return False


def _switcher_entries(user: Any | None) -> list[dict]:
    entries: list[dict] = []
    for nav_app in registry.iter_nav_apps():
        if user is None or not nav_app.accessible(user):
            continue
        entry = {
            "id": nav_app.id,
            "name": nav_app.name,
            "icon": nav_app.icon,
            "url": url_for(nav_app.endpoint),
            "kind": "nav",
        }
        entry["active"] = _entry_active(entry)
        entries.append(entry)
    for pkg in registry.iter_packages():
        if not authz.package_enabled(pkg.id):
            continue
        if user is None or authz.current_role(pkg.id, user) is None:
            if not (user and user["is_admin"]):
                continue
        entry = {
            "id": pkg.id,
            "name": pkg.name,
            "icon": pkg.icon,
            "url": url_for(f"pkg_{pkg.id}.landing"),
            "kind": "package",
        }
        entry["active"] = _entry_active(entry)
        entries.append(entry)
    return entries


def register_security_package() -> None:
    from packages.security import register as register_security

    register_security()


def init_app(app: Flask, *, config_dir: Path, data_dir: Path) -> None:
    global _data_dir
    _data_dir = data_dir.resolve()
    db.set_config_dir(config_dir)
    app.config["PACKAGES_CONFIG_DIR"] = str(config_dir)

    register_builtin_nav_apps()
    register_security_package()

    _check_slug_collisions(data_dir)

    with app.app_context():
        db.init_all_package_dbs()

    _mount_modules(app)
    hub.mount_package_hubs(app)
    app.register_blueprint(admin_bp)

    @app.context_processor
    def inject_packages():
        from flask import session

        user = auth.current_user() if "user_id" in session else None
        return {
            "app_switcher_entries": _switcher_entries(user),
            "registered_packages": registry.iter_packages(),
            "package_role": lambda pid: authz.current_role(pid, user),
            "package_enabled": authz.package_enabled,
        }

    from packages.security.modules.vulnerabilities import sync as vuln_sync

    vuln_sync.start_scheduled_sync(app)


def reserved_slugs_extra() -> set[str]:
    return set(registry.reserved_package_ids())
