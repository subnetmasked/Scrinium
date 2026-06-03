"""Per-package roles, enable gates, and decorators."""
from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Optional

from flask import abort, current_app, redirect, request, session, url_for

import auth
from packages import registry


PACKAGES_CONFIG_KEY = "packages"


def _packages_config() -> dict:
    raw = auth.get_config(PACKAGES_CONFIG_KEY) or {}
    return raw if isinstance(raw, dict) else {}


def package_config(package_id: str) -> dict:
    cfg = _packages_config()
    pkg_cfg = cfg.get(package_id)
    return pkg_cfg if isinstance(pkg_cfg, dict) else {}


def package_enabled(package_id: str) -> bool:
    return bool(package_config(package_id).get("enabled"))


def module_enabled(package_id: str, module_id: str) -> bool:
    if not package_enabled(package_id):
        return False
    mods = package_config(package_id).get("modules") or {}
    mod_cfg = mods.get(module_id) if isinstance(mods, dict) else {}
    if not isinstance(mod_cfg, dict):
        return False
    return bool(mod_cfg.get("enabled"))


def module_config(package_id: str, module_id: str) -> dict:
    mods = package_config(package_id).get("modules") or {}
    mod_cfg = mods.get(module_id) if isinstance(mods, dict) else {}
    return mod_cfg if isinstance(mod_cfg, dict) else {}


def save_packages_config(updates: dict) -> None:
    cfg = _packages_config()
    cfg.update(updates)
    auth.set_config(PACKAGES_CONFIG_KEY, cfg)


def set_package_config(package_id: str, value: dict) -> None:
    cfg = _packages_config()
    cfg[package_id] = value
    auth.set_config(PACKAGES_CONFIG_KEY, cfg)


def _user_group_names(user: Any) -> set[str]:
    if user is None:
        return set()
    uid = int(user["id"])
    return {g["name"].lower() for g in auth.groups_for_user(uid)}


def current_role(package_id: str, user: Any | None = None) -> Optional[str]:
    """Return highest role for user in package: technician > auditor > None. Admin -> 'admin'."""
    if user is None:
        user = auth.current_user()
    if user is None:
        return None
    if user["is_admin"]:
        return "admin"
    pkg = registry.get_package(package_id)
    if pkg is None:
        return None
    groups = _user_group_names(user)
    roles_cfg = package_config(package_id).get("roles") or {}
    if not isinstance(roles_cfg, dict):
        return None
    # technician supersedes auditor
    for role_id in ("technician", "auditor"):
        role_cfg = roles_cfg.get(role_id) or {}
        if not isinstance(role_cfg, dict):
            continue
        mapped = {str(g).lower() for g in (role_cfg.get("groups") or [])}
        if groups & mapped:
            return role_id
    return None


def can_access_package(package_id: str, user: Any | None = None) -> bool:
    if not package_enabled(package_id):
        return False
    role = current_role(package_id, user)
    return role is not None


def is_auditor_or_above(package_id: str, user: Any | None = None) -> bool:
    role = current_role(package_id, user)
    return role in ("admin", "auditor", "technician")


def is_technician_or_above(package_id: str, user: Any | None = None) -> bool:
    role = current_role(package_id, user)
    return role in ("admin", "technician")


def package_enabled_required(package_id: str) -> Callable:
    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not package_enabled(package_id):
                abort(404)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def module_enabled_required(package_id: str, module_id: str) -> Callable:
    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not module_enabled(package_id, module_id):
                abort(404)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def package_login_required(package_id: str) -> Callable:
    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not auth.has_admin():
                return redirect(url_for("setup"))
            if auth.current_user() is None:
                return redirect(url_for("login", next=request.path))
            if not package_enabled(package_id):
                abort(404)
            if current_role(package_id) is None:
                abort(404)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def require_auditor(package_id: str) -> Callable:
    def decorator(view: Callable) -> Callable:
        @wraps(view)
        @package_login_required(package_id)
        def wrapped(*args, **kwargs):
            if not is_auditor_or_above(package_id):
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def require_technician(package_id: str) -> Callable:
    def decorator(view: Callable) -> Callable:
        @wraps(view)
        @package_login_required(package_id)
        def wrapped(*args, **kwargs):
            if not is_technician_or_above(package_id):
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def default_package_config(package_id: str) -> dict:
    pkg = registry.get_package(package_id)
    if pkg is None:
        return {"enabled": False, "roles": {}, "modules": {}}
    roles_default: dict = {}
    for role in pkg.roles:
        roles_default[role.id] = {"groups": []}
    modules_default: dict = {}
    for mod in pkg.modules:
        modules_default[mod.id] = {"enabled": False, **mod.default_config}
    return {"enabled": False, "roles": roles_default, "modules": modules_default}


def merged_package_config(package_id: str) -> dict:
    defaults = default_package_config(package_id)
    saved = package_config(package_id)
    out = dict(defaults)
    out["enabled"] = bool(saved.get("enabled", defaults.get("enabled")))
    roles_out = dict(defaults.get("roles") or {})
    saved_roles = saved.get("roles") or {}
    if isinstance(saved_roles, dict):
        for rid, rcfg in saved_roles.items():
            if isinstance(rcfg, dict):
                roles_out[rid] = {
                    "groups": list(rcfg.get("groups") or roles_out.get(rid, {}).get("groups") or [])
                }
    out["roles"] = roles_out
    mods_out = dict(defaults.get("modules") or {})
    saved_mods = saved.get("modules") or {}
    if isinstance(saved_mods, dict):
        for mid, mcfg in saved_mods.items():
            base = dict(mods_out.get(mid) or {})
            if isinstance(mcfg, dict):
                base.update(mcfg)
            mods_out[mid] = base
    out["modules"] = mods_out
    return out
