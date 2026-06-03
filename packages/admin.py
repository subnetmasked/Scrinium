"""Admin routes for package settings."""
from __future__ import annotations

from flask import Blueprint, abort, render_template, request

import audit
import auth
from packages import authz, registry

admin_bp = Blueprint("packages_admin", __name__, url_prefix="/admin")


@admin_bp.route("/<package_id>", methods=["GET", "POST"])
@auth.admin_required
def package_admin(package_id: str):
    pkg = registry.get_package(package_id)
    if pkg is None:
        abort(404)
    error = None
    notice = None
    if request.method == "POST":
        auth.verify_csrf()
        action = request.form.get("action") or ""
        if action not in ("save_package",):
            return pkg.admin_view(
                package=pkg,
                config=authz.merged_package_config(package_id),
                groups=auth.list_groups(),
                error=error,
                notice=notice,
            )
        try:
            if action == "save_package":
                cfg = authz.merged_package_config(package_id)
                cfg["enabled"] = bool(request.form.get("enabled"))
                roles = cfg.get("roles") or {}
                for role in pkg.roles:
                    key = f"groups_{role.id}"
                    raw = request.form.get(key) or ""
                    groups = [
                        g.strip()
                        for g in raw.replace(",", "\n").splitlines()
                        if g.strip()
                    ]
                    roles[role.id] = {"groups": groups}
                cfg["roles"] = roles
                authz.set_package_config(package_id, cfg)
                audit.record(
                    "package.settings_change",
                    target=package_id,
                    details={"enabled": cfg["enabled"]},
                )
                notice = "Package settings saved."
            else:
                raise ValueError("Unknown action.")
        except ValueError as e:
            error = str(e)

    cfg = authz.merged_package_config(package_id)
    groups = auth.list_groups()
    return pkg.admin_view(
        package=pkg,
        config=cfg,
        groups=groups,
        error=error,
        notice=notice,
    )
