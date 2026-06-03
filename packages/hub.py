"""Package landing pages at /<package_id>."""
from __future__ import annotations

from flask import Blueprint

import auth
from packages import authz, registry


def _make_landing_view(pkg):
    def landing():
        user = auth.current_user()
        role = authz.current_role(pkg.id, user)
        cards = []
        for mod in pkg.modules:
            if not authz.module_enabled(pkg.id, mod.id):
                continue
            cards.append(mod.summary_card(user, role))
        return pkg.landing_view(package=pkg, role=role, module_cards=cards)

    return landing


def mount_package_hubs(app) -> None:
    for pkg in registry.iter_packages():
        bp = Blueprint(f"pkg_{pkg.id}", pkg.id, url_prefix=f"/{pkg.id}")
        view = _make_landing_view(pkg)
        view = authz.package_login_required(pkg.id)(view)
        bp.add_url_rule("/", view_func=view, endpoint="landing")
        app.register_blueprint(bp)
