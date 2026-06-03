"""Vulnerability Manager module."""
from __future__ import annotations

from flask import render_template, url_for

from packages import authz, registry
from packages.registry import Module
from packages.security.modules.vulnerabilities import db
from packages.security.modules.vulnerabilities.routes import bp

PKG = "security"
MOD = "vulnerabilities"

DEFAULT_MODULE_CONFIG = {
    "enabled": False,
    "sync_interval_minutes": 0,
    "sla": {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365},
    "scanner": {},
}


def summary_card(user, role) -> dict:
    if not authz.module_enabled(PKG, MOD):
        return {
            "id": MOD,
            "name": "Vulnerability Manager",
            "icon": "shield",
            "disabled": True,
            "message": "Module disabled in admin settings.",
        }
    stats = db.dashboard_stats()
    return {
        "id": MOD,
        "name": "Vulnerability Manager",
        "icon": "shield",
        "url": url_for("vuln.dashboard"),
        "open": stats.get("total_open", 0),
        "overdue": stats.get("overdue", 0),
        "pending_ra": stats.get("pending_risk_acceptance", 0),
        "kev": stats.get("kev_open", 0),
    }


def register() -> Module:
    return Module(
        id=MOD,
        name="Vulnerability Manager",
        icon="shield",
        blueprint=bp,
        migrate=db.migrate,
        summary_card=summary_card,
        default_config=DEFAULT_MODULE_CONFIG,
    )
