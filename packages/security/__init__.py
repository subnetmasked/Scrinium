"""Security package."""
from __future__ import annotations

import json

from flask import redirect, render_template, request, url_for

import audit
import auth
from packages import authz, registry
from packages.registry import Package, Role
from packages.security.modules.vulnerabilities import scanner, sync
from packages.security.modules.vulnerabilities import register as register_vuln_module


def landing_view(*, package, role, module_cards):
    return render_template(
        "security/package.html",
        package=package,
        role=role,
        module_cards=module_cards,
        hide_sidebar=True,
    )


def admin_view(*, package, config, groups, error=None, notice=None):
    if request.method == "POST" and request.form.get("action") == "save_vuln_module":
        auth.verify_csrf()
        try:
            cfg = authz.merged_package_config("security")
            mods = cfg.setdefault("modules", {})
            vuln = dict(mods.get("vulnerabilities") or {})
            vuln["enabled"] = bool(request.form.get("vuln_enabled"))
            try:
                vuln["sync_interval_minutes"] = max(
                    0, int(request.form.get("sync_interval_minutes") or 0)
                )
            except ValueError:
                vuln["sync_interval_minutes"] = 0
            sla = {}
            for sev in ("critical", "high", "medium", "low", "info"):
                try:
                    sla[sev] = int(request.form.get(f"sla_{sev}") or 90)
                except ValueError:
                    sla[sev] = 90
            vuln["sla"] = sla
            scanner.save_scanner_settings(request.form)
            cfg = authz.merged_package_config("security")
            mods = cfg.setdefault("modules", {})
            mods["vulnerabilities"] = {**mods.get("vulnerabilities", {}), **vuln}
            cfg["modules"] = mods
            authz.set_package_config("security", cfg)
            notice = "Vulnerability module settings saved."
            audit.record("package.settings_change", target="security.vulnerabilities")
        except ValueError as e:
            error = str(e)
    scanner_cfg = scanner.scanner_settings(redact=True)
    vuln_cfg = authz.module_config("security", "vulnerabilities")
    scanner_test = request.args.get("scanner_test")
    scanner_ok = request.args.get("scanner_ok") == "True"
    return render_template(
        "security/admin_settings.html",
        package=package,
        config=config,
        groups=groups,
        scanner_cfg=scanner_cfg,
        vuln_cfg=vuln_cfg,
        field_map_json=json.dumps(
            scanner_cfg.get("field_map") or scanner.DEFAULT_SCANNER["field_map"],
            indent=2,
        ),
        severity_map_json=json.dumps(
            scanner_cfg.get("severity_map") or scanner.DEFAULT_SCANNER["severity_map"],
            indent=2,
        ),
        error=error,
        notice=notice,
        scanner_test=scanner_test,
        scanner_ok=scanner_ok,
    )


def register() -> None:
    mod = register_vuln_module()
    pkg = Package(
        id="security",
        name="Security",
        icon="shield",
        roles=(
            Role("auditor", "Auditor", "Read-only access, exports, risk-acceptance approval."),
            Role("technician", "Technician", "Operational remediation and evidence."),
        ),
        modules=(mod,),
        admin_view=admin_view,
        landing_view=landing_view,
    )
    registry.register_package(pkg)
