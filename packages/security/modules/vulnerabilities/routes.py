"""HTTP routes for the Vulnerability Manager module."""
from __future__ import annotations

import json
import mimetypes
import os
from datetime import date
from pathlib import Path

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename

import audit
import auth
from packages import authz
from packages.security.modules.vulnerabilities import db, demo, export, import_data, remediation, scanner, sync, workflow

PKG = "security"
MOD = "vulnerabilities"
bp = Blueprint("vuln", __name__)


def _role():
    return authz.current_role(PKG)


def _config_dir() -> Path:
    return Path(current_app.config.get("PACKAGES_CONFIG_DIR", ""))


def _evidence_root() -> Path:
    root = _config_dir() / "security" / "vulnerabilities" / "evidence"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _max_upload_bytes() -> int:
    mb = int(os.environ.get("SCRINIUM_MAX_ATTACHMENT_MB", "50"))
    return mb * 1024 * 1024


_TERMINAL = {"mitigated", "closed", "false_positive", "wont_fix", "duplicate"}


def _next_step(v: dict, role: str, evidence_count: int) -> dict:
    """Plain-language guidance on what to do next, based on state and role."""
    status = v.get("status") or "open"
    ra = v.get("risk_accept_state") or "none"
    has_assignee = bool(v.get("assignee_user_id"))

    if status == "pending_review":
        proposed = v.get("proposed_status") or "final outcome"
        if role in ("admin", "auditor"):
            return {
                "tone": "review",
                "title": "Review the proposed final outcome",
                "detail": f"A technician submitted this as {proposed}. Verify the notes and evidence, then approve or send it back.",
                "focus": "approve-resolution",
            }
        return {
            "tone": "wait",
            "title": "Awaiting final approval",
            "detail": f"This is waiting for an auditor or admin to approve the proposed outcome: {proposed}.",
        }
    if ra == "requested":
        if role in ("admin", "auditor"):
            return {
                "tone": "review",
                "title": "Decide the risk-acceptance request",
                "detail": "A technician asked to accept this risk. Review the justification and approve or reject it.",
                "focus": "approve-risk",
            }
        return {
            "tone": "wait",
            "title": "Waiting for auditor decision",
            "detail": "You requested risk acceptance. An auditor or admin must approve or reject it.",
        }
    if status == "risk_accepted":
        until = v.get("risk_accept_until") or "expiry"
        return {
            "tone": "done",
            "title": "Risk accepted",
            "detail": f"No remediation required for now. This is monitored until {until}.",
        }
    if status in _TERMINAL:
        return {
            "tone": "done",
            "title": "Finding resolved",
            "detail": "No action needed. If the scanner re-detects it, it will reopen automatically.",
        }
    if not has_assignee:
        return {
            "tone": "action",
            "title": "Assign an owner",
            "detail": "Pick the technician who will drive remediation, then move it through triage.",
            "focus": "assignee",
        }
    if status == "open":
        return {
            "tone": "action",
            "title": "Triage this finding",
            "detail": "Confirm the severity and set status to Triaged to start the SLA clock.",
            "focus": "status",
        }
    if status == "triaged":
        return {
            "tone": "action",
            "title": "Start remediation",
            "detail": "When work begins, move the status to In progress.",
            "focus": "status",
        }
    if status == "in_progress":
        return {
            "tone": "action",
            "title": "Submit the final outcome",
            "detail": "When work is done, attach evidence, then set the status to Mitigated, Closed, Won't fix, or False positive to send it for auditor approval.",
            "focus": "status",
        }
    return {
        "tone": "action",
        "title": "Keep this finding moving",
        "detail": "Update the status and add a note describing progress.",
        "focus": "status",
    }


@bp.route("/")
@authz.package_login_required(PKG)
@authz.module_enabled_required(PKG, MOD)
def dashboard():
    stats = db.dashboard_stats()
    by = stats.get("by_severity") or {}
    stats["severity_max"] = max(1, max(by.values()) if by else 1)
    last_sync = db.last_sync_run()
    recent = db.list_vulnerabilities(
        limit=12, sort="severity", statuses=list(workflow.ACTIVE_STATUSES)
    )
    users = auth.list_users()
    user_map = {int(u["id"]): u["username"] for u in users}
    user = auth.current_user()
    return render_template(
        "security/vulnerabilities/dashboard.html",
        stats=stats,
        last_sync=last_sync,
        recent=recent,
        user_map=user_map,
        current_user_id=int(user["id"]) if user else None,
        role=_role(),
        hide_sidebar=True,
    )


@bp.route("/api/search")
@authz.package_login_required(PKG)
@authz.module_enabled_required(PKG, MOD)
def api_search():
    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify({"results": [], "query": q})
    rows = db.list_vulnerabilities(q=q, limit=12, sort="severity")
    users = auth.list_users()
    user_map = {int(u["id"]): u["username"] for u in users}
    results = [
        {
            "id": r["id"],
            "title": r.get("title") or r.get("external_id"),
            "host": r.get("host") or r.get("ip") or "",
            "cve": r.get("cve") or "",
            "severity": r.get("severity") or "info",
            "status": r.get("wf_status") or "open",
            "kev": bool(r.get("kev")),
            "assignee": user_map.get(r.get("assignee_user_id"), ""),
            "url": url_for("vuln.detail", vuln_id=r["id"]),
        }
        for r in rows
    ]
    return jsonify(
        {
            "results": results,
            "query": q,
            "all_url": url_for("vuln.findings_list", q=q),
        }
    )


_STATUS_VIEWS = {
    "active": list(workflow.ACTIVE_STATUSES),
    "review": list(workflow.REVIEW_STATUSES),
    "resolved": list(workflow.RESOLVED_STATUSES),
}


@bp.route("/findings")
@authz.package_login_required(PKG)
@authz.module_enabled_required(PKG, MOD)
def findings_list():
    role = _role()
    user = auth.current_user()
    q = request.args.get("q") or None
    explicit_status = request.args.get("status") or None
    pending_ra = bool(request.args.get("pending_ra"))
    # Default to the active work queue; a specific status, search, or risk
    # filter implies the user wants to reach beyond it, so show everything.
    view = request.args.get("view") or ("all" if (q or explicit_status or pending_ra) else "active")
    if role not in ("admin", "auditor") and view in ("review", "resolved"):
        view = "active"
    if view == "all":
        statuses = None
    elif view == "active" and role == "technician":
        statuses = list(workflow.ACTIVE_STATUSES | workflow.REVIEW_STATUSES)
    else:
        statuses = _STATUS_VIEWS.get(view, _STATUS_VIEWS["active"])
    rows = db.list_vulnerabilities(
        status=explicit_status,
        statuses=statuses,
        severity=request.args.get("severity") or None,
        assignee_id=int(request.args["assignee"]) if request.args.get("assignee") else None,
        owner_filter=request.args.get("owner") or None,
        current_user_id=int(user["id"]) if user else None,
        host_like=request.args.get("host") or None,
        tag=request.args.get("tag") or None,
        kev_only=bool(request.args.get("kev")),
        overdue_only=bool(request.args.get("overdue")),
        q=q,
        risk_pending=pending_ra,
        sort=request.args.get("sort") or "severity",
    )
    users = auth.list_users()
    user_map = {int(u["id"]): u["username"] for u in users}
    return render_template(
        "security/vulnerabilities/list.html",
        rows=rows,
        users=users,
        user_map=user_map,
        current_user_id=int(user["id"]) if user else None,
        today=date.today().isoformat(),
        role=role,
        view=view,
        filters=request.args,
        hide_sidebar=True,
    )


@bp.route("/duplicates")
@authz.require_auditor(PKG)
@authz.module_enabled_required(PKG, MOD)
def duplicates_page():
    role = _role()
    groups_db = db.list_duplicate_groups(limit=100)
    groups_legacy = db.scan_unkeyed_duplicates(limit=100)
    return render_template(
        "security/vulnerabilities/duplicates.html",
        groups_db=groups_db,
        groups_legacy=groups_legacy,
        role=role,
        hide_sidebar=True,
    )


@bp.route("/<int:vuln_id>")
@authz.package_login_required(PKG)
@authz.module_enabled_required(PKG, MOD)
def detail(vuln_id: int):
    v = db.get_vulnerability(vuln_id)
    if not v:
        abort(404)
    role = _role()
    tags = db.list_tags(vuln_id)
    comments = db.list_comments(vuln_id)
    events = db.list_events(vuln_id)
    evidence = db.list_evidence(vuln_id)
    users = auth.list_users()
    assignee_name = None
    if v.get("assignee_user_id"):
        for u in users:
            if int(u["id"]) == int(v["assignee_user_id"]):
                assignee_name = u["username"]
                break
    refs_raw = v.get("refs_json") or "[]"
    try:
        refs = json.loads(refs_raw) if isinstance(refs_raw, str) else (refs_raw or [])
    except json.JSONDecodeError:
        refs = []
    remediation_links = remediation.remediation_links_for_display(
        solution=v.get("solution") or "",
        cve=v.get("cve") or "",
        refs=refs,
    )
    next_step = _next_step(v, role, len(evidence))
    resolution_submitter = None
    submitter_id = v.get("resolution_submitted_by") or v.get("closure_submitted_by")
    if submitter_id:
        for u in users:
            if int(u["id"]) == int(submitter_id):
                resolution_submitter = u["username"]
                break
    return render_template(
        "security/vulnerabilities/detail.html",
        v=v,
        tags=tags,
        comments=comments,
        events=events,
        evidence=evidence,
        users=users,
        assignee_name=assignee_name,
        refs=refs,
        remediation_links=remediation_links,
        next_step=next_step,
        status_group=workflow.status_group(v.get("status")),
        technician_status_choices=workflow.TECHNICIAN_STATUS_CHOICES,
        resolution_status_choices=workflow.RESOLUTION_STATUS_CHOICES,
        resolution_submitter=resolution_submitter,
        role=role,
        hide_sidebar=True,
    )


@bp.route("/<int:vuln_id>/action", methods=["POST"])
@authz.require_technician(PKG)
@authz.module_enabled_required(PKG, MOD)
def action(vuln_id: int):
    auth.verify_csrf()
    role = _role()
    user = auth.current_user()
    act = request.form.get("action") or ""
    try:
        if act == "status":
            new_status = request.form.get("status") or ""
            if new_status in workflow.FINAL_APPROVAL_STATUSES:
                # A closure outcome chosen in the status dropdown is a request for
                # auditor sign-off, not an immediate change.
                workflow.submit_for_resolution(
                    vuln_id,
                    proposed_status=new_status,
                    note=request.form.get("note") or "",
                    false_positive_reason=request.form.get("false_positive_reason") or "",
                    user=user,
                    role=role,
                )
            else:
                workflow.set_status(
                    vuln_id,
                    new_status,
                    user=user,
                    role=role,
                    note=request.form.get("note") or "",
                    false_positive_reason=request.form.get("false_positive_reason") or "",
                    duplicate_of_id=int(request.form["duplicate_of"]) if request.form.get("duplicate_of") else None,
                    admin_override=role == "admin",
                )
        elif act == "submit_resolution":
            workflow.submit_for_resolution(
                vuln_id,
                proposed_status=request.form.get("proposed_status") or "",
                note=request.form.get("note") or "",
                false_positive_reason=request.form.get("false_positive_reason") or "",
                user=user,
                role=role,
            )
        elif act == "assign":
            aid = request.form.get("assignee_id")
            workflow.assign(vuln_id, int(aid) if aid else None, user=user, role=role)
        elif act == "severity":
            workflow.override_severity(vuln_id, request.form.get("severity") or "info", role=role)
        elif act == "request_risk_accept":
            workflow.request_risk_acceptance(
                vuln_id,
                reason=request.form.get("reason") or "",
                until=request.form.get("until") or "",
                user=user,
                role=role,
            )
        elif act == "comment":
            body = request.form.get("body") or ""
            if body.strip():
                db.add_comment(vuln_id, body, int(user["id"]), str(user["username"]))
                audit.record("vuln.comment", target=str(vuln_id))
        elif act == "tags":
            raw = request.form.get("tags") or ""
            names = [t.strip() for t in raw.replace(",", "\n").splitlines() if t.strip()]
            db.set_tags(vuln_id, names)
            audit.record("vuln.tag", target=str(vuln_id), details={"tags": names})
        elif act == "evidence":
            f = request.files.get("file")
            if not f or not f.filename:
                raise workflow.WorkflowError("No file uploaded.")
            fn = secure_filename(f.filename)
            dest_dir = _evidence_root() / str(vuln_id)
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / fn
            data = f.read()
            if len(data) > _max_upload_bytes():
                raise workflow.WorkflowError("File too large.")
            dest.write_bytes(data)
            rel = str(dest.relative_to(_config_dir()))
            mime = f.mimetype or mimetypes.guess_type(fn)[0] or "application/octet-stream"
            db.add_evidence(
                vuln_id, fn, rel, mime, len(data), int(user["id"]),
                note=request.form.get("note") or "",
            )
            audit.record("vuln.evidence_upload", target=str(vuln_id), details={"file": fn})
        else:
            raise workflow.WorkflowError("Unknown action.")
    except workflow.WorkflowError as e:
        return redirect(url_for("vuln.detail", vuln_id=vuln_id, error=str(e)))
    return redirect(url_for("vuln.detail", vuln_id=vuln_id))


@bp.route("/<int:vuln_id>/approve-risk", methods=["POST"])
@authz.require_auditor(PKG)
@authz.module_enabled_required(PKG, MOD)
def approve_risk(vuln_id: int):
    auth.verify_csrf()
    workflow.decide_risk_acceptance(
        vuln_id,
        approve=bool(request.form.get("approve")),
        note=request.form.get("note") or "",
        user=auth.current_user(),
        role=_role(),
    )
    return redirect(url_for("vuln.detail", vuln_id=vuln_id))


@bp.route("/<int:vuln_id>/approve-resolution", methods=["POST"])
@authz.require_auditor(PKG)
@authz.module_enabled_required(PKG, MOD)
def approve_resolution(vuln_id: int):
    auth.verify_csrf()
    try:
        workflow.decide_resolution(
            vuln_id,
            approve=bool(request.form.get("approve")),
            note=request.form.get("note") or "",
            user=auth.current_user(),
            role=_role(),
        )
    except workflow.WorkflowError as e:
        return redirect(url_for("vuln.detail", vuln_id=vuln_id, error=str(e)))
    return redirect(url_for("vuln.detail", vuln_id=vuln_id))


@bp.route("/bulk", methods=["POST"])
@authz.require_technician(PKG)
@authz.module_enabled_required(PKG, MOD)
def bulk():
    auth.verify_csrf()
    ids = request.form.getlist("vuln_id")
    act = request.form.get("bulk_action") or ""
    role = _role()
    user = auth.current_user()
    for sid in ids:
        try:
            vid = int(sid)
        except ValueError:
            continue
        if act == "assign":
            aid = request.form.get("assignee_id")
            workflow.assign(vid, int(aid) if aid else None, user=user, role=role)
        elif act == "status" and request.form.get("status"):
            workflow.set_status(vid, request.form["status"], user=user, role=role, note="bulk")
    audit.record("vuln.bulk_action", details={"action": act, "count": len(ids)})
    return redirect(url_for("vuln.findings_list"))


@bp.route("/import", methods=["GET", "POST"])
@authz.require_technician(PKG)
@authz.module_enabled_required(PKG, MOD)
def import_page():
    import_result = None
    if request.method == "POST":
        auth.verify_csrf()
        f = request.files.get("file")
        if not f or not f.filename:
            return redirect(url_for("vuln.import_page", error="Choose a CSV or Excel file."))
        import_result = import_data.import_file(f.filename, f.stream)
        audit.record(
            "vuln.import",
            details={
                "file": f.filename,
                "added": import_result.added,
                "updated": import_result.updated,
                "merged": import_result.merged,
            },
        )
        if import_result.ok:
            return redirect(
                url_for(
                    "vuln.findings_list",
                    notice=import_result.summary(),
                )
            )
    return render_template(
        "security/vulnerabilities/import.html",
        role=_role(),
        import_result=import_result,
        hide_sidebar=True,
    )


@bp.route("/exports")
@authz.require_auditor(PKG)
@authz.module_enabled_required(PKG, MOD)
def exports_page():
    return render_template(
        "security/vulnerabilities/exports.html",
        role=_role(),
        hide_sidebar=True,
    )


@bp.route("/export/<kind>")
@authz.require_auditor(PKG)
@authz.module_enabled_required(PKG, MOD)
def export_download(kind: str):
    since = request.args.get("since") or ""
    until = request.args.get("until") or ""
    if kind == "full":
        body = export.full_register_csv()
        export.log_export("full")
        return Response(body, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=vuln-register.csv"})
    if kind == "resolved":
        body = export.resolved_in_period_csv(since, until)
        export.log_export("resolved", {"since": since, "until": until})
        return Response(body, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=vuln-resolved.csv"})
    if kind == "open":
        body = export.open_overdue_csv()
        export.log_export("open_overdue")
        return Response(body, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=vuln-open-overdue.csv"})
    if kind == "poam":
        body = export.poam_csv()
        export.log_export("poam")
        return Response(body, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=vuln-poam.csv"})
    if kind == "risk_acceptance":
        body = export.risk_acceptance_csv()
        export.log_export("risk_acceptance")
        return Response(body, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=vuln-risk-acceptance.csv"})
    if kind == "json":
        body = export.snapshot_json()
        export.log_export("json")
        return Response(body, mimetype="application/json", headers={"Content-Disposition": "attachment; filename=vuln-snapshot.json"})
    if kind == "audit_pack":
        data = export.audit_pack_zip(_config_dir())
        export.log_export("audit_pack")
        return Response(
            data,
            mimetype="application/zip",
            headers={"Content-Disposition": "attachment; filename=vuln-audit-pack.zip"},
        )
    abort(404)


@bp.route("/activity")
@authz.require_auditor(PKG)
@authz.module_enabled_required(PKG, MOD)
def activity():
    import sqlite3
    from packages.db import connect

    rows: list[dict] = []
    with connect(PKG) as c:
        for r in c.execute(
            "SELECT * FROM vuln_events ORDER BY ts DESC LIMIT 200"
        ):
            rows.append(dict(r))
    return render_template(
        "security/vulnerabilities/activity.html",
        rows=rows,
        role=_role(),
        hide_sidebar=True,
    )


@bp.route("/admin/seed-demo", methods=["POST"])
@auth.admin_required
def seed_demo():
    auth.verify_csrf()
    user = auth.current_user()
    vid = demo.seed_demo_vulnerability(assignee_id=int(user["id"]))
    audit.record("vuln.demo_seed", target=str(vid))
    return redirect(url_for("vuln.detail", vuln_id=vid, notice="Demo finding refreshed."))


@bp.route("/admin/sync", methods=["POST"])
@auth.admin_required
def admin_sync():
    if not auth.current_user()["is_admin"] and _role() not in ("admin", "technician"):
        abort(403)
    auth.verify_csrf()
    result = sync.run_sync(trigger="manual")
    return redirect(url_for("vuln.dashboard", notice=result.get("message")))


@bp.route("/admin/test-scanner", methods=["POST"])
@auth.admin_required
def test_scanner():
    auth.verify_csrf()
    result = scanner.test_connection()
    return redirect(
        url_for(
            "packages_admin.package_admin",
            package_id=PKG,
            scanner_test=result.message,
            scanner_ok=result.ok,
        )
    )


@bp.route("/evidence/<int:evidence_id>")
@authz.package_login_required(PKG)
@authz.module_enabled_required(PKG, MOD)
def download_evidence(evidence_id: int):
    with db.connect(db.PKG) as c:
        row = c.execute(
            "SELECT * FROM vuln_evidence WHERE id = ?", (evidence_id,)
        ).fetchone()
    if not row:
        abort(404)
    path = _config_dir() / row["stored_path"]
    if not path.is_file():
        abort(404)
    return send_file(path, as_attachment=True, download_name=row["filename"])
