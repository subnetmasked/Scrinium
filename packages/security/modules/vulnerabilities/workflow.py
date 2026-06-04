"""Vulnerability workflow transitions and validation."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import audit
from packages.security.modules.vulnerabilities import db

PKG = "security"
VALID_STATUSES = frozenset({
    "open", "triaged", "in_progress", "mitigated", "pending_closure", "closed",
    "false_positive", "risk_accepted", "wont_fix", "duplicate",
})
TERMINAL = frozenset({"closed", "false_positive", "wont_fix"})

# Status groups drive where a finding shows up.
#   ACTIVE   — a technician still has work to do; shown in the active findings
#              list and the dashboard priority queue.
#   REVIEW   — work is done and is waiting for an auditor to sign off; only
#              surfaced in the auditor review queue, not the technician list.
#   RESOLVED — finalised; archived in the "Closed" list, no technician action.
ACTIVE_STATUSES = frozenset({"open", "triaged", "in_progress", "mitigated"})
REVIEW_STATUSES = frozenset({"pending_closure"})
RESOLVED_STATUSES = frozenset({
    "closed", "false_positive", "wont_fix", "risk_accepted", "duplicate",
})
# Statuses a technician picks directly. Closing now goes through an auditor,
# so "closed" is not in the dropdown — technicians submit for closure instead.
TECHNICIAN_STATUS_CHOICES = (
    "open", "triaged", "in_progress", "mitigated",
    "false_positive", "wont_fix", "duplicate",
)


def status_group(status: str | None) -> str:
    s = status or "open"
    if s in RESOLVED_STATUSES:
        return "resolved"
    if s in REVIEW_STATUSES:
        return "review"
    return "active"


class WorkflowError(ValueError):
    pass


def set_status(
    vuln_id: int,
    new_status: str,
    *,
    user: Any,
    role: str,
    note: str = "",
    false_positive_reason: str = "",
    duplicate_of_id: int | None = None,
    admin_override: bool = False,
) -> None:
    if new_status not in VALID_STATUSES:
        raise WorkflowError(f"Invalid status: {new_status}")
    v = db.get_vulnerability(vuln_id)
    if not v:
        raise WorkflowError("Vulnerability not found.")
    old = v.get("status") or "open"
    if role not in ("admin", "technician"):
        raise WorkflowError("Technician role required.")
    # Every status change must carry an explanation. For false positives the
    # dedicated reason field counts as the explanation.
    explanation = (note or "").strip()
    if new_status == "false_positive":
        explanation = explanation or (false_positive_reason or "").strip()
    if not explanation:
        raise WorkflowError("Please add a note explaining this status change.")
    if new_status == "closed":
        # Closing is an auditor decision. Technicians submit for closure and an
        # auditor signs off; only an admin override can close directly here.
        if not admin_override:
            raise WorkflowError(
                "Closing requires auditor sign-off. Use “Submit for closure” instead."
            )
        if db.evidence_count(vuln_id) < 1:
            raise WorkflowError("At least one evidence file is required to close.")
        db.update_workflow(
            vuln_id,
            status="closed",
            closed_at=datetime.now(timezone.utc).isoformat(),
            closed_by=int(user["id"]),
            mitigation_note=(note or v.get("mitigation_note") or "").strip(),
        )
    elif new_status == "pending_closure":
        raise WorkflowError("Use “Submit for closure” to send a finding for review.")
    elif new_status == "false_positive":
        if not (false_positive_reason or note or "").strip():
            raise WorkflowError("False positive requires a reason.")
        db.update_workflow(
            vuln_id,
            status="false_positive",
            false_positive_reason=(false_positive_reason or note).strip(),
        )
    elif new_status == "duplicate":
        if not duplicate_of_id:
            raise WorkflowError("Duplicate requires a canonical vulnerability id.")
        db.update_workflow(
            vuln_id,
            status="duplicate",
            duplicate_of_id=duplicate_of_id,
        )
    elif new_status == "wont_fix":
        if not (note or "").strip():
            raise WorkflowError("Won't fix requires a reason.")
        db.update_workflow(vuln_id, status="wont_fix", mitigation_note=note.strip())
    else:
        db.update_workflow(vuln_id, status=new_status)
        if new_status == "triaged":
            from packages import authz

            sla = authz.module_config(PKG, "vulnerabilities").get("sla") or {}
            sev = v.get("severity") or "medium"
            apply_sla_on_triage(vuln_id, sev, sla)
    db.add_event(vuln_id, "vuln.status_change", old_value=old, new_value=new_status, note=note)
    audit.record("vuln.status_change", target=str(vuln_id), details={"from": old, "to": new_status})


def submit_for_closure(vuln_id: int, *, note: str, user: Any, role: str) -> None:
    """Technician hands a remediated finding to an auditor for closure sign-off."""
    if role not in ("admin", "technician"):
        raise WorkflowError("Technician role required.")
    v = db.get_vulnerability(vuln_id)
    if not v:
        raise WorkflowError("Vulnerability not found.")
    old = v.get("status") or "open"
    if old == "pending_closure":
        raise WorkflowError("This finding is already awaiting closure review.")
    if old != "mitigated":
        raise WorkflowError("Mark the finding as Mitigated before submitting it for closure.")
    if db.evidence_count(vuln_id) < 1:
        raise WorkflowError("Attach at least one evidence file before submitting for closure.")
    if not (note or "").strip():
        raise WorkflowError("Add a closure summary describing the remediation.")
    db.update_workflow(
        vuln_id,
        status="pending_closure",
        mitigation_note=note.strip(),
        closure_submitted_by=int(user["id"]),
        closure_submitted_at=datetime.now(timezone.utc).isoformat(),
    )
    db.add_event(vuln_id, "vuln.closure_submitted", old_value=old, new_value="pending_closure", note=note)
    audit.record("vuln.closure_submitted", target=str(vuln_id))


def decide_closure(vuln_id: int, *, approve: bool, note: str, user: Any, role: str) -> None:
    """Auditor (or admin) accepts the completed remediation, or sends it back."""
    if role not in ("admin", "auditor"):
        raise WorkflowError("Auditor approval required.")
    v = db.get_vulnerability(vuln_id)
    if not v:
        raise WorkflowError("Not found.")
    if (v.get("status") or "") != "pending_closure":
        raise WorkflowError("This finding is not awaiting closure review.")
    submitter = v.get("closure_submitted_by")
    if approve and submitter and int(submitter) == int(user["id"]) and role != "admin":
        raise WorkflowError("You cannot approve a closure you submitted.")
    now = datetime.now(timezone.utc).isoformat()
    if approve:
        db.update_workflow(
            vuln_id,
            status="closed",
            closed_at=now,
            closed_by=int(user["id"]),
            mitigation_note=(note.strip() or v.get("mitigation_note") or "").strip(),
        )
        db.add_event(vuln_id, "vuln.closure_approved", old_value="pending_closure", new_value="closed", note=note)
        audit.record("vuln.closure_approved", target=str(vuln_id))
    else:
        if not (note or "").strip():
            raise WorkflowError("Add a note explaining why the closure is rejected.")
        db.update_workflow(vuln_id, status="mitigated")
        db.add_event(vuln_id, "vuln.closure_rejected", old_value="pending_closure", new_value="mitigated", note=note)
        audit.record("vuln.closure_rejected", target=str(vuln_id))


def assign(vuln_id: int, assignee_id: int | None, *, user: Any, role: str) -> None:
    if role not in ("admin", "technician"):
        raise WorkflowError("Technician role required.")
    v = db.get_vulnerability(vuln_id)
    if not v:
        raise WorkflowError("Not found.")
    old = v.get("assignee_user_id")
    db.update_workflow(vuln_id, assignee_user_id=assignee_id)
    db.add_event(
        vuln_id,
        "vuln.assign",
        old_value=str(old) if old else "",
        new_value=str(assignee_id) if assignee_id else "",
    )
    audit.record("vuln.assign", target=str(vuln_id), details={"assignee_id": assignee_id})


def override_severity(vuln_id: int, severity: str, *, role: str) -> None:
    if role not in ("admin", "technician"):
        raise WorkflowError("Technician role required.")
    allowed = {"critical", "high", "medium", "low", "info"}
    if severity not in allowed:
        raise WorkflowError("Invalid severity.")
    v = db.get_vulnerability(vuln_id)
    if not v:
        raise WorkflowError("Not found.")
    old = v.get("severity")
    with db.connect(db.PKG) as c:
        c.execute("UPDATE vulnerabilities SET severity = ? WHERE id = ?", (severity, vuln_id))
    db.add_event(vuln_id, "vuln.severity_override", old_value=old, new_value=severity)
    audit.record("vuln.severity_override", target=str(vuln_id), details={"severity": severity})


def request_risk_acceptance(
    vuln_id: int,
    *,
    reason: str,
    until: str,
    user: Any,
    role: str,
) -> None:
    if role not in ("admin", "technician"):
        raise WorkflowError("Technician role required.")
    if not reason.strip():
        raise WorkflowError("Risk acceptance requires a justification.")
    if not until.strip():
        raise WorkflowError("Risk acceptance requires an expiry date.")
    v = db.get_vulnerability(vuln_id)
    if not v:
        raise WorkflowError("Not found.")
    if v.get("risk_accept_state") == "requested":
        raise WorkflowError("A request is already pending.")
    db.update_workflow(
        vuln_id,
        risk_accept_state="requested",
        risk_accept_reason=reason.strip(),
        risk_accept_until=until.strip(),
        risk_accept_requested_by=int(user["id"]),
        risk_accept_requested_at=datetime.now(timezone.utc).isoformat(),
        risk_accept_decided_by=None,
        risk_accept_decided_at=None,
        risk_accept_decision_note=None,
    )
    db.add_event(vuln_id, "vuln.risk_acceptance_requested", note=reason)
    audit.record("vuln.risk_acceptance_requested", target=str(vuln_id))


def decide_risk_acceptance(
    vuln_id: int,
    *,
    approve: bool,
    note: str,
    user: Any,
    role: str,
) -> None:
    if role not in ("admin", "auditor"):
        raise WorkflowError("Auditor approval required.")
    v = db.get_vulnerability(vuln_id)
    if not v:
        raise WorkflowError("Not found.")
    if v.get("risk_accept_state") != "requested":
        raise WorkflowError("No pending risk acceptance request.")
    if int(v.get("risk_accept_requested_by") or 0) == int(user["id"]) and role != "admin":
        raise WorkflowError("You cannot approve your own request.")
    now = datetime.now(timezone.utc).isoformat()
    if approve:
        db.update_workflow(
            vuln_id,
            status="risk_accepted",
            risk_accept_state="accepted",
            risk_accept_decided_by=int(user["id"]),
            risk_accept_decided_at=now,
            risk_accept_decision_note=(note or "").strip(),
        )
        db.add_event(vuln_id, "vuln.risk_acceptance_approved", note=note)
        audit.record("vuln.risk_acceptance_approved", target=str(vuln_id))
    else:
        db.update_workflow(
            vuln_id,
            risk_accept_state="rejected",
            risk_accept_decided_by=int(user["id"]),
            risk_accept_decided_at=now,
            risk_accept_decision_note=(note or "").strip(),
        )
        db.add_event(vuln_id, "vuln.risk_acceptance_rejected", note=note)
        audit.record("vuln.risk_acceptance_rejected", target=str(vuln_id))


def apply_sla_on_triage(vuln_id: int, severity: str, sla_days: dict) -> None:
    days = sla_days.get(severity) or sla_days.get("medium") or 90
    try:
        from datetime import date, timedelta

        due = (date.today() + timedelta(days=int(days))).isoformat()
    except (TypeError, ValueError):
        due = None
    v = db.get_vulnerability(vuln_id)
    if v and not v.get("due_date") and due:
        db.update_workflow(vuln_id, due_date=due)
