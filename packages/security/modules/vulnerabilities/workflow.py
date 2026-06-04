"""Vulnerability workflow transitions and validation."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import audit
from packages.security.modules.vulnerabilities import db

PKG = "security"
VALID_STATUSES = frozenset({
    "open", "triaged", "in_progress", "pending_review", "mitigated", "closed",
    "false_positive", "risk_accepted", "wont_fix", "duplicate",
})
TERMINAL = frozenset({"mitigated", "closed", "false_positive", "wont_fix"})

# Status groups drive where a finding shows up.
#   ACTIVE   — a technician still has work to do; shown in the active findings
#              list and the dashboard priority queue.
#   REVIEW   — work is done and is waiting for an auditor to sign off; only
#              surfaced in the auditor review queue, not the technician list.
#   RESOLVED — finalised; archived in the "Closed" list, no technician action.
ACTIVE_STATUSES = frozenset({"open", "triaged", "in_progress"})
REVIEW_STATUSES = frozenset({"pending_review"})
RESOLVED_STATUSES = frozenset({
    "mitigated", "closed", "false_positive", "wont_fix", "risk_accepted", "duplicate",
})
FINAL_APPROVAL_STATUSES = frozenset({"mitigated", "closed", "false_positive", "wont_fix"})
TECHNICIAN_STATUS_CHOICES = ("open", "triaged", "in_progress", "duplicate")
RESOLUTION_STATUS_CHOICES = ("mitigated", "closed", "wont_fix", "false_positive")


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
    if new_status in FINAL_APPROVAL_STATUSES or new_status == "pending_review":
        raise WorkflowError("Use “Submit for final approval” for this outcome.")
    if new_status == "duplicate":
        if not duplicate_of_id:
            raise WorkflowError("Duplicate requires a canonical vulnerability id.")
        db.update_workflow(
            vuln_id,
            status="duplicate",
            duplicate_of_id=duplicate_of_id,
        )
    else:
        db.update_workflow(vuln_id, status=new_status)
        if new_status == "triaged":
            from packages import authz

            sla = authz.module_config(PKG, "vulnerabilities").get("sla") or {}
            sev = v.get("severity") or "medium"
            apply_sla_on_triage(vuln_id, sev, sla)
    db.add_event(vuln_id, "vuln.status_change", old_value=old, new_value=new_status, note=note)
    audit.record("vuln.status_change", target=str(vuln_id), details={"from": old, "to": new_status})


def submit_for_resolution(
    vuln_id: int,
    *,
    proposed_status: str,
    note: str,
    false_positive_reason: str = "",
    user: Any,
    role: str,
) -> None:
    """Technician submits a final outcome for auditor/admin approval."""
    if role not in ("admin", "technician"):
        raise WorkflowError("Technician role required.")
    if proposed_status not in FINAL_APPROVAL_STATUSES:
        raise WorkflowError("Choose a valid final outcome.")
    v = db.get_vulnerability(vuln_id)
    if not v:
        raise WorkflowError("Vulnerability not found.")
    old = v.get("status") or "open"
    if old == "pending_review":
        raise WorkflowError("This finding is already awaiting final approval.")
    if old in RESOLVED_STATUSES:
        raise WorkflowError("This finding is already resolved.")
    explanation = (note or "").strip()
    fp_reason = (false_positive_reason or "").strip()
    # A message is always required so the auditor understands what was done.
    if not (explanation or fp_reason):
        raise WorkflowError("Add a message describing what you did before submitting for approval.")
    # Mitigated/closed must be backed by evidence the auditor can review.
    if proposed_status in ("mitigated", "closed"):
        if db.evidence_count(vuln_id) < 1:
            raise WorkflowError("Attach at least one evidence file (Evidence tab) before submitting this outcome.")
    updates = {
        "status": "pending_review",
        "proposed_status": proposed_status,
        "previous_status": old,
        "previous_assignee_user_id": v.get("assignee_user_id"),
        "resolution_submitted_by": int(user["id"]),
        "resolution_submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    if proposed_status == "false_positive" and (fp_reason or explanation):
        updates["false_positive_reason"] = fp_reason or explanation
    elif explanation:
        updates["mitigation_note"] = explanation
    db.update_workflow(vuln_id, **updates)
    db.add_event(
        vuln_id,
        "vuln.resolution_submitted",
        old_value=old,
        new_value=proposed_status,
        note=explanation or fp_reason,
    )
    audit.record(
        "vuln.resolution_submitted",
        target=str(vuln_id),
        details={"from": old, "proposed": proposed_status},
    )


def decide_resolution(vuln_id: int, *, approve: bool, note: str, user: Any, role: str) -> None:
    """Auditor (or admin) accepts a final outcome, or sends it back."""
    if role not in ("admin", "auditor"):
        raise WorkflowError("Auditor approval required.")
    v = db.get_vulnerability(vuln_id)
    if not v:
        raise WorkflowError("Not found.")
    if (v.get("status") or "") != "pending_review":
        raise WorkflowError("This finding is not awaiting final approval.")
    proposed = v.get("proposed_status") or ""
    if proposed not in FINAL_APPROVAL_STATUSES:
        raise WorkflowError("This review item has no valid proposed outcome.")
    submitter = v.get("resolution_submitted_by") or v.get("closure_submitted_by")
    if approve and submitter and int(submitter) == int(user["id"]) and role != "admin":
        raise WorkflowError("You cannot approve a final outcome you submitted.")
    now = datetime.now(timezone.utc).isoformat()
    if approve:
        updates = {
            "status": proposed,
            "proposed_status": None,
            "previous_status": None,
            "previous_assignee_user_id": None,
        }
        if proposed == "closed":
            updates["closed_at"] = now
            updates["closed_by"] = int(user["id"])
        if note.strip() and proposed in ("mitigated", "closed", "wont_fix"):
            updates["mitigation_note"] = note.strip()
        db.update_workflow(vuln_id, **updates)
        db.add_event(vuln_id, "vuln.resolution_approved", old_value="pending_review", new_value=proposed, note=note)
        audit.record("vuln.resolution_approved", target=str(vuln_id), details={"status": proposed})
    else:
        if not (note or "").strip():
            raise WorkflowError("Add a note explaining why this is denied.")
        previous_status = v.get("previous_status") or "in_progress"
        previous_assignee = v.get("previous_assignee_user_id") or v.get("assignee_user_id")
        db.update_workflow(
            vuln_id,
            status=previous_status,
            assignee_user_id=previous_assignee,
            proposed_status=None,
            previous_status=None,
            previous_assignee_user_id=None,
        )
        db.add_event(vuln_id, "vuln.resolution_denied", old_value="pending_review", new_value=previous_status, note=note)
        audit.record("vuln.resolution_denied", target=str(vuln_id), details={"returned_to": previous_status})


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
