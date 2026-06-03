"""CSV/JSON/ZIP exports for vulnerabilities."""
from __future__ import annotations

import csv
import io
import json
import zipfile
from datetime import datetime
from typing import Any, Optional

import audit
import auth
from packages.security.modules.vulnerabilities import db

CSV_FIELDS = [
    "id", "external_id", "title", "severity", "scanner_severity", "status",
    "host", "ip", "port", "cve", "cwe", "cvss", "kev", "exploit_available",
    "assignee_user_id", "due_date", "mitigation_note", "false_positive_reason",
    "risk_accept_state", "risk_accept_reason", "risk_accept_until",
    "closed_at", "first_seen", "last_seen", "reopened_count",
]


def _row_csv(v: dict) -> dict:
    return {k: v.get(k, v.get(f"wf_{k}", "")) for k in CSV_FIELDS if k in v or k in (
        "status",
    )} | {
        "status": v.get("wf_status") or v.get("status") or "",
        **{k: v.get(k, "") for k in CSV_FIELDS},
    }


def vulnerabilities_to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    w.writeheader()
    for v in rows:
        line = {f: v.get(f, "") for f in CSV_FIELDS}
        line["status"] = v.get("wf_status") or v.get("status") or ""
        w.writerow(line)
    return buf.getvalue()


def full_register_csv() -> str:
    return vulnerabilities_to_csv(db.list_all_for_export())


def resolved_in_period_csv(since: str, until: str) -> str:
    rows = db.list_all_for_export()
    out = []
    for v in rows:
        st = v.get("wf_status") or v.get("status")
        closed = v.get("closed_at") or ""
        if st not in ("closed", "mitigated"):
            continue
        ts = closed or v.get("updated_at") or ""
        if since and ts < since:
            continue
        if until and ts > until + "T23:59:59":
            continue
        out.append(v)
    return vulnerabilities_to_csv(out)


def open_overdue_csv() -> str:
    rows = db.list_vulnerabilities(overdue_only=True, limit=5000)
    return vulnerabilities_to_csv(rows)


def poam_csv() -> str:
    rows = db.list_all_for_export()
    out = []
    for v in rows:
        st = v.get("wf_status") or v.get("status")
        if st in ("closed", "false_positive", "wont_fix"):
            continue
        if st in ("open", "triaged", "in_progress", "mitigated", "risk_accepted"):
            out.append(v)
    return vulnerabilities_to_csv(out)


def risk_acceptance_csv() -> str:
    rows = db.list_all_for_export()
    out = [v for v in rows if (v.get("risk_accept_state") == "accepted" or v.get("status") == "risk_accepted")]
    return vulnerabilities_to_csv(out)


def snapshot_json() -> str:
    rows = db.list_all_for_export()
    return json.dumps(rows, indent=2, default=str)


def audit_pack_zip(config_dir) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("register.csv", full_register_csv())
        zf.writestr("snapshot.json", snapshot_json())
        zf.writestr("risk_acceptance.csv", risk_acceptance_csv())
        sync = db.last_sync_run()
        zf.writestr(
            "sync_summary.json",
            json.dumps(sync or {}, indent=2, default=str),
        )
        jsonl = config_dir / "security" / "vulnerabilities" / "audit.jsonl"
        if jsonl.is_file():
            zf.writestr("audit_excerpt.jsonl", jsonl.read_text(encoding="utf-8")[:500000])
    buf.seek(0)
    return buf.getvalue()


def log_export(kind: str, details: dict | None = None) -> None:
    audit.record("vuln.export", target=kind, details=details or {})
