"""Rich demo / smoke vulnerability seed data."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from packages.security.modules.vulnerabilities import db
from packages.security.modules.vulnerabilities.identity import canonical_identity_key

DEMO_EXTERNAL_ID = "local-smoke-1"


def _clear_demo_artifacts(vuln_id: int) -> None:
    from packages.db import connect

    with connect(db.PKG) as c:
        c.execute("DELETE FROM vuln_comments WHERE vuln_id = ?", (vuln_id,))
        c.execute("DELETE FROM vuln_events WHERE vuln_id = ?", (vuln_id,))
        c.execute("DELETE FROM vuln_tag_map WHERE vuln_id = ?", (vuln_id,))


def seed_demo_vulnerability(*, assignee_id: int | None = None) -> int:
    """Create or replace a fully featured demo vulnerability for UI testing."""
    existing = db.get_by_external_id(DEMO_EXTERNAL_ID)
    if existing:
        _clear_demo_artifacts(int(existing["id"]))

    now = datetime.now(timezone.utc)
    today = date.today()
    fields = {
        "external_id": DEMO_EXTERNAL_ID,
        "title": "OpenBSD OpenSSH regreSSHion (CVE-2023-28531) on ise01",
        "scanner_status": "confirmed",
        "first_seen": (today - timedelta(days=120)).isoformat(),
        "last_seen": now.isoformat(),
        "severity": "high",
        "scanner_severity": "high",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.42,
        "kev": True,
        "exploit_available": True,
        "cve": "CVE-2023-28531",
        "cwe": "CWE-787",
        "refs": [
            "https://www.openssh.com/txt/release/9.3",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-28531",
        ],
        "host": "ise01.intern.example.com",
        "ip": "10.128.0.204",
        "port": "22",
        "service": "ssh",
        "asset_doc_rel": "",
        "description": (
            "The target is running vulnerable software: OpenBSD OpenSSH 9.1.\n\n"
            "Proof / detection:\n"
            "Remote banner indicates OpenSSH_9.1 and patch level predates security fix "
            "for CVE-2023-28531. Qualys of detection (QoD): 75%.\n\n"
            "Business impact: privileged remote code execution risk on a network identity "
            "appliance in the production VLAN."
        ),
        "solution": (
            "Update OpenSSH to a vendor-supported version that includes the fix for "
            "CVE-2023-28531 (OpenSSH 9.3p2 or later). Validate with authenticated package "
            "manager or vendor advisory. Schedule maintenance window and capture "
            "post-patch scan output as evidence."
        ),
        "raw": {
            "source": "demo_seed",
            "qod": "75%",
            "target_criticality": "high",
        },
    }
    fields["identity_key"] = canonical_identity_key(
        cve=fields.get("cve") or "",
        title=fields.get("title") or "",
        host=fields.get("host") or "",
        ip=fields.get("ip") or "",
        port=fields.get("port") or "",
    )
    vid, _, _ = db.upsert_vulnerability(fields)
    db.update_workflow(
        vid,
        status="in_progress",
        assignee_user_id=assignee_id,
        priority="P1",
        due_date=(today + timedelta(days=14)).isoformat(),
        mitigation_note=(
            "Patch window approved for next Tuesday 22:00. Rollback plan documented "
            "in change record CHG-2041."
        ),
        risk_accept_state="none",
    )
    db.set_tags(
        vid,
        ["internet-facing", "kev", "ssh", "prod", "identity", "q3-remediation"],
    )
    db.add_comment(
        vid,
        "Scanner re-detected this on latest monthly export. Confirmed on ise01 and ise02.",
        0,
        "import",
    )
    db.add_comment(
        vid,
        "Vendor patch bundle staged on jump host. Need evidence upload after apply.",
        assignee_id or 0,
        "technician",
    )
    db.add_event(
        vid,
        "vuln.status_change",
        actor="system",
        old_value="open",
        new_value="in_progress",
        note="Demo seed — triaged and assigned",
    )
    db.add_event(
        vid,
        "vuln.assigned",
        actor="system",
        new_value=str(assignee_id or 0),
        note="Assigned for remediation window CHG-2041",
    )
    db.add_event(
        vid,
        "vuln.tag",
        actor="system",
        note="Tagged: kev, prod, ssh",
    )
    return vid
