"""Sync vulnerabilities from configured scanner API."""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import audit
from flask import Flask

from packages import authz
from packages.security.modules.vulnerabilities import db, identity, remediation, scanner

logger = logging.getLogger(__name__)
PKG = "security"
MOD = "vulnerabilities"
_thread: threading.Thread | None = None
_stop = threading.Event()


def _finding_to_fields(f: scanner.ScannerFinding) -> dict:
    refs = remediation.merge_refs(f.refs, remediation.cve_advisory_urls(f.cve))
    solution = (f.solution or "").strip()
    identity_key = identity.canonical_identity_key(
        cve=f.cve,
        title=f.title,
        host=f.host,
        ip=f.ip,
        port=f.port,
    )
    return {
        "external_id": f.external_id,
        "identity_key": identity_key,
        "title": f.title,
        "severity": f.severity,
        "scanner_severity": f.scanner_severity,
        "scanner_status": f.scanner_status,
        "cvss": f.cvss,
        "cvss_vector": f.cvss_vector,
        "epss": f.epss,
        "kev": f.kev,
        "exploit_available": f.exploit_available,
        "cve": f.cve,
        "cwe": f.cwe,
        "refs": refs,
        "host": f.host,
        "ip": f.ip,
        "port": f.port,
        "service": f.service,
        "description": f.description,
        "solution": solution,
        "raw": {**(f.raw or {}), "sync_source": "scanner_api"},
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }


def run_sync(*, trigger: str = "manual") -> dict:
    if not authz.module_enabled(PKG, MOD):
        return {"ok": False, "message": "Module disabled."}
    settings = scanner.scanner_settings()
    run_id = db.start_sync_run(trigger)
    added = updated = merged = reopened = 0
    errors: list[str] = []
    try:
        result = scanner.fetch_all(settings)
        if not result.ok:
            errors.append(result.message)
            db.finish_sync_run(run_id, added=0, updated=0, reopened=0, errors=errors)
            audit.record("vuln.sync", target="vulnerabilities", details={"ok": False, "error": result.message})
            return {"ok": False, "message": result.message}
        seen_ext: set[str] = set()
        for f in result.findings:
            seen_ext.add(f.external_id)
            fields = _finding_to_fields(f)
            vid, created, was_merged = db.upsert_vulnerability(fields)
            if created:
                added += 1
            elif was_merged:
                merged += 1
            else:
                updated += 1
                v = db.get_vulnerability(vid)
                if v and v.get("status") in ("closed", "false_positive", "risk_accepted"):
                    db.update_workflow(
                        vid,
                        status="open",
                        reopened_count=int(v.get("reopened_count") or 0) + 1,
                        risk_accept_state="none",
                    )
                    db.add_event(vid, "vuln.reopened_by_scanner")
                    reopened += 1
        db.finish_sync_run(run_id, added=added, updated=updated, reopened=reopened, errors=errors)
        audit.record(
            "vuln.sync",
            target="vulnerabilities",
            details={
                "ok": True,
                "added": added,
                "updated": updated,
                "merged": merged,
                "reopened": reopened,
            },
        )
        merge_part = f", {merged} linked to existing import" if merged else ""
        return {
            "ok": True,
            "message": (
                f"Sync complete: {added} added, {updated} updated{merge_part}, {reopened} reopened."
            ),
            "added": added,
            "updated": updated,
            "merged": merged,
            "reopened": reopened,
        }
    except Exception as e:
        logger.exception("vuln sync failed")
        errors.append(str(e))
        db.finish_sync_run(run_id, added=added, updated=updated, reopened=reopened, errors=errors)
        return {"ok": False, "message": str(e)}


def expire_risk_acceptances() -> int:
    """Reopen risk_accepted findings past expiry. Returns count."""
    today = datetime.now(timezone.utc).date().isoformat()
    n = 0
    with db.connect(db.PKG) as c:
        rows = list(
            c.execute(
                """
                SELECT vuln_id FROM vuln_workflow
                WHERE status = 'risk_accepted' AND risk_accept_until IS NOT NULL
                AND risk_accept_until < ?
                """,
                (today,),
            )
        )
    for row in rows:
        vid = int(row["vuln_id"])
        db.update_workflow(vid, status="open", risk_accept_state="none")
        db.add_event(vid, "vuln.risk_acceptance_expired")
        audit.record("vuln.risk_acceptance_expired", target=str(vid))
        n += 1
    return n


def _sync_loop(app: Flask) -> None:
    while not _stop.is_set():
        try:
            with app.app_context():
                cfg = authz.module_config(PKG, MOD)
                interval = int(cfg.get("sync_interval_minutes") or 0)
                if (
                    authz.package_enabled(PKG)
                    and authz.module_enabled(PKG, MOD)
                    and interval > 0
                ):
                    expire_risk_acceptances()
                    run_sync(trigger="scheduled")
        except Exception:
            logger.exception("scheduled vuln sync error")
        cfg = {}
        try:
            with app.app_context():
                cfg = authz.module_config(PKG, MOD)
                interval = int(cfg.get("sync_interval_minutes") or 0)
        except Exception:
            interval = 0
        wait = max(60, interval * 60) if interval > 0 else 300
        _stop.wait(wait)


def start_scheduled_sync(app: Flask) -> None:
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_sync_loop, args=(app,), daemon=True, name="vuln-sync")
    _thread.start()


def append_jsonl_audit(config_dir: Path, event: dict) -> None:
    path = config_dir / "security" / "vulnerabilities" / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError:
        pass
