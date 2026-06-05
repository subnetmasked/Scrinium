"""CVE Registry, Host Registry, and ignore-rule screening for ingestion."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import audit
from packages.db import connect
from packages.security.modules.vulnerabilities.workflow import ACTIVE_STATUSES

PKG = "security"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_hostname(host: str | None, ip: str | None) -> str:
    """Registry key: hostname when set, else IP. Empty when neither."""
    h = (host or "").strip()
    if h:
        return h
    return (ip or "").strip()


def normalize_cve(cve: str | None) -> str:
    return (cve or "").strip().upper()


def register_seen(
    cve: str | None,
    host: str | None,
    ip: str | None,
    *,
    when: str | None = None,
) -> None:
    """Upsert CVE and host registry entries (always, even if finding will be ignored)."""
    ts = when or _now()
    cve_id = normalize_cve(cve)
    hostname = normalize_hostname(host, ip)
    with connect(PKG) as c:
        if cve_id:
            c.execute(
                """
                INSERT INTO cve_registry (cve_id, first_seen, last_seen)
                VALUES (?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET last_seen = excluded.last_seen
                """,
                (cve_id, ts, ts),
            )
        if hostname:
            c.execute(
                """
                INSERT INTO host_registry (hostname, first_seen, last_seen)
                VALUES (?, ?, ?)
                ON CONFLICT(hostname) DO UPDATE SET last_seen = excluded.last_seen
                """,
                (hostname, ts, ts),
            )


def _get_host_os(hostname: str) -> str:
    if not hostname:
        return ""
    with connect(PKG) as c:
        row = c.execute(
            "SELECT os_version FROM host_registry WHERE hostname = ? COLLATE NOCASE",
            (hostname,),
        ).fetchone()
    if row is None:
        return ""
    return (row["os_version"] or "").strip()


def screen_finding(
    cve: str | None,
    host: str | None,
    ip: str | None,
) -> Optional[dict]:
    """Return matched ignore rule dict, or None to proceed with ingestion."""
    cve_id = normalize_cve(cve)
    if not cve_id:
        return None
    hostname = normalize_hostname(host, ip)
    with connect(PKG) as c:
        if hostname:
            row = c.execute(
                """
                SELECT * FROM vuln_ignore_rules
                WHERE cve_id = ? AND type = 'host' AND value = ? COLLATE NOCASE
                LIMIT 1
                """,
                (cve_id, hostname),
            ).fetchone()
            if row:
                return dict(row)
        host_os = _get_host_os(hostname)
        if host_os:
            rows = c.execute(
                """
                SELECT * FROM vuln_ignore_rules
                WHERE cve_id = ? AND type = 'os_version'
                """,
                (cve_id,),
            ).fetchall()
            host_os_lower = host_os.lower()
            for row in rows:
                rule_val = (row["value"] or "").strip().lower()
                if rule_val and rule_val == host_os_lower:
                    return dict(row)
    return None


def log_ignore(
    *,
    cve: str | None,
    host: str | None,
    ip: str | None,
    rule: dict,
    os_version: str | None = None,
) -> None:
    cve_id = normalize_cve(cve)
    hostname = normalize_hostname(host, ip)
    os_ver = (os_version or "").strip() or _get_host_os(hostname)
    ts = _now()
    with connect(PKG) as c:
        c.execute(
            """
            INSERT INTO vuln_ignore_log (ts, cve_id, host, os_version, rule_type, rule_id, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts,
                cve_id,
                hostname or None,
                os_ver or None,
                rule.get("type"),
                rule.get("id"),
                rule.get("reason"),
            ),
        )
    audit.record(
        "vuln.ignored",
        target=cve_id,
        details={
            "host": hostname,
            "os_version": os_ver,
            "rule_type": rule.get("type"),
            "rule_id": rule.get("id"),
            "reason": rule.get("reason"),
        },
    )


def ingest_screen(
    cve: str | None,
    host: str | None,
    ip: str | None,
    *,
    when: str | None = None,
) -> Optional[dict]:
    """Register seen CVE/host, then return ignore rule if finding should be skipped."""
    register_seen(cve, host, ip, when=when)
    rule = screen_finding(cve, host, ip)
    if rule:
        log_ignore(cve=cve, host=host, ip=ip, rule=rule)
    return rule


def list_cves() -> list[dict]:
    active = tuple(ACTIVE_STATUSES)
    placeholders = ",".join("?" * len(active))
    with connect(PKG) as c:
        rows = list(
            c.execute(
                f"""
                SELECT cr.cve_id, cr.first_seen, cr.last_seen,
                    (SELECT COUNT(*) FROM vulnerabilities v
                     JOIN vuln_workflow w ON w.vuln_id = v.id
                     WHERE UPPER(TRIM(v.cve)) = cr.cve_id AND w.status IN ({placeholders})
                    ) AS active_count,
                    (SELECT COUNT(*) FROM vuln_ignore_rules r WHERE r.cve_id = cr.cve_id
                    ) AS ignore_count
                FROM cve_registry cr
                ORDER BY cr.last_seen DESC, cr.cve_id COLLATE NOCASE
                """,
                active,
            )
        )
    return [dict(r) for r in rows]


def get_cve(cve_id: str) -> Optional[dict]:
    cve_id = normalize_cve(cve_id)
    with connect(PKG) as c:
        row = c.execute(
            "SELECT * FROM cve_registry WHERE cve_id = ?", (cve_id,)
        ).fetchone()
    return dict(row) if row else None


def list_ignore_rules(cve_id: str) -> list[dict]:
    cve_id = normalize_cve(cve_id)
    with connect(PKG) as c:
        rows = list(
            c.execute(
                "SELECT * FROM vuln_ignore_rules WHERE cve_id = ? ORDER BY created_at DESC",
                (cve_id,),
            )
        )
    return [dict(r) for r in rows]


def add_ignore_rules(
    cve_id: str,
    rule_type: str,
    values: list[str],
    *,
    reason: str,
    user: Any,
) -> int:
    """Insert ignore rules. Returns count added."""
    cve_id = normalize_cve(cve_id)
    if rule_type not in ("host", "os_version"):
        raise ValueError("Invalid ignore rule type.")
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("Reason is required.")
    added = 0
    uid = int(user["id"]) if user else None
    uname = str(user["username"]) if user else ""
    ts = _now()
    with connect(PKG) as c:
        for raw in values:
            val = (raw or "").strip()
            if not val:
                continue
            if rule_type == "host":
                # Canonicalize to the registry's stored casing when the host is
                # known; otherwise accept the typed name as-is (it may not have
                # been seen by a scan yet). Matching is case-insensitive anyway.
                canon = c.execute(
                    "SELECT hostname FROM host_registry WHERE hostname = ? COLLATE NOCASE",
                    (val,),
                ).fetchone()
                if canon:
                    val = canon["hostname"]
            try:
                c.execute(
                    """
                    INSERT INTO vuln_ignore_rules
                        (cve_id, type, value, reason, added_by, added_by_name, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (cve_id, rule_type, val, reason, uid, uname, ts),
                )
                added += 1
            except Exception:
                continue
    if added:
        audit.record(
            "vuln.ignore_rule_add",
            target=cve_id,
            details={"type": rule_type, "count": added},
        )
    return added


def delete_ignore_rule(rule_id: int) -> Optional[str]:
    """Delete rule; return CVE id on success."""
    with connect(PKG) as c:
        row = c.execute(
            "SELECT cve_id FROM vuln_ignore_rules WHERE id = ?", (rule_id,)
        ).fetchone()
        if not row:
            return None
        cve_id = row["cve_id"]
        c.execute("DELETE FROM vuln_ignore_rules WHERE id = ?", (rule_id,))
    audit.record("vuln.ignore_rule_delete", target=cve_id, details={"rule_id": rule_id})
    return cve_id


def list_hosts() -> list[dict]:
    with connect(PKG) as c:
        rows = list(
            c.execute(
                "SELECT * FROM host_registry ORDER BY hostname COLLATE NOCASE"
            )
        )
    return [dict(r) for r in rows]


def get_host(host_id: int) -> Optional[dict]:
    with connect(PKG) as c:
        row = c.execute("SELECT * FROM host_registry WHERE id = ?", (host_id,)).fetchone()
    return dict(row) if row else None


def update_host(host_id: int, *, os_version: str | None, notes: str | None) -> bool:
    with connect(PKG) as c:
        row = c.execute("SELECT id FROM host_registry WHERE id = ?", (host_id,)).fetchone()
        if not row:
            return False
        c.execute(
            "UPDATE host_registry SET os_version = ?, notes = ? WHERE id = ?",
            (
                (os_version or "").strip() or None,
                (notes or "").strip() or None,
                host_id,
            ),
        )
    audit.record("vuln.host_registry_update", target=str(host_id))
    return True
