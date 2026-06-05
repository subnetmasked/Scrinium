"""Vulnerability Manager schema and queries (security.db)."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from packages.db import connect

PKG = "security"

SCHEMA = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    external_id     TEXT UNIQUE NOT NULL,
    identity_key    TEXT UNIQUE,
    title           TEXT NOT NULL DEFAULT '',
    scanner_status  TEXT NOT NULL DEFAULT '',
    first_seen      TEXT,
    last_seen       TEXT,
    raw_json        TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    scanner_severity TEXT NOT NULL DEFAULT 'info',
    cvss            REAL,
    cvss_vector     TEXT,
    epss            REAL,
    kev             INTEGER NOT NULL DEFAULT 0,
    exploit_available INTEGER NOT NULL DEFAULT 0,
    cve             TEXT,
    cwe             TEXT,
    refs_json       TEXT,
    host            TEXT,
    ip              TEXT,
    port            TEXT,
    service         TEXT,
    asset_doc_rel   TEXT,
    description     TEXT,
    solution        TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vuln_workflow (
    vuln_id                 INTEGER PRIMARY KEY REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    status                  TEXT NOT NULL DEFAULT 'open',
    assignee_user_id        INTEGER,
    priority                TEXT,
    mitigation_note         TEXT,
    false_positive_reason   TEXT,
    due_date                TEXT,
    closed_at               TEXT,
    closed_by               INTEGER,
    reopened_count          INTEGER NOT NULL DEFAULT 0,
    duplicate_of_id         INTEGER,
    risk_accept_state       TEXT NOT NULL DEFAULT 'none',
    risk_accept_reason      TEXT,
    risk_accept_until       TEXT,
    risk_accept_requested_by INTEGER,
    risk_accept_requested_at TEXT,
    risk_accept_decided_by  INTEGER,
    risk_accept_decided_at  TEXT,
    risk_accept_decision_note TEXT,
    closure_submitted_by    INTEGER,
    closure_submitted_at    TEXT,
    proposed_status         TEXT,
    previous_status         TEXT,
    previous_assignee_user_id INTEGER,
    resolution_submitted_by INTEGER,
    resolution_submitted_at TEXT
);
CREATE TABLE IF NOT EXISTS vuln_comments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id     INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    author_id   INTEGER,
    author      TEXT NOT NULL,
    ts          TEXT NOT NULL,
    body        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vuln_tags (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT UNIQUE NOT NULL COLLATE NOCASE
);
CREATE TABLE IF NOT EXISTS vuln_tag_map (
    vuln_id  INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    tag_id   INTEGER NOT NULL REFERENCES vuln_tags(id) ON DELETE CASCADE,
    PRIMARY KEY (vuln_id, tag_id)
);
CREATE TABLE IF NOT EXISTS vuln_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id    INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    ts         TEXT NOT NULL,
    actor      TEXT,
    actor_id   INTEGER,
    action     TEXT NOT NULL,
    old_value  TEXT,
    new_value  TEXT,
    note       TEXT
);
CREATE INDEX IF NOT EXISTS idx_vuln_events_vuln ON vuln_events (vuln_id, ts DESC);
CREATE TABLE IF NOT EXISTS vuln_evidence (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id      INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    stored_path  TEXT NOT NULL,
    mime         TEXT,
    size         INTEGER NOT NULL DEFAULT 0,
    uploaded_by  INTEGER,
    uploaded_at  TEXT NOT NULL,
    note         TEXT
);
CREATE TABLE IF NOT EXISTS sync_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    trigger      TEXT NOT NULL DEFAULT 'manual',
    added        INTEGER NOT NULL DEFAULT 0,
    updated      INTEGER NOT NULL DEFAULT 0,
    reopened     INTEGER NOT NULL DEFAULT 0,
    errors_json  TEXT
);
CREATE INDEX IF NOT EXISTS idx_vuln_status ON vuln_workflow (status);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities (severity);
CREATE TABLE IF NOT EXISTS cve_registry (
    cve_id      TEXT PRIMARY KEY,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS host_registry (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname    TEXT UNIQUE NOT NULL COLLATE NOCASE,
    os_version  TEXT,
    notes       TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vuln_ignore_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT NOT NULL,
    type            TEXT NOT NULL,
    value           TEXT NOT NULL,
    reason          TEXT NOT NULL,
    added_by        INTEGER,
    added_by_name   TEXT,
    created_at      TEXT NOT NULL,
    UNIQUE (cve_id, type, value)
);
CREATE INDEX IF NOT EXISTS idx_ignore_rules_cve ON vuln_ignore_rules (cve_id);
CREATE TABLE IF NOT EXISTS vuln_ignore_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    cve_id      TEXT,
    host        TEXT,
    os_version  TEXT,
    rule_type   TEXT,
    rule_id     INTEGER,
    reason      TEXT
);
CREATE INDEX IF NOT EXISTS idx_ignore_log_ts ON vuln_ignore_log (ts DESC);
"""


def migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(vulnerabilities)")}
    if "identity_key" not in cols:
        conn.execute("ALTER TABLE vulnerabilities ADD COLUMN identity_key TEXT")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_identity "
        "ON vulnerabilities (identity_key) WHERE identity_key IS NOT NULL"
    )
    wf_cols = {r[1] for r in conn.execute("PRAGMA table_info(vuln_workflow)")}
    if "closure_submitted_by" not in wf_cols:
        conn.execute("ALTER TABLE vuln_workflow ADD COLUMN closure_submitted_by INTEGER")
    if "closure_submitted_at" not in wf_cols:
        conn.execute("ALTER TABLE vuln_workflow ADD COLUMN closure_submitted_at TEXT")
    if "proposed_status" not in wf_cols:
        conn.execute("ALTER TABLE vuln_workflow ADD COLUMN proposed_status TEXT")
    if "previous_status" not in wf_cols:
        conn.execute("ALTER TABLE vuln_workflow ADD COLUMN previous_status TEXT")
    if "previous_assignee_user_id" not in wf_cols:
        conn.execute("ALTER TABLE vuln_workflow ADD COLUMN previous_assignee_user_id INTEGER")
    if "resolution_submitted_by" not in wf_cols:
        conn.execute("ALTER TABLE vuln_workflow ADD COLUMN resolution_submitted_by INTEGER")
    if "resolution_submitted_at" not in wf_cols:
        conn.execute("ALTER TABLE vuln_workflow ADD COLUMN resolution_submitted_at TEXT")
    conn.execute(
        """
        UPDATE vuln_workflow
        SET status = 'pending_review',
            proposed_status = COALESCE(proposed_status, 'closed'),
            previous_status = COALESCE(previous_status, 'mitigated'),
            previous_assignee_user_id = COALESCE(previous_assignee_user_id, assignee_user_id),
            resolution_submitted_by = COALESCE(resolution_submitted_by, closure_submitted_by),
            resolution_submitted_at = COALESCE(resolution_submitted_at, closure_submitted_at)
        WHERE status = 'pending_closure'
        """
    )
    _backfill_identity_keys(conn)
    _backfill_registries(conn)


def _backfill_registries(conn: sqlite3.Connection) -> None:
    """Populate CVE/Host registries from existing findings (idempotent)."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT OR IGNORE INTO cve_registry (cve_id, first_seen, last_seen)
        SELECT UPPER(TRIM(cve)), MIN(COALESCE(first_seen, created_at)), MAX(COALESCE(last_seen, updated_at))
        FROM vulnerabilities
        WHERE cve IS NOT NULL AND TRIM(cve) != ''
        GROUP BY UPPER(TRIM(cve))
        """
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO host_registry (hostname, first_seen, last_seen)
        SELECT DISTINCT TRIM(COALESCE(NULLIF(host, ''), ip)) AS hostname,
               MIN(COALESCE(first_seen, created_at)),
               MAX(COALESCE(last_seen, updated_at))
        FROM vulnerabilities
        WHERE TRIM(COALESCE(NULLIF(host, ''), ip)) != ''
        GROUP BY hostname
        """
    )
    # Refresh last_seen for rows that already existed before backfill.
    conn.execute(
        """
        UPDATE cve_registry SET last_seen = (
            SELECT MAX(COALESCE(v.last_seen, v.updated_at))
            FROM vulnerabilities v WHERE UPPER(TRIM(v.cve)) = cve_registry.cve_id
        )
        WHERE EXISTS (
            SELECT 1 FROM vulnerabilities v WHERE UPPER(TRIM(v.cve)) = cve_registry.cve_id
        )
        """
    )
    conn.execute(
        """
        UPDATE host_registry SET last_seen = (
            SELECT MAX(COALESCE(v.last_seen, v.updated_at))
            FROM vulnerabilities v
            WHERE TRIM(COALESCE(NULLIF(v.host, ''), v.ip)) = host_registry.hostname COLLATE NOCASE
        )
        WHERE EXISTS (
            SELECT 1 FROM vulnerabilities v
            WHERE TRIM(COALESCE(NULLIF(v.host, ''), v.ip)) = host_registry.hostname COLLATE NOCASE
        )
        """
    )


def _row_identity_key(row: dict) -> str:
    from packages.security.modules.vulnerabilities.identity import canonical_identity_key

    return canonical_identity_key(
        cve=row.get("cve") or "",
        title=row.get("title") or "",
        host=row.get("host") or "",
        ip=row.get("ip") or "",
        port=row.get("port") or "",
    )


def _backfill_identity_keys(conn: sqlite3.Connection) -> None:
    from packages.security.modules.vulnerabilities.identity import canonical_identity_key

    rows = conn.execute(
        "SELECT id, external_id, cve, title, host, ip, port, identity_key "
        "FROM vulnerabilities WHERE identity_key IS NULL OR identity_key = ''"
    ).fetchall()
    for row in rows:
        rid, _ext, cve, title, host, ip, port, _ik = row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7]
        key = canonical_identity_key(
            cve=cve or "",
            title=title or "",
            host=host or "",
            ip=ip or "",
            port=port or "",
        )
        try:
            conn.execute(
                "UPDATE vulnerabilities SET identity_key = ? WHERE id = ?",
                (key, rid),
            )
        except sqlite3.IntegrityError:
            pass


def _merge_refs(existing_json: str | None, new_refs: list | None) -> str:
    try:
        existing = json.loads(existing_json or "[]")
    except json.JSONDecodeError:
        existing = []
    if not isinstance(existing, list):
        existing = []
    from packages.security.modules.vulnerabilities.remediation import merge_refs

    merged = merge_refs(existing, new_refs or [])
    return json.dumps(merged, ensure_ascii=False)


def find_by_identity_key(identity_key: str) -> Optional[dict]:
    if not identity_key:
        return None
    with connect(PKG) as c:
        row = c.execute(
            "SELECT id FROM vulnerabilities WHERE identity_key = ?",
            (identity_key,),
        ).fetchone()
    if row is None:
        return None
    return get_vulnerability(int(row["id"]))


def list_duplicate_groups(*, limit: int = 100) -> list[dict]:
    """Groups of rows that share the same canonical identity (should be rare after upsert merge)."""
    with connect(PKG) as c:
        rows = list(
            c.execute(
                """
                SELECT identity_key, COUNT(*) AS n,
                       GROUP_CONCAT(id) AS ids,
                       GROUP_CONCAT(external_id) AS external_ids
                FROM vulnerabilities
                WHERE identity_key IS NOT NULL AND identity_key != ''
                GROUP BY identity_key
                HAVING COUNT(*) > 1
                ORDER BY n DESC
                LIMIT ?
                """,
                (max(1, limit),),
            )
        )
    out: list[dict] = []
    for r in rows:
        d = dict(r)
        d["ids"] = [int(x) for x in (d.get("ids") or "").split(",") if x]
        d["external_ids"] = (d.get("external_ids") or "").split(",")
        out.append(d)
    return out


def count_duplicate_groups() -> int:
    with connect(PKG) as c:
        return c.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT identity_key FROM vulnerabilities
                WHERE identity_key IS NOT NULL AND identity_key != ''
                GROUP BY identity_key HAVING COUNT(*) > 1
            )
            """
        ).fetchone()[0]


def scan_unkeyed_duplicates(*, limit: int = 200) -> list[dict]:
    """Detect legacy rows that match by fingerprint but were never linked (pre-migration data)."""
    from packages.security.modules.vulnerabilities.identity import canonical_identity_key

    with connect(PKG) as c:
        rows = list(
            c.execute(
                "SELECT id, external_id, cve, title, host, ip, port, identity_key "
                "FROM vulnerabilities ORDER BY id"
            )
        )
    buckets: dict[str, list[dict]] = {}
    for r in rows:
        row = dict(r)
        key = row.get("identity_key") or canonical_identity_key(
            cve=row.get("cve") or "",
            title=row.get("title") or "",
            host=row.get("host") or "",
            ip=row.get("ip") or "",
            port=row.get("port") or "",
        )
        buckets.setdefault(key, []).append(row)
    groups = []
    for key, items in buckets.items():
        if len(items) < 2:
            continue
        ext_ids = {i["external_id"] for i in items}
        if len(ext_ids) < 2:
            continue
        groups.append(
            {
                "identity_key": key,
                "n": len(items),
                "ids": [i["id"] for i in items],
                "external_ids": list(ext_ids),
                "titles": [i.get("title") or "" for i in items[:3]],
            }
        )
        if len(groups) >= limit:
            break
    groups.sort(key=lambda g: g["n"], reverse=True)
    return groups


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def row_to_dict(row: sqlite3.Row | None) -> Optional[dict]:
    if row is None:
        return None
    return dict(row)


def list_vulnerabilities(
    *,
    status: str | None = None,
    statuses: list[str] | None = None,
    severity: str | None = None,
    assignee_id: int | None = None,
    owner_filter: str | None = None,
    current_user_id: int | None = None,
    host_like: str | None = None,
    tag: str | None = None,
    kev_only: bool = False,
    overdue_only: bool = False,
    q: str | None = None,
    risk_pending: bool = False,
    sort: str = "severity",
    limit: int = 500,
    offset: int = 0,
) -> list[dict]:
    clauses: list[str] = []
    args: list[Any] = []
    if status:
        clauses.append("w.status = ?")
        args.append(status)
    elif statuses:
        placeholders = ",".join("?" for _ in statuses)
        clauses.append(f"w.status IN ({placeholders})")
        args.extend(statuses)
    if severity:
        clauses.append("v.severity = ?")
        args.append(severity)
    if assignee_id is not None:
        clauses.append("w.assignee_user_id = ?")
        args.append(assignee_id)
    if owner_filter == "mine" and current_user_id is not None:
        clauses.append("w.assignee_user_id = ?")
        args.append(current_user_id)
    elif owner_filter == "unassigned":
        clauses.append("w.assignee_user_id IS NULL")
    elif owner_filter == "mine_unassigned" and current_user_id is not None:
        clauses.append("(w.assignee_user_id = ? OR w.assignee_user_id IS NULL)")
        args.append(current_user_id)
    elif owner_filter == "assigned":
        clauses.append("w.assignee_user_id IS NOT NULL")
    if host_like:
        clauses.append("(v.host LIKE ? OR v.ip LIKE ? OR v.title LIKE ?)")
        pat = f"%{host_like}%"
        args.extend([pat, pat, pat])
    if kev_only:
        clauses.append("v.kev = 1")
    if overdue_only:
        clauses.append(
            "w.due_date IS NOT NULL AND w.due_date < ? "
            "AND w.status NOT IN ('mitigated','closed','false_positive','wont_fix','risk_accepted','duplicate','pending_review')"
        )
        args.append(datetime.now(timezone.utc).date().isoformat())
    if risk_pending:
        clauses.append("w.risk_accept_state = 'requested'")
    if q:
        clauses.append(
            "(v.title LIKE ? OR v.host LIKE ? OR v.external_id LIKE ? OR v.cve LIKE ?)"
        )
        pat = f"%{q}%"
        args.extend([pat, pat, pat, pat])
    if tag:
        clauses.append(
            "EXISTS (SELECT 1 FROM vuln_tag_map m JOIN vuln_tags t ON t.id = m.tag_id "
            "WHERE m.vuln_id = v.id AND t.name = ? COLLATE NOCASE)"
        )
        args.append(tag.strip())
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    order = {
        "severity": "CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, v.updated_at DESC",
        "updated": "v.updated_at DESC",
        "host": "v.host COLLATE NOCASE",
        "due": "w.due_date ASC",
    }.get(sort, "v.updated_at DESC")
    sql = f"""
        SELECT v.*, w.status AS wf_status, w.assignee_user_id, w.due_date,
               w.risk_accept_state, w.reopened_count, w.duplicate_of_id,
               w.proposed_status, w.previous_status, w.previous_assignee_user_id,
               w.resolution_submitted_by, w.resolution_submitted_at
        FROM vulnerabilities v
        JOIN vuln_workflow w ON w.vuln_id = v.id
        {where}
        ORDER BY {order}
        LIMIT ? OFFSET ?
    """
    args.extend([max(1, limit), max(0, offset)])
    with connect(PKG) as c:
        rows = list(c.execute(sql, args))
    return [dict(r) for r in rows]


def get_vulnerability(vuln_id: int) -> Optional[dict]:
    with connect(PKG) as c:
        row = c.execute(
            """
            SELECT v.*, w.*
            FROM vulnerabilities v
            JOIN vuln_workflow w ON w.vuln_id = v.id
            WHERE v.id = ?
            """,
            (vuln_id,),
        ).fetchone()
    if row is None:
        return None
    d = dict(row)
    return d


def get_by_external_id(external_id: str) -> Optional[dict]:
    with connect(PKG) as c:
        row = c.execute(
            "SELECT id FROM vulnerabilities WHERE external_id = ?",
            (external_id,),
        ).fetchone()
    if row is None:
        return None
    return get_vulnerability(int(row["id"]))


def upsert_vulnerability(fields: dict) -> tuple[int, bool, bool]:
    """Returns (vuln_id, created, merged_by_identity)."""
    from packages.security.modules.vulnerabilities.identity import prefer_external_id

    now = _now()
    ext = (fields.get("external_id") or "").strip()
    identity_key = fields.get("identity_key") or _row_identity_key(fields)
    fields["identity_key"] = identity_key

    raw = dict(fields.get("raw") or {})
    new_solution = (fields.get("solution") or "").strip()
    merge_event: tuple[int, str] | None = None
    result: tuple[int, bool, bool] | None = None

    with connect(PKG) as c:
        row = c.execute(
            "SELECT id, external_id, refs_json, solution FROM vulnerabilities WHERE external_id = ?",
            (ext,),
        ).fetchone() if ext else None
        merged_by_identity = False
        if row is None and identity_key:
            row = c.execute(
                "SELECT id, external_id, refs_json, solution FROM vulnerabilities WHERE identity_key = ?",
                (identity_key,),
            ).fetchone()
            if row is not None:
                merged_by_identity = True
                old_ext = row["external_id"]
                ext = prefer_external_id(old_ext, fields.get("external_id") or "")
                if old_ext != ext and old_ext:
                    alts = list(raw.get("alternate_external_ids") or [])
                    if old_ext not in alts:
                        alts.append(old_ext)
                    new_ext = fields.get("external_id") or ""
                    if new_ext and new_ext != ext and new_ext not in alts:
                        alts.append(new_ext)
                    raw["alternate_external_ids"] = alts
        if row:
            vid = int(row["id"])
            refs_json = _merge_refs(row["refs_json"], fields.get("refs"))
            raw_row = c.execute(
                "SELECT raw_json FROM vulnerabilities WHERE id = ?", (vid,)
            ).fetchone()
            try:
                prev_raw = json.loads((raw_row[0] if raw_row else None) or "{}")
            except (json.JSONDecodeError, TypeError):
                prev_raw = {}
            if not isinstance(prev_raw, dict):
                prev_raw = {}
            prev_raw.update(raw)
            raw_out = prev_raw
            c.execute(
                """
                UPDATE vulnerabilities SET
                    external_id=?, identity_key=?, title=?, scanner_status=?, last_seen=?, raw_json=?,
                    severity=COALESCE(?, severity), scanner_severity=?,
                    cvss=COALESCE(?, cvss), cvss_vector=COALESCE(?, cvss_vector),
                    epss=COALESCE(?, epss), kev=?, exploit_available=?,
                    cve=COALESCE(NULLIF(?, ''), cve), cwe=COALESCE(NULLIF(?, ''), cwe),
                    refs_json=?, host=COALESCE(NULLIF(?, ''), host),
                    ip=COALESCE(NULLIF(?, ''), ip), port=COALESCE(NULLIF(?, ''), port),
                    service=COALESCE(NULLIF(?, ''), service),
                    description=COALESCE(NULLIF(?, ''), description),
                    solution=COALESCE(NULLIF(?, ''), solution),
                    updated_at=?
                WHERE id=?
                """,
                (
                    ext,
                    identity_key,
                    fields.get("title") or "",
                    fields.get("scanner_status") or "",
                    fields.get("last_seen") or now,
                    json.dumps(raw_out, ensure_ascii=False),
                    fields.get("severity"),
                    fields.get("scanner_severity") or fields.get("severity") or "info",
                    fields.get("cvss"),
                    fields.get("cvss_vector"),
                    fields.get("epss"),
                    1 if fields.get("kev") else 0,
                    1 if fields.get("exploit_available") else 0,
                    fields.get("cve"),
                    fields.get("cwe"),
                    refs_json,
                    fields.get("host"),
                    fields.get("ip"),
                    fields.get("port"),
                    fields.get("service"),
                    fields.get("description"),
                    new_solution,
                    now,
                    vid,
                ),
            )
            if merged_by_identity:
                merge_event = (
                    vid,
                    f"Matched existing record via identity key; external_id={ext}",
                )
            result = (vid, False, merged_by_identity)
        else:
            cur = c.execute(
                """
                INSERT INTO vulnerabilities (
                    external_id, identity_key, title, scanner_status, first_seen, last_seen, raw_json,
                    severity, scanner_severity, cvss, cvss_vector, epss, kev, exploit_available,
                    cve, cwe, refs_json, host, ip, port, service, description, solution,
                    created_at, updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    ext or import_external_id_placeholder(identity_key),
                    identity_key,
                    fields.get("title") or "",
                    fields.get("scanner_status") or "",
                    fields.get("first_seen") or now,
                    fields.get("last_seen") or now,
                    json.dumps(raw, ensure_ascii=False),
                    fields.get("severity") or "info",
                    fields.get("scanner_severity") or fields.get("severity") or "info",
                    fields.get("cvss"),
                    fields.get("cvss_vector"),
                    fields.get("epss"),
                    1 if fields.get("kev") else 0,
                    1 if fields.get("exploit_available") else 0,
                    fields.get("cve"),
                    fields.get("cwe"),
                    json.dumps(fields.get("refs") or [], ensure_ascii=False),
                    fields.get("host"),
                    fields.get("ip"),
                    fields.get("port"),
                    fields.get("service"),
                    fields.get("description"),
                    new_solution,
                    now,
                    now,
                ),
            )
            vid = int(cur.lastrowid)
            c.execute(
                "INSERT INTO vuln_workflow (vuln_id, status) VALUES (?, 'open')",
                (vid,),
            )
            result = (vid, True, False)

    if merge_event:
        add_event(
            merge_event[0],
            "vuln.merged_identity",
            actor="system",
            note=merge_event[1],
        )
    assert result is not None
    return result


def import_external_id_placeholder(identity_key: str) -> str:
    from packages.security.modules.vulnerabilities.identity import import_external_id

    return import_external_id(identity_key)


def update_workflow(vuln_id: int, **fields) -> None:
    allowed = {
        "status", "assignee_user_id", "priority", "mitigation_note",
        "false_positive_reason", "due_date", "closed_at", "closed_by",
        "reopened_count", "duplicate_of_id", "risk_accept_state",
        "risk_accept_reason", "risk_accept_until", "risk_accept_requested_by",
        "risk_accept_requested_at", "risk_accept_decided_by",
        "risk_accept_decided_at", "risk_accept_decision_note",
        "closure_submitted_by", "closure_submitted_at",
        "proposed_status", "previous_status", "previous_assignee_user_id",
        "resolution_submitted_by", "resolution_submitted_at",
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return
    cols = ", ".join(f"{k} = ?" for k in updates)
    with connect(PKG) as c:
        c.execute(
            f"UPDATE vuln_workflow SET {cols} WHERE vuln_id = ?",
            (*updates.values(), vuln_id),
        )


def add_event(
    vuln_id: int,
    action: str,
    *,
    actor: str | None = None,
    actor_id: int | None = None,
    old_value: str | None = None,
    new_value: str | None = None,
    note: str | None = None,
) -> None:
    import auth

    if actor is None:
        u = auth.current_user()
        if u:
            actor = str(u["username"])
            actor_id = int(u["id"])
    if actor is None:
        actor = "system"
    with connect(PKG) as c:
        c.execute(
            """
            INSERT INTO vuln_events (vuln_id, ts, actor, actor_id, action, old_value, new_value, note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (vuln_id, _now(), actor, actor_id, action, old_value, new_value, note),
        )


def list_events(vuln_id: int, limit: int = 100) -> list[dict]:
    with connect(PKG) as c:
        rows = list(
            c.execute(
                "SELECT * FROM vuln_events WHERE vuln_id = ? ORDER BY ts DESC LIMIT ?",
                (vuln_id, limit),
            )
        )
    return [dict(r) for r in rows]


def add_comment(vuln_id: int, body: str, author_id: int, author: str) -> None:
    with connect(PKG) as c:
        c.execute(
            "INSERT INTO vuln_comments (vuln_id, author_id, author, ts, body) VALUES (?,?,?,?,?)",
            (vuln_id, author_id, author, _now(), body.strip()),
        )


def list_comments(vuln_id: int) -> list[dict]:
    with connect(PKG) as c:
        rows = list(
            c.execute(
                "SELECT * FROM vuln_comments WHERE vuln_id = ? ORDER BY ts ASC",
                (vuln_id,),
            )
        )
    return [dict(r) for r in rows]


def ensure_tag(name: str) -> int:
    cleaned = name.strip()
    with connect(PKG) as c:
        row = c.execute(
            "SELECT id FROM vuln_tags WHERE name = ? COLLATE NOCASE",
            (cleaned,),
        ).fetchone()
        if row:
            return int(row["id"])
        cur = c.execute("INSERT INTO vuln_tags (name) VALUES (?)", (cleaned,))
        return int(cur.lastrowid)


def set_tags(vuln_id: int, names: list[str]) -> None:
    with connect(PKG) as c:
        c.execute("DELETE FROM vuln_tag_map WHERE vuln_id = ?", (vuln_id,))
        for name in names:
            cleaned = name.strip()
            if not cleaned:
                continue
            # Resolve/insert the tag on the SAME connection — opening a nested
            # connection here would deadlock against this write transaction.
            row = c.execute(
                "SELECT id FROM vuln_tags WHERE name = ? COLLATE NOCASE",
                (cleaned,),
            ).fetchone()
            if row:
                tid = int(row["id"])
            else:
                cur = c.execute("INSERT INTO vuln_tags (name) VALUES (?)", (cleaned,))
                tid = int(cur.lastrowid)
            c.execute(
                "INSERT OR IGNORE INTO vuln_tag_map (vuln_id, tag_id) VALUES (?, ?)",
                (vuln_id, tid),
            )


def list_tags(vuln_id: int) -> list[str]:
    with connect(PKG) as c:
        rows = list(
            c.execute(
                """
                SELECT t.name FROM vuln_tags t
                JOIN vuln_tag_map m ON m.tag_id = t.id
                WHERE m.vuln_id = ? ORDER BY t.name COLLATE NOCASE
                """,
                (vuln_id,),
            )
        )
    return [r["name"] for r in rows]


def add_evidence(
    vuln_id: int,
    filename: str,
    stored_path: str,
    mime: str,
    size: int,
    uploaded_by: int,
    note: str = "",
) -> int:
    with connect(PKG) as c:
        cur = c.execute(
            """
            INSERT INTO vuln_evidence (vuln_id, filename, stored_path, mime, size, uploaded_by, uploaded_at, note)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (vuln_id, filename, stored_path, mime, size, uploaded_by, _now(), note),
        )
        return int(cur.lastrowid)


def list_evidence(vuln_id: int) -> list[dict]:
    with connect(PKG) as c:
        rows = list(
            c.execute(
                "SELECT * FROM vuln_evidence WHERE vuln_id = ? ORDER BY uploaded_at DESC",
                (vuln_id,),
            )
        )
    return [dict(r) for r in rows]


def evidence_count(vuln_id: int) -> int:
    with connect(PKG) as c:
        return c.execute(
            "SELECT COUNT(*) FROM vuln_evidence WHERE vuln_id = ?",
            (vuln_id,),
        ).fetchone()[0]


def start_sync_run(trigger: str) -> int:
    with connect(PKG) as c:
        cur = c.execute(
            "INSERT INTO sync_runs (started_at, trigger) VALUES (?, ?)",
            (_now(), trigger),
        )
        return int(cur.lastrowid)


def finish_sync_run(
    run_id: int,
    *,
    added: int,
    updated: int,
    reopened: int,
    errors: list | None = None,
) -> None:
    with connect(PKG) as c:
        c.execute(
            """
            UPDATE sync_runs SET finished_at=?, added=?, updated=?, reopened=?, errors_json=?
            WHERE id=?
            """,
            (
                _now(),
                added,
                updated,
                reopened,
                json.dumps(errors or []),
                run_id,
            ),
        )


def last_sync_run() -> Optional[dict]:
    with connect(PKG) as c:
        row = c.execute(
            "SELECT * FROM sync_runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
    return dict(row) if row else None


def dashboard_stats() -> dict:
    with connect(PKG) as c:
        by_sev = list(
            c.execute(
                """
                SELECT v.severity, COUNT(*) AS n FROM vulnerabilities v
                JOIN vuln_workflow w ON w.vuln_id = v.id
                WHERE w.status IN ('open','triaged','in_progress')
                GROUP BY v.severity
                """
            )
        )
        by_status = list(
            c.execute(
                "SELECT status, COUNT(*) AS n FROM vuln_workflow GROUP BY status"
            )
        )
        overdue = c.execute(
            """
            SELECT COUNT(*) FROM vuln_workflow w
            WHERE w.due_date IS NOT NULL AND w.due_date < ?
            AND w.status IN ('open','triaged','in_progress')
            """,
            (datetime.now(timezone.utc).date().isoformat(),),
        ).fetchone()[0]
        pending_ra = c.execute(
            "SELECT COUNT(*) FROM vuln_workflow WHERE risk_accept_state = 'requested'"
        ).fetchone()[0]
        pending_review = c.execute(
            "SELECT COUNT(*) FROM vuln_workflow WHERE status = 'pending_review'"
        ).fetchone()[0]
        kev_open = c.execute(
            """
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN vuln_workflow w ON w.vuln_id = v.id
            WHERE v.kev = 1 AND w.status IN ('open','triaged','in_progress')
            """
        ).fetchone()[0]
        total_open = c.execute(
            """
            SELECT COUNT(*) FROM vuln_workflow
            WHERE status IN ('open','triaged','in_progress')
            """
        ).fetchone()[0]
    dup_db = count_duplicate_groups()
    return {
        "by_severity": {r["severity"]: r["n"] for r in by_sev},
        "by_status": {r["status"]: r["n"] for r in by_status},
        "overdue": overdue,
        "pending_risk_acceptance": pending_ra,
        "pending_closure": pending_review,
        "pending_review": pending_review,
        "kev_open": kev_open,
        "total_open": total_open,
        "duplicate_groups": dup_db,
    }


def work_stats(days: int = 30, weeks: int = 8) -> dict:
    """Remediation progress for the dashboard: what the team has resolved over
    time, so technicians can see their impact.

    "Resolved" means a finding left the active queue — an auditor-approved
    outcome (mitigated/closed/won't fix/false positive) or a direct
    risk-accepted/duplicate disposition.
    """
    now = datetime.now(timezone.utc)
    cutoff_30 = (now - timedelta(days=days)).isoformat()
    cutoff_60 = (now - timedelta(days=2 * days)).isoformat()
    chart_days = weeks * 7
    cutoff_chart = (now - timedelta(days=chart_days - 1)).isoformat()
    resolved_clause = (
        "(action = 'vuln.resolution_approved' "
        "OR (action = 'vuln.status_change' AND new_value IN ('risk_accepted','duplicate')))"
    )
    with connect(PKG) as c:
        resolved_30 = c.execute(
            f"SELECT COUNT(*) FROM vuln_events WHERE {resolved_clause} AND ts >= ?",
            (cutoff_30,),
        ).fetchone()[0]
        resolved_prev = c.execute(
            f"SELECT COUNT(*) FROM vuln_events WHERE {resolved_clause} AND ts >= ? AND ts < ?",
            (cutoff_60, cutoff_30),
        ).fetchone()[0]
        submitted_30 = c.execute(
            "SELECT COUNT(*) FROM vuln_events WHERE action = 'vuln.resolution_submitted' AND ts >= ?",
            (cutoff_30,),
        ).fetchone()[0]
        found_30 = c.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE first_seen >= ?",
            (cutoff_30,),
        ).fetchone()[0]
        day_rows = c.execute(
            f"SELECT substr(ts,1,10) AS day, COUNT(*) AS n FROM vuln_events "
            f"WHERE {resolved_clause} AND ts >= ? GROUP BY day",
            (cutoff_chart,),
        ).fetchall()
        outcome_rows = c.execute(
            f"SELECT new_value AS outcome, COUNT(*) AS n FROM vuln_events "
            f"WHERE {resolved_clause} AND ts >= ? GROUP BY new_value",
            (cutoff_30,),
        ).fetchall()

    day_counts = {r["day"]: r["n"] for r in day_rows}
    today = now.date()
    buckets = [0] * weeks
    for offset in range(chart_days):
        d = today - timedelta(days=offset)
        b = offset // 7
        if b < weeks:
            buckets[b] += day_counts.get(d.isoformat(), 0)
    weekly = []
    for i in range(weeks - 1, -1, -1):  # oldest -> newest
        start = today - timedelta(days=i * 7 + 6)
        weekly.append({"label": f"{start.month}/{start.day}", "count": buckets[i]})
    weekly_max = max((w["count"] for w in weekly), default=0)

    delta = resolved_30 - resolved_prev
    if resolved_prev > 0:
        change_pct = round((delta / resolved_prev) * 100)
    elif resolved_30 > 0:
        change_pct = 100
    else:
        change_pct = 0

    return {
        "days": days,
        "resolved_30d": resolved_30,
        "resolved_prev_30d": resolved_prev,
        "resolved_delta": delta,
        "resolved_change_pct": change_pct,
        "submitted_30d": submitted_30,
        "found_30d": found_30,
        "net_30d": found_30 - resolved_30,
        "weekly": weekly,
        "weekly_max": weekly_max,
        "weekly_total": sum(w["count"] for w in weekly),
        "outcomes_30d": {r["outcome"]: r["n"] for r in outcome_rows if r["outcome"]},
    }


def list_all_for_export() -> list[dict]:
    with connect(PKG) as c:
        rows = list(
            c.execute(
                """
                SELECT v.*, w.status AS wf_status, w.assignee_user_id, w.due_date,
                       w.mitigation_note, w.false_positive_reason, w.closed_at, w.closed_by,
                       w.risk_accept_state, w.risk_accept_reason, w.risk_accept_until,
                       w.reopened_count
                FROM vulnerabilities v
                JOIN vuln_workflow w ON w.vuln_id = v.id
                ORDER BY v.severity, v.host, v.title
                """
            )
        )
    return [dict(r) for r in rows]
