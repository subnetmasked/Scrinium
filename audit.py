"""Audit log helpers backed by auth.db."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from flask import current_app, request

import auth


@contextmanager
def _conn():
    db_path = current_app.config["AUTH_DB"]
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def record(
    action: str,
    *,
    target: str | None = None,
    details: dict[str, Any] | None = None,
    actor: str | None = None,
    actor_id: int | None = None,
    ip: str | None = None,
) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    if actor is None or actor_id is None:
        user = auth.current_user()
        if user is not None:
            actor = actor or str(user["username"])
            actor_id = actor_id if actor_id is not None else int(user["id"])
    if actor is None:
        actor = "system"
    if ip is None:
        ip = request.remote_addr if request else None
    payload = json.dumps(details or {}, ensure_ascii=False)
    with _conn() as c:
        c.execute(
            "INSERT INTO audit_log (ts, actor, actor_id, ip, action, target, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, actor, actor_id, ip, action, target, payload),
        )


def _row_with_details(row: sqlite3.Row) -> dict[str, Any]:
    out = dict(row)
    raw = out.get("details") or ""
    try:
        out["details_obj"] = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        out["details_obj"] = {}
    return out


def for_doc(rel: str, limit: int = 3) -> list[dict[str, Any]]:
    with _conn() as c:
        rows = list(
            c.execute(
                "SELECT * FROM audit_log WHERE target = ? AND action LIKE 'doc.%' "
                "ORDER BY ts DESC LIMIT ?",
                (rel, max(1, int(limit))),
            )
        )
    return [_row_with_details(r) for r in rows]


def query(
    *,
    action: str | None = None,
    actor: str | None = None,
    target_like: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    args: list[Any] = []
    if action:
        clauses.append("action = ?")
        args.append(action)
    if actor:
        clauses.append("actor = ? COLLATE NOCASE")
        args.append(actor.strip())
    if target_like:
        clauses.append("target LIKE ?")
        args.append(f"%{target_like.strip()}%")
    if since:
        clauses.append("ts >= ?")
        args.append(since.strip())
    if until:
        clauses.append("ts <= ?")
        args.append(until.strip() + "T23:59:59")
    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with _conn() as c:
        rows = list(
            c.execute(
                f"SELECT * FROM audit_log {where_sql} ORDER BY ts DESC LIMIT ? OFFSET ?",
                (*args, max(1, int(limit)), max(0, int(offset))),
            )
        )
    return [_row_with_details(r) for r in rows]

