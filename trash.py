"""Soft-delete and restore helpers."""
from __future__ import annotations

import json
import shutil
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import current_app


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


def trash_root(config_dir: Path) -> Path:
    root = config_dir / "trash"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _dir_size(path: Path) -> int:
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                continue
    return total


def move_to_trash(
    *,
    data_dir: Path,
    config_dir: Path,
    original_rel: str,
    kind: str,
    user_id: int | None,
) -> int:
    ts = datetime.now(timezone.utc).isoformat()
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO trash (original_rel, kind, trashed_path, deleted_at, deleted_by, size_bytes) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (original_rel, kind, "", ts, user_id, 0),
        )
        trash_id = int(cur.lastrowid)
    root = trash_root(config_dir)
    slot = root / str(trash_id)
    slot.mkdir(parents=True, exist_ok=True)
    src = data_dir / (original_rel + ".md" if kind == "doc" else original_rel)
    main_name = src.name
    dest_main = slot / main_name
    shutil.move(str(src), str(dest_main))

    attachments_moved: list[dict[str, str]] = []
    if kind == "doc":
        parts = [p for p in original_rel.split("/") if p]
        if len(parts) == 1:
            att_rel = Path("_attachments") / parts[0]
        else:
            att_rel = Path(*parts[:-1]) / "_attachments" / parts[-1]
        att_src = data_dir / att_rel
        if att_src.is_dir():
            att_dest = slot / "_attachments"
            shutil.move(str(att_src), str(att_dest))
            attachments_moved.append(
                {"from": str(att_rel).replace("\\", "/"), "to": "_attachments"}
            )

    size_bytes = _dir_size(slot)
    meta = {
        "id": trash_id,
        "original_rel": original_rel,
        "kind": kind,
        "deleted_at": ts,
        "attachments": attachments_moved,
    }
    (slot / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    with _conn() as c:
        c.execute(
            "UPDATE trash SET trashed_path = ?, size_bytes = ? WHERE id = ?",
            (str(slot), size_bytes, trash_id),
        )
    return trash_id


def list_trash() -> list[sqlite3.Row]:
    with _conn() as c:
        return list(
            c.execute(
                "SELECT t.*, u.username AS deleted_by_name "
                "FROM trash t LEFT JOIN users u ON u.id = t.deleted_by "
                "ORDER BY t.deleted_at DESC"
            )
        )


def get_trash(trash_id: int) -> sqlite3.Row | None:
    with _conn() as c:
        return c.execute("SELECT * FROM trash WHERE id = ?", (trash_id,)).fetchone()


def restore(*, data_dir: Path, trash_id: int) -> tuple[bool, str]:
    row = get_trash(trash_id)
    if row is None:
        return False, "Trash item not found."
    kind = row["kind"]
    rel = row["original_rel"]
    slot = Path(row["trashed_path"])
    src = slot / (Path(rel).name + (".md" if kind == "doc" else ""))
    dest = data_dir / (rel + ".md" if kind == "doc" else rel)
    if dest.exists():
        return False, "Destination path already exists; restore cancelled."
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    att_slot = slot / "_attachments"
    if att_slot.exists() and kind == "doc":
        parts = [p for p in rel.split("/") if p]
        if len(parts) == 1:
            att_dest = data_dir / "_attachments" / parts[0]
        else:
            att_dest = data_dir / Path(*parts[:-1]) / "_attachments" / parts[-1]
        if not att_dest.exists():
            att_dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(att_slot), str(att_dest))
    shutil.rmtree(slot, ignore_errors=True)
    with _conn() as c:
        c.execute("DELETE FROM trash WHERE id = ?", (trash_id,))
    return True, rel


def purge(trash_id: int) -> bool:
    row = get_trash(trash_id)
    if row is None:
        return False
    shutil.rmtree(Path(row["trashed_path"]), ignore_errors=True)
    with _conn() as c:
        c.execute("DELETE FROM trash WHERE id = ?", (trash_id,))
    return True


def empty_all() -> int:
    rows = list_trash()
    n = 0
    for row in rows:
        if purge(int(row["id"])):
            n += 1
    return n

