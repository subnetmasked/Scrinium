"""Per-package SQLite databases under the config directory."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

from flask import current_app

from packages import registry


_config_dir: Path | None = None


def set_config_dir(path: Path) -> None:
    global _config_dir
    _config_dir = path.resolve()


def db_path(package_id: str) -> Path:
    base = _config_dir
    if base is None:
        cfg = current_app.config.get("PACKAGES_CONFIG_DIR")
        if cfg:
            base = Path(cfg)
        else:
            raise RuntimeError("packages db: config dir not set")
    return base / f"{package_id}.db"


def init_package_db(package_id: str) -> None:
    path = db_path(package_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    pkg = registry.get_package(package_id)
    if pkg is None:
        return
    with sqlite3.connect(path) as conn:
        for mod in pkg.modules:
            mod.migrate(conn)
        conn.commit()


def init_all_package_dbs() -> None:
    for pkg in registry.iter_packages():
        init_package_db(pkg.id)


@contextmanager
def connect(package_id: str) -> Generator[sqlite3.Connection, None, None]:
    path = db_path(package_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
