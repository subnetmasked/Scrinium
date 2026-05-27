#!/usr/bin/env python3
"""Reset a Scrinium user's local password.

Prompts for the new password twice and updates the scrypt hash in
``auth.db``. Run as the same user that owns the auth DB (the container
user, usually root if you deployed with the bundled compose file):

    sudo python3 scripts/reset_password.py admin

Pass ``--db /path/to/auth.db`` if you store the config dir somewhere
other than ``./data/.scrinium``.
"""
from __future__ import annotations

import argparse
import getpass
import sqlite3
import sys
from pathlib import Path

from werkzeug.security import generate_password_hash


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username")
    parser.add_argument(
        "--db",
        default="data/.scrinium/auth.db",
        help="Path to the Scrinium auth.db (default: data/.scrinium/auth.db)",
    )
    args = parser.parse_args()

    db_path = Path(args.db).resolve()
    if not db_path.is_file():
        print(f"auth.db not found at {db_path}", file=sys.stderr)
        return 2

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, username, source FROM users "
            "WHERE username = ? COLLATE NOCASE",
            (args.username,),
        ).fetchone()
        if row is None:
            print(f"User {args.username!r} not found.", file=sys.stderr)
            return 1
        if row["source"] != "local":
            print(
                f"User {row['username']!r} is an LDAP user; its password is "
                "managed by the directory and cannot be reset here.",
                file=sys.stderr,
            )
            return 1

        pw1 = getpass.getpass(f"New password for {row['username']}: ")
        if len(pw1) < 8:
            print("Password must be at least 8 characters.", file=sys.stderr)
            return 1
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("Passwords do not match.", file=sys.stderr)
            return 1

        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(pw1), row["id"]),
        )
        conn.commit()
        print(f"Password updated for {row['username']!r}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
