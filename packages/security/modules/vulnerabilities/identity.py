"""Canonical vulnerability identity for deduplication across import and API sync."""
from __future__ import annotations

import hashlib
import re
from typing import Any

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def normalize_port(port: Any) -> str:
    if port is None or port == "":
        return ""
    s = str(port).strip()
    if s.endswith(".0"):
        s = s[:-2]
    return s


def normalize_asset(host: str, ip: str) -> tuple[str, str]:
    host = (host or "").strip().lower()
    ip = (ip or "").strip()
    if not host and ip:
        host = ip.lower()
    return host, ip


def primary_cve(cve: str) -> str:
    """First CVE id from a cell that may list several."""
    text = (cve or "").strip()
    if not text:
        return ""
    m = CVE_RE.search(text)
    return m.group(0).upper() if m else text.split(",")[0].strip().upper()


def normalize_title(title: str) -> str:
    return re.sub(r"\s+", " ", (title or "").strip().lower())[:240]


def canonical_identity_key(
    *,
    cve: str = "",
    title: str = "",
    host: str = "",
    ip: str = "",
    port: Any = "",
) -> str:
    """
    Stable fingerprint for the same finding on the same asset.
    Used to match CSV imports with later API sync even when external_id differs.
    """
    host_n, ip_n = normalize_asset(host, ip)
    asset = host_n or ip_n
    port_n = normalize_port(port)
    cve_n = primary_cve(cve)
    if cve_n and asset:
        basis = f"{cve_n}|{asset}|{port_n}"
    else:
        title_n = normalize_title(title)
        basis = f"{title_n}|{asset}|{port_n}"
    if len(basis.strip("|")) < 3:
        basis = f"{title}|{host}|{ip}|{port}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def import_external_id(identity_key: str) -> str:
    return f"import:{identity_key[:32]}"


def is_import_external_id(external_id: str) -> bool:
    return (external_id or "").startswith("import:")


def prefer_external_id(existing: str, new: str) -> str:
    """Prefer scanner/API ids over import-derived ids when merging."""
    existing = (existing or "").strip()
    new = (new or "").strip()
    if existing and not is_import_external_id(existing):
        return existing
    if new and not is_import_external_id(new):
        return new
    return existing or new
