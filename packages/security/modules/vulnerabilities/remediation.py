"""Remediation text and authoritative reference links (no placeholder solutions)."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from packages.security.modules.vulnerabilities.identity import CVE_RE, primary_cve

URL_RE = re.compile(r"https?://[^\s,;\"'<>]+", re.IGNORECASE)


def _is_url(s: str) -> bool:
    try:
        p = urlparse(s.strip())
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def parse_refs_text(text: str) -> list[str]:
    if not text or str(text).strip().lower() in ("undefined", "n/a", "none", "[]"):
        return []
    found: list[str] = []
    for m in URL_RE.finditer(str(text)):
        u = m.group(0).rstrip(").,;]")
        if _is_url(u):
            found.append(u)
    if found:
        return found
    parts = re.split(r"[\n\r,;]+", str(text))
    for p in parts:
        p = p.strip()
        if _is_url(p):
            found.append(p)
    return found


def cve_advisory_urls(cve: str) -> list[str]:
    urls: list[str] = []
    for m in CVE_RE.finditer(cve or ""):
        cid = m.group(0).upper()
        urls.append(f"https://nvd.nist.gov/vuln/detail/{cid}")
        urls.append(f"https://www.cve.org/CVERecord?id={cid}")
    primary = primary_cve(cve)
    if primary and primary not in {u.split("/")[-1] for u in urls}:
        urls.insert(0, f"https://nvd.nist.gov/vuln/detail/{primary}")
        urls.insert(1, f"https://www.cve.org/CVERecord?id={primary}")
    return urls


def merge_refs(*groups: list[str] | None) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for group in groups:
        if not group:
            continue
        for item in group:
            u = (item or "").strip()
            if not u or u in seen:
                continue
            seen.add(u)
            out.append(u)
    return out


def prepare_import_fields(row: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize solution + refs for import rows.
    Never invent remediation text — only link to real sources when solution is empty.
    """
    solution = (row.get("solution") or "").strip()
    refs_text = row.pop("refs_text", "") or ""
    existing_refs = row.get("refs") if isinstance(row.get("refs"), list) else []
    refs = merge_refs(
        existing_refs,
        parse_refs_text(str(refs_text)),
        cve_advisory_urls(str(row.get("cve") or "")),
    )
    row["solution"] = solution
    row["refs"] = refs
    return row


def remediation_links_for_display(
    *,
    solution: str,
    cve: str,
    refs: list[str],
) -> list[dict[str, str]]:
    """Links shown in UI when scanner/import did not supply remediation text."""
    if (solution or "").strip():
        return []
    links: list[dict[str, str]] = []
    seen: set[str] = set()
    for url in merge_refs(refs, cve_advisory_urls(cve)):
        if url in seen:
            continue
        seen.add(url)
        label = url
        if "nvd.nist.gov" in url:
            label = f"NVD — {primary_cve(cve) or 'advisory'}"
        elif "cve.org" in url:
            label = f"CVE.org — {primary_cve(cve) or 'record'}"
        links.append({"url": url, "label": label})
    return links
