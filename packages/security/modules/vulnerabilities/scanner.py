"""Generic configurable scanner API client."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from packages import authz

PKG = "security"
MOD = "vulnerabilities"

DEFAULT_SCANNER = {
    "base_url": "",
    "auth_mode": "none",
    "api_key_header": "X-API-Key",
    "api_key_value": "",
    "bearer_token": "",
    "basic_user": "",
    "basic_password": "",
    "login_url": "",
    "login_user_field": "username",
    "login_pass_field": "password",
    "login_token_path": "token",
    "list_endpoint": "/api/vulnerabilities",
    "list_method": "GET",
    "pagination": "none",
    "page_param": "page",
    "page_size_param": "per_page",
    "page_size": 100,
    "offset_param": "offset",
    "cursor_param": "cursor",
    "results_path": "",
    "field_map": {
        "external_id": "id",
        "title": "title",
        "severity": "severity",
        "host": "host",
        "description": "description",
        "solution": "solution",
    },
    "severity_map": {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    },
}

_SECRET_KEYS = frozenset({
    "api_key_value", "bearer_token", "basic_password",
})


@dataclass
class ScannerFinding:
    external_id: str
    title: str = ""
    severity: str = "info"
    scanner_severity: str = "info"
    scanner_status: str = ""
    cvss: Optional[float] = None
    cvss_vector: str = ""
    epss: Optional[float] = None
    kev: bool = False
    exploit_available: bool = False
    cve: str = ""
    cwe: str = ""
    refs: list = field(default_factory=list)
    host: str = ""
    ip: str = ""
    port: str = ""
    service: str = ""
    description: str = ""
    solution: str = ""
    raw: dict = field(default_factory=dict)


class ScannerResult:
    def __init__(self, ok: bool, message: str, findings: list[ScannerFinding] | None = None):
        self.ok = ok
        self.message = message
        self.findings = findings or []


def _get_path(obj: Any, path: str) -> Any:
    if not path:
        return obj
    cur = obj
    for part in path.split("."):
        if part == "":
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            idx = int(part)
            cur = cur[idx] if idx < len(cur) else None
        else:
            return None
    return cur


def scanner_settings(*, redact: bool = False) -> dict:
    cfg = authz.module_config(PKG, MOD)
    out = dict(DEFAULT_SCANNER)
    saved = cfg.get("scanner") or {}
    if isinstance(saved, dict):
        out.update(saved)
    if redact:
        for k in _SECRET_KEYS:
            if out.get(k):
                out[k] = "********"
    return out


def save_scanner_settings(form: dict, *, keep_secrets: bool = True) -> None:
    cfg = authz.merged_package_config(PKG)
    mods = cfg.setdefault("modules", {})
    mod = dict(mods.get(MOD) or {})
    prev = (mod.get("scanner") or {}) if isinstance(mod.get("scanner"), dict) else {}
    cleaned = dict(DEFAULT_SCANNER)
    cleaned.update(prev)
    for key in DEFAULT_SCANNER:
        if key in _SECRET_KEYS:
            val = (form.get(key) or "").strip()
            if not val and keep_secrets:
                cleaned[key] = prev.get(key, "")
            else:
                cleaned[key] = val
        elif key in ("field_map", "severity_map"):
            raw = form.get(key) or prev.get(key) or DEFAULT_SCANNER[key]
            if isinstance(raw, str):
                try:
                    cleaned[key] = json.loads(raw)
                except json.JSONDecodeError:
                    cleaned[key] = DEFAULT_SCANNER[key]
            elif isinstance(raw, dict):
                cleaned[key] = raw
        else:
            cleaned[key] = (form.get(key) or prev.get(key) or DEFAULT_SCANNER.get(key, ""))
    if isinstance(cleaned.get("page_size"), str):
        try:
            cleaned["page_size"] = int(cleaned["page_size"])
        except ValueError:
            cleaned["page_size"] = 100
    mod["scanner"] = cleaned
    mods[MOD] = mod
    cfg["modules"] = mods
    authz.set_package_config(PKG, cfg)


def _auth_headers(settings: dict, session: requests.Session) -> dict:
    mode = (settings.get("auth_mode") or "none").lower()
    headers: dict[str, str] = {"Accept": "application/json"}
    if mode == "api_key":
        hname = settings.get("api_key_header") or "X-API-Key"
        headers[hname] = settings.get("api_key_value") or ""
    elif mode == "bearer":
        headers["Authorization"] = f"Bearer {settings.get('bearer_token') or ''}"
    elif mode == "basic":
        session.auth = (
            settings.get("basic_user") or "",
            settings.get("basic_password") or "",
        )
    elif mode == "login":
        login_url = (settings.get("base_url") or "").rstrip("/") + (
            settings.get("login_url") or ""
        )
        payload = {
            settings.get("login_user_field") or "username": settings.get("basic_user") or "",
            settings.get("login_pass_field") or "password": settings.get("basic_password") or "",
        }
        r = session.post(login_url, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
        token = _get_path(data, settings.get("login_token_path") or "token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    return headers


def _normalize_severity(raw: Any, severity_map: dict) -> str:
    s = str(raw or "").strip().lower()
    if s in severity_map:
        mapped = str(severity_map[s]).lower()
        if mapped in ("critical", "high", "medium", "low", "info"):
            return mapped
    for key, val in severity_map.items():
        if key.lower() == s:
            v = str(val).lower()
            if v in ("critical", "high", "medium", "low", "info"):
                return v
    if s in ("critical", "high", "medium", "low", "info"):
        return s
    return "info"


def _map_finding(item: dict, settings: dict) -> ScannerFinding:
    fmap = settings.get("field_map") or {}
    severity_map = settings.get("severity_map") or {}

    def pick(field: str, default: Any = "") -> Any:
        path = fmap.get(field) or field
        return _get_path(item, path) if path else default

    raw_sev = pick("severity", "info")
    sev = _normalize_severity(raw_sev, severity_map)
    cve_val = pick("cve", "")
    if isinstance(cve_val, list):
        cve_val = ", ".join(str(x) for x in cve_val)
    refs = pick("refs", [])
    if not isinstance(refs, list):
        refs = []
    ext = str(pick("external_id", "") or pick("id", "") or "").strip()
    if not ext:
        ext = str(hash(json.dumps(item, sort_keys=True)))[:32]
    cvss_raw = pick("cvss", None)
    try:
        cvss = float(cvss_raw) if cvss_raw is not None and cvss_raw != "" else None
    except (TypeError, ValueError):
        cvss = None
    epss_raw = pick("epss", None)
    try:
        epss = float(epss_raw) if epss_raw is not None and epss_raw != "" else None
    except (TypeError, ValueError):
        epss = None
    kev_raw = pick("kev", False)
    exploit_raw = pick("exploit_available", False)
    return ScannerFinding(
        external_id=ext,
        title=str(pick("title", "") or "")[:500],
        severity=sev,
        scanner_severity=sev,
        scanner_status=str(pick("scanner_status", "") or ""),
        cvss=cvss,
        cvss_vector=str(pick("cvss_vector", "") or ""),
        epss=epss,
        kev=bool(kev_raw),
        exploit_available=bool(exploit_raw),
        cve=str(cve_val or ""),
        cwe=str(pick("cwe", "") or ""),
        refs=refs,
        host=str(pick("host", "") or ""),
        ip=str(pick("ip", "") or ""),
        port=str(pick("port", "") or ""),
        service=str(pick("service", "") or ""),
        description=str(pick("description", "") or ""),
        solution=str(pick("solution", "") or ""),
        raw=item if isinstance(item, dict) else {"value": item},
    )


def _fetch_page(
    session: requests.Session,
    settings: dict,
    headers: dict,
    params: dict,
) -> list[dict]:
    base = (settings.get("base_url") or "").rstrip("/")
    endpoint = settings.get("list_endpoint") or "/api/vulnerabilities"
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    url = base + endpoint
    method = (settings.get("list_method") or "GET").upper()
    if method == "POST":
        r = session.post(url, headers=headers, json=params, timeout=60)
    else:
        r = session.get(url, headers=headers, params=params, timeout=60)
    r.raise_for_status()
    data = r.json()
    rpath = settings.get("results_path") or ""
    items = _get_path(data, rpath) if rpath else data
    if isinstance(items, dict):
        for key in ("items", "results", "data", "vulnerabilities", "findings"):
            if key in items and isinstance(items[key], list):
                items = items[key]
                break
    if not isinstance(items, list):
        if isinstance(data, list):
            items = data
        else:
            items = []
    return [x for x in items if isinstance(x, dict)]


def fetch_all(settings: dict | None = None, *, max_pages: int = 50) -> ScannerResult:
    settings = settings or scanner_settings()
    base = (settings.get("base_url") or "").strip()
    if not base:
        return ScannerResult(False, "Scanner base URL is not configured.")
    session = requests.Session()
    try:
        headers = _auth_headers(settings, session)
    except Exception as e:
        return ScannerResult(False, f"Authentication failed: {e}")
    findings: list[ScannerFinding] = []
    pagination = (settings.get("pagination") or "none").lower()
    page = 1
    offset = 0
    cursor = ""
    for _ in range(max_pages):
        params: dict[str, Any] = {}
        if pagination == "page":
            params[settings.get("page_param") or "page"] = page
            params[settings.get("page_size_param") or "per_page"] = settings.get("page_size") or 100
        elif pagination == "offset":
            params[settings.get("offset_param") or "offset"] = offset
            params[settings.get("page_size_param") or "limit"] = settings.get("page_size") or 100
        elif pagination == "cursor" and cursor:
            params[settings.get("cursor_param") or "cursor"] = cursor
        try:
            items = _fetch_page(session, settings, headers, params)
        except Exception as e:
            return ScannerResult(False, f"Request failed: {e}", findings)
        if not items:
            break
        for item in items:
            findings.append(_map_finding(item, settings))
        if pagination == "none":
            break
        if len(items) < int(settings.get("page_size") or 100):
            break
        page += 1
        offset += len(items)
    return ScannerResult(True, f"Fetched {len(findings)} findings.", findings)


def test_connection() -> ScannerResult:
    settings = scanner_settings()
    result = fetch_all(settings, max_pages=1)
    if not result.ok:
        return result
    sample = result.findings[0] if result.findings else None
    msg = result.message
    if sample:
        msg += f" Sample: {sample.external_id!r} — {sample.title!r} ({sample.severity})"
    return ScannerResult(True, msg, result.findings[:3])
