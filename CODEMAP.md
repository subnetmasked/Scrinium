# Scrinium CODEMAP

Architecture reference for contributors. Markdown content lives on disk;
auth and package config live in SQLite under `data/.scrinium/`.

**Version:** 1.1.0 (see `APP_VERSION` in `app.py`)

---

## High-level architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser                                                        │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTP
┌────────────────────────────▼────────────────────────────────────┐
│  app.py (Flask)                                                 │
│  ├── Core: docs, search, tags, edit, admin, attachments         │
│  ├── packages.init_app()                                        │
│  │     ├── NavApps: Documentation (/), Dashboard (/dash)        │
│  │     ├── Package hubs: /security/, /itsm/ (reserved)          │
│  │     └── Module blueprints: /security/vulnerabilities/…       │
│  └── Jinja templates + static/                                  │
└────────────┬───────────────────────────────┬────────────────────┘
             │                               │
    ┌────────▼────────┐            ┌─────────▼──────────┐
    │  data/*.md      │            │  data/.scrinium/   │
    │  (markdown tree)│            │  auth.db           │
    └─────────────────┘            │  security.db       │
                                   │  categories.json   │
                                   └────────────────────┘
```

---

## Entry point and bootstrap

| File | Role |
| ---- | ---- |
| `app.py` | Flask application, `APP_VERSION`, core routes, calls `packages.init_app(app, config_dir=..., data_dir=...)` |
| `packages/__init__.py` | `init_app()`: register nav apps, Security package, migrate DBs, mount blueprints, app switcher context processor, start vuln sync thread |
| `Containerfile` | Copies `app.py`, `packages/`, `scripts/`, `templates/`, `static/` |
| `compose.yaml` | Podman compose: `scrinium` + optional `nginx` TLS sidecar |

### Environment variables

| Variable | Default | Used by |
| -------- | ------- | ------- |
| `SCRINIUM_DATA` | `/data` | Markdown root |
| `SCRINIUM_CONFIG` | `<DATA>/.scrinium` | `auth.db`, `secret.key`, `*.db`, evidence dirs |
| `SCRINIUM_HTTPS_ONLY` | `0` | Cookie `Secure` flag |
| `SCRINIUM_TRUST_PROXY` | `0` | `ProxyFix` middleware |
| `SCRINIUM_MAX_UPLOAD_MB` | `8` | Image uploads |
| `SCRINIUM_MAX_ATTACHMENT_MB` | `50` | General attachments + vuln evidence |

---

## Core application (`app.py` and friends)

### `app.py`

Monolithic Flask app (~2200 lines) owning:

- First-run `/setup`, `/login`, `/logout`, `/health`
- Document CRUD: `/d/`, `/e/`, `/f/`, `/n`, `/edit`, `/preview`
- Search `/s`, tags `/t/`, trash restore
- Admin sections: users, categories, groups, LDAP, appearance, attachments, audit, trash, backup
- Attachment serving `/a/…`
- Integrates `nav`, `auth`, `audit`, `backlinks`, `links`, `trash`, `frontmatter`, `markdown_ext`

Does **not** contain Security/vuln routes — those are in `packages/`.

### `auth.py`

- SQLite `auth.db`: users (scrypt passwords), LDAP config, appearance, feature flags, link cards, **`packages` JSON config**
- Sessions (`user_id` in Flask session), CSRF tokens, login rate limiting
- `get_config` / `set_config` for arbitrary JSON blobs (used by `authz` for package settings)

### `nav.py`

- `categories.json` load/save, sidebar tree builder
- Reserved slugs: includes package IDs from `packages.reserved_slugs_extra()` (`security`, `itsm`, …)
- Per-category ACL: restricted categories return 404 to unauthorized users

### `audit.py`

- Append-only admin audit log in `auth.db`
- `audit.record(action, target=, details=)` — used by core app and packages

### `frontmatter.py`

- YAML frontmatter parse/serialize, category-aware templates for new entries

### `markdown_ext.py`

- Wikilink resolution, attachment URL rewriting for rendered HTML

### `backlinks.py`

- Index of incoming wikilinks per document path

### `links.py`

- `/dash` bookmark grid, favicon fetch/cache, validation

### `trash.py`

- Soft-delete moves to `.trash/`, restore, purge

---

## Platform framework (`packages/`)

### Design goals

1. Add optional product areas (Security, future ITSM) without growing `app.py`.
2. Packages are **off by default**; disabled packages return **404** (not 403).
3. Each package can have **roles** (group-mapped), **modules** (URL-mounted blueprints), and **admin UI**.

### `packages/registry.py`

Dataclasses and global registries:

| Type | Fields | Purpose |
| ---- | ------ | ------- |
| `Role` | `id`, `name`, `description` | Package role definition |
| `Module` | `id`, `name`, `icon`, `blueprint`, `migrate`, `summary_card`, `default_config` | Mountable feature |
| `Package` | `id`, `name`, `icon`, `roles`, `modules`, `admin_view`, `landing_view` | Top-level product area |
| `NavApp` | `id`, `name`, `icon`, `endpoint`, `accessible` | Apps switcher entry |

Functions: `register_package`, `register_nav_app`, `get_package`, `iter_packages`, `get_module`, `reserved_package_ids`.

### `packages/authz.py`

- Reads/writes `packages` key in `auth.db` via `auth.get_config` / `auth.set_config`
- `package_enabled`, `module_enabled`, `current_role` (admin → `admin`, else technician > auditor)
- Decorators: `package_login_required`, `require_auditor`, `require_technician`, `module_enabled_required`
- `merged_package_config()` — defaults merged with saved config

### `packages/db.py`

- `db_path(package_id)` → `config_dir / {package_id}.db` (e.g. `security.db`)
- `connect(package_id)` — context manager, `sqlite3.Row` factory
- `init_package_db` / `init_all_package_dbs` — runs each module’s `migrate(conn)`

### `packages/admin.py`

- Blueprint `packages_admin` at `/admin/<package_id>`
- Handles `save_package` (enable + role group mapping); delegates other actions to `pkg.admin_view`

### `packages/hub.py`

- Registers `pkg_{id}` blueprint at `/{package_id}/` with `landing_view`
- Builds module summary cards for enabled modules

### `packages/builtins.py`

Registers NavApps:

| ID | Endpoint | URL |
| -- | -------- | --- |
| `documentation` | `index` | `/` |
| `dashboard` | `dash` | `/dash` |

### `packages/__init__.py`

- `inject_packages` context processor → `app_switcher_entries`, `registered_packages`, `package_role`, `package_enabled`
- `_entry_active()` — highlights current app in switcher
- Warns if package slug collides with `data/<slug>/` folder

### App switcher UI

| File | Role |
| ---- | ---- |
| `templates/_app_switcher.html` | Button + fixed panel; inline JS for toggle/position |
| `static/style.css` | `.app-switcher-*` styles (global, all pages) |

---

## Security package (`packages/security/`)

### Registration — `packages/security/__init__.py`

```python
Package(
    id="security",
    roles=(Role("auditor", ...), Role("technician", ...)),
    modules=(vulnerabilities_module,),
    admin_view=admin_view,      # templates/security/admin_settings.html
    landing_view=landing_view,  # templates/security/package.html
)
```

`admin_view` also handles POST `save_vuln_module` (SLA, sync interval, scanner JSON maps).

### Vulnerability Manager module

**Blueprint:** `vuln` mounted at `/security/vulnerabilities/`  
**Register:** `packages/security/modules/vulnerabilities/__init__.py`

#### Route map (`routes.py`)

| Method | Path | Handler | Auth |
| ------ | ---- | ------- | ---- |
| GET | `/` | `dashboard` | package login |
| GET | `/findings` | `findings_list` | package login |
| GET | `/duplicates` | `duplicates_page` | auditor |
| GET/POST | `/import` | `import_page` | technician |
| GET | `/exports` | `exports_page` | auditor |
| GET | `/export/<kind>` | `export_download` | auditor |
| GET | `/activity` | `activity` | auditor |
| GET | `/<id>` | `detail` | package login |
| POST | `/<id>/action` | `action` | technician |
| POST | `/<id>/approve-risk` | `approve_risk` | auditor |
| POST | `/bulk` | `bulk` | technician |
| GET | `/evidence/<id>` | `download_evidence` | package login |
| POST | `/admin/sync` | `admin_sync` | admin |
| POST | `/admin/test-scanner` | `test_scanner` | admin |
| POST | `/admin/seed-demo` | `seed_demo` | admin |

#### Module files

| File | Responsibility |
| ---- | -------------- |
| `db.py` | Schema, queries, `upsert_vulnerability`, dashboard stats, duplicate detection |
| `identity.py` | Canonical fingerprint: CVE/title + host/IP + port → `identity_key` |
| `remediation.py` | No fake solutions; NVD/CVE.org links from `refs_text` + CVE |
| `import_data.py` | CSV + XLSX import (Greenbone-style columns), `ImportResult` |
| `scanner.py` | Generic REST client, field/severity JSON maps, pagination |
| `sync.py` | `run_sync()`, scheduled background thread, reopen on re-detect |
| `workflow.py` | Status transitions, SLA on triage, risk acceptance, evidence-gated close |
| `export.py` | CSV registers, JSON snapshot, audit-pack ZIP |
| `demo.py` | `seed_demo_vulnerability()` — rich smoke-test data (`local-smoke-1`) |

#### Upsert / deduplication flow (`db.upsert_vulnerability`)

```
1. Compute identity_key (identity.canonical_identity_key)
2. Lookup by external_id
3. Else lookup by identity_key  → merged_by_identity=True
4. UPDATE (merge refs, COALESCE empty solution/description)
   OR INSERT + new vuln_workflow row (status=open)
5. On identity merge: add_event("vuln.merged_identity")
```

Returns `(vuln_id, created, merged_by_identity)`.

Import uses `external_id = import:{hash[:32]}`; API sync uses scanner’s id; merge prefers non-import external_id.

#### Database schema (`security.db`)

**`vulnerabilities`** — finding facts: `external_id` (UNIQUE), `identity_key` (UNIQUE), severity, CVSS, CVE, host, ip, port, description, solution, refs_json, …

**`vuln_workflow`** — 1:1 with finding: status, assignee, due_date, risk acceptance fields, duplicate_of_id, …

**`vuln_comments`**, **`vuln_tags`** + **`vuln_tag_map`**, **`vuln_events`**, **`vuln_evidence`**, **`sync_runs`**

Migrate adds `identity_key` column on existing installs and backfills.

#### Templates (`templates/security/`)

| Template | Purpose |
| -------- | ------- |
| `vuln_base.html` | Extends `base.html`, `area-security` body class, loads `security.css` |
| `_vuln_nav.html` | Sub-nav: Dashboard, Findings, Import, Duplicates, Exports, Activity |
| `vulnerabilities/dashboard.html` | KPIs, severity bars, priority queue |
| `vulnerabilities/list.html` | Filters, bulk bar, findings table |
| `vulnerabilities/detail.html` | Tabs (Overview / Remediation / Activity), workflow sidebar |
| `vulnerabilities/import.html` | File upload zone |
| `vulnerabilities/duplicates.html` | Duplicate group review |
| `vulnerabilities/exports.html` | Export cards |
| `vulnerabilities/activity.html` | Event log table |
| `admin_settings.html` | Package + scanner admin (extends `admin_base.html`) |
| `package.html` | Security hub module cards |

#### Static assets

| File | Scope |
| ---- | ----- |
| `static/security.css` | Vuln manager layout, KPIs, tables, detail tabs, admin grids |
| `static/style.css` | Global + app switcher + `body.area-security` full-width |

---

## Templates (core)

| Path | Role |
| ---- | ---- |
| `base.html` | HTML shell, topbar, sidebar slot, `{% block head_extra %}`, `{% block body_class %}` |
| `admin_base.html` | Admin sidebar shell; lists `registered_packages` |
| `index.html` | Home dashboard |
| `view.html` / `edit.html` | Document read/write |
| `login.html` / `setup.html` | Auth |

---

## Scripts (`scripts/`)

| Script | Purpose |
| ------ | ------- |
| `install.sh` | `mkdir data`, `podman-compose up -d --build` |
| `update.sh` | `git pull`, rebuild, recreate container |
| `repair.sh` | Diagnostics; `--rebuild` optional |
| `reset_password.py` | Offline scrypt hash reset in `auth.db` |

---

## Config shape: `packages` in `auth.db`

```json
{
  "security": {
    "enabled": true,
    "roles": {
      "auditor": { "groups": ["security-auditors"] },
      "technician": { "groups": ["security-technicians"] }
    },
    "modules": {
      "vulnerabilities": {
        "enabled": true,
        "sync_interval_minutes": 0,
        "sla": { "critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365 },
        "scanner": {
          "base_url": "https://…",
          "auth_mode": "api_key",
          "field_map": { "external_id": "id", "title": "title", … },
          "severity_map": { "high": "high", … }
        }
      }
    }
  }
}
```

---

## Adding a new package (checklist)

1. Create `packages/mypkg/__init__.py` with `register()` calling `registry.register_package(Package(...))`.
2. Add module(s) with `Blueprint`, `db.migrate`, `summary_card`, `default_config`.
3. Implement `admin_view` and `landing_view` (render templates).
4. Call `register_mypkg()` from `packages/__init__.py` (or lazy import like Security).
5. Add reserved slug in `nav.py` / `registry._RESERVED_IDS` if needed.
6. Add admin sidebar entry via `registered_packages` (automatic).
7. Add templates under `templates/mypkg/`.
8. Optional: `static/mypkg.css` + `head_extra` block.

Future **ITSM** package: reserve slug `itsm`, follow same module pattern.

---

## Request flow examples

### View a document

```
GET /d/servers/web-01/runbook
  → auth.login_required
  → nav.path_allowed
  → read markdown from data/servers/web-01/runbook.md
  → frontmatter + markdown_ext + backlinks
  → render view.html
```

### Import vulnerabilities

```
POST /security/vulnerabilities/import
  → authz.require_technician("security")
  → import_data.import_file()
  → db.upsert_vulnerability() per row (identity merge)
  → audit.record("vuln.import")
  → redirect findings list with notice
```

### Scheduled scanner sync

```
vuln_sync._sync_loop (daemon thread)
  → app.app_context()
  → if sync_interval_minutes > 0: sync.run_sync(trigger="scheduled")
  → scanner.fetch_all() → upsert each finding
```

---

## Dependencies (`requirements.txt`)

| Package | Used for |
| ------- | -------- |
| Flask | Web framework |
| Markdown + Pygments | Rendering |
| ldap3 | LDAP auth |
| requests | Scanner API, favicons |
| PyYAML | Frontmatter |
| openpyxl | Excel vulnerability import |
| waitress | Production WSGI server |

---

## Related docs

- [README.md](README.md) — user-facing setup, tour, operations
- [LICENSE](LICENSE) — GPL-3.0-or-later
