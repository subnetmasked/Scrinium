<div align="center">

<img src="static/scrinium-icon.svg" alt="Scrinium" width="128" height="128">

# Scrinium

**A small, themable, markdown-native IT documentation web app.**

[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](#run-without-a-container)
[![Flask](https://img.shields.io/badge/flask-server--rendered-000?logo=flask&logoColor=white)](#)
[![Podman](https://img.shields.io/badge/podman-rootless-892CA0?logo=podman&logoColor=white)](#first-run)
[![Made by subnetmasked](https://img.shields.io/badge/made%20by-subnetmasked-1f6feb?logo=github&logoColor=white)](https://github.com/subnetmasked)

Runs as a single **rootless Podman** container, gated behind a login,
with optional **LDAP / Active Directory** auth. Plain `.md` files on disk
— no database for content, no lock-in.

[Quick start](#first-run) ·
[Tour](#tour) ·
[Admin panel](#admin-panel) ·
[Platform packages](#platform-packages-security) ·
[Operations](#operations) ·
[CODEMAP](CODEMAP.md) ·
[Deploy](#production-deploy-fedora-vm)

</div>

---

## Highlights

|                         |                                                                                          |
| ----------------------- | ---------------------------------------------------------------------------------------- |
| **Markdown-native**     | Plain `.md` files on disk — folder layout is the navigation.                             |
| **Server-rendered**     | Flask + Pygments + vanilla CSS/JS. No SPA, no build step, no bundler.                    |
| **Login-gated**         | scrypt-hashed local users, optional LDAP bind auth, per-IP + per-username rate-limit.    |
| **Themable**            | Dark / light / system theme per user. Bundled sans + mono fonts, including **Nerd Fonts**. |
| **Admin panel**         | Users, categories, groups, LDAP, appearance, attachments, audit, trash, backup — all in the UI. |
| **Per-category access** | Restrict a category to selected users and/or groups; admins always have access.          |
| **Home dashboard**      | At-a-glance stats, quick actions, recent docs, recent entries, tag cloud, pinned welcome. |
| **Links dashboard**     | Shared wiki-style grid of tool/service bookmarks, with auto-fetched favicons.            |
| **Obsidian-style**      | YAML frontmatter, `[[wikilinks]]`, backlinks panel, image paste/drop.                    |
| **Code blocks**         | Pygments highlighting, optional line numbers, one-click **copy** on hover.               |
| **Tags & search**       | Per-entry tag chips → `/t/<tag>`, full-text search with optional per-category scope.     |
| **One-click backup**    | Admin → Backup: download every markdown file and attachment as a single zip.             |
| **Hardened forms**      | CSRF-protected forms; login lockout; HttpOnly + SameSite cookies.                        |
| **Platform packages**   | Optional **Security** package (vulnerability manager) and future modules; off by default. |

---

## Contents

- [First run](#first-run)
- [Configuration](#configuration)
- [Tour](#tour)
  - [Top navigation](#top-navigation)
  - [Home dashboard](#home-dashboard)
  - [Documents, entries, categories](#documents-entries-categories)
  - [Wikilinks & backlinks](#wikilinks--backlinks)
  - [Tags & search](#tags--search)
  - [Code blocks](#code-blocks)
  - [Image upload](#image-upload)
  - [Links dashboard](#links-dashboard)
  - [User settings](#user-settings)
- [Admin panel](#admin-panel)
- [Authentication](#authentication)
- [YAML frontmatter & infobox](#yaml-frontmatter--infobox)
- [Operations](#operations)
  - [Backups](#backups)
  - [Reset a forgotten password](#reset-a-forgotten-password)
  - [Updating](#updating)
- [Platform packages (Security)](#platform-packages-security)
- [CODEMAP](CODEMAP.md)
- [Security notes](#security-notes)
- [Run without a container](#run-without-a-container)
- [Production deploy (Fedora VM)](#production-deploy-fedora-vm)
- [Layout](#layout)
- [License](#license)

---

## First run

```bash
cd Scrinium
./scripts/install.sh
```

Or manually:

```bash
mkdir -p data
podman-compose up -d --build
```

Open <http://localhost:8080>. The first visit redirects to `/setup` to
create the initial administrator account; subsequent visits land on
`/login`.

> [!NOTE]
> Auth state lives in `./data/.scrinium/auth.db` (SQLite) and the session
> secret in `./data/.scrinium/secret.key`. Both persist across rebuilds
> because they sit on the data volume.

---

## Configuration

All knobs are environment variables. Defaults are sane for a single-VM
internal deployment.

| Variable                | Default            | Purpose                                |
| ----------------------- | ------------------ | -------------------------------------- |
| `SCRINIUM_DATA`         | `/data`            | Markdown directory                     |
| `SCRINIUM_CONFIG`       | `<DATA>/.scrinium` | Auth DB, session key, category config  |
| `SCRINIUM_HOST`         | `0.0.0.0`          | Bind address                           |
| `SCRINIUM_PORT`         | `8080`             | Bind port                              |
| `SCRINIUM_SITE_NAME`    | `Scrinium`         | Topbar title (overridable in Admin)    |
| `SCRINIUM_SECRET_KEY`   | _generated_        | Override the autogenerated cookie key  |
| `SCRINIUM_HTTPS_ONLY`   | `0`                | `1` to set `Secure` on cookies         |
| `SCRINIUM_TRUST_PROXY`  | `0`                | `1` if behind a reverse proxy          |
| `SCRINIUM_MAX_UPLOAD_MB` | `8`               | Max image upload size (MB)             |
| `SCRINIUM_MAX_ATTACHMENT_MB` | `50`         | Max general attachment size (MB) seed  |

**Where state lives** (`SCRINIUM_CONFIG`, default `data/.scrinium/`):

| File / dir              | Holds                                                  |
| ----------------------- | ------------------------------------------------------ |
| `auth.db`               | Users, LDAP config, appearance, features, link cards, package config |
| `secret.key`            | Flask session-signing key                              |
| `categories.json`       | Category definitions (order, icon, access)             |
| `security.db`           | Vulnerability Manager findings, workflow, events (when enabled) |
| `favicons/`             | Cached favicons for the links dashboard                |
| `security/vulnerabilities/evidence/` | Uploaded remediation evidence files |

---

## Tour

### Top navigation

The topbar is consistent on every page:

- **Left** — clickable logo, site name, global search field, **Apps** switcher
  (Documentation, Dashboard, and any enabled platform packages such as Security).
- **Right** — `+ New doc`, **Admin** (admins only), the signed-in username,
  **Settings**, **Sign out**.

The active route is highlighted; on narrow viewports the brand collapses
to just the icon and buttons wrap.

### Home dashboard

`/` is a working dashboard, not a static page:

- Greeting + at-a-glance stats (total docs, entries, tags, categories).
- Quick actions: `+ New doc` and `+ <Noun>` for the first three
  categories.
- **Categories** — each card shows icon, entry count, doc count, and a
  `+` to add a new entry.
- **Recently updated** — latest edits with location and relative time
  ("2h ago", "yesterday", "3d ago").
- **Recent entries** — newest entries with their parsed tags.
- **Tag cloud** — every tag in use, with counts (admin can hide it).
- **Pinned welcome** — `data/welcome.md` is rendered at the bottom
  whenever it exists.

> [!TIP]
> Click any tag chip anywhere to jump to `/t/<tag>` — a listing of every
> entry tagged with it.

### Documents, entries, categories

The sidebar groups the data tree into four bands:

- **Loose documents** — any `.md` directly under `data/` (e.g.
  `welcome.md`). Good for quick notes.
- **Categories** — admin-defined sections (default: *Servers*,
  *Applications*, *Network*), each backed by a folder under `data/`.
- **Entries** — folders one level inside a category, e.g.
  `data/servers/web-01/`. Each entry is its own page (rendered from
  `overview.md`) with as many extra docs as you like.
- **Other** — any top-level folder that isn't a known category slug.

**Workflow**

1. **Admins** define the categories.
2. **Anyone signed in** can use `+` next to a category to add a new
   entry. The form takes a name, optional tags, and a description;
   Scrinium creates `data/<slug>/<name>/overview.md` with
   category-aware YAML frontmatter.
3. Inside an entry, `+ Add doc` drops more documents (`runbook.md`,
   `incident-2024-03.md`, …) next to the overview.

### Wikilinks & backlinks

Write `[[Other Doc]]` or `[[servers/web-01/runbook|Runbook]]` anywhere
in markdown. Scrinium resolves links by:

1. Exact path match
2. Unique filename stem (case-insensitive)
3. Ambiguous stem → first match, flagged visually
4. No match → **broken link** (red) that opens `/n` pre-filled to create
   the doc

Below the body of every doc, a **Backlinks (N)** panel lists every other
document that links here, with a one-line snippet.

### Tags & search

Tags come from YAML frontmatter or a legacy `tags:` line:

```yaml
tags: [prod, web, nginx]
```

…rendered as clickable chips on category landing tiles and above the
overview. Click any chip → `/t/<tag>` lists every entry with it.

`/s` is full-text search with an optional scope dropdown (*All
documents* or any category). Inside a category landing page, a quick
**Search ‹Category› →** link is in the heading.

### Code blocks

Fenced code blocks use Pygments highlighting. When the **code-copy**
feature is on (Admin → Appearance, on by default), a discreet **Copy**
button appears on hover in the top-right of every block. It copies the
raw `<code>` text via `navigator.clipboard.writeText`, falls back to
`execCommand` on older browsers, and shows a brief *Copied* state.

Optional **line numbers** are a separate toggle in the same panel.

### Image upload

In the editor, paste a screenshot, drag an image onto the textarea, or
click **+ Image**. Files are stored next to the doc they belong to:

- `data/welcome.md` → `data/_attachments/welcome/<file>`
- `data/servers/web-01/runbook.md` → `data/servers/web-01/_attachments/runbook/<file>`

Markdown uses a relative reference (`![](screenshot.png)`); Scrinium
rewrites it to a login-gated `/a/...` URL at render time.

Allowed types: PNG, JPEG, WebP, GIF. (SVG is intentionally disallowed.)
Size cap from `SCRINIUM_MAX_UPLOAD_MB`, default 8 MB.

### Attachments upload

In the editor, use **+ Attachment** to upload non-inline files (PDF, Office,
archives, logs, media, etc.) next to the doc's attachment directory. Allowed
extensions and max size are configured in **Admin → Attachments**.

### Links dashboard

`/dash` is a separate, shared dashboard for the kind of links that
always end up scattered across personal bookmark bars — monitoring UIs,
ticketing, iLO consoles, vendor portals, runbooks, status pages.
Everyone signed in sees the same grid, and any signed-in user can curate
it. No admin-only gate, on purpose.

- **Cards in free-form sections.** Title, URL, optional description, and
  an optional section heading. Cards with no section collect under a
  leading **Pinned** group. The section input autocompletes existing
  sections so the team converges on the same names.
- **Auto-fetched favicons.** When a link is added or its URL changes
  Scrinium parses `<link rel="icon">` on the target page (fallback:
  `/favicon.ico`). Successful fetches are cached on disk under
  `${SCRINIUM_CONFIG}/favicons/`. Each fetch is capped at 4 s and 256
  KB.
- **Letter-tile fallback.** When fetching fails Scrinium renders a
  deterministic two-letter SVG tile so the grid stays tidy.
- **Manual icon refresh.** *Icon* button on each card re-fetches the
  favicon.
- **Link to a doc.** Each card can optionally point at a markdown path
  inside `data/`. The doc — and its parent entry — then surfaces the
  matching links under a *Related links* heading.
- **Live filter.** Search box at the top filters the grid in the browser
  by title, URL, description, section, and linked doc path.

Validation rules (enforced server-side in `links.py`):

| Field         | Constraint                                                                              |
| ------------- | --------------------------------------------------------------------------------------- |
| `title`       | 1–120 characters, required                                                              |
| `url`         | `http://` or `https://`, host required; bare `host.tld` auto-prefixed with `https://`   |
| `description` | up to 280 characters, optional                                                          |
| `section`     | up to 60 characters, optional                                                           |
| `doc_path`    | optional; must resolve to an existing file under `data/`                                |

### User settings

Every signed-in user has a **Settings** entry in the topbar:

- **Appearance** — personal theme: `dark`, `light`, or `system`
  (follows the browser's `prefers-color-scheme`).
- **Account** — change your own password. Local users only; LDAP users
  see a disabled form with a note pointing them at their directory.

---

## Admin panel

When signed in as an admin, the topbar shows an **Admin** link. The
panel is a sidebar of sections:

| Section         | What you can do                                                                                                                                        |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Users**       | Add local users, toggle the admin flag, set new passwords, or delete accounts. The last admin can't be demoted or deleted; you can't delete yourself.  |
| **Categories**  | Define sidebar sections: name, slug, *noun* used in buttons (e.g. "server"), icon, description. Mark a category **Restricted** and gate it to selected users and groups. Drag cards to reorder (saved instantly via XHR). |
| **Groups**      | Create reusable access groups and manage memberships. Use groups in category restrictions. |
| **LDAP**        | Enable LDAP, configure server URI, optional bind DN/password, search base, user filter (`{username}` placeholder), StartTLS, cert verification, auto-provisioning. **Test connection** before saving. |
| **Appearance**  | Override `SCRINIUM_SITE_NAME`, pick bundled sans + mono fonts (Inter, IBM Plex, **JetBrains Mono Nerd Font**, **FiraCode Nerd Font**), set the default theme for new users, and toggle features: code-block copy, line numbers, compact density, tag cloud visibility, broken-wikilink warnings. |
| **Attachments** | Configure attachment uploads: enabled flag, extension allowlist, and max size (MB). |
| **Audit**       | Searchable admin log of authentication, document edits/moves/deletes/restores, and attachment operations. |
| **Trash**       | Soft-deleted docs/folders waiting for restore or permanent purge. |
| **Backup**      | Stream a single zip of every markdown file and attachment.                                                                                             |
| **Security**    | Enable the Security package, map groups to Auditor/Technician roles, configure a generic scanner API, and run the Vulnerability Manager module.   |

Fonts are bundled in `static/fonts/` — no outbound network from the
browser. Nerd Font choices include the standard icon glyph ranges, so
they're useful in code blocks, terminal snippets, and as actual icons in
prose.

---

## Authentication

### Login flow

1. If the username matches a **local** user, only the local password is
   checked.
2. If the username matches a known **LDAP** user, only LDAP is checked.
3. If the username is unknown and LDAP auto-provision is on, the user is
   created on first successful LDAP bind (as a non-admin).

Promote an LDAP user to admin from the **Users** tab; their password
stays managed by your directory.

### Per-category access

By default, every signed-in user can read and edit every document.
Admins can mark a category **Restricted** so that only selected
usernames and/or groups (plus all admins) can:

- see the category in the sidebar,
- visit the category landing page or any entry inside it,
- view documents under it (`/d/...`), edit them, delete them, or open
  their attachments,
- create new entries inside it.

Loose documents directly under `data/` are never restricted — move a
document into a restricted category to gate it.

> [!NOTE]
> Restricted paths return **404**, not 403, so existence is not leaked.
> Access is enforced server-side at every relevant route, including the
> attachment URLs, search results, tag pages, backlinks, and the
> wikilink resolver.

Access settings live in `categories.json` next to the slug, icon, and
description, so the existing data-volume backup story already covers
them.

---

## YAML frontmatter & infobox

Every new document starts with a YAML frontmatter block at the top of
the file (Obsidian-style). Edit it directly in the textarea — the view
page never renders the block as prose. **Empty fields are hidden** in
the infobox, so a long template doesn't clutter the view.

### Common keys

| Key        | Purpose                                            |
| ---------- | -------------------------------------------------- |
| `title`    | Display title (defaults to filename stem)          |
| `hostname` | Host / device name (pre-filled on servers/network) |
| `created`  | ISO date the doc was created                       |
| `updated`  | Last modified date (auto, not stored in YAML)      |
| `tags`     | List of tag strings → clickable chips              |
| `owner`    | Team or person responsible                         |
| `contact`  | Email, Slack handle, or on-call rotation           |
| `status`   | e.g. `draft`, `production`                         |
| `reviewed` | Last review date                                   |
| `folder`   | Vault path (auto, not stored in YAML)              |

### Category templates

When you add a new entry (`+ server`, `+ application`, `+ device`), the
starter `overview.md` includes empty placeholders for fields a sysadmin
would expect.

<details>
<summary><strong>Servers</strong> (<code>servers/&lt;name&gt;/overview.md</code>)</summary>

| Key           | Purpose                              |
| ------------- | ------------------------------------ |
| `ip`          | Primary / management IP              |
| `vlan`        | VLAN ID or name                      |
| `os`          | Operating system                     |
| `role`        | e.g. domain controller, web server   |
| `environment` | `production`, `staging`, `dev`, …    |
| `location`    | Datacenter, rack, or site            |
| `serial`      | Hardware serial number               |
| `vendor`      | Dell, HPE, VMware, …                 |
| `model`       | Hardware or VM template              |

</details>

<details>
<summary><strong>Applications</strong> (<code>applications/&lt;name&gt;/overview.md</code>)</summary>

| Key              | Purpose                       |
| ---------------- | ----------------------------- |
| `url`            | Service URL or dashboard      |
| `version`        | Deployed version              |
| `environment`    | Where it runs                 |
| `host`           | Server or cluster it runs on  |
| `port`           | Primary listen port           |
| `protocol`       | HTTP, HTTPS, TCP, …           |
| `vendor`         | Vendor or upstream project    |
| `license_expiry` | Renewal / support expiry date |

</details>

<details>
<summary><strong>Network devices</strong> (<code>network/&lt;name&gt;/overview.md</code>)</summary>

| Key           | Purpose                              |
| ------------- | ------------------------------------ |
| `ip`          | Management IP                        |
| `vlan`        | Management VLAN                      |
| `device_type` | switch, router, firewall, AP, …      |
| `model`       | Model name / SKU                     |
| `serial`      | Serial number                        |
| `firmware`    | Running firmware / OS version        |
| `location`    | Rack, building, or comms room        |
| `site`        | Campus, region, or site code         |

</details>

Loose docs and custom categories get a smaller generic template
(`hostname`, `ip`, `url`, `location`, plus the common keys above).
Legacy single-line `tags: prod, web` lines still work; frontmatter takes
precedence when both are present.

### Adding frontmatter to existing docs

Open an older doc in the editor and click **+ Metadata** in the toolbar
— it inserts the category-aware template at the top of the textarea.
The button hides itself once a valid YAML block is present and reappears
if you delete it.

---

## Operations

### Backups

Admin → **Backup** produces a single zip of all your content:

- every `.md` file under the data directory (folder layout preserved),
- every image attachment under `_attachments/`,
- a `BACKUP_README.txt` manifest with timestamp, version, and counts.

Admin-only state in `.scrinium/` (auth DB, session-signing key,
`categories.json`) is **not** included — keep it out of downloadable
archives. For full disaster recovery, snapshot the whole data volume on
the host instead:

```bash
tar -czf /var/backups/scrinium-$(date +%F).tgz -C ~/scrinium data
```

To **restore**: unzip into an empty data directory and start Scrinium
pointing at it; you'll be sent through `/setup` to create a new admin
account on first run.

### Reset a forgotten password

Locked out? `scripts/reset_password.py` rewrites the scrypt hash
directly in `auth.db`. Run it as whichever user owns the DB (usually
root, because the container writes it as root):

```bash
# inside the running container (handy when the host has no Python deps):
podman exec -it scrinium python3 /app/scripts/reset_password.py admin

# or from the host venv:
sudo .venv/bin/python scripts/reset_password.py admin
```

The script prompts for the new password twice and enforces the same
8-character minimum the web UI uses. LDAP users are refused — their
password lives in your directory.

### Updating

```bash
cd ~/scrinium
./scripts/update.sh
```

Use `./scripts/update.sh --no-cache` if a rebuild picks up stale layers.

If a build picks up stale layers (rare, but possible):

```bash
podman-compose down
podman-compose build --no-cache scrinium
podman-compose up -d --force-recreate
```

CSS and JS are cache-busted by `APP_VERSION` (`app.py`), so users get
fresh styles on their next page load — no hard refresh needed.

---

## Security notes

> [!IMPORTANT]
> Treat the `data/` volume as a secret — it holds the auth DB, the
> session secret, and any LDAP bind password.

- Sessions are signed with `SECRET_KEY` (HttpOnly, SameSite=Lax). Set
  `SCRINIUM_HTTPS_ONLY=1` once you put TLS in front to enable `Secure`.
- All state-changing forms carry a CSRF token; the markdown preview API
  uses an `X-CSRF-Token` header.
- 8 failed login attempts per (IP, username) within 5 minutes locks out
  for the rest of the window. Restarts reset the counter.
- LDAP bind passwords are stored in the local SQLite DB. Use
  `chmod 700 data/.scrinium` on the host if you bind-mount.
- Restricted categories return **404** for non-allowed users at every
  read, edit, delete, attachment, search, and tag route.
- For real exposure put Scrinium behind a TLS terminator (Caddy, nginx,
  Traefik, …) and set `SCRINIUM_TRUST_PROXY=1`.

---

## Run without a container

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
SCRINIUM_DATA=./data python app.py
```

Health check at <http://localhost:8080/health> returns
`{"data":"./data","ok":true,"version":"1.1.0"}`.

---

## Production deploy (Fedora VM)

End-to-end walkthrough for cloning Scrinium onto a fresh Fedora VM
(Server or Workstation, F39+) and running it as a rootless Podman
service that survives reboots.

<details>
<summary><strong>Show full step-by-step walkthrough</strong> (steps 1–11)</summary>

### 1. Provision the VM

Any modern Fedora release works. 1 vCPU, 1 GB RAM, 8 GB disk is plenty
for hundreds of documents. The VM needs outbound internet for `dnf`
and the initial `git clone`.

### 2. Install the runtime

```bash
sudo dnf install -y git podman podman-compose
```

Quick sanity check:

```bash
podman --version          # 4.x or newer
podman-compose --version
```

> [!TIP]
> If `podman-compose` isn't packaged on your release, fall back to
> `pip install --user podman-compose`.

### 3. Use a regular (non-root) account

Rootless Podman is the recommended mode. Pick or create a normal user
and enable `systemd-logind` lingering so its services keep running
after logout:

```bash
sudo useradd -m scrinium             # or reuse your own account
sudo loginctl enable-linger scrinium
sudo machinectl shell scrinium@      # or: su - scrinium
```

### 4. Clone from GitHub

```bash
git clone https://github.com/<your-account>/Scrinium.git ~/scrinium
cd ~/scrinium
mkdir -p data
```

`data/` is gitignored — it's where the live documentation, auth DB,
session secret, and `categories.json` will be written.

### 5. (Optional) tune `compose.yaml` for production

If Scrinium will sit behind a reverse proxy with TLS, add a couple of
environment variables under the `scrinium` service:

```yaml
environment:
  SCRINIUM_SITE_NAME: "Work Docs"
  SCRINIUM_HTTPS_ONLY: "1"
  SCRINIUM_TRUST_PROXY: "1"
```

For a strictly internal VM accessed by IP, leave the defaults alone.

### 6. Build and start

```bash
podman-compose up -d --build
curl -s http://127.0.0.1:8080/health
# expect: {"data":"/data","ok":true,"version":"1.1.0"}
```

### 7. Open the firewall

```bash
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

(Skip this if you're running a reverse proxy on the same VM and only
plan to expose `:443`.)

Browse to `http://<vm-ip>:8080` — the first request redirects to
`/setup` so you can create the admin account.

### 8. Make it survive reboots (systemd)

Generate a rootless systemd unit so Scrinium starts on boot without
having to log in:

```bash
mkdir -p ~/.config/systemd/user
cd ~/scrinium
podman generate systemd --new --name scrinium \
    --files --restart-policy=always
mv container-scrinium.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now container-scrinium.service
systemctl --user status container-scrinium
```

Reboot once and verify the service comes back up on its own.

### 9. Updating from GitHub

```bash
cd ~/scrinium
git pull
podman-compose up -d --build
```

### 10. Back up what matters

`~/scrinium/data/` is the entire state of the install. A daily tarball
is plenty for most setups:

```bash
tar -czf /var/backups/scrinium-$(date +%F).tgz -C ~/scrinium data
```

Combine with `vzdump` (Proxmox) or your usual VM-snapshot policy for
belt-and-braces protection.

### 11. TLS with the bundled nginx (recommended)

`compose.yaml` ships with an nginx sidecar that terminates TLS in front
of Scrinium. All deployment-specific values live in a `.env` file at
the project root — nothing is hardcoded in the repo.

```bash
cp .env.example .env
$EDITOR .env       # set SCRINIUM_DOMAIN, point SCRINIUM_TLS_HOST_DIR at
                   # your cert directory, etc.
```

Drop your certificate files at the paths referenced in `.env`. By
default the nginx container expects:

- `${SCRINIUM_TLS_HOST_DIR}/fullchain.pem`
- `${SCRINIUM_TLS_HOST_DIR}/privkey.pem`

> [!WARNING]
> For rootless Podman, the Linux user running `podman-compose` must be
> able to read both files. A `root:root` private key with mode `600`
> will **not** be readable from the rootless nginx container.

By default the compose file publishes nginx on `8080` and `8443`
because rootless Podman cannot bind host ports below 1024 on a stock
Linux host. For a production hostname on normal HTTPS, either allow
rootless low-port binds:

```bash
echo 'net.ipv4.ip_unprivileged_port_start=80' |
  sudo tee /etc/sysctl.d/99-rootless-low-ports.conf
sudo sysctl --system
```

…and set `SCRINIUM_HTTP_PORT=80` and `SCRINIUM_HTTPS_PORT=443` in
`.env`, or keep Scrinium on `8080`/`8443` and put an existing privileged
host proxy/firewall rule in front of it.

Three common sources for the certificate:

- **Existing wildcard cert** — set `SCRINIUM_TLS_HOST_DIR` to wherever
  it already lives on the host (e.g. `/etc/ssl/mycorp-wildcard`).
- **certbot** — point `SCRINIUM_TLS_HOST_DIR` at
  `/etc/letsencrypt/live/<domain>` and run renewals on the host with
  `certbot renew --deploy-hook 'podman exec scrinium-nginx nginx -s reload'`.
- **Self-signed (lab only)**:
  ```bash
  openssl req -x509 -newkey rsa:2048 \
    -keyout nginx/certs/privkey.pem \
    -out    nginx/certs/fullchain.pem \
    -days 365 -nodes -subj "/CN=$SCRINIUM_DOMAIN"
  ```

The nginx container expands `nginx/scrinium.conf.template` with the env
vars at startup, so changing `.env` and restarting nginx is enough to
re-roll the TLS config — no editing of committed files.

> [!NOTE]
> Prefer a different TLS solution (Caddy, Traefik, an existing nginx on
> the host)? Comment out the `nginx` service in `compose.yaml`, change
> the `scrinium` service to publish `ports: ["8080:8080"]`, and point
> your existing terminator at it.

</details>

---

## Platform packages (Security)

Optional packages extend Scrinium without touching your markdown tree. They are
**disabled by default** — existing installs behave the same until an admin
enables a package under **Admin → Security**.

The topbar **Apps** switcher lists Documentation, Dashboard, and any enabled
packages. Package routes live under `/<package_id>/` (e.g. `/security/`).

### Enabling Security

1. **Admin → Groups** — create groups such as `security-auditors` and `security-technicians`.
2. **Admin → Security** — enable the package, map groups to **Auditor** and **Technician** roles, enable the **Vulnerability Manager** module.
3. Users in mapped groups (or admins) see **Security** in the Apps switcher.

### Roles

| Role | Capabilities |
| ---- | ------------ |
| **Auditor** | View findings, exports, activity log, approve/reject risk acceptance |
| **Technician** | Everything auditors can do, plus assign, change status, upload evidence, request risk acceptance, bulk actions, import |
| **Admin** | Full access including package settings and scanner configuration |

Technician supersedes auditor when a user is in both mapped groups.

### Vulnerability Manager

Routes under `/security/vulnerabilities/`:

| Page | Path | Purpose |
| ---- | ---- | ------- |
| Dashboard | `/` | KPIs, severity breakdown, priority queue with **owner** column, live search |
| Findings | `/findings` | Filterable table (incl. owner filter), bulk assign/status |
| Finding detail | `/<id>` | Overview, remediation links, workflow sidebar, evidence, comments, timeline |
| Import | `/import` | Upload CSV or Excel (Greenbone/OpenVAS-style exports) |
| Duplicates | `/duplicates` | Review possible duplicate groups (auditors) |
| Exports | `/exports` | CSV registers, JSON snapshot, audit-pack ZIP |
| Activity | `/activity` | Cross-finding event log |

#### Ownership and filtering

Every finding shows its **owner** — the technician who has taken responsibility for
the fix. The dashboard priority queue and the findings table both render the owner's
username (highlighted as **(you)** for the signed-in user) or a muted **Unassigned**
when no one has claimed it.

Technicians can narrow the work to themselves with the **Owner** filter on the
findings list (also exposed as quick links on the dashboard):

- **Assigned to me** — only findings the current user owns.
- **Unassigned** — only findings with no owner yet.
- **Mine or unassigned** — both, for picking up new work alongside your own queue.

#### Data sources

- **CSV / Excel import** — columns such as `vulnerability name`, `target`, `target name`, `severity`, `cve`, `solution`, `solution external references`, `proof`. Requires `openpyxl` for `.xlsx`.
- **Scanner API sync** — generic JSON REST client; field map and severity map are JSON in Admin → Security. No vendor names in the UI.
- **Manual** — create or edit findings through the workflow UI.

#### Deduplication

Each finding has a canonical **identity key** (CVE or title + host/IP + port). Import
and API sync both upsert on this fingerprint, so the same vulnerability from a
spreadsheet and later from a scanner **updates one row** instead of creating a copy.
The scanner’s `external_id` is preferred over import-derived IDs when merging.

Use **Duplicates** (or the dashboard KPI) to find legacy pairs that pre-date this
logic; mark extras as `duplicate` in workflow.

#### Remediation text

If the import or scanner provides no solution text, Scrinium does **not** invent
placeholder remediation. Instead it stores authoritative links (NVD, CVE.org, and
any URLs from `solution external references`) and shows them on the finding’s
Remediation tab.

#### Workflow rules

- **Close** requires `mitigated` status first, at least one evidence file, and a closure note.
- **Risk acceptance** is two-step: technician requests → auditor (or admin) approves/rejects. Self-approval is blocked.
- **False positive** and **won’t fix** require a reason.
- SLA due dates are applied when status moves to `triaged` (configurable per severity in Admin → Security).

#### Scanner sync

Set sync interval (minutes) in Admin → Security (`0` = manual only). **Sync now**
and **Test scanner connection** are on the same page. Scheduled sync runs in a
background thread and logs results in `sync_runs`.

#### State on disk

| Path | Holds |
| ---- | ----- |
| `data/.scrinium/security.db` | Findings, workflow, comments, tags, events, sync runs |
| `data/.scrinium/security/vulnerabilities/evidence/` | Evidence uploads per finding |
| `data/.scrinium/security/vulnerabilities/audit.jsonl` | Optional JSONL audit trail |

Package configuration (enabled flag, roles, scanner settings, SLA) is stored in
`auth.db` under the `packages` config key — not in `security.db`.

### Adding future packages

See [CODEMAP.md](CODEMAP.md) for the platform framework (`packages/registry.py`,
`authz.py`, `hub.py`) and how to register a new package without editing `app.py`
beyond the existing `packages.init_app()` call.

---

## Layout

```
.
├── app.py                  # Flask app, markdown routes, admin, health
├── CODEMAP.md              # architecture map (read this when hacking the code)
├── packages/               # platform framework + optional packages
│   ├── registry.py         # Package / Module / NavApp registration
│   ├── authz.py            # per-package roles, enable gates, decorators
│   ├── db.py               # per-package SQLite helpers
│   ├── admin.py            # /admin/<package_id> settings routes
│   ├── hub.py              # package landing pages at /<package_id>/
│   ├── builtins.py         # Documentation + Dashboard nav apps
│   └── security/           # Security package (Vulnerability Manager)
├── auth.py                 # users, sessions, LDAP, CSRF, rate limit
├── nav.py                  # categories, sidebar tree, breadcrumbs, ACL
├── audit.py                # admin audit log
├── frontmatter.py          # YAML frontmatter parse/serialize
├── markdown_ext.py         # wikilinks + attachment image rewriting
├── backlinks.py            # backlinks index
├── links.py                # /dash links + favicon fetcher
├── trash.py                # soft-delete / restore
├── scripts/
│   ├── install.sh          # first-time setup
│   ├── update.sh           # git pull + rebuild
│   ├── repair.sh           # diagnostics (+ optional --rebuild)
│   └── reset_password.py   # offline password reset
├── templates/
│   ├── base.html           # layout, topbar, app switcher
│   ├── _app_switcher.html  # Apps dropdown partial
│   ├── security/           # Security package + vuln manager templates
│   └── …                   # login, setup, view, edit, admin_*, …
├── static/
│   ├── style.css           # global styles + app switcher
│   ├── security.css        # Security / vuln manager UI
│   ├── editor.js
│   ├── code-copy.js
│   └── fonts/              # bundled Inter, IBM Plex, Nerd Fonts
├── nginx/
│   └── scrinium.conf.template
├── data/                   # YOUR markdown (volume-mounted)
│   └── .scrinium/
│       ├── auth.db
│       ├── security.db     # when Security package is used
│       └── …
├── Containerfile
├── compose.yaml
├── .env.example
└── requirements.txt
```

`_attachments/` folders hold images uploaded through the editor and are
intentionally hidden from every UI listing — they only appear as the
storage backing for `/a/...` image URLs in rendered markdown.

For a full file-by-file map of routes, modules, database schema, and extension
points, see **[CODEMAP.md](CODEMAP.md)**.

---

## License

Scrinium is **free software** licensed under the
[GNU General Public License v3.0 or later](LICENSE) (GPL-3.0-or-later).

You may use, study, modify, and redistribute this program under the
terms of the GPL. See the [LICENSE](LICENSE) file for the full text.

<sub>Copyright © 2026 [subnetmasked](https://github.com/subnetmasked) ·
Source: [github.com/subnetmasked/Scrinium](https://github.com/subnetmasked/Scrinium)</sub>
