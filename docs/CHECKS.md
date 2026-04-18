# Scan Checks

Guidelines for what each scanner category looks for. The code is the source of truth for exact paths, patterns, and thresholds — this doc provides the intent and philosophy.

## Severity Scale

| Level | Meaning |
|-------|---------|
| **CRITICAL** | Immediate risk — data breach, RCE, or unauthenticated access to sensitive systems |
| **HIGH** | Significant exposure that should be fixed soon |
| **MEDIUM** | Risk exists but needs additional conditions to exploit |
| **PASS** | Check ran and found no issue — shown so users know what was verified |

## Secrets — Exposed Files

Probes common sensitive file paths (`.env`, `.git/config`, config files, backups, etc.) via HTTP GET.

- **HTTP 200** on a secret file → CRITICAL (the file is publicly readable)
- **301/302 redirect** → MEDIUM (path exists but may be behind auth — verify manually)
- **403/404** → clean, skip
- All clean → emit a single PASS finding
- Redirects are disabled — don't follow them, the redirect itself is the signal

## SSL/TLS & HTTPS

Checks whether the site supports HTTPS and has a valid certificate.

- No HTTPS available → HIGH
- Certificate expired → HIGH
- Certificate expiring soon → MEDIUM
- HTTP doesn't redirect to HTTPS → MEDIUM
- Everything good → PASS

Uses Python `ssl` stdlib for cert checks, `httpx` for redirect detection.

## Ports — Dangerous Open Ports

Scans a list of known-dangerous ports (databases, remote access, Docker API, etc.) using raw async sockets.

- Database ports open (Redis, MySQL, PostgreSQL, MongoDB) → CRITICAL
- Remote access ports open (SSH, FTP, RDP) → HIGH
- All checked ports closed → PASS
- Special probes: if Redis is open, check if auth is required. If Docker API is open, check if it responds.

**Firewall inference:** If many dangerous ports are open, the orchestrator adds a derived CRITICAL finding suggesting no firewall is in place. This is not a separate scanner — it's logic in the orchestrator.

## Admin — Exposed Admin Panels

Probes common admin and login paths (`/admin`, `/wp-admin`, `/phpmyadmin`, `/login.php`, etc.) via HTTP GET.

- HTTP 200 on an admin path → HIGH (or CRITICAL for database UIs like Adminer)
- WordPress special case: 302 redirect to `/wp-login.php` also counts as exposed
- All clean → PASS

## GitHub — Workflow Security

Scans `.github/workflows/` files in a public GitHub repo for security issues.

- **Hardcoded secrets:** Regex patterns for AWS keys, GitHub tokens, passwords, generic secrets
- **Dangerous commands:** `curl | bash`, `wget | sh` patterns
- **General approach:** Fetch workflow file contents via GitHub API, run pattern matching
- Clean workflows → PASS
- No workflows found → MEDIUM (consider adding CI/CD)
- Private/inaccessible repo → skip gracefully

## Adding New Checks

To add a new check to an existing scanner:
1. Add the probe logic to the relevant scanner module
2. Return a `Finding` object with appropriate severity, description, and fix text
3. Follow the existing pattern in that module

To add a new scanner category:
1. Create a new module in `backend/scanner/`
2. Export `async def scan(...) -> list[Finding]`
3. Add the category to `Category` enum in `models.py`
4. Wire it into `orchestrator.py`'s `asyncio.gather()` call
