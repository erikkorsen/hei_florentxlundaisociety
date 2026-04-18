import asyncio
import re

import httpx

from models import Finding, Severity, Category
from scanner.llm_content_analyzer import analyze_exposed_file

ROBOTS_SENSITIVE = re.compile(r"(admin|backup|config|internal|api|secret|private)", re.IGNORECASE)

# For these paths, a text/html response CAN be legitimate — but we still
# check the content to make sure it's the real thing, not a soft 404.
HTML_OK_PATHS = {
    "/phpinfo.php": ["php version", "configuration", "phpinfo()"],
    "/server-status": ["apache server status", "server uptime", "requests/sec"],
    "/api-docs": ["swagger", "openapi", "api documentation", "endpoints"],
}

# Phrases that indicate a custom "not found" page returning HTTP 200 (soft 404)
SOFT_404_SIGNALS = [
    "this site does not exist",
    "page not found",
    "404 not found",
    "not found",
    "error 404",
    "doesn't exist",
    "does not exist",
    "page could not be found",
    "nothing here",
    "no page",
    "sidan hittades inte",
    "siden ble ikke funnet",
    "seite nicht gefunden",
    "page introuvable",
]

# Check the <title> tag for 404 signals too
TITLE_404 = re.compile(r"<title[^>]*>[^<]*(404|not found)[^<]*</title>", re.IGNORECASE)

CREDENTIAL_PATTERNS = re.compile(
    r"(PASSWORD|SECRET|API_KEY|APIKEY|TOKEN|DATABASE_URL|DB_PASS|AWS_SECRET|PRIVATE_KEY)\s*[=:]",
    re.IGNORECASE,
)


def _analyze_content(path: str, body: str) -> str:
    """Analyze exposed file content and return extra context for the description."""
    if not body:
        return ""

    size_kb = len(body) / 1024

    if ".env" in path:
        cred_lines = CREDENTIAL_PATTERNS.findall(body)
        if cred_lines:
            return f" Contains {len(cred_lines)} credential-like variable(s) ({', '.join(set(cred_lines)[:5])}). Rotate immediately."
        return f" File is {size_kb:.1f}KB. Inspect for secrets."

    if ".git/config" in path:
        urls = re.findall(r"url\s*=\s*(.+)", body)
        if urls:
            return f" Exposes git remote(s): {', '.join(u.strip() for u in urls[:3])}."
        return " Git config exposed — may reveal repo structure."

    if path.endswith(".sql") or "backup" in path.lower():
        tables = re.findall(r"CREATE TABLE\s+[`\"']?(\w+)", body, re.IGNORECASE)
        if tables:
            return f" SQL dump ({size_kb:.0f}KB) with tables: {', '.join(tables[:5])}. Likely contains real user data."
        return f" File is {size_kb:.0f}KB. May be a database dump."

    if "phpinfo" in path:
        version_match = re.search(r"PHP Version\s*</td><td[^>]*>([^<]+)", body)
        if version_match:
            return f" PHP version: {version_match.group(1)}. Full server configuration exposed."
        return " Full PHP configuration and server environment exposed."

    if "actuator/env" in path:
        try:
            import json
            data = json.loads(body)
            prop_count = sum(len(v.get("properties", {})) for v in data.get("propertySources", []))
            return f" Spring Boot actuator exposes {prop_count} configuration properties including potential secrets."
        except Exception:
            pass
        return " Spring Boot environment variables exposed."

    if size_kb > 10:
        return f" Response is {size_kb:.0f}KB — likely contains substantial data."

    return ""

PROBES = [
    ("secrets_env", "/.env", Severity.CRITICAL, ".env file publicly accessible"),
    ("secrets_env_local", "/.env.local", Severity.CRITICAL, ".env.local file publicly accessible"),
    ("secrets_env_production", "/.env.production", Severity.CRITICAL, ".env.production file publicly accessible"),
    ("secrets_git_config", "/.git/config", Severity.CRITICAL, "Git repository exposed"),
    ("secrets_wp_config", "/wp-config.php", Severity.CRITICAL, "WordPress config file exposed"),
    ("secrets_htpasswd", "/.htpasswd", Severity.CRITICAL, ".htpasswd credentials file exposed"),
    ("secrets_backup_sql", "/backup.sql", Severity.CRITICAL, "SQL backup file publicly accessible"),
    ("secrets_db_yml", "/config/database.yml", Severity.CRITICAL, "Database config file exposed"),
    ("secrets_ds_store", "/.DS_Store", Severity.MEDIUM, ".DS_Store file exposed (leaks directory structure)"),
    ("secrets_web_config", "/web.config", Severity.CRITICAL, "IIS web.config exposed"),
    ("secrets_phpinfo", "/phpinfo.php", Severity.HIGH, "PHP info page exposed"),
    ("secrets_server_status", "/server-status", Severity.HIGH, "Apache server-status page exposed"),
    ("secrets_actuator_env", "/actuator/env", Severity.CRITICAL, "Spring Boot actuator /env endpoint exposed"),
    ("secrets_actuator_health", "/actuator/health", Severity.MEDIUM, "Spring Boot actuator /health endpoint exposed"),
    ("secrets_swagger", "/swagger.json", Severity.MEDIUM, "Swagger API docs publicly accessible"),
    ("secrets_openapi", "/openapi.json", Severity.MEDIUM, "OpenAPI docs publicly accessible"),
    ("secrets_api_docs", "/api-docs", Severity.MEDIUM, "API docs endpoint publicly accessible"),
]

DIR_LISTING_PATHS = ["/uploads", "/backup", "/static", "/files", "/assets"]

FIX_TEXT = (
    "Block access to this path in your web server config "
    "(nginx: `location ~ /\\.env { deny all; }`, "
    "Apache: `<Files .env> Require all denied </Files>`). "
    "Rotate any credentials the file contains immediately."
)


async def _get_canary_fingerprint(client: httpx.AsyncClient, base: str) -> dict | None:
    """Hit a path that definitely doesn't exist. Store the response fingerprint."""
    try:
        resp = await client.get(f"{base}/.xz9k_canary_test_404")
        if resp.status_code == 200:
            return {
                "status": 200,
                "content_type": resp.headers.get("content-type", "").split(";")[0].strip().lower(),
                "length": len(resp.text),
                "body_prefix": resp.text[:200],
            }
    except httpx.RequestError:
        pass
    return None


def _matches_canary(resp: httpx.Response, canary: dict | None) -> bool:
    """Check if a probe response looks like the canary (i.e. server returns 200 for everything)."""
    if canary is None:
        return False
    ct = resp.headers.get("content-type", "").split(";")[0].strip().lower()
    body = resp.text
    # Same content type and similar length (within 20% or same body prefix)
    if ct == canary["content_type"]:
        if body[:200] == canary["body_prefix"]:
            return True
        canary_len = canary["length"]
        if canary_len > 0 and abs(len(body) - canary_len) / canary_len < 0.2:
            return True
    return False


async def _probe(client: httpx.AsyncClient, base: str, probe_id: str, path: str, severity: Severity, title: str, canary: dict | None = None) -> Finding | None:
    try:
        url = f"{base}{path}"
        resp = await client.get(url)

        if resp.status_code == 200:
            # Canary match: server returns 200 for non-existent paths too
            if _matches_canary(resp, canary):
                return None

            content_type = resp.headers.get("content-type", "").split(";")[0].strip().lower()
            body_lower = resp.text[:2000].lower()

            # Soft-404: check body text and title tag
            if any(sig in body_lower for sig in SOFT_404_SIGNALS):
                return None
            if TITLE_404.search(resp.text[:2000]):
                return None

            # HTML responses: only allow for specific paths IF the content proves it's real
            if content_type == "text/html":
                expected_markers = HTML_OK_PATHS.get(path)
                if expected_markers is None:
                    # Not a known HTML-ok path — HTML response means soft 404
                    return None
                if not any(m in body_lower for m in expected_markers):
                    # Known path but content doesn't match what we'd expect — soft 404
                    return None

            body = resp.text[:10000]
            regex_extra = _analyze_content(path, body)
            llm_extra = await analyze_exposed_file(path, body)
            extra = llm_extra if llm_extra else regex_extra
            return Finding(
                id=probe_id,
                severity=severity,
                title=title,
                description=f"The file {path} is publicly accessible at {url}.{extra}",
                affected=url,
                fix=FIX_TEXT,
                category=Category.SECRETS,
            )
        elif resp.status_code in (301, 302):
            # Follow the redirect and check if it lands on a soft-404 page
            location = resp.headers.get("location", "")
            try:
                async with httpx.AsyncClient(follow_redirects=True, timeout=5) as follow_client:
                    final = await follow_client.get(url)
                    final_ct = final.headers.get("content-type", "").split(";")[0].strip().lower()
                    # After following a redirect, text/html always indicates a soft-404 —
                    # real file-type secrets don't redirect to HTML pages
                    if final_ct == "text/html":
                        return None
                    if any(sig in final.text[:2000].lower() for sig in SOFT_404_SIGNALS):
                        return None
            except httpx.RequestError:
                pass
            return Finding(
                id=probe_id,
                severity=Severity.MEDIUM,
                title=f"{title} (redirects)",
                description=f"The path {path} returned HTTP {resp.status_code}. It may be behind auth — verify manually.",
                affected=url,
                fix="Verify this path is not accessible after following the redirect. Block it in your web server config if unnecessary.",
                category=Category.SECRETS,
            )
    except httpx.RequestError:
        pass
    return None


async def _probe_dir_listing(client: httpx.AsyncClient, base: str, path: str) -> Finding | None:
    try:
        url = f"{base}{path}"
        resp = await client.get(url)
        if resp.status_code == 200 and "Index of " in resp.text:
            return Finding(
                id=f"secrets_dir_listing_{path.strip('/').replace('/', '_')}",
                severity=Severity.HIGH,
                title=f"Directory listing enabled at {path}",
                description=f"The directory {path} at {url} is publicly browsable. Attackers can enumerate all files.",
                affected=url,
                fix="Disable directory listing in your web server config (nginx: `autoindex off;`, Apache: `Options -Indexes`).",
                category=Category.SECRETS,
            )
    except httpx.RequestError:
        pass
    return None


async def _probe_robots_txt(client: httpx.AsyncClient, base: str) -> Finding | None:
    try:
        resp = await client.get(f"{base}/robots.txt")
        if resp.status_code != 200:
            return None
        sensitive_paths = [
            line.split(":", 1)[1].strip()
            for line in resp.text.splitlines()
            if line.strip().lower().startswith("disallow:")
            and ROBOTS_SENSITIVE.search(line)
        ]
        if sensitive_paths:
            paths_str = ", ".join(sensitive_paths[:10])
            return Finding(
                id="secrets_robots_sensitive_paths",
                severity=Severity.MEDIUM,
                title="robots.txt discloses sensitive paths",
                description=f"robots.txt reveals internal paths that may be worth investigating: {paths_str}",
                affected=f"{base}/robots.txt",
                fix="Remove sensitive path entries from robots.txt. Blocking indexing via robots.txt is not a security control — protect the paths with authentication instead.",
                category=Category.SECRETS,
            )
    except httpx.RequestError:
        pass
    return None


async def _probe_security_txt(client: httpx.AsyncClient, base: str) -> Finding | None:
    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            resp = await client.get(f"{base}{path}")
            if resp.status_code == 200:
                return Finding(
                    id="secrets_security_txt_present",
                    severity=Severity.PASS,
                    title="security.txt present",
                    description=f"A security.txt file was found at {base}{path}, providing a responsible disclosure contact for security researchers.",
                    affected=f"{base}{path}",
                    fix="No action needed.",
                    category=Category.SECRETS,
                )
        except httpx.RequestError:
            pass
    return None


async def scan(host_url: str) -> list[Finding]:
    base = host_url.rstrip("/")

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=5) as client:
            # Canary request: detect servers that return 200 for everything
            canary = await _get_canary_fingerprint(client, base)

            results = await asyncio.gather(
                *[_probe(client, base, pid, path, sev, title, canary) for pid, path, sev, title in PROBES],
                *[_probe_dir_listing(client, base, path) for path in DIR_LISTING_PATHS],
                _probe_robots_txt(client, base),
                _probe_security_txt(client, base),
            )
    except httpx.RequestError:
        return []

    findings = [r for r in results if r is not None]

    if not findings:
        findings.append(Finding(
            id="secrets_clean",
            severity=Severity.PASS,
            title="No secret files exposed",
            description="All probed secret file paths returned 403, 404, or were unreachable.",
            affected=base,
            fix="No action needed.",
            category=Category.SECRETS,
        ))

    return findings
