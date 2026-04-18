import asyncio

import httpx

from models import Finding, Severity, Category

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
]

FIX_TEXT = (
    "Block access to this path in your web server config "
    "(nginx: `location ~ /\\.env { deny all; }`, "
    "Apache: `<Files .env> Require all denied </Files>`). "
    "Rotate any credentials the file contains immediately."
)


async def _probe(
    client: httpx.AsyncClient,
    base: str,
    probe_id: str,
    path: str,
    severity: Severity,
    title: str,
) -> Finding | None | Exception:
    try:
        url = f"{base}{path}"
        resp = await client.get(url)

        if resp.status_code == 200:
            return Finding(
                id=probe_id,
                severity=severity,
                title=title,
                description=f"The file {path} responded with HTTP 200 at {url}. It may contain sensitive data.",
                affected=url,
                fix=FIX_TEXT,
                category=Category.SECRETS,
            )
        elif resp.status_code in (301, 302):
            return Finding(
                id=probe_id,
                severity=Severity.MEDIUM,
                title=f"{title} (redirects)",
                description=f"The path {path} returned HTTP {resp.status_code}. It may be behind auth — verify manually.",
                affected=url,
                fix="Verify this path is not accessible after following the redirect. Block it in your web server config if unnecessary.",
                category=Category.SECRETS,
            )
        return None
    except httpx.RequestError as e:
        return e  # Return exception so caller can detect unreachable


async def scan(host_url: str) -> list[Finding]:
    base = host_url.rstrip("/")

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=5) as client:
            results = await asyncio.gather(
                *[_probe(client, base, pid, path, sev, title) for pid, path, sev, title in PROBES]
            )
    except Exception:
        return []

    findings = [r for r in results if isinstance(r, Finding)]
    errors = [r for r in results if isinstance(r, Exception)]

    # If ALL probes errored (site unreachable), don't emit a false PASS
    if len(errors) == len(results):
        return []

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
