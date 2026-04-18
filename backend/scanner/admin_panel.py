import asyncio

import httpx

from models import Finding, Severity, Category

PROBES = [
    ("admin_panel_admin", "/admin", Severity.HIGH, "Admin panel publicly accessible"),
    ("admin_panel_wp", "/wp-admin", Severity.HIGH, "WordPress admin panel exposed"),
    ("admin_panel_phpmyadmin", "/phpmyadmin", Severity.HIGH, "phpMyAdmin exposed"),
    ("admin_panel_adminer", "/adminer.php", Severity.CRITICAL, "Adminer database UI exposed"),
    ("admin_panel_administrator", "/administrator", Severity.HIGH, "Administrator panel exposed"),
    ("admin_panel_login", "/login", Severity.MEDIUM, "Login page exposed"),
    ("admin_panel_signin", "/signin", Severity.MEDIUM, "Sign-in page exposed"),
    ("admin_panel_cpanel", "/cpanel", Severity.HIGH, "cPanel control panel exposed"),
    ("admin_panel_webmail", "/webmail", Severity.HIGH, "Webmail interface exposed"),
    ("admin_panel_grafana", "/grafana", Severity.HIGH, "Grafana dashboard exposed"),
    ("admin_panel_jenkins", "/jenkins", Severity.HIGH, "Jenkins CI exposed"),
    ("admin_panel_kibana", "/kibana", Severity.HIGH, "Kibana dashboard exposed"),
    ("admin_panel_wp_login", "/wp-login.php", Severity.HIGH, "WordPress login page exposed"),
]

DESCRIPTION = "This panel is accessible from the internet. Ensure only authorized users have credentials, and consider restricting access by IP."


async def _probe(client: httpx.AsyncClient, base: str, probe_id: str, path: str, severity: Severity, title: str) -> Finding | None:
    try:
        url = f"{base}{path}"
        resp = await client.get(url)

        if resp.status_code == 200:
            return Finding(
                id=probe_id,
                severity=severity,
                title=title,
                description=f"{DESCRIPTION} Found at {url}.",
                affected=url,
                fix="Restrict access to this admin panel by IP or move it behind a VPN.",
                category=Category.ADMIN,
            )
        elif probe_id == "admin_panel_wp" and resp.status_code == 302:
            location = resp.headers.get("location", "")
            if "wp-login" in location:
                return Finding(
                    id=probe_id,
                    severity=Severity.HIGH,
                    title="WordPress admin panel exposed",
                    description=f"WordPress detected — /wp-admin redirects to wp-login.php at {url}.",
                    affected=url,
                    fix="Restrict access to /wp-admin by IP or use a security plugin to limit login attempts.",
                    category=Category.ADMIN,
                )
    except httpx.RequestError:
        pass
    return None


async def scan(host_url: str) -> list[Finding]:
    base = host_url.rstrip("/")

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=5) as client:
            results = await asyncio.gather(
                *[_probe(client, base, pid, path, sev, title) for pid, path, sev, title in PROBES]
            )
    except httpx.RequestError:
        return []

    findings = [r for r in results if r is not None]

    if not findings:
        findings.append(Finding(
            id="admin_clean",
            severity=Severity.PASS,
            title="No admin panels exposed",
            description="All probed admin panel paths returned 403, 404, or were unreachable.",
            affected=base,
            fix="No action needed.",
            category=Category.ADMIN,
        ))

    return findings
