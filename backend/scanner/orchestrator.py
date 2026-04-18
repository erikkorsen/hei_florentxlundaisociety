import asyncio
import time
from urllib.parse import urlparse

from models import Finding, Severity, Category, ScanRequest, ScanResponse
from scanner import secrets_scanner, ssl_checker, port_scanner, admin_panel, headers_scanner, dns_scanner, github_scanner, cookie_scanner, cors_scanner

SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.PASS: 3}


async def run_scan(request: ScanRequest) -> ScanResponse:
    start = time.time()
    parsed = urlparse(request.url)
    hostname = parsed.hostname or ""

    tasks = [
        secrets_scanner.scan(request.url),
        ssl_checker.scan(request.url),
        port_scanner.scan(hostname),
        admin_panel.scan(request.url),
        headers_scanner.scan(request.url),
        dns_scanner.scan(request.url),
        cookie_scanner.scan(request.url),
        cors_scanner.scan(request.url),
    ]

    if request.github_url:
        tasks.append(github_scanner.scan(request.github_url))

    results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=30)

    findings: list[Finding] = []
    for result in results:
        if isinstance(result, list):
            findings.extend(result)
        # Exceptions from individual scanners are silently skipped

    # Firewall inference: 3+ open ports → CRITICAL
    open_port_count = sum(1 for f in findings if f.category == Category.PORTS and f.severity != Severity.PASS)
    if open_port_count >= 3:
        findings.append(Finding(
            id="firewall_disabled",
            severity=Severity.CRITICAL,
            title="Firewall likely disabled",
            description=f"{open_port_count} dangerous ports are open on {hostname}, suggesting no firewall is in place.",
            affected=hostname,
            fix="Enable a firewall and restrict inbound traffic to only necessary ports (typically 80 and 443).",
            category=Category.FIREWALL,
        ))

    # Sort: CRITICAL first, then HIGH, MEDIUM, PASS
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    duration = round(time.time() - start, 2)

    summary: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "PASS": 0}
    for f in findings:
        summary[f.severity.value] += 1

    return ScanResponse(
        target_url=request.url,
        github_url=request.github_url,
        scan_duration_seconds=duration,
        summary=summary,
        findings=findings,
    )
