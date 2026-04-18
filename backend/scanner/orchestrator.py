import asyncio
import time
from urllib.parse import urlparse

from models import Finding, Severity, Category, ScanRequest, ScanResponse
from scanner import secrets_scanner, ssl_checker, port_scanner, admin_panel

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
    ]

    results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=30)

    findings: list[Finding] = []
    for result in results:
        if isinstance(result, list):
            findings.extend(result)
        # Exceptions from individual scanners are silently skipped

    # If no findings at all, target was unreachable
    if not findings:
        return ScanResponse(
            target_url=request.url,
            github_url=request.github_url,
            scan_duration_seconds=round(time.time() - start, 2),
            summary={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "PASS": 0},
            findings=[Finding(
                id="target_unreachable",
                severity=Severity.HIGH,
                title="Target unreachable",
                description=f"Could not connect to {request.url}. The host may be down, blocked, or the URL may be incorrect.",
                affected=request.url,
                fix="Verify the URL is correct and the target is publicly accessible.",
                category=Category.SSL,
            )],
        )

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
