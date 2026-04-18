import asyncio
import time
from urllib.parse import urlparse

from models import Finding, Severity, Category, ScanRequest, ScanResponse


async def run_scan(request: ScanRequest) -> ScanResponse:
    start = time.time()

    # Stub: return hardcoded findings for now
    findings = [
        Finding(
            id="secrets_env",
            severity=Severity.CRITICAL,
            title=".env file publicly accessible",
            description=f"The file /.env responded with HTTP 200 at {request.url}/.env. It may contain database credentials, API keys, or other secrets.",
            affected=f"{request.url.rstrip('/')}/.env",
            fix="Block access to this path in your web server config. Rotate any credentials the file contains immediately.",
            category=Category.SECRETS,
        ),
        Finding(
            id="ssl_valid",
            severity=Severity.PASS,
            title="SSL certificate valid and HTTPS enforced",
            description="The SSL certificate is valid and the site redirects HTTP to HTTPS.",
            affected=request.url,
            fix="No action needed.",
            category=Category.SSL,
        ),
        Finding(
            id="ports_clean",
            severity=Severity.PASS,
            title="No dangerous ports open",
            description="None of the checked ports (22, 21, 3389, 3306, 5432, 27017, 6379, 2375) are open.",
            affected=urlparse(request.url).hostname or request.url,
            fix="No action needed.",
            category=Category.PORTS,
        ),
    ]

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
