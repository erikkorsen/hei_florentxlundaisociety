import re
from urllib.parse import urlparse

import httpx

from models import Finding, Severity, Category

HIBP_API = "https://haveibeenpwned.com/api/v3/breaches"


def _is_ip(value: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value))


async def scan(host_url: str) -> list[Finding]:
    parsed = urlparse(host_url)
    domain = parsed.hostname or ""

    if not domain or domain == "localhost" or _is_ip(domain):
        return [Finding(
            id="breach_skipped",
            severity=Severity.PASS,
            title="Breach check skipped (localhost / IP)",
            description="Breach checking requires a real domain name.",
            affected=domain or host_url,
            fix="No action needed for local targets.",
            category=Category.BREACH,
        )]

    # Strip www. for matching
    check_domain = domain
    if check_domain.startswith("www."):
        check_domain = check_domain[4:]

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                HIBP_API,
                headers={"User-Agent": "SecurityScanner-HackathonProject"},
            )
            if resp.status_code != 200:
                return [Finding(
                    id="breach_api_error",
                    severity=Severity.PASS,
                    title="Breach check inconclusive",
                    description=f"Could not reach the Have I Been Pwned API (HTTP {resp.status_code}). This does not mean the domain is safe.",
                    affected=check_domain,
                    fix="Try again later or check manually at https://haveibeenpwned.com.",
                    category=Category.BREACH,
                )]

            breaches = resp.json()
    except httpx.RequestError:
        return [Finding(
            id="breach_api_error",
            severity=Severity.PASS,
            title="Breach check inconclusive",
            description="Could not reach the Have I Been Pwned API. This does not mean the domain is safe.",
            affected=check_domain,
            fix="Try again later or check manually at https://haveibeenpwned.com.",
            category=Category.BREACH,
        )]

    # Find breaches matching this domain
    domain_breaches = [
        b for b in breaches
        if b.get("Domain", "").lower() == check_domain.lower()
    ]

    findings: list[Finding] = []

    for breach in domain_breaches:
        name = breach.get("Name", "Unknown")
        date = breach.get("BreachDate", "Unknown date")
        pwn_count = breach.get("PwnCount", 0)
        data_classes = breach.get("DataClasses", [])
        description_html = breach.get("Description", "")
        # Strip HTML tags from the HIBP description
        description_clean = re.sub(r"<[^>]+>", "", description_html)

        count_str = f"{pwn_count:,}" if pwn_count else "unknown number of"
        data_str = ", ".join(data_classes[:10]) if data_classes else "unknown data types"

        severity = Severity.CRITICAL if pwn_count > 1_000_000 else Severity.HIGH

        findings.append(Finding(
            id=f"breach_{name.lower().replace(' ', '_').replace('.', '_')}",
            severity=severity,
            title=f"Known data breach: {name} ({date})",
            description=(
                f"{check_domain} was involved in the {name} data breach on {date}. "
                f"{count_str} accounts were compromised. "
                f"Exposed data includes: {data_str}. "
                f"{description_clean[:300]}"
            ),
            affected=check_domain,
            fix=(
                "If this breach is recent: force password resets for all affected users, "
                "rotate API keys and secrets, notify affected users per your jurisdiction's breach notification laws, "
                "and review how the breach occurred to prevent recurrence."
            ),
            category=Category.BREACH,
        ))

    if not findings:
        findings.append(Finding(
            id="breach_clean",
            severity=Severity.PASS,
            title="No known data breaches",
            description=f"{check_domain} does not appear in the Have I Been Pwned database of known breaches.",
            affected=check_domain,
            fix="No action needed. Continue monitoring at https://haveibeenpwned.com.",
            category=Category.BREACH,
        ))

    return findings
