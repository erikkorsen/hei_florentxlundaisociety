import asyncio
import re
from urllib.parse import urlparse

import dns.resolver
import dns.exception
import httpx

from models import Finding, Severity, Category

COMMON_SUBDOMAINS = [
    "dev", "staging", "stage", "test", "qa", "uat",
    "api", "app", "web", "www",
    "admin", "panel", "dashboard", "portal",
    "mail", "smtp", "webmail", "imap", "pop",
    "ftp", "sftp",
    "vpn", "remote",
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "jenkins", "gitlab", "ci", "cd",
    "grafana", "kibana", "prometheus", "monitoring",
    "backup", "bak", "old", "legacy",
    "internal", "intranet", "private",
    "cdn", "static", "assets", "media",
    "docs", "wiki", "blog",
    "beta", "demo", "sandbox",
    "sso", "auth", "login",
    "docker", "registry", "k8s",
]

# CNAME targets that are vulnerable to subdomain takeover when the resource is unclaimed
TAKEOVER_SIGNATURES = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "no such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "s3-website": "NoSuchBucket",
    "azurewebsites.net": "not found",
    "cloudfront.net": "Bad request",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "pantheon.io": "404 error unknown site",
    "readme.io": "Project doesnt exist",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "ghost.io": "404 not found",
    "uservoice.com": "This UserVoice subdomain is currently available",
    "zendesk.com": "Help Center Closed",
    "teamwork.com": "Oops - We didn't find your site",
    "helpjuice.com": "We could not find what you're looking for",
    "helpscout.net": "No settings were found for this company",
    "feedpress.me": "The feed has not been found",
    "freshdesk.com": "There is no helpdesk here",
    "tumblr.com": "There's nothing here",
    "wordpress.com": "Do you want to register",
    "fly.dev": "404 Not Found",
}

_semaphore = asyncio.Semaphore(15)


def _is_ip(value: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value))


async def _resolve_subdomain(subdomain: str) -> tuple[str, list[str], str | None]:
    """Returns (subdomain, ip_list, cname_target_or_None)."""
    loop = asyncio.get_event_loop()
    ips: list[str] = []
    cname: str | None = None

    async with _semaphore:
        # Check CNAME first
        try:
            answers = await loop.run_in_executor(
                None, lambda: dns.resolver.resolve(subdomain, "CNAME", lifetime=3)
            )
            cname = str(answers[0].target).rstrip(".")
        except (dns.exception.DNSException, OSError):
            pass

        # Check A records
        try:
            answers = await loop.run_in_executor(
                None, lambda: dns.resolver.resolve(subdomain, "A", lifetime=3)
            )
            ips = [str(rdata) for rdata in answers]
        except (dns.exception.DNSException, OSError):
            pass

    return subdomain, ips, cname


async def _check_takeover(subdomain: str, cname: str) -> Finding | None:
    """If CNAME points to a known service and the service returns an error page, it's a takeover risk."""
    for service_domain, error_signature in TAKEOVER_SIGNATURES.items():
        if service_domain in cname:
            try:
                async with httpx.AsyncClient(follow_redirects=True, timeout=5, verify=False) as client:
                    resp = await client.get(f"http://{subdomain}")
                    if error_signature.lower() in resp.text.lower():
                        return Finding(
                            id=f"subdomain_takeover_{subdomain.replace('.', '_')}",
                            severity=Severity.HIGH,
                            title=f"Subdomain takeover risk: {subdomain}",
                            description=(
                                f"The subdomain {subdomain} has a CNAME pointing to {cname}, "
                                f"but the {service_domain} resource appears unclaimed. "
                                "An attacker could register this resource and serve malicious content on your domain."
                            ),
                            affected=subdomain,
                            fix=f"Either claim the resource at {cname} or remove the DNS CNAME record for {subdomain}.",
                            category=Category.SUBDOMAINS,
                        )
            except (httpx.RequestError, Exception):
                pass
            break
    return None


async def scan(host_url: str) -> list[Finding]:
    parsed = urlparse(host_url)
    domain = parsed.hostname or ""

    if not domain or domain == "localhost" or _is_ip(domain):
        return [Finding(
            id="subdomains_skipped",
            severity=Severity.PASS,
            title="Subdomain scan skipped (localhost / IP)",
            description="Subdomain enumeration requires a real domain name.",
            affected=domain or host_url,
            fix="No action needed for local targets.",
            category=Category.SUBDOMAINS,
        )]

    # Strip www. prefix for the base domain
    base_domain = domain
    if base_domain.startswith("www."):
        base_domain = base_domain[4:]

    # Build subdomain list
    targets = [f"{sub}.{base_domain}" for sub in COMMON_SUBDOMAINS]

    # Resolve all subdomains concurrently
    results = await asyncio.gather(
        *[_resolve_subdomain(t) for t in targets],
        return_exceptions=True,
    )

    found_subdomains: list[tuple[str, list[str], str | None]] = []
    for r in results:
        if isinstance(r, tuple):
            subdomain, ips, cname = r
            if ips:
                found_subdomains.append((subdomain, ips, cname))

    findings: list[Finding] = []

    # Check for takeover risks on subdomains with CNAMEs
    takeover_tasks = []
    for subdomain, ips, cname in found_subdomains:
        if cname:
            takeover_tasks.append(_check_takeover(subdomain, cname))

    if takeover_tasks:
        takeover_results = await asyncio.gather(*takeover_tasks, return_exceptions=True)
        for r in takeover_results:
            if isinstance(r, Finding):
                findings.append(r)

    # Report discovered subdomains (excluding the obvious ones like www)
    interesting = [
        (sub, ips, cname) for sub, ips, cname in found_subdomains
        if not sub.startswith("www.")
    ]

    if interesting:
        sub_list = ", ".join(sub for sub, _, _ in interesting[:20])
        count = len(interesting)
        findings.append(Finding(
            id="subdomains_found",
            severity=Severity.MEDIUM,
            title=f"{count} subdomain{'s' if count != 1 else ''} discovered",
            description=(
                f"The following subdomains resolve for {base_domain}: {sub_list}"
                + (f" (and {count - 20} more)" if count > 20 else "")
                + ". Each subdomain expands your attack surface — ensure they are all intentional, "
                "up to date, and properly secured."
            ),
            affected=base_domain,
            fix="Audit all subdomains. Remove DNS records for decommissioned services. Ensure each subdomain has proper SSL and security headers.",
            category=Category.SUBDOMAINS,
        ))

    if not findings:
        findings.append(Finding(
            id="subdomains_clean",
            severity=Severity.PASS,
            title="No notable subdomains found",
            description=f"None of the {len(COMMON_SUBDOMAINS)} common subdomain names resolved for {base_domain}.",
            affected=base_domain,
            fix="No action needed.",
            category=Category.SUBDOMAINS,
        ))

    return findings
