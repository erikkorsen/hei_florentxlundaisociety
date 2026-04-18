import re
from urllib.parse import urlparse

import httpx

from models import Finding, Severity, Category

HEADER_CHECKS = [
    (
        "strict-transport-security",
        "headers_no_hsts",
        "HSTS header missing",
        "The Strict-Transport-Security header is not set. Browsers won't enforce HTTPS on repeat visits, leaving users vulnerable to SSL-stripping attacks.",
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to your server responses.",
    ),
    (
        "x-frame-options",
        "headers_no_xframe",
        "Clickjacking protection missing",
        "The X-Frame-Options header is not set. Your site can be embedded in an iframe on a malicious page to trick users into clicking hidden elements.",
        "Add `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN` to your server responses.",
    ),
    (
        "x-content-type-options",
        "headers_no_xcto",
        "MIME sniffing protection missing",
        "The X-Content-Type-Options header is not set. Browsers may interpret files as a different MIME type, enabling certain injection attacks.",
        "Add `X-Content-Type-Options: nosniff` to your server responses.",
    ),
    (
        "content-security-policy",
        "headers_no_csp",
        "Content Security Policy missing",
        "No Content-Security-Policy header is set. Without CSP, injected scripts can execute freely in users' browsers.",
        "Add a Content-Security-Policy header. Start with `default-src 'self'` and expand as needed.",
    ),
    (
        "referrer-policy",
        "headers_no_referrer_policy",
        "Referrer-Policy missing",
        "No Referrer-Policy header is set. Browsers may send the full URL of your pages as a Referer header to third-party sites, leaking sensitive path information.",
        "Add `Referrer-Policy: strict-origin-when-cross-origin` to your server responses.",
    ),
    (
        "permissions-policy",
        "headers_no_permissions_policy",
        "Permissions-Policy missing",
        "No Permissions-Policy header is set. Without it, embedded third-party scripts may access sensitive browser features (camera, microphone, geolocation) without restriction.",
        "Add `Permissions-Policy: geolocation=(), microphone=(), camera=()` to restrict browser feature access.",
    ),
]


async def scan(host_url: str) -> list[Finding]:
    hostname = urlparse(host_url).hostname or ""
    # Security headers are only meaningful on HTTPS responses — always probe https directly.
    https_url = f"https://{hostname}"
    findings: list[Finding] = []

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=5) as client:
            resp = await client.get(https_url)
            headers = resp.headers

            for header_name, finding_id, title, description, fix in HEADER_CHECKS:
                if header_name not in headers:
                    findings.append(Finding(
                        id=finding_id,
                        severity=Severity.MEDIUM,
                        title=title,
                        description=description,
                        affected=https_url,
                        fix=fix,
                        category=Category.HEADERS,
                    ))

            # Information disclosure: Server header with version number
            server = headers.get("server", "")
            if re.search(r"/[\d.]+", server):
                findings.append(Finding(
                    id="headers_server_version",
                    severity=Severity.MEDIUM,
                    title="Server version disclosed in header",
                    description=f"The Server header reveals your software version: `{server}`. Attackers use version info to look up known CVEs.",
                    affected=https_url,
                    fix="Configure your server to omit or genericize the Server header (nginx: `server_tokens off;`, Apache: `ServerTokens Prod`).",
                    category=Category.HEADERS,
                ))

            # Information disclosure: X-Powered-By leaks tech stack
            powered = headers.get("x-powered-by", "")
            if powered:
                findings.append(Finding(
                    id="headers_x_powered_by",
                    severity=Severity.MEDIUM,
                    title="X-Powered-By header leaks technology stack",
                    description=f"The X-Powered-By header reveals your backend technology: `{powered}`. This helps attackers identify which exploits to target.",
                    affected=https_url,
                    fix="Remove the X-Powered-By header. In Express.js: `app.disable('x-powered-by')`. In PHP: set `expose_php = Off` in php.ini.",
                    category=Category.HEADERS,
                ))

    except httpx.RequestError:
        return []

    if not findings:
        findings.append(Finding(
            id="headers_all_present",
            severity=Severity.PASS,
            title="Security headers in place",
            description="HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy, and Permissions-Policy headers are all set. No server version disclosure detected.",
            affected=https_url,
            fix="No action needed.",
            category=Category.HEADERS,
        ))

    return findings
