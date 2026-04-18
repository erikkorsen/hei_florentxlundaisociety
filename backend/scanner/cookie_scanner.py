import httpx

from models import Finding, Severity, Category


def _parse_cookie(header_value: str) -> tuple[str, bool, bool, bool]:
    """Parse a Set-Cookie header. Returns (name, has_httponly, has_secure, has_samesite)."""
    parts = [p.strip() for p in header_value.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else "unknown"
    parts_lower = [p.lower() for p in parts]
    has_httponly = any(p == "httponly" for p in parts_lower)
    has_secure = any(p == "secure" for p in parts_lower)
    has_samesite = any(p.startswith("samesite=") for p in parts_lower)
    return name, has_httponly, has_secure, has_samesite


async def scan(host_url: str) -> list[Finding]:
    findings: list[Finding] = []
    is_https = host_url.startswith("https://")

    try:
        async with httpx.AsyncClient(follow_redirects=True, max_redirects=5, timeout=5) as client:
            resp = await client.get(host_url)
            raw_cookies = resp.headers.get_list("set-cookie")
    except httpx.RequestError:
        return []

    if not raw_cookies:
        findings.append(Finding(
            id="cookies_none_found",
            severity=Severity.PASS,
            title="No Set-Cookie headers in initial response",
            description="No cookies were set in the HTTP response. Note: cookies set via JavaScript after page load are not visible to this check.",
            affected=host_url,
            fix="No action needed.",
            category=Category.COOKIES,
        ))
        return findings

    missing_httponly: list[str] = []
    missing_secure: list[str] = []
    missing_samesite: list[str] = []

    for header_value in raw_cookies:
        name, has_httponly, has_secure, has_samesite = _parse_cookie(header_value)
        if not has_httponly:
            missing_httponly.append(name)
        if not has_secure:
            missing_secure.append(name)
        if not has_samesite:
            missing_samesite.append(name)

    if missing_httponly:
        names = ", ".join(missing_httponly)
        findings.append(Finding(
            id="cookies_missing_httponly",
            severity=Severity.MEDIUM,
            title="Cookies missing HttpOnly flag",
            description=f"The following cookies lack the HttpOnly flag, making them accessible to JavaScript and vulnerable to theft via XSS: {names}",
            affected=host_url,
            fix="Add the `HttpOnly` attribute to all session and authentication cookies.",
            category=Category.COOKIES,
        ))

    if missing_secure and is_https:
        names = ", ".join(missing_secure)
        findings.append(Finding(
            id="cookies_missing_secure",
            severity=Severity.HIGH,
            title="Cookies missing Secure flag on HTTPS site",
            description=f"The following cookies lack the Secure flag, meaning they can be transmitted over unencrypted HTTP connections: {names}",
            affected=host_url,
            fix="Add the `Secure` attribute to all cookies on HTTPS sites to prevent them being sent over HTTP.",
            category=Category.COOKIES,
        ))

    if missing_samesite:
        names = ", ".join(missing_samesite)
        findings.append(Finding(
            id="cookies_missing_samesite",
            severity=Severity.MEDIUM,
            title="Cookies missing SameSite attribute",
            description=f"The following cookies have no SameSite attribute, leaving them vulnerable to Cross-Site Request Forgery (CSRF) attacks: {names}",
            affected=host_url,
            fix="Add `SameSite=Lax` or `SameSite=Strict` to your cookies. Use `SameSite=None; Secure` only if cross-site access is required.",
            category=Category.COOKIES,
        ))

    if not findings:
        findings.append(Finding(
            id="cookies_all_secure",
            severity=Severity.PASS,
            title="Cookies have all security flags set",
            description="All Set-Cookie headers include HttpOnly, Secure, and SameSite attributes.",
            affected=host_url,
            fix="No action needed.",
            category=Category.COOKIES,
        ))

    return findings
