import asyncio
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from models import Finding, Severity, Category


async def scan(host_url: str) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(host_url)
    hostname = parsed.hostname or ""
    has_issues = False

    # Check 1: Is HTTPS available?
    https_ok = await _check_https(hostname)
    if not https_ok:
        has_issues = True
        findings.append(Finding(
            id="ssl_no_https",
            severity=Severity.HIGH,
            title="Site not available over HTTPS",
            description=f"Could not establish an HTTPS connection to {hostname} on port 443.",
            affected=f"https://{hostname}",
            fix="Install an SSL certificate (Let's Encrypt is free) and configure your web server to serve HTTPS.",
            category=Category.SSL,
        ))
    else:
        # Check 2: Certificate expiry
        cert_finding = await _check_cert_expiry(hostname)
        if cert_finding:
            has_issues = True
            findings.append(cert_finding)

    # Check 3: HTTP → HTTPS redirect
    redirect_finding = await _check_redirect(hostname)
    if redirect_finding:
        has_issues = True
        findings.append(redirect_finding)

    # Check 4: Deprecated TLS versions (only if HTTPS is up)
    if https_ok:
        tls_findings = await _check_tls_versions(hostname)
        if tls_findings:
            has_issues = True
            findings.extend(tls_findings)

    if not has_issues:
        findings.append(Finding(
            id="ssl_valid",
            severity=Severity.PASS,
            title="SSL certificate valid and HTTPS enforced",
            description=f"The SSL certificate for {hostname} is valid and HTTP redirects to HTTPS.",
            affected=f"https://{hostname}",
            fix="No action needed.",
            category=Category.SSL,
        ))

    return findings


async def _check_https(hostname: str) -> bool:
    try:
        ctx = ssl.create_default_context()
        conn = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None, lambda: ctx.wrap_socket(
                    socket.create_connection((hostname, 443), timeout=3),
                    server_hostname=hostname,
                )
            ),
            timeout=5,
        )
        conn.close()
        return True
    except Exception:
        return False


async def _check_cert_expiry(hostname: str) -> Finding | None:
    try:
        pem = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None, lambda: ssl.get_server_certificate((hostname, 443), timeout=3)
            ),
            timeout=5,
        )
        # Parse the notAfter date from the PEM certificate
        cert_der = ssl.PEM_cert_to_DER_cert(pem)
        # Use ssl to decode
        x509 = ssl.DER_cert_to_PEM_cert(cert_der)
        # We need to connect again to get parsed cert info
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=3),
            server_hostname=hostname,
        ) as conn:
            cert = conn.getpeercert()

        not_after_str = cert.get("notAfter", "")
        if not not_after_str:
            return None

        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days

        if days_left < 0:
            return Finding(
                id="ssl_cert_expired",
                severity=Severity.HIGH,
                title="SSL certificate expired",
                description=f"The SSL certificate for {hostname} expired {abs(days_left)} days ago ({not_after_str}).",
                affected=f"https://{hostname}",
                fix="Renew your SSL certificate immediately. If using Let's Encrypt, run `certbot renew`.",
                category=Category.SSL,
            )
        elif days_left <= 30:
            return Finding(
                id="ssl_cert_expiring_soon",
                severity=Severity.MEDIUM,
                title="SSL certificate expiring soon",
                description=f"The SSL certificate for {hostname} expires in {days_left} days ({not_after_str}).",
                affected=f"https://{hostname}",
                fix="Renew your SSL certificate before it expires. If using Let's Encrypt, run `certbot renew`.",
                category=Category.SSL,
            )
        return None
    except Exception:
        return None


async def _check_tls_versions(hostname: str) -> list[Finding]:
    if not hasattr(ssl, "TLSVersion"):
        return []  # Python < 3.7 or OpenSSL without TLS version control

    findings = []
    for tls_version, version_name in [
        (ssl.TLSVersion.TLSv1, "TLS 1.0"),
        (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.maximum_version = tls_version
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            def _try_connect():
                with socket.create_connection((hostname, 443), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname):
                        pass

            await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(None, _try_connect),
                timeout=5,
            )
            ver_id = version_name.lower().replace(" ", "").replace(".", "_")
            findings.append(Finding(
                id=f"ssl_{ver_id}_supported",
                severity=Severity.HIGH,
                title=f"Deprecated {version_name} protocol accepted",
                description=(
                    f"The server accepts {version_name}, which was deprecated by the IETF in 2021. "
                    "It is vulnerable to known attacks (POODLE, BEAST) and should not be used."
                ),
                affected=f"https://{hostname}",
                fix=f"Disable {version_name} in your server config and require TLS 1.2 or higher (nginx: `ssl_protocols TLSv1.2 TLSv1.3;`).",
                category=Category.SSL,
            ))
        except (ssl.SSLError, OSError, asyncio.TimeoutError):
            # Server refused the deprecated version, or OpenSSL has it disabled — not a finding
            pass

    return findings


async def _check_redirect(hostname: str) -> Finding | None:
    try:
        # Follow up to 5 redirects to see if we end up on HTTPS
        async with httpx.AsyncClient(follow_redirects=True, max_redirects=5, timeout=5) as client:
            resp = await client.get(f"http://{hostname}")
            # If the final URL is HTTPS, the site redirects properly
            if resp.url.scheme == "https":
                return None  # Good — eventually redirects to HTTPS
            return Finding(
                id="ssl_no_redirect",
                severity=Severity.MEDIUM,
                title="HTTP does not redirect to HTTPS",
                description=f"Requesting http://{hostname} does not redirect to HTTPS.",
                affected=f"http://{hostname}",
                fix="Add an HTTP → HTTPS redirect in your web server config.",
                category=Category.SSL,
            )
    except httpx.RequestError:
        return None  # Can't reach HTTP version — not necessarily a problem
