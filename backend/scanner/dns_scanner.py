import asyncio
from urllib.parse import urlparse

import dns.resolver
import dns.exception

from models import Finding, Severity, Category


async def _resolve_txt(domain: str) -> list[str]:
    """Return all TXT record strings for domain, or [] on any error."""
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(domain, "TXT", lifetime=5)
        )
        return [rdata.to_text().strip('"') for rdata in answers]
    except (dns.exception.DNSException, OSError):
        return []


async def _check_dkim(domain: str, loop: asyncio.AbstractEventLoop) -> Finding:
    """Check common DKIM selectors. Returns PASS if any found, MEDIUM if none."""
    selectors = ["default", "google", "mail", "dkim"]
    for selector in selectors:
        try:
            answers = await loop.run_in_executor(
                None,
                lambda s=selector: dns.resolver.resolve(f"{s}._domainkey.{domain}", "TXT", lifetime=5),
            )
            for rdata in answers:
                if "v=DKIM1" in rdata.to_text():
                    return Finding(
                        id="dns_dkim_present",
                        severity=Severity.PASS,
                        title="DKIM record present",
                        description=f"DKIM record found for {domain} (selector: {selector}).",
                        affected=f"{selector}._domainkey.{domain}",
                        fix="No action needed.",
                        category=Category.DNS,
                    )
        except (dns.exception.DNSException, OSError):
            pass

    return Finding(
        id="dns_no_dkim",
        severity=Severity.MEDIUM,
        title="No DKIM record found on common selectors",
        description=(
            f"No DKIM record was found for {domain} under common selectors (default, google, mail, dkim). "
            "DKIM adds a cryptographic signature to outbound emails, helping receiving servers verify authenticity. "
            "Note: your provider may use a non-standard selector not checked here."
        ),
        affected=domain,
        fix="Enable DKIM signing in your email provider and publish the TXT record they provide at `<selector>._domainkey." + domain + "`.",
        category=Category.DNS,
    )


async def _check_caa(domain: str, loop: asyncio.AbstractEventLoop) -> Finding:
    """Check for CAA records. Returns PASS if present, MEDIUM if absent."""
    try:
        await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(domain, "CAA", lifetime=5)
        )
        return Finding(
            id="dns_caa_present",
            severity=Severity.PASS,
            title="CAA record present",
            description=f"CAA (Certification Authority Authorization) record found for {domain}, restricting which CAs can issue certificates.",
            affected=domain,
            fix="No action needed.",
            category=Category.DNS,
        )
    except (dns.exception.DNSException, OSError):
        return Finding(
            id="dns_no_caa",
            severity=Severity.MEDIUM,
            title="No CAA record — any CA can issue certificates",
            description=(
                f"{domain} has no CAA record. Without CAA, any trusted Certificate Authority can issue an SSL certificate "
                "for your domain, increasing the risk of mis-issuance or fraudulent certificates."
            ),
            affected=domain,
            fix="Add a CAA record to your DNS restricting issuance to your CA, e.g., `0 issue \"letsencrypt.org\"` or `0 issue \"digicert.com\"`.",
            category=Category.DNS,
        )


async def scan(host_url: str) -> list[Finding]:
    parsed = urlparse(host_url)
    domain = parsed.hostname or ""

    # Skip localhost and bare IPs — DNS checks don't apply
    if not domain or domain == "localhost" or _is_ip(domain):
        return [Finding(
            id="dns_skipped",
            severity=Severity.PASS,
            title="DNS checks skipped (localhost / IP)",
            description="Email security checks require a real domain name.",
            affected=domain or host_url,
            fix="No action needed for local targets.",
            category=Category.DNS,
        )]

    loop = asyncio.get_event_loop()
    findings: list[Finding] = []

    # --- SPF ---
    txt_records = await _resolve_txt(domain)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    if not spf_records:
        findings.append(Finding(
            id="dns_no_spf",
            severity=Severity.HIGH,
            title="No SPF record — email spoofing possible",
            description=(
                f"{domain} has no SPF (Sender Policy Framework) DNS record. "
                "Anyone can send emails that appear to come from your domain."
            ),
            affected=domain,
            fix=(
                "Add a TXT record to your DNS: `v=spf1 include:your-mail-provider.com ~all`. "
                "Replace `your-mail-provider.com` with your actual email provider."
            ),
            category=Category.DNS,
        ))
    else:
        findings.append(Finding(
            id="dns_spf_present",
            severity=Severity.PASS,
            title="SPF record present",
            description=f"SPF record found for {domain}: {spf_records[0][:80]}",
            affected=domain,
            fix="No action needed.",
            category=Category.DNS,
        ))

    # --- DMARC ---
    dmarc_records = await _resolve_txt(f"_dmarc.{domain}")
    dmarc_found = [r for r in dmarc_records if r.startswith("v=DMARC1")]

    if not dmarc_found:
        findings.append(Finding(
            id="dns_no_dmarc",
            severity=Severity.HIGH,
            title="No DMARC record — phishing risk",
            description=(
                f"{domain} has no DMARC policy. Without DMARC, spoofed emails from your "
                "domain may be delivered to recipients and you have no visibility into abuse."
            ),
            affected=f"_dmarc.{domain}",
            fix=(
                "Add a TXT record: `_dmarc.{domain}` → `v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}`. "
                "Start with `p=none` to monitor before enforcing."
            ),
            category=Category.DNS,
        ))
    else:
        findings.append(Finding(
            id="dns_dmarc_present",
            severity=Severity.PASS,
            title="DMARC record present",
            description=f"DMARC policy found for {domain}: {dmarc_found[0][:80]}",
            affected=f"_dmarc.{domain}",
            fix="No action needed.",
            category=Category.DNS,
        ))

    # --- DKIM and CAA (run concurrently) ---
    dkim_finding, caa_finding = await asyncio.gather(
        _check_dkim(domain, loop),
        _check_caa(domain, loop),
    )
    findings.append(dkim_finding)
    findings.append(caa_finding)

    return findings


def _is_ip(value: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value))
