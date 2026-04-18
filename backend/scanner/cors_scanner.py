import asyncio

import httpx

from models import Finding, Severity, Category

EVIL_ORIGIN = "https://evil.example.com"
NULL_ORIGIN = "null"


async def _probe(client: httpx.AsyncClient, url: str, origin: str) -> Finding | None:
    try:
        resp = await client.get(url, headers={"Origin": origin})
    except httpx.RequestError:
        return None

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

    if not acao:
        return None

    if acao == origin and acac:
        return Finding(
            id=f"cors_reflect_credentials_{origin.replace('https://', '').replace(':', '_')}",
            severity=Severity.CRITICAL,
            title="CORS reflects arbitrary origin with credentials",
            description=(
                f"The server reflects the Origin `{origin}` in Access-Control-Allow-Origin "
                "AND sets Access-Control-Allow-Credentials: true. Any website can make "
                "authenticated cross-origin requests on behalf of your users, enabling "
                "account takeover and data theft."
            ),
            affected=url,
            fix="Never reflect arbitrary origins. Maintain an explicit allowlist of trusted origins and validate against it. Never combine `Access-Control-Allow-Credentials: true` with a dynamically reflected or wildcard origin.",
            category=Category.CORS,
        )

    if acao == origin:
        return Finding(
            id=f"cors_reflect_origin_{origin.replace('https://', '').replace(':', '_')}",
            severity=Severity.HIGH,
            title="CORS reflects arbitrary origin",
            description=(
                f"The server reflects `{origin}` in Access-Control-Allow-Origin for any requesting origin. "
                "Malicious websites can read responses from your API, potentially leaking user data from unauthenticated endpoints."
            ),
            affected=url,
            fix="Use an explicit allowlist of trusted origins instead of reflecting the request Origin header.",
            category=Category.CORS,
        )

    if acao == "*" and acac:
        return Finding(
            id="cors_wildcard_with_credentials",
            severity=Severity.HIGH,
            title="CORS wildcard with credentials flag set",
            description=(
                "The server sends `Access-Control-Allow-Origin: *` alongside `Access-Control-Allow-Credentials: true`. "
                "Browsers block this combination, but it signals broken CORS logic that may be exploitable in edge cases."
            ),
            affected=url,
            fix="Remove `Access-Control-Allow-Credentials: true` when using a wildcard origin, or switch to an explicit origin allowlist.",
            category=Category.CORS,
        )

    if acao == "*":
        return Finding(
            id="cors_wildcard_origin",
            severity=Severity.MEDIUM,
            title="CORS wildcard allows any origin",
            description=(
                "Access-Control-Allow-Origin is set to `*`, allowing any website to read responses from this endpoint. "
                "This is acceptable for fully public APIs but should not be used for endpoints that return user-specific data."
            ),
            affected=url,
            fix="If this endpoint returns user-specific data, restrict CORS to trusted origins. For truly public data, a wildcard is acceptable.",
            category=Category.CORS,
        )

    return None


async def scan(host_url: str) -> list[Finding]:
    findings: list[Finding] = []

    try:
        async with httpx.AsyncClient(follow_redirects=True, max_redirects=3, timeout=5) as client:
            evil_finding, null_finding = await asyncio.gather(
                _probe(client, host_url, EVIL_ORIGIN),
                _probe(client, host_url, NULL_ORIGIN),
            )
    except httpx.RequestError:
        return []

    # Deduplicate: if both probes return a finding, prefer the higher-severity one
    seen_ids: set[str] = set()
    for finding in [evil_finding, null_finding]:
        if finding and finding.id not in seen_ids:
            # Avoid duplicate wildcard findings from both probes
            if finding.id in ("cors_wildcard_origin", "cors_wildcard_with_credentials"):
                seen_ids.add(finding.id)
            findings.append(finding)

    if not findings:
        findings.append(Finding(
            id="cors_no_issues",
            severity=Severity.PASS,
            title="CORS policy looks safe",
            description="The server did not reflect arbitrary origins or use insecure wildcard CORS with credentials.",
            affected=host_url,
            fix="No action needed.",
            category=Category.CORS,
        ))

    return findings
