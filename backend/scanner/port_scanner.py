import asyncio

import httpx

from models import Finding, Severity, Category

PORTS = [
    (6379, "Redis", Severity.CRITICAL, "port_6379_open", "Redis database publicly accessible"),
    (2375, "Docker API", Severity.CRITICAL, "port_2375_open", "Docker API exposed (unauthenticated)"),
    (3306, "MySQL", Severity.CRITICAL, "port_3306_open", "MySQL database port open"),
    (5432, "PostgreSQL", Severity.CRITICAL, "port_5432_open", "PostgreSQL database port open"),
    (27017, "MongoDB", Severity.CRITICAL, "port_27017_open", "MongoDB port open"),
    (22, "SSH", Severity.HIGH, "port_22_open", "SSH port open to the internet"),
    (21, "FTP", Severity.HIGH, "port_21_open", "FTP port open (unencrypted)"),
    (3389, "RDP", Severity.HIGH, "port_3389_open", "Remote Desktop port open"),
]


async def scan(host: str) -> list[Finding]:
    results = await asyncio.gather(
        *[_check_port(host, port, service, severity, finding_id, title)
          for port, service, severity, finding_id, title in PORTS],
        return_exceptions=True,
    )

    findings = [r for r in results if isinstance(r, Finding)]

    if not findings:
        findings.append(Finding(
            id="ports_clean",
            severity=Severity.PASS,
            title="No dangerous ports open",
            description=f"None of the checked ports (22, 21, 3389, 3306, 5432, 27017, 6379, 2375) are open on {host}.",
            affected=host,
            fix="No action needed.",
            category=Category.PORTS,
        ))

    return findings


async def _check_port(
    host: str, port: int, service: str,
    severity: Severity, finding_id: str, title: str,
) -> Finding | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=1.5,
        )
        writer.close()
        await writer.wait_closed()
    except (ConnectionRefusedError, TimeoutError, OSError, asyncio.TimeoutError):
        return None

    # Port is open — run special probes
    description = f"Port {port} ({service}) is open on {host}."

    if port == 6379:
        extra = await _probe_redis(host)
        if extra:
            description += f" {extra}"

    if port == 2375:
        extra = await _probe_docker(host)
        if extra:
            description += f" {extra}"

    return Finding(
        id=finding_id,
        severity=severity,
        title=title,
        description=description,
        affected=f"{host}:{port}",
        fix=f"Restrict access to port {port} ({service}) using a firewall. Only allow trusted IPs.",
        category=Category.PORTS,
    )


async def _probe_redis(host: str) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 6379),
            timeout=2,
        )
        writer.write(b"*1\r\n$4\r\nPING\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(128), timeout=2)
        writer.close()
        await writer.wait_closed()
        response = data.decode(errors="ignore")
        if response.startswith("+PONG"):
            return "No authentication required — anyone can read and write your Redis data."
        if "-NOAUTH" in response or "-ERR" in response:
            return "Password required — verify it's strong."
    except Exception:
        pass
    return ""


async def _probe_docker(host: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(f"http://{host}:2375/info")
            if resp.status_code == 200:
                return "Unauthenticated Docker API — this is effectively remote code execution."
    except Exception:
        pass
    return ""
