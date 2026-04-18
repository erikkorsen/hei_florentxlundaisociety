import asyncio

import httpx

from models import Finding, Severity, Category

PORTS = [
    (6379, "Redis", Severity.CRITICAL, "port_6379_open", "Redis database publicly accessible"),
    (2375, "Docker API", Severity.CRITICAL, "port_2375_open", "Docker API exposed (unauthenticated)"),
    (3306, "MySQL", Severity.CRITICAL, "port_3306_open", "MySQL database port open"),
    (5432, "PostgreSQL", Severity.CRITICAL, "port_5432_open", "PostgreSQL database port open"),
    (27017, "MongoDB", Severity.CRITICAL, "port_27017_open", "MongoDB port open"),
    (9200, "Elasticsearch", Severity.CRITICAL, "port_9200_open", "Elasticsearch port open"),
    (22, "SSH", Severity.HIGH, "port_22_open", "SSH port open to the internet"),
    (21, "FTP", Severity.HIGH, "port_21_open", "FTP port open (unencrypted)"),
    (3389, "RDP", Severity.HIGH, "port_3389_open", "Remote Desktop port open"),
    (11211, "Memcached", Severity.HIGH, "port_11211_open", "Memcached port open"),
    (5672, "RabbitMQ", Severity.HIGH, "port_5672_open", "RabbitMQ message broker open"),
    (9090, "Prometheus", Severity.HIGH, "port_9090_open", "Prometheus metrics endpoint open"),
    (8080, "HTTP Proxy", Severity.MEDIUM, "port_8080_open", "HTTP alternate/proxy port open"),
    (8443, "HTTPS Alt", Severity.MEDIUM, "port_8443_open", "HTTPS alternate port open"),
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

    # Port is open — run special probes and banner grab
    description = f"Port {port} ({service}) is open on {host}."

    if port == 6379:
        extra = await _probe_redis(host)
        if extra:
            description += f" {extra}"
    elif port == 2375:
        extra = await _probe_docker(host)
        if extra:
            description += f" {extra}"
    elif port == 9200:
        extra = await _probe_elasticsearch(host)
        if extra:
            description += f" {extra}"
    else:
        banner = await _grab_banner(host, port)
        if banner:
            description += f" Banner: {banner}"

    return Finding(
        id=finding_id,
        severity=severity,
        title=title,
        description=description,
        affected=f"{host}:{port}",
        fix=f"Block port {port} ({service}) from public access. On Linux: `sudo ufw deny {port}/tcp`. On AWS: remove port {port} from your security group inbound rules. If the service needs remote access, restrict to specific IPs only.",
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


async def _grab_banner(host: str, port: int) -> str:
    """Try to read a service banner from an open port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=2,
        )
        # Some services send a banner immediately; others need a nudge
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=2)
        except asyncio.TimeoutError:
            # Try sending a basic HTTP request for HTTP-like ports
            if port in (8080, 8443, 9090):
                writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(256), timeout=2)
                except asyncio.TimeoutError:
                    data = b""
            else:
                data = b""
        writer.close()
        await writer.wait_closed()
        banner = data.decode(errors="ignore").strip()
        # Clean up — take just the first line, cap length
        first_line = banner.split("\n")[0].strip()[:100]
        if first_line and any(c.isalpha() for c in first_line):
            return first_line
    except Exception:
        pass
    return ""


async def _probe_elasticsearch(host: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(f"http://{host}:9200/")
            if resp.status_code == 200:
                data = resp.json()
                cluster = data.get("cluster_name", "unknown")
                version = data.get("version", {}).get("number", "unknown")
                return f"Unauthenticated Elasticsearch cluster '{cluster}' (v{version}). Anyone can read, modify, or delete all indices."
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
