from enum import Enum
from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    PASS = "PASS"


class Category(str, Enum):
    SECRETS = "secrets"
    PORTS = "ports"
    SSL = "ssl"
    ADMIN = "admin"
    FIREWALL = "firewall"
    GITHUB = "github"
    HEADERS = "headers"
    DNS = "dns"
    COOKIES = "cookies"
    CORS = "cors"


class Finding(BaseModel):
    id: str
    severity: Severity
    title: str
    description: str
    affected: str
    fix: str
    category: Category


class ScanRequest(BaseModel):
    url: str
    github_url: str | None = None


class ScanResponse(BaseModel):
    target_url: str
    github_url: str | None
    scan_duration_seconds: float
    summary: dict[str, int]
    findings: list[Finding]
