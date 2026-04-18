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
    SUBDOMAINS = "subdomains"
    BREACH = "breach"


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


class GroupedFinding(BaseModel):
    id: str
    severity: Severity
    title: str
    description: str
    affected: list[str]
    fix: str
    category: Category
    count: int
    raw_ids: list[str]
    likely_false_positive: bool = False
    plain_english: str = ""
    business_impact: str = ""


class AnalyseRequest(BaseModel):
    target_url: str
    github_url: str | None = None
    findings: list[Finding]


class AnalysisResponse(BaseModel):
    target_url: str
    summary: str | None
    priority_actions: list[str]
    grouped_findings: list[GroupedFinding]
    pass_count: int
    ai_powered: bool
    raw_findings: list[Finding]
