import json
import re
from urllib.parse import urlparse

import httpx

from models import Finding, Severity, Category

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_DEPS = 30  # cap to stay within timeout


def _parse_npm_deps(content: str) -> list[tuple[str, str]]:
    """Return [(name, version)] from package.json, pinned versions only."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    deps: dict[str, str] = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    result = []
    for name, ver in deps.items():
        clean = ver.lstrip("^~>=<").split(" ")[0]
        if clean and clean[0].isdigit():
            result.append((name, clean))
    return result[:MAX_DEPS]


def _parse_python_deps(content: str) -> list[tuple[str, str]]:
    """Return [(name, version)] from requirements.txt, pinned (==) only."""
    result = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([A-Za-z0-9_.-]+)==([^\s;,]+)', line)
        if m:
            result.append((m.group(1).lower(), m.group(2)))
    return result[:MAX_DEPS]


async def _scan_dependencies(
    client: httpx.AsyncClient, owner: str, repo: str, tree_items: list[dict]
) -> list[Finding]:
    """Fetch package.json / requirements.txt and query OSV for known CVEs."""
    tree_paths = {item["path"] for item in tree_items}
    packages: list[tuple[str, str, str]] = []  # (name, version, ecosystem)

    async def fetch_raw(path: str) -> str | None:
        try:
            r = await client.get(f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}")
            return r.text if r.status_code == 200 else None
        except httpx.RequestError:
            return None

    # Prefer root-level manifests
    if "package.json" in tree_paths:
        content = await fetch_raw("package.json")
        if content:
            packages += [(n, v, "npm") for n, v in _parse_npm_deps(content)]

    if "requirements.txt" in tree_paths:
        content = await fetch_raw("requirements.txt")
        if content:
            packages += [(n, v, "PyPI") for n, v in _parse_python_deps(content)]

    if not packages:
        return []

    # Batch query OSV
    queries = [{"package": {"name": n, "ecosystem": eco}, "version": v} for n, v, eco in packages]
    try:
        osv_resp = await client.post(OSV_BATCH_URL, json={"queries": queries}, timeout=10)
        if osv_resp.status_code != 200:
            return []
        results = osv_resp.json().get("results", [])
    except (httpx.RequestError, json.JSONDecodeError):
        return []

    findings: list[Finding] = []
    for (name, version, ecosystem), result in zip(packages, results):
        vulns = result.get("vulns", [])
        if not vulns:
            continue
        vuln_ids = ", ".join(v["id"] for v in vulns[:5])
        count = len(vulns)
        findings.append(Finding(
            id=f"github_dep_vuln_{ecosystem.lower()}_{name.replace('-', '_')}",
            severity=Severity.HIGH,
            title=f"Vulnerable dependency: {name}@{version}",
            description=(
                f"{name} version {version} ({ecosystem}) has {count} known "
                f"{'vulnerability' if count == 1 else 'vulnerabilities'}: {vuln_ids}."
            ),
            affected=f"{owner}/{repo} — {name}@{version}",
            fix=f"Upgrade {name} to a patched version. Check https://osv.dev for details on {vuln_ids.split(',')[0].strip()}.",
            category=Category.GITHUB,
        ))

    return findings

# Regex patterns for hardcoded secrets
SECRET_PATTERNS = [
    ("github_secret_aws_key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL, "AWS access key hardcoded"),
    ("github_secret_gh_token", re.compile(r"ghp_[a-zA-Z0-9]{36}"), Severity.CRITICAL, "GitHub personal access token hardcoded"),
    ("github_secret_password", re.compile(r'(?i)password\s*[:=]\s*["\'][^"\']{8,}["\']'), Severity.CRITICAL, "Hardcoded password found"),
    ("github_secret_generic", re.compile(r'(?i)(secret|token|api_key|apikey)\s*[:=]\s*["\'][^"\']{8,}["\']'), Severity.HIGH, "Possible hardcoded secret"),
]

# Patterns for dangerous workflow commands
DANGEROUS_COMMANDS = [
    ("github_curl_pipe_bash", re.compile(r"curl\b.*\|\s*(bash|sh)"), Severity.HIGH, "Workflow downloads and executes remote code"),
    ("github_wget_pipe_bash", re.compile(r"wget\b.*\|\s*(bash|sh)"), Severity.HIGH, "Workflow downloads and executes remote code"),
]


SOURCE_EXTENSIONS = {".env", ".py", ".js", ".ts", ".json", ".config", ".yml", ".yaml"}
SOURCE_EXCLUDE_PREFIXES = (".github/workflows/",)
MAX_SOURCE_FILES = 15
MAX_FILE_BYTES = 50_000



async def _scan_source_files(
    client: httpx.AsyncClient, owner: str, repo: str, tree_items: list[dict]
) -> list[Finding]:
    candidates = [
        item for item in tree_items
        if item.get("type") == "blob"
        and any(item["path"].endswith(ext) for ext in SOURCE_EXTENSIONS)
        and not any(item["path"].startswith(p) for p in SOURCE_EXCLUDE_PREFIXES)
        and item.get("size", 0) < MAX_FILE_BYTES
    ][:MAX_SOURCE_FILES]

    findings: list[Finding] = []
    seen_ids: set[str] = set()

    for item in candidates:
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{item['path']}"
        try:
            resp = await client.get(raw_url)
        except httpx.RequestError:
            continue
        if resp.status_code != 200:
            continue

        for fid, pattern, severity, title in SECRET_PATTERNS:
            src_id = f"github_src_{fid}"
            if src_id not in seen_ids and pattern.search(resp.text):
                seen_ids.add(src_id)
                findings.append(Finding(
                    id=src_id,
                    severity=severity,
                    title=f"{title} (source file)",
                    description=f"A potential hardcoded secret was found in {owner}/{repo}/{item['path']}.",
                    affected=f"{owner}/{repo}/{item['path']}",
                    fix="Remove the secret from the source file immediately and rotate the exposed credential. Use environment variables or a secrets manager instead.",
                    category=Category.GITHUB,
                ))

    return findings


def _parse_github_url(github_url: str) -> tuple[str, str] | None:
    """Extract (owner, repo) from a GitHub URL."""
    parsed = urlparse(github_url)
    if parsed.hostname not in ("github.com", "www.github.com"):
        return None
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


async def scan(github_url: str) -> list[Finding]:
    parsed = _parse_github_url(github_url)
    if not parsed:
        return []

    owner, repo = parsed
    findings: list[Finding] = []

    async with httpx.AsyncClient(timeout=8, headers={"User-Agent": "security-scanner-mvp"}) as client:
        # Step 1: Get file tree to find workflow files
        tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
        try:
            tree_resp = await client.get(tree_url)
        except httpx.RequestError:
            return []

        if tree_resp.status_code == 404:
            return [Finding(
                id="github_repo_not_found",
                severity=Severity.MEDIUM,
                title="GitHub repository not found",
                description=f"Could not access {owner}/{repo}. The repo may be private or the URL incorrect.",
                affected=github_url,
                fix="Ensure the repository URL is correct and the repo is public.",
                category=Category.GITHUB,
            )]

        if tree_resp.status_code != 200:
            return []

        tree_data = tree_resp.json()
        tree_items = tree_data.get("tree", [])
        tree_paths = [item["path"] for item in tree_items]

        workflow_paths = [
            p for p in tree_paths
            if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))
        ]

        if not workflow_paths:
            findings.append(Finding(
                id="github_no_workflows",
                severity=Severity.PASS,
                title="No CI/CD workflows found",
                description=f"No workflow files found in {owner}/{repo}/.github/workflows/.",
                affected=github_url,
                fix="No action needed.",
                category=Category.GITHUB,
            ))
        # Step 2: Fetch and scan each workflow file
        seen_ids: set[str] = set()
        for path in workflow_paths:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}"
            try:
                raw_resp = await client.get(raw_url)
            except httpx.RequestError:
                continue

            if raw_resp.status_code != 200:
                continue

            content = raw_resp.text
            file_ref = f"{owner}/{repo}/{path}"

            # Check dangerous commands
            for finding_id, pattern, severity, title in DANGEROUS_COMMANDS:
                if finding_id not in seen_ids and pattern.search(content):
                    seen_ids.add(finding_id)
                    findings.append(Finding(
                        id=finding_id,
                        severity=severity,
                        title=title,
                        description=(
                            f"A workflow in {file_ref} runs a command that downloads and pipes "
                            "content directly into a shell. This executes arbitrary remote code during CI/CD."
                        ),
                        affected=file_ref,
                        fix="Pin your workflow dependencies to specific commit SHAs. Avoid `curl | bash` patterns — download, verify checksum, then execute.",
                        category=Category.GITHUB,
                    ))

            # Check hardcoded secrets
            for finding_id, pattern, severity, title in SECRET_PATTERNS:
                if finding_id not in seen_ids and pattern.search(content):
                    seen_ids.add(finding_id)
                    findings.append(Finding(
                        id=finding_id,
                        severity=severity,
                        title=title,
                        description=f"A potential hardcoded secret was found in {file_ref}.",
                        affected=file_ref,
                        fix="Remove the secret from code immediately. Use GitHub Actions secrets (`${{ secrets.MY_SECRET }}`) instead. Rotate the exposed credential.",
                        category=Category.GITHUB,
                    ))

        # Step 3: Scan source files for hardcoded secrets
        src_findings = await _scan_source_files(client, owner, repo, tree_items)
        findings.extend(src_findings)

        # Step 4: Check dependencies for known CVEs via OSV
        dep_findings = await _scan_dependencies(client, owner, repo, tree_items)
        findings.extend(dep_findings)

    if not findings:
        findings.append(Finding(
            id="github_workflows_clean",
            severity=Severity.PASS,
            title="No secrets or dangerous commands in workflows",
            description=f"Scanned {len(workflow_paths)} workflow file(s) in {owner}/{repo} — no issues found.",
            affected=github_url,
            fix="No action needed.",
            category=Category.GITHUB,
        ))

    return findings
