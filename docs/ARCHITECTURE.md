# Architecture

## Overview

A web app that accepts a target URL (and optionally a GitHub repo URL) and returns a list of security vulnerabilities, displayed as severity-coded cards. Stateless: no database, no auth, no persistence — results are returned directly in the HTTP response.

---

## Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Frontend | Next.js 14 (App Router, TypeScript, Tailwind) | Fast to scaffold, great DX, easy deployment |
| Backend | FastAPI (Python 3.11+) | Best ecosystem for security tooling; async-native |
| HTTP client | `httpx` (async) | Drop-in async replacement for `requests` |
| Port scanning | Python `asyncio` + `socket` | No `nmap` binary or root privileges required |
| SSL checking | Python `ssl` stdlib + `httpx` | No extra deps, covers all needed checks |
| GitHub scanning | GitHub raw content URLs + REST API (unauthenticated) | Works for public repos without a token |

---
  /btw what could others work on right now in their branch without this                                                                           
                                                                                                                                                  
    - frontend/lib/api.ts — fetch wrapper for POST /api/scan                                                                                      
    - frontend/components/ScanForm.tsx — URL inputs + submit button     
    - frontend/components/LoadingState.tsx — spinner + cycling messages                                                                           
    - frontend/components/FindingCard.tsx — severity-coded card
    - frontend/components/ScanResults.tsx — summary bar + card list                                                                               
    - frontend/app/page.tsx — state machine (idle | scanning | results | error)
                                                                                                                                                  
    They can test with mock data until the backend is running. The API contract in docs/ARCHITECTURE.md has the exact response shape.

    ---
    TL;DR: Everyone can start now. Models are done, the API contract is in the docs, and the frontend is fully independent.
## Directory Structure

```
hei_florentxlundaisociety/
├── docs/
│   ├── ARCHITECTURE.md       ← this file
│   ├── CHECKS.md             ← all scan checks defined
│   └── WORK_PLAN.md          ← 7-hour sprint breakdown
├── backend/
│   ├── main.py               # FastAPI app: CORS, /api/scan endpoint
│   ├── models.py             # Pydantic request/response/finding models
│   ├── requirements.txt
│   └── scanner/
│       ├── __init__.py
│       ├── orchestrator.py   # Runs all scanners concurrently via asyncio.gather()
│       ├── secrets_scanner.py
│       ├── port_scanner.py
│       ├── ssl_checker.py
│       ├── admin_panel.py
│       └── github_scanner.py
├── frontend/
│   ├── app/
│   │   ├── page.tsx          # Main page: idle → scanning → results/error state machine
│   │   └── layout.tsx
│   ├── components/
│   │   ├── ScanForm.tsx      # URL inputs + Scan button
│   │   ├── FindingCard.tsx   # Severity badge + title + description + fix
│   │   ├── ScanResults.tsx   # Sorted findings + summary bar
│   │   └── LoadingState.tsx  # Spinner + cycling progress messages
│   ├── lib/
│   │   └── api.ts            # Typed fetch wrapper for POST /api/scan
│   └── types/
│       └── scan.ts           # TypeScript types (mirrors backend Pydantic models)
└── README.md
```

---

## API Contract

### `POST /api/scan`

**Request**
```json
{
  "url": "https://example.com",
  "github_url": "https://github.com/owner/repo"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `url` | string | Yes | Must start with `http://` or `https://` |
| `github_url` | string | No | Must be a valid `github.com/owner/repo` URL |

**Response (200 OK)**
```json
{
  "target_url": "https://example.com",
  "github_url": "https://github.com/owner/repo",
  "scan_duration_seconds": 8.3,
  "summary": {
    "CRITICAL": 2,
    "HIGH": 1,
    "MEDIUM": 1,
    "PASS": 4
  },
  "findings": [
    {
      "id": "secrets_env",
      "severity": "CRITICAL",
      "title": ".env file publicly accessible",
      "description": "The file /.env responded with HTTP 200 at https://example.com/.env. It may contain database credentials, API keys, or other secrets.",
      "affected": "https://example.com/.env",
      "fix": "Remove /.env from your web root and add it to .gitignore. Rotate any credentials it contains immediately.",
      "category": "secrets"
    }
  ]
}
```

**Error responses**

| Status | Condition |
|---|---|
| `422 Unprocessable Entity` | Missing or malformed URL |
| `400 Bad Request` | Host unreachable or not a valid web target |
| `504 Gateway Timeout` | Scan exceeded the 25-second budget |

---

## Finding Schema

Every finding — regardless of which scanner produced it — uses this uniform shape.

**Python (Pydantic) — `models.py`**
```python
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

class Finding(BaseModel):
    id: str           # snake_case, e.g. "port_6379_open"
    severity: Severity
    title: str        # plain English, max ~60 chars
    description: str  # what was found + the exact URL or port
    affected: str     # URL, "host:port", or "github.com/owner/repo/path"
    fix: str          # 1-2 sentence remediation
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
```

**TypeScript — `types/scan.ts`**
```typescript
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "PASS";
export type Category = "secrets" | "ports" | "ssl" | "admin" | "firewall" | "github";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  affected: string;
  fix: string;
  category: Category;
}

export interface ScanResponse {
  target_url: string;
  github_url: string | null;
  scan_duration_seconds: number;
  summary: Record<Severity, number>;
  findings: Finding[];
}

export interface ScanRequest {
  url: string;
  github_url?: string;
}
```

---

## Key Technical Decisions

### No nmap — use Python `asyncio` sockets
`nmap` requires a binary install and often root privileges. Instead, use `asyncio.open_connection()` with a 1.5s timeout per port, all ports scanned concurrently via `asyncio.gather()`. Covers all needed checks without any system dependency.

### `httpx` over `requests`
`httpx` is async-native and drop-in compatible. All HTTP probes (secrets, admin panels, GitHub) use a shared `httpx.AsyncClient` with a 5s timeout and redirect following disabled (to avoid masking 403s that redirect to login pages).

### Concurrency model
All scanner modules run concurrently inside a single `asyncio.gather()` call in `orchestrator.py`. Wall-clock scan time ≈ slowest individual check, not the sum. A global `asyncio.wait_for(..., timeout=25)` wraps the entire gather.

### Firewall inference (derived finding)
No separate network call. If the port scanner finds 3 or more dangerous ports open, the orchestrator emits an additional CRITICAL finding: "Firewall likely disabled." This is flagged as derived so the UI can note it.

### GitHub scanning — no token required for public repos
Workflow files are fetched via `https://raw.githubusercontent.com/{owner}/{repo}/HEAD/.github/workflows/{file}`. The repo file tree is listed via the GitHub Trees API (`/repos/{owner}/{repo}/git/trees/HEAD?recursive=1`) which is unauthenticated for public repos (rate limit: 60 req/hour per IP).

### Redirect handling for secret file probes
Follow redirects is disabled. A 301/302 to a login page should not count as "not found" — it is itself suspicious and flagged as MEDIUM ("path redirects, may be blocked by auth").

### No persistence, no auth
MVP is fully stateless. Results live only in the HTTP response. No database, no session, no user accounts.

---

## Environment Configuration

**Backend (`backend/.env`)**
```
ALLOWED_ORIGINS=http://localhost:3000
PORT=8000
```

**Frontend**
```
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## Running Locally

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```
