# Architecture

## System Design

This is a straightforward security scanning tool. The backend checks a website for security problems and provides the results instantly. It doesn't store any past scans, user information, or rely on a database.

## Data Flow

```
User enters URL
    → Frontend calls POST /api/scan
        → orchestrator.py runs all scanners concurrently (asyncio.gather)
            → secrets_scanner.scan(url)
            → ssl_checker.scan(url)
            → port_scanner.scan(hostname)
            → admin_panel.scan(url)
            → github_scanner.scan(github_url)  [if provided]
        → Collect all Finding objects, sort by severity, return as JSON
    → Frontend renders severity-coded cards
```

## API

**`POST /api/scan`** — the only endpoint that matters.

- Request: `{ url: string, github_url?: string }`
- Response: `{ target_url, github_url, scan_duration_seconds, summary, findings[] }`
- Each finding has: `id`, `severity`, `title`, `description`, `affected`, `fix`, `category`
- Error responses: 422 (bad input), 400 (unreachable host), 504 (timeout)

Health check at `GET /health`. Swagger UI at `GET /docs`.

## Scanner Pattern

Every scanner module follows the same contract:

- Exports `async def scan(url_or_host: str) -> list[Finding]`
- Handles its own errors — returns empty list or a PASS finding on failure, never crashes
- Uses `httpx.AsyncClient` for HTTP probes or `asyncio.open_connection` for ports
- All probes within a scanner run concurrently where possible

The orchestrator runs all scanners in parallel. Total scan time ≈ the slowest scanner, not the sum.

## Key Decisions

**No nmap** — Port scanning uses raw asyncio sockets. No binary dependencies, no root privileges.

**Redirects disabled for probes** — A 301/302 on a secret file path is suspicious (may be behind auth), not "clean." Flagged as MEDIUM.

**Firewall inference** — If multiple dangerous ports are open, the orchestrator adds a derived CRITICAL finding. No extra network call.

**GitHub scanning without auth** — Uses unauthenticated GitHub API. Works for public repos, rate-limited to 60 req/hour per IP.

**Stateless** — Results exist only in the HTTP response. Nothing is stored.

## Directory Structure

```
backend/
├── main.py                 # FastAPI app, CORS, endpoint
├── models.py               # Pydantic models (Finding, ScanRequest, ScanResponse)
└── scanner/
    ├── orchestrator.py      # Runs all scanners, builds response
    ├── secrets_scanner.py   # Exposed secret files
    ├── ssl_checker.py       # HTTPS, cert expiry, redirects
    ├── port_scanner.py      # Dangerous open ports
    ├── admin_panel.py       # Exposed admin/login pages
    └── github_scanner.py    # GitHub workflow analysis

frontend/
├── app/page.tsx             # State machine (idle/scanning/results/error)
├── components/              # ScanForm, FindingCard, ScanResults, LoadingState
├── lib/api.ts               # Fetch wrapper for /api/scan
└── types/scan.ts            # TypeScript interfaces
```

## Environment

Backend: `ALLOWED_ORIGINS` (default `http://localhost:3000`), `PORT` (default 8000)
Frontend: `NEXT_PUBLIC_API_URL` (default `http://localhost:8000`)
