# CLAUDE.md

Context for AI assistants (Claude, Gemini, etc.) working in this repo.

## What This Is

A security scanner web app. Users paste a URL (and optionally a GitHub repo URL) and get back a list of security findings ranked by severity: CRITICAL, HIGH, MEDIUM, or PASS. Fully stateless — no database, no auth, no persistence.

## Tech Stack

- **Backend:** FastAPI (Python), async-native, runs on port 8000
- **Frontend:** Next.js with TypeScript + Tailwind, runs on port 3000
- **HTTP probing:** `httpx` (async, redirects disabled by default for probes)
- **Port scanning:** `asyncio.open_connection()` — no nmap, no root needed
- **SSL checking:** Python `ssl` stdlib

## How to Run

```bash
# Backend
cd backend && source venv/bin/activate && uvicorn main:app --reload --port 8000

# Frontend
cd frontend && npm install && npm run dev
```

## Architecture

See `docs/ARCHITECTURE.md` for full details. The key ideas:

- **Single endpoint:** `POST /api/scan` accepts `{ url, github_url? }` and returns all findings at once.
- **Orchestrator pattern:** `scanner/orchestrator.py` runs all scanner modules concurrently via `asyncio.gather()` with a global timeout.
- **Scanner contract:** Every scanner module exports `async def scan(...) -> list[Finding]`. Each handles its own errors internally.
- **Finding model:** Uniform schema across all scanners — defined in `backend/models.py`. Fields: `id`, `severity`, `title`, `description`, `affected`, `fix`, `category`.
- **Frontend state machine:** `page.tsx` cycles through idle → scanning → results → error.

## Scan Categories

See `docs/CHECKS.md` for guidelines on what each scanner looks for. Categories: secrets, ssl, ports, admin, firewall (derived), github.

## Test Target

`http://testphp.vulnweb.com` is a legally sanctioned intentionally vulnerable site for manual testing (may be intermittently down).
