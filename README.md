# SecureCheck — AI-Powered Security Scanner for Vibe Coders



## Problem Statement

vibe coders are building and shipping real products without knowing what they are leaving to the public. This means they often miss things regarding safety, leaving secrets out.

Most vibe-coded projects skip the basics. `.env` files get committed to GitHub. Admin panels are left open to the internet. Databases listen on public ports with no authentication. SSL is misconfigured or missing entirely. These aren't rare edge cases, they're the default when security isn't front of mind.



## Solution

Palisade is a security scanner built specifically for developers who don't have a security background. You paste in your URL, press scan, and within 30 seconds you get a clear, prioritised list of security issues explained in plain English.

i.e: *"Your Redis database is open to the internet with no password. Anyone can read and delete your data. Here's how to fix it."*

The AI layer (powered by Claude) acts as a translator between raw scanner output and actionable human language. It understands the context of your site — is it a small startup, a large enterprise, a dev environment? and adjusts the severity and explanation accordingly. It also filters out false positives so you're not chasing ghosts.

---

## Technical Approach

The scanner runs a battery of checks concurrently against the target URL, collects all findings, and passes them through an AI analysis layer that groups, prioritises, and explains them.

```
User inputs URL
      │
      ▼
 POST /api/scan  ──►  11 scanners run in parallel (asyncio.gather)
                              │
                              ▼
                     Raw findings collected
                              │
                              ▼
 POST /api/analyse ──►  AI layer (Claude Haiku)
                         - Groups findings by category
                         - Rewrites titles & descriptions in plain English
                         - Flags likely false positives
                         - Generates 3 priority actions
                              │
                              ▼
                     Results rendered in UI
```

All scans are **stateless** — no database, no user accounts, no data stored. Every scan is fresh and isolated.

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.12+, FastAPI, asyncio |
| **HTTP probing** | httpx (async) |
| **Port scanning** | asyncio TCP connections (no nmap, no root required) |
| **SSL checking** | Python `ssl` stdlib |
| **DNS lookups** | dnspython |
| **AI layer** | Anthropic API (Claude Haiku) |
| **Frontend** | Next.js 16, TypeScript, Tailwind CSS |
| **Deployment** | Runs locally; backend on port 8000, frontend on port 3000 |

---

## What We Scan

The scanner runs 11 independent checks in parallel:

| Check | What it looks for |
|---|---|
| **Secrets** | Exposed `.env`, `.git/config`, `wp-config.php`, SQL backups, API docs, Spring Boot actuators |
| **Admin panels** | Publicly accessible `/admin`, `/adminer.php`, `/phpmyadmin`, `/grafana`, `/jenkins`, and 10 more |
| **Open ports** | Redis, Docker API, MySQL, PostgreSQL, MongoDB, Elasticsearch, SSH, FTP, RDP, and more — all without auth |
| **SSL/TLS** | HTTPS availability, certificate expiry, deprecated TLS 1.0/1.1, HTTP→HTTPS redirect |
| **Security headers** | Missing HSTS, X-Frame-Options, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Cookies** | Missing `HttpOnly`, `Secure`, and `SameSite` flags on session cookies |
| **CORS** | Misconfigured cross-origin policies that allow arbitrary origins or credentials leakage |
| **DNS & Email** | Missing SPF, DMARC, and DKIM records that enable email spoofing from your domain |
| **Subdomains** | Active subdomains and dangling DNS records vulnerable to subdomain takeover |
| **Data breaches** | Domain checked against the Have I Been Pwned database |
| **GitHub** | Hardcoded secrets, vulnerable dependencies (via OSV), and dangerous CI/CD patterns in workflows |

---

## AI Layer

After scanning, all findings are sent to Claude Haiku, which:

- **Rewrites** technical jargon into plain English tailored to the site's context
- **Groups** related findings by category to avoid overwhelming the user
- **Flags false positives** — e.g. a major company like Google may trigger generic scanner rules that don't represent real risk
- **Generates 3 priority actions** — the most important things to fix, in order
- **Assigns a risk grade** — from Low Risk to Critical Risk, with a coloured badge

This means a non-technical founder reads: *"3 of your session cookies don't have the HttpOnly flag. This means a malicious script on your page could steal login tokens. Add `HttpOnly` to your cookie settings — it's a one-line fix."* Not a CVE reference.

---

## How to Run

### Prerequisites
- Python 3.12+
- Node.js 18+
- An Anthropic API key (for AI analysis — scanning works without it)

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Add your API key (optional but recommended)
echo "ANTHROPIC_API_KEY=your_key_here" > .env

python run.py
```

Open [http://localhost:3000](http://localhost:3000) and paste any URL to scan.

### Demo targets (optional)

A local demo websites are included for testing:

```bash
# Vulnerable SaaS site — triggers findings across all categories
python demo_target/novadash.py      # http://localhost:8081



---

## Current Scope & How to Scale

This demo focuses on **external scanning** — you provide a URL and we probe it from the outside, the same way an attacker would. No credentials, no code access, no installation on the target.

The **GitHub scanner** already supports repo analysis: paste a GitHub URL alongside your site URL and we'll scan your workflows for hardcoded secrets and vulnerable dependencies.

Scaling further is straightforward:

- **Deeper repo scanning** — scan all source files for secrets, not just workflows
- **Authenticated scans** — provide a session cookie to scan behind login
- **CI/CD integration** — run as a GitHub Action on every pull request
- **Continuous monitoring** — schedule weekly scans and alert on regressions
- **Internal scanning** — run the backend inside a private network to scan internal services

The architecture (stateless FastAPI + asyncio scanner modules) is designed to make adding new checks trivial — each scanner is an independent `async def scan() -> list[Finding]` function.

---


Built by HEI at **Florent x Lunda i Society** 
