import { ScanRequest, ScanResponse } from "@/types/scan";

// Set NEXT_PUBLIC_API_URL in .env.local to point at the real backend.
// Falls back to mock data during frontend-only development.
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "";

export async function runScan(request: ScanRequest): Promise<ScanResponse> {
  if (!API_URL) {
    return getMockResponse(request.url, request.github_url);
  }

  const res = await fetch(`${API_URL}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });

  if (!res.ok) {
    let message = `Server error (${res.status})`;
    try {
      const body = await res.json();
      message = body.detail ?? message;
    } catch {
      // use default message
    }
    throw new Error(message);
  }

  return res.json();
}

// ---------------------------------------------------------------------------
// Mock — used when NEXT_PUBLIC_API_URL is not set
// ---------------------------------------------------------------------------

function getMockResponse(url: string, githubUrl?: string): Promise<ScanResponse> {
  return new Promise((resolve) =>
    setTimeout(
      () =>
        resolve({
          target_url: url,
          github_url: githubUrl ?? null,
          scan_duration_seconds: 4.2,
          summary: { CRITICAL: 3, HIGH: 2, MEDIUM: 1, PASS: 4 },
          findings: [
            {
              id: "secrets_env",
              severity: "CRITICAL",
              title: ".env file publicly accessible",
              description: `The file /.env responded with HTTP 200 at ${url}/.env. It likely contains database credentials, API keys, or other secrets.`,
              affected: `${url}/.env`,
              fix: "Remove /.env from your web root. Add it to .gitignore and rotate any credentials it contains immediately.",
              category: "secrets",
            },
            {
              id: "secrets_git_config",
              severity: "CRITICAL",
              title: "Git repository exposed",
              description: `/.git/config is publicly accessible at ${url}/.git/config. Attackers can reconstruct your source code.`,
              affected: `${url}/.git/config`,
              fix: "Block access to /.git in your web server config. For nginx: `location ~ /\\.git { deny all; }`",
              category: "secrets",
            },
            {
              id: "port_6379_open",
              severity: "CRITICAL",
              title: "Redis database wide open — no password",
              description: "Port 6379 is reachable and responded to PING with PONG. Anyone on the internet can read and write to your Redis instance.",
              affected: `${new URL(url).hostname}:6379`,
              fix: "Set requirepass in redis.conf and bind Redis to 127.0.0.1. Never expose Redis to the public internet.",
              category: "ports",
            },
            {
              id: "admin_panel_phpmyadmin",
              severity: "HIGH",
              title: "phpMyAdmin exposed",
              description: `/phpmyadmin returned HTTP 200. Your database management UI is publicly accessible.`,
              affected: `${url}/phpmyadmin`,
              fix: "Restrict access to phpMyAdmin by IP address, or move it behind a VPN.",
              category: "admin",
            },
            {
              id: "port_22_open",
              severity: "HIGH",
              title: "SSH port open to the internet",
              description: "Port 22 is reachable. Brute-force and credential-stuffing attacks are common against public SSH.",
              affected: `${new URL(url).hostname}:22`,
              fix: "Restrict SSH to specific IP ranges, disable password auth, and use key-based authentication only.",
              category: "ports",
            },
            {
              id: "ssl_no_redirect",
              severity: "MEDIUM",
              title: "HTTP does not redirect to HTTPS",
              description: "Visiting the site over HTTP does not redirect to HTTPS. Users on HTTP get no encryption.",
              affected: url.replace("https://", "http://"),
              fix: "Add a 301 redirect from HTTP to HTTPS in your web server config.",
              category: "ssl",
            },
            {
              id: "firewall_disabled",
              severity: "CRITICAL",
              title: "Firewall likely disabled",
              description: "3 or more dangerous ports are reachable from the internet. This strongly suggests no firewall is in place.",
              affected: `${new URL(url).hostname}`,
              fix: "Enable a firewall (e.g. ufw: `ufw enable`). Allow only ports 80, 443, and any others explicitly needed.",
              category: "firewall",
            },
            {
              id: "secrets_clean_htpasswd",
              severity: "PASS",
              title: ".htpasswd not exposed",
              description: "/.htpasswd returned 404 — credentials file is not publicly accessible.",
              affected: `${url}/.htpasswd`,
              fix: "",
              category: "secrets",
            },
            {
              id: "ssl_valid",
              severity: "PASS",
              title: "SSL certificate valid",
              description: "HTTPS is enabled and the certificate is valid.",
              affected: url,
              fix: "",
              category: "ssl",
            },
            {
              id: "port_3389_closed",
              severity: "PASS",
              title: "Remote Desktop port closed",
              description: "Port 3389 (RDP) is not reachable from the internet.",
              affected: `${new URL(url).hostname}:3389`,
              fix: "",
              category: "ports",
            },
          ],
        }),
      2500
    )
  );
}
