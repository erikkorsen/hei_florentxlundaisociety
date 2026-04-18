"""
Meridian demo server — clean corporate site that passes most scanner checks.
Runs on port 8082. No mock TCP services on database ports.
For local demo only.
"""
import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

if sys.platform == "win32" and sys.version_info < (3, 14):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

LANDING_HTML = b"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Meridian - Enterprise Data Intelligence</title>
<style>
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #fff; color: #111; }
  a { text-decoration: none; color: inherit; }

  /* Nav */
  nav { display: flex; align-items: center; justify-content: space-between; padding: 0 48px; height: 60px; border-bottom: 1px solid #e5e7eb; background: #fff; }
  .logo { font-size: 18px; font-weight: 800; color: #111; }
  .logo span { color: #2563eb; }
  .nav-links a { font-size: 14px; color: #6b7280; margin-left: 28px; font-weight: 500; }
  .nav-links a:hover { color: #111; }
  .nav-cta { background: #111; color: #fff !important; padding: 8px 18px; border-radius: 6px; font-size: 14px; font-weight: 600; margin-left: 28px; }

  /* Hero */
  .hero { padding: 80px 48px; background: #f9fafb; border-bottom: 1px solid #e5e7eb; }
  .hero-inner { max-width: 640px; }
  .hero h1 { font-size: 44px; font-weight: 900; line-height: 1.1; letter-spacing: -0.03em; margin: 0 0 20px; }
  .hero h1 span { color: #2563eb; }
  .hero p { font-size: 18px; color: #4b5563; line-height: 1.7; margin: 0 0 32px; max-width: 500px; }
  .hero-btns { display: flex; gap: 12px; align-items: center; }
  .btn-primary { background: #2563eb; color: #fff; padding: 12px 26px; border-radius: 8px; font-size: 15px; font-weight: 700; }
  .btn-secondary { color: #4b5563; font-size: 15px; font-weight: 500; padding: 12px 16px; }
  .trust { margin-top: 28px; font-size: 13px; color: #9ca3af; }
  .trust strong { color: #6b7280; }

  /* Logos */
  .logos { padding: 32px 48px; border-bottom: 1px solid #e5e7eb; text-align: center; }
  .logos p { font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; color: #9ca3af; font-weight: 600; margin-bottom: 20px; }
  .logos-row { display: flex; gap: 40px; justify-content: center; flex-wrap: wrap; }
  .logos-row span { font-size: 16px; font-weight: 800; color: #d1d5db; }

  /* Stats */
  .stats { display: flex; border-bottom: 1px solid #e5e7eb; }
  .stat { flex: 1; padding: 32px 48px; border-right: 1px solid #e5e7eb; }
  .stat:last-child { border-right: none; }
  .stat-n { font-size: 36px; font-weight: 900; color: #111; }
  .stat-n span { color: #2563eb; }
  .stat-d { font-size: 13px; color: #6b7280; margin-top: 4px; }

  /* Features */
  .features { padding: 72px 48px; background: #fff; }
  .features h2 { font-size: 32px; font-weight: 900; letter-spacing: -0.02em; margin: 0 0 8px; }
  .features .sub { font-size: 16px; color: #6b7280; margin: 0 0 48px; }
  .feat-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; max-width: 1000px; }
  .feat { border: 1px solid #e5e7eb; border-radius: 12px; padding: 28px; }
  .feat h3 { font-size: 15px; font-weight: 700; margin: 0 0 8px; }
  .feat p { font-size: 14px; color: #6b7280; line-height: 1.6; margin: 0; }

  /* Testimonials */
  .testimonials { background: #f9fafb; border-top: 1px solid #e5e7eb; border-bottom: 1px solid #e5e7eb; padding: 72px 48px; }
  .testimonials h2 { font-size: 32px; font-weight: 900; letter-spacing: -0.02em; margin: 0 0 8px; }
  .testimonials .sub { font-size: 16px; color: #6b7280; margin: 0 0 48px; }
  .testi-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; max-width: 1000px; }
  .testi { background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 28px; }
  .testi q { font-size: 14px; color: #374151; line-height: 1.7; display: block; margin-bottom: 20px; font-style: italic; }
  .testi-name { font-size: 13px; font-weight: 700; color: #111; }
  .testi-role { font-size: 12px; color: #9ca3af; }

  /* CTA */
  .cta { background: #111; padding: 72px 48px; text-align: center; }
  .cta h2 { font-size: 36px; font-weight: 900; color: #fff; margin: 0 0 12px; letter-spacing: -0.02em; }
  .cta p { font-size: 16px; color: #9ca3af; margin: 0 0 32px; }
  .btn-white { background: #fff; color: #111; padding: 13px 32px; border-radius: 8px; font-size: 15px; font-weight: 700; display: inline-block; }

  /* Footer */
  footer { padding: 32px 48px; border-top: 1px solid #e5e7eb; display: flex; justify-content: space-between; align-items: center; }
  footer p { font-size: 13px; color: #9ca3af; margin: 0; }
  .footer-links a { font-size: 13px; color: #9ca3af; margin-left: 20px; }
</style>
</head>
<body>

<nav>
  <div class="logo">meridian<span>.</span></div>
  <div class="nav-links">
    <a href="/">Product</a>
    <a href="/">Solutions</a>
    <a href="/">Customers</a>
    <a href="/">Pricing</a>
    <a href="/" class="nav-cta">Request demo</a>
  </div>
</nav>

<div class="hero">
  <div class="hero-inner">
    <h1>Data intelligence that<br><span>scales with you</span></h1>
    <p>Meridian unifies your warehouse, BI layer, and AI forecasting into one governed platform. Built for teams that can&rsquo;t afford to be wrong.</p>
    <div class="hero-btns">
      <a href="/" class="btn-primary">Request a demo</a>
      <a href="/" class="btn-secondary">See how it works &rarr;</a>
    </div>
    <div class="trust"><strong>SOC 2 Type II</strong> &nbsp;&middot;&nbsp; <strong>GDPR compliant</strong> &nbsp;&middot;&nbsp; <strong>ISO 27001</strong></div>
  </div>
</div>

<div class="logos">
  <p>Trusted by data teams at</p>
  <div class="logos-row">
    <span>Accenture</span>
    <span>Unilever</span>
    <span>Siemens</span>
    <span>ING Bank</span>
    <span>Maersk</span>
    <span>Volvo Group</span>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="stat-n"><span>2.4</span>B+</div><div class="stat-d">Events processed daily</div></div>
  <div class="stat"><div class="stat-n"><span>99.99</span>%</div><div class="stat-d">Uptime over 12 months</div></div>
  <div class="stat"><div class="stat-n"><span>340</span>+</div><div class="stat-d">Enterprise customers</div></div>
  <div class="stat"><div class="stat-n">&lt;<span>1</span>s</div><div class="stat-d">Average query latency</div></div>
</div>

<div class="features">
  <h2>Everything your data team needs</h2>
  <p class="sub">From ingestion to insight &mdash; governed, auditable, and secure by default.</p>
  <div class="feat-grid">
    <div class="feat"><h3>Real-time pipelines</h3><p>Sub-second data freshness with streaming ingest from Kafka, Kinesis, or any webhook source.</p></div>
    <div class="feat"><h3>Unified data catalog</h3><p>Discover, document, and govern every dataset across cloud, on-prem, and hybrid environments.</p></div>
    <div class="feat"><h3>AI-powered forecasting</h3><p>Predictive models trained on your historical data, refreshed nightly and deployed instantly.</p></div>
    <div class="feat"><h3>Fine-grained access control</h3><p>Row- and column-level security with SSO, SCIM provisioning, and full audit logs.</p></div>
    <div class="feat"><h3>Customer 360</h3><p>Stitch behavioural, transactional, and CRM data into a single identity graph automatically.</p></div>
    <div class="feat"><h3>500+ connectors</h3><p>Salesforce, HubSpot, Stripe, Snowflake, BigQuery &mdash; connect in minutes with pre-built connectors.</p></div>
  </div>
</div>

<div class="testimonials">
  <h2>Loved by data teams worldwide</h2>
  <p class="sub">Don&rsquo;t take our word for it.</p>
  <div class="testi-grid">
    <div class="testi">
      <q>We consolidated 14 BI tools into Meridian in eight weeks. Our time-to-insight went from three days to under an hour.</q>
      <div class="testi-name">Sara Kowalski</div>
      <div class="testi-role">Head of Data, ING Bank</div>
    </div>
    <div class="testi">
      <q>Meridian&rsquo;s forecasting models are more accurate than anything our internal team built. It&rsquo;s our single source of truth.</q>
      <div class="testi-name">Marcus Hein</div>
      <div class="testi-role">VP Engineering, Siemens</div>
    </div>
    <div class="testi">
      <q>The access control is genuinely enterprise-grade. We passed our ISO 27001 audit with no findings related to data access.</q>
      <div class="testi-name">Anika Lund</div>
      <div class="testi-role">CISO, Maersk</div>
    </div>
  </div>
</div>

<div class="cta">
  <h2>Ready to modernise your data stack?</h2>
  <p>Talk to a solutions engineer. No commitment, no pressure.</p>
  <a href="/" class="btn-white">Book a 30-minute demo</a>
</div>

<footer>
  <p>&copy; 2025 Meridian Data GmbH. All rights reserved.</p>
  <div class="footer-links">
    <a href="/">Privacy</a>
    <a href="/">Terms</a>
    <a href="/">Security</a>
    <a href="/">Trust Centre</a>
  </div>
</footer>

</body>
</html>"""

SECURITY_TXT = b"""Contact: security@meridian.example
Expires: 2026-01-01T00:00:00.000Z
Preferred-Languages: en
Policy: https://meridian.example/security-policy
"""

ROBOTS_TXT = b"""User-agent: *
Disallow:
"""

BLOCKED_PATHS = {
    "/.env", "/.env.local", "/.env.production", "/.git/config",
    "/wp-config.php", "/.htpasswd", "/backup.sql", "/config/database.yml",
    "/.DS_Store", "/phpinfo.php", "/server-status", "/actuator/env",
    "/actuator/health", "/swagger.json", "/openapi.json", "/api-docs",
    "/admin", "/wp-admin", "/wp-login.php", "/phpmyadmin", "/adminer.php",
    "/administrator", "/login", "/signin", "/cpanel", "/grafana",
    "/jenkins", "/kibana", "/webmail",
}

SECURE_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


class MeridianHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        pass

    def _send(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURE_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Set-Cookie", "session=s_mer_xyz789; Path=/; HttpOnly; Secure; SameSite=Strict")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in BLOCKED_PATHS:
            self._send(404, "text/plain", b"Not Found")
            return
        if self.path in ("/security.txt", "/.well-known/security.txt"):
            self._send(200, "text/plain", SECURITY_TXT)
            return
        if self.path == "/robots.txt":
            self._send(200, "text/plain", ROBOTS_TXT)
            return
        if self.path == "/":
            self._send(200, "text/html", LANDING_HTML)
            return
        self._send(404, "text/plain", b"Not Found")


def run_http_server():
    server = HTTPServer(("", 8082), MeridianHandler)
    server.serve_forever()


async def main():
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    http_thread.start()

    print("=" * 50)
    print("  MERIDIAN — clean corporate demo target")
    print("=" * 50)
    print("  http://localhost:8082")
    print("  Press Ctrl+C to stop.")
    print("=" * 50)

    stop_event = asyncio.Event()
    try:
        await stop_event.wait()
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down.")
