"""
Meridian demo server — clean corporate site that passes most scanner checks.
Runs on port 8082 (HTTP). No mock TCP services on database ports.
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
<title>Meridian &mdash; Enterprise Data Intelligence</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#fff;color:#0f172a;line-height:1.6}
a{text-decoration:none}

/* NAV */
nav{display:flex;align-items:center;justify-content:space-between;padding:0 64px;height:64px;border-bottom:1px solid #f1f5f9;background:#fff;position:sticky;top:0;z-index:100}
.nav-logo{font-size:18px;font-weight:800;letter-spacing:-.5px;color:#0f172a}
.nav-logo em{font-style:normal;color:#2563eb}
.nav-links{display:flex;align-items:center;gap:32px}
.nav-links a{font-size:14px;color:#475569;font-weight:500}
.nav-links a:hover{color:#0f172a}
.nav-actions{display:flex;align-items:center;gap:12px}
.btn-ghost{font-size:14px;color:#475569;font-weight:500;padding:7px 16px}
.btn-dark{background:#0f172a;color:#fff;font-size:14px;font-weight:600;padding:8px 20px;border-radius:8px}
.btn-blue{background:#2563eb;color:#fff;font-size:14px;font-weight:600;padding:8px 20px;border-radius:8px}

/* HERO */
.hero{padding:80px 64px 0;max-width:1200px;margin:0 auto;display:grid;grid-template-columns:1fr 1fr;gap:64px;align-items:center;min-height:560px}
.hero-text .eyebrow{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#2563eb;margin-bottom:16px}
.hero-text h1{font-size:50px;font-weight:900;line-height:1.08;letter-spacing:-.03em;color:#0f172a;margin-bottom:20px}
.hero-text h1 span{color:#2563eb}
.hero-text p{font-size:17px;color:#475569;line-height:1.7;margin-bottom:32px;max-width:440px}
.hero-btns{display:flex;gap:12px;align-items:center;margin-bottom:40px}
.btn-hero{background:#2563eb;color:#fff;font-size:15px;font-weight:700;padding:13px 28px;border-radius:10px}
.btn-hero-ghost{font-size:15px;color:#334155;font-weight:500;padding:13px 20px;display:flex;align-items:center;gap:6px}
.hero-trust{display:flex;align-items:center;gap:10px;font-size:13px;color:#94a3b8}
.hero-trust span{color:#22c55e;font-size:18px}
.hero-visual{background:#f8fafc;border:1px solid #e2e8f0;border-radius:20px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.08)}
.dash-bar{background:#fff;border-bottom:1px solid #f1f5f9;padding:12px 20px;display:flex;align-items:center;gap:8px}
.dash-dot{width:10px;height:10px;border-radius:50%;background:#e2e8f0}
.dash-dot.r{background:#fca5a5}
.dash-dot.y{background:#fcd34d}
.dash-dot.g{background:#86efac}
.dash-url{background:#f1f5f9;border-radius:6px;padding:4px 14px;font-size:12px;color:#94a3b8;margin-left:8px;flex:1;max-width:200px}
.dash-body{padding:20px}
.dash-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.dash-title{font-size:14px;font-weight:700;color:#0f172a}
.dash-badge{background:#eff6ff;color:#2563eb;font-size:11px;font-weight:600;padding:3px 8px;border-radius:20px}
.dash-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}
.dash-stat{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:14px}
.dash-stat-val{font-size:22px;font-weight:800;color:#0f172a}
.dash-stat-val.up{color:#16a34a}
.dash-stat-label{font-size:11px;color:#94a3b8;margin-top:2px}
.dash-chart{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:16px}
.dash-chart-label{font-size:11px;color:#94a3b8;margin-bottom:12px}
.bars{display:flex;align-items:flex-end;gap:6px;height:70px}
.bar{background:#dbeafe;border-radius:4px 4px 0 0;flex:1;transition:.3s}
.bar.hi{background:#2563eb}
.dash-line{height:2px;background:#f1f5f9;margin:16px 0}
.dash-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid #f8fafc;font-size:12px}
.dash-row-name{color:#334155;font-weight:500}
.dash-row-val{color:#0f172a;font-weight:700}
.dash-row-change{color:#16a34a;font-size:11px}

/* LOGOS */
.logos{border-top:1px solid #f1f5f9;border-bottom:1px solid #f1f5f9;padding:36px 64px;text-align:center}
.logos-label{font-size:12px;text-transform:uppercase;letter-spacing:.1em;color:#94a3b8;font-weight:600;margin-bottom:24px}
.logos-row{display:flex;gap:48px;justify-content:center;align-items:center;flex-wrap:wrap}
.logos-row span{font-size:15px;font-weight:800;color:#cbd5e1;letter-spacing:-.5px}

/* STATS */
.stats{background:#0f172a;padding:48px 64px}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:32px;max-width:1000px;margin:0 auto;text-align:center}
.stat-num{font-size:40px;font-weight:900;color:#fff;margin-bottom:6px}
.stat-num span{color:#60a5fa}
.stat-desc{font-size:13px;color:#64748b}

/* FEATURES */
.features{padding:96px 64px;max-width:1200px;margin:0 auto}
.section-label{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#2563eb;margin-bottom:12px}
.section-title{font-size:36px;font-weight:900;letter-spacing:-.02em;color:#0f172a;margin-bottom:12px}
.section-sub{font-size:16px;color:#64748b;margin-bottom:60px;max-width:560px}
.feat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:24px}
.feat{border:1px solid #e2e8f0;border-radius:16px;padding:32px;transition:.2s}
.feat:hover{border-color:#bfdbfe;box-shadow:0 4px 24px rgba(37,99,235,.06)}
.feat-icon{width:40px;height:40px;background:#eff6ff;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:20px}
.feat h3{font-size:16px;font-weight:700;color:#0f172a;margin-bottom:8px}
.feat p{font-size:14px;color:#64748b;line-height:1.65}

/* TESTIMONIALS */
.testimonials{background:#f8fafc;border-top:1px solid #e2e8f0;border-bottom:1px solid #e2e8f0;padding:80px 64px}
.testimonials .section-title{text-align:center;margin:0 auto 16px}
.testimonials .section-sub{text-align:center;margin:0 auto 56px}
.testi-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:24px;max-width:1100px;margin:0 auto}
.testi{background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:32px}
.testi-quote{font-size:15px;color:#334155;line-height:1.7;margin-bottom:24px;font-style:italic}
.testi-author{display:flex;align-items:center;gap:12px}
.testi-avatar{width:38px;height:38px;border-radius:50%;background:#dbeafe;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#2563eb}
.testi-name{font-size:13px;font-weight:700;color:#0f172a}
.testi-role{font-size:12px;color:#94a3b8}

/* CTA */
.cta-band{background:linear-gradient(135deg,#1e40af,#2563eb);padding:80px 64px;text-align:center}
.cta-band h2{font-size:38px;font-weight:900;color:#fff;margin-bottom:14px;letter-spacing:-.02em}
.cta-band p{font-size:16px;color:#bfdbfe;margin-bottom:36px}
.cta-band-btns{display:flex;gap:12px;justify-content:center}
.btn-white{background:#fff;color:#1e40af;font-size:15px;font-weight:700;padding:13px 32px;border-radius:10px}
.btn-white-ghost{border:1px solid rgba(255,255,255,.3);color:#fff;font-size:15px;font-weight:500;padding:13px 28px;border-radius:10px}

/* FOOTER */
footer{padding:48px 64px 32px;border-top:1px solid #f1f5f9}
.footer-top{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:48px;margin-bottom:48px}
.footer-brand .nav-logo{font-size:18px;margin-bottom:12px;display:block}
.footer-brand p{font-size:13px;color:#94a3b8;max-width:260px;line-height:1.6}
.footer-col h4{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;margin-bottom:16px}
.footer-col a{display:block;font-size:14px;color:#475569;margin-bottom:10px}
.footer-col a:hover{color:#0f172a}
.footer-bottom{display:flex;justify-content:space-between;align-items:center;border-top:1px solid #f1f5f9;padding-top:24px}
.footer-bottom p{font-size:13px;color:#94a3b8}
.footer-bottom-links{display:flex;gap:20px}
.footer-bottom-links a{font-size:13px;color:#94a3b8}
</style>
</head>
<body>

<nav>
  <div class="nav-logo">meridian<em>.</em></div>
  <div class="nav-links">
    <a href="/">Product</a>
    <a href="/">Solutions</a>
    <a href="/">Customers</a>
    <a href="/">Pricing</a>
    <a href="/">Docs</a>
  </div>
  <div class="nav-actions">
    <a href="/" class="btn-ghost">Sign in</a>
    <a href="/" class="btn-dark">Request demo</a>
  </div>
</nav>

<section style="background:#fff;padding-bottom:80px">
<div class="hero">
  <div class="hero-text">
    <div class="eyebrow">Enterprise Analytics Platform</div>
    <h1>Data intelligence<br>that scales with<br><span>your business</span></h1>
    <p>Meridian unifies your warehouse, BI layer, and AI forecasting into a single governed platform. Built for teams that can&#8217;t afford to be wrong.</p>
    <div class="hero-btns">
      <a href="/" class="btn-hero">Request a demo</a>
      <a href="/" class="btn-hero-ghost">See how it works &#8594;</a>
    </div>
    <div class="hero-trust"><span>&#10003;</span> SOC 2 Type II &nbsp;&nbsp; <span>&#10003;</span> GDPR compliant &nbsp;&nbsp; <span>&#10003;</span> ISO 27001</div>
  </div>
  <div class="hero-visual">
    <div class="dash-bar">
      <div class="dash-dot r"></div><div class="dash-dot y"></div><div class="dash-dot g"></div>
      <div class="dash-url">app.meridian.io/analytics</div>
    </div>
    <div class="dash-body">
      <div class="dash-header">
        <span class="dash-title">Revenue Overview</span>
        <span class="dash-badge">Live</span>
      </div>
      <div class="dash-stats">
        <div class="dash-stat"><div class="dash-stat-val up">$4.2M</div><div class="dash-stat-label">MRR</div></div>
        <div class="dash-stat"><div class="dash-stat-val">12,847</div><div class="dash-stat-label">Active users</div></div>
        <div class="dash-stat"><div class="dash-stat-val up">+23%</div><div class="dash-stat-label">Growth MoM</div></div>
      </div>
      <div class="dash-chart">
        <div class="dash-chart-label">Monthly recurring revenue</div>
        <div class="bars">
          <div class="bar" style="height:38%"></div>
          <div class="bar" style="height:45%"></div>
          <div class="bar" style="height:42%"></div>
          <div class="bar" style="height:55%"></div>
          <div class="bar" style="height:50%"></div>
          <div class="bar" style="height:62%"></div>
          <div class="bar" style="height:58%"></div>
          <div class="bar" style="height:70%"></div>
          <div class="bar" style="height:75%"></div>
          <div class="bar hi" style="height:88%"></div>
        </div>
      </div>
      <div class="dash-line"></div>
      <div class="dash-row"><span class="dash-row-name">Enterprise tier</span><span class="dash-row-val">$2.8M</span><span class="dash-row-change">+18%</span></div>
      <div class="dash-row"><span class="dash-row-name">Growth tier</span><span class="dash-row-val">$1.1M</span><span class="dash-row-change">+31%</span></div>
      <div class="dash-row"><span class="dash-row-name">Starter tier</span><span class="dash-row-val">$0.3M</span><span class="dash-row-change">+44%</span></div>
    </div>
  </div>
</div>
</section>

<div class="logos">
  <div class="logos-label">Trusted by data teams at</div>
  <div class="logos-row">
    <span>Accenture</span><span>Unilever</span><span>Siemens</span><span>ING Bank</span><span>Maersk</span><span>Volvo Group</span>
  </div>
</div>

<div class="stats">
  <div class="stats-grid">
    <div><div class="stat-num"><span>2.4</span>B+</div><div class="stat-desc">Events processed daily</div></div>
    <div><div class="stat-num"><span>99.99</span>%</div><div class="stat-desc">Uptime over 12 months</div></div>
    <div><div class="stat-num"><span>340</span>+</div><div class="stat-desc">Enterprise customers</div></div>
    <div><div class="stat-num"><span>&lt;1</span>s</div><div class="stat-desc">Average query latency</div></div>
  </div>
</div>

<div class="features">
  <div class="section-label">Platform</div>
  <div class="section-title">Everything your data team needs</div>
  <div class="section-sub">From ingestion to insight &mdash; governed, auditable, and secure by default.</div>
  <div class="feat-grid">
    <div class="feat"><div class="feat-icon">&#9889;</div><h3>Real-time pipelines</h3><p>Sub-second data freshness with streaming ingest from Kafka, Kinesis, or any webhook source. No batch lag.</p></div>
    <div class="feat"><div class="feat-icon">&#128202;</div><h3>Unified data catalog</h3><p>Discover, document, and govern every dataset across cloud, on-prem, and hybrid environments automatically.</p></div>
    <div class="feat"><div class="feat-icon">&#129504;</div><h3>AI-powered forecasting</h3><p>Predictive models trained on your historical data, refreshed nightly and deployed to dashboards instantly.</p></div>
    <div class="feat"><div class="feat-icon">&#128274;</div><h3>Fine-grained access control</h3><p>Row- and column-level security with SSO, SCIM provisioning, and full audit logs for compliance teams.</p></div>
    <div class="feat"><div class="feat-icon">&#128101;</div><h3>Customer 360</h3><p>Stitch behavioural, transactional, and CRM data into a single identity graph with automatic deduplication.</p></div>
    <div class="feat"><div class="feat-icon">&#128279;</div><h3>500+ connectors</h3><p>Salesforce, HubSpot, Stripe, Snowflake, BigQuery &mdash; connect in minutes with pre-built, maintained connectors.</p></div>
  </div>
</div>

<div class="testimonials">
  <div class="section-label" style="text-align:center">Customer stories</div>
  <div class="section-title">Loved by data teams worldwide</div>
  <div class="section-sub">Don&#8217;t take our word for it.</div>
  <div class="testi-grid">
    <div class="testi">
      <div class="testi-quote">&#8220;We consolidated 14 BI tools into Meridian in eight weeks. Our time-to-insight went from three days to under an hour.&#8221;</div>
      <div class="testi-author"><div class="testi-avatar">SK</div><div><div class="testi-name">Sara Kowalski</div><div class="testi-role">Head of Data, ING Bank</div></div></div>
    </div>
    <div class="testi">
      <div class="testi-quote">&#8220;Meridian&#8217;s forecasting models are more accurate than anything our internal team built. It&#8217;s become our single source of truth.&#8221;</div>
      <div class="testi-author"><div class="testi-avatar">MH</div><div><div class="testi-name">Marcus Hein</div><div class="testi-role">VP Engineering, Siemens</div></div></div>
    </div>
    <div class="testi">
      <div class="testi-quote">&#8220;The access control is genuinely enterprise-grade. We passed our ISO 27001 audit with no findings related to data access.&#8221;</div>
      <div class="testi-author"><div class="testi-avatar">AL</div><div><div class="testi-name">Anika Lund</div><div class="testi-role">CISO, Maersk</div></div></div>
    </div>
  </div>
</div>

<div class="cta-band">
  <h2>Ready to modernise your data stack?</h2>
  <p>Join 340+ enterprise teams. Talk to a solutions engineer &mdash; no commitment required.</p>
  <div class="cta-band-btns">
    <a href="/" class="btn-white">Book a 30-min demo</a>
    <a href="/" class="btn-white-ghost">View pricing</a>
  </div>
</div>

<footer>
  <div class="footer-top">
    <div class="footer-brand">
      <span class="nav-logo">meridian<em style="font-style:normal;color:#2563eb">.</em></span>
      <p>Enterprise data intelligence platform. Built for scale, designed for humans.</p>
    </div>
    <div class="footer-col">
      <h4>Product</h4>
      <a href="/">Overview</a><a href="/">Pipelines</a><a href="/">Catalog</a><a href="/">Forecasting</a><a href="/">Connectors</a>
    </div>
    <div class="footer-col">
      <h4>Company</h4>
      <a href="/">About</a><a href="/">Customers</a><a href="/">Blog</a><a href="/">Careers</a><a href="/">Press</a>
    </div>
    <div class="footer-col">
      <h4>Resources</h4>
      <a href="/">Docs</a><a href="/">API reference</a><a href="/">Status</a><a href="/">Security</a><a href="/">Trust centre</a>
    </div>
  </div>
  <div class="footer-bottom">
    <p>&copy; 2025 Meridian Data GmbH &mdash; All rights reserved.</p>
    <div class="footer-bottom-links">
      <a href="/">Privacy policy</a><a href="/">Terms of service</a><a href="/">Cookie settings</a>
    </div>
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

# Paths that return 404 (secret files, admin panels, etc.)
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
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


class MeridianHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        pass

    def _send(self, status: int, content_type: str, body: bytes, extra_headers: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURE_HEADERS.items():
            self.send_header(k, v)
        # Secure cookie with all flags
        self.send_header("Set-Cookie", "session=s_mer_xyz789; Path=/; HttpOnly; Secure; SameSite=Strict")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in BLOCKED_PATHS:
            self._send(404, "text/plain", b"Not Found")
            return

        if self.path == "/security.txt" or self.path == "/.well-known/security.txt":
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

    print("=" * 62)
    print("  MERIDIAN — clean corporate demo target")
    print("=" * 62)
    print("  HTTP server:  http://localhost:8082")
    print("  No open database ports.")
    print()
    print("  Scan target:  http://localhost:8082")
    print("  Press Ctrl+C to stop.")
    print("=" * 62)

    stop_event = asyncio.Event()
    try:
        await stop_event.wait()
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down Meridian demo server.")
