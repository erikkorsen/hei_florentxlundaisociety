"""
NovaDash demo server — intentionally vulnerable SaaS site.
Runs on port 8081 (HTTP) plus mock TCP services on standard database ports.
For local demo only. NEVER expose to the internet.
"""
import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

if sys.platform == "win32" and sys.version_info < (3, 14):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# ---------------------------------------------------------------------------
# Page content
# ---------------------------------------------------------------------------

LANDING_HTML = b"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NovaDash &mdash; Product Analytics for B2B Teams</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a14;color:#e2e8f0;line-height:1.6}
a{text-decoration:none}

nav{display:flex;align-items:center;justify-content:space-between;padding:0 64px;height:64px;border-bottom:1px solid #1a1a2e;background:rgba(10,10,20,.9);backdrop-filter:blur(12px);position:sticky;top:0;z-index:100}
.logo{font-size:20px;font-weight:800;background:linear-gradient(135deg,#818cf8,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.nav-links{display:flex;align-items:center;gap:28px}
.nav-links a{font-size:14px;color:#94a3b8;font-weight:500}
.nav-links a:hover{color:#e2e8f0}
.nav-actions{display:flex;align-items:center;gap:10px}
.btn-ghost{font-size:14px;color:#94a3b8;font-weight:500;padding:7px 16px}
.btn-nav{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;font-size:14px;font-weight:600;padding:8px 20px;border-radius:8px}

.hero-wrap{padding:88px 64px 0;max-width:1200px;margin:0 auto;display:grid;grid-template-columns:1fr 1fr;gap:72px;align-items:center;min-height:580px}
.hero-badge{display:inline-flex;align-items:center;gap:6px;background:#1e1e3a;border:1px solid #3730a3;color:#a5b4fc;font-size:12px;font-weight:600;padding:4px 12px;border-radius:20px;margin-bottom:20px}
.hero-badge-dot{width:6px;height:6px;background:#818cf8;border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
h1{font-size:50px;font-weight:900;line-height:1.07;letter-spacing:-.03em;margin-bottom:20px}
h1 .grad{background:linear-gradient(135deg,#818cf8,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero-sub{font-size:17px;color:#64748b;line-height:1.7;margin-bottom:32px;max-width:440px}
.hero-btns{display:flex;gap:12px;align-items:center;margin-bottom:36px}
.btn-primary{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;font-size:15px;font-weight:700;padding:13px 28px;border-radius:10px}
.btn-outline{border:1px solid #2d2d4a;color:#94a3b8;font-size:15px;font-weight:500;padding:13px 22px;border-radius:10px}
.hero-note{font-size:13px;color:#475569}
.hero-note span{color:#818cf8}

.preview{background:#111125;border:1px solid #1e2030;border-radius:20px;overflow:hidden;box-shadow:0 24px 80px rgba(99,102,241,.15)}
.preview-bar{background:#0f0f1e;border-bottom:1px solid #1e2030;padding:12px 18px;display:flex;align-items:center;gap:7px}
.dot{width:10px;height:10px;border-radius:50%}
.dot.r{background:#ef4444}
.dot.y{background:#f59e0b}
.dot.g{background:#22c55e}
.preview-url{background:#1a1a2e;border-radius:6px;padding:3px 14px;font-size:11px;color:#475569;margin-left:10px}
.preview-body{padding:20px}
.pb-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
.pb-title{font-size:13px;font-weight:700;color:#e2e8f0}
.pb-live{display:flex;align-items:center;gap:5px;font-size:11px;color:#22c55e;font-weight:600}
.pb-live-dot{width:6px;height:6px;border-radius:50%;background:#22c55e;animation:pulse 1.5s infinite}
.kpi-row{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:18px}
.kpi{background:#0a0a14;border:1px solid #1e2030;border-radius:10px;padding:12px 14px}
.kpi-val{font-size:20px;font-weight:800;color:#e2e8f0;margin-bottom:2px}
.kpi-val.g{color:#22c55e}
.kpi-val.v{color:#a78bfa}
.kpi-label{font-size:10px;color:#475569}
.chart-area{background:#0a0a14;border:1px solid #1e2030;border-radius:10px;padding:14px;margin-bottom:14px}
.chart-title{font-size:10px;color:#475569;margin-bottom:10px}
.chart-bars{display:flex;align-items:flex-end;gap:5px;height:60px}
.cb{border-radius:3px 3px 0 0;flex:1}
.users-list{background:#0a0a14;border:1px solid #1e2030;border-radius:10px;padding:12px 14px}
.ul-header{font-size:10px;color:#475569;margin-bottom:10px}
.ul-row{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #111125;font-size:11px}
.ul-row:last-child{border:none}
.ul-name{color:#94a3b8}
.ul-val{color:#e2e8f0;font-weight:600}
.ul-tag{background:#1e1e3a;color:#a78bfa;font-size:10px;padding:1px 7px;border-radius:10px}

.logos-band{border-top:1px solid #1a1a2e;padding:36px 64px;text-align:center;background:#080810}
.logos-label{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:#334155;font-weight:600;margin-bottom:22px}
.logos-row{display:flex;gap:48px;justify-content:center;align-items:center;flex-wrap:wrap}
.logos-row span{font-size:15px;font-weight:800;color:#1e2030;letter-spacing:-.5px}

.stats-band{background:#0d0d1f;border-top:1px solid #1a1a2e;border-bottom:1px solid #1a1a2e;padding:48px 64px}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:32px;max-width:900px;margin:0 auto;text-align:center}
.stat-n{font-size:38px;font-weight:900;color:#fff;margin-bottom:4px}
.stat-n span{color:#818cf8}
.stat-d{font-size:13px;color:#334155}

.feats{padding:96px 64px;max-width:1200px;margin:0 auto}
.feat-label{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#818cf8;margin-bottom:12px}
.feat-title{font-size:34px;font-weight:900;letter-spacing:-.02em;margin-bottom:10px}
.feat-sub{font-size:15px;color:#64748b;margin-bottom:56px;max-width:520px}
.feat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}
.feat{background:#0d0d1f;border:1px solid #1a1a2e;border-radius:16px;padding:28px;transition:.2s}
.feat:hover{border-color:#3730a3;background:#0f0f1e}
.feat-ic{width:38px;height:38px;background:#1e1e3a;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:17px;margin-bottom:18px}
.feat h3{font-size:15px;font-weight:700;color:#e2e8f0;margin-bottom:7px}
.feat p{font-size:13px;color:#475569;line-height:1.65}

.pricing-section{background:#080810;border-top:1px solid #1a1a2e;padding:96px 64px}
.pricing-section .feat-label{display:block;text-align:center}
.pricing-section .feat-title{text-align:center;margin-bottom:8px}
.pricing-section .feat-sub{text-align:center;margin:0 auto 56px}
.plans{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;max-width:960px;margin:0 auto}
.plan{border:1px solid #1a1a2e;border-radius:18px;padding:32px;background:#0d0d1f}
.plan.hot{border-color:#6366f1;background:#0f0f20;position:relative}
.plan-name{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#475569;margin-bottom:8px}
.plan-price{font-size:40px;font-weight:900;color:#e2e8f0;margin-bottom:4px}
.plan-price sup{font-size:18px;vertical-align:top;margin-top:8px}
.plan-price sub{font-size:14px;color:#475569;font-weight:400}
.plan-desc{font-size:13px;color:#475569;margin-bottom:24px}
.plan-features{list-style:none;margin-bottom:28px}
.plan-features li{font-size:13px;color:#64748b;padding:6px 0;border-bottom:1px solid #1a1a2e;display:flex;align-items:center;gap:8px}
.plan-features li:last-child{border:none}
.plan-features li:before{content:"";width:6px;height:6px;border-radius:50%;background:#6366f1;flex-shrink:0}
.plan-btn{display:block;text-align:center;padding:11px;border-radius:9px;font-weight:600;font-size:14px}
.plan-btn.v{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff}
.plan-btn.g{border:1px solid #1e2030;color:#64748b}
.hot-badge{position:absolute;top:-12px;left:50%;transform:translateX(-50%);background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;font-size:11px;font-weight:700;padding:3px 14px;border-radius:20px;white-space:nowrap}

.social-proof{padding:80px 64px;max-width:1100px;margin:0 auto}
.social-proof .feat-label{margin-bottom:12px}
.social-proof .feat-title{margin-bottom:8px}
.social-proof .feat-sub{margin-bottom:52px}
.review-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}
.review{background:#0d0d1f;border:1px solid #1a1a2e;border-radius:16px;padding:28px}
.stars{color:#f59e0b;font-size:13px;margin-bottom:14px}
.review-text{font-size:14px;color:#94a3b8;line-height:1.7;margin-bottom:20px;font-style:italic}
.reviewer{display:flex;align-items:center;gap:10px}
.avatar{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,#4f46e5,#7c3aed);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fff}
.rev-name{font-size:13px;font-weight:700;color:#e2e8f0}
.rev-co{font-size:11px;color:#475569}

.cta-section{background:linear-gradient(135deg,#1e1b4b,#312e81);padding:80px 64px;text-align:center;border-top:1px solid #3730a3}
.cta-section h2{font-size:38px;font-weight:900;color:#fff;letter-spacing:-.02em;margin-bottom:14px}
.cta-section p{font-size:16px;color:#a5b4fc;margin-bottom:36px}
.cta-btns{display:flex;gap:12px;justify-content:center}
.btn-cta{background:#fff;color:#4f46e5;font-size:15px;font-weight:700;padding:13px 32px;border-radius:10px}
.btn-cta-ghost{border:1px solid rgba(255,255,255,.25);color:#fff;font-size:15px;font-weight:500;padding:13px 28px;border-radius:10px}

footer{background:#070710;border-top:1px solid #1a1a2e;padding:48px 64px 28px}
.ft{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:48px;margin-bottom:44px}
.ft-brand .logo{display:block;margin-bottom:12px}
.ft-brand p{font-size:13px;color:#334155;max-width:240px;line-height:1.6}
.ft-col h4{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin-bottom:14px}
.ft-col a{display:block;font-size:13px;color:#475569;margin-bottom:9px}
.ft-col a:hover{color:#94a3b8}
.ft-bottom{display:flex;justify-content:space-between;align-items:center;border-top:1px solid #1a1a2e;padding-top:20px}
.ft-bottom p{font-size:12px;color:#334155}
.ft-bottom-links{display:flex;gap:20px}
.ft-bottom-links a{font-size:12px;color:#334155}
</style>
</head>
<body>

<nav>
  <span class="logo">NovaDash</span>
  <div class="nav-links">
    <a href="/">Product</a><a href="/">Analytics</a><a href="/">Integrations</a><a href="/">Pricing</a><a href="/">Docs</a>
  </div>
  <div class="nav-actions">
    <a href="/login" class="btn-ghost">Log in</a>
    <a href="/login" class="btn-nav">Start free trial</a>
  </div>
</nav>

<div style="padding-bottom:96px;background:#0a0a14">
<div class="hero-wrap">
  <div>
    <div class="hero-badge"><div class="hero-badge-dot"></div> Now with AI-powered insights</div>
    <h1>Know exactly<br>why users<br><span class="grad">churn or convert</span></h1>
    <p class="hero-sub">NovaDash gives B2B product teams real-time visibility into activation, retention, and expansion &mdash; with AI that explains the why, not just the what.</p>
    <div class="hero-btns">
      <a href="/login" class="btn-primary">Start free &mdash; 14 days</a>
      <a href="/" class="btn-outline">Watch demo &#9654;</a>
    </div>
    <div class="hero-note">No credit card required &nbsp;&middot;&nbsp; <span>3,200+</span> teams already onboard</div>
  </div>
  <div class="preview">
    <div class="preview-bar">
      <div class="dot r"></div><div class="dot y"></div><div class="dot g"></div>
      <div class="preview-url">app.novadash.io/dashboard</div>
    </div>
    <div class="preview-body">
      <div class="pb-header">
        <span class="pb-title">Product Overview</span>
        <span class="pb-live"><span class="pb-live-dot"></span> Live</span>
      </div>
      <div class="kpi-row">
        <div class="kpi"><div class="kpi-val g">87.3%</div><div class="kpi-label">30-day retention</div></div>
        <div class="kpi"><div class="kpi-val">4,218</div><div class="kpi-label">Active accounts</div></div>
        <div class="kpi"><div class="kpi-val v">+12%</div><div class="kpi-label">Expansion MRR</div></div>
      </div>
      <div class="chart-area">
        <div class="chart-title">Daily active users &mdash; last 10 days</div>
        <div class="chart-bars">
          <div class="cb" style="height:52%;background:#1e1e3a"></div>
          <div class="cb" style="height:60%;background:#1e1e3a"></div>
          <div class="cb" style="height:55%;background:#1e1e3a"></div>
          <div class="cb" style="height:70%;background:#1e1e3a"></div>
          <div class="cb" style="height:64%;background:#1e1e3a"></div>
          <div class="cb" style="height:75%;background:#2d2b5e"></div>
          <div class="cb" style="height:72%;background:#2d2b5e"></div>
          <div class="cb" style="height:82%;background:#4f46e5"></div>
          <div class="cb" style="height:90%;background:#6366f1"></div>
          <div class="cb" style="height:95%;background:linear-gradient(180deg,#818cf8,#6366f1)"></div>
        </div>
      </div>
      <div class="users-list">
        <div class="ul-header">Top accounts by usage</div>
        <div class="ul-row"><span class="ul-name">Acme Corp</span><span class="ul-val">2,841 events</span><span class="ul-tag">power user</span></div>
        <div class="ul-row"><span class="ul-name">Globex Inc</span><span class="ul-val">1,990 events</span><span class="ul-tag">growing</span></div>
        <div class="ul-row"><span class="ul-name">Initech Ltd</span><span class="ul-val">1,204 events</span><span class="ul-tag">at risk</span></div>
      </div>
    </div>
  </div>
</div>
</div>

<div class="logos-band">
  <div class="logos-label">Powering product teams at</div>
  <div class="logos-row">
    <span>Vercel</span><span>Linear</span><span>Loom</span><span>Retool</span><span>Clerk</span><span>Resend</span>
  </div>
</div>

<div class="stats-band">
  <div class="stats-grid">
    <div><div class="stat-n"><span>3.2</span>k+</div><div class="stat-d">Teams using NovaDash</div></div>
    <div><div class="stat-n"><span>98</span>%</div><div class="stat-d">Customer satisfaction score</div></div>
    <div><div class="stat-n"><span>5</span>min</div><div class="stat-d">Average time to first insight</div></div>
    <div><div class="stat-n"><span>0</span>ms</div><div class="stat-d">Avg. query latency (p50)</div></div>
  </div>
</div>

<div class="feats">
  <div class="feat-label">Features</div>
  <div class="feat-title">Built for the way product teams work</div>
  <div class="feat-sub">No data engineers required. Just connect, explore, and share.</div>
  <div class="feat-grid">
    <div class="feat"><div class="feat-ic">&#9889;</div><h3>Real-time event tracking</h3><p>Track any user action instantly with our lightweight SDK. Data arrives in under 500ms, every time.</p></div>
    <div class="feat"><div class="feat-ic">&#128200;</div><h3>Conversion funnels</h3><p>Visualise every step from signup to paid. Drag-and-drop funnel builder with automatic drop-off analysis.</p></div>
    <div class="feat"><div class="feat-ic">&#128101;</div><h3>Cohort analysis</h3><p>Group users by any behaviour, attribute, or time period. Retention curves update as new data arrives.</p></div>
    <div class="feat"><div class="feat-ic">&#129504;</div><h3>AI explain</h3><p>Ask &ldquo;why did retention drop last week?&rdquo; and get a plain-English answer with the contributing factors ranked.</p></div>
    <div class="feat"><div class="feat-ic">&#128276;</div><h3>Anomaly alerts</h3><p>ML-powered alerts fire when any metric moves outside its expected range &mdash; Slack, email, or PagerDuty.</p></div>
    <div class="feat"><div class="feat-ic">&#128279;</div><h3>170+ integrations</h3><p>Segment, Stripe, Salesforce, Intercom, Postgres &mdash; connect your whole stack in minutes with no code.</p></div>
  </div>
</div>

<div class="pricing-section">
  <span class="feat-label">Pricing</span>
  <div class="feat-title">Simple, honest pricing</div>
  <div class="feat-sub">Start free. Upgrade when you need more. Cancel any time, no questions.</div>
  <div class="plans">
    <div class="plan">
      <div class="plan-name">Starter</div>
      <div class="plan-price"><sup>$</sup>49<sub>/mo</sub></div>
      <div class="plan-desc">For early-stage teams getting off the ground.</div>
      <ul class="plan-features"><li>Up to 5 seats</li><li>1M events/month</li><li>30-day data history</li><li>Core analytics</li><li>Email support</li></ul>
      <a href="/login" class="plan-btn g">Get started free</a>
    </div>
    <div class="plan hot">
      <div class="hot-badge">Most popular</div>
      <div class="plan-name">Growth</div>
      <div class="plan-price"><sup>$</sup>199<sub>/mo</sub></div>
      <div class="plan-desc">For scaling teams that need the full picture.</div>
      <ul class="plan-features"><li>Up to 25 seats</li><li>10M events/month</li><li>Unlimited history</li><li>AI explain</li><li>Slack + webhook alerts</li></ul>
      <a href="/login" class="plan-btn v">Start 14-day trial</a>
    </div>
    <div class="plan">
      <div class="plan-name">Enterprise</div>
      <div class="plan-price" style="font-size:28px;padding-top:8px">Custom</div>
      <div class="plan-desc">For orgs that need SSO, SLAs, and dedicated support.</div>
      <ul class="plan-features"><li>Unlimited seats</li><li>Unlimited events</li><li>SSO / SAML</li><li>99.9% uptime SLA</li><li>Dedicated CSM</li></ul>
      <a href="/" class="plan-btn g">Talk to sales</a>
    </div>
  </div>
</div>

<div class="social-proof">
  <div class="feat-label">Reviews</div>
  <div class="feat-title">Loved by product teams</div>
  <div class="feat-sub">Don&#8217;t take our word for it.</div>
  <div class="review-grid">
    <div class="review">
      <div class="stars">&#9733;&#9733;&#9733;&#9733;&#9733;</div>
      <div class="review-text">&#8220;We cancelled Mixpanel and Amplitude the same week we onboarded NovaDash. It does both jobs better at a third of the price.&#8221;</div>
      <div class="reviewer"><div class="avatar">TN</div><div><div class="rev-name">Tom Nielsen</div><div class="rev-co">Head of Product, Linear</div></div></div>
    </div>
    <div class="review">
      <div class="stars">&#9733;&#9733;&#9733;&#9733;&#9733;</div>
      <div class="review-text">&#8220;The AI explain feature is genuinely magic. I asked why enterprise churn spiked and had an answer with supporting data in 30 seconds.&#8221;</div>
      <div class="reviewer"><div class="avatar">PM</div><div><div class="rev-name">Priya Mehta</div><div class="rev-co">VP Product, Loom</div></div></div>
    </div>
    <div class="review">
      <div class="stars">&#9733;&#9733;&#9733;&#9733;&#9733;</div>
      <div class="review-text">&#8220;Setup took 20 minutes. The funnel builder is the best I&#8217;ve used. My whole team was self-sufficient by end of day one.&#8221;</div>
      <div class="reviewer"><div class="avatar">JK</div><div><div class="rev-name">Julia Krause</div><div class="rev-co">Product Lead, Retool</div></div></div>
    </div>
  </div>
</div>

<div class="cta-section">
  <h2>Start knowing your users, today.</h2>
  <p>14-day free trial. Full access. No credit card.</p>
  <div class="cta-btns">
    <a href="/login" class="btn-cta">Create free account</a>
    <a href="/" class="btn-cta-ghost">See live demo</a>
  </div>
</div>

<footer>
  <div class="ft">
    <div class="ft-brand">
      <span class="logo">NovaDash</span>
      <p>Product analytics for B2B SaaS teams. Know why users churn before they do.</p>
    </div>
    <div class="ft-col"><h4>Product</h4><a href="/">Overview</a><a href="/">Funnels</a><a href="/">Cohorts</a><a href="/">Alerts</a><a href="/">Integrations</a></div>
    <div class="ft-col"><h4>Company</h4><a href="/">About</a><a href="/">Blog</a><a href="/">Careers</a><a href="/">Press</a><a href="/">Contact</a></div>
    <div class="ft-col"><h4>Legal</h4><a href="/">Privacy</a><a href="/">Terms</a><a href="/">Security</a><a href="/">Status</a></div>
  </div>
  <div class="ft-bottom">
    <p>&copy; 2025 NovaDash Inc. &mdash; All rights reserved.</p>
    <div class="ft-bottom-links"><a href="/">Privacy policy</a><a href="/">Terms of service</a><a href="/">Cookie settings</a></div>
  </div>
</footer>

</body>
</html>"""

ADMIN_HTML = b"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>NovaDash Admin</title>
<style>body{font-family:-apple-system,sans-serif;background:#0f0f1a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{background:#1e1e2e;border:1px solid #2d2d3d;border-radius:16px;padding:40px;width:360px}
.logo{font-size:20px;font-weight:800;background:linear-gradient(135deg,#6366f1,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}
h2{font-size:22px;font-weight:700;margin-bottom:4px}p{color:#64748b;font-size:13px;margin-bottom:28px}
label{font-size:12px;color:#94a3b8;display:block;margin-bottom:6px}
input{width:100%;background:#0f0f1a;border:1px solid #2d2d3d;color:#e2e8f0;padding:10px 12px;border-radius:8px;font-size:14px;margin-bottom:16px}
button{width:100%;background:#6366f1;color:#fff;border:none;padding:12px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer}
</style></head>
<body><div class="box">
<div class="logo">NovaDash</div>
<h2>Admin Portal</h2><p>Internal access only. Authorised personnel only.</p>
<form><label>Email</label><input type="email" placeholder="admin@novadash.io">
<label>Password</label><input type="password" placeholder="Password">
<button>Sign in</button></form></div></body></html>"""

DB_ADMIN_HTML = b"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Adminer 4.8.1</title>
<style>body{font-family:-apple-system,sans-serif;background:#1a1a2e;color:#e2e8f0;margin:0;padding:40px}
h1{font-size:24px;margin-bottom:4px}p{color:#64748b;font-size:13px;margin-bottom:24px}
select,input{background:#0f0f1a;border:1px solid #2d2d3d;color:#e2e8f0;padding:8px 12px;border-radius:6px;font-size:14px;margin-right:8px;margin-bottom:12px}
button{background:#ef4444;color:#fff;border:none;padding:9px 20px;border-radius:6px;font-size:14px;cursor:pointer}
</style></head>
<body><h1>Adminer 4.8.1</h1><p>Database management interface. All database engines supported.</p>
<form>
<select name="driver"><option>MySQL</option><option>PostgreSQL</option><option>MongoDB</option></select><br>
<input name="server" value="localhost" placeholder="Server">
<input name="username" placeholder="Username"><br>
<input type="password" name="password" placeholder="Password">
<input name="db" placeholder="Database">
<button>Login</button>
</form></body></html>"""

FAKE_CONTENT: dict[str, tuple[str, bytes]] = {
    "/": ("text/html", LANDING_HTML),
    "/login": ("text/html", ADMIN_HTML),
    "/admin": ("text/html", ADMIN_HTML),
    "/administrator": ("text/html", ADMIN_HTML),
    "/wp-admin": ("text/html", ADMIN_HTML),
    "/wp-login.php": ("text/html", ADMIN_HTML),
    "/phpmyadmin": ("text/html", DB_ADMIN_HTML),
    "/adminer.php": ("text/html", DB_ADMIN_HTML),
    "/.env": ("text/plain", b"""# NovaDash production environment
NODE_ENV=production
PORT=3000

DB_HOST=db.novadash.internal
DB_PORT=5432
DB_NAME=novadash_prod
DB_USER=novadash_app
DB_PASSWORD=Pr0d$ecretDB_2024!

REDIS_URL=redis://:r3d1sP@ss@cache.novadash.internal:6379/0

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1
S3_BUCKET=novadash-prod-uploads

STRIPE_SECRET_KEY=DEMO_NOT_A_REAL_STRIPE_KEY_REPLACE_ME_XXXXXXXXX
STRIPE_WEBHOOK_SECRET=whsec_DEMO_NOT_REAL_REPLACE_ME_XXXXXXXXXXXXX

JWT_SECRET=sup3r$ecretJWTkey_NovaDash_Pr0duction_2024
NEXTAUTH_SECRET=n3xtAuthS3cret_NovaDash_2024_DoNotShare

SENTRY_DSN=https://examplekey@o0.ingest.sentry.io/0
"""),
    "/.env.production": ("text/plain", b"""DATABASE_URL=postgres://novadash_app:Pr0d$ecretDB_2024!@db.novadash.internal:5432/novadash_prod
REDIS_URL=redis://:r3d1sP@ss@cache.novadash.internal:6379
RAILS_MASTER_KEY=a1b2c3d4e5f60718293a4b5c6d7e8f90
"""),
    "/.git/config": ("text/plain", b"""[core]
\trepositoryformatversion = 0
\tfilemode = false
\tbare = false
[remote "origin"]
\turl = https://github.com/novadash/backend.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[user]
\tname = deploy-bot
\temail = deploy@novadash.io
"""),
    "/wp-config.php": ("text/plain", b"""<?php
define('DB_NAME', 'novadash_wp');
define('DB_USER', 'wp_novadash');
define('DB_PASSWORD', 'WpN0vaDash_2024!');
define('DB_HOST', 'localhost');
define('AUTH_KEY', 'x7#kL!mN9$pQ2rS5tU8vW1yZ3aB6cD0eF4gH7iJ');
$table_prefix = 'nd_';
"""),
    "/.htpasswd": ("text/plain", b"""admin:$apr1$xyz12345$FakeHashedPasswordForDemoOnly00
devops:$apr1$abc98765$AnotherFakeHashedPasswordHere00
"""),
    "/backup.sql": ("text/plain", b"""-- NovaDash DB backup -- Mon Apr 14 03:00:01 2025
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('user','admin') DEFAULT 'user',
  PRIMARY KEY (`id`)
);
INSERT INTO `users` VALUES (1,'ceo@novadash.io','$2b$12$FakeHashedPassword123456789abcdef','admin');
INSERT INTO `users` VALUES (2,'cto@novadash.io','$2b$12$AnotherFakeHashedPassword0987654','admin');
INSERT INTO `users` VALUES (3,'alice@acme.com','$2b$12$UserFakeHash_Alice_00000000000000','user');
CREATE TABLE `api_keys` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `key` varchar(64) NOT NULL,
  PRIMARY KEY (`id`)
);
INSERT INTO `api_keys` VALUES (1,1,'ndsk_live_DEMO_NOT_REAL_REPLACE_ME_XXXXX');
"""),
    "/config/database.yml": ("text/plain", b"""default: &default
  adapter: postgresql
  encoding: unicode
  pool: 5

production:
  <<: *default
  database: novadash_production
  username: novadash_app
  password: Pr0d$ecretDB_2024!
  host: db.novadash.internal
"""),
    "/robots.txt": ("text/plain", b"""User-agent: *
Disallow: /admin
Disallow: /api/internal
Disallow: /config
Disallow: /backup
Disallow: /secret
"""),
}


class NovaDashHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        pass

    def _send(self, status: int, content_type: str, body: bytes):
        origin = self.headers.get("Origin", "*")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Intentionally insecure headers
        self.send_header("Server", "nginx/1.18.0")
        self.send_header("X-Powered-By", "Express")
        # CORS: reflect origin with credentials — CRITICAL
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        # Insecure cookies — no HttpOnly, no Secure, no SameSite
        self.send_header("Set-Cookie", "session=eyJhbGciOiJIUzI1NiJ9.nd_abc123; Path=/")
        self.send_header("Set-Cookie", "user_id=42; Path=/")
        self.send_header("Set-Cookie", "auth_token=ndtok_ABCDEF123456; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        entry = FAKE_CONTENT.get(self.path)
        if entry is None:
            self._send(404, "text/plain", b"Not Found")
            return
        content_type, body = entry
        self._send(200, content_type, body)

    def do_OPTIONS(self):
        self._send(204, "text/plain", b"")


def run_http_server():
    server = HTTPServer(("", 8081), NovaDashHandler)
    server.serve_forever()


# ---------------------------------------------------------------------------
# TCP mock services (same as server.py)
# ---------------------------------------------------------------------------

async def redis_handler(reader, writer):
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=2.0)
        if b"PING" in data:
            writer.write(b"+PONG\r\n")
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def docker_handler(reader, writer):
    try:
        await asyncio.wait_for(reader.read(4096), timeout=2.0)
        body = b'{"ApiVersion":"1.41","Os":"linux","Arch":"amd64","ServerVersion":"24.0.5"}'
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        writer.write(response)
        await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


def make_bare_handler(greeting: bytes):
    async def handler(reader, writer):
        try:
            writer.write(greeting)
            await writer.drain()
            await asyncio.sleep(2.0)
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()
    return handler


async def try_start_server(handler, port: int):
    try:
        server = await asyncio.start_server(handler, "", port)
        return server
    except OSError as e:
        print(f"  WARNING: Could not bind port {port}: {e}")
        return None


async def main():
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    http_thread.start()

    servers = []
    for server in await asyncio.gather(
        try_start_server(redis_handler, 6379),
        try_start_server(docker_handler, 2375),
        try_start_server(make_bare_handler(b"MySQL Demo\n"), 3306),
        try_start_server(make_bare_handler(b"PostgreSQL Demo\n"), 5432),
        try_start_server(make_bare_handler(b"MongoDB Demo\n"), 27017),
    ):
        if server is not None:
            servers.append(server)

    print("=" * 62)
    print("  NOVADASH — vulnerable SaaS demo target")
    print("=" * 62)
    print("  HTTP server:  http://localhost:8081")
    print("  Redis:        localhost:6379  (no auth — CRITICAL)")
    print("  Docker API:   localhost:2375  (unauthenticated — CRITICAL)")
    print("  MySQL:        localhost:3306  (CRITICAL)")
    print("  PostgreSQL:   localhost:5432  (CRITICAL)")
    print("  MongoDB:      localhost:27017 (CRITICAL)")
    print()
    print("  Scan target:  http://localhost:8081")
    print("  Press Ctrl+C to stop.")
    print("=" * 62)

    stop_event = asyncio.Event()
    try:
        await stop_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        for s in servers:
            s.close()
        for s in servers:
            await s.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down NovaDash demo server.")
