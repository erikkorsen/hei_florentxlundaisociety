"use client";

import { useState } from "react";
import { GroupedFinding, Severity, Category } from "@/types/scan";

const SEVERITY_STYLES: Record<Severity, { badge: string; border: string; label: string; bg: string }> = {
  CRITICAL: { badge: "bg-red-900 text-red-200", border: "border-red-800", label: "Critical", bg: "bg-red-950/30" },
  HIGH:     { badge: "bg-orange-900 text-orange-200", border: "border-orange-800", label: "High", bg: "bg-orange-950/20" },
  MEDIUM:   { badge: "bg-yellow-900 text-yellow-200", border: "border-yellow-800", label: "Medium", bg: "bg-yellow-950/10" },
  PASS:     { badge: "bg-green-900 text-green-200", border: "border-green-800", label: "Pass", bg: "bg-green-950/10" },
};

const SEVERITY_ICON: Record<Severity, string> = {
  CRITICAL: "●", HIGH: "▲", MEDIUM: "◆", PASS: "✓",
};

const SEVERITY_IMPACT: Record<Severity, string> = {
  CRITICAL: "Requires immediate action — actively exploitable with severe impact.",
  HIGH:     "Should be fixed urgently — significant risk if left unresolved.",
  MEDIUM:   "Address soon — lower risk but contributes to overall attack surface.",
  PASS:     "This check passed — no action needed.",
};

const CATEGORY_INFO: Record<Category, { label: string; icon: string; context: string }> = {
  secrets:    { label: "Secrets",    icon: "🔑", context: "Exposed credentials give attackers direct access to your databases, APIs, and cloud infrastructure — often the fastest path to a full compromise." },
  ports:      { label: "Network",    icon: "🔌", context: "Open ports on sensitive services allow direct attacks on databases and internal systems. Most of these should never be reachable from the public internet." },
  ssl:        { label: "SSL/TLS",    icon: "🔒", context: "SSL/TLS issues expose users to interception and man-in-the-middle attacks where an attacker can silently read or modify traffic." },
  admin:      { label: "Admin",      icon: "⚙️",  context: "Exposed admin panels are high-value targets for brute-force and credential stuffing attacks. Even with strong passwords, reducing exposure is best practice." },
  firewall:   { label: "Firewall",   icon: "🛡️",  context: "Without a firewall, your entire infrastructure is exposed to the internet. This often indicates multiple services are reachable that should be internal-only." },
  github:     { label: "GitHub",     icon: "📦", context: "Secrets committed to code repositories can be discovered by anyone with repo access — or publicly indexed if the repo is public." },
  headers:    { label: "Headers",    icon: "📋", context: "HTTP security headers are your browser-side defence against XSS, clickjacking, MIME sniffing, and data leakage. Missing headers are easy wins." },
  dns:        { label: "DNS / Email",icon: "🌐", context: "Email security records (SPF, DMARC, DKIM) prevent attackers from impersonating your domain to send phishing emails to your users or partners." },
  cookies:    { label: "Cookies",    icon: "🍪", context: "Insecure cookies can be stolen via XSS attacks or transmitted over unencrypted HTTP, exposing session tokens and authentication state." },
  cors:       { label: "CORS",       icon: "↔️",  context: "CORS misconfigurations allow malicious websites to make authenticated requests on behalf of your users, potentially exposing private data or triggering actions." },
  subdomains: { label: "Subdomains", icon: "🌍", context: "Forgotten or misconfigured subdomains expand your attack surface. Dangling DNS records pointing to deprovisioned cloud resources can be hijacked." },
  breach:     { label: "Breach",     icon: "💥", context: "A past data breach signals historical security weaknesses. Affected credentials may still be in use and could enable account takeover via credential stuffing." },
};

function isUrl(value: string) {
  return value.startsWith("http://") || value.startsWith("https://");
}

export default function GroupedFindingCard({ finding }: { finding: GroupedFinding }) {
  const [expanded, setExpanded] = useState(false);
  const [showContext, setShowContext] = useState(false);
  const styles = SEVERITY_STYLES[finding.severity];
  const muted = finding.likely_false_positive;
  const catInfo = CATEGORY_INFO[finding.category] ?? { label: finding.category, icon: "•", context: "" };
  const isPass = finding.severity === "PASS";

  return (
    <div className={`rounded-xl border ${styles.border} ${muted ? "opacity-50" : ""} ${styles.bg} bg-gray-900 overflow-hidden`}>
      {/* Top bar */}
      <div className="px-5 pt-4 pb-3 space-y-3">
        {/* Badges row */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold ${styles.badge}`}>
            <span>{SEVERITY_ICON[finding.severity]}</span>
            {styles.label}
          </span>
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-gray-800 text-gray-400">
            <span>{catInfo.icon}</span>
            {catInfo.label}
          </span>
          {finding.count > 1 && (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-gray-800 text-gray-400">
              {finding.count} instances
            </span>
          )}
          {muted && (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-gray-800 text-gray-500">
              Likely false positive
            </span>
          )}
        </div>

        {/* Title */}
        <h3 className="text-white font-bold text-base leading-snug">{finding.title}</h3>

        {/* Impact statement */}
        {!isPass && (
          <p className="text-xs font-medium text-gray-500 italic">{SEVERITY_IMPACT[finding.severity]}</p>
        )}

        {/* Description */}
        <p className="text-gray-300 text-sm leading-relaxed">{finding.description}</p>

        {/* "What does this mean?" expandable */}
        {catInfo.context && !isPass && (
          <div>
            <button
              onClick={() => setShowContext(v => !v)}
              className="text-xs text-indigo-400 hover:text-indigo-300 transition font-medium"
            >
              {showContext ? "▲ Hide context" : "▼ What does this mean?"}
            </button>
            {showContext && (
              <p className="mt-2 text-xs text-indigo-200/70 leading-relaxed bg-indigo-950/30 border border-indigo-900/50 rounded-lg px-3 py-2">
                {catInfo.context}
              </p>
            )}
          </div>
        )}
      </div>

      {/* Affected items */}
      {finding.affected.length > 0 && (
        <div className="px-5 pb-3">
          <p className="text-xs text-gray-600 font-medium uppercase tracking-wider mb-1.5">Affected</p>
          <div className="space-y-1">
            {finding.affected.slice(0, 5).map((a, i) => (
              <div key={i} className="text-xs font-mono">
                {isUrl(a) ? (
                  <a href={a} target="_blank" rel="noopener noreferrer"
                    className="text-blue-400 hover:text-blue-300 truncate block max-w-full underline underline-offset-2">
                    {a}
                  </a>
                ) : (
                  <span className="text-gray-400">{a}</span>
                )}
              </div>
            ))}
            {finding.affected.length > 5 && (
              <div className="text-xs text-gray-600">+{finding.affected.length - 5} more</div>
            )}
          </div>
        </div>
      )}

      {/* Fix section */}
      {finding.fix && !isPass && (
        <div className="mx-5 mb-4 rounded-lg bg-gray-800/60 border border-gray-700 px-4 py-3">
          <p className="text-xs font-semibold text-green-400 uppercase tracking-wider mb-1">How to fix</p>
          <p className="text-xs text-gray-300 leading-relaxed">{finding.fix}</p>
        </div>
      )}

      {/* Expand raw findings */}
      {finding.count > 1 && (
        <div className="border-t border-gray-800 px-5 py-2">
          <button
            onClick={() => setExpanded(v => !v)}
            className="text-xs text-gray-500 hover:text-gray-300 transition"
          >
            {expanded ? "▲ Hide individual findings" : `▼ Show ${finding.count} individual findings`}
          </button>
          {expanded && (
            <div className="mt-2 space-y-1">
              {finding.raw_ids.map((id) => (
                <div key={id} className="text-xs text-gray-500 font-mono">{id}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
