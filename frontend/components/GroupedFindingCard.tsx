"use client";

import { useState } from "react";
import { GroupedFinding, Severity, Category } from "@/types/scan";

const SEVERITY_STYLES: Record<Severity, { badge: string; borderLeft: string; label: string }> = {
  CRITICAL: { badge: "bg-red-900/80 text-red-200",       borderLeft: "border-l-red-600",    label: "Critical" },
  HIGH:     { badge: "bg-orange-900/80 text-orange-200", borderLeft: "border-l-orange-600", label: "High" },
  MEDIUM:   { badge: "bg-yellow-900/80 text-yellow-200", borderLeft: "border-l-yellow-600", label: "Medium" },
  PASS:     { badge: "bg-green-900/80 text-green-200",   borderLeft: "border-l-green-700",  label: "Pass" },
};

const CATEGORY_INFO: Record<Category, { label: string; context: string }> = {
  secrets:    { label: "Secrets",     context: "Exposed credentials give attackers direct access to your databases, APIs, and cloud infrastructure — often the fastest path to a full compromise." },
  ports:      { label: "Network",     context: "Open ports on sensitive services allow direct attacks on databases and internal systems. Most of these should never be reachable from the public internet." },
  ssl:        { label: "SSL/TLS",     context: "SSL/TLS issues expose users to interception and man-in-the-middle attacks where an attacker can silently read or modify traffic." },
  admin:      { label: "Admin",       context: "Exposed admin panels are high-value targets for brute-force and credential stuffing attacks. Even with strong passwords, reducing exposure is best practice." },
  firewall:   { label: "Firewall",    context: "Without a firewall, your entire infrastructure is exposed to the internet. This often indicates multiple services are reachable that should be internal-only." },
  github:     { label: "GitHub",      context: "Secrets committed to code repositories can be discovered by anyone with repo access — or publicly indexed if the repo is public." },
  headers:    { label: "Headers",     context: "HTTP security headers are your browser-side defence against XSS, clickjacking, MIME sniffing, and data leakage. Missing headers are easy wins." },
  dns:        { label: "DNS / Email", context: "Email security records (SPF, DMARC, DKIM) prevent attackers from impersonating your domain to send phishing emails to your users or partners." },
  cookies:    { label: "Cookies",     context: "Insecure cookies can be stolen via XSS attacks or transmitted over unencrypted HTTP, exposing session tokens and authentication state." },
  cors:       { label: "CORS",        context: "CORS misconfigurations allow malicious websites to make authenticated requests on behalf of your users, potentially exposing private data or triggering actions." },
  subdomains: { label: "Subdomains",  context: "Forgotten or misconfigured subdomains expand your attack surface. Dangling DNS records pointing to deprovisioned cloud resources can be hijacked." },
  breach:     { label: "Breach",      context: "A past data breach signals historical security weaknesses. Affected credentials may still be in use and could enable account takeover via credential stuffing." },
};

function isUrl(value: string) {
  return value.startsWith("http://") || value.startsWith("https://");
}

interface Props {
  finding: GroupedFinding;
  compact?: boolean;
}

export default function GroupedFindingCard({ finding, compact = false }: Props) {
  const [open, setOpen] = useState(false);
  const [showDetails, setShowDetails] = useState(false);
  const [showContext, setShowContext] = useState(false);
  const styles = SEVERITY_STYLES[finding.severity];
  const muted = finding.likely_false_positive;
  const catInfo = CATEGORY_INFO[finding.category] ?? { label: finding.category, context: "" };
  const isPass = finding.severity === "PASS";

  const hasDetails = !isPass && (finding.business_impact || finding.affected.length > 0 || finding.count > 1);

  // Compact mode: click to expand, shows only metadata + title
  if (compact) {
    return (
      <div className={`border border-zinc-800 overflow-hidden transition ${
        !isPass ? `border-l-2 ${styles.borderLeft}` : ""
      } ${muted ? "opacity-50" : ""}`}>
        <button
          onClick={() => setOpen(v => !v)}
          className="w-full px-5 py-3 flex items-center gap-3 text-left hover:bg-zinc-900/50 transition"
        >
          <span className={`inline-flex items-center px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide shrink-0 ${styles.badge}`}>
            {styles.label}
          </span>
          <span className="text-zinc-600 text-xs shrink-0">{catInfo.label}</span>
          <span className="text-white text-sm font-medium truncate">{finding.title}</span>
          <span className="text-zinc-600 text-xs ml-auto shrink-0">{open ? "−" : "+"}</span>
        </button>

        {open && (
          <div className="px-5 pb-4 space-y-3 border-t border-zinc-900 pt-3">
            {/* Explanation */}
            {finding.plain_english ? (
              <p className="text-zinc-400 text-sm leading-[1.7]">{finding.plain_english}</p>
            ) : finding.description ? (
              <p className="text-zinc-400 text-sm leading-[1.7]">{finding.description}</p>
            ) : null}

            {/* Fix — visible if present */}
            {finding.fix && !isPass && (
              <div className="border-l-2 border-zinc-700 pl-3">
                <p className="text-xs text-zinc-500 uppercase tracking-wider font-medium mb-1">How to fix</p>
                <p className="text-zinc-300 text-sm leading-[1.7]">{finding.fix}</p>
              </div>
            )}

            {/* Proof links */}
            {!isPass && finding.affected.length > 0 && (
              <div className="space-y-0.5">
                {finding.affected.slice(0, 3).map((a, i) => (
                  <div key={i} className="font-mono text-xs">
                    {isUrl(a) ? (
                      <a href={a} target="_blank" rel="noopener noreferrer"
                        className="text-zinc-500 hover:text-white truncate block max-w-full underline underline-offset-2 transition">
                        {a}
                      </a>
                    ) : (
                      <span className="text-zinc-500">{a}</span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  // Full mode: problems tab — everything visible
  return (
    <div className={`border border-zinc-800 overflow-hidden transition ${
      !isPass ? `border-l-2 ${styles.borderLeft}` : ""
    } ${muted ? "opacity-50" : ""}`}>

      {/* ── Always visible ── */}
      <div className="px-5 py-4 space-y-3">

        {/* Metadata */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`inline-flex items-center px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide ${styles.badge}`}>
            {styles.label}
          </span>
          <span className="text-zinc-600 text-xs">{catInfo.label}</span>
          {finding.count > 1 && (
            <span className="text-zinc-600 text-xs">{finding.count} instances</span>
          )}
          {muted && (
            <span className="text-zinc-600 text-xs italic">May not apply</span>
          )}
        </div>

        {/* Title */}
        <h3 className="text-white font-semibold text-[15px] leading-snug">{finding.title}</h3>

        {/* Simple explanation */}
        {!isPass && (
          finding.plain_english ? (
            <p className="text-zinc-400 text-sm leading-[1.7]">{finding.plain_english}</p>
          ) : catInfo.context ? (
            <div>
              <button
                onClick={() => setShowContext(v => !v)}
                className="text-xs text-zinc-500 hover:text-zinc-300 transition font-medium"
              >
                {showContext ? "Hide context" : "What does this mean?"}
              </button>
              {showContext && (
                <p className="mt-2 text-zinc-400 text-sm leading-[1.7]">{catInfo.context}</p>
              )}
            </div>
          ) : null
        )}

        {/* Proof links */}
        {!isPass && finding.affected.length > 0 && (
          <div className="space-y-0.5">
            {finding.affected.slice(0, 3).map((a, i) => (
              <div key={i} className="font-mono text-xs">
                {isUrl(a) ? (
                  <a href={a} target="_blank" rel="noopener noreferrer"
                    className="text-zinc-500 hover:text-white truncate block max-w-full underline underline-offset-2 transition">
                    {a}
                  </a>
                ) : (
                  <span className="text-zinc-500">{a}</span>
                )}
              </div>
            ))}
            {finding.affected.length > 3 && (
              <span className="text-xs text-zinc-600">+{finding.affected.length - 3} more</span>
            )}
          </div>
        )}

        {/* Fix — always visible, prominent */}
        {finding.fix && !isPass && (
          <div className="border-l-2 border-zinc-700 pl-3 mt-1">
            <p className="text-xs text-zinc-500 uppercase tracking-wider font-medium mb-1">How to fix</p>
            <p className="text-zinc-300 text-sm leading-[1.7]">{finding.fix}</p>
          </div>
        )}

        {/* Details toggle */}
        {hasDetails && (
          <button
            onClick={() => setShowDetails(v => !v)}
            className="text-xs text-zinc-500 hover:text-zinc-300 transition font-medium pt-1"
          >
            {showDetails ? "Hide details" : "Show details"}
          </button>
        )}
      </div>

      {/* ── Expandable details ── */}
      {showDetails && (
        <div className="px-5 pb-4 space-y-4 border-t border-zinc-900 pt-4">
          {finding.description && (
            <div>
              <p className="text-xs text-zinc-500 uppercase tracking-wider font-medium mb-1.5">Analysis</p>
              <p className="text-zinc-300 text-sm leading-[1.7]">{finding.description}</p>
            </div>
          )}
          {finding.business_impact && (
            <div>
              <p className="text-xs text-zinc-500 uppercase tracking-wider font-medium mb-1.5">Potential impact</p>
              <p className="text-zinc-300 text-sm leading-[1.7]">{finding.business_impact}</p>
            </div>
          )}
          {finding.affected.length > 3 && (
            <div>
              <p className="text-xs text-zinc-500 uppercase tracking-wider font-medium mb-1.5">All affected</p>
              <div className="space-y-0.5">
                {finding.affected.map((a, i) => (
                  <div key={i} className="font-mono text-xs">
                    {isUrl(a) ? (
                      <a href={a} target="_blank" rel="noopener noreferrer"
                        className="text-zinc-400 hover:text-white truncate block max-w-full underline underline-offset-2">
                        {a}
                      </a>
                    ) : (
                      <span className="text-zinc-400">{a}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
          {finding.count > 1 && (
            <div>
              <p className="text-xs text-zinc-500 uppercase tracking-wider font-medium mb-1.5">Individual findings</p>
              <div className="space-y-1">
                {finding.raw_ids.map((id) => (
                  <div key={id} className="text-xs text-zinc-500 font-mono">{id}</div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
