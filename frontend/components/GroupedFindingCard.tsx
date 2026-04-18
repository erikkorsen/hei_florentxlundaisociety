"use client";

import { useState } from "react";
import { GroupedFinding, Severity } from "@/types/scan";

const SEVERITY_STYLES: Record<Severity, { badge: string; border: string; label: string }> = {
  CRITICAL: { badge: "bg-red-900 text-red-200", border: "border-red-800", label: "Critical" },
  HIGH: { badge: "bg-orange-900 text-orange-200", border: "border-orange-800", label: "High" },
  MEDIUM: { badge: "bg-yellow-900 text-yellow-200", border: "border-yellow-800", label: "Medium" },
  PASS: { badge: "bg-green-900 text-green-200", border: "border-green-800", label: "Pass" },
};

const SEVERITY_ICON: Record<Severity, string> = {
  CRITICAL: "●",
  HIGH: "▲",
  MEDIUM: "◆",
  PASS: "✓",
};

export default function GroupedFindingCard({ finding }: { finding: GroupedFinding }) {
  const [expanded, setExpanded] = useState(false);
  const styles = SEVERITY_STYLES[finding.severity];
  const muted = finding.likely_false_positive;

  return (
    <div
      className={`rounded-xl border ${styles.border} ${muted ? "opacity-60" : ""} bg-gray-900 p-5 space-y-3`}
    >
      <div className="flex items-center gap-3 flex-wrap">
        <span
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold ${styles.badge}`}
        >
          <span>{SEVERITY_ICON[finding.severity]}</span>
          {styles.label}
        </span>

        {finding.count > 1 && (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-gray-800 text-gray-400">
            {finding.count} findings
          </span>
        )}

        {muted && (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-gray-800 text-gray-500">
            Likely false positive
          </span>
        )}

        <h3 className="text-white font-semibold text-sm flex-1">{finding.title}</h3>
      </div>

      <p className="text-gray-400 text-sm leading-relaxed">{finding.description}</p>

      {finding.affected.length > 0 && (
        <div className="text-xs font-mono text-gray-500 space-y-0.5">
          {finding.affected.slice(0, 3).map((a, i) => (
            <div key={i} className="truncate">{a}</div>
          ))}
          {finding.affected.length > 3 && (
            <div className="text-gray-600">+{finding.affected.length - 3} more</div>
          )}
        </div>
      )}

      {finding.fix && (
        <p className="text-xs text-gray-500 border-t border-gray-800 pt-3">
          <span className="text-gray-400 font-medium">Fix: </span>
          {finding.fix}
        </p>
      )}

      {finding.count > 1 && (
        <button
          onClick={() => setExpanded((v) => !v)}
          className="text-xs text-gray-500 hover:text-gray-300 transition"
        >
          {expanded ? "▲ Hide details" : `▼ Show ${finding.count} individual findings`}
        </button>
      )}

      {expanded && (
        <div className="mt-2 space-y-1 border-t border-gray-800 pt-3">
          {finding.raw_ids.map((id) => (
            <div key={id} className="text-xs text-gray-500 font-mono">
              {id}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
