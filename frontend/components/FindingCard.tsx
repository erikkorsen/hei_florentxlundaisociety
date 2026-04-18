import { Finding, Severity } from "@/types/scan";

const SEVERITY_STYLES: Record<Severity, { badge: string; border: string; label: string }> = {
  CRITICAL: {
    badge: "bg-red-900 text-red-200",
    border: "border-red-800",
    label: "Critical",
  },
  HIGH: {
    badge: "bg-orange-900 text-orange-200",
    border: "border-orange-800",
    label: "High",
  },
  MEDIUM: {
    badge: "bg-yellow-900 text-yellow-200",
    border: "border-yellow-800",
    label: "Medium",
  },
  PASS: {
    badge: "bg-green-900 text-green-200",
    border: "border-green-800",
    label: "Pass",
  },
};

const SEVERITY_ICON: Record<Severity, string> = {
  CRITICAL: "●",
  HIGH: "▲",
  MEDIUM: "◆",
  PASS: "✓",
};

function isUrl(value: string): boolean {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

export default function FindingCard({ finding }: { finding: Finding }) {
  const styles = SEVERITY_STYLES[finding.severity];

  return (
    <div className={`rounded-xl border ${styles.border} bg-gray-900 p-5 space-y-3`}>
      <div className="flex items-center gap-3">
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold ${styles.badge}`}>
          <span>{SEVERITY_ICON[finding.severity]}</span>
          {styles.label}
        </span>
        <h3 className="text-white font-semibold text-sm">{finding.title}</h3>
      </div>

      <p className="text-gray-400 text-sm leading-relaxed">{finding.description}</p>

      <div className="text-xs font-mono text-gray-500 truncate">
        {isUrl(finding.affected) ? (
          <a
            href={finding.affected}
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-blue-400 transition"
          >
            {finding.affected}
          </a>
        ) : (
          finding.affected
        )}
      </div>

      {finding.fix && (
        <p className="text-xs text-gray-500 border-t border-gray-800 pt-3">
          <span className="text-gray-400 font-medium">Fix: </span>
          {finding.fix}
        </p>
      )}
    </div>
  );
}
