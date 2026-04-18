import { ScanResponse, Severity, Finding } from "@/types/scan";
import FindingCard from "./FindingCard";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "PASS"];

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
}

interface ScanResultsProps {
  result: ScanResponse;
  onReset: () => void;
}

export default function ScanResults({ result, onReset }: ScanResultsProps) {
  const sorted = sortFindings(result.findings);
  const { summary } = result;

  const summaryItems = [
    { label: "Critical", count: summary.CRITICAL, color: "text-red-400" },
    { label: "High", count: summary.HIGH, color: "text-orange-400" },
    { label: "Medium", count: summary.MEDIUM, color: "text-yellow-400" },
    { label: "Passed", count: summary.PASS, color: "text-green-400" },
  ].filter((item) => item.count > 0);

  return (
    <div className="w-full max-w-2xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <p className="text-xs text-gray-500 truncate">{result.target_url}</p>
          <div className="flex flex-wrap gap-3 mt-1">
            {summaryItems.map((item) => (
              <span key={item.label} className={`text-sm font-semibold ${item.color}`}>
                {item.count} {item.label}
              </span>
            ))}
            <span className="text-sm text-gray-600">
              · {result.scan_duration_seconds.toFixed(1)}s
            </span>
          </div>
        </div>
        <button
          onClick={onReset}
          className="text-sm text-blue-400 hover:text-blue-300 transition shrink-0"
        >
          ← Scan another
        </button>
      </div>

      {/* Findings */}
      <div className="space-y-3">
        {sorted.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </div>
    </div>
  );
}
