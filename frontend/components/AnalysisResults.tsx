import { ScanResponse, AnalysisResponse, Severity } from "@/types/scan";
import AISummaryCard from "./AISummaryCard";
import GroupedFindingCard from "./GroupedFindingCard";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "PASS"];

interface AnalysisResultsProps {
  scan: ScanResponse;
  analysis: AnalysisResponse;
  onReset: () => void;
}

export default function AnalysisResults({ scan, analysis, onReset }: AnalysisResultsProps) {
  const { summary } = scan;

  const summaryItems = [
    { label: "Critical", count: summary.CRITICAL, color: "text-red-400" },
    { label: "High", count: summary.HIGH, color: "text-orange-400" },
    { label: "Medium", count: summary.MEDIUM, color: "text-yellow-400" },
    { label: "Passed", count: summary.PASS, color: "text-green-400" },
  ].filter((item) => item.count > 0);

  const sorted = [...analysis.grouped_findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  return (
    <div className="w-full max-w-2xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <p className="text-xs text-gray-500 truncate">{scan.target_url}</p>
          <div className="flex flex-wrap gap-3 mt-1">
            {summaryItems.map((item) => (
              <span key={item.label} className={`text-sm font-semibold ${item.color}`}>
                {item.count} {item.label}
              </span>
            ))}
            <span className="text-sm text-gray-600">
              · {scan.scan_duration_seconds.toFixed(1)}s
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

      {/* AI Summary */}
      <AISummaryCard analysis={analysis} />

      {/* Grouped findings */}
      <div className="space-y-3">
        {sorted.map((finding) => (
          <GroupedFindingCard key={finding.id} finding={finding} />
        ))}
      </div>
    </div>
  );
}
