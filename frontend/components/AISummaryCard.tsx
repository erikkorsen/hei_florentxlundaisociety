import { AnalysisResponse } from "@/types/scan";

export default function AISummaryCard({ analysis }: { analysis: AnalysisResponse }) {
  if (!analysis.ai_powered || !analysis.summary) return null;

  return (
    <div className="rounded-xl border border-indigo-700 bg-indigo-950/40 p-5 space-y-4">
      <div className="flex items-center gap-2">
        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-bold bg-indigo-800 text-indigo-200 tracking-wide">
          AI
        </span>
        <h2 className="text-white font-semibold text-sm">Security Analysis</h2>
      </div>

      <p className="text-gray-300 text-sm leading-relaxed">{analysis.summary}</p>

      {analysis.priority_actions.length > 0 && (
        <div className="space-y-1.5">
          <p className="text-xs text-gray-500 font-medium uppercase tracking-wider">Priority actions</p>
          <ol className="space-y-1">
            {analysis.priority_actions.map((action, i) => (
              <li key={i} className="flex gap-2 text-sm text-gray-300">
                <span className="text-indigo-400 font-bold shrink-0">{i + 1}.</span>
                {action}
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}
