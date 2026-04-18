import { AnalysisResponse } from "@/types/scan";

export default function AISummaryCard({ analysis }: { analysis: AnalysisResponse }) {
  if (!analysis.ai_powered || !analysis.summary) return null;

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div>
        <p className="text-xs text-zinc-500 uppercase tracking-widest font-medium mb-3">Summary</p>
        <p className="text-zinc-200 text-[15px] leading-[1.8]">
          {analysis.summary}
        </p>
      </div>

      {/* Priority actions */}
      {analysis.priority_actions.length > 0 && (
        <div className="border border-zinc-800 bg-zinc-950 p-5">
          <p className="text-xs text-zinc-500 uppercase tracking-widest font-medium mb-4">Recommended actions</p>
          <div className="space-y-4">
            {analysis.priority_actions.map((action, i) => (
              <div key={i} className="flex gap-4 items-start">
                <span className="text-white font-bold text-sm bg-zinc-800 w-6 h-6 flex items-center justify-center shrink-0">
                  {i + 1}
                </span>
                <p className="text-zinc-300 text-sm leading-relaxed pt-0.5">{action}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
