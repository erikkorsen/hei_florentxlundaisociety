import { AnalysisResponse } from "@/types/scan";

const EFFORT_TAGS: { tag: string; badge: string; label: string }[] = [
  { tag: "[Quick fix]", badge: "bg-green-900 text-green-300",  label: "Quick fix" },
  { tag: "[Moderate]",  badge: "bg-yellow-900 text-yellow-300", label: "Moderate" },
  { tag: "[Major]",     badge: "bg-red-900 text-red-300",      label: "Major" },
];

function parseAction(action: string): { badge: string; label: string; text: string } | null {
  for (const { tag, badge, label } of EFFORT_TAGS) {
    if (action.startsWith(tag)) {
      return { badge, label, text: action.slice(tag.length).trimStart() };
    }
  }
  return null;
}

export default function AISummaryCard({ analysis }: { analysis: AnalysisResponse }) {
  if (!analysis.ai_powered || !analysis.summary) return null;

  return (
    <div className="rounded-xl border border-indigo-700 bg-indigo-950/40 p-5 space-y-5">
      {/* Summary */}
      <p className="text-gray-200 text-sm leading-relaxed">
        {analysis.summary}
      </p>

      {/* Priority Action Plan */}
      {analysis.priority_actions.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs text-gray-500 font-medium uppercase tracking-wider">Priority Action Plan</p>
          <ol className="space-y-2">
            {analysis.priority_actions.map((action, i) => {
              const parsed = parseAction(action);
              return (
                <li key={i} className="flex gap-2.5 items-start text-sm text-gray-300">
                  <span className="text-indigo-400 font-bold shrink-0 mt-0.5">{i + 1}.</span>
                  <span className="flex flex-wrap items-baseline gap-1.5">
                    {parsed ? (
                      <>
                        <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-semibold shrink-0 ${parsed.badge}`}>
                          {parsed.label}
                        </span>
                        <span>{parsed.text}</span>
                      </>
                    ) : (
                      <span>{action}</span>
                    )}
                  </span>
                </li>
              );
            })}
          </ol>
        </div>
      )}
    </div>
  );
}
