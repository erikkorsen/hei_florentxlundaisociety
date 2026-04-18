"use client";

import { ScanResponse, AnalysisResponse, Severity } from "@/types/scan";
import { useState } from "react";
import AISummaryCard from "./AISummaryCard";
import GroupedFindingCard from "./GroupedFindingCard";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "PASS"];

interface Props {
  scan: ScanResponse;
  analysis: AnalysisResponse;
  onReset: () => void;
}

const GRADE_INFO: Record<string, { color: string; bg: string; border: string }> = {
  A: { color: "text-green-400",  bg: "bg-green-950/40",  border: "border-green-900" },
  B: { color: "text-yellow-400", bg: "bg-yellow-950/30", border: "border-yellow-900" },
  C: { color: "text-orange-400", bg: "bg-orange-950/30", border: "border-orange-900" },
  D: { color: "text-red-400",    bg: "bg-red-950/30",    border: "border-red-900" },
  F: { color: "text-red-500",    bg: "bg-red-950/40",    border: "border-red-900" },
};

function grade(s: Record<Severity, number>) {
  if (s.CRITICAL >= 4) return { g: "F", sub: "Critical Risk" };
  if (s.CRITICAL >= 2) return { g: "D", sub: "High Risk" };
  if (s.CRITICAL >= 1 || s.HIGH >= 3) return { g: "C", sub: "Elevated Risk" };
  if (s.HIGH >= 1)     return { g: "B", sub: "Moderate Risk" };
  return                        { g: "A", sub: "Low Risk" };
}

export default function AnalysisResults({ scan, analysis, onReset }: Props) {
  const [tab, setTab] = useState<"problems" | "all">("problems");
  const { summary } = scan;
  const risk = grade(summary);
  const gi = GRADE_INFO[risk.g] ?? GRADE_INFO.C;

  const bySeverity = (a: { severity: Severity }, b: { severity: Severity }) =>
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);

  const real       = [...analysis.grouped_findings].filter(f => !f.likely_false_positive).sort(bySeverity);
  const maybeNoise = [...analysis.grouped_findings].filter(f => f.likely_false_positive).sort(bySeverity);

  const problems = real.filter(f => f.severity !== "PASS");
  const passes   = real.filter(f => f.severity === "PASS");

  const visible = tab === "problems" ? problems : real;

  const totalIssues = summary.CRITICAL + summary.HIGH + summary.MEDIUM;

  return (
    <div className="w-full max-w-3xl mx-auto">

      {/* ── Report header ────────────────────────────── */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <p className="text-xs text-zinc-600 uppercase tracking-widest mb-1">Palisade Report</p>
          <p className="text-white font-medium text-lg">{scan.target_url.replace(/^https?:\/\//, "")}</p>
          <p className="text-zinc-600 text-xs mt-0.5">Scanned in {scan.scan_duration_seconds.toFixed(1)}s</p>
        </div>
        <button onClick={onReset} className="bg-white text-black text-xs font-semibold px-5 py-2.5 hover:bg-zinc-200 transition">
          New scan
        </button>
      </div>

      {/* ── Grade + stats ────────────────────────────── */}
      <div className={`border ${gi.border} ${gi.bg} p-6 mb-6 flex items-center gap-8 flex-wrap`}>
        <div className="flex items-center gap-5">
          <div className={`text-5xl font-black ${gi.color} leading-none`}>{risk.g}</div>
          <div>
            <p className={`font-bold ${gi.color}`}>{risk.sub}</p>
            <p className="text-zinc-500 text-xs mt-0.5">
              {totalIssues === 0 ? "No issues detected" : `${totalIssues} issue${totalIssues !== 1 ? "s" : ""} found`}
            </p>
          </div>
        </div>
        <div className="flex gap-8 ml-auto flex-wrap">
          {(summary.CRITICAL > 0) && <Stat n={summary.CRITICAL} label="Critical" color="text-red-400" />}
          {(summary.HIGH > 0)     && <Stat n={summary.HIGH}     label="High"     color="text-orange-400" />}
          {(summary.MEDIUM > 0)   && <Stat n={summary.MEDIUM}   label="Medium"   color="text-yellow-400" />}
          <Stat n={passes.length} label="Passed" color="text-green-400" />
        </div>
      </div>

      {/* ── AI Summary ───────────────────────────────── */}
      <div className="mb-8">
        <AISummaryCard analysis={analysis} />
      </div>

      {/* ── Tabs ─────────────────────────────────────── */}
      <div className="flex gap-1 border-b border-zinc-800 mb-4">
        <button
          onClick={() => setTab("problems")}
          className={`px-4 py-3 text-sm font-medium transition ${
            tab === "problems"
              ? "text-white border-b-2 border-white -mb-px"
              : "text-zinc-500 hover:text-zinc-300"
          }`}
        >
          Problems <span className="text-zinc-600 ml-1">{problems.length}</span>
        </button>
        <button
          onClick={() => setTab("all")}
          className={`px-4 py-3 text-sm font-medium transition ${
            tab === "all"
              ? "text-white border-b-2 border-white -mb-px"
              : "text-zinc-500 hover:text-zinc-300"
          }`}
        >
          All Tests <span className="text-zinc-600 ml-1">{real.length}</span>
        </button>
      </div>

      {/* ── Findings ─────────────────────────────────── */}
      <div className={tab === "all" ? "space-y-1" : "space-y-3"}>
        {visible.length === 0
          ? <p className="text-zinc-600 text-sm text-center py-16">No problems found.</p>
          : visible.map(f => <GroupedFindingCard key={f.id} finding={f} compact={tab === "all"} />)
        }

        {/* False positive divider */}
        {maybeNoise.length > 0 && (
          <>
            <div className="flex items-center gap-3 py-3">
              <div className="flex-1 border-t border-zinc-900" />
              <span className="text-xs text-zinc-600 whitespace-nowrap uppercase tracking-wider">
                Possibly not applicable
              </span>
              <div className="flex-1 border-t border-zinc-900" />
            </div>
            {maybeNoise.map(f => <GroupedFindingCard key={f.id} finding={f} compact={tab === "all"} />)}
          </>
        )}
      </div>

    </div>
  );
}

function Stat({ n, label, color }: { n: number; label: string; color: string }) {
  return (
    <div className="text-center min-w-[3rem]">
      <p className={`text-2xl font-bold ${color}`}>{n}</p>
      <p className="text-[10px] text-zinc-500 uppercase tracking-wider mt-0.5">{label}</p>
    </div>
  );
}
