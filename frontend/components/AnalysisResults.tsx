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


function grade(s: Record<Severity, number>) {
  if (s.CRITICAL >= 4) return { g: "F", color: "text-red-500", sub: "Critical Risk" };
  if (s.CRITICAL >= 2) return { g: "D", color: "text-red-400", sub: "High Risk" };
  if (s.CRITICAL >= 1 || s.HIGH >= 3) return { g: "C", color: "text-orange-400", sub: "Elevated Risk" };
  if (s.HIGH >= 1) return { g: "B", color: "text-yellow-400", sub: "Moderate Risk" };
  return { g: "A", color: "text-green-400", sub: "Low Risk" };
}

export default function AnalysisResults({ scan, analysis, onReset }: Props) {
  const [tab, setTab] = useState<"problems" | "all">("problems");
  const { summary } = scan;
  const risk = grade(summary);

  const sorted = [...analysis.grouped_findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  const problems = sorted.filter(f => f.severity !== "PASS");
  const passes = sorted.filter(f => f.severity === "PASS");

  const visible = tab === "problems" ? problems : sorted;

  return (
    <div className="w-full max-w-3xl mx-auto space-y-5">

      {/* ── Top bar ──────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-gray-500">{scan.target_url}</p>
          <p className="text-xs text-gray-700">{scan.scan_duration_seconds.toFixed(1)}s scan</p>
        </div>
        <button onClick={onReset} className="text-sm text-blue-400 hover:text-blue-300 transition">
          ← New scan
        </button>
      </div>

      {/* ── Score card ───────────────────────────────── */}
      <div className="rounded-2xl bg-gray-900 border border-gray-800 p-5 flex items-center gap-6 flex-wrap">
        <div className="flex items-center gap-4">
          <div className={`text-6xl font-black ${risk.color}`}>{risk.g}</div>
          <div>
            <p className="text-white font-bold text-lg">Security Grade</p>
            <p className={`text-sm font-medium ${risk.color}`}>{risk.sub}</p>
          </div>
        </div>
        <div className="flex gap-5 ml-auto flex-wrap">
          {(summary.CRITICAL > 0) && <Stat n={summary.CRITICAL} label="Critical" color="text-red-400" />}
          {(summary.HIGH > 0)     && <Stat n={summary.HIGH}     label="High"     color="text-orange-400" />}
          {(summary.MEDIUM > 0)   && <Stat n={summary.MEDIUM}   label="Medium"   color="text-yellow-400" />}
          {(passes.length > 0)    && <Stat n={passes.length}    label="Passed"   color="text-green-400" />}
        </div>
      </div>

      {/* ── Summary ──────────────────────────────────── */}
      <AISummaryCard analysis={analysis} />

      {/* ── Tabs: Problems / All Tests ───────────────── */}
      <div className="flex gap-2">
        <button
          onClick={() => setTab("problems")}
          className={`px-4 py-2 rounded-lg text-sm font-semibold transition ${
            tab === "problems"
              ? "bg-gray-700 text-white"
              : "bg-transparent text-gray-500 border border-gray-800 hover:text-gray-300"
          }`}
        >
          Problems <span className="opacity-60">({problems.length})</span>
        </button>
        <button
          onClick={() => setTab("all")}
          className={`px-4 py-2 rounded-lg text-sm font-semibold transition ${
            tab === "all"
              ? "bg-gray-700 text-white"
              : "bg-transparent text-gray-500 border border-gray-800 hover:text-gray-300"
          }`}
        >
          All Tests <span className="opacity-60">({sorted.length})</span>
        </button>
      </div>

      {/* ── Findings ─────────────────────────────────── */}
      <div className="space-y-3">
        {visible.length === 0
          ? <p className="text-gray-600 text-sm text-center py-10">No problems found — looking good!</p>
          : visible.map(f => <GroupedFindingCard key={f.id} finding={f} />)
        }
      </div>

    </div>
  );
}

function Stat({ n, label, color }: { n: number; label: string; color: string }) {
  return (
    <div className="text-center">
      <p className={`text-3xl font-black ${color}`}>{n}</p>
      <p className="text-xs text-gray-500">{label}</p>
    </div>
  );
}

