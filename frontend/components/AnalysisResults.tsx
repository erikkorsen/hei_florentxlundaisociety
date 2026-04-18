"use client";

import { ScanResponse, AnalysisResponse, Severity, GroupedFinding, Category } from "@/types/scan";
import { useState } from "react";
import AISummaryCard from "./AISummaryCard";
import GroupedFindingCard from "./GroupedFindingCard";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "PASS"];

interface Props {
  scan: ScanResponse;
  analysis: AnalysisResponse;
  onReset: () => void;
}

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "text-red-400",
  HIGH: "text-orange-400",
  MEDIUM: "text-yellow-400",
  PASS: "text-green-400",
};

const SEV_BG: Record<Severity, string> = {
  CRITICAL: "bg-red-900/40 text-red-200 border-red-800",
  HIGH: "bg-orange-900/40 text-orange-200 border-orange-800",
  MEDIUM: "bg-yellow-900/30 text-yellow-200 border-yellow-800",
  PASS: "bg-green-900/30 text-green-200 border-green-800",
};

function grade(s: Record<Severity, number>) {
  if (s.CRITICAL >= 4) return { g: "F", color: "text-red-500", sub: "Critical Risk" };
  if (s.CRITICAL >= 2) return { g: "D", color: "text-red-400", sub: "High Risk" };
  if (s.CRITICAL >= 1 || s.HIGH >= 3) return { g: "C", color: "text-orange-400", sub: "Elevated Risk" };
  if (s.HIGH >= 1) return { g: "B", color: "text-yellow-400", sub: "Moderate Risk" };
  return { g: "A", color: "text-green-400", sub: "Low Risk" };
}

export default function AnalysisResults({ scan, analysis, onReset }: Props) {
  const [filter, setFilter] = useState<Severity | "ALL">("ALL");
  const { summary } = scan;
  const risk = grade(summary);

  const sorted = [...analysis.grouped_findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  const issues = sorted.filter(f => f.severity !== "PASS");
  const passes = sorted.filter(f => f.severity === "PASS");

  const visible =
    filter === "ALL" ? sorted :
    filter === "PASS" ? passes :
    issues.filter(f => f.severity === filter);

  const severities: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "PASS"];
  const tabs = severities
    .map(s => ({ s, count: sorted.filter(f => f.severity === s).length }))
    .filter(t => t.count > 0);

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

      {/* ── AI Summary ───────────────────────────────── */}
      <AISummaryCard analysis={analysis} />

      {/* ── Filter tabs ──────────────────────────────── */}
      <div className="flex gap-2 flex-wrap">
        <Tab active={filter === "ALL"} onClick={() => setFilter("ALL")}
          label="All" count={sorted.length} color="bg-gray-700 text-white" />
        {tabs.map(({ s, count }) => (
          <Tab key={s} active={filter === s} onClick={() => setFilter(s)}
            label={s[0] + s.slice(1).toLowerCase()} count={count} color={SEV_BG[s]} />
        ))}
      </div>

      {/* ── Findings ─────────────────────────────────── */}
      <div className="space-y-3">
        {visible.length === 0
          ? <p className="text-gray-600 text-sm text-center py-10">Nothing to show.</p>
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

function Tab({ active, onClick, label, count, color }: {
  active: boolean; onClick: () => void; label: string; count: number; color: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition ${
        active ? `${color} border-transparent` : "bg-transparent text-gray-500 border-gray-800 hover:text-gray-300"
      }`}
    >
      {label} <span className="opacity-60">({count})</span>
    </button>
  );
}
