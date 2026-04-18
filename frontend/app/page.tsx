"use client";

import { useState } from "react";
import ScanForm from "@/components/ScanForm";
import AnalysisResults from "@/components/AnalysisResults";
import LoadingState from "@/components/LoadingState";
import { runScan, runAnalysis } from "@/lib/api";
import { ScanResponse, AnalysisResponse } from "@/types/scan";

type State =
  | { status: "idle" }
  | { status: "scanning"; url: string }
  | { status: "analysing"; url: string; scan: ScanResponse }
  | { status: "results"; scan: ScanResponse; analysis: AnalysisResponse }
  | { status: "error"; message: string; url: string };

export default function Home() {
  const [state, setState] = useState<State>({ status: "idle" });

  async function handleScan(url: string, githubUrl?: string) {
    setState({ status: "scanning", url });
    let scan: ScanResponse;
    const minScanTime = new Promise(r => setTimeout(r, 15000));
    try {
      const [result] = await Promise.all([
        runScan({ url, github_url: githubUrl }),
        minScanTime,
      ]);
      scan = result;
    } catch (err) {
      setState({
        status: "error",
        message: err instanceof Error ? err.message : "Something went wrong.",
        url,
      });
      return;
    }

    setState({ status: "analysing", url, scan });
    try {
      const analysis = await runAnalysis({
        target_url: scan.target_url,
        github_url: githubUrl,
        findings: scan.findings,
      });
      setState({ status: "results", scan, analysis });
    } catch (err) {
      setState({
        status: "error",
        message: err instanceof Error ? err.message : "Analysis failed.",
        url,
      });
    }
  }

  function handleReset() {
    setState({ status: "idle" });
  }

  return (
    <main className="min-h-screen bg-black text-white px-4">
      {(state.status === "idle" || state.status === "error") && (
        <div className="min-h-screen flex items-center justify-center">
          <div className="w-full max-w-lg">
            <div className="mb-12 text-center">
              <h1 className="text-4xl font-bold tracking-[0.25em] uppercase mb-4">Palisade</h1>
              <p className="text-zinc-500 text-sm max-w-sm mx-auto leading-relaxed">
                Scan any website for exposed files, open ports, misconfigurations, and weak points.
              </p>
            </div>

            {state.status === "error" && (
              <p className="mb-5 text-sm text-red-400 font-mono">
                &gt; Scan failed: {state.message}
              </p>
            )}

            <ScanForm
              onSubmit={handleScan}
              isLoading={false}
              initialUrl={state.status === "error" ? state.url : ""}
            />
          </div>
        </div>
      )}

      <div className="max-w-3xl mx-auto py-16">
        {state.status === "scanning" && <LoadingState />}

        {state.status === "analysing" && (
          <LoadingState fixedMessage="AI is reviewing findings…" />
        )}

        {state.status === "results" && (
          <AnalysisResults
            scan={state.scan}
            analysis={state.analysis}
            onReset={handleReset}
          />
        )}
      </div>
    </main>
  );
}
