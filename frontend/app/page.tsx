"use client";

import { useState } from "react";
import ScanForm from "@/components/ScanForm";
import ScanResults from "@/components/ScanResults";
import LoadingState from "@/components/LoadingState";
import { runScan } from "@/lib/api";
import { ScanResponse } from "@/types/scan";

type State =
  | { status: "idle" }
  | { status: "scanning"; url: string }
  | { status: "results"; result: ScanResponse }
  | { status: "error"; message: string; url: string };

export default function Home() {
  const [state, setState] = useState<State>({ status: "idle" });

  async function handleScan(url: string, githubUrl?: string) {
    setState({ status: "scanning", url });
    try {
      const result = await runScan({ url, github_url: githubUrl });
      setState({ status: "results", result });
    } catch (err) {
      setState({
        status: "error",
        message: err instanceof Error ? err.message : "Something went wrong.",
        url,
      });
    }
  }

  function handleReset() {
    setState({ status: "idle" });
  }

  return (
    <main className="min-h-screen bg-gray-950 text-white px-4 py-16">
      <div className="max-w-2xl mx-auto">
        {(state.status === "idle" || state.status === "error") && (
          <div className="mb-10 text-center">
            <h1 className="text-3xl font-bold tracking-tight mb-2">Security Scanner</h1>
            <p className="text-gray-400 text-sm">
              Find exposed files, open ports, and misconfigurations before attackers do.
            </p>
          </div>
        )}

        {state.status === "error" && (
          <div className="mb-6 rounded-lg bg-red-950 border border-red-800 px-4 py-3 text-sm text-red-300">
            <span className="font-semibold">Scan failed: </span>
            {state.message}
          </div>
        )}

        {(state.status === "idle" || state.status === "error") && (
          <ScanForm
            onSubmit={handleScan}
            isLoading={false}
            initialUrl={state.status === "error" ? state.url : ""}
          />
        )}

        {state.status === "scanning" && <LoadingState />}

        {state.status === "results" && (
          <ScanResults result={state.result} onReset={handleReset} />
        )}
      </div>
    </main>
  );
}
