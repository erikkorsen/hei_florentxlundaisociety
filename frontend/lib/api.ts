import { ScanRequest, ScanResponse, AnalyseRequest, AnalysisResponse } from "@/types/scan";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export async function runScan(request: ScanRequest): Promise<ScanResponse> {
  const res = await fetch(`${API_URL}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });

  if (!res.ok) {
    let message = `Server error (${res.status})`;
    try {
      const body = await res.json();
      message = body.detail ?? message;
    } catch {
      // use default message
    }
    throw new Error(message);
  }

  return res.json();
}

export async function runAnalysis(request: AnalyseRequest): Promise<AnalysisResponse> {
  const res = await fetch(`${API_URL}/api/analyse`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });

  if (!res.ok) {
    let message = `Analysis error (${res.status})`;
    try {
      const body = await res.json();
      message = body.detail ?? message;
    } catch {
      // use default message
    }
    throw new Error(message);
  }

  return res.json();
}
