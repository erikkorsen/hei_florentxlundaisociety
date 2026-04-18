"use client";

import { useState } from "react";

interface ScanFormProps {
  onSubmit: (url: string, githubUrl?: string) => void;
  isLoading: boolean;
  initialUrl?: string;
}

function normalizeUrl(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return trimmed;
  if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) return trimmed;
  return "https://" + trimmed;
}

function isValidUrl(value: string): boolean {
  try {
    const u = new URL(normalizeUrl(value));
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

export default function ScanForm({ onSubmit, isLoading, initialUrl = "" }: ScanFormProps) {
  const [url, setUrl] = useState(initialUrl);
  const [githubUrl, setGithubUrl] = useState("");
  const [urlError, setUrlError] = useState("");

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const normalized = normalizeUrl(url);
    if (!isValidUrl(normalized)) {
      setUrlError("Enter a valid URL (e.g. example.com or https://example.com)");
      return;
    }
    setUrlError("");
    onSubmit(normalized, githubUrl.trim() || undefined);
  }

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-2xl mx-auto space-y-4">
      <div className="space-y-1">
        <label htmlFor="url" className="block text-sm font-medium text-gray-300">
          Target URL <span className="text-red-400">*</span>
        </label>
        <input
          id="url"
          type="text"
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            if (urlError) setUrlError("");
          }}
          placeholder="example.com"
          disabled={isLoading}
          className={`w-full px-4 py-3 rounded-lg bg-gray-800 border text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 transition disabled:opacity-50 ${
            urlError ? "border-red-500" : "border-gray-600"
          }`}
        />
        {urlError && <p className="text-sm text-red-400">{urlError}</p>}
      </div>

      <div className="space-y-1">
        <label htmlFor="github" className="block text-sm font-medium text-gray-300">
          GitHub Repository{" "}
          <span className="text-gray-500 font-normal">(optional)</span>
        </label>
        <input
          id="github"
          type="text"
          value={githubUrl}
          onChange={(e) => setGithubUrl(e.target.value)}
          placeholder="https://github.com/owner/repo"
          disabled={isLoading}
          className="w-full px-4 py-3 rounded-lg bg-gray-800 border border-gray-600 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 transition disabled:opacity-50"
        />
      </div>

      <button
        type="submit"
        disabled={isLoading || !url}
        className="w-full py-3 px-6 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-semibold transition"
      >
        {isLoading ? "Scanning…" : "Scan for vulnerabilities"}
      </button>
    </form>
  );
}
