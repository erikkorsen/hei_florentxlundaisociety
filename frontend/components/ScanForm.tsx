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
  const [showGithub, setShowGithub] = useState(false);

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
    <form onSubmit={handleSubmit} className="w-full space-y-6">
      <div className="space-y-1.5">
        <input
          id="url"
          type="text"
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            if (urlError) setUrlError("");
          }}
          placeholder="Enter a website URL"
          disabled={isLoading}
          className={`w-full px-0 py-3 bg-transparent border-b text-white placeholder-zinc-700 focus:outline-none transition disabled:opacity-50 ${
            urlError ? "border-b-red-700" : "border-b-zinc-700 focus:border-b-white"
          }`}
        />
        {urlError && <p className="text-xs text-red-400 font-mono">&gt; {urlError}</p>}
      </div>

      {showGithub ? (
        <div className="space-y-2">
          <input
            id="github"
            type="text"
            value={githubUrl}
            onChange={(e) => setGithubUrl(e.target.value)}
            placeholder="https://github.com/owner/repo"
            disabled={isLoading}
            className="w-full px-0 py-2.5 bg-transparent border-b border-b-zinc-700 focus:border-b-white text-white placeholder-zinc-700 focus:outline-none transition disabled:opacity-50 text-sm"
          />
          <button
            type="button"
            onClick={() => { setShowGithub(false); setGithubUrl(""); }}
            className="text-xs text-zinc-700 hover:text-zinc-400 transition"
          >
            - Remove GitHub repo
          </button>
        </div>
      ) : (
        <button
          type="button"
          onClick={() => setShowGithub(true)}
          className="text-xs text-zinc-700 hover:text-zinc-400 transition"
        >
          + Add GitHub repo
        </button>
      )}

      <button
        type="submit"
        disabled={isLoading || !url}
        className="w-full bg-white text-black font-semibold disabled:bg-zinc-800 disabled:text-zinc-600 disabled:cursor-not-allowed px-8 py-3.5 text-sm tracking-wider uppercase transition"
      >
        Start scan
      </button>
    </form>
  );
}
