"use client";

import { useEffect, useState } from "react";

const MESSAGES = [
  "Probing for exposed secret files…",
  "Scanning for open ports…",
  "Checking SSL certificate…",
  "Inspecting admin panels…",
  "Scanning GitHub workflows…",
  "Analysing results…",
];

export default function LoadingState() {
  const [index, setIndex] = useState(0);

  useEffect(() => {
    const id = setInterval(() => {
      setIndex((i) => (i + 1) % MESSAGES.length);
    }, 3000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="flex flex-col items-center justify-center gap-6 py-16 text-center">
      <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
      <p className="text-gray-400 text-sm min-h-[1.5rem] transition-all">{MESSAGES[index]}</p>
    </div>
  );
}
