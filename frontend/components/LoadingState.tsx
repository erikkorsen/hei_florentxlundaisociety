"use client";

import { useEffect, useState } from "react";

const CHECKS = [
  { label: "Probing for exposed secret files",  delay: 600   },
  { label: "Checking SSL certificate",           delay: 1800  },
  { label: "Scanning for open ports",            delay: 3200  },
  { label: "Inspecting admin panels",            delay: 4600  },
  { label: "Analysing HTTP security headers",    delay: 6000  },
  { label: "Checking DNS & email records",       delay: 7200  },
  { label: "Inspecting cookies",                 delay: 8400  },
  { label: "Testing CORS policy",                delay: 9600  },
  { label: "Scanning subdomains",                delay: 11000 },
  { label: "Checking for data breaches",         delay: 12400 },
  { label: "Scanning GitHub workflows",          delay: 13800 },
];

export default function LoadingState({ fixedMessage }: { fixedMessage?: string }) {
  const [done, setDone] = useState<Set<number>>(new Set());

  useEffect(() => {
    if (fixedMessage) {
      setDone(new Set(CHECKS.map((_, i) => i)));
      return;
    }
    setDone(new Set());
    const timers = CHECKS.map((c, i) =>
      setTimeout(() => setDone(prev => new Set([...prev, i])), c.delay)
    );
    return () => timers.forEach(clearTimeout);
  }, [fixedMessage]);

  const total = CHECKS.length;
  const completedCount = done.size;
  const percentage = Math.round((completedCount / total) * 100);
  const allDone = completedCount === total;

  const activeIndex = allDone ? -1 : completedCount;

  return (
    <div className="w-full max-w-lg mx-auto py-12 font-mono">
      {/* Header line */}
      {!fixedMessage && (
        <p className="text-sm text-white mb-3">&gt; Running security scan...</p>
      )}

      {/* Progress bar — 1px tall, scanning phase only */}
      {!fixedMessage && (
        <div className="h-px w-full bg-zinc-800 mb-6 overflow-hidden">
          <div
            className="h-full bg-white transition-all duration-500 ease-out"
            style={{ width: `${percentage}%` }}
          />
        </div>
      )}

      {/* Checklist */}
      <div className="space-y-1">
        {CHECKS.map((c, i) => {
          const isDone = done.has(i);
          const isActive = i === activeIndex;
          const isPending = !isDone && !isActive;

          return (
            <div key={i} className="text-sm leading-relaxed">
              {isDone ? (
                <span className="text-zinc-600">
                  <span className="text-zinc-500">[done]</span> {c.label}
                </span>
              ) : isActive ? (
                <span className="text-white">
                  <span className="animate-pulse">[....]</span> {c.label}
                </span>
              ) : (
                <span className="text-zinc-800">
                  [{"    "}] {c.label}
                </span>
              )}
            </div>
          );
        })}
      </div>

      {/* Analysis phase */}
      {fixedMessage && (
        <div className="mt-8">
          <p className="text-sm text-white">
            &gt; Analyzing results... <span className="cursor-blink">_</span>
          </p>
        </div>
      )}
    </div>
  );
}
