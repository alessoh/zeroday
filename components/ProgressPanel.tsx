"use client";

import StageRow from "./StageRow";
import ElapsedTimer from "./ElapsedTimer";
import type { Stage } from "@/types";

interface ProgressPanelProps {
  stages: Stage[];
  isRunning: boolean;
  startTime: number | null;
  endTime: number | null;
}

export default function ProgressPanel({
  stages,
  isRunning,
  startTime,
  endTime,
}: ProgressPanelProps) {
  const allComplete = stages.every((s) => s.status === "complete");
  const hasError = stages.some((s) => s.status === "error");

  let statusLabel = "Waiting";
  if (isRunning) statusLabel = "Running";
  else if (allComplete) statusLabel = "Complete";
  else if (hasError) statusLabel = "Failed";

  const dotColor = isRunning
    ? "bg-amber-400 animate-pulse"
    : allComplete
    ? "bg-emerald-400"
    : hasError
    ? "bg-red-400"
    : "bg-zinc-600";

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
      {/* Header bar */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-zinc-800">
        <div className="flex items-center gap-2">
          <span className={`inline-block w-2 h-2 rounded-full ${dotColor}`} />
          <span className="font-mono text-[11px] text-zinc-500 uppercase tracking-widest">
            Pipeline · {statusLabel}
          </span>
        </div>
        <ElapsedTimer
          startTime={startTime}
          endTime={endTime}
          isRunning={isRunning}
        />
      </div>

      {/* Stage rows */}
      <div className="divide-y divide-zinc-800/60">
        {stages.map((stage) => (
          <StageRow key={stage.id} stage={stage} />
        ))}
      </div>
    </div>
  );
}
