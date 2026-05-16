"use client";

import type { Stage, StageStatus } from "@/types";

interface StageRowProps {
  stage: Stage;
}

function StatusIcon({ status }: { status: StageStatus }) {
  if (status === "pending") {
    return (
      <span className="text-zinc-700 text-base leading-none select-none">
        ○
      </span>
    );
  }
  if (status === "running") {
    return (
      <span
        className="inline-block w-3.5 h-3.5 border-2 border-amber-400 border-t-transparent
                   rounded-full animate-spin"
        aria-label="running"
      />
    );
  }
  if (status === "complete") {
    return (
      <span className="text-emerald-400 text-base leading-none font-bold select-none">
        ✓
      </span>
    );
  }
  return (
    <span className="text-red-400 text-base leading-none font-bold select-none">
      ✗
    </span>
  );
}

const LABEL_COLOR: Record<StageStatus, string> = {
  pending: "text-zinc-600",
  running: "text-amber-300",
  complete: "text-zinc-200",
  error: "text-red-300",
};

export default function StageRow({ stage }: StageRowProps) {
  return (
    <div className="flex items-center gap-3 px-5 py-3.5">
      <div className="w-4 flex justify-center flex-shrink-0">
        <StatusIcon status={stage.status} />
      </div>

      <div className="flex-1 min-w-0 flex items-baseline gap-2">
        <span className={`font-mono text-sm ${LABEL_COLOR[stage.status]}`}>
          {stage.label}
        </span>
        {stage.message && (
          <span className="text-xs text-zinc-600 font-mono truncate">
            — {stage.message}
          </span>
        )}
      </div>
    </div>
  );
}
