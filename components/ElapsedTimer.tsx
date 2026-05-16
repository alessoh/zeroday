"use client";

import { useEffect, useState } from "react";

interface ElapsedTimerProps {
  startTime: number | null;
  endTime: number | null;
  isRunning: boolean;
}

export default function ElapsedTimer({
  startTime,
  endTime,
  isRunning,
}: ElapsedTimerProps) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (!startTime) {
      setElapsed(0);
      return;
    }

    if (!isRunning) {
      setElapsed((endTime ?? Date.now()) - startTime);
      return;
    }

    const tick = () => setElapsed(Date.now() - startTime);
    tick();
    const id = setInterval(tick, 50); // Update more frequently for smooth animation
    return () => clearInterval(id);
  }, [startTime, endTime, isRunning]);

  const totalSeconds = elapsed / 1000;
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = Math.floor(totalSeconds % 60);
  const centiseconds = Math.floor((totalSeconds % 1) * 100);

  // Format as MM:SS.CC (stopwatch style)
  const formatted = `${minutes.toString().padStart(2, "0")}:${seconds
    .toString()
    .padStart(2, "0")}.${centiseconds.toString().padStart(2, "0")}`;

  return (
    <div className="flex items-center gap-2">
      {isRunning && (
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse" />
      )}
      <span
        className={`font-mono text-base tabular-nums tracking-tight ${
          isRunning
            ? "text-amber-600 font-semibold"
            : "text-gray-600 font-medium"
        }`}
      >
        {formatted}
      </span>
    </div>
  );
}
