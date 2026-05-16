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
    const id = setInterval(tick, 100);
    return () => clearInterval(id);
  }, [startTime, endTime, isRunning]);

  const seconds = (elapsed / 1000).toFixed(2);

  return (
    <span className="font-mono text-xs tabular-nums text-gray-500">
      {seconds}s
    </span>
  );
}
