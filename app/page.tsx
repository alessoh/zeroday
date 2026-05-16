"use client";

import { useState, useRef, useCallback } from "react";
import PipelineForm from "@/components/PipelineForm";
import ProgressPanel from "@/components/ProgressPanel";
import ResultsPanel from "@/components/ResultsPanel";
import type { Stage, StageId, StageStatus, SSEEvent, PipelineResult } from "@/types";

const STAGE_ORDER: StageId[] = [
  "advisory_parsed",
  "repository_scanned",
  "reachability_analyzed",
  "patch_generated",
  "tests_run",
  "pull_request_drafted",
];

const STAGE_LABELS: Record<StageId, string> = {
  advisory_parsed: "Advisory Parsed",
  repository_scanned: "Repository Scanned",
  reachability_analyzed: "Reachability Analyzed",
  patch_generated: "Patch Generated",
  tests_run: "Tests Run",
  pull_request_drafted: "Pull Request Drafted",
};

function makeInitialStages(): Stage[] {
  return STAGE_ORDER.map((id) => ({
    id,
    label: STAGE_LABELS[id],
    status: "pending" as StageStatus,
  }));
}

export default function Home() {
  const [stages, setStages] = useState<Stage[]>(makeInitialStages());
  const [isRunning, setIsRunning] = useState(false);
  const [startTime, setStartTime] = useState<number | null>(null);
  const [endTime, setEndTime] = useState<number | null>(null);
  const [result, setResult] = useState<PipelineResult | null>(null);
  const [hasRun, setHasRun] = useState(false);
  const [globalError, setGlobalError] = useState<string | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  const updateStage = useCallback(
    (stageId: string, status: StageStatus, message?: string) => {
      setStages((prev) =>
        prev.map((s) =>
          s.id === stageId ? { ...s, status, message } : s
        )
      );
    },
    []
  );

  const handleStart = useCallback(
    async (repoUrl: string, cveId: string) => {
      setStages(makeInitialStages());
      setResult(null);
      setGlobalError(null);
      setHasRun(true);
      setIsRunning(true);
      setEndTime(null);
      const now = Date.now();
      setStartTime(now);

      abortControllerRef.current = new AbortController();

      try {
        const response = await fetch("/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ repo_url: repoUrl, cve_id: cveId }),
          signal: abortControllerRef.current.signal,
        });

        if (!response.ok) {
          throw new Error(
            `Server responded with ${response.status} ${response.statusText}`
          );
        }

        const reader = response.body?.getReader();
        if (!reader) throw new Error("Response stream unavailable");

        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });

          // SSE frames are delimited by double newlines
          const frames = buffer.split("\n\n");
          buffer = frames.pop() ?? "";

          for (const frame of frames) {
            const dataLine = frame
              .split("\n")
              .find((l) => l.startsWith("data: "));
            if (!dataLine) continue;

            try {
              const event = JSON.parse(dataLine.slice(6)) as SSEEvent;

              if (event.stage !== "error" && event.status) {
                updateStage(event.stage, event.status, event.message);
              }

              if (
                event.stage === "pull_request_drafted" &&
                event.status === "complete" &&
                event.data
              ) {
                setResult({
                  patch: event.data.patch,
                  prTitle: event.data.prTitle,
                  prDescription: event.data.prDescription,
                });
              }
            } catch {
              // Silently skip malformed SSE frames
            }
          }
        }
      } catch (err) {
        if (err instanceof Error && err.name === "AbortError") {
          setGlobalError("Pipeline cancelled by user.");
        } else {
          const msg = err instanceof Error ? err.message : "Unknown error";
          setGlobalError(msg);
          setStages((prev) =>
            prev.map((s) =>
              s.status === "running"
                ? { ...s, status: "error", message: msg }
                : s
            )
          );
        }
      } finally {
        setIsRunning(false);
        setEndTime(Date.now());
      }
    },
    [updateStage]
  );

  const handleStop = useCallback(() => {
    abortControllerRef.current?.abort();
  }, []);

  return (
    <main className="min-h-screen bg-zinc-950">
      <div className="max-w-3xl mx-auto px-4 py-14">
        {/* ── Header ── */}
        <header className="mb-12 text-center">
          <div className="inline-flex items-center gap-2 mb-1">
            <span className="text-emerald-500 text-2xl select-none">⬡</span>
            <h1 className="text-4xl font-mono font-bold tracking-tight text-zinc-50">
              ZeroDay
            </h1>
          </div>
          <p className="mt-1 text-xs font-mono text-zinc-500 uppercase tracking-[0.25em]">
            CVE Patch Sprinter
          </p>
        </header>

        {/* ── Input Form ── */}
        <PipelineForm
          isRunning={isRunning}
          onStart={handleStart}
          onStop={handleStop}
        />

        {/* ── Global error banner (network / server errors) ── */}
        {globalError && !isRunning && (
          <div className="mt-4 px-4 py-3 bg-red-950 border border-red-800 rounded-lg text-red-300 text-sm font-mono">
            {globalError}
          </div>
        )}

        {/* ── Pipeline Progress ── */}
        {hasRun && (
          <div className="mt-6">
            <ProgressPanel
              stages={stages}
              isRunning={isRunning}
              startTime={startTime}
              endTime={endTime}
            />
          </div>
        )}

        {/* ── Results ── */}
        {result && (
          <div className="mt-6">
            <ResultsPanel result={result} />
          </div>
        )}
      </div>
    </main>
  );
}
