"use client";

import DiffViewer from "./DiffViewer";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { PipelineResult } from "@/types";

interface ResultsPanelProps {
  result: PipelineResult;
}

function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <div className="px-5 py-3 border-b border-zinc-800">
      <span className="font-mono text-[11px] text-zinc-500 uppercase tracking-widest">
        {children}
      </span>
    </div>
  );
}

export default function ResultsPanel({ result }: ResultsPanelProps) {
  return (
    <div className="space-y-5">
      {/* Generated Patch */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
        <SectionHeader>Generated Patch</SectionHeader>
        <DiffViewer patch={result.patch} />
      </div>

      {/* Pull Request */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
        <SectionHeader>
          {result.prTitle ? `Pull Request — ${result.prTitle}` : "Pull Request"}
        </SectionHeader>
        <div className="px-6 py-5 md">
          {result.prDescription ? (
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {result.prDescription}
            </ReactMarkdown>
          ) : (
            <p className="text-zinc-600 text-sm font-mono italic">
              No pull request description generated.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
