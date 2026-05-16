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
    <div className="px-5 py-3 border-b border-gray-200">
      <span className="font-mono text-[11px] text-gray-500 uppercase tracking-widest">
        {children}
      </span>
    </div>
  );
}

export default function ResultsPanel({ result }: ResultsPanelProps) {
  return (
    <div className="space-y-5">
      {/* Generated Patch */}
      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
        <SectionHeader>Generated Patch</SectionHeader>
        <DiffViewer patch={result.patch} />
      </div>

      {/* Pull Request */}
      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
        <SectionHeader>
          {result.prTitle ? `Pull Request — ${result.prTitle}` : "Pull Request"}
        </SectionHeader>
        <div className="px-6 py-5 md">
          {result.prDescription ? (
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {result.prDescription}
            </ReactMarkdown>
          ) : (
            <p className="text-gray-400 text-sm font-mono italic">
              No pull request description generated.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
