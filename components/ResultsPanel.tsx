"use client";

import DiffViewer from "./DiffViewer";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { Components } from "react-markdown";
import type { PipelineResult } from "@/types";

interface ResultsPanelProps {
  result: PipelineResult;
}

function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <div className="px-5 py-3 border-b border-gray-200 bg-gray-50">
      <span className="font-mono text-[11px] text-gray-500 uppercase tracking-widest">
        {children}
      </span>
    </div>
  );
}

// Custom Markdown components for proper styling
const markdownComponents: Components = {
  h1: ({ children }) => (
    <h1 className="text-2xl font-bold text-gray-900 mt-6 mb-4 pb-2 border-b border-gray-200">
      {children}
    </h1>
  ),
  h2: ({ children }) => (
    <h2 className="text-xl font-bold text-gray-900 mt-5 mb-3">
      {children}
    </h2>
  ),
  h3: ({ children }) => (
    <h3 className="text-lg font-semibold text-gray-800 mt-4 mb-2">
      {children}
    </h3>
  ),
  p: ({ children }) => (
    <p className="text-gray-700 leading-relaxed mb-4">
      {children}
    </p>
  ),
  ul: ({ children }) => (
    <ul className="list-disc list-inside space-y-1 mb-4 text-gray-700">
      {children}
    </ul>
  ),
  ol: ({ children }) => (
    <ol className="list-decimal list-inside space-y-1 mb-4 text-gray-700">
      {children}
    </ol>
  ),
  li: ({ children }) => (
    <li className="ml-4">
      {children}
    </li>
  ),
  code: ({ inline, children, ...props }: any) => {
    if (inline) {
      return (
        <code
          className="bg-gray-100 text-red-600 px-1.5 py-0.5 rounded text-sm font-mono"
          {...props}
        >
          {children}
        </code>
      );
    }
    return (
      <code
        className="block bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-sm font-mono leading-relaxed mb-4"
        {...props}
      >
        {children}
      </code>
    );
  },
  pre: ({ children }) => (
    <pre className="mb-4">
      {children}
    </pre>
  ),
  blockquote: ({ children }) => (
    <blockquote className="border-l-4 border-gray-300 pl-4 italic text-gray-600 my-4">
      {children}
    </blockquote>
  ),
  a: ({ href, children }) => (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="text-emerald-600 hover:text-emerald-700 underline"
    >
      {children}
    </a>
  ),
  strong: ({ children }) => (
    <strong className="font-bold text-gray-900">
      {children}
    </strong>
  ),
  em: ({ children }) => (
    <em className="italic text-gray-700">
      {children}
    </em>
  ),
  hr: () => (
    <hr className="my-6 border-t border-gray-200" />
  ),
  table: ({ children }) => (
    <div className="overflow-x-auto mb-4">
      <table className="min-w-full divide-y divide-gray-200 border border-gray-200">
        {children}
      </table>
    </div>
  ),
  thead: ({ children }) => (
    <thead className="bg-gray-50">
      {children}
    </thead>
  ),
  tbody: ({ children }) => (
    <tbody className="bg-white divide-y divide-gray-200">
      {children}
    </tbody>
  ),
  tr: ({ children }) => (
    <tr>
      {children}
    </tr>
  ),
  th: ({ children }) => (
    <th className="px-4 py-2 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td className="px-4 py-2 text-sm text-gray-700">
      {children}
    </td>
  ),
};

export default function ResultsPanel({ result }: ResultsPanelProps) {
  return (
    <div className="space-y-5 animate-fade-in">
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
        <div className="px-6 py-5 prose prose-sm max-w-none">
          {result.prDescription ? (
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={markdownComponents}
            >
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
