"use client";

type LineType = "add" | "remove" | "hunk" | "header" | "context";

function classifyLine(line: string): LineType {
  if (line.startsWith("+++") || line.startsWith("---")) return "header";
  if (line.startsWith("@@")) return "hunk";
  if (line.startsWith("+")) return "add";
  if (line.startsWith("-")) return "remove";
  return "context";
}

const LINE_STYLES: Record<LineType, string> = {
  add: "bg-emerald-50 text-emerald-900 border-l-2 border-emerald-400",
  remove: "bg-red-50 text-red-900 border-l-2 border-red-400",
  hunk: "bg-blue-50 text-blue-800 font-semibold border-l-2 border-blue-300",
  header: "bg-gray-50 text-gray-600 font-semibold border-l-2 border-gray-300",
  context: "text-gray-700 hover:bg-gray-50",
};

interface DiffViewerProps {
  patch: string;
}

export default function DiffViewer({ patch }: DiffViewerProps) {
  if (!patch.trim()) {
    return (
      <div className="px-5 py-4 text-gray-400 text-sm font-mono italic">
        No patch content.
      </div>
    );
  }

  const lines = patch.split("\n");

  return (
    <div className="overflow-x-auto bg-gray-900">
      <pre className="text-[13px] leading-6 font-mono">
        {lines.map((line, i) => {
          const type = classifyLine(line);
          const lineNumber = i + 1;
          
          return (
            <div
              key={i}
              className={`flex hover:bg-opacity-80 transition-colors ${LINE_STYLES[type]}`}
            >
              <span className="inline-block w-12 flex-shrink-0 text-right pr-3 text-gray-400 select-none text-xs">
                {lineNumber}
              </span>
              <span className="flex-1 px-3 whitespace-pre">
                {line || " "}
              </span>
            </div>
          );
        })}
      </pre>
    </div>
  );
}
