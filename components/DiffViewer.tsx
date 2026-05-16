"use client";

type LineType = "add" | "remove" | "hunk" | "header" | "context";

function classifyLine(line: string): LineType {
  if (line.startsWith("+++") || line.startsWith("---")) return "header";
  if (line.startsWith("@@")) return "hunk";
  if (line.startsWith("+")) return "add";
  if (line.startsWith("-")) return "remove";
  return "context";
}

const LINE_BG: Record<LineType, string> = {
  add: "bg-emerald-50 text-emerald-800",
  remove: "bg-red-50 text-red-800",
  hunk: "bg-blue-50 text-blue-700",
  header: "text-gray-500",
  context: "text-gray-700",
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
    <div className="overflow-x-auto">
      <pre className="text-xs leading-5 font-mono">
        {lines.map((line, i) => {
          const type = classifyLine(line);
          return (
            <div
              key={i}
              className={`px-5 py-px whitespace-pre ${LINE_BG[type]}`}
            >
              {line || " "}
            </div>
          );
        })}
      </pre>
    </div>
  );
}
