"use client";

import { useState, type FormEvent } from "react";

interface PipelineFormProps {
  isRunning: boolean;
  onStart: (repoUrl: string, cveId: string) => void;
  onStop: () => void;
}

const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/;

interface FormErrors {
  repoUrl?: string;
  cveId?: string;
}

export default function PipelineForm({
  isRunning,
  onStart,
  onStop,
}: PipelineFormProps) {
  const [repoUrl, setRepoUrl] = useState("");
  const [cveId, setCveId] = useState("");
  const [errors, setErrors] = useState<FormErrors>({});

  function validate(): boolean {
    const next: FormErrors = {};
    if (!repoUrl.match(/^https:\/\/github\.com\/[^/]+\/[^/]+/)) {
      next.repoUrl = "Must be a valid GitHub repository URL (https://github.com/owner/repo)";
    }
    if (!CVE_REGEX.test(cveId)) {
      next.cveId = "Must match format CVE-YYYY-NNNNN (e.g. CVE-2024-3772)";
    }
    setErrors(next);
    return Object.keys(next).length === 0;
  }

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (validate()) {
      onStart(repoUrl.trim(), cveId.trim());
    }
  }

  const inputBase =
    "w-full bg-zinc-950 border rounded px-3 py-2.5 font-mono text-sm text-zinc-100 " +
    "placeholder-zinc-600 focus:outline-none transition-colors disabled:opacity-40 " +
    "disabled:cursor-not-allowed";

  return (
    <form
      onSubmit={handleSubmit}
      className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 space-y-5"
    >
      {/* Repo URL */}
      <div>
        <label className="block text-[11px] font-mono text-zinc-500 uppercase tracking-widest mb-1.5">
          GitHub Repository URL
        </label>
        <input
          type="url"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          placeholder="https://github.com/owner/repo"
          disabled={isRunning}
          autoComplete="off"
          spellCheck={false}
          className={`${inputBase} ${
            errors.repoUrl
              ? "border-red-700 focus:border-red-500"
              : "border-zinc-700 focus:border-emerald-600"
          }`}
        />
        {errors.repoUrl && (
          <p className="mt-1.5 text-xs text-red-400 font-mono">
            {errors.repoUrl}
          </p>
        )}
      </div>

      {/* CVE ID */}
      <div>
        <label className="block text-[11px] font-mono text-zinc-500 uppercase tracking-widest mb-1.5">
          CVE Identifier
        </label>
        <input
          type="text"
          value={cveId}
          onChange={(e) => setCveId(e.target.value.toUpperCase())}
          placeholder="CVE-2024-3772"
          disabled={isRunning}
          autoComplete="off"
          spellCheck={false}
          className={`${inputBase} ${
            errors.cveId
              ? "border-red-700 focus:border-red-500"
              : "border-zinc-700 focus:border-emerald-600"
          }`}
        />
        {errors.cveId && (
          <p className="mt-1.5 text-xs text-red-400 font-mono">
            {errors.cveId}
          </p>
        )}
      </div>

      {/* Submit / Stop */}
      {isRunning ? (
        <button
          type="button"
          onClick={onStop}
          className="w-full py-3 px-6 bg-red-950 hover:bg-red-900 border border-red-800
                     text-red-300 font-mono font-bold text-xs uppercase tracking-widest
                     rounded-lg transition-colors"
        >
          ■ Stop
        </button>
      ) : (
        <button
          type="submit"
          className="w-full py-3 px-6 bg-emerald-950 hover:bg-emerald-900 border border-emerald-800
                     text-emerald-300 font-mono font-bold text-xs uppercase tracking-widest
                     rounded-lg transition-colors"
        >
          ▶ Start
        </button>
      )}
    </form>
  );
}
