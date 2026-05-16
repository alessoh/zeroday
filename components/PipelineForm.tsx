"use client";

import { useState, type FormEvent, useEffect } from "react";

interface PipelineFormProps {
  isRunning: boolean;
  onStart: (repoUrl: string, cveId: string) => void;
  onStop: () => void;
}

const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/i;
const GITHUB_REPO_REGEX = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+\/?$/;

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
  const [touched, setTouched] = useState({ repoUrl: false, cveId: false });

  // Clear errors when user starts typing after touching a field
  useEffect(() => {
    if (touched.repoUrl && repoUrl) {
      setErrors((prev) => ({ ...prev, repoUrl: undefined }));
    }
  }, [repoUrl, touched.repoUrl]);

  useEffect(() => {
    if (touched.cveId && cveId) {
      setErrors((prev) => ({ ...prev, cveId: undefined }));
    }
  }, [cveId, touched.cveId]);

  function validate(): boolean {
    const next: FormErrors = {};
    
    const trimmedUrl = repoUrl.trim();
    const trimmedCve = cveId.trim();

    if (!trimmedUrl) {
      next.repoUrl = "Repository URL is required";
    } else if (!GITHUB_REPO_REGEX.test(trimmedUrl)) {
      next.repoUrl = "Must be a valid GitHub repository URL (https://github.com/owner/repo)";
    }

    if (!trimmedCve) {
      next.cveId = "CVE identifier is required";
    } else if (!CVE_REGEX.test(trimmedCve)) {
      next.cveId = "Must match format CVE-YYYY-NNNNN (e.g., CVE-2024-3772)";
    }

    setErrors(next);
    return Object.keys(next).length === 0;
  }

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setTouched({ repoUrl: true, cveId: true });
    if (validate()) {
      onStart(repoUrl.trim(), cveId.trim().toUpperCase());
    }
  }

  function handleRepoUrlBlur() {
    setTouched((prev) => ({ ...prev, repoUrl: true }));
  }

  function handleCveIdBlur() {
    setTouched((prev) => ({ ...prev, cveId: true }));
  }

  const inputBase =
    "w-full bg-white border rounded-lg px-3 py-2.5 font-mono text-sm text-gray-900 " +
    "placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-offset-1 transition-all " +
    "disabled:opacity-40 disabled:cursor-not-allowed";

  const hasErrors = Object.keys(errors).length > 0;
  const isFormValid = repoUrl.trim() && cveId.trim() && !hasErrors;

  return (
    <form
      onSubmit={handleSubmit}
      className="bg-white border border-gray-200 rounded-xl p-6 space-y-5 shadow-sm"
    >
      {/* Repo URL */}
      <div>
        <label
          htmlFor="repo-url"
          className="block text-[11px] font-mono text-gray-500 uppercase tracking-widest mb-1.5"
        >
          GitHub Repository URL
        </label>
        <input
          id="repo-url"
          type="url"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          onBlur={handleRepoUrlBlur}
          placeholder="https://github.com/owner/repo"
          disabled={isRunning}
          autoComplete="off"
          spellCheck={false}
          className={`${inputBase} ${
            errors.repoUrl
              ? "border-red-400 focus:border-red-500 focus:ring-red-200"
              : "border-gray-300 focus:border-emerald-500 focus:ring-emerald-200"
          }`}
        />
        {errors.repoUrl && (
          <p className="mt-1.5 text-xs text-red-600 font-mono animate-fade-in">
            ⚠ {errors.repoUrl}
          </p>
        )}
      </div>

      {/* CVE ID */}
      <div>
        <label
          htmlFor="cve-id"
          className="block text-[11px] font-mono text-gray-500 uppercase tracking-widest mb-1.5"
        >
          CVE Identifier
        </label>
        <input
          id="cve-id"
          type="text"
          value={cveId}
          onChange={(e) => setCveId(e.target.value.toUpperCase())}
          onBlur={handleCveIdBlur}
          placeholder="CVE-2024-3772"
          disabled={isRunning}
          autoComplete="off"
          spellCheck={false}
          className={`${inputBase} ${
            errors.cveId
              ? "border-red-400 focus:border-red-500 focus:ring-red-200"
              : "border-gray-300 focus:border-emerald-500 focus:ring-emerald-200"
          }`}
        />
        {errors.cveId && (
          <p className="mt-1.5 text-xs text-red-600 font-mono animate-fade-in">
            ⚠ {errors.cveId}
          </p>
        )}
      </div>

      {/* Submit / Stop */}
      {isRunning ? (
        <button
          type="button"
          onClick={onStop}
          className="w-full py-3 px-6 bg-red-600 hover:bg-red-700 active:bg-red-800 text-white
                     font-mono font-bold text-xs uppercase tracking-widest
                     rounded-lg transition-all shadow-sm hover:shadow"
        >
          ■ Stop Pipeline
        </button>
      ) : (
        <button
          type="submit"
          disabled={!isFormValid && touched.repoUrl && touched.cveId}
          className={`w-full py-3 px-6 text-white font-mono font-bold text-xs uppercase tracking-widest
                     rounded-lg transition-all shadow-sm hover:shadow ${
                       isFormValid
                         ? "bg-emerald-600 hover:bg-emerald-700 active:bg-emerald-800"
                         : "bg-emerald-600 hover:bg-emerald-700"
                     }`}
        >
          ▶ Start Pipeline
        </button>
      )}
    </form>
  );
}
