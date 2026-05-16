# IBM Bob Handoff Document

This document lists every stub function that IBM Bob should implement, in the
recommended implementation order. Each entry describes what the function does,
what data it consumes, what data it produces, and which other modules it
depends on.

Implement the functions in the order listed below. Each function's output
becomes the next function's input, so a working end-to-end pipeline is
assembled incrementally.

---

## 1. `api/lib/cve_parser.py` — `parse_cve_advisory(cve_id: str) -> dict`

**What it does:** Fetches raw JSON from the National Vulnerability Database
and distils it into the canonical advisory shape used by every other pipeline
stage. This is the entry point for all vulnerability intelligence in the
system.

**What it consumes:** A CVE identifier string such as `"CVE-2024-3772"`. It
passes this to `lib.nvd_client.get_advisory(cve_id)`, which returns the raw
NVD `cve` object as a Python dictionary.

**What it produces:** A flat dictionary with keys `cve_id` (str), `description`
(str, English-language), `severity` (str — one of CRITICAL/HIGH/MEDIUM/LOW/NONE),
`cvss_score` (float 0.0–10.0), `affected_packages` (list of dicts with vendor,
product, version_start, version_end), `cwe_ids` (list of str), and `references`
(list of URL strings). This dictionary is passed to every downstream stage.

**Depends on:** `lib.nvd_client.get_advisory` — already implemented. No LLM
calls are needed; this function is pure data extraction from the NVD JSON
schema. See the detailed field-by-field extraction notes in the function's
docstring comment block.

---

## 2. `api/lib/repo_scanner.py` — `scan_repository(repo_url, advisory) -> dict`

**What it does:** Reads the target GitHub repository to find the files most
relevant to the vulnerability: dependency manifests (requirements.txt,
package.json, go.mod, etc.) and source files that import or reference the
affected package. The scan is scoped so it does not fetch the entire codebase.

**What it consumes:** `repo_url` (str, HTTPS GitHub URL) and `advisory` (the
dict produced by `parse_cve_advisory`). The advisory is used to determine
which package name to search for and which file extensions to prioritise.

**What it produces:** A dictionary with keys `repo_url` (str), `metadata`
(dict, raw GitHub API repo object), `dependency_files` (dict mapping file
path → content for manifests), `source_files` (dict mapping file path →
content for source files that reference the affected package),
`primary_language` (str), and `affected_package_name` (str). This is the
`repo_data` dict passed to stages 3, 4, and 5.

**Depends on:** `lib.github_client.get_repo_metadata`, `lib.github_client.list_repo_files`,
and `lib.github_client.get_file_contents` — all already implemented. No LLM
calls are needed. See the step-by-step notes in the function's docstring
comment block for language detection, manifest file selection, and source file
filtering logic.

---

## 3. `api/lib/reachability.py` — `analyze_reachability(repo_data, advisory) -> dict`

**What it does:** Determines whether the vulnerable code path described in the
advisory is actually exercised by the target application. An LLM reviews the
source files that import the affected package and decides (with a confidence
score) whether the specific vulnerable API surface is called.

**What it consumes:** `repo_data` (from `scan_repository`) and `advisory`
(from `parse_cve_advisory`). The key fields used are `repo_data["source_files"]`,
`repo_data["dependency_files"]`, `repo_data["affected_package_name"]`, and
`advisory["description"]`.

**What it produces:** A dictionary with keys `is_reachable` (bool), `confidence`
(float 0.0–1.0), `reasoning` (str, plain English explanation), `reachable_files`
(list of file paths), and `call_chain` (list of function/module names from
entry point to vulnerable call site). This dict is passed to `generate_patch`
and influences the PR description.

**Depends on:** `lib.llm_client.complete` — already implemented. The
implementation should include a fast heuristic short-circuit (no LLM call) when
the affected package is not present in any manifest. See the detailed prompt
construction notes in the function's docstring comment block.

---

## 4. `api/lib/patch_generator.py` — `generate_patch(repo_data, advisory, reachability) -> dict`

**What it does:** Produces a concrete patch that remediates the vulnerability.
For CVEs in third-party dependencies with a known fixed version, it generates
a version-bump diff against the dependency manifest. For CVEs in application
code, or when no fixed version is known, it generates a code-level fix using
the LLM.

**What it consumes:** `repo_data` (from `scan_repository`), `advisory` (from
`parse_cve_advisory`), and `reachability` (from `analyze_reachability`). Key
fields: `repo_data["dependency_files"]`, `repo_data["source_files"]`,
`advisory["affected_packages"]`, `advisory["references"]`,
`reachability["reachable_files"]`.

**What it produces:** A dictionary with keys `patch_type` (str — `"version_bump"`
or `"code_fix"`), `diff` (str — complete unified diff, ready for `git apply`),
`changed_files` (list of str), `patched_version` (str or None), and
`explanation` (str). The `diff` and explanation are shown in the browser's
results panel and included in the PR description.

**Depends on:** `lib.llm_client.complete` — for determining the safe version and
generating code-level fixes. The Python standard library's `difflib.unified_diff`
should be used to produce diffs. See the full strategy decision tree in the
function's docstring comment block.

---

## 5. `api/lib/test_runner.py` — `run_tests(repo_url, patch) -> dict`

**What it does:** Validates that the patch does not break the target repository's
existing test suite. It clones the repository into a temporary directory,
applies the generated diff, detects the test framework (pytest, npm test, go
test, etc.), installs dependencies, runs the tests with a timeout, and returns
structured pass/fail counts.

**What it consumes:** `repo_url` (str) and `patch` (from `generate_patch`).
The primary field used is `patch["diff"]`, the unified diff string to apply
with `git apply`.

**What it produces:** A dictionary with keys `passed` (bool), `total_tests`
(int), `passed_tests` (int), `failed_tests` (int), `test_output` (str, raw
stdout+stderr), and `error_message` (str or None). This function is designed
never to raise — all failures are returned in `error_message`.

**Depends on:** Standard library only — `subprocess`, `tempfile`, `shutil`,
`os`, `re`. No LLM calls and no external packages are required. The clone must
use `--depth 1` for speed, and the test run must enforce a 120-second timeout.
See the full framework detection logic and output-parsing patterns in the
function's docstring comment block.

---

## 6. `api/lib/pr_writer.py` — `write_pull_request(advisory, patch, test_result) -> dict`

**What it does:** Composes a professional GitHub pull request title, body, and
rollback plan using the LLM. The PR description includes a vulnerability
summary, patch explanation, a test results table, a step-by-step rollback plan,
a CVE reference with CVSS score, and a ZeroDay attribution footer.

**What it consumes:** `advisory` (from `parse_cve_advisory`), `patch` (from
`generate_patch`), and `test_result` (from `run_tests`). Key fields: `advisory["cve_id"]`,
`advisory["severity"]`, `advisory["cvss_score"]`, `advisory["description"]`,
`advisory["references"]`, `patch["patch_type"]`, `patch["explanation"]`,
`patch["diff"]`, `test_result["passed"]`, `test_result["passed_tests"]`,
`test_result["failed_tests"]`, `test_result["total_tests"]`.

**What it produces:** A dictionary with keys `title` (str, Conventional Commits
format), `description` (str, GitHub-flavoured Markdown), `rollback_plan`
(str, Markdown), and `labels` (list of str). The `title` and `description` are
rendered directly in the browser's results panel.

**Depends on:** `lib.llm_client.complete` — for drafting the description. The
LLM should be instructed to respond in JSON so the values can be parsed
deterministically. Always append a standard ZeroDay + NVD footer to the
description. See the full prompt template and fallback parsing strategy in the
function's docstring comment block.

---

## 7. `api/analyze.py` — `handler.do_POST` (orchestrator) — review only

The orchestrating SSE handler is already implemented. After completing steps
1–6, Bob should verify that:

1. Every import at the top of `api/analyze.py` resolves to the now-implemented
   functions.
2. The data contracts match: each stage's return dict contains the keys that
   the next stage's `emit(...)` call and the subsequent function call expect.
   Specifically, confirm that:
   - `parse_cve_advisory` → `advisory` dict with `cve_id`, `description`, etc.
   - `scan_repository` → `repo_data` dict with `dependency_files`, `source_files`, etc.
   - `analyze_reachability` → dict with `is_reachable`, `confidence`, etc.
   - `generate_patch` → dict with `patch_type`, `diff`, `explanation`, etc.
   - `run_tests` → dict with `passed`, `total_tests`, `failed_tests`, etc.
   - `write_pull_request` → dict with `title`, `description`, `rollback_plan`.
3. The final `emit("pull_request_drafted", "complete", ..., data={...})` call
   populates `patch`, `prTitle`, and `prDescription` from the correct keys in
   the `patch` and `pr` dicts — cross-reference with `types/index.ts`:`SSEPayload`.

No changes to `analyze.py` should be needed beyond this verification.

---

## Quick-Reference: Data Flow

```
parse_cve_advisory(cve_id)
        │ advisory
        ▼
scan_repository(repo_url, advisory)
        │ repo_data
        ▼
analyze_reachability(repo_data, advisory)
        │ reachability
        ▼
generate_patch(repo_data, advisory, reachability)
        │ patch
        ▼
run_tests(repo_url, patch)
        │ test_result
        ▼
write_pull_request(advisory, patch, test_result)
        │ pr  →  streamed to browser as SSE "data" payload
```

---

## Shared Infrastructure (already complete — do not modify)

| File | Status | Purpose |
|------|--------|---------|
| `api/lib/llm_client.py` | ✅ Complete | Anthropic SDK wrapper — `complete()` and `stream_complete()` |
| `api/lib/github_client.py` | ✅ Complete | GitHub REST API — `get_file_contents()`, `list_repo_files()`, `get_repo_metadata()` |
| `api/lib/nvd_client.py` | ✅ Complete | NVD API — `get_advisory()` |
| `api/analyze.py` | ✅ Complete | SSE orchestrator — do not modify, only verify |
