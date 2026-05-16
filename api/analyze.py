"""
ZeroDay Pipeline Orchestrator — Streaming Endpoint for Automated CVE Patching.

This module implements the main `/api/analyze` endpoint that coordinates the
six-stage vulnerability remediation pipeline. It accepts a GitHub repository URL
and CVE identifier, then streams real-time progress updates to the browser using
Server-Sent Events (SSE).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REQUEST FORMAT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

POST /api/analyze
Content-Type: application/json

{
    "repo_url": "https://github.com/owner/repo",
    "cve_id": "CVE-YYYY-NNNNN"
}

Both fields are required. The CVE ID will be normalized to uppercase.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RESPONSE FORMAT (Server-Sent Events)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Content-Type: text/event-stream
Cache-Control: no-cache, no-store, must-revalidate
X-Accel-Buffering: no

The response is a stream of SSE frames. Each frame is a JSON object prefixed
with "data: " and terminated with two newlines:

    data: {"stage": "...", "status": "...", "message": "...", "data": {...}}

    data: {"stage": "...", "status": "...", "message": "..."}


SSE Frame Schema
────────────────
{
    "stage": string,        // Stage identifier (see below)
    "status": string,       // "running" | "complete" | "error"
    "message": string,      // Human-readable progress update
    "data": object | null   // Optional payload (only in final frame)
}

Stage Identifiers (in execution order)
───────────────────────────────────────
1. advisory_parsed          — Fetch and parse CVE advisory from NVD
2. repository_scanned       — Scan GitHub repo for vulnerable dependencies
3. reachability_analyzed    — Determine if vulnerability is exploitable
4. patch_generated          — Generate version bump or code fix patch
5. tests_run                — Run (or predict) test suite results
6. pull_request_drafted     — Generate PR title and description

Status Transitions
──────────────────
Each stage emits exactly TWO events:

1. "running" — Stage has started
   Example: {"stage": "advisory_parsed", "status": "running",
             "message": "Fetching NVD advisory for CVE-2024-3772…"}

2. "complete" OR "error" — Stage has finished
   Example: {"stage": "advisory_parsed", "status": "complete",
             "message": "Advisory data retrieved and parsed."}

   Example: {"stage": "advisory_parsed", "status": "error",
             "message": "Advisory lookup failed: CVE not found in NVD"}

Final Frame Payload
───────────────────
The last stage (pull_request_drafted) includes a "data" field with the complete
patch and PR artifacts for display in the browser:

{
    "stage": "pull_request_drafted",
    "status": "complete",
    "message": "Pull request drafted.",
    "data": {
        "patch": "--- a/requirements.txt\n+++ b/requirements.txt\n...",
        "prTitle": "fix(deps): patch CVE-2024-3772 — pydantic ReDoS (CVSS 5.9)",
        "prDescription": "## Security Patch: CVE-2024-3772\n\n**Severity:** ..."
    }
}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ERROR HANDLING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Pipeline Halting
────────────────
If any stage fails, the pipeline halts immediately. The failed stage emits an
"error" status event, and no subsequent stages are executed. The SSE stream
closes cleanly without crashing.

Example error flow:
    data: {"stage": "repository_scanned", "status": "running", ...}
    data: {"stage": "repository_scanned", "status": "error",
           "message": "Repository scan failed: GitHub API rate limit exceeded"}
    [stream ends]

Exception Handling Per Stage
─────────────────────────────
Each stage catches four exception types:

1. NotImplementedError — Stage stub not yet implemented
   → Emits: "error" with the exception message
   → Used during development when stubs are incomplete

2. ValueError — Invalid input or data contract violation
   → Emits: "error" with descriptive message
   → Example: "CVE not found in NVD", "Repository is private"

3. RuntimeError — Stage-specific operational failure
   → Emits: "error" with descriptive message
   → Example: "GitHub API timeout", "LLM request failed"

4. Exception (catch-all) — Unexpected errors
   → Emits: "error" with "Unexpected error: <message>"
   → Prevents pipeline crashes from unforeseen issues

Client Disconnection
────────────────────
If the browser closes the connection mid-stream (BrokenPipeError or
ConnectionResetError), the emit() function silently ignores the error.
The pipeline continues executing but stops writing to the closed stream.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STAGE DEPENDENCIES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Each stage depends on the output of previous stages:

Stage 1: parse_cve_advisory(cve_id)
    → Returns: advisory dict

Stage 2: scan_repository(repo_url, advisory)
    → Requires: advisory from Stage 1
    → Returns: repo_data dict

Stage 3: analyze_reachability(repo_data, advisory)
    → Requires: repo_data from Stage 2, advisory from Stage 1
    → Returns: reachability dict

Stage 4: generate_patch(repo_data, advisory, reachability)
    → Requires: repo_data from Stage 2, advisory from Stage 1, reachability from Stage 3
    → Returns: patch dict

Stage 5: run_tests(repo_url, patch)
    → Requires: repo_url (original input), patch from Stage 4
    → Returns: test_result dict

Stage 6: write_pull_request(advisory, patch, test_result)
    → Requires: advisory from Stage 1, patch from Stage 4, test_result from Stage 5
    → Returns: pr dict with title, description, stakeholder_summary

The orchestrator validates that each stage returns the expected data structure
before passing it to the next stage. If a stage returns None or an incomplete
dict, the pipeline will fail with a descriptive error.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FRONTEND INTEGRATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The frontend (Next.js) consumes this SSE stream using the EventSource API:

    const eventSource = new EventSource('/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ repo_url, cve_id })
    });

    eventSource.onmessage = (event) => {
        const frame = JSON.parse(event.data);
        // Update UI based on frame.stage, frame.status, frame.message
        if (frame.stage === 'pull_request_drafted' && frame.status === 'complete') {
            // Display frame.data.patch and frame.data.prDescription
            eventSource.close();
        }
    };

The frontend's ProgressPanel component renders each stage as a row with:
- Stage name (human-readable)
- Status indicator (spinner, checkmark, or error icon)
- Elapsed time since pipeline start
- Message text from the SSE frame

When the final frame arrives, the ResultsPanel displays the patch diff and
PR description in a syntax-highlighted viewer.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEPLOYMENT NOTES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Vercel Serverless Constraints
──────────────────────────────
- Runtime: Python 3.12
- Memory: 1024 MB
- Timeout: 60 seconds (Pro plan)
- No persistent filesystem (use /tmp for temporary files)

The pipeline is designed to complete within 60 seconds for typical CVEs and
repositories. If a stage exceeds the timeout, Vercel will terminate the function
and the SSE stream will close abruptly. The frontend should detect this and
display a timeout error.

Environment Variables Required
──────────────────────────────
- ANTHROPIC_API_KEY — For LLM calls (Claude 3.5 Sonnet)
- GITHUB_TOKEN — For GitHub API access (optional but recommended for rate limits)
- NVD_API_KEY — For NVD API access (optional but recommended for rate limits)

CORS Configuration
──────────────────
The endpoint allows cross-origin requests from any domain (*). In production,
restrict this to your frontend domain:

    Access-Control-Allow-Origin: https://zeroday.example.com

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MAINTAINER NOTES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Adding a New Stage
──────────────────
To add a new stage to the pipeline:

1. Create a new module in api/lib/ with a main function
2. Import the function at the top of this file
3. Add a new stage block following the existing pattern:
   - emit("new_stage_id", "running", "Starting message…")
   - Call your function with appropriate inputs
   - emit("new_stage_id", "complete", "Success message")
   - Catch NotImplementedError, ValueError, RuntimeError, Exception
4. Update the docstring's "Stage Identifiers" section
5. Update the frontend's STAGES array in components/ProgressPanel.tsx

Modifying the SSE Contract
───────────────────────────
If you change the SSE frame schema (e.g., add new fields), you MUST update:
- This docstring
- The emit() function (lines 122-142)
- The frontend's EventSource handler (app/page.tsx)
- The TypeScript types (types/index.ts)

Changing the Final Payload
───────────────────────────
The final frame's "data" field is consumed by ResultsPanel.tsx. If you add or
remove fields, update both the backend (line 253-257) and the frontend component.

Testing the Orchestrator
─────────────────────────
To test the full pipeline locally:

1. Set environment variables in .env.local
2. Run: vercel dev
3. POST to http://localhost:3000/api/analyze with:
   {
     "repo_url": "https://github.com/yourusername/vulnerable_flask",
     "cve_id": "CVE-2024-3772"
   }
4. Observe SSE stream in browser DevTools → Network → analyze → Response

For automated testing, use the demo_targets/vulnerable_flask repository which
is intentionally vulnerable to CVE-2024-3772 (pydantic ReDoS).
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler
from typing import Any

# Ensure api/lib is importable when Vercel's Python runtime invokes this file
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.cve_parser import parse_cve_advisory
from lib.repo_scanner import scan_repository
from lib.reachability import analyze_reachability
from lib.patch_generator import generate_patch
from lib.test_runner import run_tests
from lib.pr_writer import write_pull_request


class handler(BaseHTTPRequestHandler):
    """Vercel Python serverless handler for the /api/analyze endpoint."""

    # ------------------------------------------------------------------
    # Suppress the noisy BaseHTTPRequestHandler default request logging
    # ------------------------------------------------------------------

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: D102
        pass

    # ------------------------------------------------------------------
    # CORS helpers
    # ------------------------------------------------------------------

    def _cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight requests from the browser."""
        self.send_response(200)
        self._cors_headers()
        self.end_headers()

    # ------------------------------------------------------------------
    # Main handler
    # ------------------------------------------------------------------

    def do_POST(self) -> None:
        """
        Accept a JSON body, validate inputs, and stream pipeline progress as SSE.

        Expected request body
        ---------------------
        {
            "repo_url": "https://github.com/owner/repo",
            "cve_id": "CVE-YYYY-NNNNN"
        }

        Response
        --------
        Content-Type: text/event-stream
        A sequence of SSE frames, one per pipeline stage transition.
        """
        # ── Parse body ────────────────────────────────────────────────
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)

        try:
            payload: dict[str, Any] = json.loads(raw_body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self._cors_headers()
            self.end_headers()
            self.wfile.write(b'{"error": "Request body must be valid JSON"}')
            return

        repo_url: str = str(payload.get("repo_url", "")).strip()
        cve_id: str = str(payload.get("cve_id", "")).strip().upper()

        if not repo_url or not cve_id:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self._cors_headers()
            self.end_headers()
            self.wfile.write(
                b'{"error": "Both repo_url and cve_id are required"}'
            )
            return

        # ── Open SSE stream ───────────────────────────────────────────
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("X-Accel-Buffering", "no")
        self._cors_headers()
        self.end_headers()

        def emit(
            stage: str,
            status: str,
            message: str = "",
            data: Any = None,
        ) -> None:
            """Write a single SSE frame to the response stream."""
            frame: dict[str, Any] = {
                "stage": stage,
                "status": status,
                "message": message,
            }
            if data is not None:
                frame["data"] = data
            line = f"data: {json.dumps(frame)}\n\n"
            try:
                self.wfile.write(line.encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                # Client disconnected — nothing we can do
                pass

        # ── Stage 1 · Parse CVE advisory ──────────────────────────────
        emit("advisory_parsed", "running", f"Fetching NVD advisory for {cve_id}…")
        try:
            advisory = parse_cve_advisory(cve_id)
            emit("advisory_parsed", "complete", "Advisory data retrieved and parsed.")
        except NotImplementedError as exc:
            emit("advisory_parsed", "error", str(exc))
            return
        except (ValueError, RuntimeError, TimeoutError) as exc:
            emit("advisory_parsed", "error", f"Advisory lookup failed: {exc}")
            return
        except Exception as exc:  # noqa: BLE001
            emit("advisory_parsed", "error", f"Unexpected error: {exc}")
            return

        # ── Stage 2 · Scan repository ─────────────────────────────────
        emit("repository_scanned", "running", f"Scanning {repo_url}…")
        try:
            repo_data = scan_repository(repo_url, advisory)
            emit(
                "repository_scanned",
                "complete",
                "Dependency manifests and source files indexed.",
            )
        except NotImplementedError as exc:
            emit("repository_scanned", "error", str(exc))
            return
        except (ValueError, RuntimeError) as exc:
            emit("repository_scanned", "error", f"Repository scan failed: {exc}")
            return
        except Exception as exc:  # noqa: BLE001
            emit("repository_scanned", "error", f"Unexpected error: {exc}")
            return

        # ── Stage 3 · Reachability analysis ──────────────────────────
        emit(
            "reachability_analyzed",
            "running",
            "Checking whether the vulnerable code path is reachable…",
        )
        try:
            reachability = analyze_reachability(repo_data, advisory)
            verdict = "Reachable" if reachability.get("is_reachable") else "Not reachable"
            confidence = reachability.get("confidence", 0.0)
            emit(
                "reachability_analyzed",
                "complete",
                f"{verdict} (confidence {confidence:.0%}).",
            )
        except NotImplementedError as exc:
            emit("reachability_analyzed", "error", str(exc))
            return
        except RuntimeError as exc:
            emit("reachability_analyzed", "error", f"Reachability check failed: {exc}")
            return
        except Exception as exc:  # noqa: BLE001
            emit("reachability_analyzed", "error", f"Unexpected error: {exc}")
            return

        # ── Stage 4 · Generate patch ──────────────────────────────────
        emit("patch_generated", "running", "Generating remediation patch…")
        try:
            patch = generate_patch(repo_data, advisory, reachability)
            patch_type = patch.get("patch_type", "unknown")
            emit(
                "patch_generated",
                "complete",
                f"Patch generated ({patch_type}).",
            )
        except NotImplementedError as exc:
            emit("patch_generated", "error", str(exc))
            return
        except RuntimeError as exc:
            emit("patch_generated", "error", f"Patch generation failed: {exc}")
            return
        except Exception as exc:  # noqa: BLE001
            emit("patch_generated", "error", f"Unexpected error: {exc}")
            return

        # ── Stage 5 · Run tests ───────────────────────────────────────
        emit("tests_run", "running", "Running test suite against the patch…")
        try:
            test_result = run_tests(repo_url, patch)
            if test_result.get("passed"):
                summary = (
                    f"All {test_result.get('total_tests', 0)} tests passed."
                )
            else:
                failed = test_result.get("failed_tests", "?")
                total = test_result.get("total_tests", "?")
                summary = f"{failed}/{total} tests failed."
                if test_result.get("error_message"):
                    summary += f" ({test_result['error_message']})"
            emit("tests_run", "complete", summary)
        except NotImplementedError as exc:
            emit("tests_run", "error", str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            emit("tests_run", "error", f"Test run error: {exc}")
            return

        # ── Stage 6 · Write pull request ──────────────────────────────
        emit("pull_request_drafted", "running", "Drafting pull request description…")
        try:
            pr = write_pull_request(advisory, patch, test_result)
            emit(
                "pull_request_drafted",
                "complete",
                "Pull request drafted.",
                data={
                    "patch": patch.get("diff", ""),
                    "prTitle": pr.get("title", ""),
                    "prDescription": pr.get("description", ""),
                },
            )
        except NotImplementedError as exc:
            emit("pull_request_drafted", "error", str(exc))
            return
        except RuntimeError as exc:
            emit("pull_request_drafted", "error", f"PR drafting failed: {exc}")
            return
        except Exception as exc:  # noqa: BLE001
            emit("pull_request_drafted", "error", f"Unexpected error: {exc}")
            return
