"""
Main streaming endpoint for the ZeroDay pipeline.

POST /api/analyze
  Body: { "repo_url": "https://github.com/owner/repo", "cve_id": "CVE-YYYY-NNNNN" }
  Response: text/event-stream — a sequence of Server-Sent Events reporting the
            progress and final results of the six-stage pipeline.

SSE event format (one JSON object per ``data:`` line):
  data: {"stage": "<stage_id>", "status": "running|complete|error",
          "message": "<human-readable update>", "data": <optional payload>}

Stage IDs (in order):
  advisory_parsed, repository_scanned, reachability_analyzed,
  patch_generated, tests_run, pull_request_drafted

The function is designed so that each stage is called through its stub module.
Until IBM Bob implements those stubs, every stage will emit an "error" status
with the NotImplementedError message and the stream will terminate after the
first unimplemented stage.
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
