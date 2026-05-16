"""
Determine whether the vulnerable code path is actually reachable in the
target repository.

This is the third stage of the ZeroDay pipeline. It combines LLM-assisted
code analysis with fast heuristic string matching to decide, with a confidence
score, whether the application actually calls the vulnerable API surface
described in the advisory.

Dependencies
------------
lib.llm_client.complete
"""

from __future__ import annotations

from typing import Any

from lib.llm_client import complete


def analyze_reachability(
    repo_data: dict[str, Any],
    advisory: dict[str, Any],
) -> dict[str, Any]:
    """
    Decide whether the vulnerable code path is reachable from the target repo.

    Combines LLM reasoning over source code with a simple string-match
    heuristic. Returns a structured result that guides the patch generator:
    if the vulnerability is not reachable, the patch may be a no-op or a
    dependency lock update; if it is reachable, code-level changes may be
    required.

    Parameters
    ----------
    repo_data : dict[str, Any]
        Structured repository scan result returned by ``scan_repository``.
        Must contain at least ``source_files`` (dict[str, str]),
        ``dependency_files`` (dict[str, str]), and
        ``affected_package_name`` (str).
    advisory : dict[str, Any]
        Parsed advisory from ``parse_cve_advisory``. Must contain at least
        ``description`` (str) and ``affected_packages`` (list).

    Returns
    -------
    dict[str, Any]
        A reachability analysis result with the following keys:

        is_reachable : bool
            ``True`` if the vulnerability appears to be reachable from the
            application code in ``repo_data["source_files"]``.
        confidence : float
            Confidence score in [0.0, 1.0] representing how certain the
            analysis is about the ``is_reachable`` conclusion.
        reasoning : str
            Plain-English explanation of why the path is or is not reachable,
            suitable for inclusion in the pull request description.
        reachable_files : list[str]
            File paths from ``source_files`` that directly invoke the
            vulnerable API surface.
        call_chain : list[str]
            Ordered list of function or module names from the application
            entry point down to the vulnerable call site, as reconstructed
            by the LLM. May be empty if no call chain is identifiable.

    Raises
    ------
    RuntimeError
        If the LLM call fails.
    EnvironmentError
        If ANTHROPIC_API_KEY is not set.

    Dependencies
    ------------
    lib.llm_client.complete : send a prompt and receive the full text response.
    """
    # -------------------------------------------------------------------------
    # IMPLEMENTATION NOTES FOR IBM BOB
    #
    # 1. Short-circuit heuristic (fast path):
    #    If `affected_package_name` does not appear in any value of
    #    repo_data["dependency_files"] (case-insensitive), the package is not
    #    even installed. Return is_reachable=False, confidence=0.95,
    #    reasoning="Package not found in dependency manifest.", and empty lists.
    #
    # 2. Build a system prompt that tells the LLM it is a senior security
    #    engineer performing a reachability analysis.
    #
    # 3. Build a user prompt containing:
    #    a. The CVE description from advisory["description"].
    #    b. The names of the vulnerable functions or APIs mentioned in the
    #       description (ask the LLM to identify them too, in a two-step approach
    #       if needed, or include them if identifiable from the CVE metadata).
    #    c. The content of each file in repo_data["source_files"], formatted as:
    #         --- path/to/file.py ---
    #         <content>
    #    d. Instruction to respond with a JSON object containing is_reachable
    #       (bool), confidence (float 0-1), reasoning (str), reachable_files
    #       (list[str]), and call_chain (list[str]).
    #
    # 4. Call complete(prompt, system=system_prompt) and attempt to parse the
    #    response as JSON. If parsing fails, extract values with regex fallbacks.
    #
    # 5. Heuristic cross-check:
    #    For each file in repo_data["source_files"], use a regex to search for
    #    calls to the vulnerable function name (extract it from advisory
    #    description with a simple heuristic). If the heuristic finds a match
    #    in a file that the LLM did not flag, add that file to reachable_files
    #    and set is_reachable=True.
    #
    # 6. Return the final structured dict. Clamp confidence to [0.0, 1.0].
    # -------------------------------------------------------------------------
    raise NotImplementedError("IBM Bob will implement this in a subsequent session")
