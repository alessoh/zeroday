"""
Generate a patch (dependency version bump or code-level fix) for the
identified vulnerability.

This is the fourth stage of the ZeroDay pipeline. It decides between two fix
strategies—bumping the vulnerable package to a safe version, or modifying
the application's own source code—then produces a unified diff that can be
applied to the repository with ``git apply``.

Dependencies
------------
lib.llm_client.complete
"""

from __future__ import annotations

from typing import Any

from lib.llm_client import complete


def generate_patch(
    repo_data: dict[str, Any],
    advisory: dict[str, Any],
    reachability: dict[str, Any],
) -> dict[str, Any]:
    """
    Generate a minimal patch that remediates the vulnerability.

    Chooses between two remediation strategies:

    * **version_bump** — if the vulnerability is in a third-party dependency
      and the advisory specifies a fixed version, update the pinned version in
      the dependency manifest (e.g. ``requirements.txt``, ``package.json``).
    * **code_fix** — if the vulnerable logic is in the application's own source
      code, or if a safe version is not yet available, produce a targeted
      code-level change in the affected source files.

    Parameters
    ----------
    repo_data : dict[str, Any]
        Structured scan result from ``scan_repository``. Contains
        ``dependency_files``, ``source_files``, ``affected_package_name``,
        and ``primary_language``.
    advisory : dict[str, Any]
        Parsed advisory from ``parse_cve_advisory``. Contains
        ``affected_packages``, ``description``, ``references``, and
        ``cvss_score``.
    reachability : dict[str, Any]
        Reachability result from ``analyze_reachability``. Contains
        ``is_reachable``, ``reachable_files``, and ``call_chain``.

    Returns
    -------
    dict[str, Any]
        A structured patch result with the following keys:

        patch_type : str
            Either ``"version_bump"`` or ``"code_fix"``.
        diff : str
            The complete patch in unified diff format (output of
            ``git diff`` or ``difflib.unified_diff``), ready to be
            applied with ``git apply``.
        changed_files : list[str]
            File paths referenced in the diff headers.
        patched_version : str | None
            For ``version_bump`` patches, the recommended safe version
            string (e.g. ``"2.7.1"``). ``None`` for ``code_fix`` patches.
        explanation : str
            Plain-English explanation of what the patch changes and why
            it resolves the vulnerability.

    Raises
    ------
    RuntimeError
        If the LLM call fails or the generated diff is syntactically invalid.
    EnvironmentError
        If ANTHROPIC_API_KEY is not set.

    Dependencies
    ------------
    lib.llm_client.complete : used to determine safe version and generate diffs.
    """
    # -------------------------------------------------------------------------
    # IMPLEMENTATION NOTES FOR IBM BOB
    #
    # 1. Determine patch_type:
    #    Choose "version_bump" when:
    #      a. advisory["affected_packages"] is non-empty (the CVE is in a
    #         third-party library), AND
    #      b. repo_data["dependency_files"] contains a manifest that pins the
    #         affected package (confirmed by string search), AND
    #      c. reachability["is_reachable"] is True OR the manifest pins a
    #         version inside the vulnerable range regardless of reachability
    #         (defence-in-depth).
    #    Otherwise choose "code_fix".
    #
    # 2. For "version_bump":
    #    a. Find the manifest file that contains the vulnerable pin by scanning
    #       repo_data["dependency_files"] for repo_data["affected_package_name"].
    #    b. Determine `patched_version`:
    #       - Search advisory["references"] URLs for GitHub release pages or
    #         CHANGELOG entries; ask the LLM to extract the fixed version.
    #       - As a fallback, ask the LLM directly: "Given CVE <id> affects
    #         <package> versions up to <version_end>, what is the earliest safe
    #         version to upgrade to?"
    #    c. Build the diff by:
    #       - Recording the original manifest content as `old_content`.
    #       - Replacing the vulnerable version string with `patched_version`
    #         using a regex (e.g. r"pydantic==[\d.]+").
    #       - Producing a unified diff with difflib.unified_diff(
    #           old_content.splitlines(keepends=True),
    #           new_content.splitlines(keepends=True),
    #           fromfile=f"a/{manifest_path}",
    #           tofile=f"b/{manifest_path}",
    #         ).
    #
    # 3. For "code_fix":
    #    a. Build a prompt containing the vulnerable source file contents
    #       (from reachability["reachable_files"]) and the CVE description.
    #    b. Ask the LLM to produce corrected file content for each affected
    #       file, responding with a JSON mapping of file_path → new_content.
    #    c. For each corrected file, generate a unified diff with difflib.
    #    d. Concatenate all diffs into a single `diff` string.
    #    e. Set patched_version = None.
    #
    # 4. Extract `changed_files` by parsing the diff string for lines matching
    #    the pattern r"^\+\+\+ b/(.+)$" and stripping the "b/" prefix.
    #
    # 5. Generate `explanation` by prompting the LLM with the diff and asking
    #    for a two-sentence plain-English summary of the change.
    #
    # 6. Return the structured dict described in the Returns section above.
    # -------------------------------------------------------------------------
    raise NotImplementedError("IBM Bob will implement this in a subsequent session")
