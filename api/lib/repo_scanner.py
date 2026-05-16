"""
Fetch and index a target repository's dependency manifests and source files.

This is the second stage of the ZeroDay pipeline. It uses the GitHub client to
enumerate the repository and retrieve the files most likely to be relevant to
the vulnerability described in the advisory.

Dependencies
------------
lib.github_client.get_file_contents
lib.github_client.list_repo_files
lib.github_client.get_repo_metadata
"""

from __future__ import annotations

from typing import Any

from lib.github_client import get_file_contents, get_repo_metadata, list_repo_files


def scan_repository(repo_url: str, advisory: dict[str, Any]) -> dict[str, Any]:
    """
    Retrieve a repository's dependency manifests and relevant source files.

    Uses the GitHub REST API to fetch the files needed by subsequent pipeline
    stages. The scan is scoped to files that reference the affected package to
    avoid pulling the entire codebase.

    Parameters
    ----------
    repo_url : str
        HTTPS URL of the target GitHub repository
        (e.g. ``"https://github.com/owner/repo"``).
    advisory : dict[str, Any]
        Structured advisory returned by ``parse_cve_advisory``. Used to
        determine which package name to search for and which file types to
        prioritise.

    Returns
    -------
    dict[str, Any]
        A structured scan result with the following keys:

        repo_url : str
            Echo of the input URL.
        metadata : dict
            Raw repository metadata from ``get_repo_metadata()``.
        dependency_files : dict[str, str]
            Map of file path → raw text content for dependency manifests
            such as ``requirements.txt``, ``pyproject.toml``,
            ``package.json``, ``go.mod``, etc.
        source_files : dict[str, str]
            Map of file path → raw text content for source files that
            import or reference the vulnerable package.
        primary_language : str
            The dominant programming language of the repository as reported
            by GitHub (e.g. ``"Python"``, ``"JavaScript"``).
        affected_package_name : str
            The name of the vulnerable package extracted or inferred from
            the advisory's ``affected_packages`` list.

    Raises
    ------
    ValueError
        If ``repo_url`` is not a valid GitHub URL.
    RuntimeError
        If the GitHub API is unreachable or returns an error.

    Dependencies
    ------------
    lib.github_client.get_repo_metadata   : fetch repo-level metadata.
    lib.github_client.list_repo_files     : enumerate files by extension.
    lib.github_client.get_file_contents   : read individual file content.
    """
    # -------------------------------------------------------------------------
    # IMPLEMENTATION NOTES FOR IBM BOB
    #
    # 1. Call get_repo_metadata(repo_url) and store the result in `metadata`.
    #
    # 2. Determine `primary_language` from metadata.get("language", "Unknown").
    #
    # 3. Build a dict `MANIFEST_NAMES` mapping language → list of manifest
    #    filenames, for example:
    #      Python  → ["requirements.txt", "pyproject.toml", "setup.cfg", "Pipfile"]
    #      JavaScript / TypeScript → ["package.json", "package-lock.json", "yarn.lock"]
    #      Go      → ["go.mod", "go.sum"]
    #      Ruby    → ["Gemfile", "Gemfile.lock"]
    #      Java    → ["pom.xml", "build.gradle"]
    #    Default to Python manifests if the language is unknown.
    #
    # 4. For each manifest filename relevant to the detected language, call
    #    get_file_contents(repo_url, filename) inside a try/except RuntimeError
    #    block. If the file exists, add {filename: content} to `dependency_files`.
    #    Silently skip files that return HTTP 404.
    #
    # 5. Extract `affected_package_name` from:
    #      advisory.get("affected_packages", [{}])[0].get("product", "")
    #    If that is empty, scan advisory["description"] for a quoted package
    #    name (look for patterns like `pydantic`, "requests", etc.) using a
    #    simple regex. Default to "" if nothing is found.
    #
    # 6. Determine source file extensions for the primary language
    #    (e.g. Python → [".py"], JS → [".js", ".ts", ".jsx", ".tsx"]).
    #    Call list_repo_files(repo_url, extensions) to enumerate all matching
    #    paths. If the repository is very large (> 500 files), limit to the
    #    first 200 paths alphabetically to avoid excessive API calls.
    #
    # 7. For each file path returned, call get_file_contents(repo_url, path)
    #    inside a try/except. Only keep the file in `source_files` if its
    #    content contains `affected_package_name` (case-insensitive substring
    #    match). This keeps the context manageable for the LLM in later stages.
    #
    # 8. Return the structured dict described in the Returns section above.
    # -------------------------------------------------------------------------
    raise NotImplementedError("IBM Bob will implement this in a subsequent session")
