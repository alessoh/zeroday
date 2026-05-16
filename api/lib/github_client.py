"""
Read-only GitHub REST API wrapper.

Exposes three functions for reading repository content without writing or
mutating any state. All functions parse a GitHub HTTPS URL to extract the
owner and repository name automatically.

Environment variables
---------------------
GITHUB_TOKEN : str
    Optional but strongly recommended. A personal access token avoids the
    60 req/hour unauthenticated rate limit. Must have the ``repo`` read scope
    for private repositories; no scope needed for public repositories.
"""

from __future__ import annotations

import base64
import os
from typing import Any
from urllib.parse import urlparse

import requests

_GITHUB_API = "https://api.github.com"
_TIMEOUT = 15  # seconds


def _headers() -> dict[str, str]:
    """Build request headers, including auth if GITHUB_TOKEN is set."""
    hdrs: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    return hdrs


def _parse_repo_url(repo_url: str) -> tuple[str, str]:
    """
    Extract the (owner, repo) pair from a GitHub HTTPS URL.

    Accepts both ``https://github.com/owner/repo`` and
    ``https://github.com/owner/repo.git`` forms.

    Raises
    ------
    ValueError
        If the URL cannot be parsed as a GitHub repository URL.
    """
    clean = repo_url.rstrip("/").removesuffix(".git")
    parsed = urlparse(clean)
    if parsed.netloc not in ("github.com", "www.github.com"):
        raise ValueError(f"Not a GitHub URL: {repo_url!r}")
    parts = parsed.path.lstrip("/").split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Cannot extract owner/repo from URL: {repo_url!r}")
    return parts[0], parts[1]


def get_file_contents(repo_url: str, file_path: str) -> str:
    """
    Fetch the raw UTF-8 text content of a single file from a GitHub repository.

    Parameters
    ----------
    repo_url : str
        HTTPS URL of the GitHub repository (e.g. ``https://github.com/owner/repo``).
    file_path : str
        Path to the file within the repository (e.g. ``requirements.txt``).

    Returns
    -------
    str
        Decoded file content as a UTF-8 string.

    Raises
    ------
    ValueError
        If repo_url is not a valid GitHub URL.
    RuntimeError
        If the GitHub API returns an error or the file is not found.
    """
    owner, repo = _parse_repo_url(repo_url)
    url = f"{_GITHUB_API}/repos/{owner}/{repo}/contents/{file_path}"
    try:
        resp = requests.get(url, headers=_headers(), timeout=_TIMEOUT)
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        if data.get("encoding") == "base64":
            raw = data.get("content", "").replace("\n", "")
            return base64.b64decode(raw).decode("utf-8")
        return data.get("content", "")
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        raise RuntimeError(
            f"GitHub API returned HTTP {status} for {file_path!r} in {repo_url!r}"
        ) from exc
    except requests.RequestException as exc:
        raise RuntimeError(
            f"GitHub API request failed for {file_path!r}: {exc}"
        ) from exc


def list_repo_files(repo_url: str, extensions: list[str]) -> list[str]:
    """
    List all file paths in a repository whose names end with any of the given
    extensions, using a single recursive tree traversal.

    Parameters
    ----------
    repo_url : str
        HTTPS URL of the GitHub repository.
    extensions : list[str]
        File extensions to filter by, including the leading dot
        (e.g. ``[".py", ".toml"]``).

    Returns
    -------
    list[str]
        Sorted list of matching file paths relative to the repository root.

    Raises
    ------
    ValueError
        If repo_url is not a valid GitHub URL.
    RuntimeError
        If the GitHub API returns an error.
    """
    owner, repo = _parse_repo_url(repo_url)
    url = f"{_GITHUB_API}/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
    try:
        resp = requests.get(url, headers=_headers(), timeout=_TIMEOUT)
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        tree: list[dict[str, Any]] = data.get("tree", [])
        matches = sorted(
            item["path"]
            for item in tree
            if item.get("type") == "blob"
            and any(item["path"].endswith(ext) for ext in extensions)
        )
        return matches
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        raise RuntimeError(
            f"GitHub API returned HTTP {status} while listing files in {repo_url!r}"
        ) from exc
    except requests.RequestException as exc:
        raise RuntimeError(
            f"GitHub API request failed while listing files: {exc}"
        ) from exc


def get_repo_metadata(repo_url: str) -> dict[str, Any]:
    """
    Fetch repository-level metadata from the GitHub API.

    Returns the raw API response dictionary, which includes fields such as
    ``name``, ``full_name``, ``description``, ``language``, ``topics``,
    ``default_branch``, ``visibility``, and ``stargazers_count``.

    Parameters
    ----------
    repo_url : str
        HTTPS URL of the GitHub repository.

    Returns
    -------
    dict[str, Any]
        Repository metadata as returned by the GitHub REST API.

    Raises
    ------
    ValueError
        If repo_url is not a valid GitHub URL.
    RuntimeError
        If the GitHub API returns an error.
    """
    owner, repo = _parse_repo_url(repo_url)
    url = f"{_GITHUB_API}/repos/{owner}/{repo}"
    try:
        resp = requests.get(url, headers=_headers(), timeout=_TIMEOUT)
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        raise RuntimeError(
            f"GitHub API returned HTTP {status} for repo metadata: {repo_url!r}"
        ) from exc
    except requests.RequestException as exc:
        raise RuntimeError(
            f"GitHub API request failed fetching repo metadata: {exc}"
        ) from exc
