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

import re
from typing import Any

from lib.github_client import get_file_contents, get_repo_metadata, list_repo_files


# Mapping of programming languages to their dependency manifest filenames
MANIFEST_NAMES: dict[str, list[str]] = {
    "Python": ["requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock"],
    "JavaScript": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    "TypeScript": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    "Go": ["go.mod", "go.sum"],
    "Ruby": ["Gemfile", "Gemfile.lock"],
    "Java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "Rust": ["Cargo.toml", "Cargo.lock"],
    "PHP": ["composer.json", "composer.lock"],
    "C#": ["*.csproj", "packages.config"],
}

# Mapping of programming languages to source file extensions
SOURCE_EXTENSIONS: dict[str, list[str]] = {
    "Python": [".py"],
    "JavaScript": [".js", ".jsx", ".mjs", ".cjs"],
    "TypeScript": [".ts", ".tsx"],
    "Go": [".go"],
    "Ruby": [".rb"],
    "Java": [".java"],
    "Rust": [".rs"],
    "PHP": [".php"],
    "C#": [".cs"],
}


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
        package_found_in_manifest : bool
            True if the affected package appears in any dependency manifest.
        installed_version : str | None
            The version of the affected package found in manifests, or None.
        is_vulnerable_version : bool
            True if installed_version falls within the advisory's vulnerable range.

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
    # Step 1: Fetch repository metadata
    metadata = get_repo_metadata(repo_url)
    
    # Step 2: Determine primary language
    primary_language = metadata.get("language", "Unknown")
    if not primary_language or primary_language == "Unknown":
        primary_language = "Python"  # Default to Python
    
    # Step 3: Extract affected package name from advisory
    affected_package_name = _extract_package_name(advisory)
    
    # Step 4: Fetch dependency manifests
    dependency_files = _fetch_dependency_manifests(repo_url, primary_language)
    
    # Step 5: Check if package is in manifests and extract version
    package_found_in_manifest = False
    installed_version = None
    is_vulnerable_version = False
    
    if affected_package_name:
        package_found_in_manifest, installed_version = _check_package_in_manifests(
            dependency_files, affected_package_name, primary_language
        )
        
        if package_found_in_manifest and installed_version:
            is_vulnerable_version = _is_version_vulnerable(
                installed_version, advisory.get("affected_packages", [])
            )
    
    # Step 6: Fetch source files that reference the affected package
    source_files = _fetch_relevant_source_files(
        repo_url, primary_language, affected_package_name
    )
    
    return {
        "repo_url": repo_url,
        "metadata": metadata,
        "dependency_files": dependency_files,
        "source_files": source_files,
        "primary_language": primary_language,
        "affected_package_name": affected_package_name,
        "package_found_in_manifest": package_found_in_manifest,
        "installed_version": installed_version,
        "is_vulnerable_version": is_vulnerable_version,
    }


def _extract_package_name(advisory: dict[str, Any]) -> str:
    """
    Extract the affected package name from the advisory.
    
    First tries to get it from affected_packages, then falls back to
    extracting from the description using regex patterns.
    
    Parameters
    ----------
    advisory : dict[str, Any]
        Parsed advisory from parse_cve_advisory.
    
    Returns
    -------
    str
        The package name, or empty string if not found.
    """
    # Try to get from affected_packages
    affected_packages = advisory.get("affected_packages", [])
    if affected_packages:
        product = affected_packages[0].get("product", "")
        if product and product != "unknown":
            return product
    
    # Fall back to extracting from description
    description = advisory.get("description", "")
    if not description:
        return ""
    
    # Look for common package name patterns in descriptions
    # Pattern 1: backticks `package_name`
    backtick_match = re.search(r"`([a-zA-Z0-9_\-]+)`", description)
    if backtick_match:
        return backtick_match.group(1)
    
    # Pattern 2: quoted "package-name" or 'package-name'
    quoted_match = re.search(r'["\']([a-zA-Z0-9_\-]+)["\']', description)
    if quoted_match:
        return quoted_match.group(1)
    
    return ""


def _fetch_dependency_manifests(repo_url: str, primary_language: str) -> dict[str, str]:
    """
    Fetch dependency manifest files for the given language.
    
    Parameters
    ----------
    repo_url : str
        GitHub repository URL.
    primary_language : str
        Primary programming language of the repository.
    
    Returns
    -------
    dict[str, str]
        Map of file path to file content for found manifests.
    """
    dependency_files: dict[str, str] = {}
    
    # Get manifest filenames for this language
    manifest_names = MANIFEST_NAMES.get(primary_language, MANIFEST_NAMES["Python"])
    
    # Try to fetch each manifest file
    for manifest_name in manifest_names:
        try:
            content = get_file_contents(repo_url, manifest_name)
            dependency_files[manifest_name] = content
        except RuntimeError:
            # File doesn't exist or can't be fetched - skip silently
            pass
    
    return dependency_files


def _check_package_in_manifests(
    dependency_files: dict[str, str],
    package_name: str,
    primary_language: str,
) -> tuple[bool, str | None]:
    """
    Check if the package appears in any manifest and extract its version.
    
    Parameters
    ----------
    dependency_files : dict[str, str]
        Map of manifest file paths to their contents.
    package_name : str
        Name of the package to search for.
    primary_language : str
        Primary language to determine parsing strategy.
    
    Returns
    -------
    tuple[bool, str | None]
        (package_found, installed_version)
    """
    if not package_name:
        return False, None
    
    package_lower = package_name.lower()
    
    for file_path, content in dependency_files.items():
        content_lower = content.lower()
        
        # Check if package name appears in the file
        if package_lower not in content_lower:
            continue
        
        # Package found - try to extract version
        if primary_language == "Python":
            version = _extract_python_version(content, package_name)
            if version:
                return True, version
        elif primary_language in ("JavaScript", "TypeScript"):
            version = _extract_npm_version(content, package_name)
            if version:
                return True, version
        
        # Package found but version not extracted
        return True, None
    
    return False, None


def _extract_python_version(content: str, package_name: str) -> str | None:
    """
    Extract version from Python dependency files.
    
    Handles requirements.txt and pyproject.toml formats.
    """
    # Pattern for requirements.txt: package==1.2.3 or package>=1.2.3
    req_pattern = rf"^{re.escape(package_name)}\s*([=<>!]+)\s*([\d\.]+)"
    match = re.search(req_pattern, content, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(2)
    
    # Pattern for pyproject.toml: package = "^1.2.3" or package = "1.2.3"
    toml_pattern = rf'{re.escape(package_name)}\s*=\s*["\'][\^~]?([\d\.]+)'
    match = re.search(toml_pattern, content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None


def _extract_npm_version(content: str, package_name: str) -> str | None:
    """
    Extract version from package.json.
    
    Looks in both dependencies and devDependencies sections.
    """
    # Pattern: "package-name": "^1.2.3" or "package-name": "1.2.3"
    pattern = rf'"{re.escape(package_name)}"\s*:\s*"[\^~]?([\d\.]+)'
    match = re.search(pattern, content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None


def _is_version_vulnerable(
    installed_version: str,
    affected_packages: list[dict[str, Any]],
) -> bool:
    """
    Check if the installed version falls within the vulnerable range.
    
    Parameters
    ----------
    installed_version : str
        The version string found in the manifest (e.g. "1.10.0").
    affected_packages : list[dict]
        List of affected package dictionaries from the advisory.
    
    Returns
    -------
    bool
        True if the version is vulnerable, False otherwise.
    """
    if not affected_packages:
        return False
    
    try:
        installed_parts = _parse_version(installed_version)
    except ValueError:
        # Can't parse version - assume vulnerable to be safe
        return True
    
    for pkg in affected_packages:
        version_start = pkg.get("version_start")
        version_end = pkg.get("version_end")
        start_inclusive = pkg.get("version_start_inclusive", True)
        end_inclusive = pkg.get("version_end_inclusive", True)
        
        # Skip packages with no version bounds (e.g., OS packages like Fedora)
        # These aren't relevant for application dependency checking
        if not version_start and not version_end:
            continue
        
        # Check lower bound
        if version_start:
            try:
                start_parts = _parse_version(version_start)
                if start_inclusive:
                    if installed_parts < start_parts:
                        continue
                else:
                    if installed_parts <= start_parts:
                        continue
            except ValueError:
                pass
        
        # Check upper bound
        if version_end:
            try:
                end_parts = _parse_version(version_end)
                if end_inclusive:
                    if installed_parts > end_parts:
                        continue
                else:
                    if installed_parts >= end_parts:
                        continue
            except ValueError:
                pass
        
        # Version is within this vulnerable range
        return True
    
    return False


def _parse_version(version_str: str) -> tuple[int, ...]:
    """
    Parse a version string into a tuple of integers for comparison.
    
    Parameters
    ----------
    version_str : str
        Version string like "1.10.0" or "2.7.1".
    
    Returns
    -------
    tuple[int, ...]
        Tuple of version components as integers.
    
    Raises
    ------
    ValueError
        If the version string cannot be parsed.
    """
    # Remove common prefixes
    clean = version_str.lstrip("v")
    
    # Split on dots and convert to integers
    parts = []
    for part in clean.split("."):
        # Extract leading digits only (handles "1.2.3rc1" -> "1.2.3")
        digit_match = re.match(r"(\d+)", part)
        if digit_match:
            parts.append(int(digit_match.group(1)))
        else:
            raise ValueError(f"Cannot parse version component: {part}")
    
    return tuple(parts)


def _fetch_relevant_source_files(
    repo_url: str,
    primary_language: str,
    package_name: str,
) -> dict[str, str]:
    """
    Fetch source files that import or reference the affected package.
    
    Parameters
    ----------
    repo_url : str
        GitHub repository URL.
    primary_language : str
        Primary programming language.
    package_name : str
        Name of the affected package.
    
    Returns
    -------
    dict[str, str]
        Map of file path to content for files that reference the package.
    """
    source_files: dict[str, str] = {}
    
    if not package_name:
        return source_files
    
    # Get source file extensions for this language
    extensions = SOURCE_EXTENSIONS.get(primary_language, [".py"])
    
    try:
        # List all source files
        all_paths = list_repo_files(repo_url, extensions)
        
        # Limit to 200 files if repository is very large
        if len(all_paths) > 500:
            all_paths = all_paths[:200]
        
        # Fetch each file and check if it references the package
        package_lower = package_name.lower()
        
        for file_path in all_paths:
            try:
                content = get_file_contents(repo_url, file_path)
                
                # Check if file references the package (case-insensitive)
                if package_lower in content.lower():
                    source_files[file_path] = content
                    
                    # Limit total source files to avoid memory issues
                    if len(source_files) >= 50:
                        break
                        
            except RuntimeError:
                # File can't be fetched - skip
                pass
                
    except RuntimeError:
        # list_repo_files failed - return empty dict
        pass
    
    return source_files


# ============================================================================
# INLINE UNIT TESTS
# ============================================================================

if __name__ == "__main__":
    print("Running inline unit tests for repo_scanner.py...\n")
    
    # Test 1: Version parsing
    print("Test 1: Version parsing and comparison")
    try:
        v1 = _parse_version("1.10.0")
        v2 = _parse_version("1.10.14")
        v3 = _parse_version("2.0.0")
        assert v1 < v2, "1.10.0 should be < 1.10.14"
        assert v2 < v3, "1.10.14 should be < 2.0.0"
        assert v1 < v3, "1.10.0 should be < 2.0.0"
        print("  [OK] Version parsing works correctly")
        print("  [OK] Test 1 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 1 FAILED: {e}\n")
    
    # Test 2: Vulnerability checking
    print("Test 2: Vulnerability version range checking")
    try:
        affected_packages = [
            {
                "vendor": "pydantic",
                "product": "pydantic",
                "version_start": None,
                "version_start_inclusive": True,
                "version_end": "1.10.14",
                "version_end_inclusive": False,
            }
        ]
        
        assert _is_version_vulnerable("1.10.0", affected_packages), "1.10.0 should be vulnerable"
        assert _is_version_vulnerable("1.10.13", affected_packages), "1.10.13 should be vulnerable"
        assert not _is_version_vulnerable("1.10.14", affected_packages), "1.10.14 should NOT be vulnerable (exclusive)"
        assert not _is_version_vulnerable("2.0.0", affected_packages), "2.0.0 should NOT be vulnerable"
        
        print("  [OK] Vulnerability checking works correctly")
        print("  [OK] Exclusive upper bound handled correctly")
        print("  [OK] Test 2 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 2 FAILED: {e}\n")
    
    # Test 3: Python version extraction
    print("Test 3: Python version extraction from manifests")
    try:
        requirements_txt = "flask==3.0.3\npydantic==1.10.0\nemail-validator==1.3.1"
        version = _extract_python_version(requirements_txt, "pydantic")
        assert version == "1.10.0", f"Expected 1.10.0, got {version}"
        
        pyproject_toml = '[tool.poetry.dependencies]\npydantic = "^1.10.0"\nflask = "3.0.3"'
        version = _extract_python_version(pyproject_toml, "pydantic")
        assert version == "1.10.0", f"Expected 1.10.0, got {version}"
        
        print("  [OK] requirements.txt parsing works")
        print("  [OK] pyproject.toml parsing works")
        print("  [OK] Test 3 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 3 FAILED: {e}\n")
    
    print("All inline unit tests completed!")

# Made with Bob
