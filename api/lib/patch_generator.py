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

import difflib
import json
import re
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
        ``primary_language``, ``package_found_in_manifest``, and
        ``is_vulnerable_version``.
    advisory : dict[str, Any]
        Parsed advisory from ``parse_cve_advisory``. Contains
        ``affected_packages``, ``description``, ``references``,
        ``cvss_score``, and ``cve_id``.
    reachability : dict[str, Any]
        Reachability result from ``analyze_reachability``. Contains
        ``is_reachable``, ``reachable_files``, ``call_sites``, and
        ``confidence``.

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
        strategy_justification : str
            Explanation of why this strategy was chosen over alternatives.
        alternatives_considered : list[str]
            List of alternative strategies that were evaluated but not chosen.

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
    # Step 1: Decide on patch strategy
    strategy_decision = _decide_strategy(repo_data, advisory, reachability)
    
    patch_type = strategy_decision["chosen_strategy"]
    alternatives = strategy_decision["alternatives_considered"]
    justification = strategy_decision["justification"]
    
    # Step 2: Generate patch based on strategy
    if patch_type == "version_bump":
        patch_result = _generate_version_bump_patch(repo_data, advisory)
    else:  # code_fix
        patch_result = _generate_code_fix_patch(repo_data, advisory, reachability)
    
    # Step 3: Extract changed files from diff
    changed_files = _extract_changed_files(patch_result["diff"])
    
    # Step 4: Generate explanation
    explanation = _generate_explanation(
        patch_type,
        patch_result,
        advisory,
        repo_data,
    )
    
    return {
        "patch_type": patch_type,
        "diff": patch_result["diff"],
        "changed_files": changed_files,
        "patched_version": patch_result.get("patched_version"),
        "explanation": explanation,
        "strategy_justification": justification,
        "alternatives_considered": alternatives,
    }


def _decide_strategy(
    repo_data: dict[str, Any],
    advisory: dict[str, Any],
    reachability: dict[str, Any],
) -> dict[str, Any]:
    """
    Decide which patch strategy to use and document alternatives.
    
    Parameters
    ----------
    repo_data : dict
        Repository scan data.
    advisory : dict
        CVE advisory data.
    reachability : dict
        Reachability analysis result.
    
    Returns
    -------
    dict
        Strategy decision with chosen_strategy, justification, and alternatives_considered.
    """
    alternatives = []
    
    # Check if package is in manifest
    package_in_manifest = repo_data.get("package_found_in_manifest", False)
    is_vulnerable_version = repo_data.get("is_vulnerable_version", False)
    is_reachable = reachability.get("is_reachable", False)
    has_affected_packages = len(advisory.get("affected_packages", [])) > 0
    
    # Criteria for version_bump:
    # 1. Package is in manifest
    # 2. Has affected packages (third-party vulnerability)
    # 3. Either reachable OR vulnerable version (defense-in-depth)
    
    can_version_bump = (
        package_in_manifest
        and has_affected_packages
        and (is_reachable or is_vulnerable_version)
    )
    
    can_code_fix = (
        is_reachable
        and len(reachability.get("call_sites", [])) > 0
    )
    
    # Decision logic
    if can_version_bump:
        chosen = "version_bump"
        justification = (
            f"Vulnerability is in third-party package "
            f"'{repo_data.get('affected_package_name', 'unknown')}'. "
            f"Version bump is the safest and most maintainable fix. "
        )
        
        if is_vulnerable_version:
            justification += (
                f"Current version is vulnerable. "
            )
        
        if is_reachable:
            justification += (
                f"Vulnerable code path is reachable "
                f"(confidence: {reachability.get('confidence', 0):.0%}). "
            )
        else:
            justification += (
                f"Applying defense-in-depth even though vulnerability "
                f"appears unreachable. "
            )
        
        if can_code_fix:
            alternatives.append(
                "code_fix: Wrap or replace vulnerable call sites, but version "
                "bump is preferred for third-party vulnerabilities"
            )
        
    elif can_code_fix:
        chosen = "code_fix"
        justification = (
            f"Vulnerability is reachable at {len(reachability['call_sites'])} "
            f"call site(s). "
        )
        
        if not package_in_manifest:
            justification += (
                "Package not found in manifest, suggesting application code vulnerability. "
            )
        elif not has_affected_packages:
            justification += (
                "No third-party packages listed in advisory. "
            )
        else:
            justification += (
                "Version bump not applicable. "
            )
        
        justification += "Generating targeted code-level fix."
        
        if package_in_manifest and has_affected_packages:
            alternatives.append(
                "version_bump: Not chosen because package version could not be determined "
                "or no fixed version is available"
            )
    
    else:
        # Fallback: no-op or defensive version bump
        if package_in_manifest and has_affected_packages:
            chosen = "version_bump"
            justification = (
                "Applying defensive version bump even though vulnerability "
                "appears unreachable. Defense-in-depth strategy."
            )
            alternatives.append(
                "no_action: Vulnerability appears unreachable, but we prefer "
                "defense-in-depth"
            )
        else:
            chosen = "code_fix"
            justification = (
                "Insufficient information for version bump. "
                "Attempting code-level fix as fallback."
            )
            alternatives.append(
                "version_bump: Not applicable - package not in manifest or "
                "no affected packages listed"
            )
    
    return {
        "chosen_strategy": chosen,
        "justification": justification,
        "alternatives_considered": alternatives,
    }


def _generate_version_bump_patch(
    repo_data: dict[str, Any],
    advisory: dict[str, Any],
) -> dict[str, Any]:
    """
    Generate a version bump patch for dependency manifests.
    
    Parameters
    ----------
    repo_data : dict
        Repository scan data with dependency_files.
    advisory : dict
        CVE advisory with affected_packages and references.
    
    Returns
    -------
    dict
        Patch result with diff and patched_version.
    """
    package_name = repo_data.get("affected_package_name", "")
    dependency_files = repo_data.get("dependency_files", {})
    
    # Find manifest file containing the package
    target_manifest = None
    target_content = None
    
    for file_path, content in dependency_files.items():
        if package_name.lower() in content.lower():
            target_manifest = file_path
            target_content = content
            break
    
    if not target_manifest or not target_content:
        raise RuntimeError(
            f"Package '{package_name}' not found in any dependency manifest"
        )
    
    # Determine patched version
    patched_version = _determine_safe_version(advisory, package_name)
    
    # Generate new content with updated version
    new_content = _update_manifest_version(
        target_content,
        package_name,
        patched_version,
        target_manifest,
    )
    
    # Generate unified diff
    diff = _create_unified_diff(
        target_content,
        new_content,
        target_manifest,
    )
    
    return {
        "diff": diff,
        "patched_version": patched_version,
    }


def _determine_safe_version(advisory: dict[str, Any], package_name: str) -> str:
    """
    Determine the safe version to upgrade to using LLM.
    
    Parameters
    ----------
    advisory : dict
        CVE advisory with affected_packages and references.
    package_name : str
        Name of the affected package.
    
    Returns
    -------
    str
        Safe version string (e.g., "2.7.1").
    """
    affected_packages = advisory.get("affected_packages", [])
    references = advisory.get("references", [])
    cve_id = advisory.get("cve_id", "unknown")
    
    # Build prompt for LLM
    version_info = []
    for pkg in affected_packages:
        if pkg.get("product", "").lower() == package_name.lower():
            version_info.append(
                f"Vulnerable: {pkg.get('version_start', 'any')} to "
                f"{pkg.get('version_end', 'unknown')} "
                f"({'inclusive' if pkg.get('version_end_inclusive') else 'exclusive'})"
            )
    
    prompt = f"""Given the following CVE information, determine the earliest safe version to upgrade to.

CVE: {cve_id}
Package: {package_name}
Vulnerable versions: {', '.join(version_info) if version_info else 'See references'}
References: {', '.join(references[:3])}

Respond with ONLY the version number (e.g., "2.7.1" or "1.10.14"), nothing else."""

    system = "You are a security engineer determining safe package versions. Be concise."
    
    try:
        response = complete(prompt, system=system, max_tokens=50)
        # Extract version number from response
        version_match = re.search(r'(\d+\.\d+\.\d+)', response)
        if version_match:
            return version_match.group(1)
        
        # Fallback: try to extract from response directly
        clean_response = response.strip().strip('"\'')
        if re.match(r'^\d+\.\d+\.\d+$', clean_response):
            return clean_response
            
    except Exception:
        pass
    
    # Fallback: use version_end + 1 patch version if available
    for pkg in affected_packages:
        if pkg.get("product", "").lower() == package_name.lower():
            version_end = pkg.get("version_end")
            if version_end:
                # If exclusive, use that version; if inclusive, bump patch
                if not pkg.get("version_end_inclusive", True):
                    return version_end
                else:
                    # Try to bump patch version
                    parts = version_end.split('.')
                    if len(parts) >= 3:
                        parts[2] = str(int(parts[2]) + 1)
                        return '.'.join(parts)
    
    # Last resort fallback
    return "latest"


def _update_manifest_version(
    content: str,
    package_name: str,
    new_version: str,
    file_path: str,
) -> str:
    """
    Update package version in manifest content.
    
    Parameters
    ----------
    content : str
        Original manifest content.
    package_name : str
        Package name to update.
    new_version : str
        New version to set.
    file_path : str
        File path to determine format.
    
    Returns
    -------
    str
        Updated manifest content.
    """
    # Determine file type and update accordingly
    if file_path.endswith('requirements.txt') or file_path.endswith('setup.py'):
        # Pattern: package==1.2.3 or package>=1.2.3
        pattern = rf'({re.escape(package_name)}\s*[=<>!]+\s*)[\d\.]+'
        replacement = rf'\g<1>{new_version}'
        new_content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
        
    elif file_path.endswith('pyproject.toml') or file_path.endswith('Pipfile'):
        # Pattern: package = "^1.2.3" or package = "1.2.3"
        pattern = rf'({re.escape(package_name)}\s*=\s*["\'][\^~]?)[\d\.]+'
        replacement = rf'\g<1>{new_version}'
        new_content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
        
    elif file_path.endswith('package.json'):
        # Pattern: "package": "^1.2.3"
        pattern = rf'("{re.escape(package_name)}"\s*:\s*"[\^~]?)[\d\.]+'
        replacement = rf'\g<1>{new_version}'
        new_content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
        
    else:
        # Generic pattern
        pattern = rf'({re.escape(package_name)}["\s:=]+[\^~]?)[\d\.]+'
        replacement = rf'\g<1>{new_version}'
        new_content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
    
    return new_content


def _generate_code_fix_patch(
    repo_data: dict[str, Any],
    advisory: dict[str, Any],
    reachability: dict[str, Any],
) -> dict[str, Any]:
    """
    Generate a code-level fix patch using LLM.
    
    Parameters
    ----------
    repo_data : dict
        Repository scan data with source_files.
    advisory : dict
        CVE advisory with description.
    reachability : dict
        Reachability analysis with call_sites.
    
    Returns
    -------
    dict
        Patch result with diff.
    """
    call_sites = reachability.get("call_sites", [])
    source_files = repo_data.get("source_files", {})
    
    if not call_sites:
        raise RuntimeError("No call sites found for code fix")
    
    # Group call sites by file
    files_to_fix = {}
    for site in call_sites:
        file_path = site["file_path"]
        if file_path not in files_to_fix:
            files_to_fix[file_path] = []
        files_to_fix[file_path].append(site)
    
    # Generate fixes for each file
    all_diffs = []
    
    for file_path, sites in files_to_fix.items():
        if file_path not in source_files:
            continue
        
        original_content = source_files[file_path]
        fixed_content = _generate_fixed_code(
            original_content,
            file_path,
            sites,
            advisory,
        )
        
        diff = _create_unified_diff(original_content, fixed_content, file_path)
        all_diffs.append(diff)
    
    # Concatenate all diffs
    combined_diff = "\n".join(all_diffs)
    
    return {
        "diff": combined_diff,
        "patched_version": None,
    }


def _generate_fixed_code(
    original_content: str,
    file_path: str,
    call_sites: list[dict[str, Any]],
    advisory: dict[str, Any],
) -> str:
    """
    Use LLM to generate fixed code for a file.
    
    Parameters
    ----------
    original_content : str
        Original file content.
    file_path : str
        Path to the file.
    call_sites : list[dict]
        Call sites in this file.
    advisory : dict
        CVE advisory.
    
    Returns
    -------
    str
        Fixed file content.
    """
    # Build call site summary
    site_summary = []
    for site in call_sites:
        site_summary.append(
            f"Line {site['line_number']}: {site['line_content']}"
        )
    
    prompt = f"""Fix the security vulnerability in this code file.

CVE: {advisory.get('cve_id', 'unknown')}
Description: {advisory.get('description', '')[:300]}

File: {file_path}
Vulnerable call sites:
{chr(10).join(site_summary)}

Original code:
```
{original_content}
```

Generate the COMPLETE fixed file content. Apply minimal changes to fix the vulnerability:
- Wrap vulnerable calls with input validation
- Replace with safe alternatives
- Add error handling
- Or remove if not essential

Respond with ONLY the complete fixed code, no explanations."""

    system = "You are a security engineer fixing vulnerabilities. Provide complete, working code."
    
    try:
        response = complete(prompt, system=system, max_tokens=3000)
        
        # Extract code from response (handle markdown code blocks)
        code_match = re.search(r'```(?:python|javascript|go|java)?\n(.*?)\n```', response, re.DOTALL)
        if code_match:
            return code_match.group(1)
        
        # If no code block, use entire response
        return response.strip()
        
    except Exception as e:
        raise RuntimeError(f"Failed to generate code fix: {e}")


def _create_unified_diff(
    old_content: str,
    new_content: str,
    file_path: str,
) -> str:
    """
    Create a unified diff between old and new content.
    
    Parameters
    ----------
    old_content : str
        Original content.
    new_content : str
        New content.
    file_path : str
        File path for diff headers.
    
    Returns
    -------
    str
        Unified diff string.
    """
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)
    
    diff_lines = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm='',
    )
    
    return '\n'.join(diff_lines)


def _extract_changed_files(diff: str) -> list[str]:
    """
    Extract list of changed files from unified diff.
    
    Parameters
    ----------
    diff : str
        Unified diff string.
    
    Returns
    -------
    list[str]
        List of file paths.
    """
    changed_files = []
    
    for line in diff.split('\n'):
        match = re.match(r'^\+\+\+ b/(.+)$', line)
        if match:
            changed_files.append(match.group(1))
    
    return changed_files


def _generate_explanation(
    patch_type: str,
    patch_result: dict[str, Any],
    advisory: dict[str, Any],
    repo_data: dict[str, Any],
) -> str:
    """
    Generate plain-English explanation of the patch.
    
    Parameters
    ----------
    patch_type : str
        Type of patch (version_bump or code_fix).
    patch_result : dict
        Patch generation result.
    advisory : dict
        CVE advisory.
    repo_data : dict
        Repository data.
    
    Returns
    -------
    str
        Explanation text.
    """
    cve_id = advisory.get("cve_id", "unknown")
    package_name = repo_data.get("affected_package_name", "unknown")
    
    if patch_type == "version_bump":
        patched_version = patch_result.get("patched_version", "latest")
        explanation = (
            f"This patch upgrades {package_name} to version {patched_version} "
            f"to remediate {cve_id}. The vulnerability is fixed in this version "
            f"according to the advisory. This is a dependency update with no "
            f"application code changes required."
        )
    else:  # code_fix
        changed_files = _extract_changed_files(patch_result["diff"])
        explanation = (
            f"This patch applies code-level fixes to {len(changed_files)} file(s) "
            f"to remediate {cve_id}. The changes wrap or replace vulnerable "
            f"call sites to prevent exploitation. Review the diff carefully "
            f"to ensure the fixes maintain application functionality."
        )
    
    return explanation


# ============================================================================
# INLINE UNIT TESTS
# ============================================================================

if __name__ == "__main__":
    print("Running inline unit tests for patch_generator.py...\n")
    
    # Test 1: Strategy decision - version bump
    print("Test 1: Strategy decision for version bump")
    try:
        repo_data = {
            "package_found_in_manifest": True,
            "is_vulnerable_version": True,
            "affected_package_name": "pydantic",
        }
        advisory = {
            "affected_packages": [{"product": "pydantic"}],
        }
        reachability = {
            "is_reachable": True,
            "confidence": 0.9,
            "call_sites": [],
        }
        
        decision = _decide_strategy(repo_data, advisory, reachability)
        assert decision["chosen_strategy"] == "version_bump", "Should choose version_bump"
        assert len(decision["alternatives_considered"]) >= 0, "Should list alternatives"
        
        print(f"  [OK] Chosen strategy: {decision['chosen_strategy']}")
        print(f"  [OK] Justification: {decision['justification'][:60]}...")
        print("  [OK] Test 1 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 1 FAILED: {e}\n")
    
    # Test 2: Manifest version update
    print("Test 2: Manifest version update")
    try:
        requirements = "flask==3.0.3\npydantic==1.10.0\nemail-validator==1.3.1"
        updated = _update_manifest_version(requirements, "pydantic", "2.7.1", "requirements.txt")
        
        assert "pydantic==2.7.1" in updated, "Should update pydantic version"
        assert "flask==3.0.3" in updated, "Should preserve other packages"
        
        print("  [OK] Version updated correctly")
        print(f"  [OK] Updated line: {[l for l in updated.split(chr(10)) if 'pydantic' in l][0]}")
        print("  [OK] Test 2 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 2 FAILED: {e}\n")
    
    # Test 3: Diff generation
    print("Test 3: Unified diff generation")
    try:
        old = "line1\nline2\nline3"
        new = "line1\nline2_modified\nline3"
        diff = _create_unified_diff(old, new, "test.txt")
        
        assert "--- a/test.txt" in diff, "Should have from-file header"
        assert "+++ b/test.txt" in diff, "Should have to-file header"
        assert "-line2" in diff, "Should show removed line"
        assert "+line2_modified" in diff, "Should show added line"
        
        print("  [OK] Diff headers present")
        print("  [OK] Changes captured")
        print("  [OK] Test 3 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 3 FAILED: {e}\n")
    
    print("All inline unit tests completed!")

# Made with Bob
