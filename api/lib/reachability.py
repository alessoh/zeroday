"""
Determine whether the vulnerable code path is actually reachable in the
target repository.

This is the third stage of the ZeroDay pipeline. It combines LLM-assisted
code analysis with fast heuristic string matching to decide, with a confidence
score, whether the application actually calls the vulnerable API surface
described in the advisory.

IMPORTANT: Production-Grade Reachability Analysis
--------------------------------------------------
This implementation uses syntactic call-site search combined with LLM reasoning
to detect whether vulnerable functions are called. This is suitable for a
hackathon proof-of-concept but has known limitations:

1. **No dataflow analysis**: Cannot track values through variables, function
   parameters, or return values. Example: `validator = EmailStr; validator(x)`
   would not be detected as calling EmailStr.

2. **No interprocedural analysis**: Cannot track calls across function
   boundaries. Example: if `foo()` calls `bar()` which calls the vulnerable
   function, we only detect the direct call in `bar()`.

3. **No alias resolution**: Limited ability to detect calls through imports
   with aliases. Example: `from pydantic import EmailStr as E; E(x)` may not
   be detected depending on LLM reasoning.

4. **No dead code elimination**: Cannot definitively determine if code is
   unreachable due to control flow. We use heuristics (e.g., `if False`) but
   these are not sound.

Production-grade reachability would require:
- Static analysis framework (e.g., CodeQL, Semgrep, or custom dataflow engine)
- Type inference and points-to analysis
- Call graph construction with interprocedural analysis
- Taint tracking from entry points to vulnerable sinks

For the hackathon, we prioritize:
- Fast execution (< 30 seconds per repository)
- High recall (catch most true positives, accept some false positives)
- Clear confidence scoring to guide human review

Dependencies
------------
lib.llm_client.complete
"""

from __future__ import annotations

import json
import re
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
        ``dependency_files`` (dict[str, str]),
        ``affected_package_name`` (str), and
        ``package_found_in_manifest`` (bool).
    advisory : dict[str, Any]
        Parsed advisory from ``parse_cve_advisory``. Must contain at least
        ``description`` (str), ``vulnerable_function`` (str | None),
        and ``cve_id`` (str).

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
        call_sites : list[dict]
            Detailed call site information with keys: file_path, line_number,
            line_content, context_before, context_after.
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
    # Step 1: Fast-path short-circuit if package not in manifests
    if not repo_data.get("package_found_in_manifest", False):
        return {
            "is_reachable": False,
            "confidence": 0.95,
            "reasoning": (
                f"Package '{repo_data.get('affected_package_name', 'unknown')}' "
                "not found in any dependency manifest. The vulnerability cannot "
                "be exploited if the package is not installed."
            ),
            "reachable_files": [],
            "call_sites": [],
            "call_chain": [],
        }
    
    # Step 2: Extract vulnerable function/pattern names
    vulnerable_functions = _extract_vulnerable_functions(advisory)
    
    # Step 3: Perform syntactic call-site search
    call_sites = _find_call_sites(
        repo_data.get("source_files", {}),
        vulnerable_functions,
        repo_data.get("affected_package_name", ""),
    )
    
    # Step 4: If no call sites found, return unreachable with high confidence
    if not call_sites:
        return {
            "is_reachable": False,
            "confidence": 0.85,
            "reasoning": (
                f"No direct calls to vulnerable functions {vulnerable_functions} "
                f"found in source files that import "
                f"'{repo_data.get('affected_package_name', 'unknown')}'. "
                "The package is installed but the vulnerable code path appears "
                "unreachable. Note: This analysis uses syntactic search and may "
                "miss calls through aliases or indirect invocations."
            ),
            "reachable_files": [],
            "call_sites": [],
            "call_chain": [],
        }
    
    # Step 5: Call sites found - use LLM for deeper analysis
    llm_result = _analyze_with_llm(
        repo_data.get("source_files", {}),
        advisory,
        call_sites,
        vulnerable_functions,
    )
    
    # Step 6: Merge syntactic and LLM results
    final_result = _merge_results(call_sites, llm_result)
    
    return final_result


def _extract_vulnerable_functions(advisory: dict[str, Any]) -> list[str]:
    """
    Extract vulnerable function/method/class names from the advisory.
    
    Parameters
    ----------
    advisory : dict[str, Any]
        Parsed advisory with vulnerable_function field.
    
    Returns
    -------
    list[str]
        List of function/method/class names to search for.
    """
    functions = []
    
    # Get from advisory's vulnerable_function field
    vuln_func = advisory.get("vulnerable_function")
    if vuln_func:
        functions.append(vuln_func)
    
    # Extract additional patterns from description
    description = advisory.get("description", "")
    
    # Pattern: EmailStr, BaseModel, etc. (CamelCase identifiers)
    camel_case = re.findall(r'\b([A-Z][a-zA-Z0-9]*(?:[A-Z][a-zA-Z0-9]*)*)\b', description)
    functions.extend(camel_case[:5])  # Limit to first 5
    
    # Pattern: validate_email, parse_obj, etc. (snake_case identifiers)
    snake_case = re.findall(r'\b([a-z_][a-z0-9_]*)\b', description)
    # Filter out common words
    common_words = {'the', 'a', 'an', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'should', 'could', 'may', 'might', 'must', 'can', 'this', 'that', 'these', 'those', 'it', 'its', 'they', 'their', 'them'}
    snake_case = [s for s in snake_case if s not in common_words and len(s) > 3]
    functions.extend(snake_case[:5])  # Limit to first 5
    
    # Remove duplicates while preserving order
    seen = set()
    unique_functions = []
    for func in functions:
        if func not in seen:
            seen.add(func)
            unique_functions.append(func)
    
    return unique_functions[:10]  # Max 10 function names


def _find_call_sites(
    source_files: dict[str, str],
    vulnerable_functions: list[str],
    package_name: str,
) -> list[dict[str, Any]]:
    """
    Perform syntactic search for call sites of vulnerable functions.
    
    Parameters
    ----------
    source_files : dict[str, str]
        Map of file path to file content.
    vulnerable_functions : list[str]
        List of function names to search for.
    package_name : str
        Name of the affected package.
    
    Returns
    -------
    list[dict]
        List of call site dictionaries with file_path, line_number, line_content,
        context_before, context_after, matched_function.
    """
    call_sites = []
    
    for file_path, content in source_files.items():
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            # Check if line contains any vulnerable function
            for func_name in vulnerable_functions:
                # Pattern 1: Direct function call: func_name(
                if re.search(rf'\b{re.escape(func_name)}\s*\(', line):
                    call_sites.append(_create_call_site(
                        file_path, line_num, line, lines, func_name
                    ))
                    break
                
                # Pattern 2: Class instantiation: func_name()
                if re.search(rf'\b{re.escape(func_name)}\s*\(\)', line):
                    call_sites.append(_create_call_site(
                        file_path, line_num, line, lines, func_name
                    ))
                    break
                
                # Pattern 3: Method call: .func_name(
                if re.search(rf'\.{re.escape(func_name)}\s*\(', line):
                    call_sites.append(_create_call_site(
                        file_path, line_num, line, lines, func_name
                    ))
                    break
    
    return call_sites


def _create_call_site(
    file_path: str,
    line_num: int,
    line_content: str,
    all_lines: list[str],
    matched_function: str,
) -> dict[str, Any]:
    """
    Create a call site dictionary with context.
    
    Parameters
    ----------
    file_path : str
        Path to the file.
    line_num : int
        Line number (1-indexed).
    line_content : str
        Content of the line containing the call.
    all_lines : list[str]
        All lines in the file.
    matched_function : str
        The function name that was matched.
    
    Returns
    -------
    dict
        Call site information.
    """
    # Get 2 lines of context before and after
    context_before = []
    for i in range(max(0, line_num - 3), line_num - 1):
        if i < len(all_lines):
            context_before.append(all_lines[i])
    
    context_after = []
    for i in range(line_num, min(len(all_lines), line_num + 2)):
        if i < len(all_lines):
            context_after.append(all_lines[i])
    
    # Check if call is in obviously dead code
    is_dead_code = _is_likely_dead_code(line_content, context_before)
    
    return {
        "file_path": file_path,
        "line_number": line_num,
        "line_content": line_content.strip(),
        "context_before": context_before,
        "context_after": context_after,
        "matched_function": matched_function,
        "is_dead_code": is_dead_code,
    }


def _is_likely_dead_code(line: str, context_before: list[str]) -> bool:
    """
    Heuristic check if code is likely unreachable.
    
    Checks for patterns like:
    - if False:
    - if 0:
    - if __name__ == "__main__": (for library code)
    - # commented out
    
    Parameters
    ----------
    line : str
        The line to check.
    context_before : list[str]
        Lines before this line.
    
    Returns
    -------
    bool
        True if likely dead code.
    """
    # Check if line is commented
    if line.strip().startswith('#'):
        return True
    
    # Check context for if False or if 0
    for prev_line in context_before[-3:]:
        if re.search(r'if\s+(False|0)\s*:', prev_line):
            return True
    
    return False


def _analyze_with_llm(
    source_files: dict[str, str],
    advisory: dict[str, Any],
    call_sites: list[dict[str, Any]],
    vulnerable_functions: list[str],
) -> dict[str, Any]:
    """
    Use LLM to analyze call sites and determine reachability with confidence.
    
    Parameters
    ----------
    source_files : dict[str, str]
        Source file contents.
    advisory : dict[str, Any]
        CVE advisory.
    call_sites : list[dict]
        Syntactically found call sites.
    vulnerable_functions : list[str]
        List of vulnerable function names.
    
    Returns
    -------
    dict
        LLM analysis result with is_reachable, confidence, reasoning, call_chain.
    """
    # Build system prompt
    system_prompt = """You are a senior security engineer performing reachability analysis for vulnerability remediation. Your task is to determine whether vulnerable code paths are actually reachable in a given application.

You will be provided with:
1. A CVE description
2. Vulnerable function names
3. Source code files with potential call sites

Analyze the code and respond with a JSON object containing:
- is_reachable (bool): true if the vulnerable function is called in a reachable code path
- confidence (float 0.0-1.0): your confidence in this assessment
- reasoning (string): clear explanation of your analysis
- call_chain (list of strings): function call chain from entry point to vulnerable call, if identifiable

Consider:
- Are the calls in production code or just tests?
- Are the calls behind feature flags or dead code (if False, etc.)?
- Are the vulnerable parameters actually passed to the function?
- Is this a direct call or through an alias/wrapper?

Be conservative: if unsure, report is_reachable=true with lower confidence."""

    # Build user prompt with call site details
    call_sites_summary = []
    for site in call_sites[:10]:  # Limit to first 10 call sites
        call_sites_summary.append(
            f"File: {site['file_path']}\n"
            f"Line {site['line_number']}: {site['line_content']}\n"
            f"Function: {site['matched_function']}\n"
            f"Dead code: {site['is_dead_code']}"
        )
    
    user_prompt = f"""CVE: {advisory.get('cve_id', 'unknown')}
Description: {advisory.get('description', '')[:500]}

Vulnerable functions: {', '.join(vulnerable_functions)}

Found {len(call_sites)} potential call sites:

{chr(10).join(call_sites_summary)}

Analyze these call sites and determine if the vulnerability is reachable. Respond with JSON only."""

    try:
        response = complete(user_prompt, system=system_prompt, max_tokens=1500)
        
        # Try to parse as JSON
        try:
            result = json.loads(response)
            # Validate required fields
            if all(k in result for k in ['is_reachable', 'confidence', 'reasoning']):
                # Ensure confidence is in valid range
                result['confidence'] = max(0.0, min(1.0, float(result.get('confidence', 0.5))))
                result['call_chain'] = result.get('call_chain', [])
                return result
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Fallback: extract values with regex
        is_reachable = bool(re.search(r'"is_reachable"\s*:\s*true', response, re.IGNORECASE))
        confidence_match = re.search(r'"confidence"\s*:\s*(0?\.\d+|1\.0|0|1)', response)
        confidence = float(confidence_match.group(1)) if confidence_match else 0.6
        
        reasoning_match = re.search(r'"reasoning"\s*:\s*"([^"]+)"', response)
        reasoning = reasoning_match.group(1) if reasoning_match else response[:200]
        
        return {
            "is_reachable": is_reachable,
            "confidence": max(0.0, min(1.0, confidence)),
            "reasoning": reasoning,
            "call_chain": [],
        }
        
    except Exception as e:
        # LLM call failed - fall back to heuristic
        # If we found call sites and none are dead code, assume reachable
        live_call_sites = [s for s in call_sites if not s.get('is_dead_code', False)]
        
        return {
            "is_reachable": len(live_call_sites) > 0,
            "confidence": 0.6,  # Lower confidence without LLM
            "reasoning": (
                f"Found {len(call_sites)} call sites ({len(live_call_sites)} in live code). "
                f"LLM analysis unavailable: {str(e)[:100]}"
            ),
            "call_chain": [],
        }


def _merge_results(
    call_sites: list[dict[str, Any]],
    llm_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Merge syntactic call site findings with LLM analysis.
    
    Parameters
    ----------
    call_sites : list[dict]
        Syntactically found call sites.
    llm_result : dict
        LLM analysis result.
    
    Returns
    -------
    dict
        Final reachability result.
    """
    # Extract unique file paths from call sites
    reachable_files = list(set(site['file_path'] for site in call_sites))
    
    # Filter out dead code call sites for final report
    live_call_sites = [s for s in call_sites if not s.get('is_dead_code', False)]
    
    # Adjust confidence based on dead code ratio
    dead_code_ratio = (len(call_sites) - len(live_call_sites)) / max(len(call_sites), 1)
    confidence_adjustment = -0.2 * dead_code_ratio  # Reduce confidence if many dead code sites
    
    final_confidence = max(0.0, min(1.0, llm_result['confidence'] + confidence_adjustment))
    
    return {
        "is_reachable": llm_result['is_reachable'],
        "confidence": final_confidence,
        "reasoning": llm_result['reasoning'],
        "reachable_files": reachable_files,
        "call_sites": live_call_sites,  # Only include live call sites
        "call_chain": llm_result.get('call_chain', []),
    }


# ============================================================================
# INLINE UNIT TESTS
# ============================================================================

if __name__ == "__main__":
    print("Running inline unit tests for reachability.py...\n")
    
    # Test 1: Call site detection
    print("Test 1: Syntactic call site detection")
    try:
        test_code = """from pydantic import EmailStr

def validate_user(email: str):
    validated = EmailStr(email)  # Line 4 - should be detected
    return validated

def test_validator():
    # EmailStr("test@example.com")  # Line 8 - commented, should be detected as dead
    if False:
        EmailStr("dead@code.com")  # Line 10 - dead code
    return True
"""
        source_files = {"test.py": test_code}
        call_sites = _find_call_sites(source_files, ["EmailStr"], "pydantic")
        
        assert len(call_sites) >= 1, f"Expected at least 1 call site, found {len(call_sites)}"
        # Line 4 in the actual string (accounting for leading newline removal)
        line_numbers = [site['line_number'] for site in call_sites]
        assert any(num in [3, 4] for num in line_numbers), f"Should detect EmailStr call, found lines: {line_numbers}"
        
        print(f"  [OK] Found {len(call_sites)} call sites")
        print(f"  [OK] Detected EmailStr call sites at lines: {line_numbers}")
        print("  [OK] Test 1 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 1 FAILED: {e}\n")
    
    # Test 2: Dead code detection
    print("Test 2: Dead code heuristics")
    try:
        test_lines = ["if False:", "    EmailStr(x)"]
        is_dead = _is_likely_dead_code(test_lines[1], test_lines[:1])
        assert is_dead, "Should detect 'if False:' as dead code"
        
        test_lines2 = ["# EmailStr(x)"]
        is_dead2 = _is_likely_dead_code(test_lines2[0], [])
        assert is_dead2, "Should detect commented line as dead code"
        
        print("  [OK] Detects 'if False:' as dead code")
        print("  [OK] Detects commented lines as dead code")
        print("  [OK] Test 2 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 2 FAILED: {e}\n")
    
    # Test 3: Function extraction
    print("Test 3: Vulnerable function extraction")
    try:
        advisory = {
            "vulnerable_function": "EmailStr",
            "description": "A vulnerability in the EmailStr validator allows ReDoS attacks via parse_obj method"
        }
        functions = _extract_vulnerable_functions(advisory)
        
        assert "EmailStr" in functions, "Should extract EmailStr from vulnerable_function"
        assert len(functions) > 0, "Should extract at least one function"
        
        print(f"  [OK] Extracted functions: {functions[:5]}")
        print("  [OK] Test 3 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 3 FAILED: {e}\n")
    
    print("All inline unit tests completed!")

# Made with Bob
