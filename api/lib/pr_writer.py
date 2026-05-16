"""
Generate a complete pull request title, body, and rollback plan.

This is the sixth and final stage of the ZeroDay pipeline. It uses the LLM
to compose a professional, GitHub-flavoured-Markdown pull request description
that summarises the vulnerability, explains the patch, presents test results,
and provides a step-by-step rollback procedure.

Dependencies
------------
lib.llm_client.complete
"""

from __future__ import annotations

import json
import re
from typing import Any

from lib.llm_client import complete


def write_pull_request(
    advisory: dict[str, Any],
    patch: dict[str, Any],
    test_result: dict[str, Any],
    reachability: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Draft a pull request title, description, labels, and rollback plan.

    Constructs a rich prompt from the advisory, patch, and test results, then
    asks the LLM to produce a structured JSON response containing all PR
    artefacts. Falls back to plain-text extraction if JSON parsing fails.

    Parameters
    ----------
    advisory : dict[str, Any]
        Parsed advisory from ``parse_cve_advisory``. Must contain ``cve_id``,
        ``description``, ``severity``, ``cvss_score``, and ``references``.
    patch : dict[str, Any]
        Structured patch from ``generate_patch``. Must contain ``patch_type``,
        ``diff``, ``changed_files``, ``patched_version``, ``explanation``,
        ``strategy_justification``, and ``alternatives_considered``.
    test_result : dict[str, Any]
        Test outcome from ``run_tests``. Must contain ``passed``,
        ``total_tests``, ``passed_tests``, ``failed_tests``, and
        ``prediction_based``.
    reachability : dict[str, Any] | None
        Optional reachability analysis result with ``is_reachable``,
        ``confidence``, and ``reasoning``.

    Returns
    -------
    dict[str, Any]
        A pull request artefact dictionary with the following keys:

        title : str
            A concise PR title following the Conventional Commits convention,
            e.g. ``"fix(deps): patch CVE-2024-3772 — pydantic ReDoS (CVSS 7.5)"``.
        description : str
            Full PR body in GitHub-flavoured Markdown. Must include sections
            for: vulnerability summary, severity, patch strategy, alternatives,
            test results, rollback plan, CVE reference, and ZeroDay footer.
        rollback_plan : str
            Step-by-step rollback instructions in Markdown, extracted from the
            ``description`` for convenient standalone display.
        stakeholder_summary : str
            4-6 sentence plain-English summary for executives explaining what
            happened, what was done, and what to expect.
        labels : list[str]
            Suggested GitHub label names for the PR (e.g. ``["security",
            "dependencies", "automated"]``).

    Raises
    ------
    RuntimeError
        If the LLM call fails.
    EnvironmentError
        If ANTHROPIC_API_KEY is not set.

    Dependencies
    ------------
    lib.llm_client.complete : sends the drafting prompt and receives the response.
    """
    # Build system prompt with strong voice and tone guidance
    system_prompt = """You are a senior security engineer at a large software company. You write clear, professional pull request descriptions for automated vulnerability remediations.

Your writing style:
- Concise and technical, but accessible to non-security engineers
- Always cite CVE numbers and CVSS scores
- Include rollback instructions for every change
- Explain "why" not just "what"
- Use active voice and present tense
- Format with GitHub-flavored Markdown

You are writing for three audiences:
1. Engineers who will review and merge the PR
2. Security team who needs to track remediation
3. Executives who need a plain-English summary

Be honest about limitations (e.g., if tests are predictions not executions)."""

    # Build comprehensive user prompt
    user_prompt = _build_user_prompt(advisory, patch, test_result, reachability)
    
    # Call LLM
    try:
        response = complete(user_prompt, system=system_prompt, max_tokens=3000)
        
        # Try to parse as JSON
        result = _parse_llm_response(response)
        
    except Exception as e:
        # Fallback to basic structure
        result = _create_fallback_pr(advisory, patch, test_result, str(e))
    
    # Ensure required fields and add footer
    result = _finalize_pr_artifacts(result, advisory, patch)
    
    return result


def _build_user_prompt(
    advisory: dict[str, Any],
    patch: dict[str, Any],
    test_result: dict[str, Any],
    reachability: dict[str, Any] | None,
) -> str:
    """
    Build comprehensive user prompt with all context.
    
    Parameters
    ----------
    advisory : dict
        CVE advisory data.
    patch : dict
        Patch generation result.
    test_result : dict
        Test execution/prediction result.
    reachability : dict | None
        Optional reachability analysis.
    
    Returns
    -------
    str
        Complete user prompt.
    """
    # Extract key data
    cve_id = advisory.get("cve_id", "unknown")
    severity = advisory.get("severity", "UNKNOWN")
    cvss_score = advisory.get("cvss_score", 0.0)
    description = advisory.get("description", "")
    references = advisory.get("references", [])[:5]
    
    patch_type = patch.get("patch_type", "unknown")
    explanation = patch.get("explanation", "")
    justification = patch.get("strategy_justification", "")
    alternatives = patch.get("alternatives_considered", [])
    changed_files = patch.get("changed_files", [])
    patched_version = patch.get("patched_version")
    diff = patch.get("diff", "")
    
    test_passed = test_result.get("passed", False)
    total_tests = test_result.get("total_tests", 0)
    passed_tests = test_result.get("passed_tests", 0)
    failed_tests = test_result.get("failed_tests", 0)
    prediction_based = test_result.get("prediction_based", False)
    test_confidence = test_result.get("confidence", 0.0)
    
    # Truncate diff if too long
    if len(diff) > 3000:
        diff = diff[:3000] + "\n... (diff truncated for brevity)"
    
    # Build reachability section
    reachability_text = ""
    if reachability:
        is_reachable = reachability.get("is_reachable", False)
        confidence = reachability.get("confidence", 0.0)
        reasoning = reachability.get("reasoning", "")
        reachability_text = f"""
**Reachability Analysis:**
- Vulnerable code path is {"reachable" if is_reachable else "NOT reachable"}
- Confidence: {confidence:.0%}
- Reasoning: {reasoning[:200]}
"""
    
    # Build alternatives section
    alternatives_text = ""
    if alternatives:
        alternatives_text = "\n**Alternatives Considered:**\n" + "\n".join(
            f"- {alt}" for alt in alternatives
        )
    
    prompt = f"""Write a professional pull request for this security patch.

## Vulnerability Details
**CVE:** {cve_id}
**Severity:** {severity} (CVSS {cvss_score})
**Description:** {description[:500]}

## Patch Strategy
**Type:** {patch_type}
**Explanation:** {explanation}
**Justification:** {justification}
{alternatives_text}

**Changed Files:** {', '.join(changed_files)}
{f"**Patched Version:** {patched_version}" if patched_version else ""}

## Diff
```diff
{diff}
```
{reachability_text}
## Test Results
**Status:** {"✅ PASSED" if test_passed else "❌ FAILED"}
**Total Tests:** {total_tests}
**Passed:** {passed_tests}
**Failed:** {failed_tests}
{"**Note:** Test results are LLM predictions, not actual execution" if prediction_based else ""}
{f"**Confidence:** {test_confidence:.0%}" if prediction_based else ""}

## References
{chr(10).join(f"- {ref}" for ref in references)}

---

Respond with a JSON object containing:

```json
{{
  "title": "Conventional Commits format title (max 72 chars)",
  "description": "Full GitHub Markdown PR description with sections: Summary, Vulnerability Details, Patch Strategy, Test Results, Rollback Plan, References",
  "rollback_plan": "Step-by-step rollback instructions in Markdown",
  "stakeholder_summary": "4-6 sentence plain-English summary for executives",
  "labels": ["security", "dependencies", "automated"]
}}
```

Make the title concise and informative. Include the CVE ID and severity.
The description should be comprehensive but scannable.
The stakeholder summary should explain: what happened, what we did, what to expect.
"""
    
    return prompt


def _parse_llm_response(response: str) -> dict[str, Any]:
    """
    Parse LLM response as JSON with fallback extraction.
    
    Parameters
    ----------
    response : str
        LLM response text.
    
    Returns
    -------
    dict
        Parsed PR artifacts.
    """
    # Try to extract JSON from code blocks
    json_match = re.search(r'```json\s*\n(.*?)\n```', response, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass
    
    # Try to parse entire response as JSON
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass
    
    # Fallback: extract fields with regex
    result = {}
    
    # Extract title
    title_match = re.search(r'"title"\s*:\s*"([^"]+)"', response)
    if title_match:
        result["title"] = title_match.group(1)
    else:
        # Use first non-empty line
        for line in response.split('\n'):
            if line.strip() and not line.strip().startswith('{'):
                result["title"] = line.strip()[:72]
                break
    
    # Extract description
    desc_match = re.search(r'"description"\s*:\s*"((?:[^"\\]|\\.)*)"', response, re.DOTALL)
    if desc_match:
        result["description"] = desc_match.group(1).replace('\\n', '\n')
    else:
        result["description"] = response
    
    # Extract rollback_plan
    rollback_match = re.search(r'"rollback_plan"\s*:\s*"((?:[^"\\]|\\.)*)"', response, re.DOTALL)
    if rollback_match:
        result["rollback_plan"] = rollback_match.group(1).replace('\\n', '\n')
    else:
        result["rollback_plan"] = "1. Revert this PR\n2. Monitor for issues\n3. Investigate alternative fixes"
    
    # Extract stakeholder_summary
    summary_match = re.search(r'"stakeholder_summary"\s*:\s*"((?:[^"\\]|\\.)*)"', response, re.DOTALL)
    if summary_match:
        result["stakeholder_summary"] = summary_match.group(1).replace('\\n', '\n')
    else:
        result["stakeholder_summary"] = "A security vulnerability was detected and automatically patched. The fix has been tested and is ready for review."
    
    # Extract labels
    labels_match = re.search(r'"labels"\s*:\s*\[(.*?)\]', response)
    if labels_match:
        labels_str = labels_match.group(1)
        result["labels"] = [l.strip().strip('"\'') for l in labels_str.split(',')]
    else:
        result["labels"] = ["security"]
    
    return result


def _create_fallback_pr(
    advisory: dict[str, Any],
    patch: dict[str, Any],
    test_result: dict[str, Any],
    error: str,
) -> dict[str, Any]:
    """
    Create basic PR structure when LLM fails.
    
    Parameters
    ----------
    advisory : dict
        CVE advisory.
    patch : dict
        Patch data.
    test_result : dict
        Test results.
    error : str
        Error message.
    
    Returns
    -------
    dict
        Basic PR structure.
    """
    cve_id = advisory.get("cve_id", "unknown")
    severity = advisory.get("severity", "UNKNOWN")
    cvss_score = advisory.get("cvss_score", 0.0)
    patch_type = patch.get("patch_type", "unknown")
    
    title = f"fix(security): patch {cve_id} ({severity} {cvss_score})"
    
    description = f"""## Security Patch: {cve_id}

**Severity:** {severity} (CVSS {cvss_score})

This PR applies an automated security patch for {cve_id}.

**Patch Type:** {patch_type}

**Test Status:** {"✅ Passed" if test_result.get("passed") else "❌ Failed"}

**Note:** PR generation encountered an issue: {error[:100]}

Please review the changes carefully before merging.
"""
    
    rollback_plan = """## Rollback Plan

1. Revert this PR using GitHub's revert button
2. Monitor application for any issues
3. Investigate alternative remediation strategies
"""
    
    stakeholder_summary = (
        f"A {severity.lower()}-severity security vulnerability ({cve_id}) was "
        f"detected in our application. An automated patch has been generated and "
        f"tested. The fix is ready for engineering review and deployment."
    )
    
    return {
        "title": title,
        "description": description,
        "rollback_plan": rollback_plan,
        "stakeholder_summary": stakeholder_summary,
        "labels": ["security"],
    }


def _finalize_pr_artifacts(
    result: dict[str, Any],
    advisory: dict[str, Any],
    patch: dict[str, Any],
) -> dict[str, Any]:
    """
    Finalize PR artifacts with footer and label normalization.
    
    Parameters
    ----------
    result : dict
        Parsed PR artifacts.
    advisory : dict
        CVE advisory.
    patch : dict
        Patch data.
    
    Returns
    -------
    dict
        Finalized PR artifacts.
    """
    cve_id = advisory.get("cve_id", "unknown")
    patch_type = patch.get("patch_type", "unknown")
    
    # Add ZeroDay footer to description
    footer = f"""

---

**🤖 Automated Security Patch**

This pull request was automatically generated by [ZeroDay](https://github.com/youraccount/zeroday) using IBM watsonx Code Assistant and Claude AI.

- **CVE Details:** https://nvd.nist.gov/vuln/detail/{cve_id}
- **Generated:** {_get_timestamp()}
- **Review Required:** ✅ Human review required before merge

*ZeroDay accelerates vulnerability response but does not replace security review. Please verify the patch addresses the vulnerability without introducing regressions.*
"""
    
    result["description"] = result.get("description", "") + footer
    
    # Normalize labels
    labels = set(result.get("labels", []))
    labels.add("security")
    labels.add("automated")
    
    if patch_type == "version_bump":
        labels.add("dependencies")
    
    result["labels"] = sorted(list(labels))
    
    # Ensure all required fields exist
    result.setdefault("title", f"fix(security): patch {cve_id}")
    result.setdefault("description", "Security patch")
    result.setdefault("rollback_plan", "Revert this PR if issues occur")
    result.setdefault("stakeholder_summary", "Security vulnerability patched")
    
    return result


def _get_timestamp() -> str:
    """Get current timestamp in ISO format."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ============================================================================
# INLINE UNIT TESTS
# ============================================================================

if __name__ == "__main__":
    print("Running inline unit tests for pr_writer.py...\n")
    
    # Test 1: Fallback PR creation
    print("Test 1: Fallback PR creation")
    try:
        advisory = {
            "cve_id": "CVE-2024-TEST",
            "severity": "HIGH",
            "cvss_score": 8.5,
        }
        patch = {
            "patch_type": "version_bump",
        }
        test_result = {
            "passed": True,
        }
        
        result = _create_fallback_pr(advisory, patch, test_result, "Test error")
        
        assert "CVE-2024-TEST" in result["title"], "Title should include CVE"
        assert "HIGH" in result["description"], "Description should include severity"
        assert len(result["rollback_plan"]) > 0, "Should have rollback plan"
        assert len(result["stakeholder_summary"]) > 0, "Should have stakeholder summary"
        
        print(f"  [OK] Title: {result['title']}")
        print(f"  [OK] Has rollback plan: {len(result['rollback_plan'])} chars")
        print(f"  [OK] Has stakeholder summary: {len(result['stakeholder_summary'])} chars")
        print("  [OK] Test 1 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 1 FAILED: {e}\n")
    
    # Test 2: Label normalization
    print("Test 2: Label normalization")
    try:
        result = {"labels": ["custom"]}
        advisory = {"cve_id": "CVE-TEST"}
        patch = {"patch_type": "version_bump"}
        
        finalized = _finalize_pr_artifacts(result, advisory, patch)
        
        assert "security" in finalized["labels"], "Should always have security label"
        assert "automated" in finalized["labels"], "Should always have automated label"
        assert "dependencies" in finalized["labels"], "Should have dependencies for version_bump"
        
        print(f"  [OK] Labels: {finalized['labels']}")
        print("  [OK] Test 2 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 2 FAILED: {e}\n")
    
    # Test 3: Footer addition
    print("Test 3: Footer addition")
    try:
        result = {"description": "Test description"}
        advisory = {"cve_id": "CVE-2024-TEST"}
        patch = {"patch_type": "code_fix"}
        
        finalized = _finalize_pr_artifacts(result, advisory, patch)
        
        assert "ZeroDay" in finalized["description"], "Should have ZeroDay footer"
        assert "CVE-2024-TEST" in finalized["description"], "Should link to CVE"
        assert "nvd.nist.gov" in finalized["description"], "Should link to NVD"
        
        print("  [OK] Footer added")
        print("  [OK] CVE link present")
        print("  [OK] Test 3 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 3 FAILED: {e}\n")
    
    print("All inline unit tests completed!")

# Made with Bob
