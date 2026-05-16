"""
Parse a raw NVD advisory dictionary into a clean, structured representation.

This module is the first stage of the ZeroDay pipeline. It calls the NVD
client to fetch the raw advisory JSON and distils it into the canonical
shape that all downstream stages consume.

Dependencies
------------
lib.nvd_client.get_advisory
lib.llm_client.complete (for inferring vulnerable function names)
"""

from __future__ import annotations

import json
import re
from typing import Any

from lib.nvd_client import get_advisory
from lib.llm_client import complete


def parse_cve_advisory(cve_id: str) -> dict[str, Any]:
    """
    Fetch and normalise a CVE advisory from the National Vulnerability Database.

    Calls ``lib.nvd_client.get_advisory`` to retrieve the raw NVD JSON object,
    then extracts the fields that the rest of the pipeline relies on into a
    flat, well-typed dictionary.

    Parameters
    ----------
    cve_id : str
        A CVE identifier such as ``"CVE-2024-3772"``. Case-insensitive; the
        function normalises it to uppercase before passing it to the NVD client.

    Returns
    -------
    dict[str, Any]
        A structured advisory dictionary with the following keys:

        cve_id : str
            Canonical CVE identifier, upper-cased (e.g. ``"CVE-2024-3772"``).
        description : str
            English-language plain-text description of the vulnerability.
        summary : str
            One-paragraph plain-language summary suitable for human review.
        severity : str
            CVSS v3.x severity level: one of ``"CRITICAL"``, ``"HIGH"``,
            ``"MEDIUM"``, ``"LOW"``, or ``"NONE"``.
        cvss_score : float
            CVSS v3.x base score in the range 0.0–10.0.
        affected_packages : list[dict]
            Each element has keys ``vendor`` (str), ``product`` (str),
            ``version_start`` (str | None), ``version_end`` (str | None),
            ``version_start_inclusive`` (bool), ``version_end_inclusive`` (bool)
            describing the vulnerable version range with boundary semantics.
        vulnerable_function : str | None
            Name of the vulnerable function or pattern if mentioned in the
            advisory description, or inferred via LLM if not explicit.
        function_inferred : bool
            True if vulnerable_function was inferred by LLM, False if explicit.
        cwe_ids : list[str]
            CWE identifiers for the weakness class (e.g. ``["CWE-1333"]``).
        references : list[str]
            URLs pointing to patches, changelogs, security advisories, or
            GitHub issues related to this CVE.

    Raises
    ------
    ValueError
        If the NVD returns no entry for the given CVE ID.
    RuntimeError
        If the NVD API call fails for any reason.

    Dependencies
    ------------
    lib.nvd_client.get_advisory : fetches the raw NVD JSON object.
    lib.llm_client.complete : infers vulnerable function names when not explicit.
    """
    # Normalize CVE ID and fetch raw advisory
    normalized_cve_id = cve_id.strip().upper()
    raw = get_advisory(normalized_cve_id)

    # Extract English description
    description = ""
    for desc_item in raw.get("descriptions", []):
        if desc_item.get("lang") == "en":
            description = desc_item.get("value", "")
            break

    # Extract CVSS v3 score and severity (try v3.1 first, then v3.0)
    severity = "NONE"
    cvss_score = 0.0
    metrics = raw.get("metrics", {})
    cvss_metrics = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
    if cvss_metrics:
        cvss_data = cvss_metrics[0].get("cvssData", {})
        severity = cvss_data.get("baseSeverity", "NONE")
        cvss_score = float(cvss_data.get("baseScore", 0.0))

    # Build affected_packages with version boundary semantics
    affected_packages: list[dict[str, Any]] = []
    seen_packages: set[tuple[str, str]] = set()  # Track (vendor, product) to avoid duplicates

    for config in raw.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue

                # Parse CPE URI: cpe:2.3:a:vendor:product:version:...
                cpe_uri = cpe_match.get("criteria", "")
                parts = cpe_uri.split(":")
                if len(parts) < 5:
                    continue

                vendor = parts[3] if parts[3] != "*" else "unknown"
                product = parts[4] if parts[4] != "*" else "unknown"

                # Skip if we've already seen this vendor/product combination
                pkg_key = (vendor, product)
                if pkg_key in seen_packages:
                    continue
                seen_packages.add(pkg_key)

                # Extract version bounds with boundary semantics
                version_start = None
                version_start_inclusive = True
                version_end = None
                version_end_inclusive = True

                if "versionStartIncluding" in cpe_match:
                    version_start = cpe_match["versionStartIncluding"]
                    version_start_inclusive = True
                elif "versionStartExcluding" in cpe_match:
                    version_start = cpe_match["versionStartExcluding"]
                    version_start_inclusive = False

                if "versionEndIncluding" in cpe_match:
                    version_end = cpe_match["versionEndIncluding"]
                    version_end_inclusive = True
                elif "versionEndExcluding" in cpe_match:
                    version_end = cpe_match["versionEndExcluding"]
                    version_end_inclusive = False

                affected_packages.append({
                    "vendor": vendor,
                    "product": product,
                    "version_start": version_start,
                    "version_start_inclusive": version_start_inclusive,
                    "version_end": version_end,
                    "version_end_inclusive": version_end_inclusive,
                })

    # Extract CWE IDs
    cwe_ids: list[str] = []
    for weakness in raw.get("weaknesses", []):
        for desc_item in weakness.get("description", []):
            value = desc_item.get("value", "")
            if value.startswith("CWE-"):
                cwe_ids.append(value)

    # Extract reference URLs
    references: list[str] = []
    for ref in raw.get("references", []):
        url = ref.get("url")
        if url:
            references.append(url)

    # Extract or infer vulnerable function name
    vulnerable_function, function_inferred = _extract_vulnerable_function(
        description, normalized_cve_id
    )

    # Generate plain-language summary
    summary = _generate_summary(
        normalized_cve_id, description, severity, cvss_score, affected_packages
    )

    return {
        "cve_id": normalized_cve_id,
        "description": description,
        "summary": summary,
        "severity": severity,
        "cvss_score": cvss_score,
        "affected_packages": affected_packages,
        "vulnerable_function": vulnerable_function,
        "function_inferred": function_inferred,
        "cwe_ids": cwe_ids,
        "references": references,
    }


def _extract_vulnerable_function(description: str, cve_id: str) -> tuple[str | None, bool]:
    """
    Extract or infer the vulnerable function/pattern name from the description.

    First attempts to find explicit function names using regex patterns.
    If none found, uses LLM to infer the most likely vulnerable function.

    Parameters
    ----------
    description : str
        The CVE description text.
    cve_id : str
        The CVE identifier for context.

    Returns
    -------
    tuple[str | None, bool]
        (function_name, is_inferred) where is_inferred is True if LLM was used.
    """
    if not description:
        return None, False

    # Try to find explicit function names in common patterns
    # Pattern 1: "in the <function_name> function"
    # Pattern 2: "function <function_name>"
    # Pattern 3: "<ClassName>.<method_name>"
    # Pattern 4: code-like identifiers in backticks
    patterns = [
        r"in the ([a-zA-Z_][a-zA-Z0-9_]*) function",
        r"function ([a-zA-Z_][a-zA-Z0-9_]*)",
        r"([A-Z][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*)",
        r"`([a-zA-Z_][a-zA-Z0-9_\.]*)`",
        r"([a-zA-Z_][a-zA-Z0-9_]*)\(\)",  # function calls
    ]

    for pattern in patterns:
        matches = re.findall(pattern, description)
        if matches:
            # Return the first match that looks like a function name
            for match in matches:
                # Filter out common words that aren't function names
                if match.lower() not in {"the", "a", "an", "is", "are", "was", "were"}:
                    return match, False

    # No explicit function found - use LLM to infer
    try:
        prompt = f"""Given this CVE description, identify the most likely vulnerable function, method, class, or API pattern name. If multiple are mentioned, choose the primary one. Respond with ONLY the function/method/class name, nothing else. If you cannot identify one, respond with "NONE".

CVE: {cve_id}
Description: {description[:1000]}

Vulnerable function/method/class name:"""

        system = "You are a security analyst extracting technical details from CVE advisories. Be concise and precise."

        response = complete(prompt, system=system, max_tokens=100)
        inferred_name = response.strip().strip('"\'`')

        if inferred_name and inferred_name.upper() != "NONE" and len(inferred_name) < 100:
            return inferred_name, True

    except Exception:
        # If LLM call fails, gracefully return None
        pass

    return None, False


def _generate_summary(
    cve_id: str,
    description: str,
    severity: str,
    cvss_score: float,
    affected_packages: list[dict[str, Any]],
) -> str:
    """
    Generate a one-paragraph plain-language summary for human review.

    Parameters
    ----------
    cve_id : str
        The CVE identifier.
    description : str
        The full CVE description.
    severity : str
        CVSS severity level.
    cvss_score : float
        CVSS base score.
    affected_packages : list[dict]
        List of affected package dictionaries.

    Returns
    -------
    str
        A concise summary paragraph.
    """
    # Extract package names for summary
    package_names = []
    for pkg in affected_packages[:3]:  # Limit to first 3 packages
        product = pkg.get("product", "unknown")
        if product != "unknown":
            package_names.append(product)

    packages_str = ", ".join(package_names) if package_names else "affected software"

    # Truncate description to first sentence or 200 chars
    desc_summary = description[:200].split(".")[0] if description else "No description available"
    if len(description) > 200:
        desc_summary += "..."

    summary = (
        f"{cve_id} is a {severity} severity vulnerability (CVSS {cvss_score}) "
        f"affecting {packages_str}. {desc_summary}."
    )

    return summary


# ============================================================================
# INLINE UNIT TESTS
# ============================================================================

if __name__ == "__main__":
    print("Running inline unit tests for cve_parser.py...\n")

    # Test 1: CVE-2024-3772 (pydantic ReDoS)
    print("Test 1: CVE-2024-3772 (pydantic ReDoS vulnerability)")
    try:
        advisory = parse_cve_advisory("CVE-2024-3772")
        assert advisory["cve_id"] == "CVE-2024-3772", "CVE ID mismatch"
        assert advisory["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"], f"Invalid severity: {advisory['severity']}"
        assert 0.0 <= advisory["cvss_score"] <= 10.0, f"Invalid CVSS score: {advisory['cvss_score']}"
        assert len(advisory["affected_packages"]) > 0, "No affected packages found"
        assert any("pydantic" in pkg["product"].lower() for pkg in advisory["affected_packages"]), "pydantic not in affected packages"
        assert advisory["description"], "Description is empty"
        assert advisory["summary"], "Summary is empty"
        assert "vulnerable_function" in advisory, "Missing vulnerable_function field"
        assert "function_inferred" in advisory, "Missing function_inferred field"
        print(f"  [OK] CVE ID: {advisory['cve_id']}")
        print(f"  [OK] Severity: {advisory['severity']} (CVSS {advisory['cvss_score']})")
        print(f"  [OK] Affected packages: {len(advisory['affected_packages'])}")
        print(f"  [OK] Vulnerable function: {advisory['vulnerable_function']} (inferred: {advisory['function_inferred']})")
        print(f"  [OK] Summary: {advisory['summary'][:100]}...")
        print("  [OK] Test 1 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 1 FAILED: {e}\n")

    # Test 2: CVE-2024-27351 (Django SQL injection)
    print("Test 2: CVE-2024-27351 (Django SQL injection)")
    try:
        advisory = parse_cve_advisory("CVE-2024-27351")
        assert advisory["cve_id"] == "CVE-2024-27351", "CVE ID mismatch"
        assert advisory["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"], f"Invalid severity: {advisory['severity']}"
        assert len(advisory["affected_packages"]) > 0, "No affected packages found"
        # Check version boundary semantics
        for pkg in advisory["affected_packages"]:
            assert "version_start_inclusive" in pkg, "Missing version_start_inclusive"
            assert "version_end_inclusive" in pkg, "Missing version_end_inclusive"
            assert isinstance(pkg["version_start_inclusive"], bool), "version_start_inclusive not bool"
            assert isinstance(pkg["version_end_inclusive"], bool), "version_end_inclusive not bool"
        print(f"  [OK] CVE ID: {advisory['cve_id']}")
        print(f"  [OK] Severity: {advisory['severity']} (CVSS {advisory['cvss_score']})")
        print(f"  [OK] Version boundary semantics validated")
        print(f"  [OK] CWE IDs: {advisory['cwe_ids']}")
        print("  [OK] Test 2 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 2 FAILED: {e}\n")

    # Test 3: CVE-2024-21626 (runc container escape)
    print("Test 3: CVE-2024-21626 (runc container escape)")
    try:
        advisory = parse_cve_advisory("CVE-2024-21626")
        assert advisory["cve_id"] == "CVE-2024-21626", "CVE ID mismatch"
        assert advisory["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"], f"Invalid severity: {advisory['severity']}"
        assert len(advisory["references"]) > 0, "No references found"
        assert all(ref.startswith("http") for ref in advisory["references"]), "Invalid reference URLs"
        print(f"  [OK] CVE ID: {advisory['cve_id']}")
        print(f"  [OK] Severity: {advisory['severity']} (CVSS {advisory['cvss_score']})")
        print(f"  [OK] References: {len(advisory['references'])} URLs")
        print(f"  [OK] Vulnerable function: {advisory['vulnerable_function']} (inferred: {advisory['function_inferred']})")
        print("  [OK] Test 3 PASSED\n")
    except Exception as e:
        print(f"  [FAIL] Test 3 FAILED: {e}\n")

    print("All inline unit tests completed!")

# Made with Bob
