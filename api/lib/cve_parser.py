"""
Parse a raw NVD advisory dictionary into a clean, structured representation.

This module is the first stage of the ZeroDay pipeline. It calls the NVD
client to fetch the raw advisory JSON and distils it into the canonical
shape that all downstream stages consume.

Dependencies
------------
lib.nvd_client.get_advisory
"""

from __future__ import annotations

from typing import Any

from lib.nvd_client import get_advisory


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
        severity : str
            CVSS v3.x severity level: one of ``"CRITICAL"``, ``"HIGH"``,
            ``"MEDIUM"``, ``"LOW"``, or ``"NONE"``.
        cvss_score : float
            CVSS v3.x base score in the range 0.0–10.0.
        affected_packages : list[dict]
            Each element has keys ``vendor`` (str), ``product`` (str),
            ``version_start`` (str | None), and ``version_end`` (str | None)
            describing the vulnerable version range.
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
    """
    # -------------------------------------------------------------------------
    # IMPLEMENTATION NOTES FOR IBM BOB
    #
    # 1. Call get_advisory(cve_id) to obtain the raw NVD "cve" object.
    #    Store the result in a variable called `raw`.
    #
    # 2. Extract the English description:
    #    Iterate raw.get("descriptions", []) and find the item where
    #    item["lang"] == "en". Use item["value"] as the description.
    #    Default to "" if not found.
    #
    # 3. Extract CVSS v3 score and severity:
    #    Try raw["metrics"].get("cvssMetricV31", []) first, then fall back to
    #    raw["metrics"].get("cvssMetricV30", []). Take the first element.
    #    Read cvss_data = element["cvssData"]; then:
    #      severity  = cvss_data.get("baseSeverity", "NONE")
    #      cvss_score = float(cvss_data.get("baseScore", 0.0))
    #
    # 4. Build affected_packages:
    #    Iterate raw.get("configurations", []). For each configuration node,
    #    iterate its "nodes" list. Each node has "cpeMatch" items. For items
    #    where item["vulnerable"] is True, parse the CPE URI in item["criteria"]
    #    to extract vendor (part[3]) and product (part[4]).
    #    Read version bounds from item.get("versionStartIncluding"),
    #    item.get("versionStartExcluding"), item.get("versionEndIncluding"),
    #    item.get("versionEndExcluding"). Store them as version_start and
    #    version_end (use the tightest bounds available).
    #
    # 5. Extract CWE IDs:
    #    Iterate raw.get("weaknesses", []). For each weakness, iterate
    #    weakness["description"] and collect item["value"] strings that start
    #    with "CWE-".
    #
    # 6. Extract reference URLs:
    #    Iterate raw.get("references", []) and collect ref["url"] for each.
    #
    # 7. Return the structured dictionary described in the Returns section above.
    #    Use .get() with sensible defaults for every field so missing data never
    #    raises a KeyError.
    # -------------------------------------------------------------------------
    raise NotImplementedError("IBM Bob will implement this in a subsequent session")
