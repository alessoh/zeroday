"""
Client for the National Vulnerability Database (NVD) public REST API v2.0.

No API key is required, but NVD may rate-limit unauthenticated requests to
5 requests per 30 seconds. If you have an NVD API key, set it in the
``NVD_API_KEY`` environment variable and it will be sent automatically.

Reference: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import os
from typing import Any

import requests

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT = 30  # seconds — NVD can be slow under load


def _headers() -> dict[str, str]:
    """Build request headers, adding NVD API key authentication if available."""
    hdrs: dict[str, str] = {"Accept": "application/json"}
    key = os.environ.get("NVD_API_KEY")
    if key:
        hdrs["apiKey"] = key
    return hdrs


def get_advisory(cve_id: str) -> dict[str, Any]:
    """
    Fetch structured advisory data for a single CVE from the NVD API.

    The returned dictionary is the ``cve`` object nested within the first
    ``vulnerabilities`` entry of the NVD response. It contains sub-keys
    such as ``id``, ``descriptions``, ``metrics``, ``weaknesses``,
    ``configurations``, and ``references``.

    Parameters
    ----------
    cve_id : str
        A CVE identifier in the form ``CVE-YYYY-NNNNN``
        (e.g. ``CVE-2024-3772``). Normalised to uppercase before the request.

    Returns
    -------
    dict[str, Any]
        The ``cve`` sub-object from the NVD API response for the given CVE.

    Raises
    ------
    ValueError
        If no vulnerability matching ``cve_id`` is found in the NVD database.
    TimeoutError
        If the NVD API does not respond within the timeout window.
    RuntimeError
        If the NVD API returns a non-success HTTP status or a network error
        occurs.

    Examples
    --------
    >>> advisory = get_advisory("CVE-2024-3772")
    >>> advisory["id"]
    'CVE-2024-3772'
    """
    normalized = cve_id.strip().upper()
    params: dict[str, str] = {"cveId": normalized}

    try:
        resp = requests.get(
            _NVD_BASE,
            params=params,
            headers=_headers(),
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
    except requests.Timeout as exc:
        raise TimeoutError(
            f"NVD API timed out after {_TIMEOUT}s while fetching {normalized}"
        ) from exc
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        raise RuntimeError(
            f"NVD API returned HTTP {status} for {normalized}"
        ) from exc
    except requests.RequestException as exc:
        raise RuntimeError(
            f"NVD API request failed for {normalized}: {exc}"
        ) from exc

    try:
        data: dict[str, Any] = resp.json()
    except ValueError as exc:
        raise RuntimeError(
            f"NVD API returned non-JSON response for {normalized}"
        ) from exc

    vulnerabilities: list[dict[str, Any]] = data.get("vulnerabilities", [])
    if not vulnerabilities:
        raise ValueError(
            f"No NVD advisory found for {normalized}. "
            "Check that the CVE ID is correct and has been published."
        )

    cve_object: dict[str, Any] = vulnerabilities[0].get("cve", {})
    return cve_object
