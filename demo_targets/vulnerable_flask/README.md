# vulnerable-flask — ZeroDay Demo Target

> **WARNING: This application is intentionally vulnerable. Do not deploy it
> to a production environment or expose it to the internet.**

This minimal Flask application exists solely as a demonstration target for the
[ZeroDay CVE Patch Sprinter](../../README.md) tool.

## Vulnerability

| Field | Value |
|-------|-------|
| CVE ID | **CVE-2024-3772** |
| Package | `pydantic==1.10.0` |
| Type | Regular-Expression Denial of Service (ReDoS) |
| CVSS Score | 7.5 (High) |
| Reachable via | `POST /register` → `EmailStr` validator |

The `EmailStr` type in pydantic 1.x uses a complex regular expression to
validate email addresses. A specially crafted input string triggers
catastrophic backtracking, causing the validation call to run for a very
long time and effectively hanging the request thread.

The fix is to upgrade `pydantic` to version `>=2.7.1` (or `>=1.10.14` on
the legacy 1.x line, though that branch is now end-of-life).

## Running Locally

```bash
cd demo_targets/vulnerable_flask
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

## Running Tests

```bash
pytest tests/ -v
```

## Using as a ZeroDay Target

Once this directory is pushed as a public GitHub repository, you can point
ZeroDay at it by entering:

- **GitHub Repository URL:** `https://github.com/<your-org>/vulnerable-flask`
- **CVE Identifier:** `CVE-2024-3772`

ZeroDay will scan the repository, confirm the vulnerability is reachable via
the `/register` endpoint, generate a version-bump patch updating
`pydantic==1.10.0` to a safe release, run the test suite, and draft a pull
request description.
