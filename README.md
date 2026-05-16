# ZeroDay — CVE Patch Sprinter

ZeroDay is a proof-of-concept tool that automatically responds to newly
disclosed software vulnerabilities. Given a GitHub repository URL and a CVE
identifier, it fetches the NVD advisory, scans the target repository for the
affected dependency, determines whether the vulnerable code path is actually
reachable, generates a minimal remediation patch (either a version bump or a
code-level fix), runs the repository's existing test suite against the patch,
and produces a ready-to-open pull request description — all streamed live to
the browser as a six-stage pipeline.

---

## Local Development

### Prerequisites

| Tool | Version |
|------|---------|
| Node.js | 18+ |
| Python | 3.12 |
| Vercel CLI | latest (`npm i -g vercel`) |

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/<your-org>/zeroday.git
cd zeroday

# 2. Install JavaScript dependencies
npm install

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env.local
# Edit .env.local and fill in ANTHROPIC_API_KEY and GITHUB_TOKEN
```

### Run with Vercel Dev (recommended)

`vercel dev` starts the Next.js frontend and the Python serverless functions
together, exactly as they will behave in production:

```bash
vercel dev
# Open http://localhost:3000
```

### Run the Next.js frontend only (no Python functions)

```bash
npm run dev
# Open http://localhost:3000
# Note: /api/analyze calls will fail until the Python functions are running.
```

---

## Environment Variables

Copy `.env.example` to `.env.local` and fill in:

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Required. Anthropic API key for all LLM calls. |
| `GITHUB_TOKEN` | Required. GitHub personal access token (read scope). |

---

## Deployment

### Deploy to Vercel

```bash
# First-time setup
vercel link          # link to a Vercel project
vercel env add ANTHROPIC_API_KEY
vercel env add GITHUB_TOKEN

# Deploy to preview
vercel deploy

# Promote to production
vercel --prod
```

The `vercel.json` at the repository root routes `/api/*` requests to the
Python 3.12 runtime and serves the Next.js build for all other paths.

---

## Running the Demo

The `demo_targets/vulnerable_flask/` directory contains a minimal Flask
application that pins `pydantic==1.10.0`, which is vulnerable to
**CVE-2024-3772** (regular-expression denial-of-service in the EmailStr
validator).

To use it as a ZeroDay target:

1. Push the `demo_targets/vulnerable_flask/` directory as a **public** GitHub
   repository (or fork the main repo and use that URL).
2. Open ZeroDay in your browser.
3. Enter the repository URL and CVE ID:
   - **Repository URL:** `https://github.com/<your-org>/vulnerable-flask`
   - **CVE ID:** `CVE-2024-3772`
4. Click **Start** and watch the pipeline run live.

---

## Project Structure

```
zeroday/
├── app/                        # Next.js App Router (frontend)
│   ├── layout.tsx
│   ├── page.tsx                # Main interactive page
│   └── globals.css
├── components/                 # React UI components
│   ├── PipelineForm.tsx        # Repo URL + CVE ID inputs
│   ├── ProgressPanel.tsx       # Six-stage live progress display
│   ├── StageRow.tsx            # Individual pipeline stage row
│   ├── ElapsedTimer.tsx        # Live elapsed-time counter
│   ├── DiffViewer.tsx          # Syntax-highlighted unified diff
│   └── ResultsPanel.tsx        # Patch + PR description display
├── types/
│   └── index.ts                # Shared TypeScript types
├── api/
│   ├── analyze.py              # Main SSE streaming endpoint
│   └── lib/
│       ├── llm_client.py       # ✅ Anthropic SDK wrapper (complete)
│       ├── github_client.py    # ✅ GitHub REST API wrapper (complete)
│       ├── nvd_client.py       # ✅ NVD API client (complete)
│       ├── cve_parser.py       # 🔧 Stub — IBM Bob
│       ├── repo_scanner.py     # 🔧 Stub — IBM Bob
│       ├── reachability.py     # 🔧 Stub — IBM Bob
│       ├── patch_generator.py  # 🔧 Stub — IBM Bob
│       ├── test_runner.py      # 🔧 Stub — IBM Bob
│       └── pr_writer.py        # 🔧 Stub — IBM Bob
├── demo_targets/
│   └── vulnerable_flask/       # CVE-2024-3772 demo target
├── vercel.json                 # Vercel routing configuration
├── requirements.txt            # Python dependencies (root)
├── package.json                # Node dependencies
└── .env.example                # Environment variable template
```

---

## Built with IBM Bob

The algorithmic core of ZeroDay — CVE advisory parsing, repository scanning,
reachability analysis, patch generation, test execution, and pull request
writing — was designed to be implemented inside **Visual Studio** using
[IBM Bob](https://www.ibm.com/products/watsonx-code-assistant), IBM's
repository-aware AI coding assistant.

The six stub functions in `api/lib/` (marked 🔧 above) each contain detailed
plain-English implementation notes written for Bob, specifying the inputs,
outputs, external API calls, LLM prompt structure, and error-handling
requirements for each stage. Bob's repository-aware context window allows it
to reason across all six stubs simultaneously and implement them with full
awareness of the shared data contracts between stages.

The exported IBM Bob session report is included with the hackathon submission.

---

## License

MIT — see [LICENSE](./LICENSE).
