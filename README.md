# vibe-audit

**Security scanner for AI-built apps.** Catches hardcoded secrets, injection vulnerabilities, missing rate limits, exposed API keys, and more — then generates a scored HTML dashboard with one-click fix prompts for your coding agent.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/vipul510-web/vibe-audit?style=social)](https://github.com/vipul510-web/vibe-audit/stargazers)

---

## The problem

Vibe coders ship fast. Security gets skipped. Then:
- An API key in GitHub gets scraped by bots within minutes
- No rate limiting means someone burns your $500 OpenAI credit overnight
- A debug `print(api_key)` ends up in your server logs forever

vibe-audit runs in 30 seconds and tells you exactly what's wrong — in plain English, with fix prompts you can paste directly into Claude, Cursor, or Copilot.

---

## Demo

```
$ vibe-audit ./my-app

vibe-audit scanning /Users/you/my-app

✓ Secrets: 1 issue
✓ .env Leaks: clean
✓ Frontend Exposure: clean
✓ Injection (SQL/XSS/CMD): 3 issues
✓ Sensitive Logging: 2 issues
✓ Security Headers: 1 issue
✓ Rate Limiting: 1 issue
✓ Dependencies: clean
✓ Auth Issues: clean

Score: 34/100 (Grade F)
Issues: 8 total

  Severity   Category          Title                              File
 ──────────────────────────────────────────────────────────────────────
  CRITICAL   Secrets           OpenAI API Key (v2) detected       config.py:12
  HIGH       Sensitive Log     Sensitive value in log statement   main.py:304
  HIGH       Rate Limiting     No rate limiting detected          .
  ...

✓ Report saved to security-report.html
  Open it in your browser for the full dashboard with fix prompts.
```

Then open `security-report.html`:

![Dashboard showing score 34/100 with red/yellow/green category cards and expandable findings with copy-paste fix prompts](https://raw.githubusercontent.com/vipul510-web/vibe-audit/main/docs/screenshot.png)

Each finding includes a **copy-paste prompt** for your AI agent:

> *"In config.py, line 12, move the hardcoded OpenAI API key to a .env file and reference it via os.environ['OPENAI_API_KEY']. Add .env to .gitignore if not already present."*

---

## What it checks

| Category | What's detected |
|---|---|
| **Secrets** | Hardcoded API keys (OpenAI, AWS, Stripe, GitHub, Google, Slack, Twilio), passwords, private keys, access tokens |
| **.env Leaks** | `.env` committed to git, not in `.gitignore`, missing `.env.example`, subdirectory `.env` files |
| **Frontend Exposure** | API keys in `.js`/`.ts`/`.html` files, `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` variables that contain secrets |
| **SQL/XSS Injection** | F-string SQL queries, string-concatenated queries, `innerHTML` with variables, `dangerouslySetInnerHTML`, `eval()`, Flask `render_template_string` |
| **Command Injection** | `subprocess` with string concatenation, `os.system`, Node.js `execSync`/`execFile`, `child_process.exec` |
| **Sensitive Logging** | API keys/tokens interpolated in `print()`, `logger.info()`, `console.log()` |
| **Security Headers** | Missing `flask-talisman`, `helmet.js`, Next.js headers config, FastAPI middleware, Django `SECURE_*` settings |
| **Rate Limiting** | API routes with no rate limiting (`flask-limiter`, `slowapi`, `express-rate-limit` not detected) |
| **Dependencies** | Known CVEs via `pip-audit` (Python) and `npm audit` (Node) |
| **Auth Issues** | Weak JWT secrets, MD5/SHA1 for password hashing, `DEBUG=True`, CORS wildcards, SSL verification disabled |

---

## Installation

**From GitHub (latest):**
```bash
pip install git+https://github.com/vipul510-web/vibe-audit.git
```

**From source:**
```bash
git clone https://github.com/vipul510-web/vibe-audit
cd vibe-audit
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

---

## Usage

```bash
# Scan current directory (with AI fix prompts)
export OPENAI_API_KEY=sk-...
vibe-audit .

# Scan a specific project
vibe-audit /path/to/your/project

# Free mode — no API key needed, no AI analysis
vibe-audit . --no-ai

# Save report to a custom path
vibe-audit . --output ~/reports/myapp-security.html

# Install pre-commit hook (blocks commits with CRITICAL findings)
vibe-audit . --install-hooks
```

### CLI flags

| Flag | Default | Description |
|---|---|---|
| `path` | `.` | Project directory to scan |
| `--output` | `security-report.html` | HTML report output path |
| `--no-ai` | off | Skip GPT-4o analysis (free, faster) |
| `--install-hooks` | off | Install pre-commit hook in target project |
| `--pre-commit` | off | Pre-commit mode: exits 1 on CRITICAL only |
| `--limit` | `500` | Max files to scan |

---

## Pre-commit hook

Automatically blocks commits that introduce CRITICAL findings (hardcoded secrets, key exposure):

```bash
vibe-audit . --install-hooks
```

This writes a hook to `.git/hooks/pre-commit` that runs a fast scan (no AI) on every commit. Only CRITICAL findings block the commit — HIGH/MEDIUM are advisory.

---

## Suppress a false positive

Add `# vibe-audit-ignore` on the line to skip it:

```python
PLACEHOLDER_KEY = "sk-test-example-not-real"  # vibe-audit-ignore
```

---

## AI analysis (GPT-4o)

When `OPENAI_API_KEY` is set, vibe-audit makes a **single GPT-4o call per scan** (not per finding) to:
- Explain each finding in plain English — no jargon
- Generate a specific fix prompt you can paste into your AI coding agent
- Filter false positives the static scanner can't determine on its own

**Cost:** ~$0.01–0.05 per scan depending on number of findings. Run `--no-ai` for free static-only analysis.

---

## Scoring

| Score | Grade | Meaning |
|---|---|---|
| 90–100 | A | Clean — ready to ship |
| 75–89 | B | Minor issues — fix before launch |
| 60–74 | C | Moderate issues — fix this week |
| 40–59 | D | Significant issues — fix before any real users |
| 0–39 | F | Critical issues — do not ship |

Each finding deducts points: CRITICAL −20, HIGH −12, MEDIUM −5, LOW −2. INFO findings (like `innerHTML` advisories) do not affect the score.

---

## Compared to alternatives

| Tool | Scans full project | Vibe-coder friendly output | Fix prompts for AI agents | Pre-commit hook | Free tier |
|---|---|---|---|---|---|
| **vibe-audit** | ✓ | ✓ | ✓ | ✓ | ✓ (--no-ai) |
| Claude `/security-review` | Diff only | ✓ | ✓ | ✗ | ✓ |
| VibeCheckAudit | ✓ | ✓ | ✗ | ✗ | ✗ (human service, paid) |
| ship-safe | ✓ | Partial | ✗ | ✗ | ✓ |
| GitGuardian | Secrets only | ✗ | ✗ | ✓ | Limited |
| semgrep / bandit | ✓ | ✗ | ✗ | ✓ | ✓ |

---

## Project structure

```
vibe_audit/
├── cli.py              # Entry point, orchestrates scan + report
├── models.py           # Finding dataclass, scoring logic
├── ai_analyzer.py      # GPT-4o enrichment (explanations + fix prompts)
├── scanner/
│   ├── secrets.py      # Hardcoded secrets (API keys, passwords, tokens)
│   ├── dotenv_check.py # .env committed to git / missing from .gitignore
│   ├── frontend.py     # API keys in JS/HTML/TS frontend files
│   ├── injection.py    # SQL injection, XSS, command injection
│   ├── logging_check.py# Sensitive values in log statements
│   ├── headers.py      # Security headers per framework
│   ├── ratelimit.py    # Rate limiting library detection
│   ├── deps.py         # pip-audit + npm audit CVE scanning
│   └── auth.py         # Auth weakness patterns
├── report/
│   └── dashboard.py    # Self-contained HTML report generator
└── hooks/
    └── installer.py    # Git pre-commit hook installer
```

---

## Roadmap

- [ ] PyPI package (`pip install vibe-audit`)
- [ ] GitHub Action (`uses: vipul510-web/vibe-audit@v1`)
- [ ] Supabase RLS misconfiguration checks
- [ ] Next.js / Vercel specific checks
- [ ] Privacy policy / data handling checklist
- [ ] SARIF output for GitHub Security tab integration

---

## Contributing

Issues and PRs welcome. When adding a new scanner:
1. Create `vibe_audit/scanner/your_check.py` returning `list[Finding]`
2. Add it to `vibe_audit/scanner/__init__.py`
3. Add it to the `SCANNERS` list in `cli.py`
4. Test against a project that should trigger it

---

## License

MIT — see [LICENSE](LICENSE)
