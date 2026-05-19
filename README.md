# vibe-audit

Automated security scanner for vibe-coded apps. Runs 9 security checks, scores your project 0–100, and generates an HTML dashboard with copy-paste fix prompts for your AI coding agent.

## What it checks

| Category | What's scanned |
|---|---|
| Secrets | Hardcoded API keys, tokens, passwords in source code |
| .env leaks | `.env` files committed to git or missing from `.gitignore` |
| Frontend exposure | API keys bundled into JS/HTML sent to the browser |
| SQL / XSS injection | String-concatenated queries, unsanitized HTML rendering |
| Sensitive logging | Passwords/tokens printed to logs |
| Security headers | Missing HSTS, CSP, X-Frame-Options config |
| Rate limiting | API routes with no rate limit protection |
| Dependencies | Known CVEs in `requirements.txt` / `package.json` |
| Auth issues | Weak JWT secrets, plain-text passwords, missing auth checks |

## Setup

```bash
pip install vibe-audit
```

Or from source:

```bash
git clone https://github.com/YOUR_USERNAME/vibe-audit
cd vibe-audit
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Set your OpenAI key for AI-powered fix prompts:

```bash
export OPENAI_API_KEY=sk-...
```

## Usage

```bash
# Scan current directory
vibe-audit .

# Scan a specific project
vibe-audit /path/to/your/project

# Skip AI analysis (free, faster)
vibe-audit . --no-ai

# Save report to custom path
vibe-audit . --output my-report.html

# Install pre-commit hook in a project
vibe-audit . --install-hooks

# Pre-commit mode (used by the hook — blocks on CRITICAL only)
vibe-audit . --pre-commit --no-ai
```

## CLI flags

| Flag | Default | Description |
|---|---|---|
| `path` | `.` | Project directory to scan |
| `--output` | `security-report.html` | Output path for HTML report |
| `--no-ai` | off | Skip GPT-4o analysis |
| `--install-hooks` | off | Install pre-commit hook in target project |
| `--pre-commit` | off | Pre-commit mode: exit 1 on CRITICAL findings |
| `--limit` | 500 | Max files to scan |

## API costs

GPT-4o is called once per scan (not per finding). Typical cost: **$0.01–0.05 per scan** depending on number of findings. Use `--no-ai` to run completely free.

## Output

Generates `security-report.html` — a self-contained file you can open in any browser. No internet required to view it.

## File structure

```
vibe_audit/
├── cli.py              # Entry point, orchestrates scan
├── models.py           # Finding dataclass
├── ai_analyzer.py      # GPT-4o integration
├── scanner/
│   ├── secrets.py      # Hardcoded secrets detection
│   ├── dotenv_check.py # .env file leak checks
│   ├── frontend.py     # API keys in frontend code
│   ├── injection.py    # SQL injection, XSS patterns
│   ├── logging_check.py# Sensitive data in logs
│   ├── headers.py      # Security headers config
│   ├── ratelimit.py    # Rate limiting presence
│   ├── deps.py         # Vulnerable dependencies
│   └── auth.py         # Auth weakness patterns
├── report/
│   └── dashboard.py    # HTML report generator
└── hooks/
    └── installer.py    # Git pre-commit hook installer
```
