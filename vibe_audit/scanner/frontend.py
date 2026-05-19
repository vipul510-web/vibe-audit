import re
import uuid
from pathlib import Path
from ._utils import iter_files, read_file, rel
from ..models import Finding

FRONTEND_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".html", ".htm", ".vue", ".svelte"}

# Patterns that suggest a secret is directly embedded in frontend code
FRONTEND_SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Key in frontend", "CRITICAL"),
    (r'sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}', "OpenAI Key in frontend", "CRITICAL"),
    (r'sk-proj-[a-zA-Z0-9_\-]{50,}', "OpenAI Key in frontend", "CRITICAL"),
    (r'sk_live_[a-zA-Z0-9]{24,}', "Stripe Live Key in frontend", "CRITICAL"),
    (r'(?i)(api_key|apikey)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{20,}["\']', "Hardcoded API key in frontend", "HIGH"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key in frontend", "HIGH"),
    (r'xox[baprs]-[0-9A-Za-z\-]{10,}', "Slack Token in frontend", "HIGH"),
]

# NEXT_PUBLIC_ / VITE_ / REACT_APP_ env vars that look like secrets
EXPOSED_ENV_PATTERN = re.compile(
    r'(?i)(NEXT_PUBLIC_|VITE_|REACT_APP_)(SECRET|KEY|TOKEN|PASSWORD|PASS|PWD)',
)


def scan_frontend(root: str, limit: int = 500) -> list[Finding]:
    findings = []

    for fpath in iter_files(root, limit):
        if fpath.suffix.lower() not in FRONTEND_EXTENSIONS:
            continue
        content = read_file(fpath)
        if not content:
            continue

        for i, line in enumerate(content.splitlines(), 1):
            # Skip lines that reference env vars (not hardcoded)
            if "process.env" in line or "import.meta.env" in line:
                # But flag if the env var name suggests it's a secret being exposed
                if EXPOSED_ENV_PATTERN.search(line):
                    findings.append(Finding(
                        id=str(uuid.uuid4())[:8],
                        category="Frontend Exposure",
                        severity="HIGH",
                        title="Secret-named env var exposed to frontend",
                        description=f"An environment variable with a secret-sounding name is exposed to frontend code in {fpath.name}. Never put secrets in NEXT_PUBLIC_, VITE_, or REACT_APP_ variables.",
                        file=rel(fpath, root),
                        line=i,
                        code_snippet=line.strip()[:200],
                    ))
                continue

            for pattern, label, severity in FRONTEND_SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append(Finding(
                        id=str(uuid.uuid4())[:8],
                        category="Frontend Exposure",
                        severity=severity,
                        title=label,
                        description=f"{label} found in a frontend file. This will be visible to anyone who opens your app.",
                        file=rel(fpath, root),
                        line=i,
                        code_snippet=line.strip()[:200],
                    ))
                    break

    return findings
