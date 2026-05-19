import re
import uuid
from pathlib import Path
from ._utils import iter_files, read_file, rel
from ..models import Finding

PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", "CRITICAL"),
    (r'(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret Key", "CRITICAL"),
    (r'sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}', "OpenAI API Key (v1)", "CRITICAL"),
    (r'sk-proj-[a-zA-Z0-9_\-]{50,}', "OpenAI API Key (v2)", "CRITICAL"),
    (r'sk_live_[a-zA-Z0-9]{24,}', "Stripe Live Secret Key", "CRITICAL"),
    (r'rk_live_[a-zA-Z0-9]{24,}', "Stripe Live Restricted Key", "CRITICAL"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token", "CRITICAL"),
    (r'ghs_[a-zA-Z0-9]{36}', "GitHub App Token", "CRITICAL"),
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key", "CRITICAL"),
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{6,}["\']', "Hardcoded Password", "HIGH"),
    (r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{16,}["\']', "Hardcoded API Key", "HIGH"),
    (r'(?i)secret_key\s*[=:]\s*["\'][^"\']{8,}["\']', "Hardcoded Secret Key", "HIGH"),
    (r'(?i)access_token\s*[=:]\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']', "Hardcoded Access Token", "HIGH"),
    (r'(?i)auth_token\s*[=:]\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']', "Hardcoded Auth Token", "HIGH"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", "HIGH"),
    (r'(?i)twilio.*[=:]\s*["\']SK[a-zA-Z0-9]{32}["\']', "Twilio API Key", "HIGH"),
    (r'xox[baprs]-[0-9A-Za-z\-]{10,}', "Slack Token", "HIGH"),
    (r'sk_test_[a-zA-Z0-9]{24,}', "Stripe Test Key", "MEDIUM"),
]

ALLOWLIST_PATTERNS = [
    r'\.env\.example',
    r'example\.',
    r'your[-_]?api[-_]?key',
    r'<your',
    r'\$\{',
    r'os\.environ',
    r'process\.env',
    r'getenv',
    r'config\[',
]


def _is_allowlisted(line: str) -> bool:
    return any(re.search(p, line, re.IGNORECASE) for p in ALLOWLIST_PATTERNS)


def scan_secrets(root: str, limit: int = 500) -> list[Finding]:
    findings = []
    skip_files = {".env.example", ".env.sample"}

    for fpath in iter_files(root, limit):
        if fpath.name in skip_files or "test" in fpath.name.lower():
            continue
        content = read_file(fpath)
        if not content:
            continue
        for i, line in enumerate(content.splitlines(), 1):
            if _is_allowlisted(line):
                continue
            for pattern, label, severity in PATTERNS:
                if re.search(pattern, line):
                    findings.append(Finding(
                        id=str(uuid.uuid4())[:8],
                        category="Secrets",
                        severity=severity,
                        title=f"{label} detected",
                        description=f"A {label} appears to be hardcoded in source code.",
                        file=rel(fpath, root),
                        line=i,
                        code_snippet=line.strip()[:200],
                    ))
                    break
    return findings
