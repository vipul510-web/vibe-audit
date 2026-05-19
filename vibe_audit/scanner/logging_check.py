import re
import uuid
from ._utils import iter_files, read_file, rel
from ..models import Finding

SENSITIVE_WORDS = r'(password|passwd|pwd|token|secret|api_key|apikey|auth_token|private_key|access_key)'

LOG_CALLS = r'(print|console\.log|console\.debug|console\.info|logger\.(info|debug|warning|error|critical)|log\.info|log\.debug|logging\.(info|debug|warning|error))'

PATTERNS = [
    # f-string/template with sensitive variable interpolated: print(f"token: {token}")
    (
        rf'(?i){LOG_CALLS}\s*\(.*f["\'].*\{{[^}}]*{SENSITIVE_WORDS}[^}}]*\}}',
        "Sensitive value interpolated in log statement",
        "HIGH",
    ),
    # Direct variable logging: print(password), log.info(api_key)
    (
        rf'(?i){LOG_CALLS}\s*\(\s*{SENSITIVE_WORDS}\s*[\),]',
        "Sensitive variable passed directly to log",
        "HIGH",
    ),
    # JS template literal: console.log(`token: ${token}`)
    (
        rf'(?i)(console\.log|console\.debug)\s*\(`[^`]*\$\{{[^}}]*{SENSITIVE_WORDS}[^}}]*\}}',
        "Sensitive value in JS template log",
        "HIGH",
    ),
    # Dict/object access being logged: print(data['password']), console.log(user.token)
    (
        rf'(?i){LOG_CALLS}\s*\(.*["\'][^"\']*["\'].*\b{SENSITIVE_WORDS}\b',
        "Sensitive key accessed in log statement",
        "MEDIUM",
    ),
]


def scan_logging(root: str, limit: int = 500) -> list[Finding]:
    findings = []
    for fpath in iter_files(root, limit):
        content = read_file(fpath)
        if not content:
            continue
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for pattern, label, severity in PATTERNS:
                if re.search(pattern, line):
                    findings.append(Finding(
                        id=str(uuid.uuid4())[:8],
                        category="Sensitive Logging",
                        severity=severity,
                        title=label,
                        description=f"{label} — logs may expose sensitive data to log files, monitoring tools, or error trackers.",
                        file=rel(fpath, root),
                        line=i,
                        code_snippet=stripped[:200],
                    ))
                    break
    return findings
