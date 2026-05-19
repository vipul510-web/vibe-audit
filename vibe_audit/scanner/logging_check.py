import re
import uuid
from ._utils import iter_files, read_file, rel
from ..models import Finding

SENSITIVE_WORDS = r'(password|passwd|pwd|token|secret|api_key|apikey|auth|credential|private_key|access_key)'

LOG_CALLS = r'(print|console\.log|console\.debug|console\.info|logger\.(info|debug|warning|error|critical)|log\.info|log\.debug|logging\.(info|debug|warning|error))'

PATTERNS = [
    (
        rf'(?i){LOG_CALLS}\s*\(.*{SENSITIVE_WORDS}',
        "Sensitive data in log statement",
        "HIGH",
    ),
    (
        r'(?i)(print|console\.log)\s*\(.*\b(request|response|req|res)\b',
        "Full request/response logged",
        "MEDIUM",
    ),
    (
        r'(?i)(print|console\.log)\s*\(.*\bheaders\b',
        "HTTP headers logged (may include auth tokens)",
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
