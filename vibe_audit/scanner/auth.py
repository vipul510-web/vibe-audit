import re
import uuid
from ._utils import iter_files, read_file, rel
from ..models import Finding

PATTERNS = [
    (r'(?i)(md5|sha1)\s*\(.*password', "Weak password hashing (MD5/SHA1)", "CRITICAL"),
    (r'(?i)hashlib\.(md5|sha1)\s*\(', "Weak hashing algorithm", "HIGH"),
    (r'(?i)jwt\.encode\s*\(.*["\']secret["\']', "JWT signed with literal 'secret'", "CRITICAL"),
    (r'(?i)jwt\.encode\s*\(.*["\'][a-zA-Z0-9]{1,15}["\']', "JWT signed with short/weak secret", "HIGH"),
    (r'(?i)secret_key\s*=\s*["\']django-insecure', "Django insecure default secret key", "HIGH"),
    (r'(?i)SECRET_KEY\s*=\s*["\'][^"\']{1,20}["\']', "Short Django SECRET_KEY", "HIGH"),
    (r'(?i)(password|passwd)\s*==\s*["\'][^"\']+["\']', "Password compared in plain text", "CRITICAL"),
    (r'(?i)verify\s*=\s*False', "SSL verification disabled", "HIGH"),
    (r'DEBUG\s*=\s*True', "DEBUG mode enabled (exposes error details)", "HIGH"),
    (r'(?i)allow_all_origins\s*=\s*True', "CORS: allow all origins", "MEDIUM"),
    (r'(?i)cors.*origins.*\*', "CORS wildcard origin", "MEDIUM"),
]


def scan_auth(root: str, limit: int = 500) -> list[Finding]:
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
                        category="Auth Issues",
                        severity=severity,
                        title=label,
                        description=f"{label} detected.",
                        file=rel(fpath, root),
                        line=i,
                        code_snippet=stripped[:200],
                    ))
                    break
    return findings
