import re
import uuid
from pathlib import Path
from ._utils import read_file
from ..models import Finding

RATELIMIT_SIGNALS = [
    "flask_limiter", "slowapi", "express-rate-limit", "rate-limit",
    "ratelimit", "rate_limit", "throttle", "throttling",
    "django_ratelimit", "django-ratelimit",
]

ROUTE_PATTERNS = [
    re.compile(r'@app\.(get|post|put|patch|delete|route)\s*\('),  # Flask
    re.compile(r'router\.(get|post|put|patch|delete)\s*\('),       # Express
    re.compile(r'@(router|app)\.(get|post|put|patch|delete)\s*\('),  # FastAPI
    re.compile(r'path\s*\(.*views\.'),                              # Django urls
]


def scan_ratelimit(root: str, **_) -> list[Finding]:
    findings = []
    root_path = Path(root)

    all_content = ""
    route_count = 0

    for fpath in root_path.rglob("*.py"):
        if any(p in str(fpath) for p in [".venv", "venv", "__pycache__"]):
            continue
        content = read_file(fpath)
        all_content += content
        for pat in ROUTE_PATTERNS[:3]:
            route_count += len(pat.findall(content))

    for fpath in list(root_path.rglob("*.js")) + list(root_path.rglob("*.ts")):
        if "node_modules" in str(fpath) or ".next" in str(fpath):
            continue
        content = read_file(fpath)
        all_content += content
        route_count += len(ROUTE_PATTERNS[1].findall(content))

    if route_count == 0:
        return findings

    all_lower = all_content.lower()
    has_ratelimit = any(sig in all_lower for sig in RATELIMIT_SIGNALS)

    if not has_ratelimit:
        findings.append(Finding(
            id=str(uuid.uuid4())[:8],
            category="Rate Limiting",
            severity="HIGH",
            title="No rate limiting detected",
            description=f"Found {route_count} API route(s) but no rate limiting library was detected. Without rate limits, anyone can spam your API or burn your OpenAI/external API budget.",
            file=".",
            line=0,
            code_snippet="",
        ))
    return findings
