import re
import uuid
from pathlib import Path
from ._utils import read_file
from ..models import Finding


def scan_headers(root: str, **_) -> list[Finding]:
    findings = []
    root_path = Path(root)

    framework = _detect_framework(root_path)
    if framework == "unknown":
        return findings

    if framework == "flask":
        findings.extend(_check_flask(root_path))
    elif framework == "express":
        findings.extend(_check_express(root_path))
    elif framework == "nextjs":
        findings.extend(_check_nextjs(root_path))
    elif framework == "fastapi":
        findings.extend(_check_fastapi(root_path))
    elif framework == "django":
        findings.extend(_check_django(root_path))

    return findings


def _detect_framework(root: Path) -> str:
    req = root / "requirements.txt"
    pkg = root / "package.json"

    if req.exists():
        content = read_file(req).lower()
        if "flask" in content:
            return "flask"
        if "fastapi" in content:
            return "fastapi"
        if "django" in content:
            return "django"

    if pkg.exists():
        content = read_file(pkg).lower()
        if "next" in content:
            return "nextjs"
        if "express" in content:
            return "express"

    return "unknown"


def _check_flask(root: Path) -> list[Finding]:
    findings = []
    has_talisman = False
    has_cors = False

    for pyfile in root.rglob("*.py"):
        if any(p in str(pyfile) for p in [".venv", "venv", "__pycache__"]):
            continue
        content = read_file(pyfile)
        if "talisman" in content.lower():
            has_talisman = True
        if "flask_cors" in content.lower() or "CORS(" in content:
            has_cors = True

    if not has_talisman:
        findings.append(Finding(
            id=str(uuid.uuid4())[:8],
            category="Security Headers",
            severity="MEDIUM",
            title="Flask: No security headers middleware (flask-talisman)",
            description="flask-talisman sets HSTS, CSP, X-Frame-Options, and other security headers automatically. Your Flask app is missing it.",
            file="requirements.txt",
            line=0,
            code_snippet="",
        ))
    return findings


def _check_express(root: Path) -> list[Finding]:
    findings = []
    has_helmet = False

    for jsfile in list(root.rglob("*.js")) + list(root.rglob("*.ts")):
        if any(p in str(jsfile) for p in ["node_modules", ".next"]):
            continue
        content = read_file(jsfile)
        if "helmet" in content.lower():
            has_helmet = True
            break

    if not has_helmet:
        findings.append(Finding(
            id=str(uuid.uuid4())[:8],
            category="Security Headers",
            severity="MEDIUM",
            title="Express: Missing helmet.js",
            description="helmet.js sets important security headers (HSTS, CSP, X-Frame-Options) in Express apps. It was not detected in your project.",
            file="package.json",
            line=0,
            code_snippet="",
        ))
    return findings


def _check_nextjs(root: Path) -> list[Finding]:
    findings = []
    config = root / "next.config.js"
    config_ts = root / "next.config.ts"
    config_mjs = root / "next.config.mjs"

    found = next((f for f in [config, config_ts, config_mjs] if f.exists()), None)
    if not found:
        return findings

    content = read_file(found)
    if "headers" not in content.lower() or "Content-Security-Policy" not in content:
        findings.append(Finding(
            id=str(uuid.uuid4())[:8],
            category="Security Headers",
            severity="MEDIUM",
            title="Next.js: Security headers not configured",
            description="next.config.js does not appear to define security headers (CSP, HSTS, etc). Add a `headers()` function to your Next.js config.",
            file=found.name,
            line=0,
            code_snippet="",
        ))
    return findings


def _check_fastapi(root: Path) -> list[Finding]:
    findings = []
    has_middleware = False

    for pyfile in root.rglob("*.py"):
        if any(p in str(pyfile) for p in [".venv", "venv", "__pycache__"]):
            continue
        content = read_file(pyfile)
        if "securityheadersmiddleware" in content.lower() or "x-frame-options" in content.lower() or "trustedhost" in content.lower():
            has_middleware = True
            break

    if not has_middleware:
        findings.append(Finding(
            id=str(uuid.uuid4())[:8],
            category="Security Headers",
            severity="MEDIUM",
            title="FastAPI: No security headers middleware detected",
            description="No security headers middleware was found. Add TrustedHostMiddleware or a custom middleware that sets X-Frame-Options, CSP, and HSTS headers.",
            file="main.py",
            line=0,
            code_snippet="",
        ))
    return findings


def _check_django(root: Path) -> list[Finding]:
    findings = []
    settings_files = list(root.rglob("settings*.py"))
    if not settings_files:
        return findings

    content = "".join(read_file(f) for f in settings_files)
    checks = [
        ("SECURE_HSTS_SECONDS", "Django: SECURE_HSTS_SECONDS not set", "MEDIUM"),
        ("SECURE_CONTENT_TYPE_NOSNIFF", "Django: SECURE_CONTENT_TYPE_NOSNIFF not set", "LOW"),
        ("X_FRAME_OPTIONS", "Django: X_FRAME_OPTIONS not set", "MEDIUM"),
        ("SECURE_SSL_REDIRECT", "Django: SECURE_SSL_REDIRECT not set", "MEDIUM"),
        ("SESSION_COOKIE_SECURE", "Django: SESSION_COOKIE_SECURE not set", "HIGH"),
        ("CSRF_COOKIE_SECURE", "Django: CSRF_COOKIE_SECURE not set", "HIGH"),
    ]
    for setting, title, severity in checks:
        if setting not in content:
            findings.append(Finding(
                id=str(uuid.uuid4())[:8],
                category="Security Headers",
                severity=severity,
                title=title,
                description=f"{setting} is not configured in your Django settings. This is a recommended security setting.",
                file="settings.py",
                line=0,
                code_snippet="",
            ))
    return findings
