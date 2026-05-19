import uuid
import json
import subprocess
from pathlib import Path
from ..models import Finding


def scan_deps(root: str, **_) -> list[Finding]:
    findings = []
    root_path = Path(root)

    if (root_path / "requirements.txt").exists() or (root_path / "Pipfile").exists() or (root_path / "pyproject.toml").exists():
        findings.extend(_pip_audit(root))

    if (root_path / "package.json").exists():
        findings.extend(_npm_audit(root))

    return findings


def _pip_audit(root: str) -> list[Finding]:
    findings = []
    try:
        result = subprocess.run(
            ["pip-audit", "--format", "json", "--progress-spinner", "off"],
            cwd=root, capture_output=True, text=True, timeout=60
        )
        data = json.loads(result.stdout or "[]")
        for dep in data:
            for vuln in dep.get("vulns", []):
                severity = _cvss_to_severity(vuln.get("fix_versions", []))
                findings.append(Finding(
                    id=str(uuid.uuid4())[:8],
                    category="Dependencies",
                    severity=severity,
                    title=f"Vulnerable dependency: {dep['name']} {dep.get('version', '')}",
                    description=f"{vuln.get('id', 'CVE unknown')}: {vuln.get('description', 'No description')}",
                    file="requirements.txt",
                    line=0,
                    code_snippet=f"{dep['name']}=={dep.get('version', '?')}",
                ))
    except FileNotFoundError:
        findings.append(Finding(
            id=str(uuid.uuid4())[:8],
            category="Dependencies",
            severity="INFO",
            title="pip-audit not installed",
            description="Install pip-audit to scan Python dependencies for known CVEs: pip install pip-audit",
            file=".",
            line=0,
            code_snippet="",
        ))
    except Exception:
        pass
    return findings


def _npm_audit(root: str) -> list[Finding]:
    findings = []
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=root, capture_output=True, text=True, timeout=60
        )
        data = json.loads(result.stdout or "{}")
        vulns = data.get("vulnerabilities", {})
        for name, info in vulns.items():
            severity = info.get("severity", "LOW").upper()
            if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                severity = "MEDIUM"
            findings.append(Finding(
                id=str(uuid.uuid4())[:8],
                category="Dependencies",
                severity=severity,
                title=f"Vulnerable npm package: {name}",
                description=info.get("via", [{}])[0].get("title", "Known vulnerability") if info.get("via") else "Known vulnerability",
                file="package.json",
                line=0,
                code_snippet=f"{name}@{info.get('range', '?')}",
            ))
    except Exception:
        pass
    return findings


def _cvss_to_severity(fix_versions: list) -> str:
    return "HIGH" if fix_versions else "MEDIUM"
