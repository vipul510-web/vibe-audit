import os
import uuid
import subprocess
from pathlib import Path
from ..models import Finding


def scan_dotenv(root: str, **_) -> list[Finding]:
    findings = []
    root_path = Path(root)
    env_file = root_path / ".env"
    gitignore = root_path / ".gitignore"

    if not env_file.exists():
        return findings

    # Check if .env is in .gitignore
    gitignore_content = gitignore.read_text(errors="ignore") if gitignore.exists() else ""
    if ".env" not in gitignore_content:
        findings.append(Finding(
            id=str(uuid.uuid4())[:8],
            category=".env Leaks",
            severity="CRITICAL",
            title=".env file not in .gitignore",
            description=".env exists but is not listed in .gitignore — it could be committed and pushed to GitHub.",
            file=".env",
            line=0,
            code_snippet="",
        ))

    # Check if .env is tracked by git
    try:
        result = subprocess.run(
            ["git", "ls-files", ".env"],
            cwd=root, capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            findings.append(Finding(
                id=str(uuid.uuid4())[:8],
                category=".env Leaks",
                severity="CRITICAL",
                title=".env is tracked by git",
                description=".env is currently tracked by git. Anyone who clones this repo will get your secrets.",
                file=".env",
                line=0,
                code_snippet="",
            ))
    except Exception:
        pass

    # Check if .env.example exists
    if not (root_path / ".env.example").exists() and not (root_path / ".env.sample").exists():
        findings.append(Finding(
            id=str(uuid.uuid4())[:8],
            category=".env Leaks",
            severity="LOW",
            title=".env.example missing",
            description="No .env.example file found. Other developers won't know what environment variables are needed.",
            file=".",
            line=0,
            code_snippet="",
        ))

    return findings
