import uuid
import subprocess
from pathlib import Path
from ._utils import SKIP_DIRS
from ..models import Finding


def scan_dotenv(root: str, **_) -> list[Finding]:
    findings = []
    root_path = Path(root)

    # Collect all .env files across the project (not just root)
    env_files = _find_env_files(root_path)
    if not env_files:
        return findings

    gitignore_content = _read_gitignore(root_path)
    env_gitignored = ".env" in gitignore_content

    # Check git tracking once for all .env files
    tracked = _git_tracked_envs(root)

    for env_file in env_files:
        rel = str(env_file.relative_to(root_path))

        # Flag if not covered by .gitignore
        if not env_gitignored:
            findings.append(Finding(
                id=str(uuid.uuid4())[:8],
                category=".env Leaks",
                severity="CRITICAL",
                title=".env file not in .gitignore",
                description=f"{rel} exists but '.env' is not in .gitignore — it could be committed and pushed to GitHub, exposing all your secrets.",
                file=rel,
                line=0,
                code_snippet="",
            ))

        # Flag if actively tracked by git
        if rel in tracked or env_file.name in tracked:
            findings.append(Finding(
                id=str(uuid.uuid4())[:8],
                category=".env Leaks",
                severity="CRITICAL",
                title=f"{rel} is tracked by git",
                description=f"{rel} is committed to git — anyone who clones this repo gets all the secrets inside it.",
                file=rel,
                line=0,
                code_snippet="",
            ))

    # Check .env.example only at root
    root_env = root_path / ".env"
    if root_env.exists():
        if not (root_path / ".env.example").exists() and not (root_path / ".env.sample").exists():
            findings.append(Finding(
                id=str(uuid.uuid4())[:8],
                category=".env Leaks",
                severity="LOW",
                title=".env.example missing",
                description="No .env.example found. Other developers won't know what environment variables are needed.",
                file=".",
                line=0,
                code_snippet="",
            ))

    return findings


def _find_env_files(root: Path) -> list[Path]:
    env_files = []
    for dirpath, dirnames, filenames in root.__class__(root).walk() if hasattr(root.__class__, 'walk') else _walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname == ".env" or (fname.startswith(".env.") and fname not in {".env.example", ".env.sample", ".env.template"}):
                env_files.append(Path(dirpath) / fname)
    return env_files


def _walk(root: Path):
    import os
    for dirpath, dirnames, filenames in os.walk(root):
        yield Path(dirpath), dirnames, filenames


def _read_gitignore(root: Path) -> str:
    gitignore = root / ".gitignore"
    return gitignore.read_text(errors="ignore") if gitignore.exists() else ""


def _git_tracked_envs(root: str) -> set:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch"],
            cwd=root, capture_output=True, text=True, timeout=5
        )
        # Get all tracked files and filter for .env ones
        all_tracked = subprocess.run(
            ["git", "ls-files"],
            cwd=root, capture_output=True, text=True, timeout=5
        )
        return {f for f in all_tracked.stdout.splitlines() if ".env" in f and "example" not in f and "sample" not in f}
    except Exception:
        return set()
