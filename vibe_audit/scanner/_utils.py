import os
from pathlib import Path

SKIP_DIRS = {".venv", "venv", "node_modules", ".git", "__pycache__", "dist", "build", ".next", ".nuxt"}
SKIP_FILES = {"security-report.html"}
TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".htm", ".vue", ".svelte",
    ".env", ".env.example", ".env.local", ".env.production", ".env.development",
    ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".conf", ".config",
    ".sh", ".bash", ".zsh", ".rb", ".php", ".go", ".rs", ".java", ".cs",
    ".tf", ".tfvars", ".hcl", ".dockerfile", "", ".txt",
}
MAX_FILE_SIZE = 512 * 1024  # 512 KB


def iter_files(root: str, limit: int = 500):
    root_path = Path(root)
    count = 0
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if count >= limit:
                return
            fpath = Path(dirpath) / fname
            if fpath.name in SKIP_FILES:
                continue
            ext = fpath.suffix.lower()
            if ext not in TEXT_EXTENSIONS and fpath.name not in {
                "Dockerfile", ".env", ".gitignore", "Makefile", "Procfile"
            }:
                continue
            if fpath.stat().st_size > MAX_FILE_SIZE:
                continue
            yield fpath
            count += 1


def read_file(path: Path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def rel(path: Path, root: str) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
