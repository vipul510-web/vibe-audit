import os
import stat
from pathlib import Path

HOOK_SCRIPT = """#!/bin/sh
echo "🔍 vibe-audit: running pre-commit security check..."
vibe-audit . --no-ai --pre-commit
exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo ""
    echo "❌ vibe-audit blocked this commit due to CRITICAL security issues."
    echo "   Run 'vibe-audit .' for the full report, then fix before committing."
    exit 1
fi
echo "✅ vibe-audit: no critical issues found."
"""


def install_hooks(project_path: str) -> tuple[bool, str]:
    git_dir = Path(project_path) / ".git"
    if not git_dir.exists():
        return False, f"No .git directory found in {project_path}. Run 'git init' first."

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)

    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists():
        existing = hook_path.read_text()
        if "vibe-audit" in existing:
            return True, f"vibe-audit hook already installed at {hook_path}"
        # Append to existing hook
        with open(hook_path, "a") as f:
            f.write("\n# vibe-audit\n")
            f.write(HOOK_SCRIPT.strip())
    else:
        hook_path.write_text(HOOK_SCRIPT)

    hook_path.chmod(hook_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return True, f"Pre-commit hook installed at {hook_path}"
