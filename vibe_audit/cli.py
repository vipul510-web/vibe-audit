import os
import sys
import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from .scanner import (
    scan_secrets, scan_dotenv, scan_frontend, scan_injection,
    scan_logging, scan_headers, scan_ratelimit, scan_deps, scan_auth,
)
from .ai_analyzer import enrich_with_ai
from .report.dashboard import generate_html
from .hooks.installer import install_hooks
from .models import compute_score, score_grade, SEVERITY_ORDER

console = Console()

SCANNERS = [
    ("Secrets", scan_secrets),
    (".env Leaks", scan_dotenv),
    ("Frontend Exposure", scan_frontend),
    ("Injection (SQL/XSS/CMD)", scan_injection),
    ("Sensitive Logging", scan_logging),
    ("Security Headers", scan_headers),
    ("Rate Limiting", scan_ratelimit),
    ("Dependencies", scan_deps),
    ("Auth Issues", scan_auth),
]


@click.command()
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option("--output", "-o", default="security-report.html", help="Output HTML report path")
@click.option("--no-ai", is_flag=True, default=False, help="Skip GPT-4o analysis")
@click.option("--install-hooks", "install_hooks_flag", is_flag=True, default=False, help="Install pre-commit hook")
@click.option("--pre-commit", is_flag=True, default=False, help="Pre-commit mode: exit 1 on CRITICAL findings")
@click.option("--limit", default=500, help="Max files to scan (default: 500)")
def main(path, output, no_ai, install_hooks_flag, pre_commit, limit):
    """vibe-audit: Security scanner for vibe-coded apps."""

    abs_path = str(Path(path).resolve())

    if install_hooks_flag:
        ok, msg = install_hooks(abs_path)
        if ok:
            console.print(f"[green]✓[/green] {msg}")
        else:
            console.print(f"[red]✗[/red] {msg}")
        return

    if not pre_commit:
        console.print(f"\n[bold]vibe-audit[/bold] scanning [cyan]{abs_path}[/cyan]\n")

    all_findings = []

    if pre_commit:
        # Fast scanners only for pre-commit
        fast_scanners = [("Secrets", scan_secrets), (".env Leaks", scan_dotenv),
                         ("Frontend Exposure", scan_frontend), ("Auth Issues", scan_auth)]
        for name, scanner in fast_scanners:
            try:
                all_findings.extend(scanner(abs_path, limit=limit))
            except Exception:
                pass
    else:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            for name, scanner in SCANNERS:
                task = progress.add_task(f"Scanning {name}...", total=None)
                try:
                    findings = scanner(abs_path, limit=limit)
                    all_findings.extend(findings)
                    count = len(findings)
                    status = f"[red]{count} issues[/red]" if count else "[green]clean[/green]"
                    progress.update(task, description=f"{name}: {status}", completed=True)
                except Exception as e:
                    progress.update(task, description=f"{name}: [yellow]skipped[/yellow]", completed=True)

    if not no_ai and not pre_commit and all_findings:
        if os.environ.get("OPENAI_API_KEY"):
            with Progress(SpinnerColumn(), TextColumn("Analyzing with GPT-4o..."), console=console) as progress:
                task = progress.add_task("", total=None)
                all_findings = enrich_with_ai(all_findings)
                progress.update(task, completed=True)
        else:
            console.print("[yellow]⚠[/yellow]  OPENAI_API_KEY not set — skipping AI analysis. Set it for fix prompts.\n")

    if pre_commit:
        critical = [f for f in all_findings if f.severity == "CRITICAL"]
        if critical:
            for f in critical:
                print(f"  CRITICAL: {f.title} ({f.file}:{f.line})")
            sys.exit(1)
        sys.exit(0)

    # Print console summary
    score = compute_score(all_findings)
    grade = score_grade(score)
    score_color = "green" if score >= 75 else "yellow" if score >= 50 else "red"

    console.print(f"\n[bold]Score:[/bold] [{score_color}]{score}/100 (Grade {grade})[/{score_color}]")
    console.print(f"[bold]Issues:[/bold] {len(all_findings)} total\n")

    if all_findings:
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold", expand=False)
        table.add_column("Severity", min_width=10, no_wrap=True)
        table.add_column("Category", min_width=18)
        table.add_column("Title", min_width=35)
        table.add_column("File", min_width=20)

        sorted_findings = sorted(all_findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        sev_colors = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "green", "INFO": "dim"}

        for f in sorted_findings:
            col = sev_colors.get(f.severity, "white")
            file_str = f"{f.file}:{f.line}" if f.line else f.file
            table.add_row(
                f"[{col}]{f.severity}[/{col}]",
                f.category,
                f.title[:40],
                file_str[:25],
            )
        console.print(table)

    # Write HTML report
    html_content = generate_html(all_findings, abs_path)
    output_path = Path(output)
    output_path.write_text(html_content, encoding="utf-8")

    console.print(f"\n[bold green]✓[/bold green] Report saved to [cyan]{output_path.resolve()}[/cyan]")
    console.print("[dim]Open it in your browser for the full dashboard with fix prompts.[/dim]\n")
