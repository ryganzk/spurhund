from dataclasses import replace
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table

from spurhund.config import (
    load_config,
    init_config,
    update_ignore_path
)
from spurhund.core.engine import ScannerEngine
from spurhund.core.filter import is_binary_file, should_ignore_path
from spurhund.core.diff import get_staged_diff, parse_patch_lines
from spurhund.models import Finding

app = typer.Typer(help="Spurhund secret and policy scanner")
ignore_app = typer.Typer(help="Manage repository-wide exclusion paths")
app.add_typer(ignore_app, name="ignore")

console = Console()

def _render_findings(findings: list[Finding]):
    if not findings:
        console.print("[green]✓ Clean. No secrets or policy violations detected.[/green]")
        raise typer.Exit(code=0)

    table = Table(title="Security Findings Detected", show_header=True)
    table.add_column("Severity", style="bold red")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Location", style="yellow")
    table.add_column("Entropy", justify="right")
    table.add_column("Masked Token")

    for f in findings:
        table.add_row(f.severity, f.rule_id, f"{f.file_path}:{f.line_number}", str(f.entropy), f.masked_secret)

    console.print(table)
    raise typer.Exit(code=1)

@app.command()
def init(
    repo_path: str = typer.Option(".", help="Root directory of the repository"),
    config_file: str = typer.Option(".spurhund-rules.yml", help="Filename for Spurhund rules")
):
    """Scaffold .spurhund-rules.yml and auto-ingest .gitignore entries."""
    root = Path(repo_path).resolve()
    cfg_path = root / config_file

    created, gitignore_added = init_config(root, cfg_path)

    if created:
        console.print(f"[green]✓ Initialized default configuration at {cfg_path.name}[/green]")
    else:
        console.print(f"[yellow]Configuration already exists at {cfg_path.name}. Updating ignore list...[/yellow]")

    if gitignore_added > 0:
        console.print(f"[cyan]→ Imported {gitignore_added} entries from .gitignore[/cyan]")
    else:
        console.print("[dim]No new .gitignore entries to import.[/dim]")

@ignore_app.command("add")
def ignore_add(
    pattern: str = typer.Argument(..., help="Path or glob pattern to ignore (e.g. 'dist/**')"),
    config: str = typer.Option(".spurhund-rules.yml", help="Path to rules YAML")
):
    """Idempotently add a path pattern to the exclusion list."""
    cfg_path = Path(config)
    if not cfg_path.exists():
        console.print(f"[red]Config file {config} not found. Run 'spurhund init' first.[/red]")
        raise typer.Exit(code=1)

    changed = update_ignore_path(cfg_path, pattern, action="add")
    if changed:
        console.print(f"[green]✓ Added '{pattern}' to {config}[/green]")
    else:
        console.print(f"[dim]'{pattern}' is already present in {config} (no change).[/dim]")

@ignore_app.command("remove")
def ignore_remove(
    pattern: str = typer.Argument(..., help="Path or glob pattern to remove"),
    config: str = typer.Option(".spurhund-rules.yml", help="Path to rules YAML")
):
    """Idempotently remove a path pattern from the exclusion list."""
    cfg_path = Path(config)
    if not cfg_path.exists():
        console.print(f"[red]Config file {config} not found.[/red]")
        raise typer.Exit(code=1)

    changed = update_ignore_path(cfg_path, pattern, action="remove")
    if changed:
        console.print(f"[green]✓ Removed '{pattern}' from {config}[/green]")
    else:
        console.print(f"[dim]'{pattern}' was not found in {config} (no change).[/dim]")

@ignore_app.command("list")
def ignore_list(config: str = typer.Option(".spurhund-rules.yml", help="Path to rules YAML")):
    """List all currently active ignore patterns."""
    cfg_path = Path(config)
    if not cfg_path.exists():
        console.print(f"[red]Config file {config} not found.[/red]")
        raise typer.Exit(code=1)

    global_ignores, _ = load_config(cfg_path)
    console.print(f"[bold cyan]Active ignore patterns in {config}:[/bold cyan]")
    for pat in global_ignores:
        console.print(f"  • {pat}")

@app.command()
def scan_file(
    file_path: str = typer.Argument(..., help="Path to file to analyze"),
    config: str = typer.Option(".spurhund-rules.yml", help="Path to rules YAML")
):
    """Scan a single raw file for secret and credential leaks."""
    try:
        _, rules = load_config(Path(config))
        content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1)

    engine = ScannerEngine(rules)
    findings = engine.scan_text(content, file_path=file_path)
    _render_findings(findings)

@app.command()
def scan_repo(
    repo_path: str = typer.Argument(".", help="Path to repository root"),
    config: str = typer.Option(".spurhund-rules.yml", help="Path to rules YAML")
):
    """Scan an entire repository filesystem while respecting ignore rules and binary gates."""
    root = Path(repo_path).resolve()
    cfg_path = Path(config)

    # Auto-initialize if config is absent
    if not cfg_path.exists():
        console.print(f"[yellow]No {config} found. Initializing defaults...[/yellow]")
        init_config(root, cfg_path)

    global_ignores, rules = load_config(cfg_path)
    engine = ScannerEngine(rules)
    all_findings: list[Finding] = []
    scanned_count = 0

    with console.status("[bold blue]Scanning repository files..."):
        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue

            rel_path = file_path.relative_to(root).as_posix()

            if should_ignore_path(rel_path, global_ignores):
                continue

            if is_binary_file(file_path):
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                findings = engine.scan_text(content, file_path=rel_path)
                all_findings.extend(findings)
                scanned_count += 1
            except Exception:
                continue

    console.print(f"[dim]Scanned {scanned_count} files.[/dim]")
    _render_findings(all_findings)

@app.command()
def scan_staged(
    repo_path: str = typer.Argument(".", help="Path to repository root"),
    config: str = typer.Option(".spurhund-rules.yml", help="Path to rules YAML")
):
    """Scan staged git changes for secret and credential leaks."""
    root = Path(repo_path).resolve()
    cfg_path = Path(config)

    if not cfg_path.exists():
        console.print(f"[yellow]No {config} found. Initializing defaults...[/yellow]")
        init_config(root, cfg_path)

    try:
        global_ignores, rules = load_config(cfg_path)
        patch = get_staged_diff(root)
    except Exception as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1)

    engine = ScannerEngine(rules)
    all_findings: list[Finding] = []
    scanned_count = 0

    for file_path, line_number, text in parse_patch_lines(patch):
        if should_ignore_path(file_path, global_ignores):
            continue

        scanned_count += 1
        for finding in engine.scan_text(text, file_path=file_path):
            all_findings.append(replace(finding, line_number=line_number))

    console.print(f"[dim]Scanned {scanned_count} staged lines.[/dim]")
    _render_findings(all_findings)

if __name__ == "__main__":
    app()