from dataclasses import replace
import os
from pathlib import Path
from typing import NoReturn
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
from spurhund.core.diff import get_branch_diff, get_staged_diff, parse_patch_lines
from spurhund.models import Finding
from spurhund.sarif import write_sarif

app = typer.Typer(help="Spurhund secret and policy scanner")
ignore_app = typer.Typer(help="Manage repository-wide exclusion paths")
app.add_typer(ignore_app, name="ignore")

console = Console()
err_console = Console(stderr=True)

_GITHUB_ANNOTATIONS_HELP = (
    "Emit GitHub Actions ::error annotations for each finding. "
    "Also enabled when GITHUB_ACTIONS=true."
)

def _fail(message: str) -> NoReturn:
    """Print a diagnostic to stderr and stop the process with exit code 2."""
    err_console.print(f"error: {message}", style="red", highlight=False, markup=False)
    raise typer.Exit(code=2)

def _annotations_enabled(explicit: bool) -> bool:
    return explicit or os.environ.get("GITHUB_ACTIONS") == "true"

def _workflow_property(value: object) -> str:
    text = str(value)
    return (
        text.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )

def _workflow_message(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

def _emit_github_annotations(findings: list[Finding]) -> None:
    for finding in findings:
        message = f"{finding.severity} {finding.rule_name}: {finding.masked_secret}"
        print(
            "::error "
            f"file={_workflow_property(finding.file_path)},"
            f"line={_workflow_property(finding.line_number)},"
            f"title={_workflow_property(finding.rule_id)}::"
            f"{_workflow_message(message)}",
            flush=True,
        )

def _load_rules(config: str, *, root: Path | None = None, auto_init: bool = False):
    """Load ignore paths and rules. Missing or invalid config exits 2."""
    cfg_path = Path(config)
    if auto_init and not cfg_path.exists():
        console.print(f"[yellow]No {config} found. Initializing defaults...[/yellow]")
        try:
            init_config(root or Path(".").resolve(), cfg_path)
        except Exception as exc:
            _fail(f"Failed to create config {cfg_path}: {exc}")

    try:
        return load_config(cfg_path)
    except FileNotFoundError:
        _fail(f"Config file not found: {cfg_path}")
    except PermissionError:
        _fail(f"Permission denied reading config {cfg_path}")
    except OSError as exc:
        _fail(f"Unable to read config {cfg_path}: {exc}")
    except Exception as exc:
        _fail(f"Invalid config {cfg_path}: {exc}")

def _findings_from_patch(patch: str, global_ignores: list[str], rules: list) -> tuple[list[Finding], int]:
    """Scan added diff lines, skipping ignored paths and keeping real file line numbers."""
    try:
        engine = ScannerEngine(rules)
    except Exception as exc:
        _fail(f"Failed to compile scan rules: {exc}")

    findings: list[Finding] = []
    scanned_count = 0

    for file_path, line_number, text in parse_patch_lines(patch):
        if should_ignore_path(file_path, global_ignores):
            continue

        scanned_count += 1
        try:
            line_findings = engine.scan_text(text, file_path=file_path)
        except Exception as exc:
            _fail(f"Scan failed for {file_path}:{line_number}: {exc}")
        for finding in line_findings:
            findings.append(replace(finding, line_number=line_number))

    return findings, scanned_count

def _render_findings(findings: list[Finding], github_annotations: bool = False, sarif: str = "") -> None:
    """Print the scan result and exit 0 when clean, or 1 when findings exist."""
    if sarif.strip():
        try:
            write_sarif(sarif, findings)
        except OSError as exc:
            _fail(f"Unable to write SARIF report {sarif}: {exc}")

    if not findings:
        console.print("[green]✓ Clean. No secrets or policy violations detected.[/green]")
        raise typer.Exit(code=0)

    if _annotations_enabled(github_annotations):
        _emit_github_annotations(findings)

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

    try:
        created, gitignore_added = init_config(root, cfg_path)
    except Exception as exc:
        _fail(f"Failed to initialize config at {cfg_path}: {exc}")

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
        _fail(f"Config file {config} not found. Run 'spurhund init' first.")

    try:
        changed = update_ignore_path(cfg_path, pattern, action="add")
    except Exception as exc:
        _fail(f"Failed to update {config}: {exc}")
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
        _fail(f"Config file {config} not found.")

    try:
        changed = update_ignore_path(cfg_path, pattern, action="remove")
    except Exception as exc:
        _fail(f"Failed to update {config}: {exc}")
    if changed:
        console.print(f"[green]✓ Removed '{pattern}' from {config}[/green]")
    else:
        console.print(f"[dim]'{pattern}' was not found in {config} (no change).[/dim]")

@ignore_app.command("list")
def ignore_list(config: str = typer.Option(".spurhund-rules.yml", help="Path to rules YAML")):
    """List all currently active ignore patterns."""
    cfg_path = Path(config)
    if not cfg_path.exists():
        _fail(f"Config file {config} not found.")

    try:
        global_ignores, _ = load_config(cfg_path)
    except Exception as exc:
        _fail(f"Invalid config {cfg_path}: {exc}")
    console.print(f"[bold cyan]Active ignore patterns in {config}:[/bold cyan]")
    for pat in global_ignores:
        console.print(f"  • {pat}")

@app.command()
def scan_file(
    file_path: str = typer.Argument(..., help="Path to file to analyze"),
    config: str = typer.Option(".spurhund-rules.yml", help="Path to rules YAML"),
    github_annotations: bool = typer.Option(False, "--github-annotations", help=_GITHUB_ANNOTATIONS_HELP),
):
    """Scan a single raw file for secret and credential leaks."""
    target = Path(file_path)
    _, rules = _load_rules(config, auto_init=False)
    try:
        content = target.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        _fail(f"File not found: {target}")
    except PermissionError:
        _fail(f"Permission denied reading {target}")
    except OSError as exc:
        _fail(f"Unable to read {target}: {exc}")

    try:
        findings = ScannerEngine(rules).scan_text(content, file_path=file_path)
    except Exception as exc:
        _fail(f"Scan failed for {target}: {exc}")

    _render_findings(findings, github_annotations)

@app.command()
def scan_repo(
    repo_path: str = typer.Argument(".", help="Path to repository root"),
    config: str = typer.Option(".spurhund-rules.yml", help="Path to rules YAML"),
    github_annotations: bool = typer.Option(False, "--github-annotations", help=_GITHUB_ANNOTATIONS_HELP),
    sarif: str = typer.Option("", "--sarif", help="Write a SARIF 2.1.0 report to this path."),
):
    """Scan an entire repository filesystem while respecting ignore rules and binary gates."""
    root = Path(repo_path).resolve()
    if not root.exists():
        _fail(f"Repository path not found: {root}")
    if not root.is_dir():
        _fail(f"Repository path is not a directory: {root}")

    global_ignores, rules = _load_rules(config, root=root, auto_init=True)
    try:
        engine = ScannerEngine(rules)
    except Exception as exc:
        _fail(f"Failed to compile scan rules: {exc}")

    all_findings: list[Finding] = []
    scanned_count = 0

    try:
        with console.status("[bold blue]Scanning repository files..."):
            for file_path in root.rglob("*"):
                if not file_path.is_file():
                    continue

                rel_path = file_path.relative_to(root).as_posix()

                if should_ignore_path(rel_path, global_ignores):
                    continue

                try:
                    if is_binary_file(file_path):
                        continue
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except PermissionError:
                    _fail(f"Permission denied reading {rel_path}")
                except OSError as exc:
                    _fail(f"Unable to read {rel_path}: {exc}")

                try:
                    all_findings.extend(engine.scan_text(content, file_path=rel_path))
                except Exception as exc:
                    _fail(f"Scan failed for {rel_path}: {exc}")
                scanned_count += 1
    except typer.Exit:
        raise
    except OSError as exc:
        _fail(f"Failed to walk repository {root}: {exc}")

    console.print(f"[dim]Scanned {scanned_count} files.[/dim]")
    _render_findings(all_findings, github_annotations, sarif)

@app.command()
def scan_staged(
    repo_path: str = typer.Argument(".", help="Path to repository root"),
    config: str = typer.Option(".spurhund-rules.yml", help="Path to rules YAML"),
    github_annotations: bool = typer.Option(False, "--github-annotations", help=_GITHUB_ANNOTATIONS_HELP),
):
    """Scan staged git changes for secret and credential leaks."""
    root = Path(repo_path).resolve()
    if not root.exists():
        _fail(f"Repository path not found: {root}")
    if not root.is_dir():
        _fail(f"Repository path is not a directory: {root}")

    global_ignores, rules = _load_rules(config, root=root, auto_init=True)
    try:
        patch = get_staged_diff(root)
    except RuntimeError as exc:
        _fail(str(exc))
    except OSError as exc:
        _fail(f"Git diff failed: {exc}")

    all_findings, scanned_count = _findings_from_patch(patch, global_ignores, rules)

    console.print(f"[dim]Scanned {scanned_count} staged lines.[/dim]")
    _render_findings(all_findings, github_annotations)

@app.command()
def scan_ci(
    repo_path: str = typer.Argument(".", help="Path to repository root"),
    base_ref: str = typer.Option("origin/main", help="Base ref for the commit range"),
    head_ref: str = typer.Option("HEAD", help="Head ref for the commit range"),
    config: str = typer.Option(".spurhund-rules.yml", help="Path to rules YAML"),
    github_annotations: bool = typer.Option(False, "--github-annotations", help=_GITHUB_ANNOTATIONS_HELP),
    sarif: str = typer.Option("", "--sarif", help="Write a SARIF 2.1.0 report to this path."),
):
    """Scan a pull-request commit range for secret and credential leaks.

    Reads ``git diff base...head`` and checks only added lines. If the range
    cannot be produced (shallow clone, missing ref), scans the whole tree.
    """
    root = Path(repo_path).resolve()
    if not root.exists():
        _fail(f"Repository path not found: {root}")
    if not root.is_dir():
        _fail(f"Repository path is not a directory: {root}")

    global_ignores, rules = _load_rules(config, root=root, auto_init=True)

    try:
        patch = get_branch_diff(base_ref, head_ref, root)
    except (RuntimeError, OSError) as exc:
        console.print(
            f"[yellow]Branch diff {base_ref}...{head_ref} failed ({exc}). "
            "Falling back to a full repository scan.[/yellow]"
        )
        scan_repo(repo_path, config, github_annotations, sarif)

    all_findings, scanned_count = _findings_from_patch(patch, global_ignores, rules)

    console.print(f"[dim]Scanned {scanned_count} lines in {base_ref}...{head_ref}.[/dim]")
    _render_findings(all_findings, github_annotations, sarif)

if __name__ == "__main__":
    app()  # pragma: no cover