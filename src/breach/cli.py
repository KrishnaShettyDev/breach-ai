#!/usr/bin/env python3
"""
BREACH v3.1 CLI
================

Shannon-Style Autonomous Security Scanner

Usage:
    breach <target>                    # Full 4-phase scan
    breach <target> --repo ./myapp     # White-box with source
    breach <target> --no-browser       # Skip browser validation

Examples:
    breach https://example.com
    breach https://example.com --repo ./repos/myapp --ai
    breach https://example.com -o ./reports
"""

import asyncio
import os
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

# Version
__version__ = "3.1.0"

# Initialize
app = typer.Typer(
    name="breach",
    help="BREACH v3.1 - Shannon-Style Autonomous Security Scanner",
    add_completion=True,
    rich_markup_mode="rich",
)
console = Console()

# Project root
PROJECT_ROOT = Path(__file__).parent.parent


def load_env():
    """Load .env file."""
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(env_file)
        except ImportError:
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ.setdefault(key.strip(), value.strip().strip('"\''))


def print_banner():
    """Print BREACH banner."""
    banner = """
[bold red]
 ██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗
 ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║
 ██████╔╝██████╔╝█████╗  ███████║██║     ███████║
 ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║
 ██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║
 ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
[/bold red]
[bold yellow]      Shannon-Style Autonomous Pentester v{version}[/bold yellow]
[bold white]           NO EXPLOIT, NO REPORT[/bold white]
""".format(version=__version__)
    console.print(banner)


def verify_ownership(target: str, skip: bool = False) -> bool:
    """Verify target ownership."""
    if skip:
        return True

    console.print("\n[yellow][!] AUTHORIZATION REQUIRED[/yellow]")
    console.print(f"\nTarget: [bold]{target}[/bold]")
    console.print("\nBy proceeding, you confirm:")
    console.print("  1. You OWN this application, OR")
    console.print("  2. You have WRITTEN authorization to test it")
    console.print("\n[red]Unauthorized testing is illegal.[/red]\n")

    response = typer.prompt("Type 'I CONFIRM' to proceed")
    return response.strip() == "I CONFIRM"


def _resolve_modules(
    categories: Optional[List[str]],
    modules: Optional[List[str]],
    verbose: bool = False
) -> Optional[List[str]]:
    """Resolve module list from categories and explicit modules."""
    if not categories and not modules:
        return None  # Run all modules

    from breach.attacks.registry import (
        ATTACK_REGISTRY,
        CATEGORY_INFO,
        AttackCategory,
    )

    selected = set()

    # Add modules from categories
    if categories:
        for cat_name in categories:
            try:
                cat = AttackCategory(cat_name.lower())
                if cat in CATEGORY_INFO:
                    cat_modules = CATEGORY_INFO[cat]["modules"]
                    selected.update(cat_modules)
                    if verbose:
                        console.print(f"[dim]  Category '{cat_name}': {len(cat_modules)} modules[/dim]")
            except ValueError:
                console.print(f"[yellow][!] Unknown category: {cat_name}[/yellow]")
                console.print("[yellow]    Use 'breach modules --categories' to list categories[/yellow]")

    # Add explicit modules
    if modules:
        for mod_name in modules:
            if mod_name in ATTACK_REGISTRY:
                selected.add(mod_name)
            else:
                console.print(f"[yellow][!] Unknown module: {mod_name}[/yellow]")
                console.print("[yellow]    Use 'breach modules' to list modules[/yellow]")

    return list(selected) if selected else None


# ============== MAIN SCAN COMMAND ==============

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL to scan"),
    repo: Optional[Path] = typer.Option(
        None, "--repo", "-r",
        help="Path to source code repository (enables white-box testing)"
    ),
    cookie: Optional[str] = typer.Option(
        None, "--cookie", "-c",
        help="Session cookie for authenticated scanning"
    ),
    output: Optional[Path] = typer.Option(
        Path("./audit-logs"), "--output", "-o",
        help="Output directory for reports"
    ),
    category: Optional[List[str]] = typer.Option(
        None, "--category", "-C",
        help="Attack categories to run (e.g., injection, auth, api). Use 'breach modules' to list."
    ),
    modules: Optional[List[str]] = typer.Option(
        None, "--module", "-m",
        help="Specific modules to run (e.g., sqli, jwt, ssrf). Use 'breach modules' to list."
    ),
    ai: bool = typer.Option(
        True, "--ai/--no-ai",
        help="Enable AI-enhanced scanning"
    ),
    browser: bool = typer.Option(
        True, "--browser/--no-browser",
        help="Enable browser validation (required for XSS)"
    ),
    max_pages: int = typer.Option(
        100, "--max-pages",
        help="Maximum pages to crawl"
    ),
    parallel: int = typer.Option(
        5, "--parallel",
        help="Parallel workers"
    ),
    skip_verify: bool = typer.Option(
        False, "--skip-verify",
        help="Skip authorization prompt"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Verbose output"
    ),
):
    """
    Run Shannon-style 4-phase security assessment.

    Phase 1: Reconnaissance - Map attack surface
    Phase 2: Vulnerability Analysis - Generate hypotheses (parallel)
    Phase 3: Exploitation - Validate with proof (parallel)
    Phase 4: Reporting - Generate comprehensive report

    Only reports vulnerabilities that are SUCCESSFULLY EXPLOITED.
    """
    load_env()
    print_banner()

    # Validate target
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    # Verify authorization
    if not verify_ownership(target, skip_verify):
        console.print("[red][!] Scan cancelled.[/red]")
        raise typer.Exit(code=2)

    # Check AI
    if ai and not os.environ.get("ANTHROPIC_API_KEY"):
        console.print("[yellow][!] ANTHROPIC_API_KEY not set. Disabling AI.[/yellow]")
        ai = False

    # Check browser
    if browser:
        try:
            import playwright
        except ImportError:
            console.print("[yellow][!] Playwright not installed. Browser validation disabled.[/yellow]")
            console.print("[yellow]    XSS findings cannot be validated without browser.[/yellow]")
            console.print("[yellow]    Install: pip install playwright && playwright install[/yellow]")
            browser = False

    # Check repo
    if repo and not repo.exists():
        console.print(f"[yellow][!] Repository not found: {repo}[/yellow]")
        repo = None

    # Resolve modules from categories and explicit modules
    selected_modules = _resolve_modules(category, modules, verbose)
    if selected_modules:
        console.print(f"[cyan][*] Running {len(selected_modules)} selected modules[/cyan]")
        if verbose:
            console.print(f"[dim]    Modules: {', '.join(selected_modules)}[/dim]")

    # Build config
    from breach.workflow import WorkflowConfig
    config = WorkflowConfig(
        target=target,
        repo_path=repo,
        cookies={"session": cookie} if cookie else None,
        use_ai=ai,
        use_browser=browser,
        use_source_analysis=repo is not None,
        max_pages=max_pages,
        max_concurrent=parallel,
        output_dir=output,
        modules=selected_modules,
    )

    # Run workflow
    try:
        result = asyncio.run(_run_workflow(config, verbose))

        # Exit code
        if result.findings:
            raise typer.Exit(code=1)  # Vulnerabilities found
        raise typer.Exit(code=0)  # Clean

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted[/yellow]")
        raise typer.Exit(code=130)
    except Exception as e:
        console.print(f"\n[red][!] Error: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        raise typer.Exit(code=2)


async def _run_workflow(config, verbose: bool):
    """Execute the workflow."""
    from breach.workflow import WorkflowEngine

    def on_progress(msg):
        if verbose:
            console.print(f"[dim]{msg}[/dim]")

    def on_finding(finding):
        console.print(f"[green]✓ EXPLOITED: {finding.vuln_type} - {finding.endpoint}[/green]")

    async with WorkflowEngine(
        config=config,
        on_progress=on_progress,
        on_finding=on_finding,
    ) as engine:
        return await engine.run()


# ============== UTILITY COMMANDS ==============

@app.command()
def version():
    """Show version information."""
    console.print(f"[bold]BREACH[/bold] v{__version__}")
    console.print("[dim]Shannon-Style Autonomous Pentester[/dim]")

    console.print("\n[cyan]Features:[/cyan]")

    # Check optional dependencies
    try:
        import anthropic
        console.print("  [green]✓[/green] AI (anthropic)")
    except ImportError:
        console.print("  [red]✗[/red] AI - pip install anthropic")

    try:
        import playwright
        console.print("  [green]✓[/green] Browser (playwright)")
    except ImportError:
        console.print("  [red]✗[/red] Browser - pip install playwright && playwright install")


@app.command()
def doctor():
    """Check system dependencies."""
    console.print("[bold]BREACH Doctor[/bold]\n")

    checks = []

    # Python
    import sys
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 11)
    checks.append(("Python >= 3.11", py_version, py_ok))

    # Core deps
    deps = [
        ("aiohttp", "aiohttp"),
        ("rich", "rich"),
        ("typer", "typer"),
        ("beautifulsoup4", "bs4"),
        ("lxml", "lxml"),
    ]
    for pkg, imp in deps:
        try:
            __import__(imp)
            checks.append((pkg, "✓", True))
        except ImportError:
            checks.append((pkg, "✗", False))

    # Optional
    try:
        import anthropic
        api_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
        checks.append(("anthropic", "✓", True))
        checks.append(("ANTHROPIC_API_KEY", "set" if api_key else "not set", api_key))
    except ImportError:
        checks.append(("anthropic", "not installed", False))

    try:
        import playwright
        checks.append(("playwright", "✓", True))
    except ImportError:
        checks.append(("playwright", "not installed", False))

    # Display
    table = Table(box=box.ROUNDED)
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("OK")

    all_ok = True
    for name, status, ok in checks:
        all_ok = all_ok and ok
        table.add_row(name, str(status), "[green]✓[/green]" if ok else "[red]✗[/red]")

    console.print(table)

    if all_ok:
        console.print("\n[green]All checks passed![/green]")
    else:
        console.print("\n[yellow]Install missing dependencies:[/yellow]")
        console.print("  pip install breach-ai[full]")
        console.print("  playwright install chromium")


@app.command("list-phases")
def list_phases():
    """List the 4-phase workflow."""
    console.print("[bold]BREACH 4-Phase Workflow[/bold]\n")

    phases = [
        ("Phase 1", "Reconnaissance", "Map attack surface, discover endpoints, detect technologies"),
        ("Phase 2", "Vulnerability Analysis", "Parallel OWASP agents generate hypotheses"),
        ("Phase 3", "Exploitation", "Test hypotheses, capture proof (NO EXPLOIT = NO REPORT)"),
        ("Phase 4", "Reporting", "Generate comprehensive assessment report"),
    ]

    for num, name, desc in phases:
        console.print(f"[cyan]{num}:[/cyan] [bold]{name}[/bold]")
        console.print(f"  {desc}\n")


@app.command("modules")
def list_modules(
    categories_only: bool = typer.Option(
        False, "--categories", "-c",
        help="Show only categories"
    ),
    category: Optional[str] = typer.Option(
        None, "--filter", "-f",
        help="Filter by category"
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s",
        help="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"
    ),
):
    """List all attack modules and categories."""
    from breach.attacks.registry import (
        ATTACK_REGISTRY,
        CATEGORY_INFO,
        AttackCategory,
        get_modules_by_category,
        get_modules_by_severity,
    )

    console.print("[bold]BREACH Attack Modules[/bold]\n")

    if categories_only:
        # Show categories table
        table = Table(box=box.ROUNDED, title="Attack Categories")
        table.add_column("Category", style="cyan")
        table.add_column("Description")
        table.add_column("Severity", style="bold")
        table.add_column("Modules", justify="right")

        for cat in AttackCategory:
            if cat in CATEGORY_INFO:
                info = CATEGORY_INFO[cat]
                sev_color = {
                    "CRITICAL": "red",
                    "HIGH": "yellow",
                    "MEDIUM": "blue",
                    "LOW": "dim",
                }.get(info["severity"], "white")

                table.add_row(
                    cat.value,
                    info["description"],
                    f"[{sev_color}]{info['severity']}[/{sev_color}]",
                    str(len(info["modules"])),
                )

        console.print(table)
        console.print("\n[dim]Use 'breach modules --filter <category>' to see modules in a category[/dim]")
        console.print("[dim]Use 'breach scan <target> --category injection --category auth' to run specific categories[/dim]")
        return

    # Build module list
    if category:
        try:
            cat = AttackCategory(category.lower())
            modules_list = get_modules_by_category(cat)
            console.print(f"[cyan]Category: {category}[/cyan]\n")
        except ValueError:
            console.print(f"[red]Unknown category: {category}[/red]")
            return
    elif severity:
        modules_list = get_modules_by_severity(severity)
        console.print(f"[cyan]Severity: {severity.upper()}[/cyan]\n")
    else:
        modules_list = list(ATTACK_REGISTRY.values())

    # Group by category
    by_category: dict = {}
    for mod in modules_list:
        cat_name = mod.category.value
        if cat_name not in by_category:
            by_category[cat_name] = []
        by_category[cat_name].append(mod)

    # Display
    for cat_name, mods in sorted(by_category.items()):
        console.print(f"\n[bold cyan]━━━ {cat_name.upper()} ━━━[/bold cyan]")

        table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
        table.add_column("Module", style="green")
        table.add_column("Name")
        table.add_column("Sev", width=8)
        table.add_column("Description")

        for mod in sorted(mods, key=lambda m: m.name):
            # Find the key for this module
            mod_key = next(
                (k for k, v in ATTACK_REGISTRY.items() if v == mod),
                "?"
            )
            sev_color = {
                "CRITICAL": "red",
                "HIGH": "yellow",
                "MEDIUM": "blue",
                "LOW": "dim",
            }.get(mod.severity, "white")

            table.add_row(
                mod_key,
                mod.name,
                f"[{sev_color}]{mod.severity[:4]}[/{sev_color}]",
                mod.description[:50] + "..." if len(mod.description) > 50 else mod.description,
            )

        console.print(table)

    # Summary
    total = len(modules_list)
    critical = len([m for m in modules_list if m.severity == "CRITICAL"])
    high = len([m for m in modules_list if m.severity == "HIGH"])

    console.print(f"\n[bold]Total: {total} modules[/bold] ([red]{critical} CRITICAL[/red], [yellow]{high} HIGH[/yellow])")
    console.print("\n[dim]Usage:[/dim]")
    console.print("[dim]  breach scan <target> --module sqli --module xss[/dim]")
    console.print("[dim]  breach scan <target> --category injection --category auth[/dim]")


@app.command("init")
def init_config(
    target: str = typer.Argument(..., help="Target URL"),
    output: Path = typer.Option(Path("./configs"), help="Config directory"),
):
    """Generate a configuration file for a target."""
    from urllib.parse import urlparse

    domain = urlparse(target).netloc.replace(":", "_")
    config_path = output / f"{domain}.yaml"

    config_content = f"""# BREACH Configuration for {target}
# Generated: {datetime.now().isoformat()}

target: {target}

# Authentication (optional)
# authentication:
#   login_type: form
#   login_url: "{target}/login"
#   credentials:
#     username: "test@example.com"
#     password: "password123"

# Scanning options
scan:
  max_pages: 100
  timeout_minutes: 30
  parallel: 5

# Modules to run (default: all)
# modules:
#   - sqli
#   - xss
#   - ssrf
#   - cmdi
#   - auth

# Paths to exclude
# exclude:
#   - /logout
#   - /admin

# Source code path (for white-box testing)
# repo: ./repos/{domain}
"""

    output.mkdir(parents=True, exist_ok=True)
    config_path.write_text(config_content)
    console.print(f"[green]Config created: {config_path}[/green]")


# ============== SOURCE CODE ANALYSIS ==============

@app.command("analyze")
def analyze_source(
    path: Path = typer.Argument(..., help="Path to source code directory"),
    target: Optional[str] = typer.Option(
        None, "--target", "-t",
        help="Target URL (for context)"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output report file (JSON)"
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s",
        help="Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW)"
    ),
    format: str = typer.Option(
        "table", "--format", "-f",
        help="Output format: table, json, sarif"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Verbose output"
    ),
):
    """
    Analyze source code for security vulnerabilities.

    Performs multi-language data flow analysis to trace
    user input from sources to dangerous sinks.

    Supports: Python, JavaScript, TypeScript, Go, Java, PHP, Ruby

    Examples:
        breach analyze ./myapp
        breach analyze ./myapp --target https://myapp.com
        breach analyze ./myapp -o report.json -f json
    """
    import json as json_lib

    console.print("[bold]BREACH Source Code Analyzer[/bold]\n")

    if not path.exists():
        console.print(f"[red][!] Path not found: {path}[/red]")
        raise typer.Exit(code=1)

    console.print(f"[cyan][*] Analyzing: {path}[/cyan]")
    if target:
        console.print(f"[cyan][*] Target URL: {target}[/cyan]")

    # Run analysis
    try:
        from breach.source.dataflow import DataFlowAnalyzer

        analyzer = DataFlowAnalyzer()
        result = asyncio.run(analyzer.analyze_directory(str(path), target))

        # Filter by severity if specified
        flows = result.tainted_flows
        if severity:
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            min_sev = sev_order.get(severity.upper(), 3)
            flows = [f for f in flows if sev_order.get(f.severity, 3) <= min_sev]

        # Print summary
        console.print(f"\n[bold]{'='*60}[/bold]")
        console.print(f"[bold]Analysis Complete[/bold]")
        console.print(f"[bold]{'='*60}[/bold]")
        console.print(f"Files analyzed: {result.files_analyzed}")
        console.print(f"Lines of code: {result.total_lines:,}")
        console.print(f"Analysis time: {result.analysis_time_ms:.0f}ms")
        console.print(f"\n[cyan]Sources found: {len(result.sources_found)}[/cyan]")
        console.print(f"[cyan]Sinks found: {len(result.sinks_found)}[/cyan]")
        console.print(f"[red]Tainted flows: {len(flows)}[/red]")

        if result.technologies_detected:
            console.print(f"\n[yellow]Technologies:[/yellow] {', '.join(result.technologies_detected.keys())}")

        # Output results
        if format == "json" or output:
            report = {
                "target": result.target,
                "files_analyzed": result.files_analyzed,
                "total_lines": result.total_lines,
                "analysis_time_ms": result.analysis_time_ms,
                "technologies": result.technologies_detected,
                "flows": [
                    {
                        "vuln_type": f.vuln_type.value,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "source": {
                            "name": f.source.name,
                            "type": f.source.type,
                            "file": f.source.file_path,
                            "line": f.source.line_number,
                        },
                        "sink": {
                            "name": f.sink.name,
                            "file": f.sink.file_path,
                            "line": f.sink.line_number,
                        },
                        "path": f.path,
                        "code_context": f.code_context[:200],
                        "payloads": f.payloads[:3],
                        "is_sanitized": f.is_sanitized,
                    }
                    for f in flows
                ],
            }

            if output:
                output.write_text(json_lib.dumps(report, indent=2))
                console.print(f"\n[green]Report saved: {output}[/green]")
            elif format == "json":
                console.print(json_lib.dumps(report, indent=2))

        elif format == "table" and flows:
            # Print table of flows
            console.print(f"\n[bold red]Vulnerable Data Flows[/bold red]\n")

            table = Table(box=box.ROUNDED)
            table.add_column("#", style="dim", width=4)
            table.add_column("Type", style="cyan", width=12)
            table.add_column("Sev", width=8)
            table.add_column("Source", width=25)
            table.add_column("Sink", width=25)
            table.add_column("File", width=30)

            for i, flow in enumerate(flows[:50], 1):  # Limit to 50
                sev_color = {
                    "CRITICAL": "red",
                    "HIGH": "yellow",
                    "MEDIUM": "blue",
                    "LOW": "dim",
                }.get(flow.severity, "white")

                # Truncate paths for display
                file_display = flow.file_path
                if len(file_display) > 30:
                    file_display = "..." + file_display[-27:]

                table.add_row(
                    str(i),
                    flow.vuln_type.value,
                    f"[{sev_color}]{flow.severity[:4]}[/{sev_color}]",
                    flow.source.name[:25],
                    flow.sink.name[:25],
                    f"{file_display}:{flow.start_line}",
                )

            console.print(table)

            if len(flows) > 50:
                console.print(f"\n[dim]...and {len(flows) - 50} more flows[/dim]")

            # Print critical flows detail
            critical = [f for f in flows if f.severity == "CRITICAL"]
            if critical:
                console.print(f"\n[bold red]CRITICAL Flows ({len(critical)})[/bold red]\n")
                for flow in critical[:5]:
                    console.print(f"[red]━━━ {flow.vuln_type.value.upper()} ━━━[/red]")
                    console.print(f"  Source: [cyan]{flow.source.name}[/cyan] ({flow.source.type})")
                    console.print(f"  Sink:   [red]{flow.sink.name}[/red]")
                    console.print(f"  File:   {flow.file_path}:{flow.start_line}-{flow.end_line}")
                    console.print(f"  Confidence: {flow.confidence:.0%}")
                    if flow.payloads:
                        console.print(f"  Payloads: {flow.payloads[0]}")
                    console.print()

        elif not flows:
            console.print("\n[green]No vulnerable data flows found![/green]")

        # Exit code
        critical_count = len([f for f in flows if f.severity == "CRITICAL"])
        high_count = len([f for f in flows if f.severity == "HIGH"])

        if critical_count > 0:
            console.print(f"\n[red]Found {critical_count} CRITICAL vulnerabilities![/red]")
            raise typer.Exit(code=2)
        elif high_count > 0:
            console.print(f"\n[yellow]Found {high_count} HIGH severity vulnerabilities[/yellow]")
            raise typer.Exit(code=1)

        raise typer.Exit(code=0)

    except ImportError as e:
        console.print(f"[red][!] Import error: {e}[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red][!] Analysis error: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        raise typer.Exit(code=2)


# ============== GOD MODE ==============

@app.command("god")
def god_mode(
    target: str = typer.Argument(..., help="Target URL to BREACH"),
    hours: float = typer.Option(
        4.0, "--hours", "-H",
        help="Maximum runtime in hours (default: 4)"
    ),
    provider: str = typer.Option(
        "anthropic", "--provider", "-p",
        help="LLM provider: anthropic, openai"
    ),
    model: Optional[str] = typer.Option(
        None, "--model", "-m",
        help="Model to use (default: claude-sonnet-4-20250514 or gpt-4o)"
    ),
    no_mercy: bool = typer.Option(
        True, "--no-mercy/--mercy",
        help="No mercy mode - never give up"
    ),
    output: Path = typer.Option(
        Path("./audit-logs"), "--output", "-o",
        help="Output directory"
    ),
    resume: bool = typer.Option(
        False, "--resume", "-r",
        help="Resume from checkpoint"
    ),
    skip_verify: bool = typer.Option(
        False, "--skip-verify",
        help="Skip authorization prompt"
    ),
    verbose: bool = typer.Option(
        True, "--verbose/--quiet", "-v",
        help="Verbose output"
    ),
):
    """
    [bold red]GOD MODE[/bold red] - Full AI autonomous pentesting.

    The AI has COMPLETE CONTROL. It decides:
    - What to attack
    - How to attack
    - When to pivot
    - When to stop

    [bold yellow]NO MERCY. NO STOPPING. BREACH EVERYTHING.[/bold yellow]

    Example:
        breach god https://target.com --hours 4
        breach god https://target.com --provider openai --hours 2
    """
    load_env()

    # Print God Mode banner
    god_banner = """
[bold red]
   ██████╗  ██████╗ ██████╗     ███╗   ███╗ ██████╗ ██████╗ ███████╗
  ██╔════╝ ██╔═══██╗██╔══██╗    ████╗ ████║██╔═══██╗██╔══██╗██╔════╝
  ██║  ███╗██║   ██║██║  ██║    ██╔████╔██║██║   ██║██║  ██║█████╗
  ██║   ██║██║   ██║██║  ██║    ██║╚██╔╝██║██║   ██║██║  ██║██╔══╝
  ╚██████╔╝╚██████╔╝██████╔╝    ██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗
   ╚═════╝  ╚═════╝ ╚═════╝     ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
[/bold red]
[bold yellow]        AI HAS FULL CONTROL. NO MERCY. NO STOPPING.[/bold yellow]
[bold white]              BREACH EVERYTHING OR DIE TRYING.[/bold white]
"""
    console.print(god_banner)

    # Validate target
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    # Verify authorization
    if not skip_verify:
        console.print("\n[red][!] GOD MODE AUTHORIZATION REQUIRED[/red]")
        console.print(f"\nTarget: [bold]{target}[/bold]")
        console.print(f"Runtime: [bold]{hours} hours[/bold]")
        console.print(f"Provider: [bold]{provider}[/bold]")
        console.print("\n[yellow]GOD MODE will:[/yellow]")
        console.print("  - Run for up to {hours} hours non-stop")
        console.print("  - Make autonomous attack decisions")
        console.print("  - Attempt to breach EVERYTHING")
        console.print("\n[red]This is AGGRESSIVE automated pentesting.[/red]")
        console.print("[red]Only use on targets you OWN or have EXPLICIT authorization.[/red]\n")

        response = typer.prompt("Type 'BREACH' to activate GOD MODE")
        if response.strip() != "BREACH":
            console.print("[red][!] GOD MODE cancelled.[/red]")
            raise typer.Exit(code=2)

    # Check API keys
    if provider == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
        console.print("[red][!] ANTHROPIC_API_KEY not set[/red]")
        raise typer.Exit(code=1)
    if provider == "openai" and not os.environ.get("OPENAI_API_KEY"):
        console.print("[red][!] OPENAI_API_KEY not set[/red]")
        raise typer.Exit(code=1)

    console.print(f"\n[green][*] GOD MODE ACTIVATED[/green]")
    console.print(f"[cyan]    Target: {target}[/cyan]")
    console.print(f"[cyan]    Runtime: {hours} hours[/cyan]")
    console.print(f"[cyan]    Provider: {provider}[/cyan]")
    console.print(f"[cyan]    No Mercy: {no_mercy}[/cyan]")

    # Run God Mode
    try:
        from breach.ai.god_mode import AIGodMode, GodModeConfig, LLMProvider

        config = GodModeConfig(
            target=target,
            max_runtime_hours=hours,
            provider=LLMProvider(provider),
            model=model or ("claude-sonnet-4-20250514" if provider == "anthropic" else "gpt-4o"),
            no_mercy=no_mercy,
            output_dir=output,
        )

        def on_finding(finding):
            console.print(f"[green]✓ BREACHED: {finding.type} - {finding.endpoint}[/green]")

        def on_progress(msg):
            if verbose:
                console.print(f"[dim]{msg}[/dim]")

        result = asyncio.run(_run_god_mode(config, on_finding, on_progress))

        # Print results
        console.print(f"\n[bold]{'='*60}[/bold]")
        console.print(f"[bold]GOD MODE COMPLETE[/bold]")
        console.print(f"[bold]{'='*60}[/bold]")
        console.print(f"Runtime: {result.runtime_seconds / 3600:.2f} hours")
        console.print(f"AI Decisions: {result.ai_decisions}")
        console.print(f"Findings: {len(result.findings)}")

        if result.findings:
            console.print(f"\n[red]TARGET BREACHED![/red]")
            for f in result.findings:
                console.print(f"  - {f.type}: {f.endpoint}")
            raise typer.Exit(code=1)
        else:
            console.print(f"\n[yellow]No breaches achieved in {hours} hours.[/yellow]")
            raise typer.Exit(code=0)

    except ImportError as e:
        console.print(f"[red][!] Missing dependency: {e}[/red]")
        console.print("[yellow]Install AI dependencies: pip install anthropic openai[/yellow]")
        raise typer.Exit(code=1)
    except KeyboardInterrupt:
        console.print("\n[yellow][!] GOD MODE interrupted - state saved[/yellow]")
        raise typer.Exit(code=130)
    except Exception as e:
        console.print(f"\n[red][!] GOD MODE error: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        raise typer.Exit(code=2)


async def _run_god_mode(config, on_finding, on_progress):
    """Execute God Mode."""
    from breach.ai.god_mode import AIGodMode

    async with AIGodMode(
        config=config,
        on_finding=on_finding,
        on_progress=on_progress,
    ) as god:
        return await god.run()


# ============== ENTRY POINT ==============

def main():
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
