#!/usr/bin/env python3
"""
BREACH.AI CLI
=============

Autonomous security scanner with proof-by-exploitation.

Usage:
    breach <target>                          # Quick scan
    breach <target> --mode deep              # Comprehensive scan
    breach <target> --mode proven            # Only report exploited vulns
    breach <target> --mode chaos             # All 60+ modules

Examples:
    breach https://example.com
    breach https://example.com --mode proven --browser
    breach https://example.com --cookie "session=xxx" -o report.json
    breach https://example.com --ai --mode chaos
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
__version__ = "2.0.0"

# Initialize
app = typer.Typer(
    name="breach",
    help="BREACH.AI - Autonomous Security Scanner",
    add_completion=True,
    rich_markup_mode="rich",
)
console = Console()

# Project root for .env loading
PROJECT_ROOT = Path(__file__).parent.parent


class ScanMode(str, Enum):
    """Scan modes."""
    quick = "quick"
    deep = "deep"
    proven = "proven"
    chaos = "chaos"


class OutputFormat(str, Enum):
    """Output formats."""
    json = "json"
    md = "md"
    html = "html"


# ============== UTILITY FUNCTIONS ==============

def load_env():
    """Load .env file from project root."""
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(env_file)
        except ImportError:
            # Manual parsing fallback
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ.setdefault(key.strip(), value.strip().strip('"\''))


def print_banner():
    """Print the BREACH.AI banner."""
    banner = """
[bold red]
 ██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗
 ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║
 ██████╔╝██████╔╝█████╗  ███████║██║     ███████║
 ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║
 ██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║
 ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
[/bold red]
[bold white]      Autonomous Security Scanner v{version}[/bold white]
[dim]      pip install breach-ai[full][/dim]
""".format(version=__version__)
    console.print(banner)


def verify_ownership(target: str, skip: bool = False) -> bool:
    """Verify ownership before scanning."""
    if skip:
        return True

    console.print("\n[yellow][!] DOMAIN OWNERSHIP VERIFICATION[/yellow]")
    console.print(f"\nYou are about to scan: [bold]{target}[/bold]")
    console.print("\nBy proceeding, you confirm that:")
    console.print("  1. You own this domain/application, OR")
    console.print("  2. You have explicit written permission to test it")
    console.print("\n[red]Unauthorized scanning is illegal and unethical.[/red]\n")

    response = typer.prompt("Type 'I CONFIRM' to proceed")
    return response.strip() == "I CONFIRM"


def get_output_path(output: Optional[str], target: str, format: OutputFormat) -> Path:
    """Generate output path."""
    if output:
        path = Path(output)
        if path.suffix:
            return path
        return path.with_suffix(f".{format.value}")

    # Auto-generate filename
    from urllib.parse import urlparse
    domain = urlparse(target).netloc.replace(":", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(f"breach_{domain}_{timestamp}.{format.value}")


# ============== MAIN SCAN COMMAND ==============

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL to scan"),
    mode: ScanMode = typer.Option(
        ScanMode.quick,
        "--mode", "-m",
        help="Scan mode: quick, deep, proven (exploitation-validated), chaos (all modules)"
    ),
    cookie: Optional[str] = typer.Option(
        None, "--cookie", "-c",
        help="Session cookie for authenticated scanning"
    ),
    cookie2: Optional[str] = typer.Option(
        None, "--cookie2",
        help="Second user cookie for IDOR testing"
    ),
    token: Optional[str] = typer.Option(
        None, "--token", "-t",
        help="Bearer token for API authentication"
    ),
    header: Optional[List[str]] = typer.Option(
        None, "--header", "-H",
        help="Custom headers (can be used multiple times)"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output file path (format detected from extension)"
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.json, "--format", "-f",
        help="Output format when -o is a directory"
    ),
    json_stdout: bool = typer.Option(
        False, "--json",
        help="Output JSON to stdout (for piping)"
    ),
    timeout: int = typer.Option(
        30, "--timeout",
        help="Timeout in minutes"
    ),
    rate_limit: int = typer.Option(
        50, "--rate-limit",
        help="Max requests per second"
    ),
    parallel: int = typer.Option(
        5, "--parallel",
        help="Parallel workers"
    ),
    modules: Optional[str] = typer.Option(
        None, "--modules",
        help="Comma-separated list of modules to run"
    ),
    skip_modules: Optional[str] = typer.Option(
        None, "--skip-modules",
        help="Comma-separated list of modules to skip"
    ),
    exclude: Optional[List[str]] = typer.Option(
        None, "--exclude",
        help="Paths to exclude from scanning"
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy",
        help="HTTP proxy URL"
    ),
    ai: bool = typer.Option(
        False, "--ai",
        help="Enable AI-enhanced scanning (requires ANTHROPIC_API_KEY)"
    ),
    browser: bool = typer.Option(
        False, "--browser",
        help="Enable browser validation (requires playwright)"
    ),
    skip_verify: bool = typer.Option(
        False, "--skip-verify",
        help="Skip ownership verification prompt"
    ),
    no_banner: bool = typer.Option(
        False, "--no-banner",
        help="Skip the banner"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Verbose output"
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Minimal output (errors only)"
    ),
):
    """
    Run a security scan against a target.

    Examples:
        breach https://example.com
        breach https://example.com --mode proven --browser
        breach https://example.com --cookie "session=abc" -o report.json
    """
    # Load environment
    load_env()

    # Banner
    if not no_banner and not quiet and not json_stdout:
        print_banner()

    # Validate target
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    # Verify ownership
    if not verify_ownership(target, skip_verify):
        console.print("[red][!] Scan cancelled. Ownership not confirmed.[/red]")
        raise typer.Exit(code=2)

    # Check AI availability
    if ai and not os.environ.get("ANTHROPIC_API_KEY"):
        console.print("[yellow][!] ANTHROPIC_API_KEY not set. Running without AI enhancement.[/yellow]")
        ai = False

    # Check browser availability
    if browser:
        try:
            import playwright
        except ImportError:
            console.print("[yellow][!] Playwright not installed. Run: pip install breach-ai[browser][/yellow]")
            browser = False

    # Build config
    config = {
        "target": target,
        "mode": mode.value,
        "cookie": cookie,
        "cookie2": cookie2,
        "token": token,
        "headers": dict(h.split(":", 1) for h in header) if header else {},
        "timeout_minutes": timeout,
        "rate_limit": rate_limit,
        "parallel": parallel,
        "modules": modules.split(",") if modules else None,
        "skip_modules": skip_modules.split(",") if skip_modules else None,
        "exclude": exclude or [],
        "proxy": proxy,
        "ai_enabled": ai,
        "browser_enabled": browser,
        "verbose": verbose,
    }

    # Run scan
    try:
        result = asyncio.run(_run_scan(config, quiet, json_stdout))

        # Output results
        if json_stdout:
            import json
            print(json.dumps(result.to_dict() if hasattr(result, 'to_dict') else {}, indent=2, default=str))
        elif output:
            output_path = get_output_path(output, target, output_format)
            _save_output(result, output_path, target=target, mode=mode.value)
            console.print(f"\n[green][+] Report saved: {output_path}[/green]")

        # Exit code based on findings
        if result.findings:
            raise typer.Exit(code=1)  # Vulnerabilities found
        raise typer.Exit(code=0)  # Clean

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Scan interrupted by user[/yellow]")
        raise typer.Exit(code=130)
    except Exception as e:
        console.print(f"\n[red][!] Error: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        raise typer.Exit(code=2)


async def _run_scan(config: dict, quiet: bool, json_stdout: bool):
    """Execute the scan based on mode."""
    mode = config["mode"]

    if mode == "quick":
        return await _run_quick_scan(config, quiet)
    elif mode == "deep":
        return await _run_deep_scan(config, quiet)
    elif mode == "proven":
        return await _run_proven_scan(config, quiet)
    elif mode == "chaos":
        return await _run_chaos_scan(config, quiet)
    else:
        raise ValueError(f"Unknown mode: {mode}")


async def _run_quick_scan(config: dict, quiet: bool):
    """Run quick reconnaissance scan."""
    from breach.engine import BreachEngine

    if not quiet:
        console.print(Panel(
            f"[bold]Quick Scan[/bold]\n"
            f"Target: {config['target']}\n"
            f"Mode: Reconnaissance + Common Vulnerabilities",
            title="[cyan]BREACH.AI[/cyan]",
            border_style="cyan"
        ))

    async with BreachEngine(deep_mode=False) as engine:
        await engine.breach(
            target=config["target"],
            cookie=config["cookie"],
        )
        return engine.state


async def _run_deep_scan(config: dict, quiet: bool):
    """Run deep comprehensive scan."""
    from breach.deep_scan.engine import DeepScanEngine

    if not quiet:
        console.print(Panel(
            f"[bold]Deep Scan[/bold]\n"
            f"Target: {config['target']}\n"
            f"Mode: Comprehensive Injection Testing",
            title="[yellow]BREACH.AI[/yellow]",
            border_style="yellow"
        ))

    async with DeepScanEngine(
        timeout_minutes=config["timeout_minutes"],
        max_concurrent=config["parallel"],
    ) as engine:
        # Progress callback
        def on_progress(pct, msg):
            if not quiet:
                console.print(f"[dim]{pct}%[/dim] {msg}")

        result = await engine.scan(
            target=config["target"],
            cookies={"session": config["cookie"]} if config["cookie"] else None,
            cookies2={"session": config["cookie2"]} if config["cookie2"] else None,
            token=config["token"],
            progress_callback=on_progress,
        )
        return result


async def _run_proven_scan(config: dict, quiet: bool):
    """Run proof-by-exploitation scan (only reports exploited vulns)."""
    from breach.exploitation.shannon_engine import ShannonEngine

    if not quiet:
        console.print(Panel(
            f"[bold]Proven Mode[/bold]\n"
            f"Target: {config['target']}\n"
            f"Mode: Proof-by-Exploitation\n"
            f"[dim]Only reports vulnerabilities that are successfully exploited[/dim]",
            title="[red]BREACH.AI[/red]",
            border_style="red"
        ))

    async with ShannonEngine(
        timeout_minutes=config["timeout_minutes"],
        use_browser=config["browser_enabled"],
        use_source_analysis=False,  # Requires source code
        parallel_agents=config["parallel"],
        screenshot=config["browser_enabled"],
    ) as engine:
        # Progress callback
        def on_progress(pct, msg):
            if not quiet:
                console.print(f"[dim]{pct}%[/dim] {msg}")

        engine.on_progress(on_progress)

        result = await engine.scan(
            target=config["target"],
            cookies={"session": config["cookie"]} if config["cookie"] else None,
        )
        return result


async def _run_chaos_scan(config: dict, quiet: bool):
    """Run all 60+ attack modules (brutal assessment)."""
    from breach.brutal_assessment import BrutalAssessment

    if not quiet:
        console.print(Panel(
            f"[bold]Chaos Mode[/bold]\n"
            f"Target: {config['target']}\n"
            f"Mode: ALL 60+ Attack Modules\n"
            f"[dim]Maximum depth exploitation[/dim]",
            title="[magenta]BREACH.AI[/magenta]",
            border_style="magenta"
        ))

    assessment = BrutalAssessment(
        target=config["target"],
        aggressive=True,
        timeout_per_module=config["timeout_minutes"] * 60 // 60,  # Convert to per-module
        max_concurrent=config["parallel"],
    )

    result = await assessment.run()
    return result


def _save_output(result, path: Path, target: str = "", mode: str = "quick"):
    """Save scan results to file using the appropriate formatter."""
    from breach.output import JSONFormatter, MarkdownFormatter, HTMLFormatter

    path.parent.mkdir(parents=True, exist_ok=True)

    # Extract findings from result
    findings = []
    if hasattr(result, 'findings'):
        for f in result.findings:
            finding = _convert_finding_to_dict(f)
            findings.append(finding)

    # Build stats
    stats = {
        "critical_count": sum(1 for f in findings if f.get("severity", "").lower() == "critical"),
        "high_count": sum(1 for f in findings if f.get("severity", "").lower() == "high"),
        "medium_count": sum(1 for f in findings if f.get("severity", "").lower() == "medium"),
        "low_count": sum(1 for f in findings if f.get("severity", "").lower() == "low"),
        "info_count": sum(1 for f in findings if f.get("severity", "").lower() == "info"),
        "total_impact": sum(f.get("business_impact", 0) for f in findings),
    }

    # Get duration if available
    duration = getattr(result, 'duration_seconds', 0) or 0

    if path.suffix == ".json":
        formatter = JSONFormatter(pretty=True)
        formatter.save(str(path), target, mode, findings, stats, duration)
    elif path.suffix == ".md":
        formatter = MarkdownFormatter(include_poc=True)
        formatter.save(str(path), target, mode, findings, stats, duration)
    elif path.suffix == ".html":
        formatter = HTMLFormatter(include_poc=True)
        formatter.save(str(path), target, mode, findings, stats, duration)
    else:
        # Default to JSON
        formatter = JSONFormatter(pretty=True)
        formatter.save(str(path.with_suffix('.json')), target, mode, findings, stats, duration)


def _convert_finding_to_dict(f) -> dict:
    """Convert a finding object to a dictionary."""
    if isinstance(f, dict):
        return f

    # Handle various finding object types
    return {
        "title": getattr(f, 'title', getattr(f, 'vulnerability_type', 'Unknown')),
        "severity": str(getattr(f, 'severity', 'medium')).lower().replace('severity.', ''),
        "category": getattr(f, 'category', getattr(f, 'vulnerability_type', '')),
        "vulnerability_type": getattr(f, 'vulnerability_type', ''),
        "endpoint": getattr(f, 'endpoint', ''),
        "method": getattr(f, 'method', 'GET'),
        "parameter": getattr(f, 'parameter', None),
        "description": getattr(f, 'description', ''),
        "payload": getattr(f, 'payload', ''),
        "evidence": getattr(f, 'evidence', {}),
        "business_impact": getattr(f, 'business_impact', 0),
        "impact_explanation": getattr(f, 'impact_explanation', ''),
        "is_exploited": getattr(f, 'is_exploited', False),
        "exploitation_confidence": getattr(f, 'exploitation_confidence', getattr(f, 'confidence', 0)),
        "exploitation_proof": getattr(f, 'exploitation_proof', getattr(f, 'proof_data', {})),
        "proof_type": getattr(f, 'proof_type', getattr(f, 'exploitation_proof_type', '')),
        "curl_command": getattr(f, 'curl_command', ''),
        "reproduction_steps": getattr(f, 'reproduction_steps', []),
        "poc_script": getattr(f, 'poc_script', ''),
        "remediation": getattr(f, 'remediation', getattr(f, 'fix_suggestion', '')),
        "cwe_id": getattr(f, 'cwe_id', ''),
    }


# ============== UTILITY COMMANDS ==============

@app.command()
def version():
    """Show version information."""
    console.print(f"[bold]BREACH.AI[/bold] v{__version__}")

    # Check optional dependencies
    console.print("\n[dim]Optional Features:[/dim]")

    try:
        import anthropic
        console.print("  [green]✓[/green] AI (anthropic)")
    except ImportError:
        console.print("  [red]✗[/red] AI - pip install breach-ai[ai]")

    try:
        import playwright
        console.print("  [green]✓[/green] Browser (playwright)")
    except ImportError:
        console.print("  [red]✗[/red] Browser - pip install breach-ai[browser]")


@app.command()
def doctor():
    """Check system dependencies and configuration."""
    console.print("[bold]BREACH.AI Doctor[/bold]\n")

    checks = []

    # Python version
    import sys
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 11)
    checks.append(("Python >= 3.11", py_version, py_ok))

    # Core dependencies (package_name, import_name)
    deps = [
        ("aiohttp", "aiohttp"),
        ("rich", "rich"),
        ("typer", "typer"),
        ("pydantic", "pydantic"),
        ("beautifulsoup4", "bs4"),
    ]
    for pkg_name, import_name in deps:
        try:
            __import__(import_name)
            checks.append((pkg_name, "installed", True))
        except ImportError:
            checks.append((pkg_name, "missing", False))

    # Optional: AI
    try:
        import anthropic
        api_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
        checks.append(("anthropic", "installed", True))
        checks.append(("ANTHROPIC_API_KEY", "set" if api_key else "not set", api_key))
    except ImportError:
        checks.append(("anthropic", "not installed", False))

    # Optional: Browser
    try:
        import playwright
        checks.append(("playwright", "installed", True))
    except ImportError:
        checks.append(("playwright", "not installed", False))

    # Display results
    table = Table(box=box.ROUNDED)
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("OK")

    all_ok = True
    for name, status, ok in checks:
        all_ok = all_ok and ok
        table.add_row(
            name,
            status,
            "[green]✓[/green]" if ok else "[red]✗[/red]"
        )

    console.print(table)

    if all_ok:
        console.print("\n[green]All checks passed![/green]")
    else:
        console.print("\n[yellow]Some optional features are not available.[/yellow]")
        console.print("Run: [bold]pip install breach-ai[full][/bold]")


@app.command("list-modules")
def list_modules():
    """List all available attack modules."""
    console.print("[bold]Available Attack Modules[/bold]\n")

    # Categories and modules
    modules = {
        "Injection": ["sqli", "xss", "ssrf", "cmdi", "ssti", "nosql", "xxe", "ldap"],
        "Authentication": ["auth_bypass", "jwt", "oauth", "saml", "mfa_bypass", "session"],
        "Access Control": ["idor", "privilege_escalation", "forced_browsing"],
        "API Security": ["graphql", "rest_api", "websocket", "api_abuse"],
        "File Attacks": ["lfi", "rfi", "file_upload", "path_traversal"],
        "Cloud": ["aws", "azure", "gcp", "kubernetes", "docker"],
        "Business Logic": ["race_condition", "price_manipulation", "workflow_bypass"],
    }

    for category, mods in modules.items():
        console.print(f"\n[cyan]{category}[/cyan]")
        for mod in mods:
            console.print(f"  • {mod}")

    console.print(f"\n[dim]Total: 60+ modules available in chaos mode[/dim]")


@app.command()
def config(
    action: str = typer.Argument(..., help="Action: show, set, unset"),
    key: Optional[str] = typer.Argument(None, help="Config key"),
    value: Optional[str] = typer.Argument(None, help="Config value"),
):
    """Manage CLI configuration."""
    config_file = Path.home() / ".breach" / "config.json"

    import json

    # Load existing config
    if config_file.exists():
        cfg = json.loads(config_file.read_text())
    else:
        cfg = {}

    if action == "show":
        if not cfg:
            console.print("[dim]No configuration set[/dim]")
        else:
            for k, v in cfg.items():
                # Mask sensitive values
                display = v[:4] + "..." if "key" in k.lower() else v
                console.print(f"  {k}: {display}")

    elif action == "set":
        if not key or not value:
            console.print("[red]Usage: breach config set <key> <value>[/red]")
            raise typer.Exit(1)

        config_file.parent.mkdir(parents=True, exist_ok=True)
        cfg[key] = value
        config_file.write_text(json.dumps(cfg, indent=2))
        console.print(f"[green]Set {key}[/green]")

    elif action == "unset":
        if not key:
            console.print("[red]Usage: breach config unset <key>[/red]")
            raise typer.Exit(1)

        if key in cfg:
            del cfg[key]
            config_file.write_text(json.dumps(cfg, indent=2))
            console.print(f"[green]Removed {key}[/green]")
        else:
            console.print(f"[yellow]Key not found: {key}[/yellow]")


# ============== ENTRY POINT ==============

def main():
    """Main entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
