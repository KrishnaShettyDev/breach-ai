"""
BREACH.AI - Console Helpers
===========================
Rich console utilities for beautiful terminal output.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.style import Style
from rich.box import ROUNDED, HEAVY, SIMPLE_HEAVY


# Global console instance
console = Console()


# Color scheme
COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#28a745",
    "info": "#17a2b8",
    "success": "#28a745",
    "warning": "#ffc107",
    "error": "#dc3545",
    "muted": "#6c757d",
    "primary": "#0d6efd",
    "brand": "#6f42c1",
}


def print_banner(version: str = "2.0.0") -> None:
    """Print the BREACH banner."""
    banner_text = """
[bold white]  ____  _____  ______          _____ _    _ [/]
[bold white] |  _ \|  __ \|  ____|   /\   / ____| |  | |[/]
[bold white] | |_) | |__) | |__     /  \ | |    | |__| |[/]
[bold white] |  _ <|  _  /|  __|   / /\ \| |    |  __  |[/]
[bold white] | |_) | | \ \| |____ / ____ \ |____| |  | |[/]
[bold white] |____/|_|  \_\______/_/    \_\_____|_|  |_|[/]
"""

    console.print(banner_text, highlight=False)
    console.print(f"[{COLORS['muted']}]  Autonomous Security Scanner v{version}[/]")
    console.print(f"[{COLORS['muted']}]  Proof-by-Exploitation Engine[/]")
    console.print()


def print_error(message: str, title: str = "Error") -> None:
    """Print an error message."""
    console.print(f"[bold red]{title}:[/bold red] {message}")


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[bold green]SUCCESS:[/bold green] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[bold yellow]WARNING:[/bold yellow] {message}")


def print_info(message: str) -> None:
    """Print an info message."""
    console.print(f"[bold blue]INFO:[/bold blue] {message}")


def severity_style(severity: str) -> Style:
    """Get Rich style for a severity level."""
    color = COLORS.get(severity.lower(), COLORS["info"])
    return Style(color=color, bold=True)


def format_severity(severity: str) -> Text:
    """Format severity with appropriate color."""
    text = Text(severity.upper())
    text.stylize(severity_style(severity))
    return text


def format_impact(impact: float) -> str:
    """Format business impact as currency."""
    if impact >= 1_000_000:
        return f"${impact/1_000_000:.1f}M"
    elif impact >= 1_000:
        return f"${impact/1_000:.0f}K"
    else:
        return f"${impact:.0f}"


def print_scan_summary(
    target: str,
    mode: str,
    duration: int,
    findings_count: int,
    severity_counts: Dict[str, int],
    total_impact: float,
) -> None:
    """Print a summary of scan results."""

    # Create summary table
    table = Table(
        show_header=False,
        box=ROUNDED,
        border_style="dim",
        padding=(0, 1),
    )
    table.add_column("Label", style="dim")
    table.add_column("Value")

    table.add_row("Target", f"[bold]{target}[/bold]")
    table.add_row("Mode", mode.upper())
    table.add_row("Duration", f"{duration // 60}m {duration % 60}s")
    table.add_row("Total Findings", str(findings_count))

    # Severity breakdown
    severity_parts = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            color = COLORS[sev]
            severity_parts.append(f"[{color}]{count} {sev.upper()}[/]")

    if severity_parts:
        table.add_row("Breakdown", " / ".join(severity_parts))

    table.add_row("Business Impact", f"[bold red]{format_impact(total_impact)}[/bold red]")

    console.print()
    console.print(Panel(table, title="[bold]Scan Complete[/bold]", border_style="green"))


def print_finding(
    title: str,
    severity: str,
    endpoint: str,
    is_exploited: bool = False,
    confidence: float = 0.0,
    compact: bool = True,
) -> None:
    """Print a single finding."""
    sev_text = format_severity(severity)

    if compact:
        # Single-line format
        exploit_badge = ""
        if is_exploited:
            exploit_badge = f" [green]EXPLOITED ({confidence*100:.0f}%)[/green]"

        console.print(f"  {sev_text}  {title} [{COLORS['muted']}]{endpoint}[/]{exploit_badge}")
    else:
        # Full format with panel
        content = f"[bold]{title}[/bold]\n"
        content += f"Endpoint: {endpoint}\n"
        if is_exploited:
            content += f"[green]Exploited with {confidence*100:.0f}% confidence[/green]"

        console.print(Panel(content, title=sev_text, border_style=COLORS[severity.lower()]))


def print_findings_table(findings: List[Dict[str, Any]]) -> None:
    """Print findings as a table."""
    if not findings:
        console.print("[dim]No findings discovered.[/dim]")
        return

    table = Table(
        show_header=True,
        header_style="bold",
        box=ROUNDED,
        border_style="dim",
    )

    table.add_column("Severity", width=10)
    table.add_column("Title", width=40)
    table.add_column("Endpoint", width=30)
    table.add_column("Status", width=12)
    table.add_column("Impact", width=10, justify="right")

    for f in findings:
        severity = f.get("severity", "info")
        status = "[green]EXPLOITED[/green]" if f.get("is_exploited") else "[dim]detected[/dim]"
        impact = format_impact(f.get("business_impact", 0))

        table.add_row(
            format_severity(severity),
            f.get("title", "Unknown"),
            f.get("endpoint", "-")[:28] + "..." if len(f.get("endpoint", "-")) > 30 else f.get("endpoint", "-"),
            status,
            impact,
        )

    console.print(table)


def print_doctor_result(
    name: str,
    available: bool,
    version: Optional[str] = None,
    message: Optional[str] = None,
) -> None:
    """Print a doctor check result."""
    if available:
        version_str = f" (v{version})" if version else ""
        console.print(f"  [green]OK[/green] {name}{version_str}")
    else:
        msg = f" - {message}" if message else ""
        console.print(f"  [red]MISSING[/red] {name}{msg}")


def print_modules_table(modules: List[Dict[str, Any]]) -> None:
    """Print available modules as a table."""
    table = Table(
        show_header=True,
        header_style="bold",
        box=SIMPLE_HEAVY,
    )

    table.add_column("Module", width=25)
    table.add_column("Description", width=50)
    table.add_column("Category", width=15)

    for m in modules:
        table.add_row(
            f"[bold]{m['name']}[/bold]",
            m.get("description", ""),
            f"[{COLORS['muted']}]{m.get('category', 'general')}[/]",
        )

    console.print(table)


def print_config_table(config: Dict[str, Any]) -> None:
    """Print configuration as a table."""
    table = Table(
        show_header=True,
        header_style="bold",
        box=ROUNDED,
        border_style="dim",
    )

    table.add_column("Setting", width=25)
    table.add_column("Value", width=40)

    for key, value in config.items():
        display_value = str(value)
        # Mask sensitive values
        if "key" in key.lower() or "secret" in key.lower() or "password" in key.lower():
            if value:
                display_value = value[:8] + "..." if len(str(value)) > 8 else "***"

        table.add_row(key, display_value)

    console.print(table)


def print_progress_bar(current: int, total: int, label: str = "") -> None:
    """Print a simple progress bar (for non-live updates)."""
    width = 40
    filled = int(width * current / total) if total > 0 else 0
    bar = "=" * filled + "-" * (width - filled)
    percent = (current / total * 100) if total > 0 else 0

    console.print(f"[{bar}] {percent:.0f}% {label}", end="\r")
