"""
BREACH.AI - Live Dashboard
==========================
Real-time terminal dashboard for scan progress.
"""

from typing import Optional, List, Dict, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import time

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.layout import Layout
from rich.text import Text
from rich.box import ROUNDED, HEAVY


@dataclass
class Finding:
    """Finding data for dashboard display."""
    title: str
    severity: str
    endpoint: str
    is_exploited: bool = False
    confidence: float = 0.0
    business_impact: float = 0.0


@dataclass
class DashboardState:
    """State for the live dashboard."""
    target: str = ""
    mode: str = "quick"
    status: str = "INITIALIZING"
    phase: str = "Starting..."
    progress: int = 0

    # Counters
    endpoints_discovered: int = 0
    endpoints_tested: int = 0
    requests_made: int = 0

    # Findings
    findings: List[Finding] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    total_impact: float = 0.0

    # Timing
    start_time: Optional[datetime] = None
    elapsed_seconds: int = 0


class ScanDashboard:
    """
    Live terminal dashboard for scan progress.

    Usage:
        dashboard = ScanDashboard(target="https://example.com", mode="deep")
        with dashboard:
            # Run your scan
            dashboard.update_progress(50, "Testing injections...")
            dashboard.add_finding(Finding(...))
    """

    # Color scheme
    COLORS = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#28a745",
        "info": "#17a2b8",
        "brand": "#6f42c1",
        "muted": "#6c757d",
        "success": "#28a745",
    }

    def __init__(
        self,
        target: str,
        mode: str = "quick",
        console: Optional[Console] = None,
    ):
        self.console = console or Console()
        self.state = DashboardState(target=target, mode=mode)
        self.live: Optional[Live] = None
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
        )
        self._task_id = None

    def __enter__(self):
        """Start the live dashboard."""
        self.state.start_time = datetime.now()
        self.state.status = "SCANNING"
        self._task_id = self._progress.add_task("Scanning...", total=100)
        self.live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=4,
            transient=False,
        )
        self.live.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop the live dashboard."""
        if self.live:
            self.state.status = "COMPLETED" if exc_type is None else "FAILED"
            self.live.update(self._render())
            self.live.__exit__(exc_type, exc_val, exc_tb)

    def update_progress(self, percent: int, phase: str = "") -> None:
        """Update scan progress."""
        self.state.progress = min(100, max(0, percent))
        if phase:
            self.state.phase = phase

        # Update elapsed time
        if self.state.start_time:
            self.state.elapsed_seconds = int((datetime.now() - self.state.start_time).total_seconds())

        # Update progress bar
        if self._task_id is not None:
            self._progress.update(self._task_id, completed=percent, description=phase or "Scanning...")

        # Refresh display
        if self.live:
            self.live.update(self._render())

    def add_finding(self, finding: Finding) -> None:
        """Add a new finding to the dashboard."""
        self.state.findings.append(finding)

        # Update severity counts
        sev = finding.severity.lower()
        if sev == "critical":
            self.state.critical_count += 1
        elif sev == "high":
            self.state.high_count += 1
        elif sev == "medium":
            self.state.medium_count += 1
        elif sev == "low":
            self.state.low_count += 1
        else:
            self.state.info_count += 1

        # Update total impact
        self.state.total_impact += finding.business_impact

        # Refresh display
        if self.live:
            self.live.update(self._render())

    def update_stats(
        self,
        endpoints_discovered: Optional[int] = None,
        endpoints_tested: Optional[int] = None,
        requests_made: Optional[int] = None,
    ) -> None:
        """Update scan statistics."""
        if endpoints_discovered is not None:
            self.state.endpoints_discovered = endpoints_discovered
        if endpoints_tested is not None:
            self.state.endpoints_tested = endpoints_tested
        if requests_made is not None:
            self.state.requests_made = requests_made

        # Refresh display
        if self.live:
            self.live.update(self._render())

    def set_status(self, status: str) -> None:
        """Set the scan status."""
        self.state.status = status
        if self.live:
            self.live.update(self._render())

    def _render(self) -> Panel:
        """Render the full dashboard."""
        # Build the layout
        content = Group(
            self._render_header(),
            "",
            self._progress,
            "",
            self._render_findings(),
            "",
            self._render_footer(),
        )

        return Panel(
            content,
            title="[bold white]BREACH[/bold white]",
            subtitle=f"v2.0.0",
            border_style=self.COLORS["brand"],
            box=ROUNDED,
        )

    def _render_header(self) -> Panel:
        """Render the header section."""
        # Status color
        status_colors = {
            "INITIALIZING": "yellow",
            "SCANNING": "blue",
            "ATTACKING": "red",
            "COMPLETED": "green",
            "FAILED": "red",
        }
        status_color = status_colors.get(self.state.status, "white")

        # Format elapsed time
        elapsed = str(timedelta(seconds=self.state.elapsed_seconds))

        header_text = (
            f"[bold]Target:[/bold] {self.state.target}\n"
            f"[bold]Mode:[/bold] {self.state.mode.upper()} | "
            f"[bold]Status:[/bold] [{status_color}]{self.state.status}[/] | "
            f"[bold]Elapsed:[/bold] {elapsed}"
        )

        return Panel(header_text, box=ROUNDED, border_style="dim")

    def _render_findings(self) -> Panel:
        """Render the findings table."""
        table = Table(
            show_header=True,
            header_style="bold",
            box=ROUNDED,
            border_style="dim",
            expand=True,
        )

        table.add_column("Severity", width=10)
        table.add_column("Title", width=35)
        table.add_column("Endpoint", width=30)
        table.add_column("Status", width=12)

        # Show last 5 findings
        recent_findings = self.state.findings[-5:] if self.state.findings else []

        if not recent_findings:
            table.add_row("[dim]No findings yet...[/dim]", "", "", "")
        else:
            for f in recent_findings:
                sev_color = self.COLORS.get(f.severity.lower(), self.COLORS["info"])
                status = f"[green]EXPLOITED[/green]" if f.is_exploited else "[dim]testing[/dim]"

                # Truncate endpoint if too long
                endpoint = f.endpoint[:28] + "..." if len(f.endpoint) > 30 else f.endpoint

                table.add_row(
                    f"[{sev_color}]{f.severity.upper()}[/]",
                    f.title[:33] + "..." if len(f.title) > 35 else f.title,
                    endpoint,
                    status,
                )

        return Panel(table, title="Findings", border_style="dim")

    def _render_footer(self) -> Text:
        """Render the footer with stats."""
        # Severity summary
        parts = []
        if self.state.critical_count > 0:
            parts.append(f"[{self.COLORS['critical']}]{self.state.critical_count} CRITICAL[/]")
        if self.state.high_count > 0:
            parts.append(f"[{self.COLORS['high']}]{self.state.high_count} HIGH[/]")
        if self.state.medium_count > 0:
            parts.append(f"[{self.COLORS['medium']}]{self.state.medium_count} MEDIUM[/]")
        if self.state.low_count > 0:
            parts.append(f"[{self.COLORS['low']}]{self.state.low_count} LOW[/]")

        severity_summary = " | ".join(parts) if parts else "[dim]No vulnerabilities found[/dim]"

        # Impact formatting
        impact = self.state.total_impact
        if impact >= 1_000_000:
            impact_str = f"${impact/1_000_000:.1f}M"
        elif impact >= 1_000:
            impact_str = f"${impact/1_000:.0f}K"
        else:
            impact_str = f"${impact:.0f}"

        footer = Text()
        footer.append(f"Endpoints: {self.state.endpoints_discovered} | ")
        footer.append(f"Vulns: {len(self.state.findings)} | ")
        footer.append(f"Impact: ", style="bold")
        footer.append(impact_str, style="bold red")

        # Add severity breakdown
        footer.append("\n")
        footer.append_text(Text.from_markup(severity_summary))

        return footer


class SimpleDashboard:
    """
    Simple non-live dashboard for basic progress output.

    Use this when Live display is not suitable (e.g., CI/CD, logging).
    """

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.last_phase = ""

    def update_progress(self, percent: int, phase: str = "") -> None:
        """Print progress update."""
        if phase != self.last_phase:
            self.console.print(f"[{percent:3d}%] {phase}")
            self.last_phase = phase

    def add_finding(self, finding: Finding) -> None:
        """Print finding."""
        sev_colors = {
            "critical": "red",
            "high": "yellow",
            "medium": "yellow",
            "low": "green",
            "info": "blue",
        }
        color = sev_colors.get(finding.severity.lower(), "white")
        exploit = " [EXPLOITED]" if finding.is_exploited else ""

        self.console.print(f"  [{color}]{finding.severity.upper()}[/] {finding.title}{exploit}")

    def print_summary(
        self,
        findings_count: int,
        severity_counts: Dict[str, int],
        total_impact: float,
        duration: int,
    ) -> None:
        """Print final summary."""
        self.console.print()
        self.console.print("[bold]Scan Complete[/bold]")
        self.console.print(f"  Total Findings: {findings_count}")
        self.console.print(f"  Duration: {duration // 60}m {duration % 60}s")

        # Impact formatting
        if total_impact >= 1_000_000:
            impact_str = f"${total_impact/1_000_000:.1f}M"
        elif total_impact >= 1_000:
            impact_str = f"${total_impact/1_000:.0f}K"
        else:
            impact_str = f"${total_impact:.0f}"

        self.console.print(f"  Business Impact: [bold red]{impact_str}[/]")
