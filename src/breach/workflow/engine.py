"""
BREACH v3.1 - Workflow Engine
==============================

Main orchestration engine for the 4-phase pentest.

Equivalent to Shannon's Temporal workflows but using native Python asyncio.
For enterprise deployments, this can be replaced with Temporal.io integration.
"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from enum import Enum

from breach.phases import (
    ReconPhase, ReconResult,
    AnalysisPhase, AnalysisResult,
    ExploitPhase, ExploitResult, ValidatedFinding,
    ReportPhase, ReportResult,
)

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()


class WorkflowState(str, Enum):
    """Workflow execution state."""
    PENDING = "pending"
    RECON = "recon"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class WorkflowConfig:
    """Configuration for the workflow."""
    # Target
    target: str = ""
    repo_path: Path = None
    cookies: Dict[str, str] = None

    # Features
    use_ai: bool = True
    use_browser: bool = True
    use_source_analysis: bool = True

    # Limits
    max_pages: int = 100
    max_concurrent: int = 5
    timeout_minutes: int = 30

    # Modules
    modules: List[str] = field(default_factory=list)

    # Output
    output_dir: Path = Path("./audit-logs")


@dataclass
class WorkflowResult:
    """Complete workflow result."""
    # Config
    target: str = ""
    config: WorkflowConfig = None

    # Timing
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0

    # State
    state: WorkflowState = WorkflowState.PENDING
    error: Optional[str] = None

    # Phase results
    recon_result: Optional[ReconResult] = None
    analysis_result: Optional[AnalysisResult] = None
    exploit_result: Optional[ExploitResult] = None
    report_result: Optional[ReportResult] = None

    # Convenience accessors
    @property
    def findings(self) -> List[ValidatedFinding]:
        return self.exploit_result.findings if self.exploit_result else []

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def success(self) -> bool:
        return self.state == WorkflowState.COMPLETED

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "state": self.state.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "total_findings": self.total_findings,
            "findings": [
                {
                    "id": f.id,
                    "type": f.vuln_type,
                    "severity": f.severity,
                    "endpoint": f.endpoint,
                }
                for f in self.findings
            ],
            "error": self.error,
        }


class WorkflowEngine:
    """
    Main workflow orchestration engine.

    Runs the 4-phase pentest:
    1. Reconnaissance
    2. Vulnerability Analysis (parallel)
    3. Exploitation (parallel)
    4. Reporting

    Usage:
        async with WorkflowEngine(config) as engine:
            result = await engine.run()
    """

    def __init__(
        self,
        config: WorkflowConfig,
        on_progress: Callable[[str], None] = None,
        on_finding: Callable[[ValidatedFinding], None] = None,
        on_state_change: Callable[[WorkflowState], None] = None,
    ):
        self.config = config
        self.on_progress = on_progress or (lambda x: None)
        self.on_finding = on_finding or (lambda x: None)
        self.on_state_change = on_state_change or (lambda x: None)

        self._result = WorkflowResult(target=config.target, config=config)
        self._audit_dir: Optional[Path] = None

        # Phase instances
        self._recon: Optional[ReconPhase] = None
        self._analysis: Optional[AnalysisPhase] = None
        self._exploit: Optional[ExploitPhase] = None
        self._report: Optional[ReportPhase] = None

    async def __aenter__(self):
        """Initialize workflow."""
        # Create audit directory
        from urllib.parse import urlparse
        domain = urlparse(self.config.target).netloc.replace(":", "_")
        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._audit_dir = self.config.output_dir / f"{domain}_{session_id}"
        self._audit_dir.mkdir(parents=True, exist_ok=True)

        return self

    async def __aexit__(self, *args):
        """Cleanup."""
        pass

    def _set_state(self, state: WorkflowState):
        """Update workflow state."""
        self._result.state = state
        self.on_state_change(state)

    async def run(self) -> WorkflowResult:
        """
        Execute the complete 4-phase workflow.

        Returns:
            WorkflowResult with all phase results and findings
        """
        start_time = time.time()
        self._result.started_at = datetime.utcnow()

        self._banner()

        try:
            # ============================================================
            # PHASE 1: RECONNAISSANCE
            # ============================================================
            self._set_state(WorkflowState.RECON)
            self._phase_banner(1, "RECONNAISSANCE")

            async with ReconPhase(
                use_ai=self.config.use_ai,
                use_browser=self.config.use_browser,
                repo_path=self.config.repo_path,
                max_pages=self.config.max_pages,
                audit_dir=self._audit_dir,
                on_progress=self.on_progress,
            ) as recon:
                self._result.recon_result = await recon.run(
                    target=self.config.target,
                    cookies=self.config.cookies,
                )

            self._phase_summary(1, self._result.recon_result)

            # ============================================================
            # PHASE 2: VULNERABILITY ANALYSIS
            # ============================================================
            self._set_state(WorkflowState.ANALYSIS)
            self._phase_banner(2, "VULNERABILITY ANALYSIS")

            analysis = AnalysisPhase(
                use_ai=self.config.use_ai,
                repo_path=self.config.repo_path,
                audit_dir=self._audit_dir,
                on_progress=self.on_progress,
            )
            self._result.analysis_result = await analysis.run(
                target=self.config.target,
                recon_result=self._result.recon_result,
            )

            self._phase_summary(2, self._result.analysis_result)

            # ============================================================
            # PHASE 3: EXPLOITATION
            # ============================================================
            self._set_state(WorkflowState.EXPLOITATION)
            self._phase_banner(3, "EXPLOITATION")

            async with ExploitPhase(
                use_browser=self.config.use_browser,
                max_concurrent=self.config.max_concurrent,
                audit_dir=self._audit_dir,
                on_progress=self.on_progress,
                on_finding=self.on_finding,
            ) as exploit:
                self._result.exploit_result = await exploit.run(
                    analysis_result=self._result.analysis_result,
                    cookies=self.config.cookies,
                )

            self._phase_summary(3, self._result.exploit_result)

            # ============================================================
            # PHASE 4: REPORTING
            # ============================================================
            self._set_state(WorkflowState.REPORTING)
            self._phase_banner(4, "REPORTING")

            report = ReportPhase(
                output_dir=self.config.output_dir,
            )
            self._result.report_result = await report.run(
                target=self.config.target,
                recon_result=self._result.recon_result,
                analysis_result=self._result.analysis_result,
                exploit_result=self._result.exploit_result,
            )

            self._phase_summary(4, self._result.report_result)

            # ============================================================
            # COMPLETE
            # ============================================================
            self._set_state(WorkflowState.COMPLETED)

        except Exception as e:
            self._set_state(WorkflowState.FAILED)
            self._result.error = str(e)
            console.print(f"\n[red]Workflow failed: {e}[/red]")
            import traceback
            traceback.print_exc()

        # Finalize
        self._result.completed_at = datetime.utcnow()
        self._result.duration_seconds = time.time() - start_time

        # Final report
        self._final_report()

        return self._result

    def _banner(self):
        """Display workflow banner."""
        console.print(Panel.fit(
            f"[bold red]BREACH v3.1[/bold red]\n"
            f"[bold yellow]Shannon-Style Autonomous Pentester[/bold yellow]\n"
            f"[bold white]NO EXPLOIT, NO REPORT[/bold white]\n\n"
            f"Target: {self.config.target}\n"
            f"AI: {'Enabled' if self.config.use_ai else 'Disabled'}\n"
            f"Browser: {'Enabled' if self.config.use_browser else 'Disabled'}\n"
            f"Source Analysis: {'Enabled' if self.config.repo_path else 'Disabled'}",
            border_style="red",
            title="[bold]BREACH[/bold]"
        ))

    def _phase_banner(self, phase_num: int, name: str):
        """Display phase banner."""
        console.print(f"\n{'='*70}")
        console.print(f"[bold cyan]PHASE {phase_num}: {name}[/bold cyan]")
        console.print(f"{'='*70}\n")

    def _phase_summary(self, phase_num: int, result: Any):
        """Display phase summary."""
        if phase_num == 1 and isinstance(result, ReconResult):
            console.print(f"\n[green]✓ Phase 1 Complete[/green]")
            console.print(f"  Endpoints: {len(result.endpoints)}")
            console.print(f"  Parameters: {len(result.parameters)}")
            console.print(f"  Technologies: {len(result.technologies)}")
            console.print(f"  Duration: {result.duration_seconds:.1f}s")

        elif phase_num == 2 and isinstance(result, AnalysisResult):
            console.print(f"\n[green]✓ Phase 2 Complete[/green]")
            console.print(f"  Hypotheses: {result.total_hypotheses}")
            console.print(f"  SQLi: {result.sqli_hypotheses}")
            console.print(f"  XSS: {result.xss_hypotheses}")
            console.print(f"  SSRF: {result.ssrf_hypotheses}")
            console.print(f"  CMDi: {result.cmdi_hypotheses}")
            console.print(f"  Duration: {result.duration_seconds:.1f}s")

        elif phase_num == 3 and isinstance(result, ExploitResult):
            console.print(f"\n[green]✓ Phase 3 Complete[/green]")
            console.print(f"  Tested: {result.hypotheses_tested}")
            console.print(f"  [bold green]Exploited: {result.successful_exploits}[/bold green]")
            console.print(f"  False Positives: {result.false_positives}")
            console.print(f"  Duration: {result.duration_seconds:.1f}s")

        elif phase_num == 4 and isinstance(result, ReportResult):
            console.print(f"\n[green]✓ Phase 4 Complete[/green]")
            console.print(f"  Report: {result.report_path}")

    def _final_report(self):
        """Display final workflow report."""
        result = self._result

        console.print(f"\n{'='*70}")
        console.print(f"[bold]WORKFLOW COMPLETE[/bold]")
        console.print(f"{'='*70}\n")

        # Summary table
        table = Table(box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Target", result.target)
        table.add_row("Duration", f"{result.duration_seconds:.1f}s")
        table.add_row("State", result.state.value)

        if result.recon_result:
            table.add_row("Endpoints", str(len(result.recon_result.endpoints)))
            table.add_row("Parameters", str(len(result.recon_result.parameters)))

        if result.analysis_result:
            table.add_row("Hypotheses", str(result.analysis_result.total_hypotheses))

        if result.exploit_result:
            table.add_row("Exploited", f"[bold green]{result.exploit_result.successful_exploits}[/bold green]")
            table.add_row("False Positives", str(result.exploit_result.false_positives))

        console.print(table)

        # Findings summary
        if result.findings:
            console.print(f"\n[bold green]VALIDATED FINDINGS ({len(result.findings)}):[/bold green]\n")

            for finding in sorted(result.findings, key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f.severity, 4)):
                severity_colors = {"CRITICAL": "red bold", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "dim"}
                color = severity_colors.get(finding.severity, "white")
                console.print(f"[{color}][{finding.severity}] {finding.vuln_type.upper()} - {finding.endpoint}[/{color}]")
                console.print(f"  [green]✓ EXPLOITED[/green] | {finding.proof_type}")
                console.print(f"  [dim]{finding.curl_command}[/dim]\n")

            if result.exploit_result:
                console.print(f"[bold green]Total Business Impact: ${result.exploit_result.total_business_impact:,}[/bold green]")

        else:
            console.print(f"\n[green]No exploitable vulnerabilities found.[/green]")

        # Report location
        if result.report_result and result.report_result.report_path:
            console.print(f"\n[cyan]Report: {result.report_result.report_path}[/cyan]")

        console.print(f"\n{'='*70}")
        console.print("[bold]BREACH v3.1 - No Exploit, No Report[/bold]")
        console.print(f"{'='*70}\n")
