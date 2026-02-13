"""
BREACH.AI - GOD LEVEL DEEP SCAN ENGINE
=======================================
One scan mode. Does EVERYTHING. Finds REAL vulnerabilities with PROOF.

Target duration: 15-20 minutes for comprehensive testing.
"""

import asyncio
import time
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable
from datetime import datetime
import aiohttp
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

from .spider import DeepSpider, SpiderResult, DiscoveredEndpoint
from .testers.injections import InjectionTester, Finding
from .testers.auth import AuthTester
from .testers.idor import IDORTester
from .testers.validator import FindingValidator

console = Console()


@dataclass
class DeepScanResult:
    """Complete scan result with all findings."""
    target: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: int = 0

    # Discovery results
    pages_crawled: int = 0
    endpoints_found: int = 0
    forms_found: int = 0
    ids_extracted: int = 0
    technology: Dict[str, str] = field(default_factory=dict)

    # Findings
    findings: List[Finding] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    # Business impact
    total_business_impact: int = 0


class DeepScanEngine:
    """
    GOD LEVEL Deep Scan Engine.

    Phases:
    1. RECON (2-3 min): Spider entire site, discover all endpoints
    2. INJECTION (5-7 min): Test all endpoints for SQLi, XSS, SSRF, CMDi, LFI, etc.
    3. AUTH (2-3 min): Test auth bypass, JWT attacks, privilege escalation
    4. IDOR (2-3 min): Test object reference vulnerabilities
    5. INFRASTRUCTURE (1-2 min): Sensitive files, config exposure
    6. REPORT: Generate comprehensive findings
    """

    def __init__(
        self,
        timeout_minutes: int = 20,
        max_pages: int = 500,
        concurrent_requests: int = 20,
    ):
        self.timeout_minutes = timeout_minutes
        self.max_pages = max_pages
        self.concurrent_requests = concurrent_requests
        self.session: Optional[aiohttp.ClientSession] = None
        self._callbacks: List[Callable] = []
        self._validator: Optional[FindingValidator] = None

    def on_finding(self, callback: Callable):
        """Register callback for when findings are discovered."""
        self._callbacks.append(callback)

    async def _fire_finding(self, finding: Finding):
        """Fire finding callbacks."""
        for cb in self._callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(finding)
                else:
                    cb(finding)
            except:
                pass

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=self.concurrent_requests, ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'BREACH.AI/5.0 DeepScan'}
        )
        self._validator = FindingValidator(self.session, timeout=10)
        return self

    async def _validate_finding(self, finding: Finding, cookies: Dict = None) -> bool:
        """Validate a finding before adding to results. Returns True if valid."""
        if not self._validator:
            return True  # No validator - accept all

        try:
            validation = await self._validator.validate(finding, cookies)

            if not validation.is_valid:
                console.print(f"   [dim red]✗ FILTERED: {finding.title} - {validation.reason}[/dim red]")
                return False

            if validation.confidence < FindingValidator.MIN_CONFIDENCE_THRESHOLD:
                console.print(f"   [dim yellow]⚠ LOW CONFIDENCE ({validation.confidence:.0%}): {finding.title}[/dim yellow]")
                return False

            console.print(f"   [green]✓ VALIDATED ({validation.confidence:.0%}): {finding.title}[/green]")
            return True

        except Exception as e:
            console.print(f"   [dim]Validation error: {e} - keeping finding[/dim]")
            return True  # On error, keep the finding

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    async def scan(
        self,
        target: str,
        cookies: Dict = None,
        cookies2: Dict = None,  # Second user for IDOR testing
        token: str = None,
        progress_callback: Callable = None,
    ) -> DeepScanResult:
        """
        Run the GOD LEVEL deep scan.

        Args:
            target: Target URL
            cookies: Session cookies for authenticated testing
            cookies2: Second user cookies for cross-user IDOR testing
            token: Bearer token (alternative to cookies)
            progress_callback: Callback for progress updates

        Returns:
            DeepScanResult with all findings
        """
        if not target.startswith('http'):
            target = f'https://{target}'

        result = DeepScanResult(
            target=target,
            started_at=datetime.now()
        )

        self._banner(target, bool(cookies))

        start_time = time.time()

        # Add auth header if token provided
        if token and self.session:
            self.session.headers.update({'Authorization': f'Bearer {token}'})

        try:
            # ===================================================================
            # PHASE 1: RECONNAISSANCE
            # ===================================================================
            console.print(f"\n[bold cyan]{'='*70}[/bold cyan]")
            console.print(f"[bold cyan]  PHASE 1: RECONNAISSANCE[/bold cyan]")
            console.print(f"[bold cyan]{'='*70}[/bold cyan]")

            spider = DeepSpider(
                session=self.session,
                base_url=target,
                max_depth=5,
                max_pages=self.max_pages,
                concurrent_requests=self.concurrent_requests
            )

            # Pass progress callback to spider for real-time updates
            spider_result = await spider.crawl(
                cookies,
                progress_callback=progress_callback
            )

            result.pages_crawled = spider_result.pages_crawled
            result.endpoints_found = len(spider_result.endpoints)
            result.forms_found = len(spider_result.forms)
            result.ids_extracted = len(spider_result.extracted_ids)
            result.technology = spider_result.technology

            self._show_recon_results(spider_result)

            if progress_callback:
                progress_callback(20, "Recon complete")

            # ===================================================================
            # PHASE 2: INJECTION TESTING
            # ===================================================================
            console.print(f"\n[bold cyan]{'='*70}[/bold cyan]")
            console.print(f"[bold cyan]  PHASE 2: INJECTION ATTACKS[/bold cyan]")
            console.print(f"[bold cyan]{'='*70}[/bold cyan]")

            injection_tester = InjectionTester(
                session=self.session,
                base_url=target,
                timeout=15,
                concurrent=10
            )

            # Filter to testable endpoints
            testable = [ep for ep in spider_result.endpoints if not ep.requires_auth or cookies][:100]

            console.print(f"\n[yellow]Testing {len(testable)} endpoints for injections...[/yellow]")

            injection_findings = await injection_tester.test_all_endpoints(
                testable,
                cookies,
                progress_callback=lambda done, total: progress_callback(20 + int(done/total * 40), f"Injection: {done}/{total}") if progress_callback else None
            )

            for finding in injection_findings:
                if await self._validate_finding(finding, cookies):
                    result.findings.append(finding)
                    await self._fire_finding(finding)
                    self._print_finding(finding)

            if progress_callback:
                progress_callback(60, f"Injection complete - {len(injection_findings)} findings")

            # ===================================================================
            # PHASE 3: AUTHENTICATION TESTING
            # ===================================================================
            console.print(f"\n[bold cyan]{'='*70}[/bold cyan]")
            console.print(f"[bold cyan]  PHASE 3: AUTHENTICATION TESTING[/bold cyan]")
            console.print(f"[bold cyan]{'='*70}[/bold cyan]")

            if progress_callback:
                progress_callback(62, "Testing authentication...")

            auth_tester = AuthTester(
                session=self.session,
                base_url=target,
                timeout=10,
                concurrent=15
            )

            auth_findings = await auth_tester.test_all(
                spider_result.endpoints,
                cookies
            )
            if progress_callback:
                progress_callback(72, f"Auth testing done - {len(auth_findings)} findings")

            for finding in auth_findings:
                if await self._validate_finding(finding, cookies):
                    result.findings.append(finding)
                    await self._fire_finding(finding)
                    self._print_finding(finding)

            if progress_callback:
                progress_callback(75, f"Auth complete - testing IDOR...")

            # ===================================================================
            # PHASE 4: IDOR TESTING
            # ===================================================================
            console.print(f"\n[bold cyan]{'='*70}[/bold cyan]")
            console.print(f"[bold cyan]  PHASE 4: IDOR TESTING[/bold cyan]")
            console.print(f"[bold cyan]{'='*70}[/bold cyan]")

            idor_tester = IDORTester(
                session=self.session,
                base_url=target,
                timeout=10,
                concurrent=15
            )

            idor_findings = await idor_tester.test_all(
                spider_result.endpoints,
                spider_result,
                cookies,
                cookies2
            )

            for finding in idor_findings:
                if await self._validate_finding(finding, cookies):
                    result.findings.append(finding)
                    await self._fire_finding(finding)
                    self._print_finding(finding)

            if progress_callback:
                progress_callback(90, f"IDOR complete - {len(idor_findings)} findings")

            # ===================================================================
            # PHASE 5: SENSITIVE FILES (Already done by spider)
            # ===================================================================
            console.print(f"\n[bold cyan]{'='*70}[/bold cyan]")
            console.print(f"[bold cyan]  PHASE 5: SENSITIVE FILE EXPOSURE[/bold cyan]")
            console.print(f"[bold cyan]{'='*70}[/bold cyan]")

            for sensitive_file in spider_result.sensitive_files:
                finding = Finding(
                    severity="HIGH" if '.env' in sensitive_file['filename'] or '.git' in sensitive_file['filename'] else "MEDIUM",
                    category="sensitive_file",
                    title=f"Sensitive File Exposed - {sensitive_file['filename']}",
                    description=f"Sensitive file accessible at {sensitive_file['url']}",
                    endpoint=sensitive_file['url'],
                    method="GET",
                    parameter="",
                    payload=sensitive_file['filename'],
                    raw_response=sensitive_file.get('sample', '')[:1000],
                    evidence=f"File content: {sensitive_file.get('sample', '')[:200]}",
                    business_impact=50000 if '.env' in sensitive_file['filename'] else 15000,
                    impact_explanation="Exposed configuration/secrets can lead to full system compromise.",
                    curl_command=f"curl '{sensitive_file['url']}'",
                    remediation="Block access to sensitive files. Configure web server to deny access to .*",
                    cwe_id="CWE-538",
                    owasp="A05:2021 – Security Misconfiguration",
                )
                if await self._validate_finding(finding, cookies):
                    result.findings.append(finding)
                    await self._fire_finding(finding)
                    self._print_finding(finding)

            if progress_callback:
                progress_callback(100, "Scan complete")

        except asyncio.TimeoutError:
            console.print(f"\n[red]Scan timed out after {self.timeout_minutes} minutes[/red]")

        except Exception as e:
            console.print(f"\n[red]Scan error: {e}[/red]")
            import traceback
            traceback.print_exc()

        # Calculate final stats
        result.completed_at = datetime.now()
        result.duration_seconds = int(time.time() - start_time)

        for finding in result.findings:
            if finding.severity == "CRITICAL":
                result.critical_count += 1
            elif finding.severity == "HIGH":
                result.high_count += 1
            elif finding.severity == "MEDIUM":
                result.medium_count += 1
            elif finding.severity == "LOW":
                result.low_count += 1

            result.total_business_impact += finding.business_impact

        # Final report
        self._final_report(result)

        return result

    def _banner(self, target: str, authenticated: bool):
        """Display scan banner."""
        console.print(Panel.fit(
            f"[bold red]BREACH.AI[/bold red]\n"
            f"[bold yellow]GOD LEVEL DEEP SCAN[/bold yellow]\n"
            f"[dim]One scan. Everything. Real vulnerabilities.[/dim]\n\n"
            f"Target: {target}\n"
            f"Auth: {'Authenticated' if authenticated else 'Unauthenticated'}\n"
            f"Duration: ~15-20 minutes",
            border_style="red",
            title="[bold]BREACH.AI v5.0[/bold]"
        ))

    def _show_recon_results(self, result: SpiderResult):
        """Display reconnaissance results."""
        table = Table(box=box.ROUNDED, title="[bold]Reconnaissance Results[/bold]")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Pages Crawled", str(result.pages_crawled))
        table.add_row("Endpoints Found", str(len(result.endpoints)))
        table.add_row("Forms Found", str(len(result.forms)))
        table.add_row("API Endpoints", str(len(result.api_endpoints)))
        table.add_row("JavaScript Files", str(len(result.js_files)))
        table.add_row("Sensitive Files", str(len(result.sensitive_files)))
        table.add_row("IDs Extracted", str(len(result.extracted_ids)))
        table.add_row("Technologies", ", ".join(result.technology.keys()) or "Unknown")

        console.print(table)

    def _print_finding(self, finding: Finding):
        """Print a finding as it's discovered."""
        severity_colors = {
            "CRITICAL": "red bold",
            "HIGH": "yellow",
            "MEDIUM": "blue",
            "LOW": "dim"
        }

        color = severity_colors.get(finding.severity, "white")
        emoji = {"CRITICAL": "", "HIGH": "", "MEDIUM": "", "LOW": ""}

        console.print(f"\n[{color}]{emoji.get(finding.severity, '')} [{finding.severity}] {finding.title}[/{color}]")
        console.print(f"   [dim]Endpoint:[/dim] {finding.endpoint}")
        if finding.parameter:
            console.print(f"   [dim]Parameter:[/dim] {finding.parameter}")
        if finding.payload:
            console.print(f"   [dim]Payload:[/dim] {finding.payload[:80]}...")
        console.print(f"   [green]Impact: ${finding.business_impact:,}[/green]")

    def _final_report(self, result: DeepScanResult):
        """Display final scan report."""
        console.print(f"\n{'='*70}")
        console.print(f"[bold]SCAN COMPLETE[/bold]")
        console.print(f"{'='*70}\n")

        # Summary stats
        if result.critical_count:
            console.print(f"[red bold] {result.critical_count} CRITICAL[/red bold]")
        if result.high_count:
            console.print(f"[yellow] {result.high_count} HIGH[/yellow]")
        if result.medium_count:
            console.print(f"[blue] {result.medium_count} MEDIUM[/blue]")
        if result.low_count:
            console.print(f"[dim] {result.low_count} LOW[/dim]")

        if result.total_business_impact:
            console.print(f"\n[bold green] TOTAL IMPACT: ${result.total_business_impact:,}[/bold green]")

        # Summary table
        table = Table(box=box.ROUNDED, title="[bold]Scan Summary[/bold]")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Target", result.target)
        table.add_row("Duration", f"{result.duration_seconds}s ({result.duration_seconds//60}m {result.duration_seconds%60}s)")
        table.add_row("Pages Crawled", str(result.pages_crawled))
        table.add_row("Endpoints Tested", str(result.endpoints_found))
        table.add_row("Total Findings", str(len(result.findings)))
        table.add_row("Critical", f"[red]{result.critical_count}[/red]")
        table.add_row("High", f"[yellow]{result.high_count}[/yellow]")
        table.add_row("Business Impact", f"[green]${result.total_business_impact:,}[/green]")

        console.print(table)

        # Detailed findings
        if result.findings:
            console.print(f"\n[bold]FINDINGS DETAIL:[/bold]\n")

            for i, finding in enumerate(sorted(result.findings, key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f.severity, 4)), 1):
                severity_colors = {"CRITICAL": "red bold", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "dim"}
                color = severity_colors.get(finding.severity, "white")

                console.print(f"[{color}]{i}. [{finding.severity}] {finding.title}[/{color}]")
                console.print(f"   {finding.description}")
                console.print(f"   [dim]Endpoint:[/dim] {finding.endpoint}")
                if finding.evidence:
                    console.print(f"   [dim]Evidence:[/dim] {finding.evidence[:100]}...")
                console.print(f"   [green]Impact: ${finding.business_impact:,}[/green]")
                console.print(f"   [cyan]Fix: {finding.remediation}[/cyan]")
                console.print(f"   [dim]Reproduce: {finding.curl_command}[/dim]")
                console.print()

        console.print(f"\n{'='*70}\n")

    def to_json_findings(self, result: DeepScanResult) -> List[Dict]:
        """Convert findings to JSON-serializable format."""
        return [
            {
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "endpoint": f.endpoint,
                "method": f.method,
                "parameter": f.parameter,
                "payload": f.payload,
                "evidence": f.evidence,
                "data_exposed": f.data_exposed,
                "business_impact": f.business_impact,
                "impact_explanation": f.impact_explanation,
                "curl_command": f.curl_command,
                "steps": f.steps,
                "remediation": f.remediation,
                "cwe_id": f.cwe_id,
                "owasp": f.owasp,
            }
            for f in result.findings
        ]
