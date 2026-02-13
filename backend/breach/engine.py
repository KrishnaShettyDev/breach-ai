#!/usr/bin/env python3
"""
██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗     █████╗ ██╗
██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║    ██╔══██╗██║
██████╔╝██████╔╝█████╗  ███████║██║     ███████║    ███████║██║
██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║    ██╔══██║██║
██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║    ██║  ██║██║
╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝

BREACH.AI - GOD LEVEL SECURITY SCANNER
======================================
ONE mode. DEEP. Does EVERYTHING. Finds REAL vulnerabilities.

Usage:
    python breach.py https://target.com
    python breach.py https://target.com --cookie "session=xxx"
    python breach.py https://target.com --cookie1 "u1=x" --cookie2 "u2=y"  # IDOR testing
"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set, Callable
from enum import Enum
from datetime import datetime

from rich.console import Console

console = Console()


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


@dataclass
class Finding:
    """A vulnerability finding."""
    severity: Severity
    category: str
    title: str
    description: str
    endpoint: str
    method: str
    evidence: Any = None
    records_exposed: int = 0
    pii_fields: List[str] = field(default_factory=list)
    business_impact: int = 0
    impact_explanation: str = ""
    curl_command: str = ""
    fix_suggestion: str = ""
    chained_from: Optional[str] = None


@dataclass
class ScanState:
    """State of the scan."""
    target: str
    findings: List[Finding] = field(default_factory=list)
    extracted_ids: Set[str] = field(default_factory=set)
    pages_crawled: int = 0
    endpoints_found: int = 0
    duration_seconds: int = 0


class BreachEngine:
    """
    BREACH.AI - GOD LEVEL Deep Scanner

    Single mode: DEEP
    - Crawls entire website (500+ pages)
    - Tests all injection types (SQLi, XSS, SSRF, CMDi, LFI, etc.)
    - Tests authentication bypass
    - Tests IDOR vulnerabilities
    - Finds sensitive file exposure

    Target duration: 15-20 minutes
    """

    def __init__(self, mode: str = "deep", timeout_hours: int = 1, deep_mode: bool = True):
        """
        Initialize the engine.

        Args:
            mode: Always "deep" - ignored for backwards compatibility
            timeout_hours: Maximum scan duration
            deep_mode: Always True - ignored for backwards compatibility
        """
        self.timeout_minutes = timeout_hours * 60
        self.state: Optional[ScanState] = None
        self._on_finding_callbacks: List[Callable] = []
        self._on_complete_callbacks: List[Callable] = []
        self._on_progress_callbacks: List[Callable] = []
        self._deep_engine = None
        self._result = None

    def on_finding(self, callback: Callable):
        """Register callback for when findings are discovered."""
        self._on_finding_callbacks.append(callback)

    def on_complete(self, callback: Callable):
        """Register callback for when scan completes."""
        self._on_complete_callbacks.append(callback)

    def on_progress(self, callback: Callable):
        """Register callback for progress updates. Callback receives (percent, phase_message)."""
        self._on_progress_callbacks.append(callback)

    async def __aenter__(self):
        from .deep_scan import DeepScanEngine
        self._deep_engine = DeepScanEngine(
            timeout_minutes=self.timeout_minutes,
            max_pages=500,
            concurrent_requests=20
        )
        await self._deep_engine.__aenter__()
        return self

    async def __aexit__(self, *args):
        if self._deep_engine:
            await self._deep_engine.__aexit__(*args)

    async def breach(
        self,
        target: str,
        cookie: str = None,
        cookie2: str = None,
        token: str = None,
        scope: List[str] = None,
    ) -> ScanState:
        """
        Run the GOD LEVEL deep scan.

        Args:
            target: Target URL
            cookie: Session cookie string for authenticated testing
            cookie2: Second user's cookie string for IDOR testing
            token: Bearer token (alternative to cookie)
            scope: Ignored - for backwards compatibility

        Returns:
            ScanState with all findings
        """
        if not target.startswith('http'):
            target = f'https://{target}'

        # Initialize state
        self.state = ScanState(target=target)

        # Parse cookies
        cookies = self._parse_cookies(cookie)
        cookies2 = self._parse_cookies(cookie2)

        # Register finding callback
        async def on_deep_finding(deep_finding):
            # Convert to old Finding format
            finding = self._convert_finding(deep_finding)
            self.state.findings.append(finding)

            # Fire callbacks
            for cb in self._on_finding_callbacks:
                try:
                    if asyncio.iscoroutinefunction(cb):
                        await cb(finding)
                    else:
                        cb(finding)
                except:
                    pass

        self._deep_engine.on_finding(on_deep_finding)

        # Progress callback to fire registered callbacks
        def on_progress(percent, message):
            for cb in self._on_progress_callbacks:
                try:
                    cb(percent, message)
                except:
                    pass

        # Run the deep scan
        start_time = time.time()

        result = await self._deep_engine.scan(
            target=target,
            cookies=cookies,
            cookies2=cookies2,
            token=token,
            progress_callback=on_progress,
        )

        self._result = result

        # Update state
        self.state.pages_crawled = result.pages_crawled
        self.state.endpoints_found = result.endpoints_found
        self.state.extracted_ids = set()  # IDs are tracked in deep engine
        self.state.duration_seconds = result.duration_seconds

        # Fire complete callbacks
        for cb in self._on_complete_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(self.state)
                else:
                    cb(self.state)
            except:
                pass

        return self.state

    def _parse_cookies(self, cookie_str: str) -> Dict[str, str]:
        """Parse cookie string to dict."""
        if not cookie_str:
            return {}

        cookies = {}
        for part in cookie_str.split(';'):
            if '=' in part:
                key, value = part.strip().split('=', 1)
                cookies[key.strip()] = value.strip()

        return cookies

    def _convert_finding(self, deep_finding) -> Finding:
        """Convert deep scan finding to old Finding format."""
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }

        return Finding(
            severity=severity_map.get(deep_finding.severity, Severity.MEDIUM),
            category=deep_finding.category,
            title=deep_finding.title,
            description=deep_finding.description,
            endpoint=deep_finding.endpoint,
            method=deep_finding.method,
            evidence=deep_finding.evidence or deep_finding.raw_response[:500] if hasattr(deep_finding, 'raw_response') else None,
            records_exposed=deep_finding.data_exposed.get('total_records', 0) if deep_finding.data_exposed else 0,
            pii_fields=deep_finding.data_exposed.get('pii_fields', []) if deep_finding.data_exposed else [],
            business_impact=deep_finding.business_impact,
            impact_explanation=deep_finding.impact_explanation,
            curl_command=deep_finding.curl_command,
            fix_suggestion=deep_finding.remediation,
        )

    def json_report(self) -> str:
        """Generate JSON report."""
        if not self._result:
            return json.dumps({})

        return json.dumps({
            'target': self.state.target,
            'duration_seconds': self.state.duration_seconds,
            'pages_crawled': self.state.pages_crawled,
            'endpoints_found': self.state.endpoints_found,
            'findings': [
                {
                    'severity': f.severity.name,
                    'category': f.category,
                    'title': f.title,
                    'description': f.description,
                    'endpoint': f.endpoint,
                    'business_impact': f.business_impact,
                    'curl_command': f.curl_command,
                    'fix': f.fix_suggestion,
                }
                for f in self.state.findings
            ],
            'summary': {
                'total_findings': len(self.state.findings),
                'critical': len([f for f in self.state.findings if f.severity == Severity.CRITICAL]),
                'high': len([f for f in self.state.findings if f.severity == Severity.HIGH]),
                'medium': len([f for f in self.state.findings if f.severity == Severity.MEDIUM]),
                'low': len([f for f in self.state.findings if f.severity == Severity.LOW]),
                'total_impact': sum(f.business_impact for f in self.state.findings),
            }
        }, indent=2)


async def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='BREACH.AI - GOD LEVEL Security Scanner')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('--cookie', '--cookie1', dest='cookie', help='Session cookie')
    parser.add_argument('--cookie2', help='Second user cookie for IDOR testing')
    parser.add_argument('--token', help='Bearer token')
    parser.add_argument('--output', '-o', help='Output JSON file')
    # Legacy args - ignored
    parser.add_argument('--mode', help='Ignored - always deep')
    parser.add_argument('--deep', action='store_true', help='Ignored - always deep')
    parser.add_argument('--quick', action='store_true', help='Ignored - always deep')
    parser.add_argument('--chainbreaker', action='store_true', help='Ignored - always deep')
    parser.add_argument('--timeout', type=int, default=1, help='Timeout in hours')

    args = parser.parse_args()

    console.print(f"\n[bold red]BREACH.AI[/bold red] - [bold yellow]GOD LEVEL[/bold yellow] Security Scanner\n")

    async with BreachEngine(timeout_hours=args.timeout) as engine:
        await engine.breach(
            target=args.target,
            cookie=args.cookie,
            cookie2=args.cookie2,
            token=args.token,
        )

        if args.output:
            with open(args.output, 'w') as f:
                f.write(engine.json_report())
            console.print(f"\n[green]Report saved to: {args.output}[/green]")


if __name__ == '__main__':
    asyncio.run(main())
