"""
BREACH.AI - Deep Engine
=======================

Comprehensive injection testing and vulnerability scanning.
Best for: Thorough security assessments, pre-release testing.
"""

import time
from datetime import datetime

from .base import BaseEngine, ScanConfig, ScanResult, Finding, Severity


class DeepEngine(BaseEngine):
    """
    Deep scan engine.

    Performs:
    - Full endpoint discovery (spider)
    - Injection testing (SQLi, XSS, SSRF, Command Injection, etc.)
    - Authentication testing
    - IDOR detection (with two cookies)
    - Sensitive file checks
    """

    MODE = "deep"
    DESCRIPTION = "Comprehensive injection testing"

    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self._engine = None

    async def initialize(self):
        """Initialize the deep scan engine."""
        from breach.deep_scan.engine import DeepScanEngine
        self._engine = DeepScanEngine(
            timeout_minutes=self.config.timeout_minutes,
            max_concurrent=self.config.parallel,
        )
        await self._engine.__aenter__()

    async def cleanup(self):
        """Cleanup resources."""
        if self._engine:
            await self._engine.__aexit__(None, None, None)

    async def scan(self) -> ScanResult:
        """Execute deep scan."""
        start_time = time.time()
        self.result.started_at = datetime.utcnow()

        await self._emit_progress(0, "Starting deep scan...")

        try:
            # Progress callback bridge
            def on_progress(percent, message):
                import asyncio
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        asyncio.create_task(self._emit_progress(percent, message))
                except:
                    pass

            # Run deep scan
            result = await self._engine.scan(
                target=self.config.target,
                cookies=self.config.get_cookies_dict(),
                cookies2=self.config.get_cookies2_dict(),
                token=self.config.token,
                progress_callback=on_progress,
            )

            await self._emit_progress(90, "Processing findings...")

            # Convert findings
            if hasattr(result, 'findings'):
                for f in result.findings:
                    finding = self._convert_finding(f)
                    self.result.findings.append(finding)
                    await self._emit_finding(finding)

            # Update stats
            self.result.endpoints_discovered = getattr(result, 'endpoints_discovered', 0)
            self.result.endpoints_tested = getattr(result, 'endpoints_tested', 0)
            self.result.requests_made = getattr(result, 'requests_made', 0)

            await self._emit_progress(100, "Deep scan complete")

        except Exception as e:
            self.result.errors.append(str(e))
            if self.config.verbose:
                import traceback
                self.result.errors.append(traceback.format_exc())

        # Finalize
        self.result.completed_at = datetime.utcnow()
        self.result.duration_seconds = int(time.time() - start_time)
        self.result.total_business_impact = sum(f.business_impact for f in self.result.findings)

        return self.result

    def _convert_finding(self, raw_finding) -> Finding:
        """Convert raw finding to unified Finding format."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }

        raw_severity = getattr(raw_finding, 'severity', 'medium')
        if hasattr(raw_severity, 'value'):
            raw_severity = raw_severity.value
        severity = severity_map.get(str(raw_severity), Severity.MEDIUM)

        return Finding(
            title=getattr(raw_finding, 'title', getattr(raw_finding, 'vulnerability_type', 'Unknown')),
            severity=severity,
            vulnerability_type=getattr(raw_finding, 'vulnerability_type', getattr(raw_finding, 'category', 'unknown')),
            endpoint=getattr(raw_finding, 'endpoint', getattr(raw_finding, 'url', '')),
            method=getattr(raw_finding, 'method', 'GET'),
            parameter=getattr(raw_finding, 'parameter', None),
            description=getattr(raw_finding, 'description', ''),
            payload=getattr(raw_finding, 'payload', ''),
            evidence=getattr(raw_finding, 'evidence', {}),
            business_impact=float(getattr(raw_finding, 'business_impact', 0)),
            curl_command=getattr(raw_finding, 'curl_command', ''),
            remediation=getattr(raw_finding, 'remediation', ''),
            cwe_id=getattr(raw_finding, 'cwe_id', ''),
        )
