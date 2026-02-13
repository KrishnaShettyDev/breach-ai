"""
BREACH.AI - Quick Engine
========================

Fast reconnaissance scan with common vulnerability checks.
Best for: Initial assessment, CI/CD pipelines, quick security checks.
"""

import time
from datetime import datetime

from .base import BaseEngine, ScanConfig, ScanResult, Finding, Severity


class QuickEngine(BaseEngine):
    """
    Quick scan engine.

    Performs:
    - Basic reconnaissance (DNS, headers, tech fingerprint)
    - Common vulnerability checks (top 10)
    - Fast endpoint discovery
    """

    MODE = "quick"
    DESCRIPTION = "Fast reconnaissance + common vulnerabilities"

    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self._engine = None

    async def initialize(self):
        """Initialize the underlying engine."""
        from backend.breach.engine import BreachEngine
        self._engine = BreachEngine(deep_mode=False)
        await self._engine.__aenter__()

    async def cleanup(self):
        """Cleanup resources."""
        if self._engine:
            await self._engine.__aexit__(None, None, None)

    async def scan(self) -> ScanResult:
        """Execute quick scan."""
        start_time = time.time()
        self.result.started_at = datetime.utcnow()

        await self._emit_progress(0, "Starting quick scan...")

        try:
            # Run the breach engine
            await self._emit_progress(10, "Reconnaissance...")

            await self._engine.breach(
                target=self.config.target,
                cookie=self.config.cookie,
            )

            await self._emit_progress(80, "Processing results...")

            # Convert findings from engine state
            if hasattr(self._engine, 'state') and self._engine.state:
                state = self._engine.state
                if hasattr(state, 'findings'):
                    for f in state.findings:
                        finding = self._convert_finding(f)
                        self.result.findings.append(finding)
                        await self._emit_finding(finding)

                # Update stats
                if hasattr(state, 'attack_surface'):
                    self.result.endpoints_discovered = len(getattr(state.attack_surface, 'endpoints', []))

            await self._emit_progress(100, "Quick scan complete")

        except Exception as e:
            self.result.errors.append(str(e))

        # Finalize
        self.result.completed_at = datetime.utcnow()
        self.result.duration_seconds = int(time.time() - start_time)
        self.result.total_business_impact = sum(f.business_impact for f in self.result.findings)

        return self.result

    def _convert_finding(self, raw_finding) -> Finding:
        """Convert raw finding to unified Finding format."""
        # Map severity
        severity_map = {
            4: Severity.CRITICAL,
            3: Severity.HIGH,
            2: Severity.MEDIUM,
            1: Severity.LOW,
            0: Severity.INFO,
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        raw_severity = getattr(raw_finding, 'severity', 'medium')
        if hasattr(raw_severity, 'value'):
            raw_severity = raw_severity.value
        severity = severity_map.get(raw_severity, Severity.MEDIUM)

        return Finding(
            title=getattr(raw_finding, 'title', 'Unknown'),
            severity=severity,
            vulnerability_type=getattr(raw_finding, 'vuln_type', getattr(raw_finding, 'category', 'unknown')),
            endpoint=getattr(raw_finding, 'endpoint', ''),
            method=getattr(raw_finding, 'method', 'GET'),
            parameter=getattr(raw_finding, 'parameter', None),
            description=getattr(raw_finding, 'description', ''),
            payload=getattr(raw_finding, 'payload', ''),
            evidence=getattr(raw_finding, 'evidence', {}),
            business_impact=float(getattr(raw_finding, 'business_impact', 0)),
            curl_command=getattr(raw_finding, 'curl_command', ''),
            remediation=getattr(raw_finding, 'remediation', ''),
        )
